//! Deterministic randomised falsification campaign over the crate's
//! untrusted-input parsers and numeric paths (`docs/AUTONOMOUS_DECISIONS.md`
//! #58). Every `cargo test` run performs a small campaign; scale it with
//! `BLERADAR_CAMPAIGN_ITERATIONS` (e.g. `5000000`, run under `--release`) and
//! reseed it with `BLERADAR_CAMPAIGN_SEED`. A failure prints the seed, so any
//! finding is reproducible.
//!
//! The 2026-09-10 campaign that introduced this file found COR-020..023
//! (forged Plus Code digits, an unvalidated coordinate fast path, and
//! non-idempotent Domain/Url canonical forms); the oracles below are the ones
//! that caught them.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use bleradar_core::coords::{self, CoordFormat};
use bleradar_core::entity::{self, HseEntity, HseEntityKind, HseEvidence};
use bleradar_core::{
    DeviceObservation, DeviceTrack, LatLon, TrackingSnapshotInput, bearing_deg, ble_distance_m,
    ble_distance_range_m, calibration_profile_from_ordinal, canonical_mac,
    effective_rssi_at_1m_dbm, filtered_rssi, haversine_m, is_locally_administered, proximity_label,
    proximity_label_from_distance_m, signal_confidence_percent, signal_trend,
    tracking_profile_from_ordinal, tracking_snapshot,
};

const DEFAULT_ITERATIONS: u64 = 10_000;
const DEFAULT_SEED: u64 = 0x5EED_2026_0910;

/// xorshift64* — dependency-free, deterministic, adequate for input generation.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }
    /// Uniform over every bit pattern: NaNs, infinities, subnormals included.
    fn any_f64(&mut self) -> f64 {
        f64::from_bits(self.next_u64())
    }
    fn any_f64_finite(&mut self) -> f64 {
        loop {
            let v = self.any_f64();
            if v.is_finite() {
                return v;
            }
        }
    }
    /// A plausible or extreme finite value.
    fn finite_f64(&mut self) -> f64 {
        match self.below(6) {
            0 => self.unit() * 200.0 - 150.0,
            1 => (self.unit() - 0.5) * 1e6,
            2 => self.any_f64_finite(),
            3 => [
                0.0,
                -0.0,
                f64::MIN_POSITIVE,
                f64::MAX,
                f64::MIN,
                f64::EPSILON,
                1e-300,
                -1e-300,
            ][self.below(8)],
            4 => (self.unit() * 200.0 - 100.0).round(),
            _ => self.unit() * 2e-3 - 1e-3,
        }
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const ALPHABET: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', ',', ' ', ' ', '-', '+', '°', 'º', '\'',
    '′', '’', '`', '"', '″', '”', 'N', 'S', 'E', 'W', 'n', 's', 'e', 'w', 'g', 'o', ':', ';', '=',
    'u', 'A', 'R', 'Q', 'G', 'k', 'x', 'C', 'F', 'H', 'J', 'M', 'P', 'V', 'X', 'a', 'z',
    '\u{FEFF}', '\u{200B}', '\u{200D}', '\t', '\n', '\r', '\u{00A0}', '\u{3000}', '@', '\\', '/',
    '?', '#', '&', '%', '_', '~', '!', 'İ', 'ß', 'ſ', '\u{212A}', 'Ĳ', 'Ń', 'é', '中', '😀',
    '\u{0000}', '\u{007F}', '\u{0085}', '\u{2028}', '\u{FF0B}', '\u{FF10}', '٣', '\u{0660}',
];

const SEEDS: &[&str] = &[
    "-27.4766, 153.0166",
    "-27.4766 153.0166",
    "27°28'35.8\"S 153°00'59.8\"E",
    "27 28.6 S, 153 01.0 E",
    "153°E, 27°S",
    "S33.87 151.21",
    "N33° E151°",
    "33°52'12\" 151°12'33\"",
    "geo:-27.4766,153.0166;u=35",
    "geo:37.786971,-122.399677,10",
    "4RRH46RW+RH7",
    "8FVC9G8F+6X",
    "QG62kn",
    "QG62",
    "QG62kn12",
    "0,0",
    "90,180",
    "-90,-180",
    "user@example.com",
    "  Someone@Example.COM\\r\\n",
    "\u{FEFF}first.last@example.com",
    "@Handle_Name",
    "www.www.Example.com.",
    "+61 (7) 1234 5678",
    "192.0.2.1",
    "::ffff:192.0.2.1",
    "2001:db8::1",
    "AA-BB-CC-DD-EE-FF",
    "aa:bb:cc:dd:ee:ff",
    "HTTPS://Example.com/Path/?utm_source=x&b=2&a=1#frag",
    "http://example.com/",
    "1e308,0",
    "1000,2000",
    "abc",
];

fn random_string(rng: &mut Rng, max_len: usize) -> String {
    let len = rng.below(max_len + 1);
    (0..len).map(|_| *rng.pick(ALPHABET)).collect()
}

fn random_bytes_lossy(rng: &mut Rng, max_len: usize) -> String {
    let len = rng.below(max_len + 1);
    let bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A non-ASCII code point whose low byte equals the ASCII character's byte.
fn homoglyph(c: char) -> Option<char> {
    if !c.is_ascii_alphanumeric() {
        return None;
    }
    let bases = [0x100u32, 0x200, 0x1000, 0x1F600 & !0xFF];
    let base = bases[(c as u32 as usize) % bases.len()];
    char::from_u32(base | (c as u32 & 0xFF)).filter(|h| !h.is_ascii())
}

fn mutate(rng: &mut Rng, seed: &str) -> String {
    let mut chars: Vec<char> = seed.chars().collect();
    let ops = 1 + rng.below(3);
    for _ in 0..ops {
        if chars.is_empty() {
            chars.push(*rng.pick(ALPHABET));
            continue;
        }
        let i = rng.below(chars.len());
        match rng.below(8) {
            0 => chars.insert(i, *rng.pick(ALPHABET)),
            1 => {
                chars.remove(i);
            }
            2 => chars[i] = *rng.pick(ALPHABET),
            3 => {
                if i + 1 < chars.len() {
                    chars.swap(i, i + 1);
                }
            }
            4 => {
                let j = (i + 1 + rng.below(4)).min(chars.len());
                let slice: Vec<char> = chars[i..j].to_vec();
                for (k, c) in slice.into_iter().enumerate() {
                    chars.insert(j + k, c);
                }
            }
            5 => {
                chars[i] = if chars[i].is_lowercase() {
                    chars[i].to_ascii_uppercase()
                } else {
                    chars[i].to_ascii_lowercase()
                }
            }
            6 => {
                if let Some(h) = homoglyph(chars[i]) {
                    chars[i] = h;
                }
            }
            _ => chars.truncate(i),
        }
    }
    chars.into_iter().collect()
}

fn random_input(rng: &mut Rng) -> String {
    match rng.below(4) {
        0 => random_string(rng, 40),
        1 => random_bytes_lossy(rng, 32),
        _ => {
            let seed = *rng.pick(SEEDS);
            mutate(rng, seed)
        }
    }
}

#[derive(Default)]
struct Report {
    checks: u64,
    violations: BTreeMap<String, Vec<String>>,
}

impl Report {
    fn violation(&mut self, category: &str, detail: String) {
        let entry = self.violations.entry(category.to_string()).or_default();
        if entry.len() < 5 {
            entry.push(detail);
        } else if entry.len() == 5 {
            entry.push("…".to_string());
        }
    }

    fn guarded<F: FnOnce() -> Result<(), String>>(&mut self, category: &str, input: &str, f: F) {
        self.checks += 1;
        match catch_unwind(AssertUnwindSafe(f)) {
            Ok(Ok(())) => {}
            Ok(Err(detail)) => self.violation(category, format!("{input:?}: {detail}")),
            Err(payload) => {
                let message = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                    .unwrap_or_else(|| "non-string panic payload".to_string());
                self.violation(
                    &format!("PANIC:{category}"),
                    format!("{input:?}: {message}"),
                );
            }
        }
    }
}

fn check_coords(report: &mut Report, s: &str) {
    report.guarded("coords::parse", s, || {
        let Some(p) = coords::parse(s) else {
            return Ok(());
        };
        let (lat, lon) = (p.point.lat(), p.point.lon());
        if !(lat.is_finite()
            && lon.is_finite()
            && (-90.0..=90.0).contains(&lat)
            && (-180.0..=180.0).contains(&lon))
        {
            return Err(format!("out-of-range result {lat},{lon} ({:?})", p.format));
        }
        match p.format {
            CoordFormat::PlusCode => {
                let bad: Vec<char> = s
                    .trim()
                    .chars()
                    .filter(|c| *c != '+' && !c.is_ascii_alphanumeric())
                    .collect();
                if !bad.is_empty() {
                    return Err(format!(
                        "PlusCode accepted non-ASCII digit(s) {bad:?} -> {lat},{lon}"
                    ));
                }
            }
            CoordFormat::Maidenhead if !s.trim().chars().all(|c| c.is_ascii_alphanumeric()) => {
                return Err(format!("Maidenhead accepted non-ASCII -> {lat},{lon}"));
            }
            _ => {}
        }
        // Idempotence through the crate's own canonical 6-dp decimal form
        // (`fmt_coord_6dp`), within the 6-dp rounding bound.
        let canon = format!("{lat:.6},{lon:.6}");
        match coords::parse(&canon) {
            Some(q)
                if (q.point.lat() - lat).abs() <= 1e-6 && (q.point.lon() - lon).abs() <= 1e-6 =>
            {
                Ok(())
            }
            other => Err(format!("canonical re-parse of {canon} gave {other:?}")),
        }
    });
}

const KINDS: &[HseEntityKind] = &[
    HseEntityKind::Person,
    HseEntityKind::Email,
    HseEntityKind::Phone,
    HseEntityKind::Username,
    HseEntityKind::IpAddress,
    HseEntityKind::Domain,
    HseEntityKind::Url,
    HseEntityKind::Coordinates,
    HseEntityKind::Organisation,
    HseEntityKind::MacAddress,
    HseEntityKind::Ssid,
    HseEntityKind::CryptoAddress,
    HseEntityKind::Cidr,
];

fn check_entity(report: &mut Report, rng: &mut Rng, s: &str) {
    let kind = if rng.chance(0.1) {
        HseEntityKind::Other(random_string(rng, 8))
    } else {
        rng.pick(KINDS).clone()
    };
    let label = format!("normalise[{kind:?}]");
    report.guarded(&label, s, || {
        let once = entity::normalise(&kind, s);
        let twice = entity::normalise(&kind, &once);
        if once != twice {
            return Err(format!("not idempotent: {once:?} -> {twice:?}"));
        }
        if entity::uid_for(&kind, s) != entity::derive_uid(&kind, &once) {
            return Err("uid_for != derive_uid(normalise)".to_string());
        }
        if matches!(kind, HseEntityKind::Coordinates)
            && once != s.trim()
            && let Some((a, b)) = once.split_once(',')
            && let (Ok(lat), Ok(lon)) = (a.parse::<f64>(), b.parse::<f64>())
            && !(lat.is_finite()
                && lon.is_finite()
                && (-90.0..=90.0).contains(&lat)
                && (-180.0..=180.0).contains(&lon))
        {
            // Only a value the normaliser actually rewrote can be a wrongly
            // minted canonical coordinate.
            return Err(format!("canonical coordinate invalid: {once:?}"));
        }
        Ok(())
    });
    let now = rng.next_u64() % (1u64 << 40);
    let observed = rng.next_u64() % (1u64 << 40);
    let confidence = rng.any_f64();
    report.guarded("HseEntity", s, || {
        let mut e = HseEntity::new(kind.clone(), s, confidence, "scan", observed);
        let decayed = e.decayed_confidence_at(now);
        if !(0.0..=1.0).contains(&decayed) {
            return Err(format!("decayed confidence {decayed} out of [0,1]"));
        }
        e.apply_decay_at(now);
        e.add_evidence(HseEvidence::new("src-a", "x", now));
        e.add_evidence(HseEvidence::new("src-b", "y", now.saturating_sub(7)));
        let c = e.c_effective();
        if !c.is_finite() || !(0.0..=1.0).contains(&c) {
            return Err(format!("c_effective {c} not in [0,1]"));
        }
        let _ = e.classify();
        let mut other = HseEntity::new(kind.clone(), s, 1.0 - decayed, "scan2", observed / 2);
        other.add_evidence(HseEvidence::new("src-c", "z", now));
        e.merge(other);
        if !e.c_effective().is_finite() {
            return Err("c_effective after merge non-finite".to_string());
        }
        let _ = e.source_count();
        Ok(())
    });
    report.guarded("canonical_handle", s, || {
        let h = entity::canonical_handle(s);
        if entity::canonical_handle(&h) != h {
            return Err(format!("not idempotent: {h:?}"));
        }
        Ok(())
    });
    report.guarded("canonical_mac", s, || match canonical_mac(s) {
        Some(m) => {
            let well_formed = m.len() == 17
                && m.chars()
                    .all(|c| c == ':' || (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
            if !well_formed
                || canonical_mac(&m).as_deref() != Some(m.as_str())
                || is_locally_administered(s).is_none()
            {
                return Err(format!("bad canonical MAC {m:?}"));
            }
            Ok(())
        }
        None => {
            if is_locally_administered(s).is_some() {
                return Err("is_locally_administered Some for non-MAC".to_string());
            }
            Ok(())
        }
    });
}

fn check_signal(report: &mut Report, rng: &mut Rng) {
    let prev = if rng.chance(0.2) {
        rng.any_f64()
    } else {
        rng.finite_f64()
    };
    let cur = if rng.chance(0.2) {
        rng.any_f64()
    } else {
        rng.finite_f64()
    };
    let spread = if rng.chance(0.2) {
        rng.any_f64()
    } else {
        rng.finite_f64().abs()
    };
    let sample_count = match rng.below(3) {
        0 => rng.below(20),
        1 => usize::MAX - rng.below(3),
        _ => rng.next_u64() as usize,
    };
    let cal_ord = rng.next_u64() as i32 % 5;
    let trk_ord = rng.next_u64() as i32 % 4;
    let age_ms = match rng.below(3) {
        0 => rng.below(60_000) as u64,
        1 => u64::MAX - rng.below(3) as u64,
        _ => rng.next_u64(),
    };
    let tx = if rng.chance(0.5) {
        None
    } else if rng.chance(0.3) {
        Some(rng.any_f64())
    } else {
        Some(rng.finite_f64())
    };
    let desc = format!(
        "prev={prev:e} cur={cur:e} spread={spread:e} n={sample_count} cal={cal_ord} trk={trk_ord} age={age_ms} tx={tx:?}"
    );
    report.guarded("tracking_snapshot", &desc, || {
        let (Some(calibration_profile), Some(tracking_profile)) = (
            calibration_profile_from_ordinal(cal_ord),
            tracking_profile_from_ordinal(trk_ord),
        ) else {
            return Ok(());
        };
        let out = tracking_snapshot(TrackingSnapshotInput {
            previous_filtered_rssi_dbm: prev,
            current_rssi_dbm: cur,
            rssi_spread_db: spread,
            sample_count,
            calibration_profile,
            tracking_profile,
            age_ms,
            tx_power_dbm: tx,
        });
        let Some(snap) = out else {
            // A finite current sample with a finite or NaN previous must yield
            // a snapshot unless the EMA itself overflowed.
            if cur.is_finite()
                && (prev.is_finite() || prev.is_nan())
                && filtered_rssi(prev, cur, 0.35).is_some()
            {
                return Err("None despite finite filtered RSSI".to_string());
            }
            return Ok(());
        };
        if !snap.filtered_rssi_dbm.is_finite() {
            return Err("non-finite filtered RSSI".to_string());
        }
        if let Some(d) = snap.distance_m {
            if !(d.is_finite() && d > 0.0) {
                return Err(format!("distance {d}"));
            }
            if let (Some(lo), Some(hi)) = (snap.distance_lower_bound_m, snap.distance_upper_bound_m)
                && !(lo.is_finite() && hi.is_finite() && lo <= d && d <= hi)
            {
                return Err(format!("bounds {lo}..{hi} do not bracket {d}"));
            }
        }
        if let (Some(lo), Some(hi)) = (snap.distance_lower_bound_m, snap.distance_upper_bound_m)
            && !(lo > 0.0 && lo <= hi)
        {
            return Err(format!("bounds {lo}..{hi} invalid"));
        }
        if snap.confidence_percent.is_some_and(|c| c > 100) {
            return Err("confidence > 100".to_string());
        }
        if prev.is_finite() {
            let tolerance = 1e-6 * prev.abs().max(cur.abs()).max(1.0);
            let lo = prev.min(cur) - tolerance;
            let hi = prev.max(cur) + tolerance;
            if snap.filtered_rssi_dbm < lo || snap.filtered_rssi_dbm > hi {
                return Err(format!(
                    "EMA {} outside [{prev},{cur}]",
                    snap.filtered_rssi_dbm
                ));
            }
        }
        Ok(())
    });
    let desc = format!("cur={cur:e} spread={spread:e} n={sample_count} tx={tx:?}");
    report.guarded("signal helpers", &desc, || {
        let reference = effective_rssi_at_1m_dbm(tx, -59.0);
        if !reference.is_finite() {
            return Err("effective_rssi_at_1m_dbm non-finite".to_string());
        }
        if let Some(d) = ble_distance_m(cur, reference, 2.0) {
            if !(d.is_finite() && d > 0.0) {
                return Err(format!("ble_distance_m {d}"));
            }
            if proximity_label_from_distance_m(d).is_none() {
                return Err("distance proximity None for finite positive distance".to_string());
            }
        }
        if let Some((lo, hi)) = ble_distance_range_m(cur, spread, reference, 2.0)
            && !(lo.is_finite() && hi.is_finite() && 0.0 < lo && lo <= hi)
        {
            return Err(format!("range {lo}..{hi}"));
        }
        if let Some(c) = signal_confidence_percent(sample_count, spread)
            && c > 100
        {
            return Err(format!("confidence {c}"));
        }
        if let Some(f) = filtered_rssi(prev, cur, 0.35)
            && !f.is_finite()
        {
            return Err("filtered_rssi non-finite".to_string());
        }
        if signal_trend(prev, cur, 3.0).is_some() && !(prev.is_finite() && cur.is_finite()) {
            return Err("signal_trend Some for non-finite".to_string());
        }
        if proximity_label(cur).is_some() != cur.is_finite() {
            return Err("proximity_label finiteness mismatch".to_string());
        }
        Ok(())
    });
}

fn check_track(report: &mut Report, rng: &mut Rng) {
    let alpha = if rng.chance(0.2) {
        rng.any_f64()
    } else {
        rng.unit() * 1.2
    };
    let n = rng.below(12);
    let desc = format!("alpha={alpha:e} n={n}");
    report.guarded("DeviceTrack", &desc, || {
        let Ok(mut track) = DeviceTrack::new(alpha) else {
            if alpha.is_finite() && alpha > 0.0 && alpha <= 1.0 {
                return Err("valid alpha rejected".to_string());
            }
            return Ok(());
        };
        let mut t: u64 = 0;
        let mut positioned = 0usize;
        for _ in 0..n {
            t = t.saturating_add(rng.below(100_000) as u64);
            if rng.chance(0.1) {
                t = u64::MAX;
            }
            let pos = if rng.chance(0.8) {
                let (lat, lon) = if rng.chance(0.5) {
                    (rng.unit() * 180.0 - 90.0, rng.unit() * 360.0 - 180.0)
                } else {
                    (rng.finite_f64(), rng.finite_f64())
                };
                LatLon::new(lat, lon).ok()
            } else {
                None
            };
            let acc = if rng.chance(0.7) {
                Some(rng.finite_f64().abs())
            } else {
                None
            };
            let rssi = if rng.chance(0.15) {
                rng.any_f64()
            } else {
                rng.finite_f64()
            };
            let obs = DeviceObservation {
                timestamp_ms: t,
                observer_position: pos,
                gps_accuracy_m: acc,
                rssi_dbm: rssi,
                tx_power_dbm: None,
            };
            let valid = rssi.is_finite() && acc.is_none_or(|a| a.is_finite() && a > 0.0);
            match track.push(obs) {
                Ok(()) => {
                    if !valid {
                        return Err("invalid observation accepted".to_string());
                    }
                    if pos.is_some() {
                        positioned += 1;
                    }
                }
                Err(e) => {
                    // Only a filter overflow may reject a valid observation.
                    let filtered = track.filtered_rssi();
                    if valid && filtered.is_some_and(f64::is_finite) && rssi.abs() < 1e300 {
                        return Err(format!("valid observation rejected: {e}"));
                    }
                }
            }
        }
        if track.observed_map_points().len() != positioned {
            return Err("map point count != positioned observations".to_string());
        }
        if let Some(est) = track.spatial_estimate() {
            if positioned < 2 {
                return Err("estimate with < 2 positioned observations".to_string());
            }
            if !(est.uncertainty_m.is_finite() && est.uncertainty_m >= 1.0) {
                return Err(format!("uncertainty {}", est.uncertainty_m));
            }
            if est.confidence.value() > 100 || est.supporting_observations != positioned {
                return Err("estimate metadata invalid".to_string());
            }
        }
        Ok(())
    });
}

fn check_geo(report: &mut Report, rng: &mut Rng) {
    let (a_lat, a_lon, b_lat, b_lon) = (
        rng.finite_f64(),
        rng.finite_f64(),
        rng.finite_f64(),
        rng.finite_f64(),
    );
    let desc = format!("{a_lat},{a_lon} -> {b_lat},{b_lon}");
    report.guarded("geo", &desc, || {
        let (Ok(a), Ok(b)) = (LatLon::new(a_lat, a_lon), LatLon::new(b_lat, b_lon)) else {
            return Ok(());
        };
        let d = haversine_m(a, b);
        if !(d.is_finite() && (0.0..=20_100_000.0).contains(&d)) {
            return Err(format!("haversine {d}"));
        }
        let br = bearing_deg(a, b);
        if !(br.is_finite() && (0.0..360.0).contains(&br)) {
            return Err(format!("bearing {br}"));
        }
        Ok(())
    });
}

fn run_campaign(iterations: u64, seed: u64) -> Report {
    let mut rng = Rng::new(seed);
    let mut report = Report::default();
    for i in 0..iterations {
        let s = random_input(&mut rng);
        check_coords(&mut report, &s);
        check_entity(&mut report, &mut rng, &s);
        if i % 2 == 0 {
            check_signal(&mut report, &mut rng);
        }
        if i % 4 == 0 {
            check_track(&mut report, &mut rng);
        }
        check_geo(&mut report, &mut rng);
    }
    report
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn randomised_falsification_campaign_finds_no_violation() {
    let iterations = env_u64("BLERADAR_CAMPAIGN_ITERATIONS", DEFAULT_ITERATIONS);
    let seed = env_u64("BLERADAR_CAMPAIGN_SEED", DEFAULT_SEED);
    let report = run_campaign(iterations, seed);
    assert!(report.checks >= iterations * 4);
    if !report.violations.is_empty() {
        let mut message = format!(
            "campaign seed={seed} iterations={iterations} checks={} found violations:\n",
            report.checks
        );
        for (category, samples) in &report.violations {
            message.push_str(&format!("  {category}:\n"));
            for sample in samples {
                message.push_str(&format!("    {sample}\n"));
            }
        }
        panic!("{message}");
    }
}

/// The oracles must still be sensitive: the campaign's own mutators have to
/// reach every notation and kind, otherwise a green run proves nothing.
#[test]
fn campaign_generators_reach_every_notation_and_kind() {
    let mut rng = Rng::new(DEFAULT_SEED);
    let mut formats = std::collections::BTreeSet::new();
    for _ in 0..20_000 {
        let s = random_input(&mut rng);
        if let Some(p) = coords::parse(&s) {
            formats.insert(format!("{:?}", p.format));
        }
    }
    for expected in ["Decimal", "Dms", "Ddm", "GeoUri", "PlusCode", "Maidenhead"] {
        assert!(
            formats.contains(expected),
            "generated inputs never parsed as {expected}: {formats:?}"
        );
    }
    assert!(homoglyph('R').is_some_and(|h| !h.is_ascii()));
}
