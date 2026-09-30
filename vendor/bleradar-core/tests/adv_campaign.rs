//! Randomized differential + robustness campaign over the BLE advertising
//! decoder (`bleradar_core::adv`).
//!
//! Radio payloads are attacker-controllable, so the decoder's contract is
//! "never panic, never assert more than the bytes support". A deterministic
//! PRNG drives three input families through the production [`adv::decode`]:
//!
//! * pure random byte strings of random length;
//! * *structured* payloads — sequences of AD structures over the modelled and
//!   unmodelled types, with random payload lengths, zero padding, and lengths
//!   deliberately corrupted to overrun the buffer;
//! * *mutations* of valid iBeacon / Eddystone frames (bit flips, truncation,
//!   extension, byte substitution).
//!
//! Every decode is compared field-by-field with an **independent reference
//! walker** written separately from the specification (a different loop shape,
//! `get`-only access), and these invariants must hold:
//!
//! * the hex hand-off path agrees with the byte path (`decode_hex(hex(b)) ==
//!   decode(b)`);
//! * the service-UUID list has no duplicates;
//! * the recognised beacon equals the one an independent recogniser derives
//!   from the same structures (kind, every field, and presence in both
//!   directions);
//! * no input panics.
//!
//! The falsification test at the bottom proves the comparison is sensitive: a
//! reference that ignores the zero-length terminator is caught diverging.

use bleradar_core::adv::{self, AdvReport, Beacon, Uuid};
use bleradar_core::hex_encode;

/// Deterministic xorshift* PRNG (no external deps), as in the other campaigns.
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
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

/// What the reference walker extracts: every field of [`AdvReport`] except
/// `beacon`, which is checked by the shape invariant instead.
#[derive(Debug, Default, PartialEq)]
struct Reference {
    flags: Option<u8>,
    complete_local_name: Option<String>,
    shortened_local_name: Option<String>,
    tx_power_level: Option<i8>,
    appearance: Option<u16>,
    service_uuids: Vec<String>,
    service_data: Vec<(String, Vec<u8>)>,
    manufacturer_data: Vec<(u16, Vec<u8>)>,
    unknown_types: Vec<u8>,
    malformed: Vec<u8>,
    truncated: bool,
}

/// Independent reference: walks the AD structures with `get`-only access and
/// re-derives each modelled field from the Core Specification Supplement.
fn reference(data: &[u8], honour_terminator: bool) -> Reference {
    let mut r = Reference::default();
    let mut i = 0usize;
    while let Some(&len) = data.get(i) {
        if len == 0 {
            if honour_terminator {
                break;
            }
            i += 1;
            continue;
        }
        let len = usize::from(len);
        let Some(structure) = data.get(i + 1..i + 1 + len) else {
            r.truncated = true;
            break;
        };
        let ad_type = structure[0];
        let p = &structure[1..];
        // Returns true when every byte formed a whole UUID (a positive
        // multiple of the width), matching the decoder's `push_uuids*`.
        let uuid_list = |width: usize, out: &mut Vec<String>| -> bool {
            let mut k = 0;
            while k + width <= p.len() {
                let mut chunk: Vec<u8> = p[k..k + width].to_vec();
                chunk.reverse(); // little-endian on the wire → big-endian text
                let text = canon(&chunk);
                if !out.contains(&text) {
                    out.push(text);
                }
                k += width;
            }
            !p.is_empty() && p.len() % width == 0
        };
        match ad_type {
            0x01 => match p.first() {
                Some(&b) => r.flags = Some(b),
                None => r.malformed.push(ad_type),
            },
            0x02 | 0x03 => {
                if !uuid_list(2, &mut r.service_uuids) {
                    r.malformed.push(ad_type);
                }
            }
            0x04 | 0x05 => {
                if !uuid_list(4, &mut r.service_uuids) {
                    r.malformed.push(ad_type);
                }
            }
            0x06 | 0x07 => {
                if !uuid_list(16, &mut r.service_uuids) {
                    r.malformed.push(ad_type);
                }
            }
            0x08 => r.shortened_local_name = Some(String::from_utf8_lossy(p).into_owned()),
            0x09 => r.complete_local_name = Some(String::from_utf8_lossy(p).into_owned()),
            0x0A => match p.first() {
                Some(&b) => r.tx_power_level = Some(i8::from_ne_bytes([b])),
                None => r.malformed.push(ad_type),
            },
            0x19 => {
                if p.len() >= 2 {
                    r.appearance = Some(u16::from(p[0]) | (u16::from(p[1]) << 8));
                } else {
                    r.malformed.push(ad_type);
                }
            }
            0x16 | 0x20 | 0x21 => {
                let width = match ad_type {
                    0x16 => 2,
                    0x20 => 4,
                    _ => 16,
                };
                if p.len() >= width {
                    let mut id: Vec<u8> = p[..width].to_vec();
                    id.reverse();
                    r.service_data.push((canon(&id), p[width..].to_vec()));
                } else {
                    r.malformed.push(ad_type);
                }
            }
            0xFF => {
                if p.len() >= 2 {
                    let company = u16::from(p[0]) | (u16::from(p[1]) << 8);
                    r.manufacturer_data.push((company, p[2..].to_vec()));
                } else {
                    r.malformed.push(ad_type);
                }
            }
            other => r.unknown_types.push(other),
        }
        i += 1 + len;
    }
    r
}

/// Canonical text for a big-endian UUID of width 2, 4 or 16, independent of
/// `Uuid::to_canonical` (dashes inserted by position here, by index there).
fn canon(be: &[u8]) -> String {
    let hex: String = be.iter().map(|b| format!("{b:02x}")).collect();
    if be.len() == 16 {
        format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )
    } else {
        hex
    }
}

fn project(report: &AdvReport) -> Reference {
    Reference {
        flags: report.flags,
        complete_local_name: report.complete_local_name.clone(),
        shortened_local_name: report.shortened_local_name.clone(),
        tx_power_level: report.tx_power_level,
        appearance: report.appearance,
        service_uuids: report
            .service_uuids
            .iter()
            .map(Uuid::to_canonical)
            .collect(),
        service_data: report
            .service_data
            .iter()
            .map(|s| (s.uuid.to_canonical(), s.data.clone()))
            .collect(),
        manufacturer_data: report
            .manufacturer_data
            .iter()
            .map(|m| (m.company_id, m.data.clone()))
            .collect(),
        unknown_types: report.unknown_types.clone(),
        malformed: report.malformed.clone(),
        truncated: report.truncated,
    }
}

/// The exact beacon the decoder should produce, re-derived independently from
/// the (already field-by-field validated) manufacturer- and service-data of the
/// report — a different code path from `adv::recognise_beacon`, so `check()` can
/// assert `report.beacon` for equality in BOTH directions: a wrong field value,
/// a wrong kind, a dropped recognition and a false recognition all diverge.
///
/// Precedence mirrors the decoder: a qualifying iBeacon (first such Apple block)
/// wins over Eddystone (first `0xFEAA` frame that parses).
fn reference_beacon(report: &AdvReport) -> Option<Beacon> {
    for m in &report.manufacturer_data {
        if m.company_id == 0x004C && m.data.len() >= 23 && m.data[..2] == [0x02, 0x15] {
            return Some(Beacon::IBeacon {
                // Big-endian in the payload, unlike the little-endian UUID lists.
                uuid: canon(&m.data[2..18]),
                major: u16::from(m.data[18]) << 8 | u16::from(m.data[19]),
                minor: u16::from(m.data[20]) << 8 | u16::from(m.data[21]),
                tx_power: m.data[22] as i8,
            });
        }
    }
    for s in &report.service_data {
        if s.uuid != Uuid::U16(0xFEAA) {
            continue;
        }
        let d = &s.data;
        let beacon = match d.first() {
            Some(0x00) if d.len() >= 18 => Some(Beacon::EddystoneUid {
                tx_power: d[1] as i8,
                namespace: bytes_hex(&d[2..12]),
                instance: bytes_hex(&d[12..18]),
            }),
            Some(0x10) if d.len() >= 3 => ref_url(d[2], &d[3..]).map(|url| Beacon::EddystoneUrl {
                url,
                tx_power: d[1] as i8,
            }),
            Some(0x20) if d.len() >= 14 && d[1] == 0x00 => Some(Beacon::EddystoneTlm {
                battery_mv: match u16::from(d[2]) << 8 | u16::from(d[3]) {
                    0 => None,
                    mv => Some(mv),
                },
                temperature_c: match i16::from_be_bytes([d[4], d[5]]) {
                    -32768 => None,
                    raw => Some(f32::from(raw) / 256.0),
                },
                adv_count: u32::from_be_bytes([d[6], d[7], d[8], d[9]]),
                uptime_deciseconds: u32::from_be_bytes([d[10], d[11], d[12], d[13]]),
            }),
            _ => None,
        };
        if let Some(beacon) = beacon {
            return Some(beacon);
        }
    }
    None
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Independent Eddystone-URL expansion, from the spec (a second copy so a table
/// error in the decoder diverges here, and the explicit per-code unit fixtures
/// in `adv.rs` pin both to the spec literals).
fn ref_url(scheme: u8, body: &[u8]) -> Option<String> {
    let mut url = String::from(match scheme {
        0x00 => "http://www.",
        0x01 => "https://www.",
        0x02 => "http://",
        0x03 => "https://",
        _ => return None,
    });
    const SUFFIX: [&str; 14] = [
        ".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/", ".com", ".org", ".edu",
        ".net", ".info", ".biz", ".gov",
    ];
    for &b in body {
        match b {
            0x00..=0x0d => url.push_str(SUFFIX[b as usize]),
            0x21..=0x7e => url.push(b as char),
            _ => url.push_str(&format!("\\x{b:02x}")),
        }
    }
    Some(url)
}

fn check(data: &[u8]) -> Result<(), String> {
    let report = adv::decode(data);
    let expected = reference(data, true);
    let got = project(&report);
    if got != expected {
        return Err(format!(
            "decoder diverges from the reference on {}:\n  got      {got:?}\n  expected {expected:?}",
            hex_encode(data)
        ));
    }
    if adv::decode_hex(&hex_encode(data)) != report {
        return Err(format!("hex path disagrees on {}", hex_encode(data)));
    }
    let uuids = &report.service_uuids;
    for (i, u) in uuids.iter().enumerate() {
        if uuids[..i].contains(u) {
            return Err(format!("duplicate service UUID on {}", hex_encode(data)));
        }
    }
    // The recognised beacon must equal the one an independent recogniser derives
    // from the same structures — catching a wrong field value, a wrong kind, a
    // dropped recognition and a false recognition alike.
    if report.beacon != reference_beacon(&report) {
        return Err(format!(
            "beacon diverges on {}:\n  got      {:?}\n  expected {:?}",
            hex_encode(data),
            report.beacon,
            reference_beacon(&report)
        ));
    }
    Ok(())
}

/// A structured payload: a run of AD structures, sometimes padded, sometimes
/// with one length corrupted to overrun the buffer.
fn structured(rng: &mut Rng) -> Vec<u8> {
    const TYPES: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x16, 0x19, 0x20, 0x21, 0xFF,
        0x3D, 0x2A, 0x24,
    ];
    let mut out = Vec::new();
    for _ in 0..rng.below(6) {
        let ad_type = TYPES[rng.below(TYPES.len() as u64) as usize];
        let payload = rng.below(24) as usize;
        out.push(u8::try_from(payload + 1).expect("small"));
        out.push(ad_type);
        out.extend(rng.bytes(payload));
    }
    match rng.below(4) {
        0 => out.extend(std::iter::repeat_n(0u8, rng.below(8) as usize)),
        1 if !out.is_empty() => {
            // Corrupt the first length byte to overrun the buffer.
            out[0] = out[0].saturating_add(1 + rng.byte() % 40);
        }
        _ => {}
    }
    out
}

fn ibeacon() -> Vec<u8> {
    let mut v = vec![0x1A, 0xFF, 0x4C, 0x00, 0x02, 0x15];
    v.extend(1u8..=16);
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xC5]);
    v
}

fn eddystone(frame: &[u8]) -> Vec<u8> {
    let mut v = vec![
        u8::try_from(frame.len() + 3).expect("small"),
        0x16,
        0xAA,
        0xFE,
    ];
    v.extend_from_slice(frame);
    v
}

fn eddystone_url() -> Vec<u8> {
    eddystone(&[0x10, 0xEE, 0x03, b'h', b's', b'e', 0x00])
}

fn eddystone_uid() -> Vec<u8> {
    let mut frame = vec![0x00u8, 0xEE];
    frame.extend(0u8..16); // 10-byte namespace + 6-byte instance
    eddystone(&frame)
}

fn eddystone_tlm() -> Vec<u8> {
    let mut frame = vec![0x20u8, 0x00];
    frame.extend_from_slice(&3300u16.to_be_bytes());
    frame.extend_from_slice(&0x1980i16.to_be_bytes());
    frame.extend_from_slice(&7u32.to_be_bytes());
    frame.extend_from_slice(&9u32.to_be_bytes());
    eddystone(&frame)
}

fn mutate(rng: &mut Rng, mut v: Vec<u8>) -> Vec<u8> {
    for _ in 0..=rng.below(3) {
        match rng.below(4) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len() as u64) as usize;
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let keep = rng.below(v.len() as u64) as usize;
                v.truncate(keep);
            }
            2 => {
                let extra = rng.below(6) as usize;
                v.extend(rng.bytes(extra));
            }
            _ if !v.is_empty() => {
                let i = rng.below(v.len() as u64) as usize;
                v[i] = rng.byte();
            }
            _ => {}
        }
    }
    v
}

#[test]
fn decoder_matches_the_reference_and_never_panics() {
    const ITERATIONS: u64 = 200_000;
    let mut rng = Rng::new(0x00AD_5EED_B1E5_0001);
    let mut families = [0u64; 3];
    let mut beacons = 0u64;
    for n in 0..ITERATIONS {
        let data = match n % 3 {
            0 => {
                let len = rng.below(72) as usize;
                rng.bytes(len)
            }
            1 => structured(&mut rng),
            _ => {
                let base = match rng.below(4) {
                    0 => ibeacon(),
                    1 => eddystone_url(),
                    2 => eddystone_uid(),
                    _ => eddystone_tlm(),
                };
                mutate(&mut rng, base)
            }
        };
        families[(n % 3) as usize] += 1;
        if adv::decode(&data).beacon.is_some() {
            beacons += 1;
        }
        if let Err(e) = check(&data) {
            panic!("iteration {n}: {e}");
        }
    }
    // The campaign must actually have exercised recognition, not only noise.
    assert!(beacons > 1_000, "only {beacons} beacons recognised");
    assert!(families.iter().all(|&c| c > 60_000), "{families:?}");
}

#[test]
fn every_truncation_of_a_valid_beacon_is_safe_and_honest() {
    for base in [ibeacon(), eddystone_url()] {
        for cut in 0..=base.len() {
            let data = &base[..cut];
            check(data).unwrap_or_else(|e| panic!("cut {cut}: {e}"));
            // A beacon is recognised only from the complete frame.
            let recognised = adv::decode(data).beacon.is_some();
            assert_eq!(
                recognised,
                cut == base.len(),
                "cut {cut} of {}",
                hex_encode(&base)
            );
        }
    }
}

#[test]
fn falsification_a_reference_without_the_terminator_is_caught() {
    // Flags, zero padding, then bytes that would parse as a name if the
    // terminator were ignored: the correct decoder stops at the zero.
    let data = [0x02, 0x01, 0x06, 0x00, 0x03, 0x09, b'h', b'i'];
    let report = adv::decode(&data);
    assert_eq!(project(&report), reference(&data, true));
    assert_ne!(
        project(&report),
        reference(&data, false),
        "the comparison must detect a walker that skips the terminator"
    );
}
