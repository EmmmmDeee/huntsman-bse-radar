//! Property and fuzz-style regression tests for the reconstructed domain core.
//!
//! These exercise true invariants over large randomized input sweeps using a
//! deterministic, dependency-free PRNG (the workspace forbids third-party
//! crates, so `proptest`/`quickcheck` are intentionally not used). The sweeps
//! permanently lock in the falsification methodology that originally surfaced
//! the haversine domain bug (COR-010), the bearing range bug (COR-011), the
//! `LatLon` validation gap (COR-012), and the antimeridian averaging bug
//! (COR-013): a fresh reintroduction of any of those classes fails here.

use bleradar_core::{
    Confidence, DeviceObservation, DeviceTrack, EstimateKind, GeoError, LatLon, ProximityBand,
    RssiEma, bearing_deg, ble_distance_m, haversine_m, proximity_label,
    proximity_label_from_distance_m, wifi_channel_to_frequency, wifi_frequency_to_channel,
};

/// Deterministic xorshift64 generator. Seeds are fixed per test so failures
/// reproduce exactly.
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform in [0, 1) using the top 53 bits.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in [lo, hi).
    fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + self.unit() * (hi - lo)
    }
}

// Kept in sync with `geo.rs::haversine_m`'s private constant (BF-002 fixed
// this to the IUGG/WGS84 mean radius, matching the oracle exactly).
const EARTH_RADIUS_M: f64 = 6_371_008.8;

#[test]
fn prop_haversine_is_finite_nonnegative_bounded_and_symmetric() {
    let mut rng = Rng::new(0x1234_5678_9abc_def1);
    let max_distance = std::f64::consts::PI * EARTH_RADIUS_M + 1.0;
    for _ in 0..100_000 {
        let a = LatLon::new(rng.range(-90.0, 90.0), rng.range(-180.0, 180.0)).unwrap();
        let b = LatLon::new(rng.range(-90.0, 90.0), rng.range(-180.0, 180.0)).unwrap();
        let d = haversine_m(a, b);
        assert!(d.is_finite(), "distance not finite for {a:?} -> {b:?}");
        assert!(d >= 0.0, "negative distance {d}");
        assert!(d <= max_distance, "distance {d} exceeds half-circumference");
        assert!(
            (d - haversine_m(b, a)).abs() < 1e-6,
            "asymmetric distance for {a:?} <-> {b:?}"
        );
        assert_eq!(haversine_m(a, a), 0.0, "self-distance not zero for {a:?}");
    }
}

#[test]
fn prop_bearing_stays_in_documented_range() {
    let mut rng = Rng::new(0x0bad_c0de_dead_beef);
    for _ in 0..100_000 {
        let a = LatLon::new(rng.range(-90.0, 90.0), rng.range(-180.0, 180.0)).unwrap();
        let b = LatLon::new(rng.range(-90.0, 90.0), rng.range(-180.0, 180.0)).unwrap();
        let bearing = bearing_deg(a, b);
        assert!(
            (0.0..360.0).contains(&bearing),
            "bearing {bearing} outside [0, 360) for {a:?} -> {b:?}"
        );
    }
}

#[test]
fn prop_latlon_new_enforces_its_invariant() {
    let mut rng = Rng::new(0x00c0_ffee_0000_0001);
    for _ in 0..100_000 {
        let (lat, lon) = match rng.next_u64() % 4 {
            0 => (rng.range(-90.0, 90.0), rng.range(-180.0, 180.0)),
            1 => (rng.range(-1000.0, 1000.0), rng.range(-1000.0, 1000.0)),
            2 => (f64::NAN, rng.range(-180.0, 180.0)),
            _ => (rng.range(-90.0, 90.0), f64::INFINITY),
        };
        match LatLon::new(lat, lon) {
            Ok(p) => {
                assert!(p.lat().is_finite() && p.lon().is_finite());
                assert!((-90.0..=90.0).contains(&p.lat()));
                assert!((-180.0..=180.0).contains(&p.lon()));
            }
            Err(GeoError::NonFinite) => {
                assert!(!lat.is_finite() || !lon.is_finite());
            }
            Err(GeoError::OutOfRange) => {
                assert!(lat.is_finite() && lon.is_finite());
                assert!(
                    !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon),
                    "OutOfRange for an in-range coordinate {lat}, {lon}"
                );
            }
        }
    }
}

#[test]
fn prop_rssi_ema_output_is_finite_and_bounded_by_samples() {
    let mut rng = Rng::new(0xfeed_face_cafe_0001);
    for _ in 0..20_000 {
        let mut ema = RssiEma::new(rng.range(f64::EPSILON, 1.0)).unwrap();
        let mut lo = f64::INFINITY;
        let mut hi = f64::NEG_INFINITY;
        let samples = 1 + (rng.next_u64() % 32);
        for _ in 0..samples {
            let sample = rng.range(-120.0, 0.0);
            lo = lo.min(sample);
            hi = hi.max(sample);
            let out = ema.push(sample).unwrap();
            assert!(out.is_finite(), "EMA produced non-finite output");
            assert!(
                out >= lo - 1e-9 && out <= hi + 1e-9,
                "EMA {out} escaped the sample envelope [{lo}, {hi}]"
            );
        }
    }
}

#[test]
fn prop_proximity_band_is_monotonic_in_signal_strength() {
    fn closeness(band: ProximityBand) -> u8 {
        match band {
            ProximityBand::Immediate => 3,
            ProximityBand::Near => 2,
            ProximityBand::Mid => 1,
            ProximityBand::Far => 0,
        }
    }
    let mut rng = Rng::new(0x5151_5151_5151_5151);
    for _ in 0..100_000 {
        let r1 = rng.range(-120.0, -20.0);
        let r2 = rng.range(-120.0, -20.0);
        let (stronger, weaker) = if r1 >= r2 { (r1, r2) } else { (r2, r1) };
        assert!(
            closeness(proximity_label(stronger).expect("finite stronger RSSI"))
                >= closeness(proximity_label(weaker).expect("finite weaker RSSI")),
            "stronger signal {stronger} classified farther than {weaker}"
        );
    }
}

#[test]
fn prop_distance_proximity_band_is_monotonic() {
    fn distance_order(band: ProximityBand) -> u8 {
        match band {
            ProximityBand::Immediate => 0,
            ProximityBand::Near => 1,
            ProximityBand::Mid => 2,
            ProximityBand::Far => 3,
        }
    }
    let bands = [
        proximity_label_from_distance_m(0.0).unwrap(),
        proximity_label_from_distance_m(1.0).unwrap(),
        proximity_label_from_distance_m(2.0).unwrap(),
        proximity_label_from_distance_m(5.0).unwrap(),
        proximity_label_from_distance_m(25.0).unwrap(),
    ];
    for window in bands.windows(2) {
        assert!(distance_order(window[0]) <= distance_order(window[1]));
    }
}

#[test]
fn prop_ble_distance_is_positive_and_monotonic_in_rssi() {
    let mut rng = Rng::new(0xabcd_ef01_2345_6789);
    for _ in 0..100_000 {
        let at_1m = rng.range(-80.0, -40.0);
        let path_loss = rng.range(1.5, 4.0);
        let r1 = rng.range(-120.0, -20.0);
        let r2 = rng.range(-120.0, -20.0);
        let d1 = ble_distance_m(r1, at_1m, path_loss).unwrap();
        let d2 = ble_distance_m(r2, at_1m, path_loss).unwrap();
        assert!(d1.is_finite() && d1 > 0.0);
        assert!(d2.is_finite() && d2 > 0.0);
        // A weaker (more negative) RSSI must never estimate as closer.
        if r1 <= r2 {
            assert!(d1 >= d2 - 1e-6, "weaker {r1} closer than {r2}");
        } else {
            assert!(d2 >= d1 - 1e-6, "weaker {r2} closer than {r1}");
        }
    }
}

#[test]
fn prop_ble_distance_returns_only_positive_finite_estimates_at_numeric_boundaries() {
    let rssi_values = [
        f64::MIN,
        -1.0,
        -f64::MIN_POSITIVE,
        0.0,
        f64::MIN_POSITIVE,
        1.0,
        f64::MAX,
    ];
    let path_loss_values = [f64::MIN_POSITIVE, 1.0, 2.0, f64::MAX];

    for rssi in rssi_values {
        for reference in rssi_values {
            for path_loss in path_loss_values {
                if let Some(distance) = ble_distance_m(rssi, reference, path_loss) {
                    assert!(
                        distance.is_finite() && distance > 0.0,
                        "invalid distance {distance} for ({rssi}, {reference}, {path_loss})"
                    );
                }
            }
        }
    }
}

#[test]
fn prop_track_push_and_spatial_estimate_stay_valid() {
    let mut rng = Rng::new(0x9e37_79b9_7f4a_7c15);
    for _ in 0..20_000 {
        let mut track = DeviceTrack::new(rng.range(f64::EPSILON, 1.0)).unwrap();
        let base_lat = rng.range(-80.0, 80.0);
        // Force a known fraction of clusters onto the ±180 meridian so that
        // longitude wrapping below yields genuinely straddling observations
        // every time — random longitudes almost never land within 0.001° of
        // the antimeridian, which would leave COR-013 unexercised.
        let base_lon = match rng.next_u64() % 4 {
            0 => 180.0,
            1 => -180.0,
            _ => rng.range(-180.0, 180.0),
        };
        let count = 2 + (rng.next_u64() % 20);
        let mut timestamp = 0u64;
        let mut first_pos: Option<LatLon> = None;
        for _ in 0..count {
            timestamp += 1 + rng.next_u64() % 5;
            let lat = (base_lat + rng.range(-0.001, 0.001)).clamp(-90.0, 90.0);
            // Wrap longitude across the antimeridian instead of clamping, so a
            // cluster near ±180 contains genuinely straddling observations.
            let mut lon = base_lon + rng.range(-0.001, 0.001);
            if lon > 180.0 {
                lon -= 360.0;
            } else if lon < -180.0 {
                lon += 360.0;
            }
            let pos = LatLon::new(lat, lon).unwrap();
            if first_pos.is_none() {
                first_pos = Some(pos);
            }
            track
                .push(DeviceObservation {
                    timestamp_ms: timestamp,
                    observer_position: Some(pos),
                    gps_accuracy_m: Some(rng.range(1.0, 30.0)),
                    rssi_dbm: rng.range(-110.0, -30.0),
                    tx_power_dbm: None,
                })
                .unwrap();
        }
        for point in track.observed_map_points() {
            assert_eq!(point.kind, EstimateKind::Observed);
        }
        if let Some(estimate) = track.spatial_estimate() {
            assert!(estimate.center.lat().is_finite() && estimate.center.lon().is_finite());
            assert!((-90.0..=90.0).contains(&estimate.center.lat()));
            assert!((-180.0..=180.0).contains(&estimate.center.lon()));
            assert!(estimate.uncertainty_m.is_finite() && estimate.uncertainty_m >= 1.0);
            assert!(estimate.confidence.value() <= 100);
            assert!(estimate.supporting_observations >= 2);
            // The cluster spans ~111 m, so the estimate must stay local to it.
            // A linear longitude mean across the antimeridian would place the
            // centre ~20,000 km away (COR-013); these bounds separate the two.
            let base = first_pos.unwrap();
            let offset = haversine_m(estimate.center, base);
            assert!(offset < 50_000.0, "estimate is {offset} m from its cluster");
            assert!(
                estimate.uncertainty_m < 100_000.0,
                "uncertainty {} m implausible for a local cluster",
                estimate.uncertainty_m
            );
        }
    }
}

#[test]
fn prop_confidence_is_clamped_to_100() {
    let mut rng = Rng::new(0x0102_0304_0506_0708);
    for _ in 0..50_000 {
        let raw = (rng.next_u64() & 0xff) as u8;
        assert!(Confidence::new(raw).value() <= 100);
    }
}

#[test]
fn prop_wifi_channel_frequency_roundtrips_over_full_range() {
    for channel in (1..=14u16).chain(32..=177u16) {
        if let Some(freq) = wifi_channel_to_frequency(channel) {
            assert_eq!(
                wifi_frequency_to_channel(freq),
                Some(channel),
                "channel {channel} did not round-trip via {freq} MHz"
            );
        }
    }
}
