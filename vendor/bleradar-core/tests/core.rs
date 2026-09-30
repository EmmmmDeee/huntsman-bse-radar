//! Behavioral regression tests for the reconstructed BLE Radar domain core.

use bleradar_core::{
    AddressKind, CalibrationProfile, DeviceIdentity, DeviceObservation, DeviceTrack, EstimateKind,
    FreshnessClass, GeoError, IdentityEvidence, LatLon, ProximityBand, RssiEma, SelectedDevice,
    SignalTrend, TrackError, TrackingProfile, TrackingSnapshotInput, bearing_deg, ble_distance_m,
    ble_distance_range_m, calibration_profile, calibration_profile_from_ordinal, canonical_mac,
    filtered_rssi, haversine_m, is_locally_administered, proximity_label,
    proximity_label_from_distance_m, signal_confidence_percent, signal_trend, tracking_profile,
    tracking_profile_from_ordinal, tracking_snapshot, wifi_channel_to_frequency,
    wifi_frequency_to_channel,
};

/// Builds a `DeviceObservation` from its varying fields; `tx_power_dbm` is
/// always `None` across these tests.
fn observation(
    timestamp_ms: u64,
    observer_position: Option<LatLon>,
    gps_accuracy_m: Option<f64>,
    rssi_dbm: f64,
) -> DeviceObservation {
    DeviceObservation {
        timestamp_ms,
        observer_position,
        gps_accuracy_m,
        rssi_dbm,
        tx_power_dbm: None,
    }
}

#[test]
fn zero_distance_is_zero() {
    let p = LatLon::new(-26.8, 152.8).unwrap();
    assert_eq!(haversine_m(p, p), 0.0);
}

#[test]
fn haversine_is_finite_at_near_antipodal_points() {
    // Reproducer found by randomized falsification (3,525 NaN results in 60M
    // near-antipodal samples of the unclamped formula): floating error pushes
    // the haversine term above 1.0 and asin leaves its domain.
    let a = LatLon::new(58.533_453_260_712_69, -79.146_585_029_992_61).unwrap();
    let b = LatLon::new(-58.533_453_260_712_285, 100.853_414_970_007_24).unwrap();
    let d = haversine_m(a, b);
    assert!(d.is_finite());
    // Near-antipodal separation is close to half the great circle (BF-002
    // fixed the radius to 6,371,008.8 m; the 5 km tolerance dwarfs that
    // ~27 m shift, but the literal is kept in sync for clarity).
    assert!((d - std::f64::consts::PI * 6_371_008.8).abs() < 5_000.0);
}

#[test]
fn bearing_stays_in_documented_range() {
    // rem_euclid rounds a tiny negative angle up to exactly 360.0, violating
    // the documented [0, 360) contract without the fold-back.
    let a = LatLon::new(0.0, 0.0).unwrap();
    let b = LatLon::new(1.0e-9, -1.0e-300).unwrap();
    let bearing = bearing_deg(a, b);
    assert!((0.0..360.0).contains(&bearing));
}

#[test]
fn latlon_rejects_invalid_input() {
    assert_eq!(LatLon::new(f64::NAN, 0.0), Err(GeoError::NonFinite));
    assert_eq!(LatLon::new(0.0, f64::INFINITY), Err(GeoError::NonFinite));
    assert_eq!(LatLon::new(90.1, 0.0), Err(GeoError::OutOfRange));
    assert_eq!(LatLon::new(0.0, -180.5), Err(GeoError::OutOfRange));
}

#[test]
fn bearing_north_is_zero() {
    let a = LatLon::new(0.0, 0.0).unwrap();
    let b = LatLon::new(1.0, 0.0).unwrap();
    assert!(bearing_deg(a, b).abs() < 1e-9);
}

#[test]
fn mac_canonicalization_and_local_bit() {
    assert_eq!(
        canonical_mac("36-32-62-36-31-33").as_deref(),
        Some("36:32:62:36:31:33")
    );
    assert_eq!(is_locally_administered("36:32:62:36:31:33"), Some(true));
    assert_eq!(is_locally_administered("00:11:22:33:44:55"), Some(false));
}

#[test]
fn randomized_address_is_not_stable_identity() {
    let identity = DeviceIdentity::new("36:32:62:36:31:33", IdentityEvidence::default()).unwrap();
    assert_eq!(identity.address_kind, AddressKind::Randomized);
}

#[test]
fn wifi_channel_round_trip() {
    assert_eq!(wifi_channel_to_frequency(1), Some(2412));
    assert_eq!(wifi_channel_to_frequency(14), Some(2484));
    assert_eq!(wifi_frequency_to_channel(2412), Some(1));
    assert_eq!(wifi_frequency_to_channel(2484), Some(14));
}

#[test]
fn ema_and_trend_are_deterministic() {
    let mut f = RssiEma::new(0.5).unwrap();
    assert_eq!(f.push(-80.0).unwrap(), -80.0);
    assert_eq!(f.push(-60.0).unwrap(), -70.0);
    assert_eq!(signal_trend(-80.0, -70.0, 2.0), Some(SignalTrend::Stronger));
    assert_eq!(signal_trend(f64::NAN, -70.0, 2.0), None);
    assert_eq!(signal_trend(-80.0, f64::INFINITY, 2.0), None);
    assert_eq!(signal_trend(-80.0, -70.0, f64::NAN), None);
}

#[test]
fn distance_model_is_calibrated_not_absolute() {
    assert!((ble_distance_m(-59.0, -59.0, 2.0).unwrap() - 1.0).abs() < 1e-12);
    assert!(ble_distance_m(-70.0, -59.0, 0.0).is_none());
}

#[test]
fn distance_model_rejects_unrepresentable_results() {
    assert!(ble_distance_m(-f64::MAX, f64::MAX, 2.0).is_none());
    assert!(ble_distance_m(f64::MAX, -f64::MAX, 2.0).is_none());
    assert!(ble_distance_m(-70.0, -59.0, f64::MIN_POSITIVE).is_none());
}

#[test]
fn filtered_rssi_bootstraps_and_then_applies_ema() {
    assert_eq!(filtered_rssi(f64::NAN, -80.0, 0.5), Some(-80.0));
    assert_eq!(filtered_rssi(-80.0, -60.0, 0.5), Some(-70.0));
}

#[test]
fn ema_rejects_invalid_samples_without_mutating_state() {
    let mut ema = RssiEma::new(0.5).unwrap();
    assert_eq!(ema.push(-80.0), Ok(-80.0));
    assert_eq!(
        ema.push(f64::NAN),
        Err(bleradar_core::FilterError::NonFiniteSample)
    );
    assert_eq!(ema.value(), Some(-80.0));
    assert_eq!(filtered_rssi(-80.0, f64::INFINITY, 0.5), None);
}

#[test]
fn distance_range_expands_around_the_estimate() {
    let (near, far) = ble_distance_range_m(-59.0, 6.0, -59.0, 2.0).unwrap();
    assert!(near < 1.0);
    assert!(far > 1.0);
    assert!(near < far);
}

#[test]
fn distance_range_rejects_invalid_spread() {
    assert!(ble_distance_range_m(-59.0, -1.0, -59.0, 2.0).is_none());
    assert!(ble_distance_range_m(-59.0, f64::NAN, -59.0, 2.0).is_none());
}

#[test]
fn signal_confidence_rewards_stability_and_sample_support() {
    let low = signal_confidence_percent(1, 10.0).unwrap();
    let high = signal_confidence_percent(12, 1.5).unwrap();
    assert!(high > low);
    assert_eq!(high, 100);
}

#[test]
fn signal_confidence_rejects_invalid_spread() {
    assert!(signal_confidence_percent(1, -1.0).is_none());
    assert!(signal_confidence_percent(1, f64::INFINITY).is_none());
}

#[test]
fn calibration_profiles_are_stable_and_distinct() {
    assert_eq!(
        calibration_profile_from_ordinal(0),
        Some(CalibrationProfile::Baseline)
    );
    assert_eq!(
        calibration_profile_from_ordinal(1),
        Some(CalibrationProfile::Indoor)
    );
    assert_eq!(
        calibration_profile_from_ordinal(2),
        Some(CalibrationProfile::OpenSpace)
    );
    assert_eq!(calibration_profile_from_ordinal(99), None);

    let baseline = calibration_profile(CalibrationProfile::Baseline);
    let indoor = calibration_profile(CalibrationProfile::Indoor);
    let open = calibration_profile(CalibrationProfile::OpenSpace);
    assert_eq!(baseline.rssi_at_1m_dbm, -59.0);
    assert_eq!(baseline.path_loss_exponent, 2.0);
    assert!(indoor.path_loss_exponent > baseline.path_loss_exponent);
    assert!(open.path_loss_exponent < baseline.path_loss_exponent);
}

#[test]
fn tracking_profiles_are_stable_and_distinct() {
    assert_eq!(
        tracking_profile_from_ordinal(0),
        Some(TrackingProfile::Standard)
    );
    assert_eq!(
        tracking_profile_from_ordinal(1),
        Some(TrackingProfile::Responsive)
    );
    assert_eq!(tracking_profile_from_ordinal(99), None);

    let standard = tracking_profile(TrackingProfile::Standard);
    let responsive = tracking_profile(TrackingProfile::Responsive);
    assert_eq!(standard.rssi_alpha, 0.35);
    assert_eq!(standard.trend_deadband_db, 3.0);
    assert!(responsive.rssi_alpha > standard.rssi_alpha);
    assert!(responsive.trend_deadband_db < standard.trend_deadband_db);
}

#[test]
fn tracking_snapshot_derives_a_coherent_bundle() {
    let snapshot = tracking_snapshot(TrackingSnapshotInput {
        previous_filtered_rssi_dbm: -80.0,
        current_rssi_dbm: -60.0,
        rssi_spread_db: 4.0,
        sample_count: 6,
        calibration_profile: CalibrationProfile::Baseline,
        tracking_profile: TrackingProfile::Responsive,
        age_ms: 1_000,
        tx_power_dbm: None,
    })
    .unwrap();
    assert!((snapshot.filtered_rssi_dbm - (-69.0)).abs() < 1e-9);
    assert_eq!(snapshot.trend, SignalTrend::Stronger);
    assert_eq!(snapshot.proximity, ProximityBand::Mid);
    assert_eq!(snapshot.distance_proximity, Some(ProximityBand::Mid));
    assert!(snapshot.distance_m.unwrap() > 1.0);
    assert!(snapshot.distance_lower_bound_m.unwrap() < snapshot.distance_m.unwrap());
    assert!(snapshot.distance_upper_bound_m.unwrap() > snapshot.distance_m.unwrap());
    assert!(snapshot.confidence_percent.unwrap() > 0);
    assert_eq!(snapshot.freshness, FreshnessClass::Live);
}

#[test]
fn tracking_snapshot_keeps_distance_proximity_distinct_from_rssi_proximity() {
    let snapshot = tracking_snapshot(TrackingSnapshotInput {
        previous_filtered_rssi_dbm: f64::NAN,
        current_rssi_dbm: -59.0,
        rssi_spread_db: 0.0,
        sample_count: 1,
        calibration_profile: CalibrationProfile::Baseline,
        tracking_profile: TrackingProfile::Standard,
        age_ms: 0,
        tx_power_dbm: None,
    })
    .unwrap();
    assert_eq!(snapshot.proximity, ProximityBand::Near);
    assert_eq!(snapshot.distance_proximity, Some(ProximityBand::Immediate));
}

#[test]
fn tracking_snapshot_bootstraps_and_classifies_stale_observations() {
    let snapshot = tracking_snapshot(TrackingSnapshotInput {
        previous_filtered_rssi_dbm: f64::NAN,
        current_rssi_dbm: -59.0,
        rssi_spread_db: 0.0,
        sample_count: 1,
        calibration_profile: CalibrationProfile::Baseline,
        tracking_profile: TrackingProfile::Standard,
        age_ms: 31_000,
        tx_power_dbm: None,
    })
    .unwrap();
    assert_eq!(snapshot.filtered_rssi_dbm, -59.0);
    assert_eq!(snapshot.trend, SignalTrend::Stable);
    assert_eq!(snapshot.freshness, FreshnessClass::Stale);
}

#[test]
fn tracking_snapshot_keeps_filtered_signal_when_spread_is_invalid() {
    // Live repro (2026-09-09): invalid rssi_spread_db previously short-circuited
    // the entire snapshot via `?`, erasing a finite filtered RSSI/trend/
    // proximity/freshness bundle. Bounds and confidence must fail alone.
    let base = TrackingSnapshotInput {
        previous_filtered_rssi_dbm: -70.0,
        current_rssi_dbm: -68.0,
        rssi_spread_db: 3.0,
        sample_count: 5,
        calibration_profile: CalibrationProfile::Baseline,
        tracking_profile: TrackingProfile::Standard,
        age_ms: 1_000,
        tx_power_dbm: None,
    };
    assert!(tracking_snapshot(base).is_some());

    for spread in [f64::NAN, -1.0, f64::INFINITY] {
        let mut input = base;
        input.rssi_spread_db = spread;
        let snapshot = tracking_snapshot(input).unwrap_or_else(|| {
            panic!("invalid spread {spread:?} erased the filtered-signal snapshot")
        });
        assert!(snapshot.filtered_rssi_dbm.is_finite());
        assert!(snapshot.distance_m.is_some());
        assert_eq!(snapshot.distance_lower_bound_m, None);
        assert_eq!(snapshot.distance_upper_bound_m, None);
        assert_eq!(snapshot.distance_proximity, Some(ProximityBand::Mid));
        assert_eq!(snapshot.confidence_percent, None);
        assert_eq!(snapshot.freshness, FreshnessClass::Live);
    }
}

#[test]
fn tracking_snapshot_prefers_plausible_device_tx_power_over_profile_calibration() {
    // Baseline profile calibration is -59.0 dBm at 1 m / exponent 2.0. A
    // device that advertises a materially different, plausible TX power
    // (-70.0 dBm) must shift the calibrated distance away from the profile-only
    // estimate, proving the per-device override actually reaches `ble_distance_m`.
    let without_tx_power = tracking_snapshot(TrackingSnapshotInput {
        previous_filtered_rssi_dbm: f64::NAN,
        current_rssi_dbm: -70.0,
        rssi_spread_db: 0.0,
        sample_count: 1,
        calibration_profile: CalibrationProfile::Baseline,
        tracking_profile: TrackingProfile::Standard,
        age_ms: 0,
        tx_power_dbm: None,
    })
    .unwrap();
    let with_tx_power = tracking_snapshot(TrackingSnapshotInput {
        previous_filtered_rssi_dbm: f64::NAN,
        current_rssi_dbm: -70.0,
        rssi_spread_db: 0.0,
        sample_count: 1,
        calibration_profile: CalibrationProfile::Baseline,
        tracking_profile: TrackingProfile::Standard,
        age_ms: 0,
        tx_power_dbm: Some(-70.0),
    })
    .unwrap();
    // Matching the reference RSSI at exactly the device's own calibrated
    // 1 m power collapses the estimate to 1 m, unlike the generic profile.
    assert!((with_tx_power.distance_m.unwrap() - 1.0).abs() < 1e-9);
    assert!(with_tx_power.distance_m.unwrap() < without_tx_power.distance_m.unwrap());
}

#[test]
fn tracking_snapshot_ignores_implausible_or_absent_device_tx_power() {
    let profile_only = tracking_snapshot(TrackingSnapshotInput {
        previous_filtered_rssi_dbm: f64::NAN,
        current_rssi_dbm: -70.0,
        rssi_spread_db: 0.0,
        sample_count: 1,
        calibration_profile: CalibrationProfile::Baseline,
        tracking_profile: TrackingProfile::Standard,
        age_ms: 0,
        tx_power_dbm: None,
    })
    .unwrap();
    for implausible in [f64::NAN, f64::INFINITY, 127.0, -101.0, 21.0] {
        let snapshot = tracking_snapshot(TrackingSnapshotInput {
            previous_filtered_rssi_dbm: f64::NAN,
            current_rssi_dbm: -70.0,
            rssi_spread_db: 0.0,
            sample_count: 1,
            calibration_profile: CalibrationProfile::Baseline,
            tracking_profile: TrackingProfile::Standard,
            age_ms: 0,
            tx_power_dbm: Some(implausible),
        })
        .unwrap();
        assert_eq!(
            snapshot.distance_m, profile_only.distance_m,
            "implausible tx_power_dbm {implausible:?} should fall back to profile calibration"
        );
    }
}

#[test]
fn effective_rssi_at_1m_dbm_prefers_plausible_tx_power() {
    use bleradar_core::effective_rssi_at_1m_dbm;
    assert_eq!(effective_rssi_at_1m_dbm(Some(-63.0), -59.0), -63.0);
    assert_eq!(effective_rssi_at_1m_dbm(None, -59.0), -59.0);
    assert_eq!(effective_rssi_at_1m_dbm(Some(f64::NAN), -59.0), -59.0);
    assert_eq!(effective_rssi_at_1m_dbm(Some(f64::INFINITY), -59.0), -59.0);
    // Android's `ScanResult.TX_POWER_NOT_PRESENT` sentinel is out of range.
    assert_eq!(effective_rssi_at_1m_dbm(Some(127.0), -59.0), -59.0);
    // Boundary values are inclusive.
    assert_eq!(effective_rssi_at_1m_dbm(Some(-100.0), -59.0), -100.0);
    assert_eq!(effective_rssi_at_1m_dbm(Some(20.0), -59.0), 20.0);
    assert_eq!(effective_rssi_at_1m_dbm(Some(-100.1), -59.0), -59.0);
    assert_eq!(effective_rssi_at_1m_dbm(Some(20.1), -59.0), -59.0);
}

#[test]
fn proximity_label_rejects_non_finite_rssi() {
    assert_eq!(proximity_label(-40.0), Some(ProximityBand::Immediate));
    assert_eq!(proximity_label(-95.0), Some(ProximityBand::Far));
    assert_eq!(proximity_label(f64::NAN), None);
    assert_eq!(proximity_label(f64::INFINITY), None);
    assert_eq!(proximity_label(f64::NEG_INFINITY), None);
}

#[test]
fn distance_proximity_label_preserves_boundaries_and_invalid_inputs() {
    assert_eq!(
        proximity_label_from_distance_m(0.0),
        Some(ProximityBand::Immediate)
    );
    assert_eq!(
        proximity_label_from_distance_m(1.0),
        Some(ProximityBand::Immediate)
    );
    assert_eq!(
        proximity_label_from_distance_m(1.000_001),
        Some(ProximityBand::Near)
    );
    assert_eq!(
        proximity_label_from_distance_m(2.0),
        Some(ProximityBand::Near)
    );
    assert_eq!(
        proximity_label_from_distance_m(2.000_001),
        Some(ProximityBand::Mid)
    );
    assert_eq!(
        proximity_label_from_distance_m(5.0),
        Some(ProximityBand::Mid)
    );
    assert_eq!(
        proximity_label_from_distance_m(5.000_001),
        Some(ProximityBand::Far)
    );
    assert_eq!(
        proximity_label_from_distance_m(25.0),
        Some(ProximityBand::Far)
    );
    assert_eq!(proximity_label_from_distance_m(-1.0), None);
    assert_eq!(proximity_label_from_distance_m(f64::NAN), None);
    assert_eq!(proximity_label_from_distance_m(f64::INFINITY), None);
}

#[test]
fn track_rejects_time_reversal() {
    let mut track = DeviceTrack::new(0.5).unwrap();
    let p = LatLon::new(-26.8, 152.8).unwrap();
    track
        .push(observation(10, Some(p), Some(5.0), -70.0))
        .unwrap();
    let err = track
        .push(observation(9, Some(p), Some(5.0), -69.0))
        .unwrap_err();
    assert_eq!(err, TrackError::NonMonotonicTime);
}

#[test]
fn map_points_remain_observed_not_inferred() {
    let mut track = DeviceTrack::new(0.5).unwrap();
    let p = LatLon::new(-26.8, 152.8).unwrap();
    track
        .push(observation(1, Some(p), Some(4.0), -55.0))
        .unwrap();
    let points = track.observed_map_points();
    assert_eq!(points.len(), 1);
    assert_eq!(points[0].kind, EstimateKind::Observed);
}

#[test]
fn map_point_confidence_preserves_accuracy_tiers() {
    let position = LatLon::new(-26.8, 152.8).unwrap();
    let cases = [
        (3.0, 95),
        (5.0, 90),
        (10.0, 80),
        (20.0, 65),
        (50.0, 45),
        (50.1, 25),
    ];
    for (accuracy_m, expected_confidence) in cases {
        let mut track = DeviceTrack::new(0.5).unwrap();
        track
            .push(observation(1, Some(position), Some(accuracy_m), -55.0))
            .unwrap();
        assert_eq!(
            track.observed_map_points()[0].confidence.value(),
            expected_confidence,
            "unexpected confidence for {accuracy_m}m accuracy"
        );
    }
}

#[test]
fn stronger_samples_produce_hotter_state() {
    let mut track = DeviceTrack::new(0.5).unwrap();
    track.push(observation(1, None, None, -80.0)).unwrap();
    track.push(observation(2, None, None, -50.0)).unwrap();
    assert_eq!(track.trend(), SignalTrend::Stronger);
    assert_eq!(track.proximity(), Some(ProximityBand::Near));
}

#[test]
fn spatial_estimate_requires_multiple_positioned_observations() {
    let mut track = DeviceTrack::new(0.4).unwrap();
    let a = LatLon::new(-26.8000, 152.8000).unwrap();
    let b = LatLon::new(-26.8001, 152.8001).unwrap();
    track
        .push(observation(1, Some(a), Some(5.0), -65.0))
        .unwrap();
    assert!(track.spatial_estimate().is_none());
    track
        .push(observation(2, Some(b), Some(5.0), -55.0))
        .unwrap();
    let estimate = track.spatial_estimate().unwrap();
    assert_eq!(estimate.supporting_observations, 2);
    assert!(estimate.uncertainty_m > 0.0);
    // The center of two ~15 m-apart observations must stay local to them.
    assert!(haversine_m(estimate.center, a) < 1_000.0);
}

#[test]
fn spatial_estimate_handles_antimeridian_straddling() {
    // Two observations ~111 m apart across the ±180° meridian. A linear
    // longitude mean places the center near lon 0 — the far side of the
    // planet — instead of near ±180.
    let mut track = DeviceTrack::new(0.5).unwrap();
    let east = LatLon::new(0.0, 179.9995).unwrap();
    let west = LatLon::new(0.0, -179.9995).unwrap();
    track
        .push(observation(1, Some(east), Some(5.0), -60.0))
        .unwrap();
    track
        .push(observation(2, Some(west), Some(5.0), -60.0))
        .unwrap();
    let estimate = track.spatial_estimate().unwrap();
    let true_midpoint = LatLon::new(0.0, 180.0).unwrap();
    assert!(haversine_m(estimate.center, true_midpoint) < 1_000.0);
    assert!(estimate.uncertainty_m < 10_000.0);
}

#[test]
fn spatial_estimate_prefers_recent_position_fixes() {
    let mut track = DeviceTrack::new(0.5).unwrap();
    let old = LatLon::new(0.0, 0.0).unwrap();
    let recent = LatLon::new(0.0, 0.001).unwrap();
    track
        .push(observation(0, Some(old), Some(5.0), -60.0))
        .unwrap();
    track
        .push(observation(120_000, Some(recent), Some(5.0), -60.0))
        .unwrap();

    let estimate = track.spatial_estimate().unwrap();
    assert!(haversine_m(estimate.center, recent) < 20.0);
    assert!(haversine_m(estimate.center, old) > 80.0);
}

#[test]
fn spatial_estimate_uncertainty_contains_every_fix_error_radius() {
    let mut track = DeviceTrack::new(0.5).unwrap();
    let positions = [
        LatLon::new(0.0, 0.0).unwrap(),
        LatLon::new(0.0, 0.001).unwrap(),
        LatLon::new(0.0, 0.01).unwrap(),
    ];
    for (timestamp, position) in positions.into_iter().enumerate() {
        track
            .push(observation(
                timestamp as u64,
                Some(position),
                Some(3.0),
                -60.0,
            ))
            .unwrap();
    }

    let estimate = track.spatial_estimate().unwrap();
    let largest_error_radius = positions
        .into_iter()
        .map(|position| haversine_m(estimate.center, position) + 3.0)
        .fold(0.0, f64::max);
    assert!(estimate.uncertainty_m >= largest_error_radius);
}

#[test]
fn selection_lock_retains_history() {
    let mut selected = SelectedDevice::new("device-1", 0.5).unwrap();
    selected.start_tracking();
    assert!(selected.tracking);
    selected
        .track
        .push(observation(1, None, None, -70.0))
        .unwrap();
    selected.stop_tracking();
    assert!(!selected.tracking);
    // "Releases active tracking while retaining history" (tracking.rs docs)
    // is a claim about `track`, not just the `tracking` flag: unlocking must
    // not discard previously observed samples.
    assert_eq!(selected.track.observations().len(), 1);
    // History must keep accumulating even while unlocked.
    selected
        .track
        .push(observation(2, None, None, -65.0))
        .unwrap();
    assert_eq!(selected.track.observations().len(), 2);
}
