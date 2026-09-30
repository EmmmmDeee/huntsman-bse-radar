//! Reconstructed Rust domain core for BLE Radar.
//!
//! The crate intentionally separates observed measurements from inferred state.
//! Functions that cannot be proven from the supplied APK remain compatibility
//! gaps rather than guessed legacy behavior.

mod advancement;
mod evidence;
mod fusion;
mod geo;
mod history;
mod identity;
mod infrastructure;
mod osint;
mod pipeline;
mod runtime;
mod scan;
mod signal;
mod sweep;
mod tracking;
mod validation;
mod verification;
mod website;

/// Bounds-checked, panic-free BLE advertising-payload decoder (AD structures,
/// service UUIDs, manufacturer/service data, iBeacon and Eddystone).
pub mod adv;
/// Huntsman Search Engine (HSE) universal coordinate parser.
pub mod coords;
/// Huntsman Search Engine (HSE) entity model.
pub mod entity;
/// Machine-readable capability registry and the supersession matrix it renders.
pub mod registry;
/// Huntsman Search Engine (HSE) canonical entity tag vocabulary.
pub mod tags;
/// Robust, deterministic automatic-update engine (version/integrity/lifecycle).
pub mod update;

pub use advancement::{
    AdvancementDecision, AdvancementError, AdvancementExecution, AdvancementFactors,
    AdvancementPhase, AdvancementPriority, AdvancementProposal, AdvancementRanking,
    AdvancementRejection, AdvancementRun, AdvancementState, BenchmarkMetric, BenchmarkReport,
    FalsificationCheck, FalsificationFinding, FalsificationResult, FalsificationStatus,
    MetamorphicSoftwareAdvancementEngine, MetricDirection, SoftwareAdvancementEngine,
};
pub use entity::{
    CANDIDATE_CONF, CONSENSUS_SOURCE, CORROBORATION_COEFF, CORROBORATION_DOUBT_DECAY,
    CROSS_SCAN_CORROBORATION_SOURCE, CROSS_SCAN_SOURCE, ENRICHMENT_ONLY_SOURCES, GAMMA_PER_HOUR,
    GEO_CORROBORATION_SOURCE, HseClassification, HseEntity, HseEntityBuilder, HseEntityKind,
    HseEntityRef, HseEvidence, HseVerificationMethod, MULTIPATH_CORROBORATION_SOURCE,
    RECALL_SOURCE, Sha256, canonical_handle, derive_uid, evidence_sources, expansion_timeline,
    hex_encode, is_engine_corroboration_source, is_enrichment_source, is_non_corroborating_source,
    is_promotion_source, is_tracking_param_key, normalise, scan_id, uid_for,
};
pub use evidence::{
    Action, ActionId, ActionStatus, ActionType, Artifact, ArtifactId, ArtifactType,
    CanonicalEvidence, Claim, ClaimId, ClaimTrace, ConfidenceTarget, ConfidenceUpdate,
    ConfidenceUpdateId, EdgeType, Entity, EntityId, EntityKind, EntityType, Event, EventId,
    EventType, Evidence, EvidenceId, EvidenceRole, EvidenceStore, EvidenceTrace, EvidenceValue,
    Feature, FeatureId, Hypothesis, HypothesisId, HypothesisKind, Observation, ObservationId,
    ObservationTimeline, ProvenanceCore, ProvenanceError, RecordId, Relationship, RelationshipId,
    RelationshipProvenance, Representation, RepresentationId, RepresentationType, RetrievalMethod,
    Source, SourceId, SourceType, Test, TestId, TestStatus, TestType, Timestamp, Transformation,
    TransformationId, TransformationTrace, Value, Verification, VerificationStatus,
};
pub use fusion::{
    CalibratedEvidenceFusion, DependencyKind, EvidenceAssessment, EvidenceQuality,
    ExpectedEvidence, FalsificationReport, FusionError, FusionResult, HypothesisScore,
};
pub use geo::{GeoError, LatLon, bearing_deg, haversine_m};
pub use history::{
    HISTORY_HEADER, History, HistoryRecord, MAX_ENTRIES as HISTORY_MAX_ENTRIES,
    VISIT_GAP_MS as HISTORY_VISIT_GAP_MS, history_lookup, history_merge, is_history_key,
};
pub use identity::{
    AddressKind, DeviceIdentity, Distinctiveness, IdentityEvidence, IdentityMatch, MatchVerdict,
    canonical_mac, group_key, group_key_typed, is_locally_administered, resolve,
};
pub use infrastructure::{
    CompetingExplanation, ControlAssessment, CorrelationEdge, CorrelationFactors,
    CorrelationFalsification, CorrelationRanking, CorrelationReport, InfrastructureCorrelationEdge,
    InfrastructureCorrelationEngine, InfrastructureCorrelationReport, InfrastructureError,
    InfrastructureExplanation, InfrastructureFactors, InfrastructureFalsificationReport,
    InfrastructureKind, InfrastructureLimits, InfrastructureObservation, InfrastructurePhase,
    InfrastructureRecord, TemporalInfrastructureCorrelationEngine, TemporalInterval,
    TemporalMetamorphicInfrastructureCorrelationEngine, TemporalRelation,
};
pub use osint::{
    AdaptiveOsintSearchEngine, AdaptiveSearchFactors, ExecutionFeedbackAdaptiveOsintSearchEngine,
    ExecutionFeedbackAdaptiveSearchEngine, OsintSearchError, SearchError, SearchExecution,
    SearchFamilyStatistics, SearchFeedback, SearchFinding, SearchLimits, SearchOutcome,
    SearchPhase, SearchPivot, SearchPivotSeed, SearchPivotState, SearchPriority,
    SearchPriorityFactors, SearchRanking, SearchRepresentation,
};
pub use pipeline::{
    DiminishingGainStopCriterion, GraphEdge, InformationGainSample, InvestigationPipeline, NodeId,
    PipelineError, PipelineStage, TemporalGeoGraph, TemporalSpan,
};
pub use runtime::{Runtime, ScanCommand, ScanMode};
pub use scan::{
    MAX_SCAN_RATE_LIMIT_RETRIES, MAX_SCAN_RETRIES, SCAN_FAILED_ALREADY_STARTED,
    SCAN_FAILED_APPLICATION_REGISTRATION_FAILED, SCAN_FAILED_FEATURE_UNSUPPORTED,
    SCAN_FAILED_INTERNAL_ERROR, SCAN_FAILED_OUT_OF_HARDWARE_RESOURCES,
    SCAN_FAILED_SCANNING_TOO_FREQUENTLY, SCAN_RATE_LIMIT_RETRY_MS, SCAN_RETRY_BASE_MS,
    SCAN_RETRY_CAP_MS, ScanFailureAction, scan_failure_action,
};
pub use signal::{
    BleCalibration, CalibrationProfile, FilterError, ProximityBand, RssiEma, SignalTrend,
    ble_distance_m, ble_distance_range_m, calibration_profile, calibration_profile_from_ordinal,
    effective_rssi_at_1m_dbm, filtered_rssi, proximity_label, proximity_label_from_distance_m,
    signal_confidence_percent, signal_trend,
};
pub use sweep::{
    ANDROID_UNAVAILABLE, AddressTrackability, BleAddressType, CellRadio, RssiReliability,
    WifiObservation, address_trackability, ble_address_trackability, is_numeric_segment,
    is_real_device_address, sighting_key, tower_id, usable_cell_identity, usable_dbm, wifi_channel,
    wifi_observation, wifi_proximity, wifi_rssi_reliability,
};
pub use tracking::{
    Confidence, DeviceObservation, DeviceTrack, EstimateKind, FreshnessClass, MapPoint,
    SelectedDevice, SpatialEstimate, TrackError, TrackingPolicy, TrackingProfile, TrackingSnapshot,
    TrackingSnapshotInput, tracking_profile, tracking_profile_from_ordinal, tracking_snapshot,
};
pub use update::{
    ArtifactVerifier, DownloadConditions, DownloadPolicy, DownloadReadiness, ManifestFetchFailure,
    ManifestSourceDecision, NetworkType, ReleaseManifest, RetryDecision, RetryPolicy,
    UpdateDecision, UpdateError, UpdateSession, UpdateStage, Version, check_update,
    download_readiness, manifest_source_decision, should_check_for_update, update_decision,
    verify_artifact,
};
pub use verification::{
    DifferentialCase, DifferentialReport, DifferentialViolation, ExecutionOutcome, FailureCause,
    FamilyStatistics, MetamorphicRelation, MetamorphicTest, RegressionLock, RepairRecord,
    RequiredSemantics, VerificationEngine, VerificationError, VerificationReport,
    VerificationSurface, VerificationViolation,
};
pub use website::{
    OperatorAssessment, WebsiteCorrelationEdge, WebsiteCorrelationFactors,
    WebsiteCorrelationFalsification, WebsiteCorrelationRanking, WebsiteCorrelationReport,
    WebsiteEcosystemAnalysisEngine, WebsiteError, WebsiteExplanation, WebsiteFactors,
    WebsiteFalsificationReport, WebsiteFeatureKind, WebsiteLimits,
    WebsiteLineageEcosystemAnalysisEngine, WebsiteLineageEdge, WebsiteLineageEngine,
    WebsiteLineageReport, WebsiteObservation, WebsiteObservationKind, WebsiteObservationPair,
    WebsitePhase, WebsiteRecord, WebsiteSnapshot, WebsiteTimeline,
};

/// 2.4/5 GHz Wi-Fi channel to center frequency in MHz where defined.
///
/// # Examples
/// ```
/// use bleradar_core::wifi_channel_to_frequency;
/// assert_eq!(wifi_channel_to_frequency(1), Some(2412));
/// assert_eq!(wifi_channel_to_frequency(14), Some(2484));
/// assert_eq!(wifi_channel_to_frequency(15), None);
/// ```
#[must_use]
pub fn wifi_channel_to_frequency(channel: u16) -> Option<u16> {
    match channel {
        1..=13 => Some(2407 + channel * 5),
        14 => Some(2484),
        32..=177 => Some(5000 + channel * 5),
        _ => None,
    }
}

/// Wi-Fi center frequency in MHz to channel where unambiguous for 2.4/5/6 GHz.
///
/// Channel numbers are recovered by floor division within each inclusive
/// range, not only at exact 5 MHz grid points: this matches the immutable
/// native oracle's verified behavior (`docs/BEHAVIORAL_CONTRACT.md` BF-004),
/// including the 6 GHz band (IEEE 802.11ax-2021).
///
/// # Examples
/// ```
/// use bleradar_core::wifi_frequency_to_channel;
/// assert_eq!(wifi_frequency_to_channel(2412), Some(1));
/// assert_eq!(wifi_frequency_to_channel(2484), Some(14));
/// assert_eq!(wifi_frequency_to_channel(5955), Some(1));
/// assert_eq!(wifi_frequency_to_channel(7115), Some(233));
/// ```
#[must_use]
pub fn wifi_frequency_to_channel(mhz: u16) -> Option<u16> {
    match mhz {
        2412..=2472 => Some((mhz - 2407) / 5),
        2484 => Some(14),
        5160..=5885 => Some((mhz - 5000) / 5),
        5955..=7115 => Some((mhz - 5950) / 5),
        _ => None,
    }
}

/// The Wi-Fi frequency band a channel center frequency (MHz) falls in.
///
/// [`label`](WifiBand::label) returns the exact string the shipped native
/// `wifi_band` contract emits, so the two are differentially comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WifiBand {
    /// 2.4 GHz band.
    TwoPointFourGhz,
    /// 5 GHz band.
    FiveGhz,
    /// 6 GHz band.
    SixGhz,
}

impl WifiBand {
    /// The band label, matching the shipped native `wifi_band` output verbatim.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::TwoPointFourGhz => "2.4 GHz",
            Self::FiveGhz => "5 GHz",
            Self::SixGhz => "6 GHz",
        }
    }
}

/// Wi-Fi band for a center frequency in MHz, matching the shipped native
/// `wifi_band` contract's split at 3000 and 5900 MHz.
///
/// The native contract's argument is an `Option<i32>` (a missing frequency maps
/// to the `"?"` band, and negatives to 2.4 GHz); this reconstruction takes the
/// narrower `u16` domain, mirroring [`wifi_channel_to_frequency`]. Over that
/// domain it is differentially verified bit-for-bit against the executed oracle
/// (`docs/ORACLE_DIFFERENTIAL.md`).
///
/// # Examples
/// ```
/// use bleradar_core::{wifi_band, WifiBand};
/// assert_eq!(wifi_band(2412), WifiBand::TwoPointFourGhz);
/// assert_eq!(wifi_band(5180), WifiBand::FiveGhz);
/// assert_eq!(wifi_band(5955), WifiBand::SixGhz);
/// ```
#[must_use]
pub fn wifi_band(mhz: u16) -> WifiBand {
    if mhz < 3000 {
        WifiBand::TwoPointFourGhz
    } else if mhz < 5900 {
        WifiBand::FiveGhz
    } else {
        WifiBand::SixGhz
    }
}

// wifi_distance calibration, recovered bit-for-bit from the executed oracle
// (docs/ORACLE_DIFFERENTIAL.md): a log-distance path-loss estimate with a folded
// free-space/TX-power constant and a path-loss exponent of 2.7.
const WIFI_DISTANCE_FSPL_CONST: f64 = 47.55;
const WIFI_DISTANCE_PATH_LOSS_DENOM: f64 = 27.0; // 10 * path-loss exponent (2.7)
// Plausible WiFi channel center-frequency window (MHz). The shipped contract
// substitutes the 2.4 GHz channel-6 default for any frequency outside it.
const WIFI_DISTANCE_FREQ_MIN_MHZ: i32 = 2000;
const WIFI_DISTANCE_FREQ_MAX_MHZ: i32 = 7199;
const WIFI_DISTANCE_DEFAULT_FREQ_MHZ: i32 = 2437;
// Output range (metres): the shipped contract clamps the estimate to [0.1, 400]
// and treats a non-negative RSSI as an invalid/implausibly-strong reading that
// saturates to the far clamp.
const WIFI_DISTANCE_MIN_M: f64 = 0.1;
const WIFI_DISTANCE_MAX_M: f64 = 400.0;

/// Estimated distance in metres to a Wi-Fi transmitter from its RSSI (dBm) and
/// channel center frequency (MHz), reproducing the shipped native `wifi_distance`
/// contract exactly.
///
/// The estimate is `10^((47.55 - 20·log10(f) - rssi) / 27)` — a log-distance
/// path-loss model with a path-loss exponent of 2.7 — subject to the shipped
/// contract's three guards, each recovered from the executed oracle
/// (`docs/ORACLE_DIFFERENTIAL.md`):
///
/// * a non-negative `rssi_dbm` is treated as invalid/implausibly strong and
///   saturates to the [`WIFI_DISTANCE_MAX_M`](self) far clamp (400 m);
/// * a `frequency_mhz` outside the plausible `2000..=7199` MHz window falls back
///   to the 2437 MHz (channel 6) default before the estimate is computed;
/// * the estimate is clamped to `[0.1, 400]` m.
///
/// The reconstruction accepts the oracle's full `i32` domain on both arguments,
/// so it reproduces the executed oracle with no domain divergence; only the
/// transcendental `log10`/`powf` step differs from Bionic `libm` by last-bit
/// rounding (verified to `<1e-12` relative — `oracle_wifi_distance_differential.rs`).
///
/// # Examples
/// ```
/// use bleradar_core::wifi_distance;
/// // A non-negative RSSI is invalid and saturates to the 400 m far clamp.
/// assert_eq!(wifi_distance(0, 2412), 400.0);
/// // A very weak signal saturates to the same far clamp.
/// assert_eq!(wifi_distance(-130, 2412), 400.0);
/// // A strong 6 GHz reading saturates to the 0.1 m near clamp.
/// assert_eq!(wifi_distance(-1, 7115), 0.1);
/// // An out-of-band frequency falls back to the 2437 MHz (channel 6) default.
/// assert_eq!(wifi_distance(-70, 100), wifi_distance(-70, 2437));
/// // In the valid region the estimate grows as the signal weakens.
/// assert!(wifi_distance(-80, 2437) > wifi_distance(-50, 2437));
/// ```
#[must_use]
pub fn wifi_distance(rssi_dbm: i32, frequency_mhz: i32) -> f64 {
    if rssi_dbm >= 0 {
        return WIFI_DISTANCE_MAX_M;
    }
    let effective_mhz =
        if (WIFI_DISTANCE_FREQ_MIN_MHZ..=WIFI_DISTANCE_FREQ_MAX_MHZ).contains(&frequency_mhz) {
            frequency_mhz
        } else {
            WIFI_DISTANCE_DEFAULT_FREQ_MHZ
        };
    let exponent =
        (WIFI_DISTANCE_FSPL_CONST - 20.0 * f64::from(effective_mhz).log10() - f64::from(rssi_dbm))
            / WIFI_DISTANCE_PATH_LOSS_DENOM;
    10_f64
        .powf(exponent)
        .clamp(WIFI_DISTANCE_MIN_M, WIFI_DISTANCE_MAX_M)
}

/// The Wi-Fi security scheme inferred from an access point's capabilities string.
///
/// [`label`](WifiSecurity::label) returns the exact string the shipped native
/// `wifi_security` contract emits, so the two are differentially comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WifiSecurity {
    /// No capabilities were supplied (`"?"`).
    Unknown,
    /// No recognised security token (`"Open"`).
    Open,
    /// WEP (`"WEP"`).
    Wep,
    /// WPA (`"WPA"`).
    Wpa,
    /// WPA2 / RSN (`"WPA2"`).
    Wpa2,
    /// WPA3 / SAE (`"WPA3"`).
    Wpa3,
    /// Opportunistic Wireless Encryption / Enhanced Open (`"OWE"`).
    Owe,
}

impl WifiSecurity {
    /// The label, matching the shipped native `wifi_security` output verbatim.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "?",
            Self::Open => "Open",
            Self::Wep => "WEP",
            Self::Wpa => "WPA",
            Self::Wpa2 => "WPA2",
            Self::Wpa3 => "WPA3",
            Self::Owe => "OWE",
        }
    }
}

/// Classifies a Wi-Fi access point's security scheme from its capabilities
/// string, reproducing the shipped native `wifi_security` contract exactly.
///
/// The classification is a case-sensitive substring test applied in a fixed
/// precedence order, recovered from the executed oracle
/// (`docs/ORACLE_DIFFERENTIAL.md`): a missing capabilities string is
/// [`Unknown`](WifiSecurity::Unknown) (`"?"`); otherwise `"SAE"` or `"WPA3"` →
/// WPA3, then `"WPA2"` or `"RSN"` → WPA2, then `"OWE"` → OWE, then `"WPA"` →
/// WPA, then `"WEP"` → WEP, else [`Open`](WifiSecurity::Open). Because a WPA2
/// network is advertised as RSN and mixed WPA2/WPA3 as `[WPA2-…][RSN-SAE-…]`,
/// the WPA3 and WPA2 tests deliberately precede the WPA/WEP ones.
///
/// # Examples
/// ```
/// use bleradar_core::{wifi_security, WifiSecurity};
/// assert_eq!(wifi_security(Some("[WPA2-PSK-CCMP][ESS]")), WifiSecurity::Wpa2);
/// assert_eq!(wifi_security(Some("[RSN-SAE-CCMP][ESS]")), WifiSecurity::Wpa3);
/// assert_eq!(wifi_security(Some("[RSN-OWE-CCMP][ESS]")), WifiSecurity::Wpa2);
/// assert_eq!(wifi_security(Some("[OWE][ESS]")), WifiSecurity::Owe);
/// assert_eq!(wifi_security(Some("[ESS]")), WifiSecurity::Open);
/// assert_eq!(wifi_security(None), WifiSecurity::Unknown);
/// ```
#[must_use]
pub fn wifi_security(caps: Option<&str>) -> WifiSecurity {
    let Some(caps) = caps else {
        return WifiSecurity::Unknown;
    };
    if caps.contains("SAE") || caps.contains("WPA3") {
        WifiSecurity::Wpa3
    } else if caps.contains("WPA2") || caps.contains("RSN") {
        WifiSecurity::Wpa2
    } else if caps.contains("OWE") {
        WifiSecurity::Owe
    } else if caps.contains("WPA") {
        WifiSecurity::Wpa
    } else if caps.contains("WEP") {
        WifiSecurity::Wep
    } else {
        WifiSecurity::Open
    }
}

/// Whether a Wi-Fi access point uses enterprise (802.1X/EAP) authentication,
/// reproducing the shipped native `wifi_is_enterprise` contract exactly.
///
/// This is a case-sensitive test for the substring `"EAP"` in the capabilities
/// string (a missing string is not enterprise), recovered from the executed
/// oracle (`docs/ORACLE_DIFFERENTIAL.md`).
///
/// # Examples
/// ```
/// use bleradar_core::wifi_is_enterprise;
/// assert!(wifi_is_enterprise(Some("[WPA2-EAP-CCMP][ESS]")));
/// assert!(!wifi_is_enterprise(Some("[WPA2-PSK-CCMP][ESS]")));
/// assert!(!wifi_is_enterprise(Some("[wpa2-eap]"))); // case-sensitive
/// assert!(!wifi_is_enterprise(None));
/// ```
#[must_use]
pub fn wifi_is_enterprise(caps: Option<&str>) -> bool {
    caps.is_some_and(|caps| caps.contains("EAP"))
}

/// Unsupported reconstructed behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityGap {
    /// Public symbol or behavior whose exact semantics cannot be recovered from the APK.
    pub contract: &'static str,
    /// Why reconstruction would require guessing.
    pub reason: &'static str,
}

impl std::fmt::Display for CompatibilityGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unsupported contract `{}`: {}",
            self.contract, self.reason
        )
    }
}

impl std::error::Error for CompatibilityGap {}
