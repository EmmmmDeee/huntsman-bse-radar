//! Temporal metamorphic infrastructure correlation.
//!
//! This module keeps infrastructure observations in the canonical evidence
//! store and compares them without turning shared hosting into proof of shared
//! control.  Correlations are scored on an explicit ordinal calibration scale,
//! collapse dependent sources, preserve temporal intervals, and are stress
//! tested by removing common infrastructure support and uncertain assumptions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::{
    Confidence, EdgeType, Entity, EntityType, EvidenceStore, EvidenceValue, Observation,
    ObservationTimeline, ProvenanceError, Relationship, RelationshipProvenance, RetrievalMethod,
    Source, SourceType, Timestamp,
};

const DEFAULT_MAX_OBSERVATIONS: usize = 10_000;
const DEFAULT_MAX_CORRELATIONS: usize = 10_000;
const DEFAULT_MAX_TEMPORAL_GAP: Timestamp = 86_400_000;
const CORRELATION_SOURCE_ID: &str = "temporal-infrastructure-correlation";
const CORRELATION_METHOD: &str = "temporal-metamorphic-infrastructure-correlation";

/// Infrastructure observation family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InfrastructureKind {
    /// A domain name.
    Domain,
    /// A DNS record, resolver result, or DNS provider indicator.
    Dns,
    /// An IP address.
    IpAddress,
    /// An autonomous-system number or ASN-associated identifier.
    Asn,
    /// A certificate, certificate fingerprint, or certificate subject.
    Certificate,
    /// A hosting, CDN, or infrastructure provider.
    HostingProvider,
    /// An HTTP response characteristic.
    HttpCharacteristic,
    /// A publicly reachable asset.
    PublicAsset,
    /// A public identifier exposed by an application or service.
    PublicIdentifier,
    /// An application or framework structure signature.
    ApplicationStructure,
    /// An archived website or infrastructure state.
    ArchivedState,
}

impl InfrastructureKind {
    /// Every supported infrastructure family in stable order.
    pub const ALL: [Self; 11] = [
        Self::Domain,
        Self::Dns,
        Self::IpAddress,
        Self::Asn,
        Self::Certificate,
        Self::HostingProvider,
        Self::HttpCharacteristic,
        Self::PublicAsset,
        Self::PublicIdentifier,
        Self::ApplicationStructure,
        Self::ArchivedState,
    ];

    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Dns => "dns",
            Self::IpAddress => "ip_address",
            Self::Asn => "asn",
            Self::Certificate => "certificate",
            Self::HostingProvider => "hosting_provider",
            Self::HttpCharacteristic => "http_characteristic",
            Self::PublicAsset => "public_asset",
            Self::PublicIdentifier => "public_identifier",
            Self::ApplicationStructure => "application_structure",
            Self::ArchivedState => "archived_state",
        }
    }

    /// Whether a value in this family is ordinarily high-base-rate support.
    ///
    /// This is a conservative default.  Callers can additionally mark a
    /// particular observation as high-base-rate when local prevalence is known.
    #[must_use]
    pub const fn is_high_base_rate(self) -> bool {
        matches!(
            self,
            Self::IpAddress | Self::Asn | Self::HostingProvider | Self::HttpCharacteristic
        )
    }
}

impl fmt::Display for InfrastructureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated first-seen, observed-at, and last-seen interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemporalInterval {
    first_seen: Timestamp,
    observed_at: Timestamp,
    last_seen: Timestamp,
}

impl TemporalInterval {
    /// Creates an interval after enforcing `first_seen <= observed_at <= last_seen`.
    pub fn new(
        first_seen: Timestamp,
        observed_at: Timestamp,
        last_seen: Timestamp,
    ) -> Result<Self, InfrastructureError> {
        ObservationTimeline::new(first_seen, observed_at, last_seen)
            .map(Self::from_timeline)
            .map_err(InfrastructureError::from)
    }

    /// Creates an interval for one observation instant.
    #[must_use]
    pub const fn at(observed_at: Timestamp) -> Self {
        Self {
            first_seen: observed_at,
            observed_at,
            last_seen: observed_at,
        }
    }

    /// Converts a canonical observation timeline.
    #[must_use]
    pub const fn from_timeline(timeline: ObservationTimeline) -> Self {
        Self {
            first_seen: timeline.first_seen(),
            observed_at: timeline.observed_at(),
            last_seen: timeline.last_seen(),
        }
    }

    /// First time represented by the interval.
    #[must_use]
    pub const fn first_seen(self) -> Timestamp {
        self.first_seen
    }

    /// Representative observation time.
    #[must_use]
    pub const fn observed_at(self) -> Timestamp {
        self.observed_at
    }

    /// Last time represented by the interval.
    #[must_use]
    pub const fn last_seen(self) -> Timestamp {
        self.last_seen
    }

    /// Inclusive duration of the interval.
    #[must_use]
    pub const fn duration(self) -> Timestamp {
        self.last_seen.saturating_sub(self.first_seen)
    }

    /// Whether two intervals overlap, including at a boundary.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.first_seen <= other.last_seen && other.first_seen <= self.last_seen
    }

    /// Returns the inclusive intersection when the intervals overlap.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Option<Self> {
        if !self.overlaps(other) {
            return None;
        }
        let first_seen = if self.first_seen > other.first_seen {
            self.first_seen
        } else {
            other.first_seen
        };
        let last_seen = if self.last_seen < other.last_seen {
            self.last_seen
        } else {
            other.last_seen
        };
        let observed_at = if self.observed_at >= first_seen && self.observed_at <= last_seen {
            self.observed_at
        } else if other.observed_at >= first_seen && other.observed_at <= last_seen {
            other.observed_at
        } else {
            first_seen
        };
        Some(Self {
            first_seen,
            observed_at,
            last_seen,
        })
    }

    /// Gap between disjoint intervals, or zero when they overlap.
    #[must_use]
    pub const fn gap(self, other: Self) -> Timestamp {
        if self.overlaps(other) {
            0
        } else if self.last_seen < other.first_seen {
            other.first_seen.saturating_sub(self.last_seen)
        } else {
            self.first_seen.saturating_sub(other.last_seen)
        }
    }

    /// Whether two intervals overlap or are within an allowed continuity gap.
    #[must_use]
    pub const fn is_contiguous_with(self, other: Self, maximum_gap: Timestamp) -> bool {
        self.gap(other) <= maximum_gap
    }
}

impl From<TemporalInterval> for ObservationTimeline {
    fn from(interval: TemporalInterval) -> Self {
        Self::new(
            interval.first_seen,
            interval.observed_at,
            interval.last_seen,
        )
        .expect("TemporalInterval is validated at construction")
    }
}

/// Explicit ordinal quality factors for an infrastructure correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfrastructureFactors {
    reliability: Confidence,
    specificity: Confidence,
    rarity: Confidence,
    discriminative_power: Confidence,
    source_independence: Confidence,
    temporal_compatibility: Confidence,
    transformation_resistance: Confidence,
    provenance_quality: Confidence,
    reproducibility: Confidence,
    high_base_rate: bool,
    uncertainty: Confidence,
}

impl InfrastructureFactors {
    /// Creates the nine calibrated factors.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        reliability: u8,
        specificity: u8,
        rarity: u8,
        discriminative_power: u8,
        source_independence: u8,
        temporal_compatibility: u8,
        transformation_resistance: u8,
        provenance_quality: u8,
        reproducibility: u8,
    ) -> Self {
        Self {
            reliability: Confidence::new(reliability),
            specificity: Confidence::new(specificity),
            rarity: Confidence::new(rarity),
            discriminative_power: Confidence::new(discriminative_power),
            source_independence: Confidence::new(source_independence),
            temporal_compatibility: Confidence::new(temporal_compatibility),
            transformation_resistance: Confidence::new(transformation_resistance),
            provenance_quality: Confidence::new(provenance_quality),
            reproducibility: Confidence::new(reproducibility),
            high_base_rate: false,
            uncertainty: Confidence::new(0),
        }
    }

    /// Creates equal values for all nine quality dimensions.
    #[must_use]
    pub const fn uniform(score: u8) -> Self {
        Self::new(
            score, score, score, score, score, score, score, score, score,
        )
    }

    /// Marks this support as high-base-rate.
    #[must_use]
    pub const fn high_base_rate(mut self) -> Self {
        self.high_base_rate = true;
        self
    }

    /// Adds an uncertainty penalty used by falsification.
    #[must_use]
    pub const fn with_uncertainty(mut self, uncertainty: u8) -> Self {
        self.uncertainty = Confidence::new(uncertainty);
        self
    }

    /// Reliability factor.
    #[must_use]
    pub const fn reliability(self) -> Confidence {
        self.reliability
    }

    /// Specificity factor.
    #[must_use]
    pub const fn specificity(self) -> Confidence {
        self.specificity
    }

    /// Rarity factor.
    #[must_use]
    pub const fn rarity(self) -> Confidence {
        self.rarity
    }

    /// Discriminative-power factor.
    #[must_use]
    pub const fn discriminative_power(self) -> Confidence {
        self.discriminative_power
    }

    /// Source-independence factor.
    #[must_use]
    pub const fn source_independence(self) -> Confidence {
        self.source_independence
    }

    /// Temporal-compatibility factor supplied by the caller.
    #[must_use]
    pub const fn temporal_compatibility(self) -> Confidence {
        self.temporal_compatibility
    }

    /// Resistance to normalization or representation changes.
    #[must_use]
    pub const fn transformation_resistance(self) -> Confidence {
        self.transformation_resistance
    }

    /// Provenance-quality factor.
    #[must_use]
    pub const fn provenance_quality(self) -> Confidence {
        self.provenance_quality
    }

    /// Reproducibility factor.
    #[must_use]
    pub const fn reproducibility(self) -> Confidence {
        self.reproducibility
    }

    /// Whether this item was explicitly marked high-base-rate.
    #[must_use]
    pub const fn is_high_base_rate(self) -> bool {
        self.high_base_rate
    }

    /// Uncertainty penalty.
    #[must_use]
    pub const fn uncertainty(self) -> Confidence {
        self.uncertainty
    }

    /// Conservative arithmetic mean of the nine quality factors.
    #[must_use]
    pub const fn calibrated_weight(self) -> u8 {
        let sum = self.reliability.value() as u16
            + self.specificity.value() as u16
            + self.rarity.value() as u16
            + self.discriminative_power.value() as u16
            + self.source_independence.value() as u16
            + self.temporal_compatibility.value() as u16
            + self.transformation_resistance.value() as u16
            + self.provenance_quality.value() as u16
            + self.reproducibility.value() as u16;
        (sum / 9) as u8
    }
}

/// One raw infrastructure observation with additive normalization and provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct InfrastructureObservation {
    id: String,
    node_id: String,
    kind: InfrastructureKind,
    raw_value: EvidenceValue,
    normalized_value: Option<EvidenceValue>,
    source: Source,
    timeline: TemporalInterval,
    factors: InfrastructureFactors,
    dependency_group: Option<String>,
    feature_key: Option<String>,
}

impl InfrastructureObservation {
    /// Creates an observation at one instant.
    pub fn new(
        id: impl Into<String>,
        node_id: impl Into<String>,
        kind: InfrastructureKind,
        raw_value: impl Into<EvidenceValue>,
        source: Source,
        observed_at: Timestamp,
    ) -> Result<Self, InfrastructureError> {
        Self::with_timeline(
            id,
            node_id,
            kind,
            raw_value,
            source,
            TemporalInterval::at(observed_at),
        )
    }

    /// Creates an observation with an explicit temporal interval.
    pub fn with_timeline(
        id: impl Into<String>,
        node_id: impl Into<String>,
        kind: InfrastructureKind,
        raw_value: impl Into<EvidenceValue>,
        source: Source,
        timeline: TemporalInterval,
    ) -> Result<Self, InfrastructureError> {
        let id = require_text(id.into(), "infrastructure observation id")?;
        let node_id = require_text(node_id.into(), "infrastructure node id")?;
        Ok(Self {
            id,
            node_id,
            kind,
            raw_value: raw_value.into(),
            normalized_value: None,
            source,
            timeline,
            factors: InfrastructureFactors::uniform(50),
            dependency_group: None,
            feature_key: None,
        })
    }

    /// Returns a copy with an additive normalized value.
    #[must_use]
    pub fn with_normalized_value(&self, normalized_value: impl Into<EvidenceValue>) -> Self {
        let mut copy = self.clone();
        copy.normalized_value = Some(normalized_value.into());
        copy
    }

    /// Returns a copy with an additive normalized value and derivation label.
    ///
    /// The label is retained as a feature signature for correlation; raw
    /// evidence remains unchanged.
    pub fn with_normalization(
        &self,
        normalized_value: impl Into<EvidenceValue>,
        feature_key: impl Into<String>,
    ) -> Result<Self, InfrastructureError> {
        self.with_normalized_value(normalized_value)
            .with_feature(feature_key)
    }

    /// Returns a copy with an explicit temporal interval.
    #[must_use]
    pub const fn with_interval(mut self, timeline: TemporalInterval) -> Self {
        self.timeline = timeline;
        self
    }

    /// Returns a copy with explicit quality factors.
    #[must_use]
    pub const fn with_factors(mut self, factors: InfrastructureFactors) -> Self {
        self.factors = factors;
        self
    }

    /// Returns a copy with a stable feature signature.
    pub fn with_feature(
        mut self,
        feature_key: impl Into<String>,
    ) -> Result<Self, InfrastructureError> {
        self.feature_key = Some(require_text(
            feature_key.into(),
            "infrastructure feature key",
        )?);
        Ok(self)
    }

    /// Assigns a dependency group used for source-independence collapse.
    pub fn in_dependency_group(
        mut self,
        dependency_group: impl Into<String>,
    ) -> Result<Self, InfrastructureError> {
        self.dependency_group = Some(require_text(
            dependency_group.into(),
            "infrastructure dependency group",
        )?);
        Ok(self)
    }

    /// Marks this observation as high-base-rate support.
    #[must_use]
    pub const fn high_base_rate(mut self) -> Self {
        self.factors.high_base_rate = true;
        self
    }

    /// Adds uncertainty to this observation's quality factors.
    #[must_use]
    pub const fn with_uncertainty(mut self, uncertainty: u8) -> Self {
        self.factors.uncertainty = Confidence::new(uncertainty);
        self
    }

    /// Stable observation identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Infrastructure node associated with the observation.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Observation family.
    #[must_use]
    pub const fn kind(&self) -> InfrastructureKind {
        self.kind
    }

    /// Exact raw value captured from the source.
    #[must_use]
    pub const fn raw_value(&self) -> &EvidenceValue {
        &self.raw_value
    }

    /// Additive normalized value, if available.
    #[must_use]
    pub const fn normalized_value(&self) -> Option<&EvidenceValue> {
        self.normalized_value.as_ref()
    }

    /// Source record, including its retrieval metadata.
    #[must_use]
    pub const fn source(&self) -> &Source {
        &self.source
    }

    /// Source identifier.
    #[must_use]
    pub fn source_id(&self) -> &str {
        self.source.id()
    }

    /// Temporal interval for the observation.
    #[must_use]
    pub const fn timeline(&self) -> TemporalInterval {
        self.timeline
    }

    /// First-seen timestamp.
    #[must_use]
    pub const fn first_seen(&self) -> Timestamp {
        self.timeline.first_seen()
    }

    /// Representative observation timestamp.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.timeline.observed_at()
    }

    /// Last-seen timestamp.
    #[must_use]
    pub const fn last_seen(&self) -> Timestamp {
        self.timeline.last_seen()
    }

    /// Calibrated quality factors.
    #[must_use]
    pub const fn factors(&self) -> InfrastructureFactors {
        self.factors
    }

    /// Explicit dependency group, if supplied.
    #[must_use]
    pub fn dependency_group(&self) -> Option<&str> {
        self.dependency_group.as_deref()
    }

    /// Stable feature signature, if supplied.
    #[must_use]
    pub fn feature_key(&self) -> Option<&str> {
        self.feature_key.as_deref()
    }

    /// Whether this observation should receive high-base-rate down-weighting.
    #[must_use]
    pub const fn is_high_base_rate(&self) -> bool {
        self.kind.is_high_base_rate() || self.factors.is_high_base_rate()
    }

    fn canonical_observation(&self) -> Result<Observation, InfrastructureError> {
        Observation::with_timeline(
            self.id.clone(),
            self.raw_value.clone(),
            self.normalized_value.clone(),
            self.source.id().to_owned(),
            self.source.source_type().clone(),
            self.source.retrieval_method().clone(),
            self.timeline.into(),
        )
        .map_err(InfrastructureError::from)
    }

    /// Creates an observation using metadata copied from a canonical source.
    pub fn from_source(
        id: impl Into<String>,
        node_id: impl Into<String>,
        kind: InfrastructureKind,
        raw_value: impl Into<EvidenceValue>,
        source: &Source,
        observed_at: Timestamp,
    ) -> Result<Self, InfrastructureError> {
        Self::new(id, node_id, kind, raw_value, source.clone(), observed_at)
    }
}

/// Explanation tested for a pair of infrastructure nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InfrastructureExplanation {
    /// The nodes share a common CDN or edge network.
    CommonCdn,
    /// The nodes share a common hosting provider or host.
    CommonHost,
    /// The nodes share a common CMS or framework.
    CommonCms,
    /// The nodes share a common registrar or DNS administration service.
    CommonRegistrar,
    /// The nodes share a common template or static structure.
    CommonTemplate,
    /// The nodes share a third-party service or dependency.
    SharedThirdPartyService,
    /// The observations support a direct technical relationship.
    DirectTechnicalRelationship,
    /// A common administrator is possible but not established.
    PossibleCommonAdministration,
    /// The observations do not discriminate among explanations.
    Unknown,
}

impl InfrastructureExplanation {
    /// Every explanation in stable order.
    pub const ALL: [Self; 9] = [
        Self::CommonCdn,
        Self::CommonHost,
        Self::CommonCms,
        Self::CommonRegistrar,
        Self::CommonTemplate,
        Self::SharedThirdPartyService,
        Self::DirectTechnicalRelationship,
        Self::PossibleCommonAdministration,
        Self::Unknown,
    ];

    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommonCdn => "common_cdn",
            Self::CommonHost => "common_host",
            Self::CommonCms => "common_cms",
            Self::CommonRegistrar => "common_registrar",
            Self::CommonTemplate => "common_template",
            Self::SharedThirdPartyService => "shared_third_party_service",
            Self::DirectTechnicalRelationship => "direct_technical_relationship",
            Self::PossibleCommonAdministration => "possible_common_administration",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the explanation describes shared infrastructure rather than control.
    #[must_use]
    pub const fn is_shared_infrastructure(self) -> bool {
        matches!(
            self,
            Self::CommonCdn
                | Self::CommonHost
                | Self::CommonCms
                | Self::CommonRegistrar
                | Self::CommonTemplate
                | Self::SharedThirdPartyService
        )
    }
}

impl fmt::Display for InfrastructureExplanation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Temporal relationship between two matched observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TemporalRelation {
    /// Intervals overlap.
    Overlapping,
    /// Intervals are disjoint but within the configured continuity gap.
    Contiguous,
    /// Intervals are too far apart to establish continuity.
    Disjoint,
}

impl TemporalRelation {
    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overlapping => "overlapping",
            Self::Contiguous => "contiguous",
            Self::Disjoint => "disjoint",
        }
    }
}

impl fmt::Display for TemporalRelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Classification of the strongest relationship signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlAssessment {
    /// The result is explained by shared infrastructure; control is not inferred.
    SharedInfrastructure,
    /// The result supports a direct technical relationship.
    DirectTechnicalRelationship,
    /// Common administration is a live but unproven alternative.
    PossibleCommonAdministration,
    /// The available observations do not establish a relationship class.
    Unknown,
}

impl ControlAssessment {
    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SharedInfrastructure => "shared_infrastructure",
            Self::DirectTechnicalRelationship => "direct_technical_relationship",
            Self::PossibleCommonAdministration => "possible_common_administration",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ControlAssessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One independent pair of observations supporting an explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationPair {
    left_observation: String,
    right_observation: String,
    weight: u16,
    temporal_relation: TemporalRelation,
}

impl ObservationPair {
    /// Left-side observation identifier.
    #[must_use]
    pub fn left_observation(&self) -> &str {
        &self.left_observation
    }

    /// Right-side observation identifier.
    #[must_use]
    pub fn right_observation(&self) -> &str {
        &self.right_observation
    }

    /// Calibrated contribution of the pair.
    #[must_use]
    pub const fn weight(&self) -> u16 {
        self.weight
    }

    /// Temporal relation for the pair.
    #[must_use]
    pub const fn temporal_relation(&self) -> TemporalRelation {
        self.temporal_relation
    }
}

/// Ranking for one competing infrastructure explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationRanking {
    explanation: InfrastructureExplanation,
    score: u16,
    confidence: Confidence,
    independent_support: usize,
    supporting_pairs: Vec<ObservationPair>,
    collapsed_pairs: Vec<ObservationPair>,
    high_base_rate_support: bool,
    temporal_compatibility: Confidence,
}

impl CorrelationRanking {
    /// Explanation being ranked.
    #[must_use]
    pub const fn explanation(&self) -> InfrastructureExplanation {
        self.explanation
    }

    /// Ordinal score, not a probability.
    #[must_use]
    pub const fn score(&self) -> u16 {
        self.score
    }

    /// Bounded confidence projection of the ordinal score.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Number of independent support groups retained.
    #[must_use]
    pub const fn independent_support(&self) -> usize {
        self.independent_support
    }

    /// Independent supporting observation pairs.
    #[must_use]
    pub fn supporting_pairs(&self) -> &[ObservationPair] {
        &self.supporting_pairs
    }

    /// Pairs collapsed as copied, derivative, or otherwise dependent support.
    #[must_use]
    pub fn collapsed_pairs(&self) -> &[ObservationPair] {
        &self.collapsed_pairs
    }

    /// Whether one or more retained pairs are high-base-rate support.
    #[must_use]
    pub const fn has_high_base_rate_support(&self) -> bool {
        self.high_base_rate_support
    }

    /// Aggregate temporal compatibility of retained support.
    #[must_use]
    pub const fn temporal_compatibility(&self) -> Confidence {
        self.temporal_compatibility
    }

    /// All retained observation identifiers in left/right order.
    #[must_use]
    pub fn supporting_observation_ids(&self) -> Vec<String> {
        self.supporting_pairs
            .iter()
            .flat_map(|pair| {
                [
                    pair.left_observation.clone(),
                    pair.right_observation.clone(),
                ]
            })
            .collect()
    }
}

/// Adversarial stress-test result for a correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationFalsification {
    leading_explanation: InfrastructureExplanation,
    strongest_alternative: Option<InfrastructureExplanation>,
    baseline: CorrelationRanking,
    without_high_base_rate: CorrelationRanking,
    without_strongest_support: CorrelationRanking,
    perturbed_uncertainty: CorrelationRanking,
    removed_support: Option<ObservationPair>,
    missing_expected_evidence: Vec<InfrastructureKind>,
    survives: bool,
}

impl CorrelationFalsification {
    /// Baseline leading explanation.
    #[must_use]
    pub const fn leading_explanation(&self) -> InfrastructureExplanation {
        self.leading_explanation
    }

    /// Strongest baseline alternative, if one exists.
    #[must_use]
    pub const fn strongest_alternative(&self) -> Option<InfrastructureExplanation> {
        self.strongest_alternative
    }

    /// Baseline ranking.
    #[must_use]
    pub const fn baseline(&self) -> &CorrelationRanking {
        &self.baseline
    }

    /// Ranking after removing high-base-rate support.
    #[must_use]
    pub const fn without_high_base_rate(&self) -> &CorrelationRanking {
        &self.without_high_base_rate
    }

    /// Ranking after removing the strongest independent support group.
    #[must_use]
    pub const fn without_strongest_support(&self) -> &CorrelationRanking {
        &self.without_strongest_support
    }

    /// Ranking after perturbing uncertain assumptions.
    #[must_use]
    pub const fn perturbed_uncertainty(&self) -> &CorrelationRanking {
        &self.perturbed_uncertainty
    }

    /// Support pair removed by the strongest-support pass.
    #[must_use]
    pub const fn removed_support(&self) -> Option<&ObservationPair> {
        self.removed_support.as_ref()
    }

    /// Infrastructure families expected but not observed for the leading explanation.
    #[must_use]
    pub fn missing_expected_evidence(&self) -> &[InfrastructureKind] {
        &self.missing_expected_evidence
    }

    /// Whether the leading explanation survives every configured stress pass.
    #[must_use]
    pub const fn survives(&self) -> bool {
        self.survives
    }
}

/// Ordered execution phases recorded for one correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InfrastructurePhase {
    /// Capture canonical observation references.
    Capture,
    /// Compare raw, normalized, and feature representations.
    Normalize,
    /// Align first-seen and last-seen intervals.
    TemporalAlign,
    /// Generate competing explanations.
    Compare,
    /// Apply calibrated quality and dependency collapse.
    Score,
    /// Remove support and perturb uncertain assumptions.
    Falsify,
    /// Persist the relationship edge.
    Persist,
    /// Recompute deterministic rankings.
    Recompute,
}

/// A persisted infrastructure correlation edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfrastructureCorrelationEdge {
    id: String,
    subject: String,
    object: String,
    predicate: String,
    edge_type: EdgeType,
    leading_explanation: InfrastructureExplanation,
    confidence: Confidence,
    temporal_relation: TemporalRelation,
    observation_ids: Vec<String>,
    control_assessment: ControlAssessment,
    relationship_id: String,
}

impl InfrastructureCorrelationEdge {
    /// Stable edge identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Subject node identifier.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Object node identifier.
    #[must_use]
    pub fn object(&self) -> &str {
        &self.object
    }

    /// Stable relationship predicate.
    #[must_use]
    pub fn predicate(&self) -> &str {
        &self.predicate
    }

    /// Canonical edge classification.
    #[must_use]
    pub const fn edge_type(&self) -> EdgeType {
        self.edge_type
    }

    /// Leading competing explanation.
    #[must_use]
    pub const fn leading_explanation(&self) -> InfrastructureExplanation {
        self.leading_explanation
    }

    /// Bounded confidence projection.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Temporal relationship of the strongest support.
    #[must_use]
    pub const fn temporal_relation(&self) -> TemporalRelation {
        self.temporal_relation
    }

    /// Observation identifiers cited by the canonical edge.
    #[must_use]
    pub fn observation_ids(&self) -> &[String] {
        &self.observation_ids
    }

    /// Explicit shared-infrastructure versus control assessment.
    #[must_use]
    pub const fn control_assessment(&self) -> ControlAssessment {
        self.control_assessment
    }

    /// Identifier of the corresponding canonical [`Relationship`].
    #[must_use]
    pub fn relationship_id(&self) -> &str {
        &self.relationship_id
    }

    /// Whether this edge proves common administration.
    ///
    /// Shared infrastructure and a possible common administrator are never
    /// upgraded to proof by this engine alone.
    #[must_use]
    pub const fn common_control_proven(&self) -> bool {
        false
    }
}

/// Complete execution report for one infrastructure correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfrastructureCorrelationReport {
    edge: InfrastructureCorrelationEdge,
    rankings: Vec<CorrelationRanking>,
    falsification: CorrelationFalsification,
    temporal_relation: TemporalRelation,
    phases: Vec<InfrastructurePhase>,
}

impl InfrastructureCorrelationReport {
    /// Persisted correlation edge.
    #[must_use]
    pub const fn edge(&self) -> &InfrastructureCorrelationEdge {
        &self.edge
    }

    /// Competing explanations in descending score order.
    #[must_use]
    pub fn rankings(&self) -> &[CorrelationRanking] {
        &self.rankings
    }

    /// Returns the ranking for an explanation.
    #[must_use]
    pub fn ranking(&self, explanation: InfrastructureExplanation) -> Option<&CorrelationRanking> {
        self.rankings
            .iter()
            .find(|ranking| ranking.explanation == explanation)
    }

    /// Adversarial falsification report.
    #[must_use]
    pub const fn falsification(&self) -> &CorrelationFalsification {
        &self.falsification
    }

    /// Leading explanation.
    #[must_use]
    pub const fn leading_explanation(&self) -> InfrastructureExplanation {
        self.edge.leading_explanation
    }

    /// Leading calibrated confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.edge.confidence
    }

    /// Aggregate temporal relationship.
    #[must_use]
    pub const fn temporal_relation(&self) -> TemporalRelation {
        self.temporal_relation
    }

    /// Ordered control-loop phases.
    #[must_use]
    pub fn phases(&self) -> &[InfrastructurePhase] {
        &self.phases
    }

    /// Shared-infrastructure versus control classification.
    #[must_use]
    pub const fn control_assessment(&self) -> ControlAssessment {
        self.edge.control_assessment
    }

    /// Whether the report proves common administration.
    #[must_use]
    pub const fn common_control_proven(&self) -> bool {
        false
    }
}

/// Resource limits for infrastructure correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfrastructureLimits {
    max_observations: usize,
    max_correlations: usize,
    maximum_temporal_gap: Timestamp,
}

impl InfrastructureLimits {
    /// Creates limits with a one-day default temporal continuity window.
    pub fn new(
        max_observations: usize,
        max_correlations: usize,
    ) -> Result<Self, InfrastructureError> {
        if max_observations == 0 {
            return Err(InfrastructureError::InvalidLimit {
                resource: "observations",
                limit: max_observations,
            });
        }
        if max_correlations == 0 {
            return Err(InfrastructureError::InvalidLimit {
                resource: "correlations",
                limit: max_correlations,
            });
        }
        Ok(Self {
            max_observations,
            max_correlations,
            maximum_temporal_gap: DEFAULT_MAX_TEMPORAL_GAP,
        })
    }

    /// Sets the maximum gap treated as temporal continuity.
    #[must_use]
    pub const fn with_maximum_temporal_gap(mut self, maximum_temporal_gap: Timestamp) -> Self {
        self.maximum_temporal_gap = maximum_temporal_gap;
        self
    }

    /// Maximum canonical infrastructure observations.
    #[must_use]
    pub const fn max_observations(self) -> usize {
        self.max_observations
    }

    /// Maximum persisted correlation edges.
    #[must_use]
    pub const fn max_correlations(self) -> usize {
        self.max_correlations
    }

    /// Maximum gap accepted as temporal continuity.
    #[must_use]
    pub const fn maximum_temporal_gap(self) -> Timestamp {
        self.maximum_temporal_gap
    }
}

impl Default for InfrastructureLimits {
    fn default() -> Self {
        Self {
            max_observations: DEFAULT_MAX_OBSERVATIONS,
            max_correlations: DEFAULT_MAX_CORRELATIONS,
            maximum_temporal_gap: DEFAULT_MAX_TEMPORAL_GAP,
        }
    }
}

/// Validation, persistence, and correlation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfrastructureError {
    /// A required identifier or value was empty.
    EmptyValue {
        /// Name of the empty field.
        field: &'static str,
    },
    /// A configured resource limit was zero.
    InvalidLimit {
        /// Resource name.
        resource: &'static str,
        /// Invalid limit.
        limit: usize,
    },
    /// A resource limit was reached.
    ResourceLimit {
        /// Resource name.
        resource: &'static str,
        /// Configured limit.
        limit: usize,
    },
    /// An observation identifier is already registered.
    DuplicateObservation {
        /// Duplicate observation identifier.
        observation_id: String,
    },
    /// An observation was requested for a node absent from the engine.
    MissingNode {
        /// Missing node identifier.
        node_id: String,
    },
    /// A node cannot be correlated with itself.
    SameNode {
        /// Repeated node identifier.
        node_id: String,
    },
    /// No comparable values or feature signatures were found.
    NoComparableObservations {
        /// Left node.
        left_node: String,
        /// Right node.
        right_node: String,
    },
    /// A pair has already been correlated.
    DuplicateCorrelation {
        /// Duplicate correlation identifier.
        correlation_id: String,
    },
    /// A source identifier conflicts with canonical source metadata.
    SourceConflict {
        /// Conflicting source identifier.
        source_id: String,
    },
    /// A canonical observation identifier conflicts with an existing record.
    ObservationConflict {
        /// Conflicting observation identifier.
        observation_id: String,
    },
    /// Canonical provenance validation failed.
    Provenance {
        /// Underlying error.
        error: ProvenanceError,
    },
}

impl fmt::Display for InfrastructureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue { field } => write!(formatter, "{field} must not be empty"),
            Self::InvalidLimit { resource, limit } => {
                write!(formatter, "{resource} limit must be positive (got {limit})")
            }
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "{resource} limit of {limit} was reached")
            }
            Self::DuplicateObservation { observation_id } => {
                write!(
                    formatter,
                    "duplicate infrastructure observation `{observation_id}`"
                )
            }
            Self::MissingNode { node_id } => {
                write!(
                    formatter,
                    "infrastructure node `{node_id}` has no observations"
                )
            }
            Self::SameNode { node_id } => {
                write!(
                    formatter,
                    "cannot correlate infrastructure node `{node_id}` with itself"
                )
            }
            Self::NoComparableObservations {
                left_node,
                right_node,
            } => write!(
                formatter,
                "no comparable infrastructure observations for `{left_node}` and `{right_node}`"
            ),
            Self::DuplicateCorrelation { correlation_id } => {
                write!(
                    formatter,
                    "duplicate infrastructure correlation `{correlation_id}`"
                )
            }
            Self::SourceConflict { source_id } => {
                write!(formatter, "source `{source_id}` has conflicting metadata")
            }
            Self::ObservationConflict { observation_id } => {
                write!(
                    formatter,
                    "observation `{observation_id}` conflicts with canonical evidence"
                )
            }
            Self::Provenance { error } => {
                write!(formatter, "canonical persistence failed: {error}")
            }
        }
    }
}

impl std::error::Error for InfrastructureError {}

impl crate::validation::EmptyValueError for InfrastructureError {
    fn empty_value(field: &'static str) -> Self {
        Self::EmptyValue { field }
    }
}

fn require_text(value: String, field: &'static str) -> Result<String, InfrastructureError> {
    crate::validation::require_text(value, field)
}

impl From<ProvenanceError> for InfrastructureError {
    fn from(error: ProvenanceError) -> Self {
        Self::Provenance { error }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ScoreMode<'a> {
    Baseline,
    WithoutHighBaseRate,
    WithoutGroup(&'a str),
    PerturbedUncertainty,
}

#[derive(Debug, Clone)]
struct Support {
    explanation: InfrastructureExplanation,
    left_observation: String,
    right_observation: String,
    group: String,
    weight: u16,
    temporal_relation: TemporalRelation,
    high_base_rate: bool,
    uncertainty: u8,
}

#[derive(Debug, Clone)]
struct ComparablePair<'a> {
    left: &'a InfrastructureObservation,
    right: &'a InfrastructureObservation,
    temporal_relation: TemporalRelation,
    base_weight: u16,
}

/// Temporal metamorphic infrastructure correlation engine.
#[derive(Debug, Clone)]
pub struct TemporalMetamorphicInfrastructureCorrelationEngine {
    evidence: EvidenceStore,
    limits: InfrastructureLimits,
    correlation_source: Source,
    observations: BTreeMap<String, InfrastructureObservation>,
    node_observations: BTreeMap<String, BTreeSet<String>>,
    correlations: BTreeMap<String, InfrastructureCorrelationReport>,
}

impl TemporalMetamorphicInfrastructureCorrelationEngine {
    /// Creates an engine with default limits and a derived edge source.
    #[must_use]
    pub fn new(evidence: EvidenceStore) -> Self {
        let correlation_source = Source::new(
            CORRELATION_SOURCE_ID,
            SourceType::Derived,
            RetrievalMethod::Derived,
        )
        .expect("the built-in correlation source has valid metadata");
        Self {
            evidence,
            limits: InfrastructureLimits::default(),
            correlation_source,
            observations: BTreeMap::new(),
            node_observations: BTreeMap::new(),
            correlations: BTreeMap::new(),
        }
    }

    /// Creates an engine with explicit resource limits.
    #[must_use]
    pub fn with_limits(evidence: EvidenceStore, limits: InfrastructureLimits) -> Self {
        let mut engine = Self::new(evidence);
        engine.limits = limits;
        engine
    }

    /// Returns a copy using a caller-supplied derived relationship source.
    #[must_use]
    pub fn with_correlation_source(mut self, source: Source) -> Self {
        self.correlation_source = source;
        self
    }

    /// Authoritative canonical evidence store.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceStore {
        &self.evidence
    }

    /// Mutable access to the canonical evidence store.
    #[must_use]
    pub const fn evidence_mut(&mut self) -> &mut EvidenceStore {
        &mut self.evidence
    }

    /// Consumes the engine and returns its canonical evidence store, so a caller composing the infrastructure engine
    /// with the OSINT, website, and fusion engines can move the store into the
    /// next stage without cloning it
    /// (see [`Self::evidence`] to borrow it in place).
    #[must_use]
    pub fn into_evidence(self) -> EvidenceStore {
        self.evidence
    }

    /// Configured limits.
    #[must_use]
    pub const fn limits(&self) -> InfrastructureLimits {
        self.limits
    }

    /// Relationship source used for derived correlation edges.
    #[must_use]
    pub const fn correlation_source(&self) -> &Source {
        &self.correlation_source
    }

    /// Registers and transactionally persists one infrastructure observation.
    pub fn observe(
        &mut self,
        observation: InfrastructureObservation,
    ) -> Result<(), InfrastructureError> {
        if self.observations.len() >= self.limits.max_observations {
            return Err(InfrastructureError::ResourceLimit {
                resource: "observations",
                limit: self.limits.max_observations,
            });
        }
        let observation_id = observation.id().to_owned();
        if self.observations.contains_key(&observation_id) {
            return Err(InfrastructureError::DuplicateObservation { observation_id });
        }
        if let Some(existing) = self.evidence.source(observation.source_id())
            && existing != observation.source()
        {
            return Err(InfrastructureError::SourceConflict {
                source_id: observation.source_id().to_owned(),
            });
        }
        let canonical = observation.canonical_observation()?;
        if let Some(existing) = self.evidence.observation(observation.id())
            && existing != &canonical
        {
            return Err(InfrastructureError::ObservationConflict { observation_id });
        }

        self.evidence.transaction(|store| {
            if store.source(observation.source_id()).is_none() {
                store.add_source(observation.source().clone())?;
            }
            if store.entity(observation.node_id()).is_none() {
                store.add_entity(Entity::new(
                    observation.node_id(),
                    EntityType::Infrastructure,
                )?)?;
            }
            if store.observation(observation.id()).is_none() {
                store.add_observation(canonical)?;
            }
            Ok::<(), InfrastructureError>(())
        })?;
        self.node_observations
            .entry(observation.node_id().to_owned())
            .or_default()
            .insert(observation_id.clone());
        self.observations.insert(observation_id, observation);
        Ok(())
    }

    /// Convenience alias for [`Self::observe`].
    pub fn add_observation(
        &mut self,
        observation: InfrastructureObservation,
    ) -> Result<(), InfrastructureError> {
        self.observe(observation)
    }

    /// Returns one engine observation.
    #[must_use]
    pub fn observation(&self, observation_id: &str) -> Option<&InfrastructureObservation> {
        self.observations.get(observation_id)
    }

    /// Returns all engine observations in stable identifier order.
    pub fn observations(&self) -> impl Iterator<Item = &InfrastructureObservation> {
        self.observations.values()
    }

    /// Returns observations for one infrastructure node.
    pub fn observations_for_node(
        &self,
        node_id: &str,
    ) -> impl Iterator<Item = &InfrastructureObservation> {
        self.node_observations
            .get(node_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.observations.get(id))
    }

    /// Number of registered observations.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Number of persisted correlation edges.
    #[must_use]
    pub fn correlation_count(&self) -> usize {
        self.correlations.len()
    }

    /// Returns a persisted correlation report.
    #[must_use]
    pub fn correlation(&self, correlation_id: &str) -> Option<&InfrastructureCorrelationReport> {
        self.correlations.get(correlation_id)
    }

    /// Returns all persisted reports in stable identifier order.
    pub fn correlations(&self) -> impl Iterator<Item = &InfrastructureCorrelationReport> {
        self.correlations.values()
    }

    /// Correlates two nodes, runs adversarial falsification, and persists the edge.
    pub fn correlate(
        &mut self,
        left_node: &str,
        right_node: &str,
    ) -> Result<InfrastructureCorrelationReport, InfrastructureError> {
        let left_node = require_text(left_node.to_owned(), "left node")?;
        let right_node = require_text(right_node.to_owned(), "right node")?;
        if left_node == right_node {
            return Err(InfrastructureError::SameNode { node_id: left_node });
        }
        if !self.node_observations.contains_key(&left_node) {
            return Err(InfrastructureError::MissingNode { node_id: left_node });
        }
        if !self.node_observations.contains_key(&right_node) {
            return Err(InfrastructureError::MissingNode {
                node_id: right_node,
            });
        }
        if self.correlations.len() >= self.limits.max_correlations {
            return Err(InfrastructureError::ResourceLimit {
                resource: "correlations",
                limit: self.limits.max_correlations,
            });
        }

        let correlation_id = correlation_identifier(&left_node, &right_node);
        if self.correlations.contains_key(&correlation_id) {
            return Err(InfrastructureError::DuplicateCorrelation { correlation_id });
        }

        let pairs = self.comparable_pairs(&left_node, &right_node);
        if pairs.is_empty() {
            return Err(InfrastructureError::NoComparableObservations {
                left_node,
                right_node,
            });
        }
        let supports = self.supports(&pairs);
        let rankings = rank_supports(&supports, ScoreMode::Baseline);
        let baseline = rankings.first().cloned().ok_or_else(|| {
            InfrastructureError::NoComparableObservations {
                left_node: left_node.clone(),
                right_node: right_node.clone(),
            }
        })?;
        if baseline.score == 0 {
            return Err(InfrastructureError::NoComparableObservations {
                left_node,
                right_node,
            });
        }
        let falsification = build_falsification(&supports, &rankings, &baseline);
        let leading = baseline.explanation;
        let control_assessment = control_assessment(leading);
        let temporal_relation = strongest_temporal_relation(&baseline);
        let observation_ids = unique_observation_ids(baseline.supporting_observation_ids());
        let relationship_id = format!("{correlation_id}:relationship");
        let edge_type = if falsification.survives {
            EdgeType::Inferred
        } else {
            EdgeType::Contested
        };
        let predicate = format!("infrastructure-correlation:{}", leading.as_str());
        let edge = InfrastructureCorrelationEdge {
            id: correlation_id.clone(),
            subject: left_node.clone(),
            object: right_node.clone(),
            predicate: predicate.clone(),
            edge_type,
            leading_explanation: leading,
            confidence: baseline.confidence,
            temporal_relation,
            observation_ids: observation_ids.clone(),
            control_assessment,
            relationship_id: relationship_id.clone(),
        };

        if let Some(existing) = self.evidence.source(self.correlation_source.id())
            && existing != &self.correlation_source
        {
            return Err(InfrastructureError::SourceConflict {
                source_id: self.correlation_source.id().to_owned(),
            });
        }
        let timestamp = observation_ids
            .iter()
            .filter_map(|id| self.observations.get(id))
            .map(InfrastructureObservation::observed_at)
            .max()
            .unwrap_or(0);
        let provenance = RelationshipProvenance::new(
            self.correlation_source.id().to_owned(),
            timestamp,
            CORRELATION_METHOD,
        )?
        .from_observations(observation_ids);
        let relationship = Relationship::new(
            relationship_id,
            left_node,
            predicate,
            right_node,
            edge_type,
            provenance,
        )?
        .with_confidence(baseline.confidence);
        let correlation_source = &self.correlation_source;
        self.evidence.transaction(|store| {
            if store.source(correlation_source.id()).is_none() {
                store.add_source(correlation_source.clone())?;
            }
            store.add_relationship(relationship)?;
            Ok::<(), InfrastructureError>(())
        })?;

        let report = InfrastructureCorrelationReport {
            edge,
            rankings,
            falsification,
            temporal_relation,
            phases: vec![
                InfrastructurePhase::Capture,
                InfrastructurePhase::Normalize,
                InfrastructurePhase::TemporalAlign,
                InfrastructurePhase::Compare,
                InfrastructurePhase::Score,
                InfrastructurePhase::Falsify,
                InfrastructurePhase::Persist,
                InfrastructurePhase::Recompute,
            ],
        };
        self.correlations.insert(correlation_id, report.clone());
        Ok(report)
    }

    /// Convenience alias emphasizing pairwise correlation.
    pub fn correlate_pair(
        &mut self,
        left_node: &str,
        right_node: &str,
    ) -> Result<InfrastructureCorrelationReport, InfrastructureError> {
        self.correlate(left_node, right_node)
    }

    /// Correlates every pair of nodes not yet correlated in either direction,
    /// skipping pairs with no comparable values.
    ///
    /// The batch is transactional: any other failure (a resource limit, a
    /// source conflict, a provenance error) leaves the engine and its evidence
    /// store unchanged. Only the reports persisted by this call are returned,
    /// in node-identifier order, so repeating the call once every comparable
    /// pair is covered yields an empty list rather than a duplicate-correlation
    /// error.
    pub fn correlate_all(
        &mut self,
    ) -> Result<Vec<InfrastructureCorrelationReport>, InfrastructureError> {
        let node_ids: Vec<_> = self.node_observations.keys().cloned().collect();
        let mut reports = Vec::new();
        let outcome = EvidenceStore::transaction_through(
            self,
            |engine| &mut engine.evidence,
            |engine| engine.correlate_pairs(&node_ids, &mut reports),
        );
        if outcome.is_err() {
            for report in &reports {
                self.correlations.remove(report.edge().id());
            }
        }
        outcome.map(|()| reports)
    }

    /// Correlates every uncorrelated comparable pair in key order, appending
    /// each persisted report; the caller provides the transaction.
    fn correlate_pairs(
        &mut self,
        node_ids: &[String],
        reports: &mut Vec<InfrastructureCorrelationReport>,
    ) -> Result<(), InfrastructureError> {
        for (left_index, left_node) in node_ids.iter().enumerate() {
            for right_node in node_ids.iter().skip(left_index + 1) {
                if self.is_correlated(left_node, right_node) {
                    continue;
                }
                match self.correlate(left_node, right_node) {
                    Ok(report) => reports.push(report),
                    Err(InfrastructureError::NoComparableObservations { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    /// Whether a pair already has a persisted correlation in either direction.
    fn is_correlated(&self, left_node: &str, right_node: &str) -> bool {
        self.correlations
            .contains_key(&correlation_identifier(left_node, right_node))
            || self
                .correlations
                .contains_key(&correlation_identifier(right_node, left_node))
    }

    /// Returns persisted reports ordered by descending leading confidence.
    pub fn ranked_correlations(&self) -> Vec<&InfrastructureCorrelationReport> {
        let mut reports: Vec<_> = self.correlations.values().collect();
        reports.sort_by(|left, right| {
            right
                .confidence()
                .cmp(&left.confidence())
                .then_with(|| left.edge.id.cmp(&right.edge.id))
        });
        reports
    }

    fn comparable_pairs(&self, left_node: &str, right_node: &str) -> Vec<ComparablePair<'_>> {
        let left_observations: Vec<&InfrastructureObservation> =
            self.observations_for_node(left_node).collect();
        let right_observations: Vec<&InfrastructureObservation> =
            self.observations_for_node(right_node).collect();
        let mut pairs = Vec::new();
        for (left, right) in matching_pairs(&left_observations, &right_observations) {
            let temporal_relation = temporal_relation(
                left.timeline(),
                right.timeline(),
                self.limits.maximum_temporal_gap,
            );
            let temporal_score = temporal_score(
                temporal_relation,
                left.timeline(),
                right.timeline(),
                self.limits.maximum_temporal_gap,
            );
            let factor_weight = (u16::from(left.factors().calibrated_weight())
                + u16::from(right.factors().calibrated_weight()))
                / 2;
            let mut base_weight = (factor_weight + u16::from(temporal_score)) / 2;
            if left.is_high_base_rate() || right.is_high_base_rate() {
                base_weight /= 2;
            }
            if temporal_relation == TemporalRelation::Disjoint {
                base_weight /= 2;
            }
            pairs.push(ComparablePair {
                left,
                right,
                temporal_relation,
                base_weight,
            });
        }
        pairs.sort_by(|left, right| {
            left.left
                .id()
                .cmp(right.left.id())
                .then_with(|| left.right.id().cmp(right.right.id()))
        });
        pairs
    }

    fn supports(&self, pairs: &[ComparablePair<'_>]) -> Vec<Support> {
        let mut supports = Vec::new();
        for pair in pairs {
            let explanations = explanations_for(pair.left, pair.right);
            let group = dependency_group(pair.left).to_owned() + "|" + dependency_group(pair.right);
            let uncertainty = pair
                .left
                .factors()
                .uncertainty()
                .value()
                .max(pair.right.factors().uncertainty().value());
            for explanation in explanations {
                let mut weight = pair.base_weight;
                if explanation == InfrastructureExplanation::PossibleCommonAdministration {
                    weight = weight.min(60);
                } else if explanation == InfrastructureExplanation::Unknown {
                    weight /= 2;
                }
                supports.push(Support {
                    explanation,
                    left_observation: pair.left.id().to_owned(),
                    right_observation: pair.right.id().to_owned(),
                    group: group.clone(),
                    weight,
                    temporal_relation: pair.temporal_relation,
                    high_base_rate: pair.left.is_high_base_rate() || pair.right.is_high_base_rate(),
                    uncertainty,
                });
            }
        }
        supports
    }
}

/// Accessor surface shared by every engine module's per-observation value
/// comparison, letting [`values_match`] be written once instead of once per
/// module's concrete observation type.
pub(crate) trait ComparableValue {
    /// Stable feature signature, if supplied.
    fn feature_key(&self) -> Option<&str>;
    /// Additive normalized value, if available.
    fn normalized_value(&self) -> Option<&EvidenceValue>;
    /// Exact raw value captured from the source.
    fn raw_value(&self) -> &EvidenceValue;
}

impl ComparableValue for InfrastructureObservation {
    fn feature_key(&self) -> Option<&str> {
        Self::feature_key(self)
    }

    fn normalized_value(&self) -> Option<&EvidenceValue> {
        Self::normalized_value(self)
    }

    fn raw_value(&self) -> &EvidenceValue {
        Self::raw_value(self)
    }
}

pub(crate) fn values_match<O: ComparableValue>(left: &O, right: &O) -> bool {
    if let (Some(left_feature), Some(right_feature)) = (left.feature_key(), right.feature_key())
        && left_feature == right_feature
    {
        return true;
    }
    match (left.normalized_value(), right.normalized_value()) {
        (Some(left_value), Some(right_value)) if left_value == right_value => true,
        (Some(left_value), _) if left_value == right.raw_value() => true,
        (_, Some(right_value)) if left.raw_value() == right_value => true,
        _ => left.raw_value() == right.raw_value(),
    }
}

/// Orderable projection of an [`EvidenceValue`] used to index observations by
/// value; `None` for a NaN float, which never matches anything. Signed zeros
/// share one key so the index never misses a pair that [`values_match`]
/// would accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ValueKey<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
    Integer(i128),
    Float(u64),
    Boolean(bool),
    Null,
}

fn value_key(value: &EvidenceValue) -> Option<ValueKey<'_>> {
    Some(match value {
        EvidenceValue::Text(text) => ValueKey::Text(text),
        EvidenceValue::Bytes(bytes) => ValueKey::Bytes(bytes),
        EvidenceValue::Integer(integer) => ValueKey::Integer(*integer),
        EvidenceValue::Float(float) if float.is_nan() => return None,
        EvidenceValue::Float(float) => {
            ValueKey::Float(if *float == 0.0 { 0.0f64 } else { *float }.to_bits())
        }
        EvidenceValue::Boolean(boolean) => ValueKey::Boolean(*boolean),
        EvidenceValue::Null => ValueKey::Null,
    })
}

/// Every `(left, right)` pair for which [`values_match`] holds, found through
/// indexes over the right-hand feature keys, normalized values and raw values
/// instead of a left × right scan. Every candidate the indexes propose is
/// re-checked with [`values_match`], and the indexes cover each of its
/// clauses, so the result is exactly the scan's set (in index order).
pub(crate) fn matching_pairs<'a, O: ComparableValue>(
    left: &[&'a O],
    right: &[&'a O],
) -> Vec<(&'a O, &'a O)> {
    let mut by_feature: BTreeMap<&'a str, Vec<usize>> = BTreeMap::new();
    let mut by_normalized: BTreeMap<ValueKey<'a>, Vec<usize>> = BTreeMap::new();
    let mut by_raw: BTreeMap<ValueKey<'a>, Vec<usize>> = BTreeMap::new();
    for (index, &observation) in right.iter().enumerate() {
        if let Some(feature) = observation.feature_key() {
            by_feature.entry(feature).or_default().push(index);
        }
        if let Some(key) = observation.normalized_value().and_then(value_key) {
            by_normalized.entry(key).or_default().push(index);
        }
        if let Some(key) = value_key(observation.raw_value()) {
            by_raw.entry(key).or_default().push(index);
        }
    }
    let mut pairs = Vec::new();
    let mut candidates = BTreeSet::new();
    for &observation in left {
        candidates.clear();
        if let Some(indexes) = observation.feature_key().and_then(|f| by_feature.get(f)) {
            candidates.extend(indexes.iter().copied());
        }
        let keys = [
            observation.normalized_value().and_then(value_key),
            value_key(observation.raw_value()),
        ];
        for key in keys.iter().flatten() {
            if let Some(indexes) = by_normalized.get(key) {
                candidates.extend(indexes.iter().copied());
            }
            if let Some(indexes) = by_raw.get(key) {
                candidates.extend(indexes.iter().copied());
            }
        }
        for &index in &candidates {
            if values_match(observation, right[index]) {
                pairs.push((observation, right[index]));
            }
        }
    }
    pairs
}

pub(crate) fn temporal_relation(
    left: TemporalInterval,
    right: TemporalInterval,
    maximum_gap: Timestamp,
) -> TemporalRelation {
    if left.overlaps(right) {
        TemporalRelation::Overlapping
    } else if left.is_contiguous_with(right, maximum_gap) {
        TemporalRelation::Contiguous
    } else {
        TemporalRelation::Disjoint
    }
}

pub(crate) fn temporal_score(
    relation: TemporalRelation,
    left: TemporalInterval,
    right: TemporalInterval,
    maximum_gap: Timestamp,
) -> u8 {
    match relation {
        TemporalRelation::Overlapping => 100,
        TemporalRelation::Contiguous => {
            if maximum_gap == 0 {
                50
            } else {
                let gap = left.gap(right).min(maximum_gap);
                50 + (maximum_gap.saturating_sub(gap).saturating_mul(50) / maximum_gap) as u8
            }
        }
        TemporalRelation::Disjoint => 0,
    }
}

fn explanations_for(
    left: &InfrastructureObservation,
    right: &InfrastructureObservation,
) -> Vec<InfrastructureExplanation> {
    let mut explanations = BTreeSet::new();
    match (left.kind(), right.kind()) {
        (InfrastructureKind::Domain, InfrastructureKind::Domain)
        | (InfrastructureKind::Dns, InfrastructureKind::Dns)
        | (InfrastructureKind::Domain, InfrastructureKind::Dns)
        | (InfrastructureKind::Dns, InfrastructureKind::Domain) => {
            explanations.insert(InfrastructureExplanation::CommonRegistrar);
            explanations.insert(InfrastructureExplanation::DirectTechnicalRelationship);
        }
        (InfrastructureKind::IpAddress, InfrastructureKind::IpAddress)
        | (InfrastructureKind::Asn, InfrastructureKind::Asn)
        | (InfrastructureKind::HostingProvider, InfrastructureKind::HostingProvider) => {
            explanations.insert(InfrastructureExplanation::CommonHost);
            explanations.insert(InfrastructureExplanation::CommonCdn);
            explanations.insert(InfrastructureExplanation::SharedThirdPartyService);
        }
        (InfrastructureKind::Certificate, InfrastructureKind::Certificate) => {
            explanations.insert(InfrastructureExplanation::DirectTechnicalRelationship);
            explanations.insert(InfrastructureExplanation::SharedThirdPartyService);
        }
        (InfrastructureKind::HttpCharacteristic, InfrastructureKind::HttpCharacteristic)
        | (InfrastructureKind::ApplicationStructure, InfrastructureKind::ApplicationStructure) => {
            explanations.insert(InfrastructureExplanation::CommonCms);
            explanations.insert(InfrastructureExplanation::CommonTemplate);
            explanations.insert(InfrastructureExplanation::SharedThirdPartyService);
        }
        (InfrastructureKind::PublicAsset, InfrastructureKind::PublicAsset)
        | (InfrastructureKind::PublicIdentifier, InfrastructureKind::PublicIdentifier)
        | (InfrastructureKind::ArchivedState, InfrastructureKind::ArchivedState) => {
            explanations.insert(InfrastructureExplanation::DirectTechnicalRelationship);
            explanations.insert(InfrastructureExplanation::CommonTemplate);
            explanations.insert(InfrastructureExplanation::SharedThirdPartyService);
        }
        (
            InfrastructureKind::Domain,
            InfrastructureKind::IpAddress
            | InfrastructureKind::Certificate
            | InfrastructureKind::HostingProvider,
        )
        | (
            InfrastructureKind::Dns,
            InfrastructureKind::IpAddress
            | InfrastructureKind::Certificate
            | InfrastructureKind::HostingProvider,
        )
        | (
            InfrastructureKind::IpAddress,
            InfrastructureKind::Domain | InfrastructureKind::Dns | InfrastructureKind::Certificate,
        )
        | (
            InfrastructureKind::Certificate,
            InfrastructureKind::Domain | InfrastructureKind::Dns | InfrastructureKind::IpAddress,
        )
        | (
            InfrastructureKind::HostingProvider,
            InfrastructureKind::Domain | InfrastructureKind::Dns,
        ) => {
            explanations.insert(InfrastructureExplanation::DirectTechnicalRelationship);
        }
        _ => {
            explanations.insert(InfrastructureExplanation::SharedThirdPartyService);
        }
    }
    if !left.is_high_base_rate()
        && !right.is_high_base_rate()
        && left.factors().rarity().value() >= 70
        && right.factors().rarity().value() >= 70
        && left.factors().specificity().value() >= 70
        && right.factors().specificity().value() >= 70
    {
        explanations.insert(InfrastructureExplanation::PossibleCommonAdministration);
    }
    explanations.insert(InfrastructureExplanation::Unknown);
    explanations.into_iter().collect()
}

/// Accessor surface needed by [`dependency_group`]'s fallback resolution,
/// letting it be written once instead of once per module's concrete
/// observation type.
pub(crate) trait ObservationSource {
    /// Explicit dependency group, if supplied.
    fn dependency_group(&self) -> Option<&str>;
    /// Source record, including its retrieval metadata.
    fn source(&self) -> &Source;
}

impl ObservationSource for InfrastructureObservation {
    fn dependency_group(&self) -> Option<&str> {
        Self::dependency_group(self)
    }

    fn source(&self) -> &Source {
        Self::source(self)
    }
}

pub(crate) fn dependency_group<O: ObservationSource>(observation: &O) -> &str {
    observation
        .dependency_group()
        .or_else(|| {
            observation
                .source()
                .metadata()
                .get("dependency_group")
                .map(String::as_str)
        })
        .or_else(|| {
            observation
                .source()
                .metadata()
                .get("provider")
                .map(String::as_str)
        })
        .or_else(|| {
            observation
                .source()
                .metadata()
                .get("dataset")
                .map(String::as_str)
        })
        .unwrap_or_else(|| observation.source().id())
}

/// Accessor surface shared by every engine module's per-pair support record,
/// letting [`active_weight`] and [`pair_key`] be written once instead of once
/// per module's concrete `Support` type.
pub(crate) trait SupportFields {
    /// Dependency group the support belongs to.
    fn group(&self) -> &str;
    /// Whether the support is subject to common-feature down-weighting.
    fn high_base_rate(&self) -> bool;
    /// Uncertainty penalty in percentage points.
    fn uncertainty(&self) -> u8;
    /// Blended base weight before mode adjustments.
    fn weight(&self) -> u16;
    /// Left observation identifier.
    fn left_observation(&self) -> &str;
    /// Right observation identifier.
    fn right_observation(&self) -> &str;
}

impl SupportFields for Support {
    fn group(&self) -> &str {
        &self.group
    }

    fn high_base_rate(&self) -> bool {
        self.high_base_rate
    }

    fn uncertainty(&self) -> u8 {
        self.uncertainty
    }

    fn weight(&self) -> u16 {
        self.weight
    }

    fn left_observation(&self) -> &str {
        &self.left_observation
    }

    fn right_observation(&self) -> &str {
        &self.right_observation
    }
}

impl<T: SupportFields> SupportFields for &T {
    fn group(&self) -> &str {
        T::group(self)
    }

    fn high_base_rate(&self) -> bool {
        T::high_base_rate(self)
    }

    fn uncertainty(&self) -> u8 {
        T::uncertainty(self)
    }

    fn weight(&self) -> u16 {
        T::weight(self)
    }

    fn left_observation(&self) -> &str {
        T::left_observation(self)
    }

    fn right_observation(&self) -> &str {
        T::right_observation(self)
    }
}

pub(crate) fn active_weight<S: SupportFields>(support: &S, mode: ScoreMode<'_>) -> u16 {
    match mode {
        ScoreMode::WithoutHighBaseRate if support.high_base_rate() => 0,
        ScoreMode::WithoutGroup(group) if support.group() == group => 0,
        _ => {
            let uncertainty_factor = match mode {
                ScoreMode::PerturbedUncertainty => 100 - u16::from(support.uncertainty()),
                _ => 100,
            };
            support.weight().saturating_mul(uncertainty_factor) / 100
        }
    }
}

/// Orders two supports by their `"{left}:{right}"` pair key, exactly as the
/// concatenated strings would compare, without building them: the common
/// prefix of the left identifiers is compared as slices, and only when one
/// left identifier is a prefix of the other does the comparison continue
/// byte by byte across the separator.
pub(crate) fn pair_key_cmp<S: SupportFields>(left: &S, right: &S) -> std::cmp::Ordering {
    let (l1, r1) = (
        left.left_observation().as_bytes(),
        left.right_observation().as_bytes(),
    );
    let (l2, r2) = (
        right.left_observation().as_bytes(),
        right.right_observation().as_bytes(),
    );
    let shared = l1.len().min(l2.len());
    match l1[..shared].cmp(&l2[..shared]) {
        std::cmp::Ordering::Equal if l1.len() == l2.len() => r1.cmp(r2),
        std::cmp::Ordering::Equal => {
            let tail = |longer: &[u8], own: &[u8]| -> Vec<u8> {
                let mut bytes = longer[shared..].to_vec();
                bytes.push(b':');
                bytes.extend_from_slice(own);
                bytes
            };
            // One left identifier extends the other: compare the remaining
            // bytes of each key from the divergence point.
            if l1.len() < l2.len() {
                let mut own = vec![b':'];
                own.extend_from_slice(r1);
                own.cmp(&tail(l2, r2))
            } else {
                let mut other = vec![b':'];
                other.extend_from_slice(r2);
                tail(l1, r1).cmp(&other)
            }
        }
        ordering => ordering,
    }
}

/// Corroborated score for one explanation: the strongest retained support
/// plus ten points per additional independent support, with the corroboration
/// capped at the headroom below 100.
///
/// Computed in `usize` so any number of supports representable in memory is
/// safe; `u16` arithmetic overflowed at 6,555 independent supports.
pub(crate) fn corroborated_score(strongest: u16, independent_support: usize) -> u16 {
    let headroom = 100u16.saturating_sub(strongest);
    let corroboration = independent_support
        .saturating_sub(1)
        .saturating_mul(10)
        .min(usize::from(headroom));
    strongest.saturating_add(u16::try_from(corroboration).unwrap_or(headroom))
}

/// Points one temporal relation contributes to temporal compatibility.
const fn temporal_compatibility_points(relation: TemporalRelation) -> u8 {
    match relation {
        TemporalRelation::Overlapping => 100,
        TemporalRelation::Contiguous => 75,
        TemporalRelation::Disjoint => 0,
    }
}

/// Mean temporal compatibility (0–100) over retained supports, or 0 when there
/// are none.
///
/// Accumulated in `u64` so the sum cannot overflow and the divisor cannot be
/// truncated; `u16` arithmetic overflowed the sum at 656 overlapping supports
/// (panicking in debug builds and silently reporting a wrong mean in release
/// builds) and truncated the divisor to zero at 65,536 supports.
pub(crate) fn mean_temporal_compatibility(relations: impl Iterator<Item = TemporalRelation>) -> u8 {
    let (total, count) = relations.fold((0u64, 0u64), |(total, count), relation| {
        (
            total.saturating_add(u64::from(temporal_compatibility_points(relation))),
            count.saturating_add(1),
        )
    });
    if count == 0 {
        return 0;
    }
    // The mean of values in 0..=100 is itself in 0..=100.
    u8::try_from(total / count).unwrap_or(100)
}

/// Observation pairs carrying at least one high-base-rate support under any
/// explanation, so each retained pair is checked with one lookup instead of a
/// scan over every support.
pub(crate) fn high_base_rate_pairs<S: SupportFields>(supports: &[S]) -> BTreeSet<(&str, &str)> {
    supports
        .iter()
        .filter(|support| support.high_base_rate())
        .map(|support| (support.left_observation(), support.right_observation()))
        .collect()
}

/// Sorted, de-duplicated observation identifiers cited by a canonical edge.
pub(crate) fn unique_observation_ids(mut ids: Vec<String>) -> Vec<String> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Stable identifier of the persisted correlation from `left_node` to
/// `right_node`.
fn correlation_identifier(left_node: &str, right_node: &str) -> String {
    format!("infrastructure-correlation:{left_node}:{right_node}")
}

fn rank_supports(supports: &[Support], mode: ScoreMode<'_>) -> Vec<CorrelationRanking> {
    let flagged = high_base_rate_pairs(supports);
    let mut explanations = BTreeSet::new();
    for support in supports {
        explanations.insert(support.explanation);
    }
    let mut rankings = explanations
        .into_iter()
        .map(|explanation| rank_explanation(supports, &flagged, explanation, mode))
        .collect::<Vec<_>>();
    rankings.sort_by(|left, right| {
        right.score.cmp(&left.score).then_with(|| {
            explanation_order(left.explanation).cmp(&explanation_order(right.explanation))
        })
    });
    rankings
}

fn explanation_order(explanation: InfrastructureExplanation) -> u8 {
    match explanation {
        InfrastructureExplanation::DirectTechnicalRelationship => 0,
        InfrastructureExplanation::PossibleCommonAdministration => 1,
        InfrastructureExplanation::CommonHost => 2,
        InfrastructureExplanation::CommonCdn => 3,
        InfrastructureExplanation::CommonCms => 4,
        InfrastructureExplanation::CommonTemplate => 5,
        InfrastructureExplanation::CommonRegistrar => 6,
        InfrastructureExplanation::SharedThirdPartyService => 7,
        InfrastructureExplanation::Unknown => 8,
    }
}

fn rank_explanation(
    supports: &[Support],
    flagged: &BTreeSet<(&str, &str)>,
    explanation: InfrastructureExplanation,
    mode: ScoreMode<'_>,
) -> CorrelationRanking {
    let mut retained: BTreeMap<String, (&Support, u16)> = BTreeMap::new();
    let mut collapsed = Vec::new();
    for support in supports
        .iter()
        .filter(|support| support.explanation == explanation)
    {
        let weight = active_weight(support, mode);
        if weight == 0 {
            continue;
        }
        match retained.get(&support.group) {
            Some((previous, previous_weight))
                if *previous_weight > weight
                    || (*previous_weight == weight && pair_key_cmp(*previous, support).is_le()) =>
            {
                collapsed.push(to_pair(support, weight));
            }
            Some((previous, previous_weight)) => {
                collapsed.push(to_pair(previous, *previous_weight));
                retained.insert(support.group.clone(), (support, weight));
            }
            None => {
                retained.insert(support.group.clone(), (support, weight));
            }
        }
    }
    let supporting_pairs: Vec<_> = retained
        .values()
        .map(|(support, weight)| to_pair(support, *weight))
        .collect();
    let independent_support = supporting_pairs.len();
    let strongest = supporting_pairs
        .iter()
        .map(|pair| pair.weight)
        .max()
        .unwrap_or(0);
    let score = corroborated_score(strongest, independent_support);
    let temporal_compatibility =
        mean_temporal_compatibility(supporting_pairs.iter().map(|pair| pair.temporal_relation));
    let high_base_rate_support = supporting_pairs.iter().any(|pair| {
        flagged.contains(&(
            pair.left_observation.as_str(),
            pair.right_observation.as_str(),
        ))
    });
    CorrelationRanking {
        explanation,
        score,
        confidence: Confidence::new(score.min(100) as u8),
        independent_support,
        high_base_rate_support,
        supporting_pairs,
        collapsed_pairs: collapsed,
        temporal_compatibility: Confidence::new(temporal_compatibility),
    }
}

fn to_pair(support: &Support, weight: u16) -> ObservationPair {
    ObservationPair {
        left_observation: support.left_observation.clone(),
        right_observation: support.right_observation.clone(),
        weight,
        temporal_relation: support.temporal_relation,
    }
}

fn build_falsification(
    supports: &[Support],
    baseline_rankings: &[CorrelationRanking],
    baseline: &CorrelationRanking,
) -> CorrelationFalsification {
    let without_high_base_rate = rank_supports(supports, ScoreMode::WithoutHighBaseRate)
        .into_iter()
        .find(|ranking| ranking.explanation == baseline.explanation)
        .unwrap_or_else(|| empty_ranking(baseline.explanation));
    let strongest_group = supports
        .iter()
        .filter(|support| support.explanation == baseline.explanation)
        .max_by(|left, right| {
            active_weight(left, ScoreMode::Baseline)
                .cmp(&active_weight(right, ScoreMode::Baseline))
                .then_with(|| pair_key_cmp(left, right))
        })
        .map(|support| support.group.clone());
    let without_strongest_support = rank_supports(
        supports,
        strongest_group
            .as_deref()
            .map_or(ScoreMode::Baseline, ScoreMode::WithoutGroup),
    )
    .into_iter()
    .find(|ranking| ranking.explanation == baseline.explanation)
    .unwrap_or_else(|| empty_ranking(baseline.explanation));
    let perturbed_uncertainty = rank_supports(supports, ScoreMode::PerturbedUncertainty)
        .into_iter()
        .find(|ranking| ranking.explanation == baseline.explanation)
        .unwrap_or_else(|| empty_ranking(baseline.explanation));
    let strongest_alternative = baseline_rankings
        .iter()
        .find(|ranking| ranking.explanation != baseline.explanation && ranking.score > 0)
        .map(|ranking| ranking.explanation);
    let removed_support = strongest_group.as_deref().and_then(|group| {
        supports
            .iter()
            .filter(|support| support.explanation == baseline.explanation && support.group == group)
            .max_by_key(|support| active_weight(support, ScoreMode::Baseline))
            .map(|support| to_pair(support, active_weight(support, ScoreMode::Baseline)))
    });
    let missing_expected_evidence = missing_expected_evidence(baseline);
    let survives = baseline.score > 0
        && without_high_base_rate.score > 0
        && without_strongest_support.score > 0
        && perturbed_uncertainty.score > 0
        && strongest_alternative.is_none_or(|alternative| {
            baseline.score >= score_for(supports, alternative, ScoreMode::Baseline)
        });
    CorrelationFalsification {
        leading_explanation: baseline.explanation,
        strongest_alternative,
        baseline: baseline.clone(),
        without_high_base_rate,
        without_strongest_support,
        perturbed_uncertainty,
        removed_support,
        missing_expected_evidence,
        survives,
    }
}

fn score_for(
    supports: &[Support],
    explanation: InfrastructureExplanation,
    mode: ScoreMode<'_>,
) -> u16 {
    rank_supports(supports, mode)
        .into_iter()
        .find(|ranking| ranking.explanation == explanation)
        .map_or(0, |ranking| ranking.score)
}

fn empty_ranking(explanation: InfrastructureExplanation) -> CorrelationRanking {
    CorrelationRanking {
        explanation,
        score: 0,
        confidence: Confidence::new(0),
        independent_support: 0,
        supporting_pairs: Vec::new(),
        collapsed_pairs: Vec::new(),
        high_base_rate_support: false,
        temporal_compatibility: Confidence::new(0),
    }
}

fn missing_expected_evidence(baseline: &CorrelationRanking) -> Vec<InfrastructureKind> {
    match baseline.explanation {
        InfrastructureExplanation::PossibleCommonAdministration => {
            if baseline.independent_support < 2 {
                vec![
                    InfrastructureKind::Certificate,
                    InfrastructureKind::ArchivedState,
                ]
            } else {
                Vec::new()
            }
        }
        InfrastructureExplanation::DirectTechnicalRelationship
            if baseline.independent_support < 2 =>
        {
            vec![InfrastructureKind::Certificate]
        }
        _ => Vec::new(),
    }
}

fn strongest_temporal_relation(ranking: &CorrelationRanking) -> TemporalRelation {
    ranking
        .supporting_pairs()
        .iter()
        .map(ObservationPair::temporal_relation)
        .min()
        .unwrap_or(TemporalRelation::Disjoint)
}

fn control_assessment(explanation: InfrastructureExplanation) -> ControlAssessment {
    match explanation {
        InfrastructureExplanation::PossibleCommonAdministration => {
            ControlAssessment::PossibleCommonAdministration
        }
        InfrastructureExplanation::DirectTechnicalRelationship => {
            ControlAssessment::DirectTechnicalRelationship
        }
        InfrastructureExplanation::CommonCdn
        | InfrastructureExplanation::CommonHost
        | InfrastructureExplanation::CommonCms
        | InfrastructureExplanation::CommonRegistrar
        | InfrastructureExplanation::CommonTemplate
        | InfrastructureExplanation::SharedThirdPartyService => {
            ControlAssessment::SharedInfrastructure
        }
        InfrastructureExplanation::Unknown => ControlAssessment::Unknown,
    }
}

/// Alias for the architecture's shorter engine name.
pub type InfrastructureCorrelationEngine = TemporalMetamorphicInfrastructureCorrelationEngine;

/// Alias emphasizing temporal correlation.
pub type TemporalInfrastructureCorrelationEngine =
    TemporalMetamorphicInfrastructureCorrelationEngine;

/// Alias for one infrastructure observation.
pub type InfrastructureRecord = InfrastructureObservation;

/// Alias for calibrated infrastructure factors.
pub type CorrelationFactors = InfrastructureFactors;

/// Alias for a competing explanation.
pub type CompetingExplanation = InfrastructureExplanation;

/// Alias for a persisted correlation edge.
pub type CorrelationEdge = InfrastructureCorrelationEdge;

/// Alias for a complete correlation execution report.
pub type CorrelationReport = InfrastructureCorrelationReport;

/// Alias for adversarial correlation falsification.
pub type InfrastructureFalsificationReport = CorrelationFalsification;

#[cfg(test)]
mod tests {
    use super::{
        InfrastructureKind, InfrastructureObservation, TemporalRelation, corroborated_score,
        matching_pairs, mean_temporal_compatibility, values_match,
    };
    use crate::{EvidenceValue, RetrievalMethod, Source, SourceType};

    #[test]
    fn matching_pairs_equals_the_full_scan_on_random_observations() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let source = Source::new("s", SourceType::Api, RetrievalMethod::Direct).unwrap();
        let values = [
            EvidenceValue::Text("a".to_owned()),
            EvidenceValue::Text("b".to_owned()),
            EvidenceValue::Bytes(vec![1, 2]),
            EvidenceValue::Integer(7),
            EvidenceValue::Float(0.0),
            EvidenceValue::Float(-0.0),
            EvidenceValue::Float(f64::NAN),
            EvidenceValue::Float(2.5),
            EvidenceValue::Boolean(true),
            EvidenceValue::Null,
        ];
        let observation = |id: usize, next: &mut dyn FnMut() -> u64| {
            let raw = values[(next() % values.len() as u64) as usize].clone();
            let mut item = InfrastructureObservation::new(
                format!("o{id}"),
                "node",
                InfrastructureKind::Domain,
                raw,
                source.clone(),
                1,
            )
            .unwrap();
            if next().is_multiple_of(2) {
                item = item
                    .with_normalized_value(values[(next() % values.len() as u64) as usize].clone());
            }
            if next().is_multiple_of(3) {
                item = item.with_feature(format!("f{}", next() % 3)).unwrap();
            }
            item
        };
        for round in 0..300 {
            let left: Vec<InfrastructureObservation> = (0..(round % 7))
                .map(|i| observation(i, &mut next))
                .collect();
            let right: Vec<InfrastructureObservation> = (0..(round % 5))
                .map(|i| observation(100 + i, &mut next))
                .collect();
            let left_refs: Vec<&InfrastructureObservation> = left.iter().collect();
            let right_refs: Vec<&InfrastructureObservation> = right.iter().collect();
            let mut indexed: Vec<(&str, &str)> = matching_pairs(&left_refs, &right_refs)
                .into_iter()
                .map(|(l, r)| (l.id(), r.id()))
                .collect();
            let mut scanned: Vec<(&str, &str)> = left
                .iter()
                .flat_map(|l| {
                    right
                        .iter()
                        .filter(move |r| values_match(l, *r))
                        .map(move |r| (l.id(), r.id()))
                })
                .collect();
            indexed.sort_unstable();
            scanned.sort_unstable();
            assert_eq!(indexed, scanned, "round {round}");
        }
    }

    #[test]
    fn corroborated_score_caps_corroboration_at_the_headroom_below_100() {
        assert_eq!(corroborated_score(0, 0), 0);
        assert_eq!(corroborated_score(40, 1), 40);
        assert_eq!(corroborated_score(40, 3), 60);
        assert_eq!(corroborated_score(40, 7), 100);
        // `(n - 1) * 10` overflowed a `u16` from here on.
        assert_eq!(corroborated_score(40, 6_555), 100);
        assert_eq!(corroborated_score(130, 2), 130);
        assert_eq!(corroborated_score(u16::MAX, usize::MAX), u16::MAX);
    }

    #[test]
    fn mean_temporal_compatibility_is_exact_beyond_u16_accumulation() {
        assert_eq!(mean_temporal_compatibility(std::iter::empty()), 0);
        assert_eq!(
            mean_temporal_compatibility(
                [TemporalRelation::Overlapping, TemporalRelation::Disjoint].into_iter()
            ),
            50
        );
        assert_eq!(
            mean_temporal_compatibility(
                [
                    TemporalRelation::Overlapping,
                    TemporalRelation::Contiguous,
                    TemporalRelation::Contiguous
                ]
                .into_iter()
            ),
            83
        );
        // A `u16` sum overflowed at 656 overlapping supports.
        assert_eq!(
            mean_temporal_compatibility(std::iter::repeat_n(TemporalRelation::Overlapping, 656)),
            100
        );
        // A `u16` divisor truncated to zero at 65,536 supports.
        assert_eq!(
            mean_temporal_compatibility(std::iter::repeat_n(TemporalRelation::Contiguous, 65_536)),
            75
        );
    }
}
