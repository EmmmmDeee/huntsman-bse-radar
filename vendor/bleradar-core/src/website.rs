//! Website lineage and ecosystem analysis.
//!
//! Website similarity is represented as competing, provenance-linked
//! explanations.  Shared templates, platforms, hosting, and third-party
//! services are not promoted to common operator attribution.  Raw page values
//! remain separate from normalized values, and every extracted observation
//! retains its source and temporal interval in the canonical evidence store.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::infrastructure::{
    ComparableValue, ObservationSource, ScoreMode, SupportFields, TemporalInterval,
    TemporalRelation, active_weight, corroborated_score, dependency_group, high_base_rate_pairs,
    matching_pairs, mean_temporal_compatibility, pair_key_cmp, temporal_relation, temporal_score,
    unique_observation_ids,
};
use crate::{
    Confidence, EdgeType, Entity, EntityType, EvidenceStore, EvidenceValue, Observation,
    ProvenanceError, Relationship, RelationshipProvenance, RetrievalMethod, Source, SourceType,
    Timestamp,
};

const DEFAULT_MAX_OBSERVATIONS: usize = 10_000;
const DEFAULT_MAX_CORRELATIONS: usize = 10_000;
const DEFAULT_MAX_TEMPORAL_GAP: Timestamp = 86_400_000;
const LINEAGE_SOURCE_ID: &str = "website-lineage-ecosystem-analysis";
const LINEAGE_METHOD: &str = "website-lineage-ecosystem-analysis";

/// Content or application feature extracted from a website snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WebsiteFeatureKind {
    /// Text after deterministic tag removal and whitespace normalization.
    NormalizedText,
    /// A phrase retained as a potentially distinctive content feature.
    DistinctivePhrase,
    /// The ordered HTML tag structure.
    HtmlStructure,
    /// A publicly reachable asset such as an image, font, or download.
    PublicAsset,
    /// A referenced JavaScript resource.
    ScriptReference,
    /// A referenced stylesheet resource.
    StyleReference,
    /// A public analytics or telemetry identifier.
    PublicAnalyticsIdentifier,
    /// A publicly displayed contact value.
    PublicContactInformation,
    /// A certificate identifier or public certificate characteristic.
    Certificate,
    /// A public outbound link.
    OutboundLink,
    /// An application or framework characteristic.
    ApplicationCharacteristic,
    /// A retained archived state or archive locator.
    ArchivedState,
}

impl WebsiteFeatureKind {
    /// Every supported website feature family in stable order.
    pub const ALL: [Self; 12] = [
        Self::NormalizedText,
        Self::DistinctivePhrase,
        Self::HtmlStructure,
        Self::PublicAsset,
        Self::ScriptReference,
        Self::StyleReference,
        Self::PublicAnalyticsIdentifier,
        Self::PublicContactInformation,
        Self::Certificate,
        Self::OutboundLink,
        Self::ApplicationCharacteristic,
        Self::ArchivedState,
    ];

    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NormalizedText => "normalized_text",
            Self::DistinctivePhrase => "distinctive_phrase",
            Self::HtmlStructure => "html_structure",
            Self::PublicAsset => "public_asset",
            Self::ScriptReference => "script_reference",
            Self::StyleReference => "style_reference",
            Self::PublicAnalyticsIdentifier => "public_analytics_identifier",
            Self::PublicContactInformation => "public_contact_information",
            Self::Certificate => "certificate",
            Self::OutboundLink => "outbound_link",
            Self::ApplicationCharacteristic => "application_characteristic",
            Self::ArchivedState => "archived_state",
        }
    }

    /// Whether the family is ordinarily common across unrelated sites.
    #[must_use]
    pub const fn is_high_base_rate(self) -> bool {
        matches!(
            self,
            Self::HtmlStructure
                | Self::ScriptReference
                | Self::StyleReference
                | Self::ApplicationCharacteristic
        )
    }

    /// Whether a matching value is normally a rare, discriminative signal.
    #[must_use]
    pub const fn is_rare_signal(self) -> bool {
        matches!(
            self,
            Self::DistinctivePhrase
                | Self::PublicAsset
                | Self::PublicAnalyticsIdentifier
                | Self::PublicContactInformation
                | Self::Certificate
        )
    }
}

impl fmt::Display for WebsiteFeatureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Explicit ordinal quality factors for one website feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebsiteFactors {
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

impl WebsiteFactors {
    /// Creates the nine calibrated quality dimensions.
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

    /// Creates equal values for all nine dimensions.
    #[must_use]
    pub const fn uniform(score: u8) -> Self {
        Self::new(
            score, score, score, score, score, score, score, score, score,
        )
    }

    /// Marks the feature as common-platform/template support.
    #[must_use]
    pub const fn high_base_rate(mut self) -> Self {
        self.high_base_rate = true;
        self
    }

    /// Alias for [`Self::high_base_rate`].
    #[must_use]
    pub const fn common_platform(self) -> Self {
        self.high_base_rate()
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

    /// Temporal-compatibility factor.
    #[must_use]
    pub const fn temporal_compatibility(self) -> Confidence {
        self.temporal_compatibility
    }

    /// Transformation-resistance factor.
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

    /// Whether this feature was explicitly marked high-base-rate.
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

/// One extracted website feature with complete source and temporal provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct WebsiteObservation {
    id: String,
    website_id: String,
    kind: WebsiteFeatureKind,
    raw_value: EvidenceValue,
    normalized_value: Option<EvidenceValue>,
    source: Source,
    timeline: TemporalInterval,
    factors: WebsiteFactors,
    dependency_group: Option<String>,
    feature_key: Option<String>,
}

impl WebsiteObservation {
    /// Creates an observation at one instant.
    pub fn new(
        id: impl Into<String>,
        website_id: impl Into<String>,
        kind: WebsiteFeatureKind,
        raw_value: impl Into<EvidenceValue>,
        source: Source,
        observed_at: Timestamp,
    ) -> Result<Self, WebsiteError> {
        Self::with_interval(
            id,
            website_id,
            kind,
            raw_value,
            source,
            TemporalInterval::at(observed_at),
        )
    }

    /// Creates an observation with an explicit first/observed/last interval.
    pub fn with_interval(
        id: impl Into<String>,
        website_id: impl Into<String>,
        kind: WebsiteFeatureKind,
        raw_value: impl Into<EvidenceValue>,
        source: Source,
        timeline: TemporalInterval,
    ) -> Result<Self, WebsiteError> {
        Ok(Self {
            id: require_text(id.into(), "website observation id")?,
            website_id: require_text(website_id.into(), "website id")?,
            kind,
            raw_value: raw_value.into(),
            normalized_value: None,
            source,
            timeline,
            factors: WebsiteFactors::uniform(50),
            dependency_group: None,
            feature_key: None,
        })
    }

    /// Creates an observation using metadata copied from a canonical source.
    pub fn from_source(
        id: impl Into<String>,
        website_id: impl Into<String>,
        kind: WebsiteFeatureKind,
        raw_value: impl Into<EvidenceValue>,
        source: &Source,
        observed_at: Timestamp,
    ) -> Result<Self, WebsiteError> {
        Self::new(id, website_id, kind, raw_value, source.clone(), observed_at)
    }

    /// Returns a copy with an additive normalized value.
    #[must_use]
    pub fn with_normalized_value(&self, normalized_value: impl Into<EvidenceValue>) -> Self {
        let mut copy = self.clone();
        copy.normalized_value = Some(normalized_value.into());
        copy
    }

    /// Returns a copy with an additive normalized value and feature signature.
    pub fn with_normalization(
        &self,
        normalized_value: impl Into<EvidenceValue>,
        feature_key: impl Into<String>,
    ) -> Result<Self, WebsiteError> {
        self.with_normalized_value(normalized_value)
            .with_feature(feature_key)
    }

    /// Returns a copy with an explicit temporal interval.
    #[must_use]
    pub const fn with_timeline(mut self, timeline: TemporalInterval) -> Self {
        self.timeline = timeline;
        self
    }

    /// Returns a copy with calibrated quality factors.
    #[must_use]
    pub const fn with_factors(mut self, factors: WebsiteFactors) -> Self {
        self.factors = factors;
        self
    }

    /// Returns a copy with a stable feature signature.
    pub fn with_feature(mut self, feature_key: impl Into<String>) -> Result<Self, WebsiteError> {
        self.feature_key = Some(require_text(feature_key.into(), "website feature key")?);
        Ok(self)
    }

    /// Assigns a copied-reporting/provider dependency group.
    pub fn in_dependency_group(
        mut self,
        dependency_group: impl Into<String>,
    ) -> Result<Self, WebsiteError> {
        self.dependency_group = Some(require_text(
            dependency_group.into(),
            "website dependency group",
        )?);
        Ok(self)
    }

    /// Marks this feature as high-base-rate support.
    #[must_use]
    pub const fn high_base_rate(mut self) -> Self {
        self.factors.high_base_rate = true;
        self
    }

    /// Adds uncertainty to the feature's calibrated factors.
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

    /// Website identifier associated with the observation.
    #[must_use]
    pub fn website_id(&self) -> &str {
        &self.website_id
    }

    /// Feature family.
    #[must_use]
    pub const fn kind(&self) -> WebsiteFeatureKind {
        self.kind
    }

    /// Exact raw value captured or extracted.
    #[must_use]
    pub const fn raw_value(&self) -> &EvidenceValue {
        &self.raw_value
    }

    /// Additive normalized value, if available.
    #[must_use]
    pub const fn normalized_value(&self) -> Option<&EvidenceValue> {
        self.normalized_value.as_ref()
    }

    /// Source record including locator and retrieval metadata.
    #[must_use]
    pub const fn source(&self) -> &Source {
        &self.source
    }

    /// Source identifier.
    #[must_use]
    pub fn source_id(&self) -> &str {
        self.source.id()
    }

    /// Temporal interval represented by the observation.
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
    pub const fn factors(&self) -> WebsiteFactors {
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

    /// Whether this observation should receive common-feature down-weighting.
    #[must_use]
    pub const fn is_high_base_rate(&self) -> bool {
        self.kind.is_high_base_rate() || self.factors.is_high_base_rate()
    }

    fn canonical_observation(&self) -> Result<Observation, WebsiteError> {
        Observation::with_timeline(
            self.id.clone(),
            self.raw_value.clone(),
            self.normalized_value.clone(),
            self.source.id().to_owned(),
            self.source.source_type().clone(),
            self.source.retrieval_method().clone(),
            self.timeline.into(),
        )
        .map_err(WebsiteError::from)
    }
}

/// Raw website capture and public feature inputs.
///
/// The engine extracts normalized text and HTML structure from `raw_html`, and
/// retains every explicitly supplied public feature as a separate raw and
/// normalized observation.
#[derive(Debug, Clone, PartialEq)]
pub struct WebsiteSnapshot {
    id: String,
    website_id: String,
    raw_html: String,
    source: Source,
    timeline: TemporalInterval,
    public_assets: Vec<String>,
    script_references: Vec<String>,
    style_references: Vec<String>,
    public_analytics_identifiers: Vec<String>,
    public_contact_information: Vec<String>,
    certificates: Vec<String>,
    outbound_links: Vec<String>,
    application_characteristics: Vec<String>,
    archived_states: Vec<String>,
    factors: WebsiteFactors,
    dependency_group: Option<String>,
}

impl WebsiteSnapshot {
    /// Creates a snapshot from raw HTML captured at one instant.
    pub fn new(
        id: impl Into<String>,
        website_id: impl Into<String>,
        raw_html: impl Into<String>,
        source: Source,
        observed_at: Timestamp,
    ) -> Result<Self, WebsiteError> {
        Ok(Self {
            id: require_text(id.into(), "website snapshot id")?,
            website_id: require_text(website_id.into(), "website id")?,
            raw_html: require_text(raw_html.into(), "raw html")?,
            source,
            timeline: TemporalInterval::at(observed_at),
            public_assets: Vec::new(),
            script_references: Vec::new(),
            style_references: Vec::new(),
            public_analytics_identifiers: Vec::new(),
            public_contact_information: Vec::new(),
            certificates: Vec::new(),
            outbound_links: Vec::new(),
            application_characteristics: Vec::new(),
            archived_states: Vec::new(),
            factors: WebsiteFactors::uniform(50),
            dependency_group: None,
        })
    }

    /// Returns a copy with an explicit temporal interval.
    #[must_use]
    pub const fn with_timeline(mut self, timeline: TemporalInterval) -> Self {
        self.timeline = timeline;
        self
    }

    /// Returns a copy with calibrated factors inherited by extracted features.
    #[must_use]
    pub const fn with_factors(mut self, factors: WebsiteFactors) -> Self {
        self.factors = factors;
        self
    }

    /// Assigns a dependency group inherited by extracted features.
    pub fn in_dependency_group(
        mut self,
        dependency_group: impl Into<String>,
    ) -> Result<Self, WebsiteError> {
        self.dependency_group = Some(require_text(
            dependency_group.into(),
            "website dependency group",
        )?);
        Ok(self)
    }

    /// Adds a public asset reference.
    pub fn with_public_asset(mut self, value: impl Into<String>) -> Result<Self, WebsiteError> {
        self.public_assets
            .push(require_text(value.into(), "public asset")?);
        Ok(self)
    }

    /// Adds a JavaScript reference.
    pub fn with_script_reference(mut self, value: impl Into<String>) -> Result<Self, WebsiteError> {
        self.script_references
            .push(require_text(value.into(), "script reference")?);
        Ok(self)
    }

    /// Adds a stylesheet reference.
    pub fn with_style_reference(mut self, value: impl Into<String>) -> Result<Self, WebsiteError> {
        self.style_references
            .push(require_text(value.into(), "style reference")?);
        Ok(self)
    }

    /// Adds a public analytics identifier.
    pub fn with_public_analytics_identifier(
        mut self,
        value: impl Into<String>,
    ) -> Result<Self, WebsiteError> {
        self.public_analytics_identifiers
            .push(require_text(value.into(), "analytics identifier")?);
        Ok(self)
    }

    /// Adds public contact information.
    pub fn with_public_contact_information(
        mut self,
        value: impl Into<String>,
    ) -> Result<Self, WebsiteError> {
        self.public_contact_information
            .push(require_text(value.into(), "public contact information")?);
        Ok(self)
    }

    /// Adds a public certificate characteristic.
    pub fn with_certificate(mut self, value: impl Into<String>) -> Result<Self, WebsiteError> {
        self.certificates
            .push(require_text(value.into(), "certificate")?);
        Ok(self)
    }

    /// Adds a public outbound link.
    pub fn with_outbound_link(mut self, value: impl Into<String>) -> Result<Self, WebsiteError> {
        self.outbound_links
            .push(require_text(value.into(), "outbound link")?);
        Ok(self)
    }

    /// Adds an application or framework characteristic.
    pub fn with_application_characteristic(
        mut self,
        value: impl Into<String>,
    ) -> Result<Self, WebsiteError> {
        self.application_characteristics
            .push(require_text(value.into(), "application characteristic")?);
        Ok(self)
    }

    /// Adds an archived state or archive locator.
    pub fn with_archived_state(mut self, value: impl Into<String>) -> Result<Self, WebsiteError> {
        self.archived_states
            .push(require_text(value.into(), "archived state")?);
        Ok(self)
    }

    /// Snapshot identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Website identifier.
    #[must_use]
    pub fn website_id(&self) -> &str {
        &self.website_id
    }

    /// Raw HTML exactly as captured.
    #[must_use]
    pub fn raw_html(&self) -> &str {
        &self.raw_html
    }

    /// Source record for the snapshot.
    #[must_use]
    pub const fn source(&self) -> &Source {
        &self.source
    }

    /// Snapshot temporal interval.
    #[must_use]
    pub const fn timeline(&self) -> TemporalInterval {
        self.timeline
    }

    /// Extracts all available feature observations in stable feature order.
    pub fn extract_observations(&self) -> Result<Vec<WebsiteObservation>, WebsiteError> {
        let normalized_text = normalize_html_text(&self.raw_html);
        let html_structure = normalize_html_structure(&self.raw_html);
        let mut observations = Vec::new();

        if !normalized_text.is_empty() {
            observations.push(self.extracted(
                "normalized-text",
                WebsiteFeatureKind::NormalizedText,
                self.raw_html.clone(),
                Some(normalized_text.clone()),
            )?);
            for (index, phrase) in distinctive_phrases(&normalized_text)
                .into_iter()
                .enumerate()
            {
                observations.push(self.extracted(
                    &format!("distinctive-phrase-{index}"),
                    WebsiteFeatureKind::DistinctivePhrase,
                    phrase.clone(),
                    Some(phrase),
                )?);
            }
        }
        if !html_structure.is_empty() {
            observations.push(self.extracted(
                "html-structure",
                WebsiteFeatureKind::HtmlStructure,
                self.raw_html.clone(),
                Some(html_structure),
            )?);
        }

        self.push_values(
            &mut observations,
            WebsiteFeatureKind::PublicAsset,
            "public-asset",
            &self.public_assets,
        )?;
        self.push_values(
            &mut observations,
            WebsiteFeatureKind::ScriptReference,
            "script-reference",
            &self.script_references,
        )?;
        self.push_values(
            &mut observations,
            WebsiteFeatureKind::StyleReference,
            "style-reference",
            &self.style_references,
        )?;
        self.push_values(
            &mut observations,
            WebsiteFeatureKind::PublicAnalyticsIdentifier,
            "analytics-identifier",
            &self.public_analytics_identifiers,
        )?;
        self.push_values(
            &mut observations,
            WebsiteFeatureKind::PublicContactInformation,
            "public-contact",
            &self.public_contact_information,
        )?;
        self.push_values(
            &mut observations,
            WebsiteFeatureKind::Certificate,
            "certificate",
            &self.certificates,
        )?;
        self.push_values(
            &mut observations,
            WebsiteFeatureKind::OutboundLink,
            "outbound-link",
            &self.outbound_links,
        )?;
        self.push_values(
            &mut observations,
            WebsiteFeatureKind::ApplicationCharacteristic,
            "application-characteristic",
            &self.application_characteristics,
        )?;
        self.push_values(
            &mut observations,
            WebsiteFeatureKind::ArchivedState,
            "archived-state",
            &self.archived_states,
        )?;

        Ok(observations)
    }

    /// Alias for [`Self::extract_observations`].
    pub fn extract(&self) -> Result<Vec<WebsiteObservation>, WebsiteError> {
        self.extract_observations()
    }

    fn extracted(
        &self,
        suffix: &str,
        kind: WebsiteFeatureKind,
        raw_value: String,
        normalized_value: Option<String>,
    ) -> Result<WebsiteObservation, WebsiteError> {
        let id = format!("{}:{suffix}", self.id);
        let mut observation = WebsiteObservation::with_interval(
            id,
            self.website_id.clone(),
            kind,
            raw_value,
            self.source.clone(),
            self.timeline,
        )?
        .with_factors(self.factors);
        if let Some(dependency_group) = &self.dependency_group {
            observation = observation.in_dependency_group(dependency_group.clone())?;
        }
        if let Some(normalized_value) = normalized_value {
            let feature_key = format!("{}:{normalized_value}", kind.as_str());
            observation = observation.with_normalization(normalized_value, feature_key)?;
        }
        Ok(observation)
    }

    fn push_values(
        &self,
        observations: &mut Vec<WebsiteObservation>,
        kind: WebsiteFeatureKind,
        suffix: &str,
        values: &[String],
    ) -> Result<(), WebsiteError> {
        for (index, value) in values.iter().enumerate() {
            let normalized = normalize_feature_value(value);
            observations.push(self.extracted(
                &format!("{suffix}-{index}"),
                kind,
                value.clone(),
                Some(normalized),
            )?);
        }
        Ok(())
    }
}

/// Competing explanation for a website relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WebsiteExplanation {
    /// Matching features are coincidental.
    Coincidence,
    /// Sites share a platform or framework.
    CommonPlatform,
    /// Sites share a template or structural composition.
    CommonTemplate,
    /// Sites reuse content or distinctive text.
    ContentReuse,
    /// Sites reuse a public asset.
    AssetReuse,
    /// Sites show evidence of a development relationship.
    DevelopmentRelationship,
    /// Sites show evidence of an operational relationship.
    OperationalRelationship,
    /// Evidence does not discriminate among explanations.
    Unknown,
}

impl WebsiteExplanation {
    /// Every explanation in stable order.
    pub const ALL: [Self; 8] = [
        Self::Coincidence,
        Self::CommonPlatform,
        Self::CommonTemplate,
        Self::ContentReuse,
        Self::AssetReuse,
        Self::DevelopmentRelationship,
        Self::OperationalRelationship,
        Self::Unknown,
    ];

    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coincidence => "coincidence",
            Self::CommonPlatform => "common_platform",
            Self::CommonTemplate => "common_template",
            Self::ContentReuse => "content_reuse",
            Self::AssetReuse => "asset_reuse",
            Self::DevelopmentRelationship => "development_relationship",
            Self::OperationalRelationship => "operational_relationship",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this explanation is a high-base-rate web similarity explanation.
    #[must_use]
    pub const fn is_high_base_rate(self) -> bool {
        matches!(self, Self::CommonPlatform | Self::CommonTemplate)
    }
}

impl fmt::Display for WebsiteExplanation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Explicit operator-attribution posture for a website edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperatorAssessment {
    /// Available evidence does not justify a common-operator hypothesis.
    NotEstablished,
    /// A common operator is a live alternative, not a confirmed conclusion.
    PossibleCommonOperator,
}

impl OperatorAssessment {
    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotEstablished => "not_established",
            Self::PossibleCommonOperator => "possible_common_operator",
        }
    }
}

impl fmt::Display for OperatorAssessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One independent pair of website observations supporting an explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebsiteObservationPair {
    left_observation: String,
    right_observation: String,
    weight: u16,
    temporal_relation: TemporalRelation,
}

impl WebsiteObservationPair {
    /// Left observation identifier.
    #[must_use]
    pub fn left_observation(&self) -> &str {
        &self.left_observation
    }

    /// Right observation identifier.
    #[must_use]
    pub fn right_observation(&self) -> &str {
        &self.right_observation
    }

    /// Calibrated ordinal contribution.
    #[must_use]
    pub const fn weight(&self) -> u16 {
        self.weight
    }

    /// Temporal relation of the pair.
    #[must_use]
    pub const fn temporal_relation(&self) -> TemporalRelation {
        self.temporal_relation
    }
}

/// Ranking for one competing website explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebsiteCorrelationRanking {
    explanation: WebsiteExplanation,
    score: u16,
    confidence: Confidence,
    independent_support: usize,
    supporting_pairs: Vec<WebsiteObservationPair>,
    collapsed_pairs: Vec<WebsiteObservationPair>,
    high_base_rate_support: bool,
    temporal_compatibility: Confidence,
}

impl WebsiteCorrelationRanking {
    /// Explanation being ranked.
    #[must_use]
    pub const fn explanation(&self) -> WebsiteExplanation {
        self.explanation
    }

    /// Ordinal score, not a probability.
    #[must_use]
    pub const fn score(&self) -> u16 {
        self.score
    }

    /// Bounded confidence projection.
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
    pub fn supporting_pairs(&self) -> &[WebsiteObservationPair] {
        &self.supporting_pairs
    }

    /// Pairs collapsed as copied, derivative, or provider-dependent support.
    #[must_use]
    pub fn collapsed_pairs(&self) -> &[WebsiteObservationPair] {
        &self.collapsed_pairs
    }

    /// Whether retained support includes a high-base-rate feature.
    #[must_use]
    pub const fn has_high_base_rate_support(&self) -> bool {
        self.high_base_rate_support
    }

    /// Aggregate temporal compatibility of retained support.
    #[must_use]
    pub const fn temporal_compatibility(&self) -> Confidence {
        self.temporal_compatibility
    }

    /// All retained observation identifiers in stable pair order.
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

/// Adversarial stress-test result for one website correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebsiteCorrelationFalsification {
    leading_explanation: WebsiteExplanation,
    strongest_alternative: Option<WebsiteExplanation>,
    baseline: WebsiteCorrelationRanking,
    without_high_base_rate: WebsiteCorrelationRanking,
    without_strongest_support: WebsiteCorrelationRanking,
    perturbed_uncertainty: WebsiteCorrelationRanking,
    removed_support: Option<WebsiteObservationPair>,
    missing_expected_evidence: Vec<WebsiteFeatureKind>,
    survives: bool,
}

impl WebsiteCorrelationFalsification {
    /// Baseline leading explanation.
    #[must_use]
    pub const fn leading_explanation(&self) -> WebsiteExplanation {
        self.leading_explanation
    }

    /// Strongest baseline alternative, if present.
    #[must_use]
    pub const fn strongest_alternative(&self) -> Option<WebsiteExplanation> {
        self.strongest_alternative
    }

    /// Baseline ranking.
    #[must_use]
    pub const fn baseline(&self) -> &WebsiteCorrelationRanking {
        &self.baseline
    }

    /// Ranking after removing common/high-base-rate support.
    #[must_use]
    pub const fn without_high_base_rate(&self) -> &WebsiteCorrelationRanking {
        &self.without_high_base_rate
    }

    /// Ranking after removing the strongest independent support group.
    #[must_use]
    pub const fn without_strongest_support(&self) -> &WebsiteCorrelationRanking {
        &self.without_strongest_support
    }

    /// Ranking after perturbing uncertain assumptions.
    #[must_use]
    pub const fn perturbed_uncertainty(&self) -> &WebsiteCorrelationRanking {
        &self.perturbed_uncertainty
    }

    /// Support pair removed by the strongest-support pass.
    #[must_use]
    pub const fn removed_support(&self) -> Option<&WebsiteObservationPair> {
        self.removed_support.as_ref()
    }

    /// Feature families expected but not observed for the leading explanation.
    #[must_use]
    pub fn missing_expected_evidence(&self) -> &[WebsiteFeatureKind] {
        &self.missing_expected_evidence
    }

    /// Whether the leading explanation survives all stress passes.
    #[must_use]
    pub const fn survives(&self) -> bool {
        self.survives
    }
}

/// Ordered phases recorded for one website analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WebsitePhase {
    /// Capture canonical source observations.
    Capture,
    /// Normalize raw values without replacing them.
    Normalize,
    /// Extract content and application feature families.
    Extract,
    /// Align observation intervals.
    TemporalAlign,
    /// Generate competing explanations.
    Compare,
    /// Apply calibrated weights and dependency collapse.
    Score,
    /// Remove common support and perturb uncertain assumptions.
    Falsify,
    /// Persist a provenance-linked relationship edge.
    Persist,
    /// Recompute deterministic rankings.
    Recompute,
}

/// Persisted website lineage edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebsiteLineageEdge {
    id: String,
    subject: String,
    object: String,
    predicate: String,
    edge_type: EdgeType,
    leading_explanation: WebsiteExplanation,
    confidence: Confidence,
    temporal_relation: TemporalRelation,
    observation_ids: Vec<String>,
    operator_assessment: OperatorAssessment,
    relationship_id: String,
}

impl WebsiteLineageEdge {
    /// Stable edge identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Subject website identifier.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Object website identifier.
    #[must_use]
    pub fn object(&self) -> &str {
        &self.object
    }

    /// Stable relationship predicate.
    #[must_use]
    pub fn predicate(&self) -> &str {
        &self.predicate
    }

    /// Canonical relationship classification.
    #[must_use]
    pub const fn edge_type(&self) -> EdgeType {
        self.edge_type
    }

    /// Leading website explanation.
    #[must_use]
    pub const fn leading_explanation(&self) -> WebsiteExplanation {
        self.leading_explanation
    }

    /// Bounded confidence projection.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Temporal relation of strongest retained support.
    #[must_use]
    pub const fn temporal_relation(&self) -> TemporalRelation {
        self.temporal_relation
    }

    /// Observation identifiers cited by this edge.
    #[must_use]
    pub fn observation_ids(&self) -> &[String] {
        &self.observation_ids
    }

    /// Explicit common-operator posture.
    #[must_use]
    pub const fn operator_assessment(&self) -> OperatorAssessment {
        self.operator_assessment
    }

    /// Identifier of the corresponding canonical relationship.
    #[must_use]
    pub fn relationship_id(&self) -> &str {
        &self.relationship_id
    }

    /// Whether this engine proves common operator attribution.
    #[must_use]
    pub const fn common_operator_proven(&self) -> bool {
        false
    }
}

/// Complete website lineage execution report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebsiteLineageReport {
    edge: WebsiteLineageEdge,
    rankings: Vec<WebsiteCorrelationRanking>,
    falsification: WebsiteCorrelationFalsification,
    temporal_relation: TemporalRelation,
    phases: Vec<WebsitePhase>,
}

impl WebsiteLineageReport {
    /// Persisted website edge.
    #[must_use]
    pub const fn edge(&self) -> &WebsiteLineageEdge {
        &self.edge
    }

    /// Competing explanations in descending score order.
    #[must_use]
    pub fn rankings(&self) -> &[WebsiteCorrelationRanking] {
        &self.rankings
    }

    /// Returns one explanation ranking.
    #[must_use]
    pub fn ranking(&self, explanation: WebsiteExplanation) -> Option<&WebsiteCorrelationRanking> {
        self.rankings
            .iter()
            .find(|ranking| ranking.explanation == explanation)
    }

    /// Adversarial falsification report.
    #[must_use]
    pub const fn falsification(&self) -> &WebsiteCorrelationFalsification {
        &self.falsification
    }

    /// Leading explanation.
    #[must_use]
    pub const fn leading_explanation(&self) -> WebsiteExplanation {
        self.edge.leading_explanation
    }

    /// Leading bounded confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.edge.confidence
    }

    /// Aggregate temporal relation.
    #[must_use]
    pub const fn temporal_relation(&self) -> TemporalRelation {
        self.temporal_relation
    }

    /// Ordered control-loop phases.
    #[must_use]
    pub fn phases(&self) -> &[WebsitePhase] {
        &self.phases
    }

    /// Common-operator posture.
    #[must_use]
    pub const fn operator_assessment(&self) -> OperatorAssessment {
        self.edge.operator_assessment
    }

    /// Whether this report proves common operator attribution.
    #[must_use]
    pub const fn common_operator_proven(&self) -> bool {
        false
    }
}

/// Resource limits for website lineage analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebsiteLimits {
    max_observations: usize,
    max_correlations: usize,
    maximum_temporal_gap: Timestamp,
}

impl WebsiteLimits {
    /// Creates limits with a one-day default continuity window.
    pub fn new(max_observations: usize, max_correlations: usize) -> Result<Self, WebsiteError> {
        if max_observations == 0 {
            return Err(WebsiteError::InvalidLimit {
                resource: "observations",
                limit: max_observations,
            });
        }
        if max_correlations == 0 {
            return Err(WebsiteError::InvalidLimit {
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

    /// Sets the maximum gap accepted as temporal continuity.
    #[must_use]
    pub const fn with_maximum_temporal_gap(mut self, maximum_temporal_gap: Timestamp) -> Self {
        self.maximum_temporal_gap = maximum_temporal_gap;
        self
    }

    /// Maximum canonical website observations.
    #[must_use]
    pub const fn max_observations(self) -> usize {
        self.max_observations
    }

    /// Maximum persisted correlations.
    #[must_use]
    pub const fn max_correlations(self) -> usize {
        self.max_correlations
    }

    /// Maximum interval gap treated as continuity.
    #[must_use]
    pub const fn maximum_temporal_gap(self) -> Timestamp {
        self.maximum_temporal_gap
    }
}

impl Default for WebsiteLimits {
    fn default() -> Self {
        Self {
            max_observations: DEFAULT_MAX_OBSERVATIONS,
            max_correlations: DEFAULT_MAX_CORRELATIONS,
            maximum_temporal_gap: DEFAULT_MAX_TEMPORAL_GAP,
        }
    }
}

/// Validation, persistence, and analysis failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebsiteError {
    /// A required identifier or textual value was empty.
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
    /// A website has no registered observations.
    MissingWebsite {
        /// Missing website identifier.
        website_id: String,
    },
    /// A website cannot be correlated with itself.
    SameWebsite {
        /// Repeated website identifier.
        website_id: String,
    },
    /// No matching feature values were found.
    NoComparableObservations {
        /// Left website.
        left_website: String,
        /// Right website.
        right_website: String,
    },
    /// A correlation identifier is already registered.
    DuplicateCorrelation {
        /// Duplicate correlation identifier.
        correlation_id: String,
    },
    /// A source identifier conflicts with canonical metadata.
    SourceConflict {
        /// Conflicting source identifier.
        source_id: String,
    },
    /// An observation conflicts with a canonical record.
    ObservationConflict {
        /// Conflicting observation identifier.
        observation_id: String,
    },
    /// Canonical provenance validation failed.
    Provenance {
        /// Underlying provenance error.
        error: ProvenanceError,
    },
}

impl fmt::Display for WebsiteError {
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
                    "duplicate website observation `{observation_id}`"
                )
            }
            Self::MissingWebsite { website_id } => {
                write!(formatter, "website `{website_id}` has no observations")
            }
            Self::SameWebsite { website_id } => {
                write!(
                    formatter,
                    "cannot correlate website `{website_id}` with itself"
                )
            }
            Self::NoComparableObservations {
                left_website,
                right_website,
            } => write!(
                formatter,
                "no comparable website observations for `{left_website}` and `{right_website}`"
            ),
            Self::DuplicateCorrelation { correlation_id } => {
                write!(
                    formatter,
                    "duplicate website correlation `{correlation_id}`"
                )
            }
            Self::SourceConflict { source_id } => {
                write!(formatter, "source `{source_id}` has conflicting metadata")
            }
            Self::ObservationConflict { observation_id } => {
                write!(
                    formatter,
                    "website observation `{observation_id}` conflicts with canonical evidence"
                )
            }
            Self::Provenance { error } => {
                write!(formatter, "canonical persistence failed: {error}")
            }
        }
    }
}

impl std::error::Error for WebsiteError {}

impl crate::validation::EmptyValueError for WebsiteError {
    fn empty_value(field: &'static str) -> Self {
        Self::EmptyValue { field }
    }
}

fn require_text(value: String, field: &'static str) -> Result<String, WebsiteError> {
    crate::validation::require_text(value, field)
}

impl From<ProvenanceError> for WebsiteError {
    fn from(error: ProvenanceError) -> Self {
        Self::Provenance { error }
    }
}

fn normalize_feature_value(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn normalize_html_text(raw_html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for character in raw_html.chars() {
        match character {
            '<' => {
                in_tag = true;
                text.push(' ');
            }
            '>' if in_tag => {
                in_tag = false;
                text.push(' ');
            }
            _ if !in_tag => text.push(character),
            _ => {}
        }
    }
    let decoded = text
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    normalize_feature_value(&decoded)
}

fn normalize_html_structure(raw_html: &str) -> String {
    let mut tags = Vec::new();
    let mut remainder = raw_html;
    while let Some(start) = remainder.find('<') {
        let after_start = &remainder[start + 1..];
        let Some(end) = after_start.find('>') else {
            break;
        };
        let token = after_start[..end].trim_start_matches(['/', '!', '?']);
        let name: String = token
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if !name.is_empty() {
            tags.push(name);
        }
        remainder = &after_start[end + 1..];
    }
    tags.join(">")
}

fn distinctive_phrases(normalized_text: &str) -> Vec<String> {
    normalized_text
        .split(['.', '!', '?', ';'])
        .map(str::trim)
        .filter(|phrase| phrase.split_whitespace().count() >= 4)
        .filter(|phrase| phrase.len() >= 20)
        .take(8)
        .map(str::to_owned)
        .collect()
}

#[derive(Debug, Clone)]
struct Support {
    explanation: WebsiteExplanation,
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
    left: &'a WebsiteObservation,
    right: &'a WebsiteObservation,
    temporal_relation: TemporalRelation,
    base_weight: u16,
}

/// Website lineage and ecosystem analysis engine.
#[derive(Debug, Clone)]
pub struct WebsiteLineageEcosystemAnalysisEngine {
    evidence: EvidenceStore,
    limits: WebsiteLimits,
    lineage_source: Source,
    observations: BTreeMap<String, WebsiteObservation>,
    website_observations: BTreeMap<String, BTreeSet<String>>,
    correlations: BTreeMap<String, WebsiteLineageReport>,
}

impl WebsiteLineageEcosystemAnalysisEngine {
    /// Creates an engine with default limits and a derived relationship source.
    #[must_use]
    pub fn new(evidence: EvidenceStore) -> Self {
        let lineage_source = Source::new(
            LINEAGE_SOURCE_ID,
            SourceType::Derived,
            RetrievalMethod::Derived,
        )
        .expect("the built-in website lineage source has valid metadata");
        Self {
            evidence,
            limits: WebsiteLimits::default(),
            lineage_source,
            observations: BTreeMap::new(),
            website_observations: BTreeMap::new(),
            correlations: BTreeMap::new(),
        }
    }

    /// Creates an engine with explicit resource limits.
    #[must_use]
    pub fn with_limits(evidence: EvidenceStore, limits: WebsiteLimits) -> Self {
        let mut engine = Self::new(evidence);
        engine.limits = limits;
        engine
    }

    /// Returns a copy using a caller-supplied derived relationship source.
    #[must_use]
    pub fn with_lineage_source(mut self, source: Source) -> Self {
        self.lineage_source = source;
        self
    }

    /// Authoritative canonical evidence store.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceStore {
        &self.evidence
    }

    /// Mutable access to canonical evidence.
    #[must_use]
    pub const fn evidence_mut(&mut self) -> &mut EvidenceStore {
        &mut self.evidence
    }

    /// Consumes the engine and returns its canonical evidence store, so a caller composing the website engine with
    /// the OSINT, infrastructure, and fusion engines can move the store into the
    /// next stage without cloning it
    /// (see [`Self::evidence`] to borrow it in place).
    #[must_use]
    pub fn into_evidence(self) -> EvidenceStore {
        self.evidence
    }

    /// Configured resource limits.
    #[must_use]
    pub const fn limits(&self) -> WebsiteLimits {
        self.limits
    }

    /// Source used for derived lineage relationships.
    #[must_use]
    pub const fn lineage_source(&self) -> &Source {
        &self.lineage_source
    }

    /// Registers and transactionally persists one website observation.
    ///
    /// A refused observation (limit, duplicate id, conflicting source or
    /// canonical record, invalid provenance) leaves the engine and its
    /// evidence store unchanged.
    pub fn observe(&mut self, observation: WebsiteObservation) -> Result<(), WebsiteError> {
        let Self {
            evidence,
            limits,
            observations,
            website_observations,
            ..
        } = self;
        observe_into(
            evidence,
            observations,
            website_observations,
            *limits,
            observation,
        )
    }

    /// Extracts and transactionally persists every feature in a snapshot.
    ///
    /// The snapshot is all-or-nothing: if any extracted feature is refused,
    /// the engine and its evidence store are left unchanged.
    pub fn observe_snapshot(
        &mut self,
        snapshot: &WebsiteSnapshot,
    ) -> Result<Vec<String>, WebsiteError> {
        let extracted = snapshot.extract_observations()?;
        let Self {
            evidence,
            limits,
            observations,
            website_observations,
            ..
        } = self;
        let mut ids = Vec::with_capacity(extracted.len());
        let outcome = evidence.transaction(|store| {
            for observation in extracted {
                let id = observation.id().to_owned();
                observe_into(
                    store,
                    observations,
                    website_observations,
                    *limits,
                    observation,
                )?;
                ids.push(id);
            }
            Ok::<(), WebsiteError>(())
        });
        if outcome.is_err() {
            for id in &ids {
                if let Some(observation) = observations.remove(id) {
                    forget_index(website_observations, observation.website_id(), id);
                }
            }
        }
        outcome.map(|()| ids)
    }

    /// Convenience alias for [`Self::observe`].
    pub fn add_observation(&mut self, observation: WebsiteObservation) -> Result<(), WebsiteError> {
        self.observe(observation)
    }

    /// Returns one website observation.
    #[must_use]
    pub fn observation(&self, observation_id: &str) -> Option<&WebsiteObservation> {
        self.observations.get(observation_id)
    }

    /// Returns all observations in stable identifier order.
    pub fn observations(&self) -> impl Iterator<Item = &WebsiteObservation> {
        self.observations.values()
    }

    /// Returns observations for one website.
    pub fn observations_for_website(
        &self,
        website_id: &str,
    ) -> impl Iterator<Item = &WebsiteObservation> {
        self.website_observations
            .get(website_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.observations.get(id))
    }

    /// Number of registered observations.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Number of persisted lineage correlations.
    #[must_use]
    pub fn correlation_count(&self) -> usize {
        self.correlations.len()
    }

    /// Returns one persisted lineage report.
    #[must_use]
    pub fn correlation(&self, correlation_id: &str) -> Option<&WebsiteLineageReport> {
        self.correlations.get(correlation_id)
    }

    /// Returns all persisted reports in stable identifier order.
    pub fn correlations(&self) -> impl Iterator<Item = &WebsiteLineageReport> {
        self.correlations.values()
    }

    /// Correlates two websites, falsifies the result, and persists the edge.
    pub fn correlate(
        &mut self,
        left_website: &str,
        right_website: &str,
    ) -> Result<WebsiteLineageReport, WebsiteError> {
        let left_website = require_text(left_website.to_owned(), "left website")?;
        let right_website = require_text(right_website.to_owned(), "right website")?;
        if left_website == right_website {
            return Err(WebsiteError::SameWebsite {
                website_id: left_website,
            });
        }
        if !self.website_observations.contains_key(&left_website) {
            return Err(WebsiteError::MissingWebsite {
                website_id: left_website,
            });
        }
        if !self.website_observations.contains_key(&right_website) {
            return Err(WebsiteError::MissingWebsite {
                website_id: right_website,
            });
        }
        if self.correlations.len() >= self.limits.max_correlations {
            return Err(WebsiteError::ResourceLimit {
                resource: "correlations",
                limit: self.limits.max_correlations,
            });
        }

        let correlation_id = correlation_identifier(&left_website, &right_website);
        if self.correlations.contains_key(&correlation_id) {
            return Err(WebsiteError::DuplicateCorrelation { correlation_id });
        }

        let pairs = self.comparable_pairs(&left_website, &right_website);
        if pairs.is_empty() {
            return Err(WebsiteError::NoComparableObservations {
                left_website,
                right_website,
            });
        }
        let supports = self.supports(&pairs);
        let rankings = rank_supports(&supports, ScoreMode::Baseline);
        let baseline =
            rankings
                .first()
                .cloned()
                .ok_or_else(|| WebsiteError::NoComparableObservations {
                    left_website: left_website.clone(),
                    right_website: right_website.clone(),
                })?;
        if baseline.score == 0 {
            return Err(WebsiteError::NoComparableObservations {
                left_website,
                right_website,
            });
        }

        let falsification = build_falsification(&supports, &rankings, &baseline);
        let leading_explanation = baseline.explanation;
        let operator_assessment = operator_assessment(&baseline);
        let temporal_relation = strongest_temporal_relation(&baseline);
        let observation_ids = unique_observation_ids(baseline.supporting_observation_ids());
        let predicate = format!("website-lineage:{}", leading_explanation.as_str());
        let relationship_id = format!("{correlation_id}:relationship");
        let edge_type = if falsification.survives {
            EdgeType::Inferred
        } else {
            EdgeType::Contested
        };
        let edge = WebsiteLineageEdge {
            id: correlation_id.clone(),
            subject: left_website.clone(),
            object: right_website.clone(),
            predicate: predicate.clone(),
            edge_type,
            leading_explanation,
            confidence: baseline.confidence,
            temporal_relation,
            observation_ids: observation_ids.clone(),
            operator_assessment,
            relationship_id: relationship_id.clone(),
        };

        if let Some(existing) = self.evidence.source(self.lineage_source.id())
            && existing != &self.lineage_source
        {
            return Err(WebsiteError::SourceConflict {
                source_id: self.lineage_source.id().to_owned(),
            });
        }
        let timestamp = observation_ids
            .iter()
            .filter_map(|id| self.observations.get(id))
            .map(WebsiteObservation::observed_at)
            .max()
            .unwrap_or(0);
        let provenance = RelationshipProvenance::new(
            self.lineage_source.id().to_owned(),
            timestamp,
            LINEAGE_METHOD,
        )?
        .from_observations(observation_ids);
        let relationship = Relationship::new(
            relationship_id,
            left_website,
            predicate,
            right_website,
            edge_type,
            provenance,
        )?
        .with_confidence(baseline.confidence);
        let lineage_source = &self.lineage_source;
        self.evidence.transaction(|store| {
            if store.source(lineage_source.id()).is_none() {
                store.add_source(lineage_source.clone())?;
            }
            store.add_relationship(relationship)?;
            Ok::<(), WebsiteError>(())
        })?;

        let report = WebsiteLineageReport {
            edge,
            rankings,
            falsification,
            temporal_relation,
            phases: vec![
                WebsitePhase::Capture,
                WebsitePhase::Normalize,
                WebsitePhase::Extract,
                WebsitePhase::TemporalAlign,
                WebsitePhase::Compare,
                WebsitePhase::Score,
                WebsitePhase::Falsify,
                WebsitePhase::Persist,
                WebsitePhase::Recompute,
            ],
        };
        self.correlations.insert(correlation_id, report.clone());
        Ok(report)
    }

    /// Convenience alias emphasizing pairwise lineage analysis.
    pub fn correlate_pair(
        &mut self,
        left_website: &str,
        right_website: &str,
    ) -> Result<WebsiteLineageReport, WebsiteError> {
        self.correlate(left_website, right_website)
    }

    /// Correlates every pair of websites not yet correlated in either
    /// direction, skipping pairs without matches.
    ///
    /// The batch is transactional: any other failure (a resource limit, a
    /// source conflict, a provenance error) leaves the engine and its evidence
    /// store unchanged. Only the reports persisted by this call are returned,
    /// in website-identifier order, so repeating the call once every comparable
    /// pair is covered yields an empty list rather than a duplicate-correlation
    /// error.
    pub fn correlate_all(&mut self) -> Result<Vec<WebsiteLineageReport>, WebsiteError> {
        let website_ids: Vec<_> = self.website_observations.keys().cloned().collect();
        let mut reports = Vec::new();
        let outcome = EvidenceStore::transaction_through(
            self,
            |engine| &mut engine.evidence,
            |engine| engine.correlate_pairs(&website_ids, &mut reports),
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
        website_ids: &[String],
        reports: &mut Vec<WebsiteLineageReport>,
    ) -> Result<(), WebsiteError> {
        for (left_index, left_website) in website_ids.iter().enumerate() {
            for right_website in website_ids.iter().skip(left_index + 1) {
                if self.is_correlated(left_website, right_website) {
                    continue;
                }
                match self.correlate(left_website, right_website) {
                    Ok(report) => reports.push(report),
                    Err(WebsiteError::NoComparableObservations { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    /// Whether a pair already has a persisted correlation in either direction.
    fn is_correlated(&self, left_website: &str, right_website: &str) -> bool {
        self.correlations
            .contains_key(&correlation_identifier(left_website, right_website))
            || self
                .correlations
                .contains_key(&correlation_identifier(right_website, left_website))
    }

    /// Returns persisted correlations ordered by descending confidence.
    pub fn ranked_correlations(&self) -> Vec<&WebsiteLineageReport> {
        let mut reports: Vec<_> = self.correlations.values().collect();
        reports.sort_by(|left, right| {
            right
                .confidence()
                .cmp(&left.confidence())
                .then_with(|| left.edge.id.cmp(&right.edge.id))
        });
        reports
    }

    fn comparable_pairs(&self, left_website: &str, right_website: &str) -> Vec<ComparablePair<'_>> {
        let left_observations: Vec<&WebsiteObservation> =
            self.observations_for_website(left_website).collect();
        let right_observations: Vec<&WebsiteObservation> =
            self.observations_for_website(right_website).collect();
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
            let signal_weight = feature_signal_weight(left, right);
            let mut base_weight =
                (factor_weight.saturating_mul(signal_weight) / 100 + u16::from(temporal_score)) / 2;
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
            let group = format!(
                "{}|{}",
                dependency_group(pair.left),
                dependency_group(pair.right)
            );
            let uncertainty = pair
                .left
                .factors()
                .uncertainty()
                .value()
                .max(pair.right.factors().uncertainty().value());
            for explanation in explanations {
                let mut weight = pair.base_weight;
                weight = explanation_weight(explanation, weight, pair.left, pair.right);
                supports.push(Support {
                    explanation,
                    left_observation: pair.left.id().to_owned(),
                    right_observation: pair.right.id().to_owned(),
                    group: group.clone(),
                    weight,
                    temporal_relation: pair.temporal_relation,
                    high_base_rate: pair.left.is_high_base_rate()
                        || pair.right.is_high_base_rate()
                        || explanation.is_high_base_rate(),
                    uncertainty,
                });
            }
        }
        supports
    }
}

impl ComparableValue for WebsiteObservation {
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

fn feature_signal_weight(left: &WebsiteObservation, right: &WebsiteObservation) -> u16 {
    let kind = if left.kind() == right.kind() || left.kind().is_rare_signal() {
        left.kind()
    } else {
        right.kind()
    };
    let mut weight: u16 = match kind {
        WebsiteFeatureKind::DistinctivePhrase
        | WebsiteFeatureKind::PublicAsset
        | WebsiteFeatureKind::PublicAnalyticsIdentifier
        | WebsiteFeatureKind::PublicContactInformation
        | WebsiteFeatureKind::Certificate => 130,
        WebsiteFeatureKind::NormalizedText => 95,
        WebsiteFeatureKind::HtmlStructure => 80,
        WebsiteFeatureKind::ScriptReference
        | WebsiteFeatureKind::StyleReference
        | WebsiteFeatureKind::ApplicationCharacteristic => 65,
        WebsiteFeatureKind::OutboundLink | WebsiteFeatureKind::ArchivedState => 105,
    };
    if left.factors().rarity().value() >= 70 && right.factors().rarity().value() >= 70 {
        weight = weight.saturating_add(15);
    }
    weight
}

fn explanations_for(
    left: &WebsiteObservation,
    right: &WebsiteObservation,
) -> Vec<WebsiteExplanation> {
    let mut explanations = BTreeSet::new();
    match (left.kind(), right.kind()) {
        (WebsiteFeatureKind::DistinctivePhrase, WebsiteFeatureKind::DistinctivePhrase)
        | (WebsiteFeatureKind::NormalizedText, WebsiteFeatureKind::NormalizedText) => {
            explanations.insert(WebsiteExplanation::ContentReuse);
            explanations.insert(WebsiteExplanation::CommonTemplate);
        }
        (WebsiteFeatureKind::HtmlStructure, WebsiteFeatureKind::HtmlStructure) => {
            explanations.insert(WebsiteExplanation::CommonTemplate);
            explanations.insert(WebsiteExplanation::CommonPlatform);
        }
        (WebsiteFeatureKind::PublicAsset, WebsiteFeatureKind::PublicAsset) => {
            explanations.insert(WebsiteExplanation::AssetReuse);
            explanations.insert(WebsiteExplanation::DevelopmentRelationship);
            explanations.insert(WebsiteExplanation::OperationalRelationship);
        }
        (WebsiteFeatureKind::ScriptReference, WebsiteFeatureKind::ScriptReference)
        | (WebsiteFeatureKind::StyleReference, WebsiteFeatureKind::StyleReference)
        | (
            WebsiteFeatureKind::ApplicationCharacteristic,
            WebsiteFeatureKind::ApplicationCharacteristic,
        ) => {
            explanations.insert(WebsiteExplanation::CommonPlatform);
            explanations.insert(WebsiteExplanation::CommonTemplate);
            explanations.insert(WebsiteExplanation::DevelopmentRelationship);
        }
        (
            WebsiteFeatureKind::PublicAnalyticsIdentifier,
            WebsiteFeatureKind::PublicAnalyticsIdentifier,
        )
        | (
            WebsiteFeatureKind::PublicContactInformation,
            WebsiteFeatureKind::PublicContactInformation,
        )
        | (WebsiteFeatureKind::Certificate, WebsiteFeatureKind::Certificate)
        | (WebsiteFeatureKind::OutboundLink, WebsiteFeatureKind::OutboundLink) => {
            explanations.insert(WebsiteExplanation::OperationalRelationship);
            explanations.insert(WebsiteExplanation::DevelopmentRelationship);
        }
        (WebsiteFeatureKind::ArchivedState, WebsiteFeatureKind::ArchivedState) => {
            explanations.insert(WebsiteExplanation::DevelopmentRelationship);
            explanations.insert(WebsiteExplanation::ContentReuse);
        }
        _ => {
            explanations.insert(WebsiteExplanation::OperationalRelationship);
        }
    }
    explanations.insert(WebsiteExplanation::Coincidence);
    explanations.insert(WebsiteExplanation::Unknown);
    explanations.into_iter().collect()
}

fn explanation_weight(
    explanation: WebsiteExplanation,
    base_weight: u16,
    left: &WebsiteObservation,
    right: &WebsiteObservation,
) -> u16 {
    let rare = left.kind().is_rare_signal() && right.kind().is_rare_signal();
    match explanation {
        WebsiteExplanation::Coincidence => base_weight / 3,
        WebsiteExplanation::Unknown => base_weight / 4,
        WebsiteExplanation::CommonPlatform | WebsiteExplanation::CommonTemplate => {
            base_weight.saturating_mul(3) / 5
        }
        WebsiteExplanation::OperationalRelationship
            if left.kind() == WebsiteFeatureKind::PublicAnalyticsIdentifier
                || right.kind() == WebsiteFeatureKind::PublicAnalyticsIdentifier
                || left.kind() == WebsiteFeatureKind::PublicContactInformation
                || right.kind() == WebsiteFeatureKind::PublicContactInformation =>
        {
            base_weight.saturating_add(10)
        }
        WebsiteExplanation::ContentReuse if rare => base_weight.saturating_add(5),
        WebsiteExplanation::AssetReuse if rare => base_weight.saturating_add(15),
        WebsiteExplanation::DevelopmentRelationship
            if left.kind() == WebsiteFeatureKind::PublicAsset
                || right.kind() == WebsiteFeatureKind::PublicAsset =>
        {
            base_weight.saturating_add(10)
        }
        _ => base_weight,
    }
}

impl ObservationSource for WebsiteObservation {
    fn dependency_group(&self) -> Option<&str> {
        Self::dependency_group(self)
    }

    fn source(&self) -> &Source {
        Self::source(self)
    }
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

/// Validates one observation against the registry and the live store, then
/// persists it inside a (nested) store transaction and indexes it.
///
/// Nothing is written unless every check passes, so the caller's registry
/// and the store agree after both success and refusal.
fn observe_into(
    evidence: &mut EvidenceStore,
    observations: &mut BTreeMap<String, WebsiteObservation>,
    website_observations: &mut BTreeMap<String, BTreeSet<String>>,
    limits: WebsiteLimits,
    observation: WebsiteObservation,
) -> Result<(), WebsiteError> {
    if observations.len() >= limits.max_observations() {
        return Err(WebsiteError::ResourceLimit {
            resource: "observations",
            limit: limits.max_observations(),
        });
    }
    let observation_id = observation.id().to_owned();
    if observations.contains_key(&observation_id) {
        return Err(WebsiteError::DuplicateObservation { observation_id });
    }
    if let Some(existing) = evidence.source(observation.source_id())
        && existing != observation.source()
    {
        return Err(WebsiteError::SourceConflict {
            source_id: observation.source_id().to_owned(),
        });
    }
    let canonical = observation.canonical_observation()?;
    if let Some(existing) = evidence.observation(observation.id())
        && existing != &canonical
    {
        return Err(WebsiteError::ObservationConflict { observation_id });
    }
    evidence.transaction(|store| {
        if store.source(observation.source_id()).is_none() {
            store.add_source(observation.source().clone())?;
        }
        if store.entity(observation.website_id()).is_none() {
            store.add_entity(Entity::new(observation.website_id(), EntityType::Website)?)?;
        }
        if store.observation(observation.id()).is_none() {
            store.add_observation(canonical)?;
        }
        Ok::<(), WebsiteError>(())
    })?;
    website_observations
        .entry(observation.website_id().to_owned())
        .or_default()
        .insert(observation_id.clone());
    observations.insert(observation_id, observation);
    Ok(())
}

/// Drops one observation id from a website's index, removing the website's
/// entry when it becomes empty.
fn forget_index(
    website_observations: &mut BTreeMap<String, BTreeSet<String>>,
    website_id: &str,
    observation_id: &str,
) {
    if let Some(ids) = website_observations.get_mut(website_id) {
        ids.remove(observation_id);
        if ids.is_empty() {
            website_observations.remove(website_id);
        }
    }
}

/// Stable identifier of the persisted correlation from `left_website` to
/// `right_website`.
fn correlation_identifier(left_website: &str, right_website: &str) -> String {
    format!("website-lineage:{left_website}:{right_website}")
}

fn rank_supports(supports: &[Support], mode: ScoreMode<'_>) -> Vec<WebsiteCorrelationRanking> {
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

fn explanation_order(explanation: WebsiteExplanation) -> u8 {
    match explanation {
        WebsiteExplanation::AssetReuse => 0,
        WebsiteExplanation::DevelopmentRelationship => 1,
        WebsiteExplanation::OperationalRelationship => 2,
        WebsiteExplanation::ContentReuse => 3,
        WebsiteExplanation::CommonTemplate => 4,
        WebsiteExplanation::CommonPlatform => 5,
        WebsiteExplanation::Coincidence => 6,
        WebsiteExplanation::Unknown => 7,
    }
}

fn rank_explanation(
    supports: &[Support],
    flagged: &BTreeSet<(&str, &str)>,
    explanation: WebsiteExplanation,
    mode: ScoreMode<'_>,
) -> WebsiteCorrelationRanking {
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
    WebsiteCorrelationRanking {
        explanation,
        score,
        confidence: Confidence::new(score.min(100) as u8),
        independent_support,
        supporting_pairs,
        collapsed_pairs: collapsed,
        high_base_rate_support,
        temporal_compatibility: Confidence::new(temporal_compatibility),
    }
}

fn to_pair(support: &Support, weight: u16) -> WebsiteObservationPair {
    WebsiteObservationPair {
        left_observation: support.left_observation.clone(),
        right_observation: support.right_observation.clone(),
        weight,
        temporal_relation: support.temporal_relation,
    }
}

fn build_falsification(
    supports: &[Support],
    baseline_rankings: &[WebsiteCorrelationRanking],
    baseline: &WebsiteCorrelationRanking,
) -> WebsiteCorrelationFalsification {
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
            .max_by(|left, right| {
                active_weight(left, ScoreMode::Baseline)
                    .cmp(&active_weight(right, ScoreMode::Baseline))
                    .then_with(|| pair_key_cmp(left, right))
            })
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
    WebsiteCorrelationFalsification {
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

fn score_for(supports: &[Support], explanation: WebsiteExplanation, mode: ScoreMode<'_>) -> u16 {
    rank_supports(supports, mode)
        .into_iter()
        .find(|ranking| ranking.explanation == explanation)
        .map_or(0, |ranking| ranking.score)
}

fn empty_ranking(explanation: WebsiteExplanation) -> WebsiteCorrelationRanking {
    WebsiteCorrelationRanking {
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

fn missing_expected_evidence(baseline: &WebsiteCorrelationRanking) -> Vec<WebsiteFeatureKind> {
    match baseline.explanation {
        WebsiteExplanation::DevelopmentRelationship if baseline.independent_support < 2 => {
            vec![WebsiteFeatureKind::PublicAsset]
        }
        WebsiteExplanation::OperationalRelationship if baseline.independent_support < 2 => {
            vec![WebsiteFeatureKind::PublicAnalyticsIdentifier]
        }
        WebsiteExplanation::AssetReuse if baseline.independent_support < 2 => {
            vec![WebsiteFeatureKind::ApplicationCharacteristic]
        }
        _ => Vec::new(),
    }
}

fn strongest_temporal_relation(ranking: &WebsiteCorrelationRanking) -> TemporalRelation {
    ranking
        .supporting_pairs()
        .iter()
        .map(WebsiteObservationPair::temporal_relation)
        .min()
        .unwrap_or(TemporalRelation::Disjoint)
}

fn operator_assessment(ranking: &WebsiteCorrelationRanking) -> OperatorAssessment {
    if ranking.explanation == WebsiteExplanation::OperationalRelationship
        && ranking.independent_support >= 2
        && ranking.score >= 70
    {
        OperatorAssessment::PossibleCommonOperator
    } else {
        OperatorAssessment::NotEstablished
    }
}

/// Alias for the architecture's shorter engine name.
pub type WebsiteLineageEngine = WebsiteLineageEcosystemAnalysisEngine;

/// Alias emphasizing website ecosystem analysis.
pub type WebsiteEcosystemAnalysisEngine = WebsiteLineageEcosystemAnalysisEngine;

/// Alias for one website feature observation.
pub type WebsiteRecord = WebsiteObservation;

/// Alias for website feature factors.
pub type WebsiteCorrelationFactors = WebsiteFactors;

/// Alias for a website feature family.
pub type WebsiteObservationKind = WebsiteFeatureKind;

/// Alias for a complete website report.
pub type WebsiteCorrelationReport = WebsiteLineageReport;

/// Alias for a persisted website relationship edge.
pub type WebsiteCorrelationEdge = WebsiteLineageEdge;

/// Alias for website falsification.
pub type WebsiteFalsificationReport = WebsiteCorrelationFalsification;

/// Alias for the shared temporal interval.
pub type WebsiteTimeline = TemporalInterval;
