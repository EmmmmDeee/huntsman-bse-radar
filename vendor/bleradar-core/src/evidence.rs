//! Canonical evidence and provenance records.
//!
//! This module is the authoritative, dependency-free state model for facts
//! collected by other engines.  Raw observations are immutable after
//! construction; normalized values and derivations are stored alongside them
//! and never replace them.  References are represented by stable caller-owned
//! identifiers so every claim and transformation can be traced back to its
//! inputs.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fmt;

use crate::Confidence;

/// Stable identifier used by a caller for a record in the evidence core.
pub type RecordId = String;

/// Identifier for an [`Entity`].
pub type EntityId = RecordId;

/// Identifier for an [`Artifact`].
pub type ArtifactId = RecordId;

/// Identifier for an [`Observation`].
pub type ObservationId = RecordId;

/// Identifier for a [`Feature`].
pub type FeatureId = RecordId;

/// Identifier for a [`Representation`].
pub type RepresentationId = RecordId;

/// Identifier for a [`Transformation`].
pub type TransformationId = RecordId;

/// Identifier for a [`Source`].
pub type SourceId = RecordId;

/// Identifier for an [`Event`].
pub type EventId = RecordId;

/// Identifier for a [`Relationship`].
pub type RelationshipId = RecordId;

/// Identifier for a [`Hypothesis`].
pub type HypothesisId = RecordId;

/// Identifier for a [`Claim`].
pub type ClaimId = RecordId;

/// Identifier for an [`Evidence`].
pub type EvidenceId = RecordId;

/// Identifier for a [`Test`].
pub type TestId = RecordId;

/// Identifier for an [`Action`].
pub type ActionId = RecordId;

/// Identifier for a [`ConfidenceUpdate`].
pub type ConfidenceUpdateId = RecordId;

/// Milliseconds since the caller's chosen epoch or monotonic origin.
pub type Timestamp = u64;

/// A lossless-enough value container for raw and normalized evidence.
///
/// The raw variant is retained exactly as supplied.  Normalization may use a
/// different variant, but is stored in a separate field on [`Observation`].
#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceValue {
    /// Human-readable text.
    Text(String),
    /// Opaque bytes that must not be interpreted as text.
    Bytes(Vec<u8>),
    /// An integer value.
    Integer(i128),
    /// A floating-point value.
    Float(f64),
    /// A boolean value.
    Boolean(bool),
    /// An explicitly absent value.
    Null,
}

/// Short alias for [`EvidenceValue`].
pub type Value = EvidenceValue;

impl EvidenceValue {
    /// Creates a text value.
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Creates an opaque byte value.
    #[must_use]
    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    /// Returns the text when this is a [`EvidenceValue::Text`] value.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the bytes when this is a [`EvidenceValue::Bytes`] value.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value),
            _ => None,
        }
    }
}

impl From<&str> for EvidenceValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for EvidenceValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<Vec<u8>> for EvidenceValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<&[u8]> for EvidenceValue {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

impl From<i128> for EvidenceValue {
    fn from(value: i128) -> Self {
        Self::Integer(value)
    }
}

impl From<i64> for EvidenceValue {
    fn from(value: i64) -> Self {
        Self::Integer(i128::from(value))
    }
}

impl From<i8> for EvidenceValue {
    fn from(value: i8) -> Self {
        Self::Integer(i128::from(value))
    }
}

impl From<i16> for EvidenceValue {
    fn from(value: i16) -> Self {
        Self::Integer(i128::from(value))
    }
}

impl From<i32> for EvidenceValue {
    fn from(value: i32) -> Self {
        Self::Integer(i128::from(value))
    }
}

impl From<isize> for EvidenceValue {
    fn from(value: isize) -> Self {
        Self::Integer(value as i128)
    }
}

impl From<u8> for EvidenceValue {
    fn from(value: u8) -> Self {
        Self::Integer(i128::from(value))
    }
}

impl From<u16> for EvidenceValue {
    fn from(value: u16) -> Self {
        Self::Integer(i128::from(value))
    }
}

impl From<u32> for EvidenceValue {
    fn from(value: u32) -> Self {
        Self::Integer(i128::from(value))
    }
}

impl From<u64> for EvidenceValue {
    fn from(value: u64) -> Self {
        Self::Integer(i128::from(value))
    }
}

impl From<usize> for EvidenceValue {
    fn from(value: usize) -> Self {
        Self::Integer(value as i128)
    }
}

impl From<f32> for EvidenceValue {
    fn from(value: f32) -> Self {
        Self::Float(f64::from(value))
    }
}

impl From<f64> for EvidenceValue {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<bool> for EvidenceValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

/// Broad origin classification for a source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceType {
    /// A hardware or software sensor.
    Sensor,
    /// A text or structured document.
    Document,
    /// An image, audio, video, or other media item.
    Media,
    /// A website or web property.
    Website,
    /// A source repository.
    Repository,
    /// A package or release artifact.
    Package,
    /// A compiled binary.
    Binary,
    /// A firmware component.
    Firmware,
    /// An API response.
    Api,
    /// An archived snapshot.
    Archive,
    /// An imported user-supplied record.
    Import,
    /// A manually supplied public source.
    UserProvided,
    /// A value produced by an explicitly recorded derivation.
    Derived,
    /// A source whose family is not known.
    Unknown,
    /// An application-specific source family.
    Other(String),
}

impl SourceType {
    /// Returns a stable lower-case label for this source family.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sensor => "sensor",
            Self::Document => "document",
            Self::Media => "media",
            Self::Website => "website",
            Self::Repository => "repository",
            Self::Package => "package",
            Self::Binary => "binary",
            Self::Firmware => "firmware",
            Self::Api => "api",
            Self::Archive => "archive",
            Self::Import => "import",
            Self::UserProvided => "user_provided",
            Self::Derived => "derived",
            Self::Unknown => "unknown",
            Self::Other(value) => value,
        }
    }
}

impl fmt::Display for SourceType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How a source was retrieved.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetrievalMethod {
    /// Directly read from the source.
    Direct,
    /// Retrieved through an API.
    Api,
    /// Retrieved as a downloaded file or object.
    Download,
    /// Retrieved from an archive or snapshot.
    Archive,
    /// Supplied through a manual workflow.
    Manual,
    /// Captured by a sensor.
    Sensor,
    /// Read from an import.
    Import,
    /// Found by a search operation.
    Search,
    /// Produced by an explicitly recorded derivation.
    Derived,
    /// An application-specific retrieval method.
    Other(String),
}

impl RetrievalMethod {
    /// Returns a stable lower-case label for this retrieval method.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Direct => "direct",
            Self::Api => "api",
            Self::Download => "download",
            Self::Archive => "archive",
            Self::Manual => "manual",
            Self::Sensor => "sensor",
            Self::Import => "import",
            Self::Search => "search",
            Self::Derived => "derived",
            Self::Other(value) => value,
        }
    }
}

impl fmt::Display for RetrievalMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Validation and referential-integrity failures in the evidence core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// A required identifier or textual value was empty.
    EmptyValue {
        /// Name of the empty field.
        field: &'static str,
    },
    /// An observation timeline is not ordered.
    InvalidTimeline {
        /// First time the observation was seen.
        first_seen: Timestamp,
        /// Time at which the observation was made.
        observed_at: Timestamp,
        /// Most recent time the observation was seen.
        last_seen: Timestamp,
    },
    /// A derived record was timestamped before the record it depends on.
    TemporalViolation {
        /// Type of the derived record.
        record: &'static str,
        /// Identifier of the derived record.
        record_id: String,
        /// Identifier of the earlier record it depends on.
        reference: String,
        /// Timestamp assigned to the derived record.
        record_time: Timestamp,
        /// Timestamp assigned to its dependency.
        reference_time: Timestamp,
    },
    /// An identifier is already present in a collection.
    DuplicateId {
        /// Collection containing the duplicate.
        collection: &'static str,
        /// Duplicate identifier.
        id: String,
    },
    /// A record refers to a record that is not in the store.
    MissingReference {
        /// Type of the record containing the reference.
        record: &'static str,
        /// Identifier of the record containing the reference.
        record_id: String,
        /// Field containing the reference.
        field: &'static str,
        /// Missing referenced identifier.
        reference: String,
    },
    /// A source's metadata disagrees with the copy retained by an observation.
    SourceMetadataMismatch {
        /// Observation carrying the inconsistent metadata.
        observation_id: String,
        /// Source referenced by the observation.
        source_id: String,
    },
    /// A feature was declared both preserved and changed by a transformation.
    FeatureInBothSets {
        /// Transformation with the contradictory declaration.
        transformation_id: String,
        /// Feature in both sets.
        feature_id: String,
    },
    /// A non-unverified transformation has no verification tests.
    MissingVerification {
        /// Transformation lacking verification evidence.
        transformation_id: String,
    },
    /// A claim has no evidence attached through its hypothesis.
    ClaimWithoutEvidence {
        /// Claim lacking an evidence chain.
        claim_id: String,
    },
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue { field } => write!(formatter, "{field} must not be empty"),
            Self::InvalidTimeline {
                first_seen,
                observed_at,
                last_seen,
            } => write!(
                formatter,
                "observation timeline must satisfy first_seen <= observed_at <= last_seen (got {first_seen} <= {observed_at} <= {last_seen})"
            ),
            Self::TemporalViolation {
                record,
                record_id,
                reference,
                record_time,
                reference_time,
            } => write!(
                formatter,
                "{record} `{record_id}` at {record_time} precedes dependency `{reference}` at {reference_time}"
            ),
            Self::DuplicateId { collection, id } => {
                write!(formatter, "duplicate {collection} identifier `{id}`")
            }
            Self::MissingReference {
                record,
                record_id,
                field,
                reference,
            } => write!(
                formatter,
                "{record} `{record_id}` references missing {field} `{reference}`"
            ),
            Self::SourceMetadataMismatch {
                observation_id,
                source_id,
            } => write!(
                formatter,
                "observation `{observation_id}` does not preserve source metadata for `{source_id}`"
            ),
            Self::FeatureInBothSets {
                transformation_id,
                feature_id,
            } => write!(
                formatter,
                "transformation `{transformation_id}` marks feature `{feature_id}` as both preserved and changed"
            ),
            Self::MissingVerification { transformation_id } => write!(
                formatter,
                "transformation `{transformation_id}` requires at least one verification test"
            ),
            Self::ClaimWithoutEvidence { claim_id } => {
                write!(formatter, "claim `{claim_id}` has no evidence chain")
            }
        }
    }
}

impl std::error::Error for ProvenanceError {}

impl crate::validation::EmptyValueError for ProvenanceError {
    fn empty_value(field: &'static str) -> Self {
        Self::EmptyValue { field }
    }
}

fn require_text(value: String, field: &'static str) -> Result<String, ProvenanceError> {
    crate::validation::require_text(value, field)
}

fn require_ref<T>(
    collection: &BTreeMap<String, T>,
    record: &'static str,
    record_id: &str,
    field: &'static str,
    reference: &str,
) -> Result<(), ProvenanceError> {
    if collection.contains_key(reference) {
        Ok(())
    } else {
        Err(ProvenanceError::MissingReference {
            record,
            record_id: record_id.to_owned(),
            field,
            reference: reference.to_owned(),
        })
    }
}

fn insert_unique<T>(
    collection: &mut BTreeMap<String, T>,
    journal: &mut Option<Vec<Undo>>,
    kind: RecordKind,
    id: &str,
    value: T,
) -> Result<(), ProvenanceError> {
    match collection.entry(id.to_owned()) {
        Entry::Vacant(entry) => {
            entry.insert(value);
            if let Some(journal) = journal.as_mut() {
                journal.push(Undo::Remove(kind, id.to_owned()));
            }
            Ok(())
        }
        Entry::Occupied(_) => Err(ProvenanceError::DuplicateId {
            collection: kind.collection_name(),
            id: id.to_owned(),
        }),
    }
}

/// An ordered observation timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationTimeline {
    first_seen: Timestamp,
    observed_at: Timestamp,
    last_seen: Timestamp,
}

impl ObservationTimeline {
    /// Creates a timeline after enforcing `first_seen <= observed_at <= last_seen`.
    pub fn new(
        first_seen: Timestamp,
        observed_at: Timestamp,
        last_seen: Timestamp,
    ) -> Result<Self, ProvenanceError> {
        if first_seen > observed_at || observed_at > last_seen {
            return Err(ProvenanceError::InvalidTimeline {
                first_seen,
                observed_at,
                last_seen,
            });
        }
        Ok(Self {
            first_seen,
            observed_at,
            last_seen,
        })
    }

    /// Creates a timeline for a single observation instant.
    pub const fn at(observed_at: Timestamp) -> Self {
        Self {
            first_seen: observed_at,
            observed_at,
            last_seen: observed_at,
        }
    }

    /// First time the observation was seen.
    #[must_use]
    pub const fn first_seen(self) -> Timestamp {
        self.first_seen
    }

    /// Time at which the observation was made.
    #[must_use]
    pub const fn observed_at(self) -> Timestamp {
        self.observed_at
    }

    /// Most recent time the observation was seen.
    #[must_use]
    pub const fn last_seen(self) -> Timestamp {
        self.last_seen
    }
}

/// A public entity that may be related to other records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    id: EntityId,
    kind: EntityType,
    label: Option<String>,
    metadata: BTreeMap<String, String>,
}

/// Broad classification for an [`Entity`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntityType {
    /// A public person or account.
    PublicEntity,
    /// An organization.
    Organization,
    /// A physical or logical device.
    Device,
    /// A website.
    Website,
    /// A software project.
    Software,
    /// A repository.
    Repository,
    /// A document.
    Document,
    /// A media item.
    Media,
    /// Infrastructure such as a host, address, or certificate.
    Infrastructure,
    /// An application-specific entity type.
    Other(String),
}

/// Alias for [`EntityType`].
pub type EntityKind = EntityType;

impl Entity {
    /// Creates an entity with no label or metadata.
    pub fn new(id: impl Into<String>, kind: EntityType) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "entity id")?,
            kind,
            label: None,
            metadata: BTreeMap::new(),
        })
    }

    /// Adds a human-readable label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Adds one metadata entry.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Stable entity identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Entity classification.
    #[must_use]
    pub const fn kind(&self) -> &EntityType {
        &self.kind
    }

    /// Optional human-readable label.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Read-only metadata.
    #[must_use]
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }
}

/// Broad classification for an [`Artifact`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactType {
    /// A generic digital artifact.
    Digital,
    /// A source file or source tree.
    Source,
    /// A package or release.
    Package,
    /// A compiled binary.
    Binary,
    /// A document.
    Document,
    /// A media item.
    Media,
    /// A web capture.
    WebCapture,
    /// A firmware component.
    Firmware,
    /// An application-specific artifact type.
    Other(String),
}

/// An observed or obtained object that can have multiple representations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    id: ArtifactId,
    kind: ArtifactType,
    entity_id: Option<EntityId>,
    source_id: Option<SourceId>,
    created_at: Option<Timestamp>,
    representation_ids: Vec<RepresentationId>,
    metadata: BTreeMap<String, String>,
}

impl Artifact {
    /// Creates an artifact with no optional links.
    pub fn new(id: impl Into<String>, kind: ArtifactType) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "artifact id")?,
            kind,
            entity_id: None,
            source_id: None,
            created_at: None,
            representation_ids: Vec::new(),
            metadata: BTreeMap::new(),
        })
    }

    /// Associates the artifact with an entity.
    #[must_use]
    pub fn for_entity(mut self, entity_id: impl Into<String>) -> Self {
        self.entity_id = Some(entity_id.into());
        self
    }

    /// Associates the artifact with a source.
    #[must_use]
    pub fn from_source(mut self, source_id: impl Into<String>) -> Self {
        self.source_id = Some(source_id.into());
        self
    }

    /// Records the artifact's creation time.
    #[must_use]
    pub const fn created_at(mut self, timestamp: Timestamp) -> Self {
        self.created_at = Some(timestamp);
        self
    }

    /// Adds a representation identifier to the artifact's index.
    #[must_use]
    pub fn with_representation(mut self, representation_id: impl Into<String>) -> Self {
        self.representation_ids.push(representation_id.into());
        self
    }

    /// Adds one metadata entry.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Stable artifact identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Artifact classification.
    #[must_use]
    pub const fn kind(&self) -> &ArtifactType {
        &self.kind
    }

    /// Entity associated with this artifact, if any.
    #[must_use]
    pub fn entity_id(&self) -> Option<&str> {
        self.entity_id.as_deref()
    }

    /// Source associated with this artifact, if any.
    #[must_use]
    pub fn source_id(&self) -> Option<&str> {
        self.source_id.as_deref()
    }

    /// Artifact creation time, if known.
    #[must_use]
    pub const fn created_at_value(&self) -> Option<Timestamp> {
        self.created_at
    }

    /// Indexed representation identifiers.
    #[must_use]
    pub fn representation_ids(&self) -> &[RepresentationId] {
        &self.representation_ids
    }

    /// Read-only metadata.
    #[must_use]
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }
}

/// A source of public evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    id: SourceId,
    source_type: SourceType,
    retrieval_method: RetrievalMethod,
    locator: Option<String>,
    captured_at: Option<Timestamp>,
    metadata: BTreeMap<String, String>,
}

impl Source {
    /// Creates a source with no locator, capture time, or metadata.
    pub fn new(
        id: impl Into<String>,
        source_type: SourceType,
        retrieval_method: RetrievalMethod,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "source id")?,
            source_type,
            retrieval_method,
            locator: None,
            captured_at: None,
            metadata: BTreeMap::new(),
        })
    }

    /// Records a public locator such as a URL, path, or content address.
    #[must_use]
    pub fn with_locator(mut self, locator: impl Into<String>) -> Self {
        self.locator = Some(locator.into());
        self
    }

    /// Records the time at which the source was captured.
    #[must_use]
    pub const fn captured_at(mut self, timestamp: Timestamp) -> Self {
        self.captured_at = Some(timestamp);
        self
    }

    /// Adds one source metadata entry.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Stable source identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Source family.
    #[must_use]
    pub const fn source_type(&self) -> &SourceType {
        &self.source_type
    }

    /// Retrieval method.
    #[must_use]
    pub const fn retrieval_method(&self) -> &RetrievalMethod {
        &self.retrieval_method
    }

    /// Public locator, if known.
    #[must_use]
    pub fn locator(&self) -> Option<&str> {
        self.locator.as_deref()
    }

    /// Capture time, if known.
    #[must_use]
    pub const fn captured_at_value(&self) -> Option<Timestamp> {
        self.captured_at
    }

    /// Read-only source metadata.
    #[must_use]
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }
}

/// One directly observed value with complete temporal and source provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    id: ObservationId,
    raw_value: EvidenceValue,
    normalized_value: Option<EvidenceValue>,
    source: SourceId,
    source_type: SourceType,
    retrieval_method: RetrievalMethod,
    timeline: ObservationTimeline,
    derivation_history: Vec<TransformationId>,
}

impl Observation {
    /// Creates an observation whose first and last seen times equal `observed_at`.
    ///
    /// `raw_value` and `normalized_value` are stored separately.  The raw value
    /// is never changed by normalization.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        raw_value: impl Into<EvidenceValue>,
        normalized_value: Option<EvidenceValue>,
        source: impl Into<String>,
        source_type: SourceType,
        retrieval_method: RetrievalMethod,
        observed_at: Timestamp,
    ) -> Result<Self, ProvenanceError> {
        Self::with_timeline(
            id,
            raw_value,
            normalized_value,
            source,
            source_type,
            retrieval_method,
            ObservationTimeline::at(observed_at),
        )
    }

    /// Creates an observation with an explicit first-seen/last-seen interval.
    #[allow(clippy::too_many_arguments)]
    pub fn with_timeline(
        id: impl Into<String>,
        raw_value: impl Into<EvidenceValue>,
        normalized_value: Option<EvidenceValue>,
        source: impl Into<String>,
        source_type: SourceType,
        retrieval_method: RetrievalMethod,
        timeline: ObservationTimeline,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "observation id")?,
            raw_value: raw_value.into(),
            normalized_value,
            source: require_text(source.into(), "observation source")?,
            source_type,
            retrieval_method,
            timeline,
            derivation_history: Vec::new(),
        })
    }

    /// Creates an observation using metadata copied from a [`Source`].
    pub fn from_source(
        id: impl Into<String>,
        raw_value: impl Into<EvidenceValue>,
        normalized_value: Option<EvidenceValue>,
        source: &Source,
        observed_at: Timestamp,
    ) -> Result<Self, ProvenanceError> {
        Self::new(
            id,
            raw_value,
            normalized_value,
            source.id.clone(),
            source.source_type.clone(),
            source.retrieval_method.clone(),
            observed_at,
        )
    }

    /// Returns a copy with a normalized value while preserving the raw value.
    #[must_use]
    pub fn with_normalized_value(&self, normalized_value: impl Into<EvidenceValue>) -> Self {
        let mut copy = self.clone();
        copy.normalized_value = Some(normalized_value.into());
        copy
    }

    /// Returns a copy with a normalized value and a recorded transformation.
    pub fn with_normalization(
        &self,
        normalized_value: impl Into<EvidenceValue>,
        transformation_id: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        let transformation_id = require_text(transformation_id.into(), "transformation id")?;
        let mut copy = self.with_normalized_value(normalized_value);
        copy.derivation_history.push(transformation_id);
        Ok(copy)
    }

    /// Returns a copy with one additional derivation-history entry.
    pub fn with_derivation(
        &self,
        transformation_id: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        let transformation_id = require_text(transformation_id.into(), "transformation id")?;
        let mut copy = self.clone();
        copy.derivation_history.push(transformation_id);
        Ok(copy)
    }

    /// Returns a copy whose last-seen time is extended.
    pub fn seen_at(&self, timestamp: Timestamp) -> Result<Self, ProvenanceError> {
        if timestamp < self.timeline.last_seen {
            return Err(ProvenanceError::InvalidTimeline {
                first_seen: self.timeline.first_seen,
                observed_at: self.timeline.observed_at,
                last_seen: timestamp,
            });
        }
        let mut copy = self.clone();
        copy.timeline.last_seen = timestamp;
        Ok(copy)
    }

    /// Stable observation identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Exact raw value captured by the observation.
    #[must_use]
    pub const fn raw_value(&self) -> &EvidenceValue {
        &self.raw_value
    }

    /// Normalized value, if one has been produced.
    #[must_use]
    pub const fn normalized_value(&self) -> Option<&EvidenceValue> {
        self.normalized_value.as_ref()
    }

    /// Source identifier.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Source family copied at observation time.
    #[must_use]
    pub const fn source_type(&self) -> &SourceType {
        &self.source_type
    }

    /// Retrieval method copied at observation time.
    #[must_use]
    pub const fn retrieval_method(&self) -> &RetrievalMethod {
        &self.retrieval_method
    }

    /// Observation time.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.timeline.observed_at
    }

    /// First time the observation was seen.
    #[must_use]
    pub const fn first_seen(&self) -> Timestamp {
        self.timeline.first_seen
    }

    /// Most recent time the observation was seen.
    #[must_use]
    pub const fn last_seen(&self) -> Timestamp {
        self.timeline.last_seen
    }

    /// Transformations that produced normalized or derived values.
    #[must_use]
    pub fn derivation_history(&self) -> &[TransformationId] {
        &self.derivation_history
    }
}

/// A named extracted property of an artifact or observation.
#[derive(Debug, Clone, PartialEq)]
pub struct Feature {
    id: FeatureId,
    name: String,
    value: EvidenceValue,
    source_observation: Option<ObservationId>,
    derived_from: Vec<FeatureId>,
    confidence: Confidence,
    created_at: Option<Timestamp>,
}

impl Feature {
    /// Creates a feature with the default zero confidence.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        value: impl Into<EvidenceValue>,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "feature id")?,
            name: require_text(name.into(), "feature name")?,
            value: value.into(),
            source_observation: None,
            derived_from: Vec::new(),
            confidence: Confidence::new(0),
            created_at: None,
        })
    }

    /// Associates the feature with its direct observation.
    #[must_use]
    pub fn from_observation(mut self, observation_id: impl Into<String>) -> Self {
        self.source_observation = Some(observation_id.into());
        self
    }

    /// Records feature identifiers used to derive this feature.
    #[must_use]
    pub fn derived_from(mut self, feature_ids: impl IntoIterator<Item = String>) -> Self {
        self.derived_from.extend(feature_ids);
        self
    }

    /// Sets the feature confidence.
    #[must_use]
    pub const fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Records the time at which the feature was extracted or derived.
    #[must_use]
    pub const fn created_at(mut self, timestamp: Timestamp) -> Self {
        self.created_at = Some(timestamp);
        self
    }

    /// Stable feature identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Feature name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Feature value.
    #[must_use]
    pub const fn value(&self) -> &EvidenceValue {
        &self.value
    }

    /// Direct observation that supplied the feature, if known.
    #[must_use]
    pub fn source_observation(&self) -> Option<&str> {
        self.source_observation.as_deref()
    }

    /// Feature identifiers used in derivation.
    #[must_use]
    pub fn derived_feature_ids(&self) -> &[FeatureId] {
        &self.derived_from
    }

    /// Feature confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Feature extraction or derivation time, if known.
    #[must_use]
    pub const fn created_at_value(&self) -> Option<Timestamp> {
        self.created_at
    }
}

/// Representation format for an artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RepresentationType {
    /// Original bytes or source form.
    Raw,
    /// Normalized textual or structured form.
    Normalized,
    /// A document representation.
    Document,
    /// A media representation.
    Media,
    /// A source-code representation.
    Source,
    /// A package representation.
    Package,
    /// A compiled binary representation.
    Binary,
    /// An application-specific representation.
    Other(String),
}

/// One representation of an [`Artifact`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Representation {
    id: RepresentationId,
    artifact: ArtifactId,
    kind: RepresentationType,
    feature_ids: Vec<FeatureId>,
    source: Option<SourceId>,
    created_at: Option<Timestamp>,
}

impl Representation {
    /// Creates a representation for an artifact.
    pub fn new(
        id: impl Into<String>,
        artifact: impl Into<String>,
        kind: RepresentationType,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "representation id")?,
            artifact: require_text(artifact.into(), "representation artifact")?,
            kind,
            feature_ids: Vec::new(),
            source: None,
            created_at: None,
        })
    }

    /// Adds a feature identifier to the representation.
    #[must_use]
    pub fn with_feature(mut self, feature_id: impl Into<String>) -> Self {
        self.feature_ids.push(feature_id.into());
        self
    }

    /// Adds several feature identifiers to the representation.
    #[must_use]
    pub fn with_features(mut self, feature_ids: impl IntoIterator<Item = String>) -> Self {
        self.feature_ids.extend(feature_ids);
        self
    }

    /// Associates the representation with a source.
    #[must_use]
    pub fn from_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Records the representation creation time.
    #[must_use]
    pub const fn created_at(mut self, timestamp: Timestamp) -> Self {
        self.created_at = Some(timestamp);
        self
    }

    /// Stable representation identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Artifact represented by this record.
    #[must_use]
    pub fn artifact(&self) -> &str {
        &self.artifact
    }

    /// Representation format.
    #[must_use]
    pub const fn kind(&self) -> &RepresentationType {
        &self.kind
    }

    /// Feature identifiers in this representation.
    #[must_use]
    pub fn feature_ids(&self) -> &[FeatureId] {
        &self.feature_ids
    }

    /// Source identifier, if known.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Creation time, if known.
    #[must_use]
    pub const fn created_at_value(&self) -> Option<Timestamp> {
        self.created_at
    }
}

/// Verification status for a transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// No verification has run yet.
    Unverified,
    /// Verification passed.
    Passed,
    /// Verification failed.
    Failed,
    /// Verification produced mixed or incomplete results.
    Inconclusive,
}

/// Verification record attached to a transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    status: VerificationStatus,
    test_ids: Vec<TestId>,
    notes: Option<String>,
}

impl Verification {
    /// Creates an explicitly unverified record.
    #[must_use]
    pub const fn unverified() -> Self {
        Self {
            status: VerificationStatus::Unverified,
            test_ids: Vec::new(),
            notes: None,
        }
    }

    /// Creates a passed verification backed by test identifiers.
    pub fn passed(test_ids: impl IntoIterator<Item = String>) -> Result<Self, ProvenanceError> {
        let test_ids: Vec<_> = test_ids.into_iter().collect();
        if test_ids.is_empty() {
            return Err(ProvenanceError::EmptyValue {
                field: "verification test ids",
            });
        }
        Ok(Self {
            status: VerificationStatus::Passed,
            test_ids,
            notes: None,
        })
    }

    /// Creates a failed verification backed by test identifiers.
    pub fn failed(test_ids: impl IntoIterator<Item = String>) -> Result<Self, ProvenanceError> {
        let test_ids: Vec<_> = test_ids.into_iter().collect();
        if test_ids.is_empty() {
            return Err(ProvenanceError::EmptyValue {
                field: "verification test ids",
            });
        }
        Ok(Self {
            status: VerificationStatus::Failed,
            test_ids,
            notes: None,
        })
    }

    /// Adds explanatory notes to the verification.
    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Verification status.
    #[must_use]
    pub const fn status(&self) -> VerificationStatus {
        self.status
    }

    /// Test identifiers supporting the status.
    #[must_use]
    pub fn test_ids(&self) -> &[TestId] {
        &self.test_ids
    }

    /// Optional explanatory notes.
    #[must_use]
    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }
}

/// Records a transformation between two representations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transformation {
    id: TransformationId,
    input_representation: RepresentationId,
    output_representation: RepresentationId,
    preserved_features: Vec<FeatureId>,
    changed_features: Vec<FeatureId>,
    verification: Verification,
}

impl Transformation {
    /// Creates a transformation and rejects features declared both preserved
    /// and changed.
    pub fn new(
        id: impl Into<String>,
        input_representation: impl Into<String>,
        output_representation: impl Into<String>,
        preserved_features: impl IntoIterator<Item = String>,
        changed_features: impl IntoIterator<Item = String>,
        verification: Verification,
    ) -> Result<Self, ProvenanceError> {
        let id = require_text(id.into(), "transformation id")?;
        let input_representation =
            require_text(input_representation.into(), "input representation")?;
        let output_representation =
            require_text(output_representation.into(), "output representation")?;
        let preserved_features: Vec<_> = preserved_features.into_iter().collect();
        let changed_features: Vec<_> = changed_features.into_iter().collect();
        let changed: BTreeSet<_> = changed_features.iter().collect();
        if let Some(feature_id) = preserved_features.iter().find(|id| changed.contains(id)) {
            return Err(ProvenanceError::FeatureInBothSets {
                transformation_id: id,
                feature_id: feature_id.clone(),
            });
        }
        Ok(Self {
            id,
            input_representation,
            output_representation,
            preserved_features,
            changed_features,
            verification,
        })
    }

    /// Stable transformation identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Input representation identifier.
    #[must_use]
    pub fn input_representation(&self) -> &str {
        &self.input_representation
    }

    /// Output representation identifier.
    #[must_use]
    pub fn output_representation(&self) -> &str {
        &self.output_representation
    }

    /// Feature identifiers preserved by the transformation.
    #[must_use]
    pub fn preserved_features(&self) -> &[FeatureId] {
        &self.preserved_features
    }

    /// Feature identifiers changed by the transformation.
    #[must_use]
    pub fn changed_features(&self) -> &[FeatureId] {
        &self.changed_features
    }

    /// Verification record.
    #[must_use]
    pub const fn verification(&self) -> &Verification {
        &self.verification
    }
}

/// Event kind in the evidence timeline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventType {
    /// An item was first created.
    Created,
    /// An item was retrieved.
    Retrieved,
    /// An item was published.
    Published,
    /// An item was transformed.
    Transformed,
    /// An item was observed.
    Observed,
    /// An item was updated.
    Updated,
    /// An application-specific event.
    Other(String),
}

/// A timestamped event relating public records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    id: EventId,
    kind: EventType,
    occurred_at: Timestamp,
    entity_ids: Vec<EntityId>,
    source: Option<SourceId>,
    description: Option<String>,
}

impl Event {
    /// Creates an event with no description or source.
    pub fn new(
        id: impl Into<String>,
        kind: EventType,
        occurred_at: Timestamp,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "event id")?,
            kind,
            occurred_at,
            entity_ids: Vec::new(),
            source: None,
            description: None,
        })
    }

    /// Associates the event with entities.
    #[must_use]
    pub fn involving(mut self, entity_ids: impl IntoIterator<Item = String>) -> Self {
        self.entity_ids.extend(entity_ids);
        self
    }

    /// Associates the event with a source.
    #[must_use]
    pub fn from_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Adds a human-readable description.
    #[must_use]
    pub fn described_as(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Stable event identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Event kind.
    #[must_use]
    pub const fn kind(&self) -> &EventType {
        &self.kind
    }

    /// Event timestamp.
    #[must_use]
    pub const fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }

    /// Entity identifiers involved in the event.
    #[must_use]
    pub fn entity_ids(&self) -> &[EntityId] {
        &self.entity_ids
    }

    /// Source identifier, if known.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Optional event description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// Edge classification for a relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    /// Directly observed relationship.
    Observed,
    /// Directly derived relationship.
    Derived,
    /// Relationship inferred from evidence.
    Inferred,
    /// Relationship with material contradictory support.
    Contested,
    /// Relationship rejected by verification.
    Rejected,
}

/// Source, method, support, contradiction, and observation provenance for an edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipProvenance {
    source: SourceId,
    timestamp: Timestamp,
    method: String,
    support: Vec<EvidenceId>,
    contradiction: Vec<EvidenceId>,
    observations: Vec<ObservationId>,
}

impl RelationshipProvenance {
    /// Creates provenance for a relationship edge.
    pub fn new(
        source: impl Into<String>,
        timestamp: Timestamp,
        method: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            source: require_text(source.into(), "relationship source")?,
            timestamp,
            method: require_text(method.into(), "relationship method")?,
            support: Vec::new(),
            contradiction: Vec::new(),
            observations: Vec::new(),
        })
    }

    /// Adds supporting evidence identifiers.
    #[must_use]
    pub fn supporting(mut self, evidence_ids: impl IntoIterator<Item = String>) -> Self {
        self.support.extend(evidence_ids);
        self
    }

    /// Adds contradictory evidence identifiers.
    #[must_use]
    pub fn contradicting(mut self, evidence_ids: impl IntoIterator<Item = String>) -> Self {
        self.contradiction.extend(evidence_ids);
        self
    }

    /// Adds observation identifiers used by the edge.
    #[must_use]
    pub fn from_observations(mut self, observation_ids: impl IntoIterator<Item = String>) -> Self {
        self.observations.extend(observation_ids);
        self
    }

    /// Source identifier.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Provenance timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// Method that produced the edge.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Supporting evidence identifiers.
    #[must_use]
    pub fn support(&self) -> &[EvidenceId] {
        &self.support
    }

    /// Contradictory evidence identifiers.
    #[must_use]
    pub fn contradiction(&self) -> &[EvidenceId] {
        &self.contradiction
    }

    /// Observation identifiers in the edge provenance.
    #[must_use]
    pub fn observations(&self) -> &[ObservationId] {
        &self.observations
    }
}

/// A relationship between two public records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationship {
    id: RelationshipId,
    subject: RecordId,
    predicate: String,
    object: RecordId,
    edge_type: EdgeType,
    provenance: RelationshipProvenance,
    confidence: Confidence,
}

impl Relationship {
    /// Creates a relationship with zero confidence.
    pub fn new(
        id: impl Into<String>,
        subject: impl Into<String>,
        predicate: impl Into<String>,
        object: impl Into<String>,
        edge_type: EdgeType,
        provenance: RelationshipProvenance,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "relationship id")?,
            subject: require_text(subject.into(), "relationship subject")?,
            predicate: require_text(predicate.into(), "relationship predicate")?,
            object: require_text(object.into(), "relationship object")?,
            edge_type,
            provenance,
            confidence: Confidence::new(0),
        })
    }

    /// Sets the relationship confidence.
    #[must_use]
    pub const fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Stable relationship identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Subject record identifier.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Relationship predicate.
    #[must_use]
    pub fn predicate(&self) -> &str {
        &self.predicate
    }

    /// Object record identifier.
    #[must_use]
    pub fn object(&self) -> &str {
        &self.object
    }

    /// Edge classification.
    #[must_use]
    pub const fn edge_type(&self) -> EdgeType {
        self.edge_type
    }

    /// Full relationship provenance.
    #[must_use]
    pub const fn provenance(&self) -> &RelationshipProvenance {
        &self.provenance
    }

    /// Relationship confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }
}

/// Competing-hypothesis role.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HypothesisKind {
    /// Null or ordinary explanation.
    Null,
    /// A leading explanation.
    Leading,
    /// A competing alternative explanation.
    Alternative,
    /// An application-specific hypothesis role.
    Other(String),
}

/// A competing explanation for a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hypothesis {
    id: HypothesisId,
    label: String,
    kind: HypothesisKind,
}

impl Hypothesis {
    /// Creates a hypothesis.
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        kind: HypothesisKind,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "hypothesis id")?,
            label: require_text(label.into(), "hypothesis label")?,
            kind,
        })
    }

    /// Stable hypothesis identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Hypothesis label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Hypothesis role.
    #[must_use]
    pub const fn kind(&self) -> &HypothesisKind {
        &self.kind
    }
}

/// A claim attached to one competing hypothesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    id: ClaimId,
    statement: String,
    hypothesis: HypothesisId,
    confidence: Confidence,
}

impl Claim {
    /// Creates a claim with zero confidence.
    pub fn new(
        id: impl Into<String>,
        statement: impl Into<String>,
        hypothesis: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "claim id")?,
            statement: require_text(statement.into(), "claim statement")?,
            hypothesis: require_text(hypothesis.into(), "claim hypothesis")?,
            confidence: Confidence::new(0),
        })
    }

    /// Sets the claim confidence.
    #[must_use]
    pub const fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Stable claim identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Claim statement.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Hypothesis explaining the claim.
    #[must_use]
    pub fn hypothesis(&self) -> &str {
        &self.hypothesis
    }

    /// Claim confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }
}

/// How an observation bears on a hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceRole {
    /// Observation supports the hypothesis.
    Supporting,
    /// Observation contradicts the hypothesis.
    Contradicting,
    /// Observation is relevant context without a directional weight.
    Contextual,
}

/// One explicit link from a hypothesis to a directly observed fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    id: EvidenceId,
    hypothesis: HypothesisId,
    observation: ObservationId,
    role: EvidenceRole,
    rationale: Option<String>,
}

impl Evidence {
    /// Creates an evidence link.
    pub fn new(
        id: impl Into<String>,
        hypothesis: impl Into<String>,
        observation: impl Into<String>,
        role: EvidenceRole,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "evidence id")?,
            hypothesis: require_text(hypothesis.into(), "evidence hypothesis")?,
            observation: require_text(observation.into(), "evidence observation")?,
            role,
            rationale: None,
        })
    }

    /// Adds a rationale without replacing the linked observation.
    #[must_use]
    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = Some(rationale.into());
        self
    }

    /// Stable evidence identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Hypothesis supported or contradicted by this evidence.
    #[must_use]
    pub fn hypothesis(&self) -> &str {
        &self.hypothesis
    }

    /// Direct observation linked by this evidence.
    #[must_use]
    pub fn observation(&self) -> &str {
        &self.observation
    }

    /// Directional role.
    #[must_use]
    pub const fn role(&self) -> EvidenceRole {
        self.role
    }

    /// Optional rationale.
    #[must_use]
    pub fn rationale(&self) -> Option<&str> {
        self.rationale.as_deref()
    }
}

/// Test family used to verify a transformation or evidence claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TestType {
    /// A direct behavioral verification.
    Verification,
    /// A baseline-versus-variant comparison.
    Differential,
    /// A relation-preserving metamorphic test.
    Metamorphic,
    /// A provenance consistency test.
    Provenance,
    /// An application-specific test family.
    Other(String),
}

/// Result of executing a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    /// Test has not run.
    Pending,
    /// Test passed.
    Passed,
    /// Test failed.
    Failed,
    /// Test was unable to establish a result.
    Inconclusive,
}

/// A recorded verification or falsification test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Test {
    id: TestId,
    name: String,
    kind: TestType,
    status: TestStatus,
    executed_at: Option<Timestamp>,
    input_observations: Vec<ObservationId>,
    output_observations: Vec<ObservationId>,
}

impl Test {
    /// Creates a pending test.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        kind: TestType,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "test id")?,
            name: require_text(name.into(), "test name")?,
            kind,
            status: TestStatus::Pending,
            executed_at: None,
            input_observations: Vec::new(),
            output_observations: Vec::new(),
        })
    }

    /// Records a test result and execution time.
    #[must_use]
    pub const fn completed(mut self, status: TestStatus, executed_at: Timestamp) -> Self {
        self.status = status;
        self.executed_at = Some(executed_at);
        self
    }

    /// Adds input observation identifiers.
    #[must_use]
    pub fn with_inputs(mut self, observations: impl IntoIterator<Item = String>) -> Self {
        self.input_observations.extend(observations);
        self
    }

    /// Adds output observation identifiers.
    #[must_use]
    pub fn with_outputs(mut self, observations: impl IntoIterator<Item = String>) -> Self {
        self.output_observations.extend(observations);
        self
    }

    /// Stable test identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Test name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Test family.
    #[must_use]
    pub const fn kind(&self) -> &TestType {
        &self.kind
    }

    /// Test status.
    #[must_use]
    pub const fn status(&self) -> TestStatus {
        self.status
    }

    /// Test execution time, if executed.
    #[must_use]
    pub const fn executed_at(&self) -> Option<Timestamp> {
        self.executed_at
    }

    /// Input observation identifiers.
    #[must_use]
    pub fn input_observations(&self) -> &[ObservationId] {
        &self.input_observations
    }

    /// Output observation identifiers.
    #[must_use]
    pub fn output_observations(&self) -> &[ObservationId] {
        &self.output_observations
    }
}

/// Action lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionStatus {
    /// Proposed but not executed.
    Proposed,
    /// Currently executing.
    Running,
    /// Completed successfully.
    Succeeded,
    /// Completed unsuccessfully.
    Failed,
    /// Rejected before execution.
    Rejected,
}

/// Kind of follow-up action recorded by the workbench.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActionType {
    /// Retrieve additional public evidence.
    Retrieve,
    /// Run a verification test.
    Verify,
    /// Search for a contradiction.
    Falsify,
    /// Compare representations.
    Compare,
    /// Export a report or graph.
    Export,
    /// An application-specific action.
    Other(String),
}

/// A proposed or executed next action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    id: ActionId,
    kind: ActionType,
    description: String,
    status: ActionStatus,
    target: Option<RecordId>,
    created_at: Timestamp,
    evidence_ids: Vec<EvidenceId>,
}

impl Action {
    /// Creates a proposed action.
    pub fn new(
        id: impl Into<String>,
        kind: ActionType,
        description: impl Into<String>,
        created_at: Timestamp,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "action id")?,
            kind,
            description: require_text(description.into(), "action description")?,
            status: ActionStatus::Proposed,
            target: None,
            created_at,
            evidence_ids: Vec::new(),
        })
    }

    /// Associates an action with a target record.
    #[must_use]
    pub fn targeting(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Links evidence motivating the action.
    #[must_use]
    pub fn motivated_by(mut self, evidence_ids: impl IntoIterator<Item = String>) -> Self {
        self.evidence_ids.extend(evidence_ids);
        self
    }

    /// Updates the action lifecycle state.
    #[must_use]
    pub const fn with_status(mut self, status: ActionStatus) -> Self {
        self.status = status;
        self
    }

    /// Stable action identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Action kind.
    #[must_use]
    pub const fn kind(&self) -> &ActionType {
        &self.kind
    }

    /// Action description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Action lifecycle status.
    #[must_use]
    pub const fn status(&self) -> ActionStatus {
        self.status
    }

    /// Target record, if any.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Action creation time.
    #[must_use]
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Motivating evidence identifiers.
    #[must_use]
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }
}

/// Record type whose confidence was updated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfidenceTarget {
    /// A claim.
    Claim,
    /// A hypothesis.
    Hypothesis,
    /// A relationship.
    Relationship,
    /// An observation.
    Observation,
    /// An entity.
    Entity,
    /// An application-specific target type.
    Other(String),
}

/// A calibrated confidence change with its reason and evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidenceUpdate {
    id: ConfidenceUpdateId,
    target_type: ConfidenceTarget,
    target_id: RecordId,
    previous: Confidence,
    updated: Confidence,
    reason: String,
    evidence_ids: Vec<EvidenceId>,
    updated_at: Timestamp,
}

impl ConfidenceUpdate {
    /// Creates a confidence update.
    pub fn new(
        id: impl Into<String>,
        target_type: ConfidenceTarget,
        target_id: impl Into<String>,
        previous: Confidence,
        updated: Confidence,
        reason: impl Into<String>,
        updated_at: Timestamp,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: require_text(id.into(), "confidence update id")?,
            target_type,
            target_id: require_text(target_id.into(), "confidence target id")?,
            previous,
            updated,
            reason: require_text(reason.into(), "confidence update reason")?,
            evidence_ids: Vec::new(),
            updated_at,
        })
    }

    /// Links evidence that caused the confidence update.
    #[must_use]
    pub fn based_on(mut self, evidence_ids: impl IntoIterator<Item = String>) -> Self {
        self.evidence_ids.extend(evidence_ids);
        self
    }

    /// Stable update identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Updated record type.
    #[must_use]
    pub const fn target_type(&self) -> &ConfidenceTarget {
        &self.target_type
    }

    /// Updated record identifier.
    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Confidence before the update.
    #[must_use]
    pub const fn previous(&self) -> Confidence {
        self.previous
    }

    /// Confidence after the update.
    #[must_use]
    pub const fn updated(&self) -> Confidence {
        self.updated
    }

    /// Reason for the update.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Evidence identifiers supporting the update.
    #[must_use]
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }

    /// Update timestamp.
    #[must_use]
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
}

/// A resolved claim chain from a claim to its source observations.
#[derive(Debug)]
pub struct ClaimTrace<'a> {
    /// The traced claim.
    pub claim: &'a Claim,
    /// The competing hypothesis attached to the claim.
    pub hypothesis: &'a Hypothesis,
    /// Evidence links and their source observations.
    pub evidence: Vec<EvidenceTrace<'a>>,
}

/// One evidence link expanded through its observation and source.
#[derive(Debug)]
pub struct EvidenceTrace<'a> {
    /// Evidence link.
    pub evidence: &'a Evidence,
    /// Direct observation supporting the link.
    pub observation: &'a Observation,
    /// Source retained by the observation.
    pub source: &'a Source,
}

/// A resolved transformation chain from input to output.
#[derive(Debug)]
pub struct TransformationTrace<'a> {
    /// Transformation record.
    pub transformation: &'a Transformation,
    /// Input representation.
    pub input_representation: &'a Representation,
    /// Output representation.
    pub output_representation: &'a Representation,
    /// Preserved feature records.
    pub preserved_features: Vec<&'a Feature>,
    /// Changed feature records.
    pub changed_features: Vec<&'a Feature>,
    /// Tests attached to the verification record.
    pub verification_tests: Vec<&'a Test>,
}

/// Record collections of the store, used to journal insertions so a failed
/// transaction can remove exactly what it inserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordKind {
    Source,
    Entity,
    Artifact,
    Observation,
    Feature,
    Representation,
    Test,
    Transformation,
    Event,
    Hypothesis,
    Claim,
    Evidence,
    Relationship,
    Action,
    ConfidenceUpdate,
}

impl RecordKind {
    /// Collection name used in [`ProvenanceError::DuplicateId`].
    const fn collection_name(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Entity => "entity",
            Self::Artifact => "artifact",
            Self::Observation => "observation",
            Self::Feature => "feature",
            Self::Representation => "representation",
            Self::Test => "test",
            Self::Transformation => "transformation",
            Self::Event => "event",
            Self::Hypothesis => "hypothesis",
            Self::Claim => "claim",
            Self::Evidence => "evidence",
            Self::Relationship => "relationship",
            Self::Action => "action",
            Self::ConfidenceUpdate => "confidence update",
        }
    }
}

/// One reversible change recorded while a transaction is open.
#[derive(Debug, Clone)]
enum Undo {
    /// Remove the record inserted under `1` from collection `0`.
    Remove(RecordKind, String),
    /// Put back an observation that was replaced in place.
    RestoreObservation(Observation),
    /// Put back an artifact whose representation links were extended.
    RestoreArtifact(Artifact),
}

/// Rolls back and closes a transaction unless it was committed, so a panic
/// inside the closure leaves the store exactly as it was.
struct TransactionGuard<'a> {
    store: &'a mut EvidenceStore,
    mark: usize,
    committed: bool,
}

impl Drop for TransactionGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.store.rollback_to(self.mark);
        }
        self.store.end_transaction();
    }
}

/// The authoritative in-memory evidence and provenance state.
#[derive(Debug, Clone, Default)]
pub struct EvidenceStore {
    entities: BTreeMap<EntityId, Entity>,
    artifacts: BTreeMap<ArtifactId, Artifact>,
    observations: BTreeMap<ObservationId, Observation>,
    features: BTreeMap<FeatureId, Feature>,
    representations: BTreeMap<RepresentationId, Representation>,
    transformations: BTreeMap<TransformationId, Transformation>,
    sources: BTreeMap<SourceId, Source>,
    events: BTreeMap<EventId, Event>,
    relationships: BTreeMap<RelationshipId, Relationship>,
    hypotheses: BTreeMap<HypothesisId, Hypothesis>,
    claims: BTreeMap<ClaimId, Claim>,
    evidence: BTreeMap<EvidenceId, Evidence>,
    tests: BTreeMap<TestId, Test>,
    actions: BTreeMap<ActionId, Action>,
    confidence_updates: BTreeMap<ConfidenceUpdateId, ConfidenceUpdate>,
    /// Undo log, present only while at least one transaction is open.
    journal: Option<Vec<Undo>>,
    /// Number of nested open transactions.
    open_transactions: usize,
}

/// Alias emphasizing the core's canonical role.
pub type CanonicalEvidence = EvidenceStore;

/// Alias emphasizing the provenance responsibility of the store.
pub type ProvenanceCore = EvidenceStore;

impl EvidenceStore {
    /// Creates an empty authoritative store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entities: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            observations: BTreeMap::new(),
            features: BTreeMap::new(),
            representations: BTreeMap::new(),
            transformations: BTreeMap::new(),
            sources: BTreeMap::new(),
            events: BTreeMap::new(),
            relationships: BTreeMap::new(),
            hypotheses: BTreeMap::new(),
            claims: BTreeMap::new(),
            evidence: BTreeMap::new(),
            tests: BTreeMap::new(),
            actions: BTreeMap::new(),
            confidence_updates: BTreeMap::new(),
            journal: None,
            open_transactions: 0,
        }
    }

    /// Runs `operation` against the store and keeps its changes only if it
    /// returns `Ok`; on `Err` (or a panic) every insertion and in-place update
    /// the operation made is undone, in reverse order, before the error is
    /// returned.
    ///
    /// This is the store's single all-or-nothing mechanism: it journals each
    /// change while a transaction is open (an `O(1)` note per change) instead
    /// of requiring callers to clone the whole store, so a multi-record
    /// operation costs the same whether the store holds ten records or ten
    /// million. Transactions nest: an inner failure undoes only the inner
    /// changes, and an outer failure undoes everything since it began. The
    /// error type is the caller's; `?` on store operations converts
    /// [`ProvenanceError`] into it as usual.
    ///
    /// # Examples
    /// ```
    /// use bleradar_core::{Entity, EntityType, EvidenceStore, ProvenanceError};
    /// let mut store = EvidenceStore::new();
    /// let outcome: Result<(), ProvenanceError> = store.transaction(|store| {
    ///     store.add_entity(Entity::new("device-1", EntityType::Device)?)?;
    ///     // The duplicate fails the transaction, which also removes device-1.
    ///     store.add_entity(Entity::new("device-1", EntityType::Device)?)
    /// });
    /// assert!(outcome.is_err());
    /// assert!(store.entity("device-1").is_none());
    /// assert!(store.is_empty());
    /// ```
    pub fn transaction<T, E>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let mark = self.begin_transaction();
        let mut guard = TransactionGuard {
            store: self,
            mark,
            committed: false,
        };
        let result = operation(&mut *guard.store);
        guard.committed = result.is_ok();
        drop(guard);
        result
    }

    /// [`Self::transaction`] for an owner that holds the store as a field and
    /// whose operation needs the whole owner (an engine correlating through
    /// its own methods): `evidence` locates the store inside the owner.
    ///
    /// A panic inside `operation` is not part of the contract; every engine
    /// path returns a `Result`, so no unwind guard is used here.
    pub(crate) fn transaction_through<S, T, E>(
        owner: &mut S,
        evidence: impl Fn(&mut S) -> &mut Self,
        operation: impl FnOnce(&mut S) -> Result<T, E>,
    ) -> Result<T, E> {
        let mark = evidence(owner).begin_transaction();
        let result = operation(owner);
        if result.is_err() {
            evidence(owner).rollback_to(mark);
        }
        evidence(owner).end_transaction();
        result
    }

    /// Opens a (possibly nested) transaction and returns the journal position
    /// that [`Self::rollback_to`] undoes back to.
    pub(crate) fn begin_transaction(&mut self) -> usize {
        self.open_transactions += 1;
        self.journal.get_or_insert_with(Vec::new).len()
    }

    /// Closes the innermost open transaction, keeping its changes; when the
    /// last one closes the journal is released.
    pub(crate) fn end_transaction(&mut self) {
        self.open_transactions = self.open_transactions.saturating_sub(1);
        if self.open_transactions == 0 {
            self.journal = None;
        }
    }

    /// Undoes every journaled change made since `mark`, most recent first.
    pub(crate) fn rollback_to(&mut self, mark: usize) {
        let undo: Vec<Undo> = match self.journal.as_mut() {
            Some(journal) if journal.len() > mark => journal.drain(mark..).collect(),
            _ => return,
        };
        for entry in undo.into_iter().rev() {
            self.apply_undo(entry);
        }
    }

    fn apply_undo(&mut self, entry: Undo) {
        match entry {
            Undo::Remove(kind, id) => {
                match kind {
                    RecordKind::Entity => self.entities.remove(&id).is_some(),
                    RecordKind::Artifact => self.artifacts.remove(&id).is_some(),
                    RecordKind::Observation => self.observations.remove(&id).is_some(),
                    RecordKind::Feature => self.features.remove(&id).is_some(),
                    RecordKind::Representation => self.representations.remove(&id).is_some(),
                    RecordKind::Transformation => self.transformations.remove(&id).is_some(),
                    RecordKind::Source => self.sources.remove(&id).is_some(),
                    RecordKind::Event => self.events.remove(&id).is_some(),
                    RecordKind::Relationship => self.relationships.remove(&id).is_some(),
                    RecordKind::Hypothesis => self.hypotheses.remove(&id).is_some(),
                    RecordKind::Claim => self.claims.remove(&id).is_some(),
                    RecordKind::Evidence => self.evidence.remove(&id).is_some(),
                    RecordKind::Test => self.tests.remove(&id).is_some(),
                    RecordKind::Action => self.actions.remove(&id).is_some(),
                    RecordKind::ConfidenceUpdate => self.confidence_updates.remove(&id).is_some(),
                };
            }
            Undo::RestoreObservation(observation) => {
                self.observations
                    .insert(observation.id().to_owned(), observation);
            }
            Undo::RestoreArtifact(artifact) => {
                self.artifacts.insert(artifact.id().to_owned(), artifact);
            }
        }
    }

    /// Inserts a source.
    pub fn insert_source(&mut self, source: Source) -> Result<(), ProvenanceError> {
        let id = source.id().to_owned();
        insert_unique(
            &mut self.sources,
            &mut self.journal,
            RecordKind::Source,
            &id,
            source,
        )
    }

    /// Inserts an entity.
    pub fn insert_entity(&mut self, entity: Entity) -> Result<(), ProvenanceError> {
        let id = entity.id().to_owned();
        insert_unique(
            &mut self.entities,
            &mut self.journal,
            RecordKind::Entity,
            &id,
            entity,
        )
    }

    /// Inserts an artifact and checks its optional references.
    pub fn insert_artifact(&mut self, artifact: Artifact) -> Result<(), ProvenanceError> {
        if let Some(entity_id) = artifact.entity_id() {
            require_ref(
                &self.entities,
                "artifact",
                artifact.id(),
                "entity",
                entity_id,
            )?;
        }
        if let Some(source_id) = artifact.source_id() {
            require_ref(
                &self.sources,
                "artifact",
                artifact.id(),
                "source",
                source_id,
            )?;
        }
        let id = artifact.id().to_owned();
        insert_unique(
            &mut self.artifacts,
            &mut self.journal,
            RecordKind::Artifact,
            &id,
            artifact,
        )
    }

    /// Inserts an observation and verifies that its source metadata is copied
    /// consistently from the authoritative source record.
    pub fn insert_observation(&mut self, observation: Observation) -> Result<(), ProvenanceError> {
        let source = self.sources.get(observation.source()).ok_or_else(|| {
            ProvenanceError::MissingReference {
                record: "observation",
                record_id: observation.id().to_owned(),
                field: "source",
                reference: observation.source().to_owned(),
            }
        })?;
        if source.source_type() != observation.source_type()
            || source.retrieval_method() != observation.retrieval_method()
        {
            return Err(ProvenanceError::SourceMetadataMismatch {
                observation_id: observation.id().to_owned(),
                source_id: observation.source().to_owned(),
            });
        }
        for transformation_id in observation.derivation_history() {
            require_ref(
                &self.transformations,
                "observation",
                observation.id(),
                "derivation",
                transformation_id,
            )?;
        }
        let id = observation.id().to_owned();
        insert_unique(
            &mut self.observations,
            &mut self.journal,
            RecordKind::Observation,
            &id,
            observation,
        )
    }

    /// Extends a stored observation's last-seen time without replacing its evidence.
    ///
    /// # Errors
    /// Returns [`ProvenanceError::MissingReference`] when `observation_id` is
    /// unknown, or [`ProvenanceError::InvalidTimeline`] when `timestamp`
    /// precedes the current last-seen time. The store is unchanged on failure.
    pub fn record_observation_seen_at(
        &mut self,
        observation_id: &str,
        timestamp: Timestamp,
    ) -> Result<(), ProvenanceError> {
        let current = self.observations.get(observation_id).ok_or_else(|| {
            ProvenanceError::MissingReference {
                record: "observation update",
                record_id: observation_id.to_owned(),
                field: "observation",
                reference: observation_id.to_owned(),
            }
        })?;
        let updated = current.seen_at(timestamp)?;
        if let Some(journal) = self.journal.as_mut() {
            journal.push(Undo::RestoreObservation(current.clone()));
        }
        self.observations.insert(observation_id.to_owned(), updated);
        Ok(())
    }

    /// Inserts a feature and checks its optional observation and feature links.
    pub fn insert_feature(&mut self, feature: Feature) -> Result<(), ProvenanceError> {
        if let Some(observation_id) = feature.source_observation() {
            require_ref(
                &self.observations,
                "feature",
                feature.id(),
                "source observation",
                observation_id,
            )?;
            if let Some(created_at) = feature.created_at_value() {
                let observation = self
                    .observations
                    .get(observation_id)
                    .expect("feature observation reference was validated above");
                if created_at < observation.observed_at() {
                    return Err(ProvenanceError::TemporalViolation {
                        record: "feature",
                        record_id: feature.id().to_owned(),
                        reference: observation.id().to_owned(),
                        record_time: created_at,
                        reference_time: observation.observed_at(),
                    });
                }
            }
        }
        for feature_id in feature.derived_feature_ids() {
            require_ref(
                &self.features,
                "feature",
                feature.id(),
                "derived feature",
                feature_id,
            )?;
            if let (Some(created_at), Some(dependency)) =
                (feature.created_at_value(), self.features.get(feature_id))
                && let Some(dependency_created_at) = dependency.created_at_value()
                && created_at < dependency_created_at
            {
                return Err(ProvenanceError::TemporalViolation {
                    record: "feature",
                    record_id: feature.id().to_owned(),
                    reference: dependency.id().to_owned(),
                    record_time: created_at,
                    reference_time: dependency_created_at,
                });
            }
        }
        let id = feature.id().to_owned();
        insert_unique(
            &mut self.features,
            &mut self.journal,
            RecordKind::Feature,
            &id,
            feature,
        )
    }

    /// Inserts a representation and verifies its artifact, source, and feature links.
    pub fn insert_representation(
        &mut self,
        representation: Representation,
    ) -> Result<(), ProvenanceError> {
        require_ref(
            &self.artifacts,
            "representation",
            representation.id(),
            "artifact",
            representation.artifact(),
        )?;
        if let Some(source_id) = representation.source() {
            require_ref(
                &self.sources,
                "representation",
                representation.id(),
                "source",
                source_id,
            )?;
        }
        for feature_id in representation.feature_ids() {
            require_ref(
                &self.features,
                "representation",
                representation.id(),
                "feature",
                feature_id,
            )?;
        }
        let id = representation.id().to_owned();
        let artifact_id = representation.artifact().to_owned();
        insert_unique(
            &mut self.representations,
            &mut self.journal,
            RecordKind::Representation,
            &id,
            representation,
        )?;
        let artifact = self
            .artifacts
            .get_mut(&artifact_id)
            .expect("artifact reference was validated above");
        if !artifact.representation_ids.contains(&id) {
            if let Some(journal) = self.journal.as_mut() {
                journal.push(Undo::RestoreArtifact(artifact.clone()));
            }
            artifact.representation_ids.push(id);
        }
        Ok(())
    }

    /// Inserts a test and verifies its observation inputs and outputs.
    pub fn insert_test(&mut self, test: Test) -> Result<(), ProvenanceError> {
        for observation_id in test.input_observations() {
            require_ref(
                &self.observations,
                "test",
                test.id(),
                "input observation",
                observation_id,
            )?;
        }
        for observation_id in test.output_observations() {
            require_ref(
                &self.observations,
                "test",
                test.id(),
                "output observation",
                observation_id,
            )?;
        }
        let id = test.id().to_owned();
        insert_unique(
            &mut self.tests,
            &mut self.journal,
            RecordKind::Test,
            &id,
            test,
        )
    }

    /// Inserts a transformation and verifies its complete transformation path.
    pub fn insert_transformation(
        &mut self,
        transformation: Transformation,
    ) -> Result<(), ProvenanceError> {
        require_ref(
            &self.representations,
            "transformation",
            transformation.id(),
            "input representation",
            transformation.input_representation(),
        )?;
        require_ref(
            &self.representations,
            "transformation",
            transformation.id(),
            "output representation",
            transformation.output_representation(),
        )?;
        for feature_id in transformation
            .preserved_features()
            .iter()
            .chain(transformation.changed_features())
        {
            require_ref(
                &self.features,
                "transformation",
                transformation.id(),
                "feature",
                feature_id,
            )?;
        }
        if transformation.verification().status() != VerificationStatus::Unverified
            && transformation.verification().test_ids().is_empty()
        {
            return Err(ProvenanceError::MissingVerification {
                transformation_id: transformation.id().to_owned(),
            });
        }
        for test_id in transformation.verification().test_ids() {
            require_ref(
                &self.tests,
                "transformation",
                transformation.id(),
                "verification test",
                test_id,
            )?;
        }
        let id = transformation.id().to_owned();
        insert_unique(
            &mut self.transformations,
            &mut self.journal,
            RecordKind::Transformation,
            &id,
            transformation,
        )
    }

    /// Inserts an event and verifies its entity and source links.
    pub fn insert_event(&mut self, event: Event) -> Result<(), ProvenanceError> {
        for entity_id in event.entity_ids() {
            require_ref(&self.entities, "event", event.id(), "entity", entity_id)?;
        }
        if let Some(source_id) = event.source() {
            require_ref(&self.sources, "event", event.id(), "source", source_id)?;
        }
        let id = event.id().to_owned();
        insert_unique(
            &mut self.events,
            &mut self.journal,
            RecordKind::Event,
            &id,
            event,
        )
    }

    /// Inserts a hypothesis.
    pub fn insert_hypothesis(&mut self, hypothesis: Hypothesis) -> Result<(), ProvenanceError> {
        let id = hypothesis.id().to_owned();
        insert_unique(
            &mut self.hypotheses,
            &mut self.journal,
            RecordKind::Hypothesis,
            &id,
            hypothesis,
        )
    }

    /// Inserts a claim after verifying its hypothesis.
    pub fn insert_claim(&mut self, claim: Claim) -> Result<(), ProvenanceError> {
        require_ref(
            &self.hypotheses,
            "claim",
            claim.id(),
            "hypothesis",
            claim.hypothesis(),
        )?;
        let id = claim.id().to_owned();
        insert_unique(
            &mut self.claims,
            &mut self.journal,
            RecordKind::Claim,
            &id,
            claim,
        )
    }

    /// Inserts evidence after verifying its hypothesis and direct observation.
    pub fn insert_evidence(&mut self, evidence: Evidence) -> Result<(), ProvenanceError> {
        require_ref(
            &self.hypotheses,
            "evidence",
            evidence.id(),
            "hypothesis",
            evidence.hypothesis(),
        )?;
        require_ref(
            &self.observations,
            "evidence",
            evidence.id(),
            "observation",
            evidence.observation(),
        )?;
        let id = evidence.id().to_owned();
        insert_unique(
            &mut self.evidence,
            &mut self.journal,
            RecordKind::Evidence,
            &id,
            evidence,
        )
    }

    /// Inserts a relationship after verifying all explicit evidence provenance.
    pub fn insert_relationship(
        &mut self,
        relationship: Relationship,
    ) -> Result<(), ProvenanceError> {
        if !self.contains_record(relationship.subject()) {
            return Err(ProvenanceError::MissingReference {
                record: "relationship",
                record_id: relationship.id().to_owned(),
                field: "subject",
                reference: relationship.subject().to_owned(),
            });
        }
        if !self.contains_record(relationship.object()) {
            return Err(ProvenanceError::MissingReference {
                record: "relationship",
                record_id: relationship.id().to_owned(),
                field: "object",
                reference: relationship.object().to_owned(),
            });
        }
        require_ref(
            &self.sources,
            "relationship",
            relationship.id(),
            "source",
            relationship.provenance().source(),
        )?;
        for evidence_id in relationship
            .provenance()
            .support()
            .iter()
            .chain(relationship.provenance().contradiction())
        {
            require_ref(
                &self.evidence,
                "relationship",
                relationship.id(),
                "evidence",
                evidence_id,
            )?;
        }
        for observation_id in relationship.provenance().observations() {
            require_ref(
                &self.observations,
                "relationship",
                relationship.id(),
                "observation",
                observation_id,
            )?;
        }
        let id = relationship.id().to_owned();
        insert_unique(
            &mut self.relationships,
            &mut self.journal,
            RecordKind::Relationship,
            &id,
            relationship,
        )
    }

    /// Inserts an action after verifying its motivating evidence.
    pub fn insert_action(&mut self, action: Action) -> Result<(), ProvenanceError> {
        for evidence_id in action.evidence_ids() {
            require_ref(
                &self.evidence,
                "action",
                action.id(),
                "evidence",
                evidence_id,
            )?;
        }
        let id = action.id().to_owned();
        insert_unique(
            &mut self.actions,
            &mut self.journal,
            RecordKind::Action,
            &id,
            action,
        )
    }

    /// Inserts a confidence update after verifying its target and evidence.
    pub fn insert_confidence_update(
        &mut self,
        update: ConfidenceUpdate,
    ) -> Result<(), ProvenanceError> {
        self.require_confidence_target(&update)?;
        for evidence_id in update.evidence_ids() {
            require_ref(
                &self.evidence,
                "confidence update",
                update.id(),
                "evidence",
                evidence_id,
            )?;
        }
        let id = update.id().to_owned();
        insert_unique(
            &mut self.confidence_updates,
            &mut self.journal,
            RecordKind::ConfidenceUpdate,
            &id,
            update,
        )
    }

    /// Convenience alias for [`EvidenceStore::insert_source`].
    pub fn add_source(&mut self, source: Source) -> Result<(), ProvenanceError> {
        self.insert_source(source)
    }

    /// Convenience alias for [`EvidenceStore::insert_entity`].
    pub fn add_entity(&mut self, entity: Entity) -> Result<(), ProvenanceError> {
        self.insert_entity(entity)
    }

    /// Convenience alias for [`EvidenceStore::insert_artifact`].
    pub fn add_artifact(&mut self, artifact: Artifact) -> Result<(), ProvenanceError> {
        self.insert_artifact(artifact)
    }

    /// Convenience alias for [`EvidenceStore::insert_observation`].
    pub fn add_observation(&mut self, observation: Observation) -> Result<(), ProvenanceError> {
        self.insert_observation(observation)
    }

    /// Convenience alias for [`EvidenceStore::insert_feature`].
    pub fn add_feature(&mut self, feature: Feature) -> Result<(), ProvenanceError> {
        self.insert_feature(feature)
    }

    /// Convenience alias for [`EvidenceStore::insert_representation`].
    pub fn add_representation(
        &mut self,
        representation: Representation,
    ) -> Result<(), ProvenanceError> {
        self.insert_representation(representation)
    }

    /// Convenience alias for [`EvidenceStore::insert_transformation`].
    pub fn add_transformation(
        &mut self,
        transformation: Transformation,
    ) -> Result<(), ProvenanceError> {
        self.insert_transformation(transformation)
    }

    /// Convenience alias for [`EvidenceStore::insert_event`].
    pub fn add_event(&mut self, event: Event) -> Result<(), ProvenanceError> {
        self.insert_event(event)
    }

    /// Convenience alias for [`EvidenceStore::insert_relationship`].
    pub fn add_relationship(&mut self, relationship: Relationship) -> Result<(), ProvenanceError> {
        self.insert_relationship(relationship)
    }

    /// Convenience alias for [`EvidenceStore::insert_hypothesis`].
    pub fn add_hypothesis(&mut self, hypothesis: Hypothesis) -> Result<(), ProvenanceError> {
        self.insert_hypothesis(hypothesis)
    }

    /// Convenience alias for [`EvidenceStore::insert_claim`].
    pub fn add_claim(&mut self, claim: Claim) -> Result<(), ProvenanceError> {
        self.insert_claim(claim)
    }

    /// Convenience alias for [`EvidenceStore::insert_evidence`].
    pub fn add_evidence(&mut self, evidence: Evidence) -> Result<(), ProvenanceError> {
        self.insert_evidence(evidence)
    }

    /// Convenience alias for [`EvidenceStore::insert_test`].
    pub fn add_test(&mut self, test: Test) -> Result<(), ProvenanceError> {
        self.insert_test(test)
    }

    /// Convenience alias for [`EvidenceStore::insert_action`].
    pub fn add_action(&mut self, action: Action) -> Result<(), ProvenanceError> {
        self.insert_action(action)
    }

    /// Convenience alias for [`EvidenceStore::insert_confidence_update`].
    pub fn add_confidence_update(
        &mut self,
        update: ConfidenceUpdate,
    ) -> Result<(), ProvenanceError> {
        self.insert_confidence_update(update)
    }

    fn require_confidence_target(&self, update: &ConfidenceUpdate) -> Result<(), ProvenanceError> {
        let target_exists = match update.target_type() {
            ConfidenceTarget::Claim => self.claims.contains_key(update.target_id()),
            ConfidenceTarget::Hypothesis => self.hypotheses.contains_key(update.target_id()),
            ConfidenceTarget::Relationship => self.relationships.contains_key(update.target_id()),
            ConfidenceTarget::Observation => self.observations.contains_key(update.target_id()),
            ConfidenceTarget::Entity => self.entities.contains_key(update.target_id()),
            ConfidenceTarget::Other(_) => true,
        };
        if target_exists {
            Ok(())
        } else {
            Err(ProvenanceError::MissingReference {
                record: "confidence update",
                record_id: update.id().to_owned(),
                field: "target",
                reference: update.target_id().to_owned(),
            })
        }
    }

    fn contains_record(&self, id: &str) -> bool {
        self.entities.contains_key(id)
            || self.artifacts.contains_key(id)
            || self.observations.contains_key(id)
            || self.features.contains_key(id)
            || self.representations.contains_key(id)
            || self.transformations.contains_key(id)
            || self.sources.contains_key(id)
            || self.events.contains_key(id)
            || self.relationships.contains_key(id)
            || self.hypotheses.contains_key(id)
            || self.claims.contains_key(id)
            || self.evidence.contains_key(id)
            || self.tests.contains_key(id)
            || self.actions.contains_key(id)
            || self.confidence_updates.contains_key(id)
    }

    /// Validates every stored cross-reference and provenance invariant.
    pub fn validate(&self) -> Result<(), ProvenanceError> {
        for observation in self.observations.values() {
            let source = self.sources.get(observation.source()).ok_or_else(|| {
                ProvenanceError::MissingReference {
                    record: "observation",
                    record_id: observation.id().to_owned(),
                    field: "source",
                    reference: observation.source().to_owned(),
                }
            })?;
            if source.source_type() != observation.source_type()
                || source.retrieval_method() != observation.retrieval_method()
            {
                return Err(ProvenanceError::SourceMetadataMismatch {
                    observation_id: observation.id().to_owned(),
                    source_id: observation.source().to_owned(),
                });
            }
            for transformation_id in observation.derivation_history() {
                require_ref(
                    &self.transformations,
                    "observation",
                    observation.id(),
                    "derivation",
                    transformation_id,
                )?;
            }
        }

        for artifact in self.artifacts.values() {
            if let Some(entity_id) = artifact.entity_id() {
                require_ref(
                    &self.entities,
                    "artifact",
                    artifact.id(),
                    "entity",
                    entity_id,
                )?;
            }
            if let Some(source_id) = artifact.source_id() {
                require_ref(
                    &self.sources,
                    "artifact",
                    artifact.id(),
                    "source",
                    source_id,
                )?;
            }
            for representation_id in artifact.representation_ids() {
                require_ref(
                    &self.representations,
                    "artifact",
                    artifact.id(),
                    "representation",
                    representation_id,
                )?;
            }
        }

        for feature in self.features.values() {
            if let Some(observation_id) = feature.source_observation() {
                require_ref(
                    &self.observations,
                    "feature",
                    feature.id(),
                    "source observation",
                    observation_id,
                )?;
                if let Some(created_at) = feature.created_at_value() {
                    let observation = self
                        .observations
                        .get(observation_id)
                        .expect("feature observation reference was validated above");
                    if created_at < observation.observed_at() {
                        return Err(ProvenanceError::TemporalViolation {
                            record: "feature",
                            record_id: feature.id().to_owned(),
                            reference: observation.id().to_owned(),
                            record_time: created_at,
                            reference_time: observation.observed_at(),
                        });
                    }
                }
            }
            for feature_id in feature.derived_feature_ids() {
                require_ref(
                    &self.features,
                    "feature",
                    feature.id(),
                    "derived feature",
                    feature_id,
                )?;
                if let (Some(created_at), Some(dependency)) =
                    (feature.created_at_value(), self.features.get(feature_id))
                    && let Some(dependency_created_at) = dependency.created_at_value()
                    && created_at < dependency_created_at
                {
                    return Err(ProvenanceError::TemporalViolation {
                        record: "feature",
                        record_id: feature.id().to_owned(),
                        reference: dependency.id().to_owned(),
                        record_time: created_at,
                        reference_time: dependency_created_at,
                    });
                }
            }
        }

        for representation in self.representations.values() {
            require_ref(
                &self.artifacts,
                "representation",
                representation.id(),
                "artifact",
                representation.artifact(),
            )?;
            if let Some(source_id) = representation.source() {
                require_ref(
                    &self.sources,
                    "representation",
                    representation.id(),
                    "source",
                    source_id,
                )?;
            }
            for feature_id in representation.feature_ids() {
                require_ref(
                    &self.features,
                    "representation",
                    representation.id(),
                    "feature",
                    feature_id,
                )?;
            }
        }

        for test in self.tests.values() {
            for observation_id in test
                .input_observations()
                .iter()
                .chain(test.output_observations())
            {
                require_ref(
                    &self.observations,
                    "test",
                    test.id(),
                    "observation",
                    observation_id,
                )?;
            }
        }

        for transformation in self.transformations.values() {
            require_ref(
                &self.representations,
                "transformation",
                transformation.id(),
                "input representation",
                transformation.input_representation(),
            )?;
            require_ref(
                &self.representations,
                "transformation",
                transformation.id(),
                "output representation",
                transformation.output_representation(),
            )?;
            let changed: BTreeSet<_> = transformation.changed_features().iter().collect();
            for feature_id in transformation.preserved_features() {
                if changed.contains(feature_id) {
                    return Err(ProvenanceError::FeatureInBothSets {
                        transformation_id: transformation.id().to_owned(),
                        feature_id: feature_id.clone(),
                    });
                }
            }
            for feature_id in transformation
                .preserved_features()
                .iter()
                .chain(transformation.changed_features())
            {
                require_ref(
                    &self.features,
                    "transformation",
                    transformation.id(),
                    "feature",
                    feature_id,
                )?;
            }
            if transformation.verification().status() != VerificationStatus::Unverified
                && transformation.verification().test_ids().is_empty()
            {
                return Err(ProvenanceError::MissingVerification {
                    transformation_id: transformation.id().to_owned(),
                });
            }
            for test_id in transformation.verification().test_ids() {
                require_ref(
                    &self.tests,
                    "transformation",
                    transformation.id(),
                    "verification test",
                    test_id,
                )?;
            }
        }

        for event in self.events.values() {
            for entity_id in event.entity_ids() {
                require_ref(&self.entities, "event", event.id(), "entity", entity_id)?;
            }
            if let Some(source_id) = event.source() {
                require_ref(&self.sources, "event", event.id(), "source", source_id)?;
            }
        }

        for claim in self.claims.values() {
            require_ref(
                &self.hypotheses,
                "claim",
                claim.id(),
                "hypothesis",
                claim.hypothesis(),
            )?;
            if !self
                .evidence
                .values()
                .any(|evidence| evidence.hypothesis() == claim.hypothesis())
            {
                return Err(ProvenanceError::ClaimWithoutEvidence {
                    claim_id: claim.id().to_owned(),
                });
            }
        }

        for evidence in self.evidence.values() {
            require_ref(
                &self.hypotheses,
                "evidence",
                evidence.id(),
                "hypothesis",
                evidence.hypothesis(),
            )?;
            require_ref(
                &self.observations,
                "evidence",
                evidence.id(),
                "observation",
                evidence.observation(),
            )?;
        }

        for relationship in self.relationships.values() {
            if !self.contains_record(relationship.subject()) {
                return Err(ProvenanceError::MissingReference {
                    record: "relationship",
                    record_id: relationship.id().to_owned(),
                    field: "subject",
                    reference: relationship.subject().to_owned(),
                });
            }
            if !self.contains_record(relationship.object()) {
                return Err(ProvenanceError::MissingReference {
                    record: "relationship",
                    record_id: relationship.id().to_owned(),
                    field: "object",
                    reference: relationship.object().to_owned(),
                });
            }
            require_ref(
                &self.sources,
                "relationship",
                relationship.id(),
                "source",
                relationship.provenance().source(),
            )?;
            for evidence_id in relationship
                .provenance()
                .support()
                .iter()
                .chain(relationship.provenance().contradiction())
            {
                require_ref(
                    &self.evidence,
                    "relationship",
                    relationship.id(),
                    "evidence",
                    evidence_id,
                )?;
            }
            for observation_id in relationship.provenance().observations() {
                require_ref(
                    &self.observations,
                    "relationship",
                    relationship.id(),
                    "observation",
                    observation_id,
                )?;
            }
        }

        for action in self.actions.values() {
            for evidence_id in action.evidence_ids() {
                require_ref(
                    &self.evidence,
                    "action",
                    action.id(),
                    "evidence",
                    evidence_id,
                )?;
            }
        }

        for update in self.confidence_updates.values() {
            self.require_confidence_target(update)?;
            for evidence_id in update.evidence_ids() {
                require_ref(
                    &self.evidence,
                    "confidence update",
                    update.id(),
                    "evidence",
                    evidence_id,
                )?;
            }
        }

        Ok(())
    }

    /// Traces `claim → hypothesis → evidence → observation → source`.
    pub fn trace_claim(&self, claim_id: &str) -> Result<ClaimTrace<'_>, ProvenanceError> {
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| ProvenanceError::MissingReference {
                record: "claim trace",
                record_id: claim_id.to_owned(),
                field: "claim",
                reference: claim_id.to_owned(),
            })?;
        let hypothesis = self.hypotheses.get(claim.hypothesis()).ok_or_else(|| {
            ProvenanceError::MissingReference {
                record: "claim",
                record_id: claim.id().to_owned(),
                field: "hypothesis",
                reference: claim.hypothesis().to_owned(),
            }
        })?;
        let mut evidence = Vec::new();
        for link in self
            .evidence
            .values()
            .filter(|link| link.hypothesis() == hypothesis.id())
        {
            let observation = self.observations.get(link.observation()).ok_or_else(|| {
                ProvenanceError::MissingReference {
                    record: "evidence",
                    record_id: link.id().to_owned(),
                    field: "observation",
                    reference: link.observation().to_owned(),
                }
            })?;
            let source = self.sources.get(observation.source()).ok_or_else(|| {
                ProvenanceError::MissingReference {
                    record: "observation",
                    record_id: observation.id().to_owned(),
                    field: "source",
                    reference: observation.source().to_owned(),
                }
            })?;
            evidence.push(EvidenceTrace {
                evidence: link,
                observation,
                source,
            });
        }
        if evidence.is_empty() {
            return Err(ProvenanceError::ClaimWithoutEvidence {
                claim_id: claim.id().to_owned(),
            });
        }
        Ok(ClaimTrace {
            claim,
            hypothesis,
            evidence,
        })
    }

    /// Traces a transformation through its representations, features, and tests.
    pub fn trace_transformation(
        &self,
        transformation_id: &str,
    ) -> Result<TransformationTrace<'_>, ProvenanceError> {
        let transformation = self.transformations.get(transformation_id).ok_or_else(|| {
            ProvenanceError::MissingReference {
                record: "transformation trace",
                record_id: transformation_id.to_owned(),
                field: "transformation",
                reference: transformation_id.to_owned(),
            }
        })?;
        let input_representation = self
            .representations
            .get(transformation.input_representation())
            .ok_or_else(|| ProvenanceError::MissingReference {
                record: "transformation",
                record_id: transformation.id().to_owned(),
                field: "input representation",
                reference: transformation.input_representation().to_owned(),
            })?;
        let output_representation = self
            .representations
            .get(transformation.output_representation())
            .ok_or_else(|| ProvenanceError::MissingReference {
                record: "transformation",
                record_id: transformation.id().to_owned(),
                field: "output representation",
                reference: transformation.output_representation().to_owned(),
            })?;
        let preserved_features = transformation
            .preserved_features()
            .iter()
            .map(|feature_id| {
                self.features
                    .get(feature_id)
                    .ok_or_else(|| ProvenanceError::MissingReference {
                        record: "transformation",
                        record_id: transformation.id().to_owned(),
                        field: "preserved feature",
                        reference: feature_id.clone(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let changed_features = transformation
            .changed_features()
            .iter()
            .map(|feature_id| {
                self.features
                    .get(feature_id)
                    .ok_or_else(|| ProvenanceError::MissingReference {
                        record: "transformation",
                        record_id: transformation.id().to_owned(),
                        field: "changed feature",
                        reference: feature_id.clone(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let verification_tests = transformation
            .verification()
            .test_ids()
            .iter()
            .map(|test_id| {
                self.tests
                    .get(test_id)
                    .ok_or_else(|| ProvenanceError::MissingReference {
                        record: "transformation",
                        record_id: transformation.id().to_owned(),
                        field: "verification test",
                        reference: test_id.clone(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TransformationTrace {
            transformation,
            input_representation,
            output_representation,
            preserved_features,
            changed_features,
            verification_tests,
        })
    }

    /// Returns the source with the given identifier.
    #[must_use]
    pub fn source(&self, id: &str) -> Option<&Source> {
        self.sources.get(id)
    }

    /// Returns the entity with the given identifier.
    #[must_use]
    pub fn entity(&self, id: &str) -> Option<&Entity> {
        self.entities.get(id)
    }

    /// Returns the artifact with the given identifier.
    #[must_use]
    pub fn artifact(&self, id: &str) -> Option<&Artifact> {
        self.artifacts.get(id)
    }

    /// Returns the observation with the given identifier.
    #[must_use]
    pub fn observation(&self, id: &str) -> Option<&Observation> {
        self.observations.get(id)
    }

    /// Returns observations whose source identifier matches `source_id`.
    #[must_use]
    pub fn observations_by_source(&self, source_id: &str) -> Vec<&Observation> {
        self.observations
            .values()
            .filter(|observation| observation.source() == source_id)
            .collect()
    }

    /// Returns observations whose seen interval overlaps an inclusive window.
    #[must_use]
    pub fn observations_in_window(
        &self,
        first_seen: Timestamp,
        last_seen: Timestamp,
    ) -> Vec<&Observation> {
        self.observations
            .values()
            .filter(|observation| {
                observation.last_seen() >= first_seen && observation.first_seen() <= last_seen
            })
            .collect()
    }

    /// Returns the feature with the given identifier.
    #[must_use]
    pub fn feature(&self, id: &str) -> Option<&Feature> {
        self.features.get(id)
    }

    /// Returns features directly extracted from an observation.
    #[must_use]
    pub fn features_from_observation(&self, observation_id: &str) -> Vec<&Feature> {
        self.features
            .values()
            .filter(|feature| feature.source_observation() == Some(observation_id))
            .collect()
    }

    /// Returns the representation with the given identifier.
    #[must_use]
    pub fn representation(&self, id: &str) -> Option<&Representation> {
        self.representations.get(id)
    }

    /// Returns the event with the given identifier.
    #[must_use]
    pub fn event(&self, id: &str) -> Option<&Event> {
        self.events.get(id)
    }

    /// Returns the relationship with the given identifier.
    #[must_use]
    pub fn relationship(&self, id: &str) -> Option<&Relationship> {
        self.relationships.get(id)
    }

    /// Returns the hypothesis with the given identifier.
    #[must_use]
    pub fn hypothesis(&self, id: &str) -> Option<&Hypothesis> {
        self.hypotheses.get(id)
    }

    /// Returns the claim with the given identifier.
    #[must_use]
    pub fn claim(&self, id: &str) -> Option<&Claim> {
        self.claims.get(id)
    }

    /// Returns the evidence link with the given identifier.
    #[must_use]
    pub fn evidence(&self, id: &str) -> Option<&Evidence> {
        self.evidence.get(id)
    }

    /// Returns the test with the given identifier.
    #[must_use]
    pub fn test(&self, id: &str) -> Option<&Test> {
        self.tests.get(id)
    }

    /// Returns the action with the given identifier.
    #[must_use]
    pub fn action(&self, id: &str) -> Option<&Action> {
        self.actions.get(id)
    }

    /// Returns the confidence update with the given identifier.
    #[must_use]
    pub fn confidence_update(&self, id: &str) -> Option<&ConfidenceUpdate> {
        self.confidence_updates.get(id)
    }

    /// Returns the transformation with the given identifier.
    #[must_use]
    pub fn transformation(&self, id: &str) -> Option<&Transformation> {
        self.transformations.get(id)
    }

    /// Number of records across all collections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entities.len()
            + self.artifacts.len()
            + self.observations.len()
            + self.features.len()
            + self.representations.len()
            + self.transformations.len()
            + self.sources.len()
            + self.events.len()
            + self.relationships.len()
            + self.hypotheses.len()
            + self.claims.len()
            + self.evidence.len()
            + self.tests.len()
            + self.actions.len()
            + self.confidence_updates.len()
    }

    /// Whether the store contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
