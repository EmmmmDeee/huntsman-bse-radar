//! Execution-feedback adaptive OSINT search.
//!
//! Search is represented as an executable, provenance-preserving frontier
//! rather than as a static list of query expansions.  A caller supplies the
//! real search adapter and records its observed result; the engine classifies
//! that result, updates per-representation feedback, registers new pivots, and
//! re-ranks the remaining frontier.  Search findings are persisted as
//! observations and retrieval actions in the canonical evidence store.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::{
    Action, ActionStatus, ActionType, Confidence, EvidenceStore, EvidenceValue, Observation,
    ProvenanceError, Source, Timestamp,
};

/// Representation used for an adaptive OSINT search pivot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SearchRepresentation {
    /// Search the indicator exactly as observed.
    Exact,
    /// Search a losslessly normalized spelling or token form.
    Normalized,
    /// Search a known alias or alternate identifier.
    Alias,
    /// Search historical names, versions, or past values.
    Historical,
    /// Search a semantic description of the observed feature.
    Semantic,
    /// Search a structural signature or composition.
    Structural,
    /// Search a time-bounded form or temporal pivot.
    Temporal,
    /// Search a relationship to a known entity or artifact.
    Relational,
    /// Search a technical implementation, protocol, or format detail.
    Technical,
    /// Search for provenance, source, or derivation information.
    Provenance,
    /// Search a neighboring node in the observed relationship graph.
    GraphNeighbor,
}

impl SearchRepresentation {
    /// Every supported representation in stable order.
    pub const ALL: [Self; 11] = [
        Self::Exact,
        Self::Normalized,
        Self::Alias,
        Self::Historical,
        Self::Semantic,
        Self::Structural,
        Self::Temporal,
        Self::Relational,
        Self::Technical,
        Self::Provenance,
        Self::GraphNeighbor,
    ];

    /// Stable lower-case label for this representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Normalized => "normalized",
            Self::Alias => "alias",
            Self::Historical => "historical",
            Self::Semantic => "semantic",
            Self::Structural => "structural",
            Self::Temporal => "temporal",
            Self::Relational => "relational",
            Self::Technical => "technical",
            Self::Provenance => "provenance",
            Self::GraphNeighbor => "graph_neighbor",
        }
    }
}

impl fmt::Display for SearchRepresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Classification of one executed search pivot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SearchOutcome {
    /// The execution produced relevant, novel observations.
    Useful,
    /// The execution produced a contradiction worth investigating.
    Contradictory,
    /// The execution completed but produced no results.
    NoResults,
    /// The execution completed with results that were not useful or novel.
    Weak,
    /// The execution returned only duplicated or derivative observations.
    Duplicate,
    /// The search adapter failed to execute the pivot.
    Failed,
    /// The execution did not provide enough information to classify it.
    Inconclusive,
}

impl SearchOutcome {
    /// Whether the execution completed without an adapter failure.
    #[must_use]
    pub const fn completed(self) -> bool {
        !matches!(self, Self::Failed | Self::Inconclusive)
    }

    /// Whether the result should influence the frontier as informative.
    #[must_use]
    pub const fn informative(self) -> bool {
        matches!(self, Self::Useful | Self::Contradictory)
    }
}

/// Factors used to rank an OSINT search pivot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchPriorityFactors {
    expected_information_gain: Confidence,
    novelty: Confidence,
    reachability: Confidence,
    source_independence: Confidence,
    provenance_quality: Confidence,
    execution_cost: u8,
    failure_risk: u8,
}

impl SearchPriorityFactors {
    /// Creates bounded ranking factors.
    ///
    /// The numerator is the product of expected information gain, novelty,
    /// reachability, source independence, and provenance quality.  Cost and
    /// failure risk are non-zero divisors and are clamped to 100.
    pub fn new(
        expected_information_gain: u8,
        novelty: u8,
        reachability: u8,
        source_independence: u8,
        provenance_quality: u8,
        execution_cost: u8,
        failure_risk: u8,
    ) -> Result<Self, SearchError> {
        if execution_cost == 0 {
            return Err(SearchError::InvalidFactor {
                factor: "execution cost",
                value: execution_cost,
            });
        }
        if failure_risk == 0 {
            return Err(SearchError::InvalidFactor {
                factor: "failure risk",
                value: failure_risk,
            });
        }
        Ok(Self {
            expected_information_gain: Confidence::new(expected_information_gain),
            novelty: Confidence::new(novelty),
            reachability: Confidence::new(reachability),
            source_independence: Confidence::new(source_independence),
            provenance_quality: Confidence::new(provenance_quality),
            execution_cost: execution_cost.min(100),
            failure_risk: failure_risk.min(100),
        })
    }

    /// Expected information gain.
    #[must_use]
    pub const fn expected_information_gain(self) -> Confidence {
        self.expected_information_gain
    }

    /// Expected novelty.
    #[must_use]
    pub const fn novelty(self) -> Confidence {
        self.novelty
    }

    /// Reachability of the intended source or pivot.
    #[must_use]
    pub const fn reachability(self) -> Confidence {
        self.reachability
    }

    /// Expected independence of the resulting source.
    #[must_use]
    pub const fn source_independence(self) -> Confidence {
        self.source_independence
    }

    /// Expected provenance quality of the result.
    #[must_use]
    pub const fn provenance_quality(self) -> Confidence {
        self.provenance_quality
    }

    /// Relative execution cost, in the range 1..=100.
    #[must_use]
    pub const fn execution_cost(self) -> u8 {
        self.execution_cost
    }

    /// Relative failure risk, in the range 1..=100.
    #[must_use]
    pub const fn failure_risk(self) -> u8 {
        self.failure_risk
    }

    /// Computes the exact base priority before execution feedback adjustment.
    #[must_use]
    pub const fn priority(self) -> SearchPriority {
        let numerator = self.expected_information_gain.value() as u128
            * self.novelty.value() as u128
            * self.reachability.value() as u128
            * self.source_independence.value() as u128
            * self.provenance_quality.value() as u128;
        let denominator = self.execution_cost as u128 * self.failure_risk as u128;
        SearchPriority {
            numerator,
            denominator,
        }
    }
}

/// Exact rational representation of a search priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchPriority {
    numerator: u128,
    denominator: u128,
}

impl SearchPriority {
    /// Numerator of the priority formula.
    #[must_use]
    pub const fn numerator(self) -> u128 {
        self.numerator
    }

    /// Denominator of the priority formula.
    #[must_use]
    pub const fn denominator(self) -> u128 {
        self.denominator
    }

    /// Human-friendly fixed-point score scaled by one million.
    #[must_use]
    pub fn scaled(self) -> u128 {
        self.numerator
            .saturating_mul(1_000_000)
            .checked_div(self.denominator)
            .unwrap_or(0)
    }
}

impl Ord for SearchPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.numerator * other.denominator).cmp(&(other.numerator * self.denominator))
    }
}

impl PartialOrd for SearchPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A proposed search pivot with raw and optional normalized query forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchPivot {
    id: String,
    raw_query: String,
    normalized_query: Option<String>,
    representation: SearchRepresentation,
    parent_id: Option<String>,
    rationale: String,
    factors: SearchPriorityFactors,
    state: SearchPivotState,
}

impl SearchPivot {
    /// Creates a search pivot.
    pub fn new(
        id: impl Into<String>,
        raw_query: impl Into<String>,
        representation: SearchRepresentation,
        factors: SearchPriorityFactors,
    ) -> Result<Self, SearchError> {
        Ok(Self {
            id: require_text(id.into(), "pivot id")?,
            raw_query: require_text(raw_query.into(), "raw query")?,
            normalized_query: None,
            representation,
            parent_id: None,
            rationale: "caller-supplied search pivot".to_owned(),
            factors,
            state: SearchPivotState::Proposed,
        })
    }

    /// Returns a copy with an additive normalized query.
    pub fn with_normalization(
        &self,
        normalized_query: impl Into<String>,
    ) -> Result<Self, SearchError> {
        let normalized_query = require_text(normalized_query.into(), "normalized query")?;
        let mut copy = self.clone();
        copy.normalized_query = Some(normalized_query);
        Ok(copy)
    }

    /// Returns a copy linked to the pivot that generated it.
    #[must_use]
    pub fn derived_from(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Returns a copy with a rationale for the pivot.
    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Result<Self, SearchError> {
        self.rationale = require_text(rationale.into(), "pivot rationale")?;
        Ok(self)
    }

    /// Stable pivot identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Query exactly as supplied by the caller.
    #[must_use]
    pub fn raw_query(&self) -> &str {
        &self.raw_query
    }

    /// Normalized query, if one was supplied.
    #[must_use]
    pub fn normalized_query(&self) -> Option<&str> {
        self.normalized_query.as_deref()
    }

    /// Query selected by the caller's representation-aware adapter.
    #[must_use]
    pub fn query_for_execution(&self) -> &str {
        self.normalized_query.as_deref().unwrap_or(&self.raw_query)
    }

    /// Search representation.
    #[must_use]
    pub const fn representation(&self) -> SearchRepresentation {
        self.representation
    }

    /// Parent pivot, if this pivot was generated from another execution.
    #[must_use]
    pub fn parent_id(&self) -> Option<&str> {
        self.parent_id.as_deref()
    }

    /// Reason this pivot was generated.
    #[must_use]
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Base ranking factors.
    #[must_use]
    pub const fn factors(&self) -> SearchPriorityFactors {
        self.factors
    }

    /// Base priority before adaptive feedback.
    #[must_use]
    pub const fn priority(&self) -> SearchPriority {
        self.factors.priority()
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SearchPivotState {
        self.state
    }
}

/// A caller-supplied next pivot generated from execution feedback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchPivotSeed {
    raw_query: String,
    normalized_query: Option<String>,
    representation: SearchRepresentation,
    rationale: String,
    factors: SearchPriorityFactors,
}

impl SearchPivotSeed {
    /// Creates a next-pivot seed.
    pub fn new(
        raw_query: impl Into<String>,
        representation: SearchRepresentation,
        factors: SearchPriorityFactors,
    ) -> Result<Self, SearchError> {
        Ok(Self {
            raw_query: require_text(raw_query.into(), "next pivot query")?,
            normalized_query: None,
            representation,
            rationale: "execution-feedback pivot".to_owned(),
            factors,
        })
    }

    /// Adds a normalized query without replacing the raw query.
    pub fn with_normalization(
        mut self,
        normalized_query: impl Into<String>,
    ) -> Result<Self, SearchError> {
        self.normalized_query = Some(require_text(
            normalized_query.into(),
            "next pivot normalized query",
        )?);
        Ok(self)
    }

    /// Records why the next pivot is being generated.
    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Result<Self, SearchError> {
        self.rationale = require_text(rationale.into(), "next pivot rationale")?;
        Ok(self)
    }

    /// Raw next-pivot query.
    #[must_use]
    pub fn raw_query(&self) -> &str {
        &self.raw_query
    }

    /// Normalized next-pivot query, if supplied.
    #[must_use]
    pub fn normalized_query(&self) -> Option<&str> {
        self.normalized_query.as_deref()
    }

    /// Representation of the next pivot.
    #[must_use]
    pub const fn representation(&self) -> SearchRepresentation {
        self.representation
    }

    /// Rationale for the next pivot.
    #[must_use]
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Ranking factors for the next pivot.
    #[must_use]
    pub const fn factors(&self) -> SearchPriorityFactors {
        self.factors
    }

    fn query_key(&self) -> String {
        query_key(
            self.representation,
            self.normalized_query.as_deref().unwrap_or(&self.raw_query),
        )
    }
}

/// Lifecycle state of a search pivot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SearchPivotState {
    /// Registered and available for execution.
    Proposed,
    /// Executed and retained as provenance.
    Executed,
    /// Explicitly retired from the active frontier.
    Exhausted,
}

/// One public source-backed finding returned by a search.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchFinding {
    id: String,
    raw_value: EvidenceValue,
    normalized_value: Option<EvidenceValue>,
    source: Source,
    observed_at: Timestamp,
    dependency_group: Option<String>,
}

impl SearchFinding {
    /// Creates a finding with a raw value and complete source metadata.
    pub fn new(
        id: impl Into<String>,
        raw_value: impl Into<EvidenceValue>,
        source: Source,
        observed_at: Timestamp,
    ) -> Result<Self, SearchError> {
        Ok(Self {
            id: require_text(id.into(), "finding id")?,
            raw_value: raw_value.into(),
            normalized_value: None,
            source,
            observed_at,
            dependency_group: None,
        })
    }

    /// Adds a normalized value while preserving the raw value.
    #[must_use]
    pub fn with_normalized_value(mut self, normalized_value: impl Into<EvidenceValue>) -> Self {
        self.normalized_value = Some(normalized_value.into());
        self
    }

    /// Records a dependency group for later calibrated fusion.
    pub fn in_dependency_group(
        mut self,
        dependency_group: impl Into<String>,
    ) -> Result<Self, SearchError> {
        self.dependency_group = Some(require_text(
            dependency_group.into(),
            "finding dependency group",
        )?);
        Ok(self)
    }

    /// Stable finding identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Original value returned by the source.
    #[must_use]
    pub const fn raw_value(&self) -> &EvidenceValue {
        &self.raw_value
    }

    /// Normalized value, if supplied by the search adapter.
    #[must_use]
    pub const fn normalized_value(&self) -> Option<&EvidenceValue> {
        self.normalized_value.as_ref()
    }

    /// Source record for this finding.
    #[must_use]
    pub const fn source(&self) -> &Source {
        &self.source
    }

    /// Observation timestamp.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Dependency group, if known.
    #[must_use]
    pub fn dependency_group(&self) -> Option<&str> {
        self.dependency_group.as_deref()
    }

    fn to_observation(&self) -> Result<Observation, ProvenanceError> {
        Observation::from_source(
            self.id.clone(),
            self.raw_value.clone(),
            self.normalized_value.clone(),
            &self.source,
            self.observed_at,
        )
    }
}

/// Feedback captured from one real search execution.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchFeedback {
    outcome: SearchOutcome,
    result_count: u32,
    relevant_count: u32,
    novel_observation_count: u32,
    duplicate_observation_count: u32,
    contradiction_count: u32,
    independent_source_count: u32,
    latency_ms: Option<u64>,
    findings: Vec<SearchFinding>,
    next_pivots: Vec<SearchPivotSeed>,
    note: Option<String>,
    error: Option<String>,
}

impl SearchFeedback {
    /// Creates feedback with an explicit classification.
    #[must_use]
    pub fn new(outcome: SearchOutcome, result_count: u32) -> Self {
        Self {
            outcome,
            result_count,
            relevant_count: 0,
            novel_observation_count: 0,
            duplicate_observation_count: 0,
            contradiction_count: 0,
            independent_source_count: 0,
            latency_ms: None,
            findings: Vec::new(),
            next_pivots: Vec::new(),
            note: None,
            error: None,
        }
    }

    /// Classifies feedback from the observed result counts.
    #[must_use]
    pub fn classified(
        result_count: u32,
        relevant_count: u32,
        novel_observation_count: u32,
        duplicate_observation_count: u32,
        contradiction_count: u32,
    ) -> Self {
        let outcome = classify_outcome(
            result_count,
            relevant_count,
            novel_observation_count,
            duplicate_observation_count,
            contradiction_count,
        );
        Self::new(outcome, result_count)
            .with_relevant_count(relevant_count)
            .with_novel_observations(novel_observation_count)
            .with_duplicate_observations(duplicate_observation_count)
            .with_contradictions(contradiction_count)
    }

    /// Creates failed feedback for an adapter error.
    pub fn failed(error: impl Into<String>) -> Result<Self, SearchError> {
        let error = require_text(error.into(), "search failure")?;
        Ok(Self::new(SearchOutcome::Failed, 0).with_error(error))
    }

    /// Sets the number of relevant returned results.
    #[must_use]
    pub const fn with_relevant_count(mut self, count: u32) -> Self {
        self.relevant_count = count;
        self
    }

    /// Sets the number of novel observations.
    #[must_use]
    pub const fn with_novel_observations(mut self, count: u32) -> Self {
        self.novel_observation_count = count;
        self
    }

    /// Sets the number of duplicated or derivative observations.
    #[must_use]
    pub const fn with_duplicate_observations(mut self, count: u32) -> Self {
        self.duplicate_observation_count = count;
        self
    }

    /// Sets the number of contradictions.
    #[must_use]
    pub const fn with_contradictions(mut self, count: u32) -> Self {
        self.contradiction_count = count;
        self
    }

    /// Sets the number of independent sources observed.
    #[must_use]
    pub const fn with_independent_sources(mut self, count: u32) -> Self {
        self.independent_source_count = count;
        self
    }

    /// Records observed adapter latency.
    #[must_use]
    pub const fn with_latency_ms(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    /// Attaches findings that will be persisted in the canonical store.
    #[must_use]
    pub fn with_findings<I>(mut self, findings: I) -> Self
    where
        I: IntoIterator<Item = SearchFinding>,
    {
        self.findings = findings.into_iter().collect();
        self
    }

    /// Adds one finding to this feedback.
    #[must_use]
    pub fn with_finding(mut self, finding: SearchFinding) -> Self {
        self.findings.push(finding);
        self
    }

    /// Adds one execution-feedback next pivot.
    #[must_use]
    pub fn with_next_pivot(mut self, pivot: SearchPivotSeed) -> Self {
        self.next_pivots.push(pivot);
        self
    }

    /// Adds a human-readable execution note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        let note = note.into();
        self.note = (!note.trim().is_empty()).then_some(note);
        self
    }

    /// Records an adapter error without changing the other measurements.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        let error = error.into();
        self.error = (!error.trim().is_empty()).then_some(error);
        self
    }

    /// Classification of the execution.
    #[must_use]
    pub const fn outcome(&self) -> SearchOutcome {
        self.outcome
    }

    /// Number of returned results.
    #[must_use]
    pub const fn result_count(&self) -> u32 {
        self.result_count
    }

    /// Number of relevant results.
    #[must_use]
    pub const fn relevant_count(&self) -> u32 {
        self.relevant_count
    }

    /// Number of novel observations.
    #[must_use]
    pub const fn novel_observation_count(&self) -> u32 {
        self.novel_observation_count
    }

    /// Number of duplicate or derivative observations.
    #[must_use]
    pub const fn duplicate_observation_count(&self) -> u32 {
        self.duplicate_observation_count
    }

    /// Number of contradictions.
    #[must_use]
    pub const fn contradiction_count(&self) -> u32 {
        self.contradiction_count
    }

    /// Number of independent sources.
    #[must_use]
    pub const fn independent_source_count(&self) -> u32 {
        self.independent_source_count
    }

    /// Adapter latency, if measured.
    #[must_use]
    pub const fn latency_ms(&self) -> Option<u64> {
        self.latency_ms
    }

    /// Findings returned by the search.
    #[must_use]
    pub fn findings(&self) -> &[SearchFinding] {
        &self.findings
    }

    /// Pivots generated from this execution feedback.
    #[must_use]
    pub fn next_pivots(&self) -> &[SearchPivotSeed] {
        &self.next_pivots
    }

    /// Execution note, if supplied.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// Adapter error, if one was recorded.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// Per-representation execution feedback used to adapt the search frontier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchFamilyStatistics {
    representation: SearchRepresentation,
    executions: u32,
    useful: u32,
    contradictory: u32,
    no_results: u32,
    weak: u32,
    duplicate: u32,
    failed: u32,
    inconclusive: u32,
    novel_observations: u32,
    duplicate_observations: u32,
}

impl SearchFamilyStatistics {
    fn new(representation: SearchRepresentation) -> Self {
        Self {
            representation,
            executions: 0,
            useful: 0,
            contradictory: 0,
            no_results: 0,
            weak: 0,
            duplicate: 0,
            failed: 0,
            inconclusive: 0,
            novel_observations: 0,
            duplicate_observations: 0,
        }
    }

    fn record(&mut self, feedback: &SearchFeedback) {
        self.executions = self.executions.saturating_add(1);
        match feedback.outcome() {
            SearchOutcome::Useful => self.useful = self.useful.saturating_add(1),
            SearchOutcome::Contradictory => {
                self.contradictory = self.contradictory.saturating_add(1)
            }
            SearchOutcome::NoResults => self.no_results = self.no_results.saturating_add(1),
            SearchOutcome::Weak => self.weak = self.weak.saturating_add(1),
            SearchOutcome::Duplicate => self.duplicate = self.duplicate.saturating_add(1),
            SearchOutcome::Failed => self.failed = self.failed.saturating_add(1),
            SearchOutcome::Inconclusive => self.inconclusive = self.inconclusive.saturating_add(1),
        }
        self.novel_observations = self
            .novel_observations
            .saturating_add(feedback.novel_observation_count());
        self.duplicate_observations = self
            .duplicate_observations
            .saturating_add(feedback.duplicate_observation_count());
    }

    /// Representation summarized by this record.
    #[must_use]
    pub const fn representation(self) -> SearchRepresentation {
        self.representation
    }

    /// Number of executions in this representation family.
    #[must_use]
    pub const fn executions(self) -> u32 {
        self.executions
    }

    /// Number of useful executions.
    #[must_use]
    pub const fn useful(self) -> u32 {
        self.useful
    }

    /// Number of contradictory executions.
    #[must_use]
    pub const fn contradictory(self) -> u32 {
        self.contradictory
    }

    /// Number of no-result executions.
    #[must_use]
    pub const fn no_results(self) -> u32 {
        self.no_results
    }

    /// Number of weak executions.
    #[must_use]
    pub const fn weak(self) -> u32 {
        self.weak
    }

    /// Number of duplicate-only executions.
    #[must_use]
    pub const fn duplicate(self) -> u32 {
        self.duplicate
    }

    /// Number of failed executions.
    #[must_use]
    pub const fn failed(self) -> u32 {
        self.failed
    }

    /// Number of inconclusive executions.
    #[must_use]
    pub const fn inconclusive(self) -> u32 {
        self.inconclusive
    }

    /// Total novel observations attributed to this family.
    #[must_use]
    pub const fn novel_observations(self) -> u32 {
        self.novel_observations
    }

    /// Total duplicate observations attributed to this family.
    #[must_use]
    pub const fn duplicate_observations(self) -> u32 {
        self.duplicate_observations
    }

    /// Calibrated useful-yield score, with 50 as the no-data prior.
    #[must_use]
    pub const fn yield_score(self) -> u8 {
        if self.executions == 0 {
            50
        } else {
            let useful = self.useful.saturating_add(self.contradictory) as u64;
            let score = useful * 100 / self.executions as u64;
            if score > 100 { 100 } else { score as u8 }
        }
    }

    /// Calibrated novelty score, with 50 as the no-data prior.
    #[must_use]
    pub const fn novelty_score(self) -> u8 {
        let total = self
            .novel_observations
            .saturating_add(self.duplicate_observations);
        if total == 0 {
            50
        } else {
            let score = self.novel_observations as u64 * 100 / total as u64;
            if score > 100 { 100 } else { score as u8 }
        }
    }

    /// Adaptive pressure assigned to this representation family.
    ///
    /// High-yield and novel families receive more pressure; families with no
    /// useful or novel output naturally receive less.
    #[must_use]
    pub const fn adaptive_pressure(self) -> u8 {
        ((self.yield_score() as u16 * self.novelty_score() as u16) / 100) as u8
    }
}

/// Ordered phases recorded for each adaptive search execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SearchPhase {
    /// Preserve the caller's raw query and representation.
    Query,
    /// Invoke the caller's real search adapter.
    Execute,
    /// Capture results and provenance.
    Observe,
    /// Classify the execution feedback.
    Classify,
    /// Update family statistics and canonical evidence.
    Update,
    /// Generate and deduplicate next pivots.
    GenerateNextPivot,
    /// Recompute the active search frontier.
    Rank,
}

/// Complete record of one search execution.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchExecution {
    id: String,
    pivot_id: String,
    representation: SearchRepresentation,
    raw_query: String,
    normalized_query: Option<String>,
    observed_at: Timestamp,
    feedback: SearchFeedback,
    phases: Vec<SearchPhase>,
    observation_ids: Vec<String>,
    generated_pivot_ids: Vec<String>,
    suppressed_pivots: Vec<String>,
    action_id: String,
}

impl SearchExecution {
    /// Stable execution identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Pivot executed by this record.
    #[must_use]
    pub fn pivot_id(&self) -> &str {
        &self.pivot_id
    }

    /// Search representation used.
    #[must_use]
    pub const fn representation(&self) -> SearchRepresentation {
        self.representation
    }

    /// Raw query preserved in the record.
    #[must_use]
    pub fn raw_query(&self) -> &str {
        &self.raw_query
    }

    /// Normalized query, if present.
    #[must_use]
    pub fn normalized_query(&self) -> Option<&str> {
        self.normalized_query.as_deref()
    }

    /// Time at which feedback was observed.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Captured execution feedback.
    #[must_use]
    pub const fn feedback(&self) -> &SearchFeedback {
        &self.feedback
    }

    /// Ordered control-loop phases completed by this record.
    #[must_use]
    pub fn phases(&self) -> &[SearchPhase] {
        &self.phases
    }

    /// Canonical observation identifiers produced by this execution.
    #[must_use]
    pub fn observation_ids(&self) -> &[String] {
        &self.observation_ids
    }

    /// Generated next-pivot identifiers.
    #[must_use]
    pub fn generated_pivot_ids(&self) -> &[String] {
        &self.generated_pivot_ids
    }

    /// Queries suppressed because they were duplicates or over budget.
    #[must_use]
    pub fn suppressed_pivots(&self) -> &[String] {
        &self.suppressed_pivots
    }

    /// Retrieval action persisted in the canonical store.
    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.action_id
    }
}

/// One active pivot with feedback-adjusted priority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRanking {
    pivot_id: String,
    representation: SearchRepresentation,
    priority: SearchPriority,
    base_priority: SearchPriority,
    adaptive_pressure: u8,
    state: SearchPivotState,
}

impl SearchRanking {
    /// Pivot identifier.
    #[must_use]
    pub fn pivot_id(&self) -> &str {
        &self.pivot_id
    }

    /// Pivot representation.
    #[must_use]
    pub const fn representation(&self) -> SearchRepresentation {
        self.representation
    }

    /// Feedback-adjusted priority.
    #[must_use]
    pub const fn priority(&self) -> SearchPriority {
        self.priority
    }

    /// Priority before feedback adjustment.
    #[must_use]
    pub const fn base_priority(&self) -> SearchPriority {
        self.base_priority
    }

    /// Adaptive family pressure applied to this ranking.
    #[must_use]
    pub const fn adaptive_pressure(&self) -> u8 {
        self.adaptive_pressure
    }

    /// Current pivot state.
    #[must_use]
    pub const fn state(&self) -> SearchPivotState {
        self.state
    }
}

/// Search execution resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchLimits {
    max_executions: usize,
    max_pivots: usize,
}

impl SearchLimits {
    /// Creates non-zero execution and pivot limits.
    pub fn new(max_executions: usize, max_pivots: usize) -> Result<Self, SearchError> {
        if max_executions == 0 {
            return Err(SearchError::InvalidLimit {
                limit: "maximum executions",
                value: max_executions,
            });
        }
        if max_pivots == 0 {
            return Err(SearchError::InvalidLimit {
                limit: "maximum pivots",
                value: max_pivots,
            });
        }
        Ok(Self {
            max_executions,
            max_pivots,
        })
    }

    /// Maximum number of executions.
    #[must_use]
    pub const fn max_executions(self) -> usize {
        self.max_executions
    }

    /// Maximum number of registered pivots.
    #[must_use]
    pub const fn max_pivots(self) -> usize {
        self.max_pivots
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_executions: 128,
            max_pivots: 512,
        }
    }
}

/// Search frontier construction, execution, and provenance failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchError {
    /// A required textual field was empty.
    EmptyValue {
        /// Empty field name.
        field: &'static str,
    },
    /// A divisor factor was zero.
    InvalidFactor {
        /// Factor name.
        factor: &'static str,
        /// Invalid value.
        value: u8,
    },
    /// A resource limit was zero.
    InvalidLimit {
        /// Limit name.
        limit: &'static str,
        /// Invalid value.
        value: usize,
    },
    /// A pivot identifier was already registered.
    DuplicatePivot {
        /// Duplicated pivot identifier.
        pivot_id: String,
    },
    /// A representation/query pair was already registered.
    DuplicateQuery {
        /// Duplicated query key.
        query: String,
        /// Representation containing the duplicate.
        representation: SearchRepresentation,
    },
    /// The requested pivot is absent.
    MissingPivot {
        /// Missing pivot identifier.
        pivot_id: String,
    },
    /// The pivot is not available for execution or retirement.
    InvalidState {
        /// Pivot identifier.
        pivot_id: String,
        /// Current state.
        state: SearchPivotState,
    },
    /// The configured execution or pivot budget is exhausted.
    ResourceLimit {
        /// Resource name.
        resource: &'static str,
        /// Configured limit.
        limit: usize,
    },
    /// A finding identifier conflicts with an existing observation.
    FindingConflict {
        /// Conflicting finding identifier.
        finding_id: String,
    },
    /// Two records use the same source identifier with different metadata.
    SourceConflict {
        /// Conflicting source identifier.
        source_id: String,
    },
    /// Canonical evidence persistence failed.
    Provenance {
        /// Underlying provenance error.
        error: ProvenanceError,
    },
}

impl fmt::Display for SearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue { field } => write!(formatter, "{field} must not be empty"),
            Self::InvalidFactor { factor, value } => {
                write!(formatter, "{factor} must be greater than zero, got {value}")
            }
            Self::InvalidLimit { limit, value } => {
                write!(formatter, "{limit} must be greater than zero, got {value}")
            }
            Self::DuplicatePivot { pivot_id } => {
                write!(
                    formatter,
                    "pivot `{pivot_id}` was registered more than once"
                )
            }
            Self::DuplicateQuery {
                query,
                representation,
            } => write!(
                formatter,
                "{representation} query `{query}` was registered more than once"
            ),
            Self::MissingPivot { pivot_id } => {
                write!(formatter, "unknown search pivot `{pivot_id}`")
            }
            Self::InvalidState { pivot_id, state } => {
                write!(
                    formatter,
                    "pivot `{pivot_id}` is in invalid state {state:?}"
                )
            }
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "{resource} limit of {limit} was reached")
            }
            Self::FindingConflict { finding_id } => {
                write!(
                    formatter,
                    "finding `{finding_id}` conflicts with existing evidence"
                )
            }
            Self::SourceConflict { source_id } => {
                write!(formatter, "source `{source_id}` has conflicting metadata")
            }
            Self::Provenance { error } => {
                write!(formatter, "canonical persistence failed: {error}")
            }
        }
    }
}

impl std::error::Error for SearchError {}

impl crate::validation::EmptyValueError for SearchError {
    fn empty_value(field: &'static str) -> Self {
        Self::EmptyValue { field }
    }
}

fn require_text(value: String, field: &'static str) -> Result<String, SearchError> {
    crate::validation::require_text(value, field)
}

impl From<ProvenanceError> for SearchError {
    fn from(error: ProvenanceError) -> Self {
        Self::Provenance { error }
    }
}

/// Execution-feedback adaptive OSINT search engine.
#[derive(Debug, Clone)]
pub struct ExecutionFeedbackAdaptiveOsintSearchEngine {
    evidence: EvidenceStore,
    limits: SearchLimits,
    pivots: BTreeMap<String, SearchPivot>,
    query_keys: BTreeMap<String, String>,
    executions: BTreeMap<String, SearchExecution>,
    family_statistics: BTreeMap<SearchRepresentation, SearchFamilyStatistics>,
    next_sequence: u64,
}

impl ExecutionFeedbackAdaptiveOsintSearchEngine {
    /// Creates an engine with the supplied authoritative evidence store.
    #[must_use]
    pub fn new(evidence: EvidenceStore) -> Self {
        Self::with_limits(evidence, SearchLimits::default())
    }

    /// Creates an engine with explicit resource limits.
    #[must_use]
    pub fn with_limits(evidence: EvidenceStore, limits: SearchLimits) -> Self {
        Self {
            evidence,
            limits,
            pivots: BTreeMap::new(),
            query_keys: BTreeMap::new(),
            executions: BTreeMap::new(),
            family_statistics: BTreeMap::new(),
            next_sequence: 0,
        }
    }

    /// Authoritative evidence store receiving search findings and actions.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceStore {
        &self.evidence
    }

    /// Mutable access to the authoritative evidence store.
    #[must_use]
    pub const fn evidence_mut(&mut self) -> &mut EvidenceStore {
        &mut self.evidence
    }

    /// Consumes the engine and returns its canonical evidence store, so a caller composing OSINT with the
    /// infrastructure, website, and fusion engines can move the store into the
    /// next stage without cloning it
    /// (see [`Self::evidence`] to borrow it in place).
    #[must_use]
    pub fn into_evidence(self) -> EvidenceStore {
        self.evidence
    }

    /// Configured resource limits.
    #[must_use]
    pub const fn limits(&self) -> SearchLimits {
        self.limits
    }

    /// Registers a complete search pivot.
    pub fn add_pivot(&mut self, pivot: SearchPivot) -> Result<(), SearchError> {
        if self.pivots.len() >= self.limits.max_pivots {
            return Err(SearchError::ResourceLimit {
                resource: "pivot",
                limit: self.limits.max_pivots,
            });
        }
        let pivot_id = pivot.id().to_owned();
        if self.pivots.contains_key(&pivot_id) {
            return Err(SearchError::DuplicatePivot { pivot_id });
        }
        let key = query_key(
            pivot.representation(),
            pivot
                .normalized_query()
                .unwrap_or_else(|| pivot.raw_query()),
        );
        if self.query_keys.contains_key(&key) {
            return Err(SearchError::DuplicateQuery {
                query: pivot.query_for_execution().to_owned(),
                representation: pivot.representation(),
            });
        }
        self.query_keys.insert(key, pivot_id.clone());
        self.pivots.insert(pivot_id, pivot);
        Ok(())
    }

    /// Registers a pivot seed under a stable identifier.
    pub fn add_seed(
        &mut self,
        pivot_id: impl Into<String>,
        seed: SearchPivotSeed,
    ) -> Result<(), SearchError> {
        let pivot_id = pivot_id.into();
        let mut pivot = SearchPivot::new(
            pivot_id,
            seed.raw_query.clone(),
            seed.representation,
            seed.factors,
        )?;
        pivot.rationale = seed.rationale;
        pivot.normalized_query = seed.normalized_query;
        self.add_pivot(pivot)
    }

    /// Returns a registered pivot.
    #[must_use]
    pub fn pivot(&self, pivot_id: &str) -> Option<&SearchPivot> {
        self.pivots.get(pivot_id)
    }

    /// Returns a completed execution by its action/execution identifier.
    #[must_use]
    pub fn execution(&self, execution_id: &str) -> Option<&SearchExecution> {
        self.executions.get(execution_id)
    }

    /// Returns all completed executions in stable identifier order.
    pub fn executions(&self) -> impl Iterator<Item = &SearchExecution> {
        self.executions.values()
    }

    /// Returns statistics for one representation family.
    #[must_use]
    pub fn statistics(&self, representation: SearchRepresentation) -> SearchFamilyStatistics {
        self.family_statistics
            .get(&representation)
            .copied()
            .unwrap_or_else(|| SearchFamilyStatistics::new(representation))
    }

    /// Returns statistics for every supported representation.
    #[must_use]
    pub fn family_statistics(&self) -> Vec<SearchFamilyStatistics> {
        SearchRepresentation::ALL
            .into_iter()
            .map(|representation| self.statistics(representation))
            .collect()
    }

    /// Returns the active frontier in descending feedback-adjusted priority.
    #[must_use]
    pub fn ranked_pivots(&self) -> Vec<SearchRanking> {
        let mut rankings: Vec<_> = self
            .pivots
            .values()
            .filter(|pivot| pivot.state() == SearchPivotState::Proposed)
            .map(|pivot| {
                let statistics = self.statistics(pivot.representation());
                SearchRanking {
                    pivot_id: pivot.id().to_owned(),
                    representation: pivot.representation(),
                    priority: adaptive_priority(pivot.priority(), statistics),
                    base_priority: pivot.priority(),
                    adaptive_pressure: statistics.adaptive_pressure(),
                    state: pivot.state(),
                }
            })
            .collect();
        rankings.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.pivot_id.cmp(&right.pivot_id))
        });
        rankings
    }

    /// Recomputes the active frontier after execution feedback.
    #[must_use]
    pub fn recompute_rankings(&self) -> Vec<SearchRanking> {
        self.ranked_pivots()
    }

    /// Returns the highest-ranked unexecuted pivot.
    #[must_use]
    pub fn next_pivot(&self) -> Option<&SearchPivot> {
        let rankings = self.ranked_pivots();
        let id = rankings.first()?.pivot_id();
        self.pivots.get(id)
    }

    /// Whether any executable pivot remains.
    #[must_use]
    pub fn has_ready_pivot(&self) -> bool {
        !self.ranked_pivots().is_empty()
    }

    /// Number of registered pivots.
    #[must_use]
    pub fn pivot_count(&self) -> usize {
        self.pivots.len()
    }

    /// Number of executed pivots.
    #[must_use]
    pub fn execution_count(&self) -> usize {
        self.executions.len()
    }

    /// Executes a caller-supplied real adapter and records its feedback.
    pub fn execute<F>(
        &mut self,
        pivot_id: &str,
        observed_at: Timestamp,
        executor: F,
    ) -> Result<SearchExecution, SearchError>
    where
        F: FnOnce(&SearchPivot) -> SearchFeedback,
    {
        let pivot = self
            .pivot(pivot_id)
            .cloned()
            .ok_or_else(|| SearchError::MissingPivot {
                pivot_id: pivot_id.to_owned(),
            })?;
        let feedback = executor(&pivot);
        self.record_feedback(pivot_id, observed_at, feedback)
    }

    /// Executes an adapter that can return a failure and records it as feedback.
    pub fn execute_result<F, E>(
        &mut self,
        pivot_id: &str,
        observed_at: Timestamp,
        executor: F,
    ) -> Result<SearchExecution, SearchError>
    where
        F: FnOnce(&SearchPivot) -> Result<SearchFeedback, E>,
        E: fmt::Display,
    {
        let pivot = self
            .pivot(pivot_id)
            .cloned()
            .ok_or_else(|| SearchError::MissingPivot {
                pivot_id: pivot_id.to_owned(),
            })?;
        let feedback = match executor(&pivot) {
            Ok(feedback) => feedback,
            Err(error) => SearchFeedback::failed(error.to_string())?,
        };
        self.record_feedback(pivot_id, observed_at, feedback)
    }

    /// Records execution feedback, updates the frontier, and persists evidence.
    pub fn record_feedback(
        &mut self,
        pivot_id: &str,
        observed_at: Timestamp,
        feedback: SearchFeedback,
    ) -> Result<SearchExecution, SearchError> {
        let pivot = self
            .pivot(pivot_id)
            .cloned()
            .ok_or_else(|| SearchError::MissingPivot {
                pivot_id: pivot_id.to_owned(),
            })?;
        if pivot.state() != SearchPivotState::Proposed {
            return Err(SearchError::InvalidState {
                pivot_id: pivot_id.to_owned(),
                state: pivot.state(),
            });
        }
        if self.executions.len() >= self.limits.max_executions {
            return Err(SearchError::ResourceLimit {
                resource: "execution",
                limit: self.limits.max_executions,
            });
        }

        let action_id = format!("osint-search:{}", pivot.id());
        let action_status = match feedback.outcome() {
            SearchOutcome::Failed | SearchOutcome::Inconclusive => ActionStatus::Failed,
            SearchOutcome::Useful
            | SearchOutcome::Contradictory
            | SearchOutcome::NoResults
            | SearchOutcome::Weak
            | SearchOutcome::Duplicate => ActionStatus::Succeeded,
        };
        // Findings, the retrieval action, and the generated pivots are
        // validated together inside one store transaction, so a refusal at any
        // step (a conflicting source or finding, an invalid action, an invalid
        // seed) leaves the store and the engine unchanged.
        let Self {
            evidence,
            pivots,
            query_keys,
            limits,
            next_sequence,
            ..
        } = self;
        let (observation_ids, generated_pivots, generated_pivot_ids, suppressed_pivots) = evidence
            .transaction(|store| {
                let mut observation_ids = Vec::new();
                for finding in feedback.findings() {
                    if let Some(existing) = store.source(finding.source().id()) {
                        if existing != finding.source() {
                            return Err(SearchError::SourceConflict {
                                source_id: finding.source().id().to_owned(),
                            });
                        }
                    } else {
                        store.add_source(finding.source().clone())?;
                    }

                    let observation = finding.to_observation()?;
                    if let Some(existing) = store.observation(finding.id()) {
                        if existing != &observation {
                            return Err(SearchError::FindingConflict {
                                finding_id: finding.id().to_owned(),
                            });
                        }
                    } else {
                        store.add_observation(observation)?;
                    }
                    observation_ids.push(finding.id().to_owned());
                }

                let action = Action::new(
                    action_id.clone(),
                    ActionType::Retrieve,
                    format!(
                        "execute {} OSINT search pivot `{}`",
                        pivot.representation(),
                        pivot.id()
                    ),
                    observed_at,
                )?
                .targeting(pivot.id().to_owned())
                .with_status(action_status);
                store.add_action(action)?;

                let mut generated_pivots = Vec::new();
                let mut generated_pivot_ids = Vec::new();
                let mut suppressed_pivots = Vec::new();
                let mut pending_keys = BTreeSet::new();
                for seed in feedback.next_pivots() {
                    let key = seed.query_key();
                    let query = seed
                        .normalized_query
                        .as_deref()
                        .unwrap_or(&seed.raw_query)
                        .to_owned();
                    if query_keys.contains_key(&key) || !pending_keys.insert(key) {
                        suppressed_pivots.push(format!("{}: duplicate query", query));
                        continue;
                    }
                    if pivots.len() + generated_pivots.len() >= limits.max_pivots {
                        suppressed_pivots.push(format!("{}: pivot limit", query));
                        continue;
                    }
                    let generated_id = format!("{}::pivot-{}", pivot.id(), *next_sequence);
                    *next_sequence = next_sequence.saturating_add(1);
                    let mut generated = SearchPivot::new(
                        generated_id.clone(),
                        &seed.raw_query,
                        seed.representation,
                        seed.factors,
                    )?;
                    generated.normalized_query = seed.normalized_query.clone();
                    generated.rationale = seed.rationale.clone();
                    generated.parent_id = Some(pivot.id().to_owned());
                    generated_pivot_ids.push(generated_id);
                    generated_pivots.push(generated);
                }
                Ok((
                    observation_ids,
                    generated_pivots,
                    generated_pivot_ids,
                    suppressed_pivots,
                ))
            })?;

        let execution = SearchExecution {
            id: action_id.clone(),
            pivot_id: pivot.id().to_owned(),
            representation: pivot.representation(),
            raw_query: pivot.raw_query().to_owned(),
            normalized_query: pivot.normalized_query().map(str::to_owned),
            observed_at,
            feedback: feedback.clone(),
            phases: vec![
                SearchPhase::Query,
                SearchPhase::Execute,
                SearchPhase::Observe,
                SearchPhase::Classify,
                SearchPhase::Update,
                SearchPhase::GenerateNextPivot,
                SearchPhase::Rank,
            ],
            observation_ids,
            generated_pivot_ids,
            suppressed_pivots,
            action_id,
        };

        let executed_pivot = self
            .pivots
            .get_mut(pivot.id())
            .expect("pivot reference was validated before persistence");
        executed_pivot.state = SearchPivotState::Executed;
        for generated in generated_pivots {
            let key = query_key(
                generated.representation(),
                generated
                    .normalized_query()
                    .unwrap_or_else(|| generated.raw_query()),
            );
            self.query_keys.insert(key, generated.id().to_owned());
            self.pivots.insert(generated.id().to_owned(), generated);
        }
        self.family_statistics
            .entry(pivot.representation())
            .or_insert_with(|| SearchFamilyStatistics::new(pivot.representation()))
            .record(&feedback);
        self.executions
            .insert(execution.id().to_owned(), execution.clone());
        Ok(execution)
    }

    /// Retires a proposed pivot without executing it.
    pub fn exhaust(&mut self, pivot_id: &str) -> Result<(), SearchError> {
        let pivot = self
            .pivots
            .get_mut(pivot_id)
            .ok_or_else(|| SearchError::MissingPivot {
                pivot_id: pivot_id.to_owned(),
            })?;
        if pivot.state != SearchPivotState::Proposed {
            return Err(SearchError::InvalidState {
                pivot_id: pivot_id.to_owned(),
                state: pivot.state,
            });
        }
        pivot.state = SearchPivotState::Exhausted;
        Ok(())
    }
}

/// Short alias for the execution-feedback adaptive OSINT engine.
pub type AdaptiveOsintSearchEngine = ExecutionFeedbackAdaptiveOsintSearchEngine;

/// Alias using the architecture's full engine name.
pub type ExecutionFeedbackAdaptiveSearchEngine = ExecutionFeedbackAdaptiveOsintSearchEngine;

/// Alias for [`SearchPriorityFactors`].
pub type AdaptiveSearchFactors = SearchPriorityFactors;

/// Alias for [`SearchError`].
pub type OsintSearchError = SearchError;

fn classify_outcome(
    result_count: u32,
    relevant_count: u32,
    novel_observation_count: u32,
    duplicate_observation_count: u32,
    contradiction_count: u32,
) -> SearchOutcome {
    if contradiction_count > 0 {
        SearchOutcome::Contradictory
    } else if result_count == 0 {
        SearchOutcome::NoResults
    } else if relevant_count > 0 && novel_observation_count > 0 {
        SearchOutcome::Useful
    } else if novel_observation_count == 0 && duplicate_observation_count > 0 {
        SearchOutcome::Duplicate
    } else if relevant_count == 0 && novel_observation_count == 0 {
        SearchOutcome::Weak
    } else {
        SearchOutcome::Inconclusive
    }
}

fn adaptive_priority(base: SearchPriority, statistics: SearchFamilyStatistics) -> SearchPriority {
    let multiplier = u128::from(statistics.adaptive_pressure()) + 1;
    let repeat_penalty = u128::from(statistics.executions()) + 1;
    SearchPriority {
        numerator: base.numerator.saturating_mul(multiplier),
        denominator: base.denominator.saturating_mul(repeat_penalty),
    }
}

fn query_key(representation: SearchRepresentation, query: &str) -> String {
    format!("{}\u{1f}{}", representation.as_str(), query)
}
