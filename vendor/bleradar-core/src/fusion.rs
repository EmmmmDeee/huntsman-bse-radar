//! Calibrated evidence fusion and adversarial falsification.
//!
//! This module deliberately uses bounded, ordinal weights rather than
//! pretending that unmeasured priors or likelihood ratios are available.
//! Evidence with the same independence group contributes at most once to a
//! hypothesis.  Callers can therefore collapse copied reporting, shared
//! providers, common datasets, derivative sources, and duplicate observations
//! without counting them as independent confirmations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::{
    Confidence, EvidenceId, EvidenceRole, EvidenceStore, HypothesisId, ObservationId, SourceId,
};

/// A bounded ordinal score used for evidence-quality dimensions.
///
/// This is a calibration scale, not a probability.  The nine dimensions are
/// intentionally kept visible so a caller can explain why an item received
/// its weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceQuality {
    reliability: Confidence,
    specificity: Confidence,
    rarity: Confidence,
    discriminative_power: Confidence,
    source_independence: Confidence,
    temporal_compatibility: Confidence,
    transformation_resistance: Confidence,
    provenance_quality: Confidence,
    reproducibility: Confidence,
}

impl EvidenceQuality {
    /// Creates a quality profile from the nine required calibrated dimensions.
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
        }
    }

    /// Creates a profile with the same score for every dimension.
    #[must_use]
    pub const fn uniform(score: u8) -> Self {
        Self::new(
            score, score, score, score, score, score, score, score, score,
        )
    }

    /// Reliability score.
    #[must_use]
    pub const fn reliability(self) -> Confidence {
        self.reliability
    }

    /// Specificity score.
    #[must_use]
    pub const fn specificity(self) -> Confidence {
        self.specificity
    }

    /// Rarity score.
    #[must_use]
    pub const fn rarity(self) -> Confidence {
        self.rarity
    }

    /// Discriminative-power score.
    #[must_use]
    pub const fn discriminative_power(self) -> Confidence {
        self.discriminative_power
    }

    /// Source-independence score.
    #[must_use]
    pub const fn source_independence(self) -> Confidence {
        self.source_independence
    }

    /// Temporal-compatibility score.
    #[must_use]
    pub const fn temporal_compatibility(self) -> Confidence {
        self.temporal_compatibility
    }

    /// Transformation-resistance score.
    #[must_use]
    pub const fn transformation_resistance(self) -> Confidence {
        self.transformation_resistance
    }

    /// Provenance-quality score.
    #[must_use]
    pub const fn provenance_quality(self) -> Confidence {
        self.provenance_quality
    }

    /// Reproducibility score.
    #[must_use]
    pub const fn reproducibility(self) -> Confidence {
        self.reproducibility
    }

    /// Conservative arithmetic mean of the nine dimensions.
    ///
    /// The result remains an ordinal calibration score and must not be read as
    /// a posterior probability.
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

/// Known causes of dependent or duplicated reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyKind {
    /// Several reports copy one original report.
    CopiedReporting,
    /// Several sources use one common dataset.
    CommonDataset,
    /// Several sources depend on one provider.
    CommonProvider,
    /// Several observations derive from one common dependency.
    CommonDependency,
    /// A source is derived from another source.
    DerivativeSource,
    /// Several evidence links point to one observation.
    DuplicatedObservation,
}

/// An assessment of one canonical evidence link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceAssessment {
    evidence_id: EvidenceId,
    quality: EvidenceQuality,
    independence_group: Option<String>,
    dependency: Option<DependencyKind>,
    high_base_rate: bool,
    uncertainty: Confidence,
}

impl EvidenceAssessment {
    /// Creates an assessment for an evidence identifier.
    pub fn new(
        evidence_id: impl Into<String>,
        quality: EvidenceQuality,
    ) -> Result<Self, FusionError> {
        let evidence_id = require_text(evidence_id.into(), "evidence id")?;
        Ok(Self {
            evidence_id,
            quality,
            independence_group: None,
            dependency: None,
            high_base_rate: false,
            uncertainty: Confidence::new(0),
        })
    }

    /// Assigns a caller-defined independence/dependency group.
    ///
    /// Evidence in the same group is collapsed to the strongest item for each
    /// hypothesis and evidence role.
    #[must_use]
    pub fn in_group(mut self, group: impl Into<String>) -> Self {
        let group = group.into();
        self.independence_group = (!group.trim().is_empty()).then_some(group);
        self
    }

    /// Marks the dependency relationship represented by this assessment.
    #[must_use]
    pub fn with_dependency(mut self, dependency: DependencyKind) -> Self {
        self.dependency = Some(dependency);
        self
    }

    /// Marks support that should be removed during high-base-rate falsification.
    #[must_use]
    pub const fn high_base_rate(mut self) -> Self {
        self.high_base_rate = true;
        self
    }

    /// Records uncertainty in the assessment's assumptions.
    ///
    /// A value of 100 means the weight is removed during the perturbation
    /// pass; zero leaves the calibrated weight unchanged.
    #[must_use]
    pub const fn with_uncertainty(mut self, uncertainty: u8) -> Self {
        self.uncertainty = Confidence::new(uncertainty);
        self
    }

    /// Evidence identifier being assessed.
    #[must_use]
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    /// Nine-dimensional quality profile.
    #[must_use]
    pub const fn quality(&self) -> EvidenceQuality {
        self.quality
    }

    /// Explicit independence group, if supplied.
    #[must_use]
    pub fn independence_group(&self) -> Option<&str> {
        self.independence_group.as_deref()
    }

    /// Dependency classification, if supplied.
    #[must_use]
    pub const fn dependency(&self) -> Option<DependencyKind> {
        self.dependency
    }

    /// Whether this item is high-base-rate support.
    #[must_use]
    pub const fn is_high_base_rate(&self) -> bool {
        self.high_base_rate
    }

    /// Uncertainty penalty used by the perturbation pass.
    #[must_use]
    pub const fn uncertainty(&self) -> Confidence {
        self.uncertainty
    }
}

/// An expected observation used to detect missing support during falsification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedEvidence {
    id: String,
    hypothesis: HypothesisId,
    description: String,
    present: bool,
}

impl ExpectedEvidence {
    /// Creates an expected-evidence requirement, initially marked missing.
    pub fn new(
        id: impl Into<String>,
        hypothesis: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<Self, FusionError> {
        Ok(Self {
            id: require_text(id.into(), "expected evidence id")?,
            hypothesis: require_text(hypothesis.into(), "expected evidence hypothesis")?,
            description: require_text(description.into(), "expected evidence description")?,
            present: false,
        })
    }

    /// Marks the expected item as observed.
    #[must_use]
    pub const fn observed(mut self) -> Self {
        self.present = true;
        self
    }

    /// Marks the expected item as missing.
    #[must_use]
    pub const fn missing(mut self) -> Self {
        self.present = false;
        self
    }

    /// Expected-evidence identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Hypothesis for which the item is expected.
    #[must_use]
    pub fn hypothesis(&self) -> &str {
        &self.hypothesis
    }

    /// Human-readable expected item.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Whether the expected item was observed.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.present
    }
}

/// Fusion and falsification validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FusionError {
    /// A required textual value was empty.
    EmptyValue {
        /// Name of the empty field.
        field: &'static str,
    },
    /// One evidence identifier was assessed more than once.
    DuplicateAssessment {
        /// Duplicated evidence identifier.
        evidence_id: String,
    },
    /// One expected-evidence identifier was registered more than once.
    DuplicateExpectedEvidence {
        /// Duplicated expected-evidence identifier.
        expected_id: String,
    },
    /// An assessment references evidence absent from the canonical store.
    MissingEvidence {
        /// Missing evidence identifier.
        evidence_id: String,
    },
    /// Evidence points to an observation absent from the canonical store.
    MissingObservation {
        /// Evidence identifier containing the missing reference.
        evidence_id: String,
        /// Missing observation identifier.
        observation_id: ObservationId,
    },
    /// An observation points to a source absent from the canonical store.
    MissingSource {
        /// Observation identifier containing the missing reference.
        observation_id: ObservationId,
        /// Missing source identifier.
        source_id: SourceId,
    },
    /// A requested hypothesis is absent from the canonical store.
    MissingHypothesis {
        /// Missing hypothesis identifier.
        hypothesis_id: HypothesisId,
    },
    /// No candidate hypotheses were supplied or assessable.
    NoHypotheses,
}

impl fmt::Display for FusionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue { field } => write!(formatter, "{field} must not be empty"),
            Self::DuplicateAssessment { evidence_id } => {
                write!(
                    formatter,
                    "evidence `{evidence_id}` was assessed more than once"
                )
            }
            Self::DuplicateExpectedEvidence { expected_id } => {
                write!(
                    formatter,
                    "expected evidence `{expected_id}` was registered more than once"
                )
            }
            Self::MissingEvidence { evidence_id } => {
                write!(
                    formatter,
                    "assessment references missing evidence `{evidence_id}`"
                )
            }
            Self::MissingObservation {
                evidence_id,
                observation_id,
            } => write!(
                formatter,
                "evidence `{evidence_id}` references missing observation `{observation_id}`"
            ),
            Self::MissingSource {
                observation_id,
                source_id,
            } => write!(
                formatter,
                "observation `{observation_id}` references missing source `{source_id}`"
            ),
            Self::MissingHypothesis { hypothesis_id } => {
                write!(formatter, "missing hypothesis `{hypothesis_id}`")
            }
            Self::NoHypotheses => formatter.write_str("no hypotheses were available for fusion"),
        }
    }
}

impl std::error::Error for FusionError {}

impl crate::validation::EmptyValueError for FusionError {
    fn empty_value(field: &'static str) -> Self {
        Self::EmptyValue { field }
    }
}

fn require_text(value: String, field: &'static str) -> Result<String, FusionError> {
    crate::validation::require_text(value, field)
}

/// Score for one competing hypothesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypothesisScore {
    hypothesis: HypothesisId,
    support_score: u32,
    contradiction_score: u32,
    net_score: i32,
    calibrated_confidence: Confidence,
    supporting_evidence: Vec<EvidenceId>,
    contradicting_evidence: Vec<EvidenceId>,
    collapsed_evidence: Vec<EvidenceId>,
}

impl HypothesisScore {
    /// Hypothesis identifier.
    #[must_use]
    pub fn hypothesis(&self) -> &str {
        &self.hypothesis
    }

    /// Sum of strongest independent supporting weights.
    #[must_use]
    pub const fn support_score(&self) -> u32 {
        self.support_score
    }

    /// Sum of strongest independent contradictory weights.
    #[must_use]
    pub const fn contradiction_score(&self) -> u32 {
        self.contradiction_score
    }

    /// Support minus contradiction, an ordinal comparison score.
    #[must_use]
    pub const fn net_score(&self) -> i32 {
        self.net_score
    }

    /// Bounded ordinal confidence derived from the net score.
    #[must_use]
    pub const fn calibrated_confidence(&self) -> Confidence {
        self.calibrated_confidence
    }

    /// Evidence retained as independent support.
    #[must_use]
    pub fn supporting_evidence(&self) -> &[EvidenceId] {
        &self.supporting_evidence
    }

    /// Evidence retained as independent contradiction.
    #[must_use]
    pub fn contradicting_evidence(&self) -> &[EvidenceId] {
        &self.contradicting_evidence
    }

    /// Evidence suppressed by independence/dependency collapse.
    #[must_use]
    pub fn collapsed_evidence(&self) -> &[EvidenceId] {
        &self.collapsed_evidence
    }
}

/// Result of calibrated fusion over competing hypotheses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusionResult {
    scores: Vec<HypothesisScore>,
    leading_hypothesis: HypothesisId,
}

impl FusionResult {
    /// Identifier of the highest-scoring hypothesis.
    #[must_use]
    pub fn leading_hypothesis(&self) -> &str {
        &self.leading_hypothesis
    }

    /// Scores in descending net-score order.
    #[must_use]
    pub fn scores(&self) -> &[HypothesisScore] {
        &self.scores
    }

    /// Returns the score for a hypothesis.
    #[must_use]
    pub fn score(&self, hypothesis_id: &str) -> Option<&HypothesisScore> {
        self.scores
            .iter()
            .find(|score| score.hypothesis() == hypothesis_id)
    }

    /// Runs adversarial stress tests against the leading hypothesis.
    pub fn falsify(
        &self,
        fusion: &CalibratedEvidenceFusion,
        store: &EvidenceStore,
    ) -> Result<FalsificationReport, FusionError> {
        fusion.falsify_from(self, store)
    }
}

/// Outcome of adversarial falsification of one fusion result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalsificationReport {
    leading_hypothesis: HypothesisId,
    strongest_alternative: Option<HypothesisId>,
    baseline: HypothesisScore,
    without_high_base_rate: HypothesisScore,
    without_strongest_support: HypothesisScore,
    perturbed_uncertainty: HypothesisScore,
    contradictory_evidence: Vec<EvidenceId>,
    missing_expected_evidence: Vec<ExpectedEvidence>,
    removed_support: Option<EvidenceId>,
    survives: bool,
}

impl FalsificationReport {
    /// Leading hypothesis under the baseline fusion.
    #[must_use]
    pub fn leading_hypothesis(&self) -> &str {
        &self.leading_hypothesis
    }

    /// Strongest alternative under the baseline fusion, if one exists.
    #[must_use]
    pub fn strongest_alternative(&self) -> Option<&str> {
        self.strongest_alternative.as_deref()
    }

    /// Baseline score.
    #[must_use]
    pub const fn baseline(&self) -> &HypothesisScore {
        &self.baseline
    }

    /// Score after removing high-base-rate support.
    #[must_use]
    pub const fn without_high_base_rate(&self) -> &HypothesisScore {
        &self.without_high_base_rate
    }

    /// Score after removing the strongest independent supporting group.
    #[must_use]
    pub const fn without_strongest_support(&self) -> &HypothesisScore {
        &self.without_strongest_support
    }

    /// Score after perturbing uncertain assumptions.
    #[must_use]
    pub const fn perturbed_uncertainty(&self) -> &HypothesisScore {
        &self.perturbed_uncertainty
    }

    /// Contradictory evidence attached to the leading hypothesis.
    #[must_use]
    pub fn contradictory_evidence(&self) -> &[EvidenceId] {
        &self.contradictory_evidence
    }

    /// Expected evidence that remains missing.
    #[must_use]
    pub fn missing_expected_evidence(&self) -> &[ExpectedEvidence] {
        &self.missing_expected_evidence
    }

    /// Supporting evidence removed for the strongest-support stress test.
    #[must_use]
    pub fn removed_support(&self) -> Option<&str> {
        self.removed_support.as_deref()
    }

    /// Whether the leading hypothesis remains ahead through all stress tests.
    #[must_use]
    pub const fn survives(&self) -> bool {
        self.survives
    }
}

/// Mutable collection of calibrated assessments and expected-evidence checks.
#[derive(Debug, Clone, Default)]
pub struct CalibratedEvidenceFusion {
    assessments: BTreeMap<EvidenceId, EvidenceAssessment>,
    expected: BTreeMap<String, ExpectedEvidence>,
}

impl CalibratedEvidenceFusion {
    /// Creates an empty fusion policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            assessments: BTreeMap::new(),
            expected: BTreeMap::new(),
        }
    }

    /// Registers one quality assessment.
    pub fn add_assessment(&mut self, assessment: EvidenceAssessment) -> Result<(), FusionError> {
        let evidence_id = assessment.evidence_id().to_owned();
        if self.assessments.contains_key(&evidence_id) {
            return Err(FusionError::DuplicateAssessment { evidence_id });
        }
        self.assessments.insert(evidence_id, assessment);
        Ok(())
    }

    /// Registers an expected item for a hypothesis.
    pub fn add_expected_evidence(&mut self, expected: ExpectedEvidence) -> Result<(), FusionError> {
        let expected_id = expected.id().to_owned();
        if self.expected.contains_key(&expected_id) {
            return Err(FusionError::DuplicateExpectedEvidence { expected_id });
        }
        self.expected.insert(expected_id, expected);
        Ok(())
    }

    /// Read-only registered assessments.
    pub fn assessments(&self) -> impl Iterator<Item = &EvidenceAssessment> {
        self.assessments.values()
    }

    /// Read-only expected-evidence requirements.
    pub fn expected_evidence(&self) -> impl Iterator<Item = &ExpectedEvidence> {
        self.expected.values()
    }

    /// Fuses every hypothesis referenced by an assessment or expected item.
    pub fn fuse(&self, store: &EvidenceStore) -> Result<FusionResult, FusionError> {
        let mut hypotheses = BTreeSet::new();
        for assessment in self.assessments.values() {
            let evidence = self.evidence_for(store, assessment.evidence_id())?;
            hypotheses.insert(evidence.hypothesis().to_owned());
        }
        hypotheses.extend(
            self.expected
                .values()
                .map(|expected| expected.hypothesis.clone()),
        );
        let hypotheses: Vec<_> = hypotheses.into_iter().collect();
        self.fuse_hypotheses(store, &hypotheses)
    }

    /// Fuses an explicit set of competing hypotheses.
    pub fn fuse_hypotheses(
        &self,
        store: &EvidenceStore,
        hypotheses: &[HypothesisId],
    ) -> Result<FusionResult, FusionError> {
        self.fuse_with_options(store, hypotheses, ScoreOptions::default())
    }

    fn fuse_with_options(
        &self,
        store: &EvidenceStore,
        hypotheses: &[HypothesisId],
        options: ScoreOptions<'_>,
    ) -> Result<FusionResult, FusionError> {
        if hypotheses.is_empty() {
            return Err(FusionError::NoHypotheses);
        }
        let mut unique_hypotheses = BTreeSet::new();
        for hypothesis_id in hypotheses {
            if store.hypothesis(hypothesis_id).is_none() {
                return Err(FusionError::MissingHypothesis {
                    hypothesis_id: hypothesis_id.clone(),
                });
            }
            unique_hypotheses.insert(hypothesis_id.clone());
        }
        let mut scores = unique_hypotheses
            .iter()
            .map(|hypothesis_id| self.score_hypothesis(store, hypothesis_id, options))
            .collect::<Result<Vec<_>, _>>()?;
        scores.sort_by(|left, right| {
            right
                .net_score()
                .cmp(&left.net_score())
                .then_with(|| left.hypothesis().cmp(right.hypothesis()))
        });
        let leading_hypothesis = scores
            .first()
            .map(|score| score.hypothesis.clone())
            .ok_or(FusionError::NoHypotheses)?;
        Ok(FusionResult {
            scores,
            leading_hypothesis,
        })
    }

    fn score_hypothesis(
        &self,
        store: &EvidenceStore,
        hypothesis_id: &str,
        options: ScoreOptions<'_>,
    ) -> Result<HypothesisScore, FusionError> {
        let mut support = BTreeMap::<String, Contribution>::new();
        let mut contradiction = BTreeMap::<String, Contribution>::new();
        let mut collapsed = Vec::new();

        for assessment in self.assessments.values() {
            let evidence = self.evidence_for(store, assessment.evidence_id())?;
            if evidence.hypothesis() != hypothesis_id {
                continue;
            }
            let observation = store.observation(evidence.observation()).ok_or_else(|| {
                FusionError::MissingObservation {
                    evidence_id: evidence.id().to_owned(),
                    observation_id: evidence.observation().to_owned(),
                }
            })?;
            let source =
                store
                    .source(observation.source())
                    .ok_or_else(|| FusionError::MissingSource {
                        observation_id: observation.id().to_owned(),
                        source_id: observation.source().to_owned(),
                    })?;
            let group = assessment
                .independence_group()
                .map(str::to_owned)
                .unwrap_or_else(|| default_group(assessment, observation.id(), source.id()));
            if options.skip_group.is_some_and(|skip| skip == group) {
                continue;
            }
            let weight = calibrated_contribution(assessment, options);
            if weight == 0 {
                continue;
            }
            let contribution = Contribution {
                group,
                evidence_id: evidence.id().to_owned(),
                weight,
            };
            let target = match evidence.role() {
                EvidenceRole::Supporting => &mut support,
                EvidenceRole::Contradicting => &mut contradiction,
                EvidenceRole::Contextual => continue,
            };
            match target.get(&contribution.group) {
                Some(previous) if previous.weight >= contribution.weight => {
                    collapsed.push(contribution.evidence_id);
                }
                Some(previous) => {
                    collapsed.push(previous.evidence_id.clone());
                    target.insert(contribution.group.clone(), contribution);
                }
                None => {
                    target.insert(contribution.group.clone(), contribution);
                }
            }
        }

        let supporting_evidence: Vec<_> = support
            .values()
            .map(|contribution| contribution.evidence_id.clone())
            .collect();
        let contradicting_evidence: Vec<_> = contradiction
            .values()
            .map(|contribution| contribution.evidence_id.clone())
            .collect();
        let support_score = support
            .values()
            .map(|contribution| u32::from(contribution.weight))
            .sum();
        let contradiction_score = contradiction
            .values()
            .map(|contribution| u32::from(contribution.weight))
            .sum();
        let net_score = support_score as i32 - contradiction_score as i32;
        let calibrated_confidence = Confidence::new(net_score.clamp(0, 100) as u8);
        Ok(HypothesisScore {
            hypothesis: hypothesis_id.to_owned(),
            support_score,
            contradiction_score,
            net_score,
            calibrated_confidence,
            supporting_evidence,
            contradicting_evidence,
            collapsed_evidence: collapsed,
        })
    }

    fn evidence_for<'a>(
        &self,
        store: &'a EvidenceStore,
        evidence_id: &str,
    ) -> Result<&'a crate::Evidence, FusionError> {
        store
            .evidence(evidence_id)
            .ok_or_else(|| FusionError::MissingEvidence {
                evidence_id: evidence_id.to_owned(),
            })
    }

    fn falsify_from(
        &self,
        baseline_result: &FusionResult,
        store: &EvidenceStore,
    ) -> Result<FalsificationReport, FusionError> {
        let leading_hypothesis = baseline_result.leading_hypothesis.clone();
        let baseline = baseline_result
            .score(&leading_hypothesis)
            .cloned()
            .ok_or(FusionError::NoHypotheses)?;
        let strongest_alternative = baseline_result
            .scores
            .iter()
            .find(|score| score.hypothesis() != leading_hypothesis)
            .map(|score| score.hypothesis.clone());
        let candidates: Vec<_> = baseline_result
            .scores
            .iter()
            .map(|score| score.hypothesis.clone())
            .collect();
        let without_high_base_rate = self
            .fuse_with_options(
                store,
                &candidates,
                ScoreOptions {
                    remove_high_base_rate: true,
                    ..ScoreOptions::default()
                },
            )?
            .score(&leading_hypothesis)
            .cloned()
            .ok_or(FusionError::NoHypotheses)?;
        let strongest_group = self.strongest_support_group(store, &leading_hypothesis)?;
        let without_strongest_support = self
            .fuse_with_options(
                store,
                &candidates,
                ScoreOptions {
                    skip_group: strongest_group.as_deref(),
                    ..ScoreOptions::default()
                },
            )?
            .score(&leading_hypothesis)
            .cloned()
            .ok_or(FusionError::NoHypotheses)?;
        let perturbed_uncertainty = self
            .fuse_with_options(
                store,
                &candidates,
                ScoreOptions {
                    perturb_uncertainty: true,
                    ..ScoreOptions::default()
                },
            )?
            .score(&leading_hypothesis)
            .cloned()
            .ok_or(FusionError::NoHypotheses)?;
        let contradictory_evidence = baseline.contradicting_evidence.clone();
        let missing_expected_evidence = self
            .expected
            .values()
            .filter(|expected| {
                expected.hypothesis() == leading_hypothesis && !expected.is_present()
            })
            .cloned()
            .collect::<Vec<_>>();
        let survives = self.leading_survives(
            store,
            &candidates,
            &leading_hypothesis,
            strongest_group.as_deref(),
            &missing_expected_evidence,
        )?;
        Ok(FalsificationReport {
            leading_hypothesis,
            strongest_alternative,
            baseline,
            without_high_base_rate,
            without_strongest_support,
            perturbed_uncertainty,
            contradictory_evidence,
            missing_expected_evidence,
            removed_support: strongest_group.and_then(|group| {
                self.strongest_support_in_group(store, &baseline_result.leading_hypothesis, &group)
            }),
            survives,
        })
    }

    fn strongest_support_group(
        &self,
        store: &EvidenceStore,
        hypothesis_id: &str,
    ) -> Result<Option<String>, FusionError> {
        let mut groups = BTreeMap::<String, Contribution>::new();
        for assessment in self.assessments.values() {
            let evidence = self.evidence_for(store, assessment.evidence_id())?;
            if evidence.hypothesis() != hypothesis_id || evidence.role() != EvidenceRole::Supporting
            {
                continue;
            }
            let observation = store.observation(evidence.observation()).ok_or_else(|| {
                FusionError::MissingObservation {
                    evidence_id: evidence.id().to_owned(),
                    observation_id: evidence.observation().to_owned(),
                }
            })?;
            let source =
                store
                    .source(observation.source())
                    .ok_or_else(|| FusionError::MissingSource {
                        observation_id: observation.id().to_owned(),
                        source_id: observation.source().to_owned(),
                    })?;
            let group = assessment
                .independence_group()
                .map(str::to_owned)
                .unwrap_or_else(|| default_group(assessment, observation.id(), source.id()));
            let contribution = Contribution {
                group: group.clone(),
                evidence_id: evidence.id().to_owned(),
                weight: calibrated_contribution(assessment, ScoreOptions::default()),
            };
            if groups
                .get(&group)
                .is_none_or(|previous| previous.weight < contribution.weight)
            {
                groups.insert(group, contribution);
            }
        }
        Ok(groups
            .values()
            .max_by(|left, right| {
                left.weight
                    .cmp(&right.weight)
                    .then_with(|| right.group.cmp(&left.group))
            })
            .map(|contribution| contribution.group.clone()))
    }

    fn strongest_support_in_group(
        &self,
        store: &EvidenceStore,
        hypothesis_id: &str,
        group: &str,
    ) -> Option<EvidenceId> {
        self.assessments
            .values()
            .filter_map(|assessment| {
                let evidence = store.evidence(assessment.evidence_id())?;
                if evidence.hypothesis() != hypothesis_id
                    || evidence.role() != EvidenceRole::Supporting
                {
                    return None;
                }
                let observation = store.observation(evidence.observation())?;
                let source = store.source(observation.source())?;
                let candidate_group = assessment
                    .independence_group()
                    .map(str::to_owned)
                    .unwrap_or_else(|| default_group(assessment, observation.id(), source.id()));
                (candidate_group == group).then(|| {
                    (
                        calibrated_contribution(assessment, ScoreOptions::default()),
                        evidence.id().to_owned(),
                    )
                })
            })
            .max_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)))
            .map(|(_, evidence_id)| evidence_id)
    }

    fn leading_survives(
        &self,
        store: &EvidenceStore,
        candidates: &[HypothesisId],
        leading: &str,
        strongest_group: Option<&str>,
        missing_expected: &[ExpectedEvidence],
    ) -> Result<bool, FusionError> {
        if !missing_expected.is_empty() {
            return Ok(false);
        }
        let scenarios = [
            ScoreOptions {
                remove_high_base_rate: true,
                ..ScoreOptions::default()
            },
            ScoreOptions {
                skip_group: strongest_group,
                ..ScoreOptions::default()
            },
            ScoreOptions {
                perturb_uncertainty: true,
                ..ScoreOptions::default()
            },
        ];
        for options in scenarios {
            let result = self.fuse_with_options(store, candidates, options)?;
            if result.leading_hypothesis() != leading {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ScoreOptions<'a> {
    remove_high_base_rate: bool,
    perturb_uncertainty: bool,
    skip_group: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Contribution {
    group: String,
    evidence_id: EvidenceId,
    weight: u8,
}

fn default_group(assessment: &EvidenceAssessment, observation_id: &str, source_id: &str) -> String {
    match assessment.dependency() {
        Some(DependencyKind::DuplicatedObservation) => format!("observation:{observation_id}"),
        _ => format!("source:{source_id}"),
    }
}

fn calibrated_contribution(assessment: &EvidenceAssessment, options: ScoreOptions<'_>) -> u8 {
    if options.remove_high_base_rate && assessment.is_high_base_rate() {
        return 0;
    }
    let base = u32::from(assessment.quality().calibrated_weight());
    let uncertainty = if options.perturb_uncertainty {
        u32::from(assessment.uncertainty().value())
    } else {
        0
    };
    (base * (100 - uncertainty) / 100) as u8
}
