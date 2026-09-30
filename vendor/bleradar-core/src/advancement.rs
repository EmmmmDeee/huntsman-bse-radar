//! Metamorphic software advancement gated by measured verification results.
//!
//! This module keeps an advancement proposal separate from its implementation.
//! A proposal is ranked using explicit factors, then evaluated through the
//! metamorphic and differential verification engine before it can be accepted
//! or integrated. A change is never accepted merely because it is plausible:
//! required semantics, measurable improvement, regression analysis,
//! falsification, and reproducibility must all pass.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use crate::{
    Confidence, DifferentialCase, DifferentialReport, VerificationEngine, VerificationError,
    VerificationReport,
};

/// Factors used to rank a proposed software transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvancementFactors {
    expected_net_benefit: Confidence,
    correctness_confidence: Confidence,
    reachability: Confidence,
    reversibility: Confidence,
    implementation_cost: u8,
    regression_risk: u8,
}

impl AdvancementFactors {
    /// Creates the six factors from bounded 0..=100 scores.
    ///
    /// Implementation cost and regression risk use 1..=100 because they are
    /// divisors in the priority formula; zero would falsely create an
    /// unbounded priority.
    pub fn new(
        expected_net_benefit: u8,
        correctness_confidence: u8,
        reachability: u8,
        reversibility: u8,
        implementation_cost: u8,
        regression_risk: u8,
    ) -> Result<Self, AdvancementError> {
        if implementation_cost == 0 {
            return Err(AdvancementError::InvalidFactor {
                factor: "implementation cost",
                value: implementation_cost,
            });
        }
        if regression_risk == 0 {
            return Err(AdvancementError::InvalidFactor {
                factor: "regression risk",
                value: regression_risk,
            });
        }
        Ok(Self {
            expected_net_benefit: Confidence::new(expected_net_benefit),
            correctness_confidence: Confidence::new(correctness_confidence),
            reachability: Confidence::new(reachability),
            reversibility: Confidence::new(reversibility),
            implementation_cost: implementation_cost.min(100),
            regression_risk: regression_risk.min(100),
        })
    }

    /// Expected net benefit score.
    #[must_use]
    pub const fn expected_net_benefit(self) -> Confidence {
        self.expected_net_benefit
    }

    /// Confidence that the proposed change is correct.
    #[must_use]
    pub const fn correctness_confidence(self) -> Confidence {
        self.correctness_confidence
    }

    /// Fraction of relevant behavior reachable by the change.
    #[must_use]
    pub const fn reachability(self) -> Confidence {
        self.reachability
    }

    /// Ease of reversing the change.
    #[must_use]
    pub const fn reversibility(self) -> Confidence {
        self.reversibility
    }

    /// Relative implementation cost, in the range 1..=100.
    #[must_use]
    pub const fn implementation_cost(self) -> u8 {
        self.implementation_cost
    }

    /// Relative regression risk, in the range 1..=100.
    #[must_use]
    pub const fn regression_risk(self) -> u8 {
        self.regression_risk
    }

    /// Computes the explicit ranking formula.
    #[must_use]
    pub const fn priority(self) -> AdvancementPriority {
        let numerator = self.expected_net_benefit.value() as u64
            * self.correctness_confidence.value() as u64
            * self.reachability.value() as u64
            * self.reversibility.value() as u64;
        let denominator = self.implementation_cost as u64 * self.regression_risk as u64;
        AdvancementPriority {
            numerator,
            denominator,
        }
    }
}

/// Exact rational representation of an advancement priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvancementPriority {
    numerator: u64,
    denominator: u64,
}

impl AdvancementPriority {
    /// Numerator of the ranking formula.
    #[must_use]
    pub const fn numerator(self) -> u64 {
        self.numerator
    }

    /// Denominator of the ranking formula.
    #[must_use]
    pub const fn denominator(self) -> u64 {
        self.denominator
    }

    /// Human-friendly fixed-point score, scaled by one million.
    #[must_use]
    pub fn scaled(self) -> u64 {
        self.numerator
            .saturating_mul(1_000_000)
            .checked_div(self.denominator)
            .unwrap_or(0)
    }
}

impl Ord for AdvancementPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.numerator as u128 * other.denominator as u128)
            .cmp(&(other.numerator as u128 * self.denominator as u128))
    }
}

impl PartialOrd for AdvancementPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A proposed implementation change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancementProposal {
    id: String,
    description: String,
    factors: AdvancementFactors,
    dependencies: Vec<String>,
    limiter: Option<String>,
}

impl AdvancementProposal {
    /// Creates a proposal with explicit ranking factors.
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        factors: AdvancementFactors,
    ) -> Result<Self, AdvancementError> {
        Ok(Self {
            id: require_text(id.into(), "proposal id")?,
            description: require_text(description.into(), "proposal description")?,
            factors,
            dependencies: Vec::new(),
            limiter: None,
        })
    }

    /// Records dependencies that constrain implementation or verification.
    #[must_use]
    pub fn with_dependencies<I, S>(mut self, dependencies: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.dependencies = dependencies.into_iter().map(Into::into).collect();
        self
    }

    /// Records the current limiting factor.
    #[must_use]
    pub fn limited_by(mut self, limiter: impl Into<String>) -> Self {
        self.limiter = Some(limiter.into());
        self
    }

    /// Stable proposal identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Human-readable proposal description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Explicit ranking factors.
    #[must_use]
    pub const fn factors(&self) -> AdvancementFactors {
        self.factors
    }

    /// Dependencies recorded for the proposal.
    #[must_use]
    pub fn dependencies(&self) -> &[String] {
        &self.dependencies
    }

    /// Current limiting factor, if identified.
    #[must_use]
    pub fn limiter(&self) -> Option<&str> {
        self.limiter.as_deref()
    }

    /// Priority computed from the proposal factors.
    #[must_use]
    pub const fn priority(&self) -> AdvancementPriority {
        self.factors.priority()
    }
}

/// Lifecycle state of an advancement proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvancementState {
    /// Registered but not yet evaluated.
    Proposed,
    /// Evaluation passed; integration is still explicit.
    Accepted,
    /// Evaluation failed one or more acceptance gates.
    Rejected,
    /// Accepted result was integrated into the active implementation.
    Integrated,
}

/// One ranked proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancementRanking {
    proposal_id: String,
    priority: AdvancementPriority,
    state: AdvancementState,
}

impl AdvancementRanking {
    /// Proposal identifier.
    #[must_use]
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    /// Formula-based priority.
    #[must_use]
    pub const fn priority(&self) -> AdvancementPriority {
        self.priority
    }

    /// Current proposal state.
    #[must_use]
    pub const fn state(&self) -> AdvancementState {
        self.state
    }
}

/// Direction of a benchmark metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MetricDirection {
    /// Larger values are improvements.
    HigherIsBetter,
    /// Smaller values are improvements.
    LowerIsBetter,
}

/// One measured baseline-versus-candidate metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkMetric {
    name: String,
    baseline: u64,
    candidate: u64,
    direction: MetricDirection,
    material_threshold: u64,
    explanation: Option<String>,
}

impl BenchmarkMetric {
    /// Creates a metric comparison with a one-unit materiality threshold.
    pub fn new(
        name: impl Into<String>,
        baseline: u64,
        candidate: u64,
        direction: MetricDirection,
    ) -> Result<Self, AdvancementError> {
        Ok(Self {
            name: require_text(name.into(), "benchmark metric name")?,
            baseline,
            candidate,
            direction,
            material_threshold: 1,
            explanation: None,
        })
    }

    /// Sets the minimum absolute change considered material.
    #[must_use]
    pub const fn with_material_threshold(mut self, threshold: u64) -> Self {
        self.material_threshold = if threshold == 0 { 1 } else { threshold };
        self
    }

    /// Explains a material regression without hiding it.
    #[must_use]
    pub fn explained_by(mut self, explanation: impl Into<String>) -> Self {
        let explanation = explanation.into();
        self.explanation = (!explanation.trim().is_empty()).then_some(explanation);
        self
    }

    /// Metric name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Baseline measurement.
    #[must_use]
    pub const fn baseline(&self) -> u64 {
        self.baseline
    }

    /// Candidate measurement.
    #[must_use]
    pub const fn candidate(&self) -> u64 {
        self.candidate
    }

    /// Metric direction.
    #[must_use]
    pub const fn direction(&self) -> MetricDirection {
        self.direction
    }

    /// Materiality threshold.
    #[must_use]
    pub const fn material_threshold(&self) -> u64 {
        self.material_threshold
    }

    /// Explanation for a material regression, if supplied.
    #[must_use]
    pub fn explanation(&self) -> Option<&str> {
        self.explanation.as_deref()
    }

    /// Absolute difference between baseline and candidate.
    #[must_use]
    pub const fn absolute_delta(&self) -> u64 {
        self.baseline.abs_diff(self.candidate)
    }

    /// Whether the metric shows a material improvement.
    #[must_use]
    pub const fn is_improvement(&self) -> bool {
        self.absolute_delta() >= self.material_threshold
            && match self.direction {
                MetricDirection::HigherIsBetter => self.candidate > self.baseline,
                MetricDirection::LowerIsBetter => self.candidate < self.baseline,
            }
    }

    /// Whether the metric shows a material regression.
    #[must_use]
    pub const fn is_material_regression(&self) -> bool {
        self.absolute_delta() >= self.material_threshold
            && match self.direction {
                MetricDirection::HigherIsBetter => self.candidate < self.baseline,
                MetricDirection::LowerIsBetter => self.candidate > self.baseline,
            }
    }

    /// Whether a material regression has an explicit explanation.
    #[must_use]
    pub fn is_explained_material_regression(&self) -> bool {
        self.is_material_regression() && self.explanation.is_some()
    }
}

/// Collection of benchmark measurements for one advancement evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkReport {
    metrics: Vec<BenchmarkMetric>,
}

impl BenchmarkReport {
    /// Creates a benchmark report and rejects duplicate metric names.
    pub fn new<I>(metrics: I) -> Result<Self, AdvancementError>
    where
        I: IntoIterator<Item = BenchmarkMetric>,
    {
        let mut report = Self {
            metrics: Vec::new(),
        };
        for metric in metrics {
            if report
                .metrics
                .iter()
                .any(|known| known.name() == metric.name())
            {
                return Err(AdvancementError::DuplicateMetric {
                    metric: metric.name().to_owned(),
                });
            }
            report.metrics.push(metric);
        }
        Ok(report)
    }

    /// Measured metrics.
    #[must_use]
    pub fn metrics(&self) -> &[BenchmarkMetric] {
        &self.metrics
    }

    /// Whether at least one metric materially improved.
    #[must_use]
    pub fn has_measurable_improvement(&self) -> bool {
        self.metrics.iter().any(BenchmarkMetric::is_improvement)
    }

    /// Material regressions, including explained ones.
    #[must_use]
    pub fn material_regressions(&self) -> Vec<&BenchmarkMetric> {
        self.metrics
            .iter()
            .filter(|metric| metric.is_material_regression())
            .collect()
    }

    /// Material regressions without an explicit explanation.
    #[must_use]
    pub fn unexplained_material_regressions(&self) -> Vec<&BenchmarkMetric> {
        self.metrics
            .iter()
            .filter(|metric| {
                metric.is_material_regression() && !metric.is_explained_material_regression()
            })
            .collect()
    }
}

/// Status of adversarial falsification for a proposed change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FalsificationStatus {
    /// The strongest alternatives and configured checks did not defeat it.
    Resistant,
    /// A contradiction or alternative defeated the proposal.
    Failed,
    /// The available checks could not establish resistance.
    Inconclusive,
}

/// Adversarial check recorded for an advancement proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FalsificationCheck {
    /// Search for the strongest competing explanation.
    StrongestAlternative,
    /// Search for contradictions.
    ContradictionSearch,
    /// Search for missing expected evidence.
    MissingExpectedEvidence,
    /// Remove high-base-rate support.
    HighBaseRateRemoval,
    /// Remove duplicated or dependent support.
    DuplicateSupportRemoval,
    /// Perturb uncertain assumptions.
    UncertaintyPerturbation,
    /// Explicitly records completion of the configured review.
    CompleteReview,
}

/// Result of one adversarial check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalsificationFinding {
    check: FalsificationCheck,
    passed: bool,
    detail: String,
}

impl FalsificationFinding {
    /// Creates one falsification finding.
    pub fn new(
        check: FalsificationCheck,
        passed: bool,
        detail: impl Into<String>,
    ) -> Result<Self, AdvancementError> {
        Ok(Self {
            check,
            passed,
            detail: require_text(detail.into(), "falsification detail")?,
        })
    }

    /// Check represented by the finding.
    #[must_use]
    pub const fn check(&self) -> FalsificationCheck {
        self.check
    }

    /// Whether this check passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }

    /// Human-readable finding detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Falsification evidence supplied to the advancement gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalsificationResult {
    status: FalsificationStatus,
    findings: Vec<FalsificationFinding>,
}

impl FalsificationResult {
    /// Creates a result with an explicit status.
    #[must_use]
    pub const fn new(status: FalsificationStatus) -> Self {
        Self {
            status,
            findings: Vec::new(),
        }
    }

    /// Creates a resistant result with an explicit completion finding.
    #[must_use]
    pub fn resistant() -> Self {
        Self {
            status: FalsificationStatus::Resistant,
            findings: vec![FalsificationFinding {
                check: FalsificationCheck::CompleteReview,
                passed: true,
                detail: "configured falsification review completed".to_owned(),
            }],
        }
    }

    /// Adds one check result.
    #[must_use]
    pub fn with_finding(mut self, finding: FalsificationFinding) -> Self {
        self.findings.push(finding);
        self
    }

    /// Overall falsification status.
    #[must_use]
    pub const fn status(&self) -> FalsificationStatus {
        self.status
    }

    /// Individual falsification findings.
    #[must_use]
    pub fn findings(&self) -> &[FalsificationFinding] {
        &self.findings
    }

    /// Whether all supplied checks support a resistant result.
    #[must_use]
    pub fn is_resistant(&self) -> bool {
        self.status == FalsificationStatus::Resistant
            && self.findings.iter().all(FalsificationFinding::passed)
    }
}

/// Inputs needed to evaluate one advancement proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancementExecution {
    cases: Vec<DifferentialCase>,
    benchmark: BenchmarkReport,
    falsification: FalsificationResult,
    reproducible: bool,
}

impl AdvancementExecution {
    /// Creates an advancement evaluation input.
    pub fn new<I>(
        cases: I,
        benchmark: BenchmarkReport,
        falsification: FalsificationResult,
        reproducible: bool,
    ) -> Self
    where
        I: IntoIterator<Item = DifferentialCase>,
    {
        Self {
            cases: cases.into_iter().collect(),
            benchmark,
            falsification,
            reproducible,
        }
    }

    /// Differential cases supplied to the evaluation.
    #[must_use]
    pub fn cases(&self) -> &[DifferentialCase] {
        &self.cases
    }

    /// Benchmark report supplied to the evaluation.
    #[must_use]
    pub const fn benchmark(&self) -> &BenchmarkReport {
        &self.benchmark
    }

    /// Falsification result supplied to the evaluation.
    #[must_use]
    pub const fn falsification(&self) -> &FalsificationResult {
        &self.falsification
    }

    /// Whether the measured result reproduced.
    #[must_use]
    pub const fn reproducible(&self) -> bool {
        self.reproducible
    }
}

/// Reason an advancement proposal was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvancementRejection {
    /// The captured baseline did not satisfy required semantics.
    BaselineSemanticsNotPreserved,
    /// The candidate did not satisfy required semantics.
    CandidateSemanticsNotPreserved,
    /// Baseline and candidate differed on a required surface.
    DifferentialMismatch,
    /// No benchmark metric materially improved.
    NoMeasurableImprovement,
    /// A material regression lacked an explanation.
    UnexplainedMaterialRegression,
    /// Falsification did not establish resistance.
    FalsificationNotResistant,
    /// The observed result was not reproducible.
    NotReproducible,
    /// No active metamorphic or differential cases were executed.
    InsufficientVerificationCoverage,
}

/// Accept/reject result for one advancement proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancementDecision {
    disposition: AdvancementState,
    rejection_reasons: Vec<AdvancementRejection>,
}

impl AdvancementDecision {
    /// Creates a decision from its rejection reasons.
    #[must_use]
    pub fn from_reasons(rejection_reasons: Vec<AdvancementRejection>) -> Self {
        let disposition = if rejection_reasons.is_empty() {
            AdvancementState::Accepted
        } else {
            AdvancementState::Rejected
        };
        Self {
            disposition,
            rejection_reasons,
        }
    }

    /// Whether all acceptance gates passed.
    #[must_use]
    pub const fn accepted(&self) -> bool {
        match self.disposition {
            AdvancementState::Accepted => true,
            AdvancementState::Proposed
            | AdvancementState::Rejected
            | AdvancementState::Integrated => false,
        }
    }

    /// Decision state.
    #[must_use]
    pub const fn disposition(&self) -> AdvancementState {
        self.disposition
    }

    /// Reasons for rejection, empty for an accepted decision.
    #[must_use]
    pub fn rejection_reasons(&self) -> &[AdvancementRejection] {
        &self.rejection_reasons
    }
}

/// Ordered phases completed by an advancement run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvancementPhase {
    /// Verify baseline and candidate required semantics.
    Verify,
    /// Execute baseline and candidate over the same cases.
    DifferentialExecute,
    /// Apply adversarial falsification results.
    Falsify,
    /// Compare measured benchmark metrics.
    Benchmark,
    /// Apply acceptance gates.
    AcceptOrReject,
    /// Mark an accepted proposal integrated.
    Integrate,
    /// Recompute priorities after integration.
    Recompute,
}

/// Complete evidence for one advancement evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancementRun {
    proposal_id: String,
    phases: Vec<AdvancementPhase>,
    baseline_verification: VerificationReport,
    candidate_verification: VerificationReport,
    differential: DifferentialReport,
    benchmark: BenchmarkReport,
    falsification: FalsificationResult,
    reproducible: bool,
    decision: AdvancementDecision,
}

impl AdvancementRun {
    /// Proposal evaluated by this run.
    #[must_use]
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    /// Phases completed by this run.
    #[must_use]
    pub fn phases(&self) -> &[AdvancementPhase] {
        &self.phases
    }

    /// Baseline semantic verification report.
    #[must_use]
    pub const fn baseline_verification(&self) -> &VerificationReport {
        &self.baseline_verification
    }

    /// Candidate semantic verification report.
    #[must_use]
    pub const fn candidate_verification(&self) -> &VerificationReport {
        &self.candidate_verification
    }

    /// Baseline-versus-candidate differential report.
    #[must_use]
    pub const fn differential(&self) -> &DifferentialReport {
        &self.differential
    }

    /// Benchmark comparison.
    #[must_use]
    pub const fn benchmark(&self) -> &BenchmarkReport {
        &self.benchmark
    }

    /// Adversarial falsification result.
    #[must_use]
    pub const fn falsification(&self) -> &FalsificationResult {
        &self.falsification
    }

    /// Whether the result reproduced.
    #[must_use]
    pub const fn reproducible(&self) -> bool {
        self.reproducible
    }

    /// Acceptance decision.
    #[must_use]
    pub const fn decision(&self) -> &AdvancementDecision {
        &self.decision
    }
}

/// Advancement-plan construction or evaluation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvancementError {
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
    /// A proposal identifier was registered twice.
    DuplicateProposal {
        /// Duplicated proposal identifier.
        proposal_id: String,
    },
    /// A benchmark metric name was registered twice.
    DuplicateMetric {
        /// Duplicated metric name.
        metric: String,
    },
    /// The requested proposal does not exist.
    MissingProposal {
        /// Missing proposal identifier.
        proposal_id: String,
    },
    /// The proposal is not in a state that permits the requested operation.
    InvalidState {
        /// Proposal identifier.
        proposal_id: String,
        /// Current state.
        state: AdvancementState,
    },
    /// The underlying verification engine rejected the run.
    Verification {
        /// Verification failure.
        error: VerificationError,
    },
}

impl fmt::Display for AdvancementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue { field } => write!(formatter, "{field} must not be empty"),
            Self::InvalidFactor { factor, value } => {
                write!(formatter, "{factor} must be greater than zero, got {value}")
            }
            Self::DuplicateProposal { proposal_id } => {
                write!(
                    formatter,
                    "proposal `{proposal_id}` was registered more than once"
                )
            }
            Self::DuplicateMetric { metric } => {
                write!(
                    formatter,
                    "benchmark metric `{metric}` was registered more than once"
                )
            }
            Self::MissingProposal { proposal_id } => {
                write!(formatter, "unknown advancement proposal `{proposal_id}`")
            }
            Self::InvalidState { proposal_id, state } => {
                write!(
                    formatter,
                    "proposal `{proposal_id}` is in invalid state {state:?}"
                )
            }
            Self::Verification { error } => write!(formatter, "verification failed: {error}"),
        }
    }
}

impl std::error::Error for AdvancementError {}

impl crate::validation::EmptyValueError for AdvancementError {
    fn empty_value(field: &'static str) -> Self {
        Self::EmptyValue { field }
    }
}

fn require_text(value: String, field: &'static str) -> Result<String, AdvancementError> {
    crate::validation::require_text(value, field)
}

/// Engine that ranks, verifies, and integrates metamorphic software changes.
#[derive(Debug, Clone)]
pub struct MetamorphicSoftwareAdvancementEngine {
    verification: VerificationEngine,
    proposals: BTreeMap<String, AdvancementProposal>,
    states: BTreeMap<String, AdvancementState>,
    runs: BTreeMap<String, AdvancementRun>,
}

impl MetamorphicSoftwareAdvancementEngine {
    /// Creates an advancement engine backed by the required verification plan.
    #[must_use]
    pub fn new(verification: VerificationEngine) -> Self {
        Self {
            verification,
            proposals: BTreeMap::new(),
            states: BTreeMap::new(),
            runs: BTreeMap::new(),
        }
    }

    /// Shared metamorphic/differential verification engine.
    #[must_use]
    pub const fn verification(&self) -> &VerificationEngine {
        &self.verification
    }

    /// Mutable access to the shared verification plan.
    #[must_use]
    pub const fn verification_mut(&mut self) -> &mut VerificationEngine {
        &mut self.verification
    }

    /// Registers a proposal for ranking and later evaluation.
    pub fn add_proposal(&mut self, proposal: AdvancementProposal) -> Result<(), AdvancementError> {
        let proposal_id = proposal.id().to_owned();
        if self.proposals.contains_key(&proposal_id) {
            return Err(AdvancementError::DuplicateProposal { proposal_id });
        }
        self.states
            .insert(proposal_id.clone(), AdvancementState::Proposed);
        self.proposals.insert(proposal_id, proposal);
        Ok(())
    }

    /// Returns a registered proposal.
    #[must_use]
    pub fn proposal(&self, proposal_id: &str) -> Option<&AdvancementProposal> {
        self.proposals.get(proposal_id)
    }

    /// Returns the current proposal state.
    #[must_use]
    pub fn state(&self, proposal_id: &str) -> Option<AdvancementState> {
        self.states.get(proposal_id).copied()
    }

    /// Returns the latest evaluation run.
    #[must_use]
    pub fn run(&self, proposal_id: &str) -> Option<&AdvancementRun> {
        self.runs.get(proposal_id)
    }

    /// Returns proposals ordered by descending priority.
    #[must_use]
    pub fn ranked_proposals(&self) -> Vec<AdvancementRanking> {
        let mut rankings: Vec<_> = self
            .proposals
            .values()
            .filter_map(|proposal| {
                let state = self.state(proposal.id())?;
                (state != AdvancementState::Rejected && state != AdvancementState::Integrated)
                    .then_some(AdvancementRanking {
                        proposal_id: proposal.id().to_owned(),
                        priority: proposal.priority(),
                        state,
                    })
            })
            .collect();
        rankings.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.proposal_id.cmp(&right.proposal_id))
        });
        rankings
    }

    /// Alias for recomputing proposal priority after state changes.
    #[must_use]
    pub fn recompute_rankings(&self) -> Vec<AdvancementRanking> {
        self.ranked_proposals()
    }

    /// Evaluates baseline and candidate implementations through all gates.
    pub fn evaluate<B, C>(
        &mut self,
        proposal_id: &str,
        execution: AdvancementExecution,
        baseline: B,
        candidate: C,
    ) -> Result<AdvancementDecision, AdvancementError>
    where
        B: Fn(&[u8]) -> crate::ExecutionOutcome,
        C: Fn(&[u8]) -> crate::ExecutionOutcome,
    {
        let state = self
            .state(proposal_id)
            .ok_or_else(|| AdvancementError::MissingProposal {
                proposal_id: proposal_id.to_owned(),
            })?;
        if state == AdvancementState::Integrated || state == AdvancementState::Accepted {
            return Err(AdvancementError::InvalidState {
                proposal_id: proposal_id.to_owned(),
                state,
            });
        }

        let baseline_verification = self
            .verification
            .verify(&baseline)
            .map_err(|error| AdvancementError::Verification { error })?;
        let candidate_verification = self
            .verification
            .verify(&candidate)
            .map_err(|error| AdvancementError::Verification { error })?;
        let differential =
            self.verification
                .differential(execution.cases.clone(), &baseline, &candidate);

        let mut rejection_reasons = Vec::new();
        if !baseline_verification.passed() {
            rejection_reasons.push(AdvancementRejection::BaselineSemanticsNotPreserved);
        }
        if !candidate_verification.passed() {
            rejection_reasons.push(AdvancementRejection::CandidateSemanticsNotPreserved);
        }
        if !differential.passed() {
            rejection_reasons.push(AdvancementRejection::DifferentialMismatch);
        }
        if baseline_verification.executed_tests() == 0
            || candidate_verification.executed_tests() == 0
            || differential.executed_cases() == 0
        {
            rejection_reasons.push(AdvancementRejection::InsufficientVerificationCoverage);
        }
        if !execution.benchmark.has_measurable_improvement() {
            rejection_reasons.push(AdvancementRejection::NoMeasurableImprovement);
        }
        if !execution
            .benchmark
            .unexplained_material_regressions()
            .is_empty()
        {
            rejection_reasons.push(AdvancementRejection::UnexplainedMaterialRegression);
        }
        if !execution.falsification.is_resistant() {
            rejection_reasons.push(AdvancementRejection::FalsificationNotResistant);
        }
        if !execution.reproducible {
            rejection_reasons.push(AdvancementRejection::NotReproducible);
        }

        let decision = AdvancementDecision::from_reasons(rejection_reasons);
        let run = AdvancementRun {
            proposal_id: proposal_id.to_owned(),
            phases: vec![
                AdvancementPhase::Verify,
                AdvancementPhase::DifferentialExecute,
                AdvancementPhase::Falsify,
                AdvancementPhase::Benchmark,
                AdvancementPhase::AcceptOrReject,
            ],
            baseline_verification,
            candidate_verification,
            differential,
            benchmark: execution.benchmark,
            falsification: execution.falsification,
            reproducible: execution.reproducible,
            decision: decision.clone(),
        };
        self.states
            .insert(proposal_id.to_owned(), decision.disposition());
        self.runs.insert(proposal_id.to_owned(), run);
        Ok(decision)
    }

    /// Integrates an accepted proposal and recomputes the remaining ranking.
    pub fn integrate(
        &mut self,
        proposal_id: &str,
    ) -> Result<Vec<AdvancementRanking>, AdvancementError> {
        let state = self
            .state(proposal_id)
            .ok_or_else(|| AdvancementError::MissingProposal {
                proposal_id: proposal_id.to_owned(),
            })?;
        if state != AdvancementState::Accepted {
            return Err(AdvancementError::InvalidState {
                proposal_id: proposal_id.to_owned(),
                state,
            });
        }
        self.states
            .insert(proposal_id.to_owned(), AdvancementState::Integrated);
        if let Some(run) = self.runs.get_mut(proposal_id) {
            run.phases.push(AdvancementPhase::Integrate);
            run.phases.push(AdvancementPhase::Recompute);
        }
        Ok(self.recompute_rankings())
    }
}

/// Backwards-friendly shorter name for the advancement engine.
pub type SoftwareAdvancementEngine = MetamorphicSoftwareAdvancementEngine;
