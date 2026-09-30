//! Metamorphic and differential verification for observable software behavior.
//!
//! The engine keeps required semantics separate from implementation details.
//! Callers provide executable inputs and an outcome adapter; the engine applies
//! relation checks, compares baseline and candidate outcomes, minimizes failing
//! inputs, and records enough metadata to lock a repaired case as a regression.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// An externally visible surface that can be part of the required contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationSurface {
    /// Inputs and their accepted representation.
    Inputs,
    /// Returned values or serialized output.
    Outputs,
    /// Persistent or externally visible state.
    State,
    /// Writes, notifications, messages, or other side effects.
    SideEffects,
    /// Error presence and error classification.
    Errors,
    /// Process or operation exit code.
    ExitCodes,
    /// Observable ordering of returned or emitted items.
    Ordering,
    /// Observable concurrency behavior.
    Concurrency,
    /// Restart behavior and restart-visible state.
    Restart,
    /// Recovery behavior after an interrupted or failed operation.
    Recovery,
    /// Runtime cost when performance is explicitly contractual.
    PerformanceWhenContractual,
}

/// A metamorphic relation supported by the verification engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetamorphicRelation {
    /// Equivalent inputs must produce equivalent observable behavior.
    Invariance,
    /// Applying the same transformation twice has the same result as once.
    Idempotence,
    /// Applying two transformations in either order has the same result.
    Commutativity,
    /// A contract metric must not decrease as the ordered input increases.
    Monotonicity,
    /// Applying a transformation and its inverse returns the original result.
    Reversibility,
    /// A transformation followed by a round trip preserves behavior.
    RoundTripConsistency,
    /// Partitioning and recombining an input preserves behavior.
    PartitionRecombinationEquivalence,
    /// Normalized and unnormalized forms preserve behavior.
    NormalizationEquivalence,
    /// Input permutation preserves behavior where ordering is not contractual.
    PermutationEquivalence,
}

/// The semantic contract that verification must preserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredSemantics {
    name: String,
    surfaces: BTreeSet<VerificationSurface>,
    relations: BTreeSet<MetamorphicRelation>,
}

impl RequiredSemantics {
    /// Creates a named semantic contract.
    pub fn new(name: impl Into<String>) -> Result<Self, VerificationError> {
        let name = require_text(name.into(), "semantics name")?;
        Ok(Self {
            name,
            surfaces: BTreeSet::new(),
            relations: BTreeSet::new(),
        })
    }

    /// Adds an observable surface to the contract.
    #[must_use]
    pub fn requires_surface(mut self, surface: VerificationSurface) -> Self {
        self.surfaces.insert(surface);
        self
    }

    /// Adds a metamorphic relation to the contract.
    #[must_use]
    pub fn requires_relation(mut self, relation: MetamorphicRelation) -> Self {
        self.relations.insert(relation);
        self
    }

    /// Adds every observable surface except the input representation.
    #[must_use]
    pub fn requires_all_observables(mut self) -> Self {
        for surface in observable_surfaces() {
            self.surfaces.insert(*surface);
        }
        self
    }

    /// Contract name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Configured observable surfaces.
    pub fn surfaces(&self) -> impl Iterator<Item = &VerificationSurface> {
        self.surfaces.iter()
    }

    /// Configured metamorphic relations.
    pub fn relations(&self) -> impl Iterator<Item = &MetamorphicRelation> {
        self.relations.iter()
    }

    /// Whether a surface is required.
    #[must_use]
    pub fn checks_surface(&self, surface: VerificationSurface) -> bool {
        self.surfaces.contains(&surface)
    }

    /// Whether a relation is part of this contract.
    #[must_use]
    pub fn allows_relation(&self, relation: MetamorphicRelation) -> bool {
        self.relations.is_empty() || self.relations.contains(&relation)
    }
}

/// An execution outcome normalized for comparison across implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutcome {
    input_representation: Option<Vec<u8>>,
    output: Vec<u8>,
    state: Vec<u8>,
    side_effects: Vec<String>,
    error: Option<String>,
    exit_code: Option<i32>,
    ordering: Vec<String>,
    concurrency: Vec<String>,
    restart: Vec<String>,
    recovery: Vec<String>,
    performance_ns: Option<u64>,
    monotonic_value: Option<i64>,
}

impl ExecutionOutcome {
    /// Creates a successful outcome with the supplied output.
    pub fn success(output: impl Into<Vec<u8>>) -> Self {
        Self {
            input_representation: None,
            output: output.into(),
            state: Vec::new(),
            side_effects: Vec::new(),
            error: None,
            exit_code: Some(0),
            ordering: Vec::new(),
            concurrency: Vec::new(),
            restart: Vec::new(),
            recovery: Vec::new(),
            performance_ns: None,
            monotonic_value: None,
        }
    }

    /// Creates a failed outcome with a descriptive error.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            error: Some(error.into()),
            exit_code: Some(1),
            ..Self::success(Vec::new())
        }
    }

    /// Replaces the returned output.
    #[must_use]
    pub fn with_output(mut self, output: impl Into<Vec<u8>>) -> Self {
        self.output = output.into();
        self
    }

    /// Records the input representation accepted by the implementation.
    #[must_use]
    pub fn with_input_representation(mut self, input: impl Into<Vec<u8>>) -> Self {
        self.input_representation = Some(input.into());
        self
    }

    /// Records externally visible state.
    #[must_use]
    pub fn with_state(mut self, state: impl Into<Vec<u8>>) -> Self {
        self.state = state.into();
        self
    }

    /// Records side effects in observed order.
    #[must_use]
    pub fn with_side_effects<I, S>(mut self, side_effects: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.side_effects = side_effects.into_iter().map(Into::into).collect();
        self
    }

    /// Records an error without changing the other outcome surfaces.
    #[must_use]
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Records the operation exit code.
    #[must_use]
    pub const fn with_exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = Some(exit_code);
        self
    }

    /// Records observable ordering.
    #[must_use]
    pub fn with_ordering<I, S>(mut self, ordering: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.ordering = ordering.into_iter().map(Into::into).collect();
        self
    }

    /// Records observable concurrency events.
    #[must_use]
    pub fn with_concurrency<I, S>(mut self, events: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.concurrency = events.into_iter().map(Into::into).collect();
        self
    }

    /// Records restart-visible behavior.
    #[must_use]
    pub fn with_restart<I, S>(mut self, events: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.restart = events.into_iter().map(Into::into).collect();
        self
    }

    /// Records recovery behavior.
    #[must_use]
    pub fn with_recovery<I, S>(mut self, events: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.recovery = events.into_iter().map(Into::into).collect();
        self
    }

    /// Records runtime in nanoseconds when performance is contractual.
    #[must_use]
    pub const fn with_performance_ns(mut self, performance_ns: u64) -> Self {
        self.performance_ns = Some(performance_ns);
        self
    }

    /// Records the ordered metric used by a monotonicity relation.
    #[must_use]
    pub const fn with_monotonic_value(mut self, value: i64) -> Self {
        self.monotonic_value = Some(value);
        self
    }

    /// Returned output.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// Input representation observed by the implementation, if captured.
    #[must_use]
    pub fn input_representation(&self) -> Option<&[u8]> {
        self.input_representation.as_deref()
    }

    /// Externally visible state.
    #[must_use]
    pub fn state(&self) -> &[u8] {
        &self.state
    }

    /// Side effects in observed order.
    #[must_use]
    pub fn side_effects(&self) -> &[String] {
        &self.side_effects
    }

    /// Error, if the operation failed.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Exit code, if the operation reports one.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Observable ordering.
    #[must_use]
    pub fn ordering(&self) -> &[String] {
        &self.ordering
    }

    /// Observable concurrency events.
    #[must_use]
    pub fn concurrency(&self) -> &[String] {
        &self.concurrency
    }

    /// Restart-visible behavior.
    #[must_use]
    pub fn restart(&self) -> &[String] {
        &self.restart
    }

    /// Recovery behavior.
    #[must_use]
    pub fn recovery(&self) -> &[String] {
        &self.recovery
    }

    /// Runtime in nanoseconds, if measured.
    #[must_use]
    pub const fn performance_ns(&self) -> Option<u64> {
        self.performance_ns
    }

    /// Monotonicity metric, if supplied.
    #[must_use]
    pub const fn monotonic_value(&self) -> Option<i64> {
        self.monotonic_value
    }

    fn differing_surfaces(
        &self,
        other: &Self,
        semantics: &RequiredSemantics,
    ) -> Vec<VerificationSurface> {
        let surfaces: Vec<VerificationSurface> = if semantics.surfaces.is_empty() {
            observable_surfaces().to_vec()
        } else {
            semantics.surfaces.iter().copied().collect()
        };
        surfaces
            .into_iter()
            .filter(|surface| match surface {
                VerificationSurface::Inputs => {
                    self.input_representation != other.input_representation
                }
                VerificationSurface::Outputs => self.output != other.output,
                VerificationSurface::State => self.state != other.state,
                VerificationSurface::SideEffects => self.side_effects != other.side_effects,
                VerificationSurface::Errors => self.error != other.error,
                VerificationSurface::ExitCodes => self.exit_code != other.exit_code,
                VerificationSurface::Ordering => self.ordering != other.ordering,
                VerificationSurface::Concurrency => self.concurrency != other.concurrency,
                VerificationSurface::Restart => self.restart != other.restart,
                VerificationSurface::Recovery => self.recovery != other.recovery,
                VerificationSurface::PerformanceWhenContractual => {
                    self.performance_ns != other.performance_ns
                }
            })
            .collect()
    }

    fn missing_surfaces(
        &self,
        other: &Self,
        semantics: &RequiredSemantics,
    ) -> Vec<VerificationSurface> {
        if semantics.surfaces.is_empty() {
            return Vec::new();
        }
        semantics
            .surfaces
            .iter()
            .copied()
            .filter(|surface| match surface {
                VerificationSurface::Inputs => {
                    self.input_representation.is_none() || other.input_representation.is_none()
                }
                VerificationSurface::PerformanceWhenContractual => {
                    self.performance_ns.is_none() || other.performance_ns.is_none()
                }
                VerificationSurface::Outputs
                | VerificationSurface::State
                | VerificationSurface::SideEffects
                | VerificationSurface::Errors
                | VerificationSurface::ExitCodes
                | VerificationSurface::Ordering
                | VerificationSurface::Concurrency
                | VerificationSurface::Restart
                | VerificationSurface::Recovery => false,
            })
            .collect()
    }
}

/// A concrete metamorphic test vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetamorphicTest {
    id: String,
    relation: MetamorphicRelation,
    inputs: Vec<Vec<u8>>,
    description: Option<String>,
}

impl MetamorphicTest {
    /// Creates a test vector for a relation.
    ///
    /// Invariance, commutativity, monotonicity, reversibility, round trips,
    /// partition recombination, normalization, and permutation use two inputs.
    /// Idempotence uses three inputs: original, once-transformed, and
    /// twice-transformed.
    pub fn new(
        id: impl Into<String>,
        relation: MetamorphicRelation,
        inputs: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Self, VerificationError> {
        let id = require_text(id.into(), "test id")?;
        let inputs: Vec<Vec<u8>> = inputs.into_iter().collect();
        let minimum = relation.minimum_inputs();
        let valid_count = (relation == MetamorphicRelation::Invariance && inputs.len() >= minimum)
            || (relation != MetamorphicRelation::Invariance && inputs.len() == minimum);
        if !valid_count {
            return Err(VerificationError::InvalidInputCount {
                test_id: id,
                relation,
                minimum,
                actual: inputs.len(),
            });
        }
        Ok(Self {
            id,
            relation,
            inputs,
            description: None,
        })
    }

    /// Generates a test vector by applying a transformation.
    ///
    /// For idempotence the transformation is applied twice. For other
    /// relations this helper creates an original/transformed pair; callers
    /// should use [`MetamorphicTest::new`] when a relation needs two distinct
    /// transformation paths, such as commutativity.
    pub fn generated<F>(
        id: impl Into<String>,
        relation: MetamorphicRelation,
        input: Vec<u8>,
        transform: F,
    ) -> Result<Self, VerificationError>
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, String>,
    {
        let id = id.into();
        let once = transform(&input).map_err(|reason| VerificationError::TransformationFailed {
            test_id: id.clone(),
            reason,
        })?;
        let inputs = if relation == MetamorphicRelation::Idempotence {
            let twice =
                transform(&once).map_err(|reason| VerificationError::TransformationFailed {
                    test_id: id.clone(),
                    reason,
                })?;
            vec![input, once, twice]
        } else {
            vec![input, once]
        };
        Self::new(id, relation, inputs)
    }

    /// Adds a human-readable test description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Stable test identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Relation exercised by the test.
    #[must_use]
    pub const fn relation(&self) -> MetamorphicRelation {
        self.relation
    }

    /// Inputs in the relation-specific order.
    #[must_use]
    pub fn inputs(&self) -> &[Vec<u8>] {
        &self.inputs
    }

    /// Human-readable description, if supplied.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

impl MetamorphicRelation {
    const fn minimum_inputs(self) -> usize {
        match self {
            Self::Idempotence => 3,
            Self::Invariance
            | Self::Commutativity
            | Self::Monotonicity
            | Self::Reversibility
            | Self::RoundTripConsistency
            | Self::PartitionRecombinationEquivalence
            | Self::NormalizationEquivalence
            | Self::PermutationEquivalence => 2,
        }
    }
}

/// One baseline/candidate input for differential verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DifferentialCase {
    id: String,
    input: Vec<u8>,
}

impl DifferentialCase {
    /// Creates a differential case.
    pub fn new(id: impl Into<String>, input: Vec<u8>) -> Result<Self, VerificationError> {
        Ok(Self {
            id: require_text(id.into(), "differential case id")?,
            input,
        })
    }

    /// Stable case identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Input supplied to both implementations.
    #[must_use]
    pub fn input(&self) -> &[u8] {
        &self.input
    }
}

/// A repair recorded after a failing verification case is understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairRecord {
    test_id: String,
    description: String,
}

impl RepairRecord {
    /// Creates a repair record.
    pub fn new(
        test_id: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<Self, VerificationError> {
        Ok(Self {
            test_id: require_text(test_id.into(), "repair test id")?,
            description: require_text(description.into(), "repair description")?,
        })
    }

    /// Test addressed by the repair.
    #[must_use]
    pub fn test_id(&self) -> &str {
        &self.test_id
    }

    /// Repair description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// A test vector that has been explicitly locked as a regression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegressionLock {
    id: String,
    test_id: String,
    relation: MetamorphicRelation,
    inputs: Vec<Vec<u8>>,
    reason: String,
}

impl RegressionLock {
    /// Creates a regression lock from a concrete test vector.
    pub fn new(
        id: impl Into<String>,
        test_id: impl Into<String>,
        relation: MetamorphicRelation,
        inputs: impl IntoIterator<Item = Vec<u8>>,
        reason: impl Into<String>,
    ) -> Result<Self, VerificationError> {
        let id = require_text(id.into(), "regression lock id")?;
        let test_id = require_text(test_id.into(), "regression test id")?;
        let reason = require_text(reason.into(), "regression lock reason")?;
        let inputs: Vec<Vec<u8>> = inputs.into_iter().collect();
        let minimum = relation.minimum_inputs();
        let valid_count = (relation == MetamorphicRelation::Invariance && inputs.len() >= minimum)
            || (relation != MetamorphicRelation::Invariance && inputs.len() == minimum);
        if !valid_count {
            return Err(VerificationError::InvalidInputCount {
                test_id,
                relation,
                minimum,
                actual: inputs.len(),
            });
        }
        Ok(Self {
            id,
            test_id,
            relation,
            inputs,
            reason,
        })
    }

    /// Stable lock identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Test covered by this lock.
    #[must_use]
    pub fn test_id(&self) -> &str {
        &self.test_id
    }

    /// Relation covered by this lock.
    #[must_use]
    pub const fn relation(&self) -> MetamorphicRelation {
        self.relation
    }

    /// Locked test inputs.
    #[must_use]
    pub fn inputs(&self) -> &[Vec<u8>] {
        &self.inputs
    }

    /// Reason the lock was created.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Root-cause category for a verification violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureCause {
    /// One observable surface diverged.
    ObservableDivergence(VerificationSurface),
    /// The ordered monotonicity metric decreased.
    MonotonicityViolation,
    /// A surface required by the contract was not captured.
    MissingContractualMeasurement(VerificationSurface),
}

/// One failed relation comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationViolation {
    test_id: String,
    relation: MetamorphicRelation,
    left_input_index: usize,
    right_input_index: usize,
    differing_surfaces: Vec<VerificationSurface>,
    baseline: ExecutionOutcome,
    variant: ExecutionOutcome,
    minimized_input: Option<Vec<u8>>,
    minimized_inputs: Option<Vec<Vec<u8>>>,
    cause: FailureCause,
}

impl VerificationViolation {
    /// Test that produced the violation.
    #[must_use]
    pub fn test_id(&self) -> &str {
        &self.test_id
    }

    /// Relation that was violated.
    #[must_use]
    pub const fn relation(&self) -> MetamorphicRelation {
        self.relation
    }

    /// Index of the left input in the test vector.
    #[must_use]
    pub const fn left_input_index(&self) -> usize {
        self.left_input_index
    }

    /// Index of the right input in the test vector.
    #[must_use]
    pub const fn right_input_index(&self) -> usize {
        self.right_input_index
    }

    /// Observable surfaces that differed.
    #[must_use]
    pub fn differing_surfaces(&self) -> &[VerificationSurface] {
        &self.differing_surfaces
    }

    /// Left-side execution outcome.
    #[must_use]
    pub const fn baseline(&self) -> &ExecutionOutcome {
        &self.baseline
    }

    /// Right-side execution outcome.
    #[must_use]
    pub const fn variant(&self) -> &ExecutionOutcome {
        &self.variant
    }

    /// Minimized input that still reproduces the relation failure, if found.
    #[must_use]
    pub fn minimized_input(&self) -> Option<&[u8]> {
        self.minimized_input.as_deref()
    }

    /// Complete minimized input vector that still reproduces the violation.
    #[must_use]
    pub fn minimized_inputs(&self) -> Option<&[Vec<u8>]> {
        self.minimized_inputs.as_deref()
    }

    /// Classified root cause.
    #[must_use]
    pub const fn root_cause(&self) -> FailureCause {
        self.cause
    }
}

/// Per-relation execution and defect-discovery feedback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyStatistics {
    relation: MetamorphicRelation,
    executions: u32,
    violations: u32,
    pressure: u32,
    retired_tests: u32,
}

impl FamilyStatistics {
    /// Relation summarized by this record.
    #[must_use]
    pub const fn relation(&self) -> MetamorphicRelation {
        self.relation
    }

    /// Number of test vectors executed.
    #[must_use]
    pub const fn executions(&self) -> u32 {
        self.executions
    }

    /// Number of relation violations discovered.
    #[must_use]
    pub const fn violations(&self) -> u32 {
        self.violations
    }

    /// Adaptive pressure assigned to this relation family.
    #[must_use]
    pub const fn pressure(&self) -> u32 {
        self.pressure
    }

    /// Number of explicitly retired tests in this family.
    #[must_use]
    pub const fn retired_tests(&self) -> u32 {
        self.retired_tests
    }
}

/// A differential mismatch between baseline and candidate implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DifferentialViolation {
    case_id: String,
    input: Vec<u8>,
    differing_surfaces: Vec<VerificationSurface>,
    baseline: ExecutionOutcome,
    candidate: ExecutionOutcome,
    minimized_input: Option<Vec<u8>>,
    cause: FailureCause,
}

impl DifferentialViolation {
    /// Differential case that failed.
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Input that produced the differential mismatch.
    #[must_use]
    pub fn input(&self) -> &[u8] {
        &self.input
    }

    /// Observable surfaces that differed.
    #[must_use]
    pub fn differing_surfaces(&self) -> &[VerificationSurface] {
        &self.differing_surfaces
    }

    /// Baseline outcome.
    #[must_use]
    pub const fn baseline(&self) -> &ExecutionOutcome {
        &self.baseline
    }

    /// Candidate outcome.
    #[must_use]
    pub const fn candidate(&self) -> &ExecutionOutcome {
        &self.candidate
    }

    /// Minimized input that still reproduces the mismatch, if found.
    #[must_use]
    pub fn minimized_input(&self) -> Option<&[u8]> {
        self.minimized_input.as_deref()
    }

    /// Classified root cause.
    #[must_use]
    pub const fn root_cause(&self) -> FailureCause {
        self.cause
    }
}

/// Result of baseline-versus-candidate differential execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DifferentialReport {
    executed_cases: usize,
    passed_cases: usize,
    inconclusive_cases: usize,
    violations: Vec<DifferentialViolation>,
}

impl DifferentialReport {
    /// Number of cases executed.
    #[must_use]
    pub const fn executed_cases(&self) -> usize {
        self.executed_cases
    }

    /// Number of cases with equivalent required behavior.
    #[must_use]
    pub const fn passed_cases(&self) -> usize {
        self.passed_cases
    }

    /// Number of cases missing a required measurement.
    #[must_use]
    pub const fn inconclusive_cases(&self) -> usize {
        self.inconclusive_cases
    }

    /// Differential violations.
    #[must_use]
    pub fn violations(&self) -> &[DifferentialViolation] {
        &self.violations
    }

    /// Whether every case passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.violations.is_empty() && self.inconclusive_cases == 0
    }
}

/// Result of executing a metamorphic verification plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    executed_tests: usize,
    passed_tests: usize,
    inconclusive_tests: usize,
    executed_test_ids: Vec<String>,
    inconclusive_test_ids: Vec<String>,
    retired_tests: Vec<String>,
    violations: Vec<VerificationViolation>,
    family_statistics: Vec<FamilyStatistics>,
    repairs: Vec<RepairRecord>,
    regression_locks: Vec<String>,
}

impl VerificationReport {
    /// Number of non-retired test vectors executed.
    #[must_use]
    pub const fn executed_tests(&self) -> usize {
        self.executed_tests
    }

    /// Number of test vectors with no detected violation.
    #[must_use]
    pub const fn passed_tests(&self) -> usize {
        self.passed_tests
    }

    /// Number of test vectors that could not establish a relation result.
    #[must_use]
    pub const fn inconclusive_tests(&self) -> usize {
        self.inconclusive_tests
    }

    /// Test identifiers executed during this run.
    #[must_use]
    pub fn executed_test_ids(&self) -> &[String] {
        &self.executed_test_ids
    }

    /// Test identifiers that lacked a required measurement.
    #[must_use]
    pub fn inconclusive_test_ids(&self) -> &[String] {
        &self.inconclusive_test_ids
    }

    /// Explicitly retired tests skipped by this run.
    #[must_use]
    pub fn retired_tests(&self) -> &[String] {
        &self.retired_tests
    }

    /// Relation violations discovered during this run.
    #[must_use]
    pub fn violations(&self) -> &[VerificationViolation] {
        &self.violations
    }

    /// Per-family execution feedback.
    #[must_use]
    pub fn family_statistics(&self) -> &[FamilyStatistics] {
        &self.family_statistics
    }

    /// Repairs recorded before this run.
    #[must_use]
    pub fn repairs(&self) -> &[RepairRecord] {
        &self.repairs
    }

    /// Regression lock identifiers included in this run.
    #[must_use]
    pub fn regression_locks(&self) -> &[String] {
        &self.regression_locks
    }

    /// Persists one executed result as a canonical metamorphic test record.
    ///
    /// The supplied observation identifiers are validated by
    /// [`crate::EvidenceStore`], so a report cannot silently create an
    /// untraceable verification record.
    pub fn persist_test(
        &self,
        store: &mut crate::EvidenceStore,
        test_id: &str,
        name: impl Into<String>,
        executed_at: crate::Timestamp,
        input_observations: impl IntoIterator<Item = String>,
        output_observations: impl IntoIterator<Item = String>,
    ) -> Result<(), VerificationError> {
        if !self.executed_test_ids.iter().any(|id| id == test_id) {
            return Err(VerificationError::MissingTest {
                test_id: test_id.to_owned(),
            });
        }
        let status = if self
            .violations
            .iter()
            .any(|violation| violation.test_id() == test_id)
        {
            crate::TestStatus::Failed
        } else if self.inconclusive_test_ids.iter().any(|id| id == test_id) {
            crate::TestStatus::Inconclusive
        } else {
            crate::TestStatus::Passed
        };
        let test = crate::Test::new(test_id, name, crate::TestType::Metamorphic)
            .map_err(|error| VerificationError::CanonicalStore { error })?
            .with_inputs(input_observations)
            .with_outputs(output_observations)
            .completed(status, executed_at);
        store
            .add_test(test)
            .map_err(|error| VerificationError::CanonicalStore { error })
    }

    /// Whether every executed test passed without inconclusive results.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.violations.is_empty() && self.inconclusive_tests == 0
    }
}

/// Errors in verification-plan construction or transformation generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// A required textual field was empty.
    EmptyValue {
        /// Empty field name.
        field: &'static str,
    },
    /// A test vector has too few relation inputs.
    InvalidInputCount {
        /// Test identifier.
        test_id: String,
        /// Relation requiring the inputs.
        relation: MetamorphicRelation,
        /// Minimum number of inputs.
        minimum: usize,
        /// Supplied number of inputs.
        actual: usize,
    },
    /// A test identifier was registered twice.
    DuplicateTest {
        /// Duplicated test identifier.
        test_id: String,
    },
    /// A lock identifier was registered twice.
    DuplicateRegressionLock {
        /// Duplicated lock identifier.
        lock_id: String,
    },
    /// A repair was registered twice for one test.
    DuplicateRepair {
        /// Duplicated test identifier.
        test_id: String,
    },
    /// A lock or repair refers to an unknown test.
    MissingTest {
        /// Unknown test identifier.
        test_id: String,
    },
    /// A test relation is outside the configured required contract.
    RelationNotRequired {
        /// Test identifier.
        test_id: String,
        /// Relation not enabled by the contract.
        relation: MetamorphicRelation,
    },
    /// A generated transformation failed.
    TransformationFailed {
        /// Test identifier.
        test_id: String,
        /// Transformation-provided reason.
        reason: String,
    },
    /// The verification result could not be recorded in the canonical store.
    CanonicalStore {
        /// Store validation failure.
        error: crate::ProvenanceError,
    },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue { field } => write!(formatter, "{field} must not be empty"),
            Self::InvalidInputCount {
                test_id,
                relation,
                minimum,
                actual,
            } => write!(
                formatter,
                "test `{test_id}` for {relation:?} requires {minimum} inputs, got {actual}"
            ),
            Self::DuplicateTest { test_id } => {
                write!(formatter, "test `{test_id}` was registered more than once")
            }
            Self::DuplicateRegressionLock { lock_id } => {
                write!(
                    formatter,
                    "regression lock `{lock_id}` was registered more than once"
                )
            }
            Self::DuplicateRepair { test_id } => {
                write!(
                    formatter,
                    "repair for test `{test_id}` was registered more than once"
                )
            }
            Self::MissingTest { test_id } => {
                write!(formatter, "unknown verification test `{test_id}`")
            }
            Self::RelationNotRequired { test_id, relation } => write!(
                formatter,
                "test `{test_id}` uses {relation:?}, which is not in the required contract"
            ),
            Self::TransformationFailed { test_id, reason } => {
                write!(
                    formatter,
                    "transformation for test `{test_id}` failed: {reason}"
                )
            }
            Self::CanonicalStore { error } => {
                write!(
                    formatter,
                    "canonical verification persistence failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for VerificationError {}

impl crate::validation::EmptyValueError for VerificationError {
    fn empty_value(field: &'static str) -> Self {
        Self::EmptyValue { field }
    }
}

fn require_text(value: String, field: &'static str) -> Result<String, VerificationError> {
    crate::validation::require_text(value, field)
}

/// Mutable metamorphic verification plan and adaptive feedback state.
#[derive(Debug, Clone)]
pub struct VerificationEngine {
    semantics: RequiredSemantics,
    tests: BTreeMap<String, MetamorphicTest>,
    retired: BTreeSet<String>,
    locks: BTreeMap<String, RegressionLock>,
    repairs: BTreeMap<String, RepairRecord>,
    family_feedback: BTreeMap<MetamorphicRelation, FamilyStatistics>,
}

impl VerificationEngine {
    /// Creates an empty verification plan for a semantic contract.
    #[must_use]
    pub fn new(semantics: RequiredSemantics) -> Self {
        Self {
            semantics,
            tests: BTreeMap::new(),
            retired: BTreeSet::new(),
            locks: BTreeMap::new(),
            repairs: BTreeMap::new(),
            family_feedback: BTreeMap::new(),
        }
    }

    /// Required semantic contract.
    #[must_use]
    pub const fn semantics(&self) -> &RequiredSemantics {
        &self.semantics
    }

    /// Registers a metamorphic test vector.
    pub fn add_test(&mut self, test: MetamorphicTest) -> Result<(), VerificationError> {
        let test_id = test.id().to_owned();
        if self.tests.contains_key(&test_id) {
            return Err(VerificationError::DuplicateTest { test_id });
        }
        self.tests.insert(test_id, test);
        Ok(())
    }

    /// Registers a regression lock for an existing test.
    pub fn add_regression_lock(&mut self, lock: RegressionLock) -> Result<(), VerificationError> {
        if !self.tests.contains_key(lock.test_id()) {
            return Err(VerificationError::MissingTest {
                test_id: lock.test_id().to_owned(),
            });
        }
        let lock_id = lock.id().to_owned();
        if self.locks.contains_key(&lock_id) {
            return Err(VerificationError::DuplicateRegressionLock { lock_id });
        }
        self.locks.insert(lock_id, lock);
        Ok(())
    }

    /// Records a repair for an existing test.
    pub fn record_repair(&mut self, repair: RepairRecord) -> Result<(), VerificationError> {
        if !self.tests.contains_key(repair.test_id()) {
            return Err(VerificationError::MissingTest {
                test_id: repair.test_id().to_owned(),
            });
        }
        let test_id = repair.test_id().to_owned();
        if self.repairs.contains_key(&test_id) {
            return Err(VerificationError::DuplicateRepair { test_id });
        }
        self.repairs.insert(test_id, repair);
        Ok(())
    }

    /// Retires a redundant low-yield test without deleting its history.
    pub fn retire_test(&mut self, test_id: &str) -> Result<(), VerificationError> {
        if !self.tests.contains_key(test_id) {
            return Err(VerificationError::MissingTest {
                test_id: test_id.to_owned(),
            });
        }
        self.retired.insert(test_id.to_owned());
        Ok(())
    }

    /// Returns a retired test to the active verification plan.
    pub fn reinstate_test(&mut self, test_id: &str) -> Result<(), VerificationError> {
        if !self.tests.contains_key(test_id) {
            return Err(VerificationError::MissingTest {
                test_id: test_id.to_owned(),
            });
        }
        self.retired.remove(test_id);
        Ok(())
    }

    /// Registered tests.
    pub fn tests(&self) -> impl Iterator<Item = &MetamorphicTest> {
        self.tests.values()
    }

    /// Registered regression locks.
    pub fn regression_locks(&self) -> impl Iterator<Item = &RegressionLock> {
        self.locks.values()
    }

    /// Recorded repairs.
    pub fn repairs(&self) -> impl Iterator<Item = &RepairRecord> {
        self.repairs.values()
    }

    /// Adaptive pressure for a relation family.
    #[must_use]
    pub fn family_pressure(&self, relation: MetamorphicRelation) -> u32 {
        self.family_feedback
            .get(&relation)
            .map_or(1, FamilyStatistics::pressure)
    }

    /// Relation families ordered by current adaptive pressure.
    #[must_use]
    pub fn prioritized_relations(&self) -> Vec<MetamorphicRelation> {
        let mut relations: Vec<_> = self.family_feedback.values().collect();
        relations.sort_by(|left, right| {
            right
                .pressure
                .cmp(&left.pressure)
                .then_with(|| left.relation.cmp(&right.relation))
        });
        relations
            .into_iter()
            .map(|statistics| statistics.relation)
            .collect()
    }

    /// Executes every active test and updates family feedback.
    pub fn verify<F>(&mut self, execute: F) -> Result<VerificationReport, VerificationError>
    where
        F: Fn(&[u8]) -> ExecutionOutcome,
    {
        let mut executed_tests = 0;
        let mut passed_tests = 0;
        let mut inconclusive_tests = 0;
        let mut executed_test_ids = Vec::new();
        let mut inconclusive_test_ids = Vec::new();
        let mut violations = Vec::new();
        let mut run_feedback: BTreeMap<MetamorphicRelation, (u32, u32)> = BTreeMap::new();

        for test in self.tests.values() {
            if self.retired.contains(test.id()) {
                continue;
            }
            if !self.semantics.allows_relation(test.relation()) {
                return Err(VerificationError::RelationNotRequired {
                    test_id: test.id().to_owned(),
                    relation: test.relation(),
                });
            }
            executed_tests += 1;
            executed_test_ids.push(test.id().to_owned());
            let outcomes: Vec<_> = test.inputs().iter().map(|input| execute(input)).collect();
            let evaluation = evaluate_test(test, &outcomes, &self.semantics);
            let feedback = run_feedback.entry(test.relation()).or_default();
            feedback.0 += 1;
            if evaluation.inconclusive {
                inconclusive_tests += 1;
                inconclusive_test_ids.push(test.id().to_owned());
            }
            if evaluation.violations.is_empty() && !evaluation.inconclusive {
                passed_tests += 1;
            }
            feedback.1 += evaluation.violations.len() as u32;
            for mut violation in evaluation.violations {
                let minimized_inputs =
                    minimize_violation(test, &violation, &execute, &self.semantics);
                violation.minimized_input = minimized_inputs.as_ref().and_then(|inputs| {
                    inputs
                        .get(violation.left_input_index)
                        .cloned()
                        .or_else(|| inputs.first().cloned())
                });
                violation.minimized_inputs = minimized_inputs;
                violations.push(violation);
            }
        }

        self.update_feedback(&run_feedback);
        let family_statistics = self.family_feedback.values().cloned().collect::<Vec<_>>();
        Ok(VerificationReport {
            executed_tests,
            passed_tests,
            inconclusive_tests,
            executed_test_ids,
            inconclusive_test_ids,
            retired_tests: self.retired.iter().cloned().collect(),
            violations,
            family_statistics,
            repairs: self.repairs.values().cloned().collect(),
            regression_locks: self.locks.keys().cloned().collect(),
        })
    }

    /// Compares baseline and candidate implementations over the supplied cases.
    pub fn differential<I, B, C>(&self, cases: I, baseline: B, candidate: C) -> DifferentialReport
    where
        I: IntoIterator<Item = DifferentialCase>,
        B: Fn(&[u8]) -> ExecutionOutcome,
        C: Fn(&[u8]) -> ExecutionOutcome,
    {
        let mut executed_cases = 0;
        let mut passed_cases = 0;
        let mut inconclusive_cases = 0;
        let mut violations = Vec::new();
        for case in cases {
            executed_cases += 1;
            let baseline_outcome = baseline(case.input());
            let candidate_outcome = candidate(case.input());
            if !baseline_outcome
                .missing_surfaces(&candidate_outcome, &self.semantics)
                .is_empty()
            {
                inconclusive_cases += 1;
                continue;
            }
            let differing_surfaces =
                baseline_outcome.differing_surfaces(&candidate_outcome, &self.semantics);
            if differing_surfaces.is_empty() {
                passed_cases += 1;
            } else {
                let cause = FailureCause::ObservableDivergence(differing_surfaces[0]);
                violations.push(DifferentialViolation {
                    case_id: case.id,
                    input: case.input,
                    differing_surfaces,
                    baseline: baseline_outcome,
                    candidate: candidate_outcome,
                    minimized_input: None,
                    cause,
                });
                let violation = violations
                    .last_mut()
                    .expect("the differential violation was just inserted");
                violation.minimized_input = minimize_differential_input(
                    &violation.input,
                    &violation.differing_surfaces,
                    &baseline,
                    &candidate,
                    &self.semantics,
                );
            }
        }
        DifferentialReport {
            executed_cases,
            passed_cases,
            inconclusive_cases,
            violations,
        }
    }

    fn update_feedback(&mut self, run_feedback: &BTreeMap<MetamorphicRelation, (u32, u32)>) {
        for (relation, (executions, violations)) in run_feedback {
            let statistics = self
                .family_feedback
                .entry(*relation)
                .or_insert(FamilyStatistics {
                    relation: *relation,
                    executions: 0,
                    violations: 0,
                    pressure: 1,
                    retired_tests: 0,
                });
            statistics.executions += executions;
            statistics.violations += violations;
            if *violations > 0 {
                statistics.pressure = statistics.pressure.saturating_add(*violations);
            } else if statistics.pressure > 1 {
                statistics.pressure -= 1;
            }
        }
        for relation in self.family_feedback.keys().copied().collect::<Vec<_>>() {
            let retired_tests = self
                .retired
                .iter()
                .filter(|test_id| {
                    self.tests
                        .get(*test_id)
                        .is_some_and(|test| test.relation() == relation)
                })
                .count() as u32;
            if let Some(statistics) = self.family_feedback.get_mut(&relation) {
                statistics.retired_tests = retired_tests;
            }
        }
    }
}

#[derive(Debug)]
struct TestEvaluation {
    violations: Vec<VerificationViolation>,
    inconclusive: bool,
}

#[derive(Debug)]
enum PairEvaluation {
    Pass,
    Inconclusive,
    Violation {
        surfaces: Vec<VerificationSurface>,
        cause: FailureCause,
    },
}

fn evaluate_test(
    test: &MetamorphicTest,
    outcomes: &[ExecutionOutcome],
    semantics: &RequiredSemantics,
) -> TestEvaluation {
    let pairs = relation_pairs(test.relation(), outcomes.len());
    let mut violations = Vec::new();
    let mut inconclusive = false;
    for (left_index, right_index) in pairs {
        match evaluate_pair(
            test.relation(),
            &outcomes[left_index],
            &outcomes[right_index],
            semantics,
        ) {
            PairEvaluation::Pass => {}
            PairEvaluation::Inconclusive => inconclusive = true,
            PairEvaluation::Violation { surfaces, cause } => {
                violations.push(VerificationViolation {
                    test_id: test.id().to_owned(),
                    relation: test.relation(),
                    left_input_index: left_index,
                    right_input_index: right_index,
                    differing_surfaces: surfaces,
                    baseline: outcomes[left_index].clone(),
                    variant: outcomes[right_index].clone(),
                    minimized_input: None,
                    minimized_inputs: None,
                    cause,
                });
            }
        }
    }
    TestEvaluation {
        violations,
        inconclusive,
    }
}

fn relation_pairs(relation: MetamorphicRelation, input_count: usize) -> Vec<(usize, usize)> {
    match relation {
        MetamorphicRelation::Invariance => (1..input_count).map(|index| (0, index)).collect(),
        MetamorphicRelation::Idempotence => vec![(1, 2)],
        MetamorphicRelation::Commutativity
        | MetamorphicRelation::Monotonicity
        | MetamorphicRelation::Reversibility
        | MetamorphicRelation::RoundTripConsistency
        | MetamorphicRelation::PartitionRecombinationEquivalence
        | MetamorphicRelation::NormalizationEquivalence
        | MetamorphicRelation::PermutationEquivalence => vec![(0, 1)],
    }
}

fn evaluate_pair(
    relation: MetamorphicRelation,
    left: &ExecutionOutcome,
    right: &ExecutionOutcome,
    semantics: &RequiredSemantics,
) -> PairEvaluation {
    let differing_surfaces = left.differing_surfaces(right, semantics);
    if !differing_surfaces.is_empty() {
        return PairEvaluation::Violation {
            cause: FailureCause::ObservableDivergence(differing_surfaces[0]),
            surfaces: differing_surfaces,
        };
    }
    if !left.missing_surfaces(right, semantics).is_empty() {
        return PairEvaluation::Inconclusive;
    }
    if relation == MetamorphicRelation::Monotonicity {
        return match (left.monotonic_value(), right.monotonic_value()) {
            (Some(left_value), Some(right_value)) if left_value <= right_value => {
                PairEvaluation::Pass
            }
            (Some(_), Some(_)) => PairEvaluation::Violation {
                surfaces: Vec::new(),
                cause: FailureCause::MonotonicityViolation,
            },
            _ => PairEvaluation::Inconclusive,
        };
    }
    PairEvaluation::Pass
}

fn minimize_violation<F>(
    test: &MetamorphicTest,
    violation: &VerificationViolation,
    execute: &F,
    semantics: &RequiredSemantics,
) -> Option<Vec<Vec<u8>>>
where
    F: Fn(&[u8]) -> ExecutionOutcome,
{
    let mut inputs = test.inputs().to_vec();
    for input_index in [violation.left_input_index, violation.right_input_index] {
        inputs = minimize_input(
            test,
            inputs,
            input_index,
            (violation.left_input_index, violation.right_input_index),
            violation.cause,
            &violation.differing_surfaces,
            execute,
            semantics,
        );
    }
    Some(inputs)
}

#[allow(clippy::too_many_arguments)]
fn minimize_input<F>(
    test: &MetamorphicTest,
    inputs: Vec<Vec<u8>>,
    input_index: usize,
    pair: (usize, usize),
    cause: FailureCause,
    surfaces: &[VerificationSurface],
    execute: &F,
    semantics: &RequiredSemantics,
) -> Vec<Vec<u8>>
where
    F: Fn(&[u8]) -> ExecutionOutcome,
{
    let mut current_inputs = inputs;
    let mut current = current_inputs[input_index].clone();
    let mut granularity = 2;
    loop {
        if current.is_empty() {
            break;
        }
        let chunk_size = current.len().div_ceil(granularity);
        let mut reduced = false;
        let mut start = 0;
        while start < current.len() {
            let end = (start + chunk_size).min(current.len());
            let mut candidate = current.clone();
            candidate.drain(start..end);
            let mut candidate_inputs = current_inputs.clone();
            candidate_inputs[input_index] = candidate.clone();
            let mut candidate_test = test.clone();
            candidate_test.inputs = candidate_inputs.clone();
            let outcomes: Vec<_> = candidate_test
                .inputs()
                .iter()
                .map(|input| execute(input))
                .collect();
            let remains_violation = match evaluate_pair(
                test.relation(),
                &outcomes[pair.0],
                &outcomes[pair.1],
                semantics,
            ) {
                PairEvaluation::Violation {
                    surfaces: candidate_surfaces,
                    cause: candidate_cause,
                } => candidate_cause == cause && candidate_surfaces == surfaces,
                PairEvaluation::Pass | PairEvaluation::Inconclusive => false,
            };
            if remains_violation {
                current = candidate;
                current_inputs = candidate_inputs;
                granularity = 2;
                reduced = true;
                break;
            }
            start = end;
        }
        if reduced {
            continue;
        }
        if granularity >= current.len() {
            break;
        }
        granularity = (granularity * 2).min(current.len());
    }
    current_inputs
}

fn minimize_differential_input<B, C>(
    input: &[u8],
    surfaces: &[VerificationSurface],
    baseline: &B,
    candidate: &C,
    semantics: &RequiredSemantics,
) -> Option<Vec<u8>>
where
    B: Fn(&[u8]) -> ExecutionOutcome,
    C: Fn(&[u8]) -> ExecutionOutcome,
{
    let mut current = input.to_vec();
    let mut granularity = 2;
    loop {
        if current.is_empty() {
            break;
        }
        let chunk_size = current.len().div_ceil(granularity);
        let mut reduced = false;
        let mut start = 0;
        while start < current.len() {
            let end = (start + chunk_size).min(current.len());
            let mut trial = current.clone();
            trial.drain(start..end);
            let baseline_outcome = baseline(&trial);
            let candidate_outcome = candidate(&trial);
            if baseline_outcome.differing_surfaces(&candidate_outcome, semantics) == surfaces {
                current = trial;
                granularity = 2;
                reduced = true;
                break;
            }
            start = end;
        }
        if reduced {
            continue;
        }
        if granularity >= current.len() {
            break;
        }
        granularity = (granularity * 2).min(current.len());
    }
    Some(current)
}

fn observable_surfaces() -> &'static [VerificationSurface] {
    &[
        VerificationSurface::Outputs,
        VerificationSurface::State,
        VerificationSurface::SideEffects,
        VerificationSurface::Errors,
        VerificationSurface::ExitCodes,
        VerificationSurface::Ordering,
        VerificationSurface::Concurrency,
        VerificationSurface::Restart,
        VerificationSurface::Recovery,
        VerificationSurface::PerformanceWhenContractual,
    ]
}
