//! Random-operation campaign over `VerificationEngine`
//! (`docs/AUTONOMOUS_DECISIONS.md` #68): random required semantics (explicit
//! surface subsets or every observable surface, one to three relations),
//! random metamorphic tests (every relation, minimum and larger input
//! counts, random bytes), deterministic but adversarial executors (output
//! transforms, failures, states, side effects, exit codes, missing
//! input-representation and performance measurements, monotonic values),
//! random differential cases, and retire / reinstate / lock / repair
//! transitions. Oracles after every `verify` and `differential`: no panic;
//! `RelationNotRequired` refusals leave the engine's feedback untouched;
//! executed, inconclusive, passed and retired accounting agrees with an
//! independent recount; every violation names an executed test, valid input
//! indices, a cause consistent with its differing surfaces, and minimized
//! inputs that are subsequences of the originals, unchanged outside the
//! violating pair, and that still fail with the same cause and surfaces when
//! re-verified from scratch; differential outcomes, their differing surfaces,
//! inconclusiveness and minimized inputs agree with a reference comparison
//! written from the surface definitions; family statistics accumulate
//! executions, violations, pressure and retirements exactly. Scale with
//! `BLERADAR_VERIFICATION_CAMPAIGN_SEQUENCES`, reseed with
//! `BLERADAR_VERIFICATION_CAMPAIGN_SEED`; a failure prints the seed.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use bleradar_core::{
    DifferentialCase, ExecutionOutcome, FailureCause, MetamorphicRelation, MetamorphicTest,
    RegressionLock, RepairRecord, RequiredSemantics, VerificationEngine, VerificationError,
    VerificationSurface,
};

const DEFAULT_SEQUENCES: u64 = 150;
const OPS_PER_SEQUENCE: usize = 24;
const DEFAULT_SEED: u64 = 0x0517_2026_0910_7E51;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, p: f64) -> bool {
        ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
    }
}

const RELATIONS: [MetamorphicRelation; 9] = [
    MetamorphicRelation::Invariance,
    MetamorphicRelation::Idempotence,
    MetamorphicRelation::Commutativity,
    MetamorphicRelation::Monotonicity,
    MetamorphicRelation::Reversibility,
    MetamorphicRelation::RoundTripConsistency,
    MetamorphicRelation::PartitionRecombinationEquivalence,
    MetamorphicRelation::NormalizationEquivalence,
    MetamorphicRelation::PermutationEquivalence,
];

const SURFACES: [VerificationSurface; 11] = [
    VerificationSurface::Inputs,
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
];

/// The surfaces compared when a contract names none: every observable one,
/// which excludes `Inputs`.
const OBSERVABLE: [VerificationSurface; 10] = [
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
];

fn minimum_inputs(relation: MetamorphicRelation) -> usize {
    if relation == MetamorphicRelation::Idempotence {
        3
    } else {
        2
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A deterministic executor whose behaviour is chosen per sequence.
#[derive(Clone, Copy)]
struct Executor {
    transform: u8,
    fail_on_ff: bool,
    state_mod: u8,
    side_effect_mod: u8,
    exit_code_mod: u8,
    input_representation: bool,
    performance: bool,
    monotonic: bool,
    ordering_mod: u8,
}

impl Executor {
    fn random(rng: &mut Rng) -> Self {
        Self {
            transform: rng.below(6) as u8,
            fail_on_ff: rng.chance(0.6),
            state_mod: rng.below(5) as u8,
            side_effect_mod: rng.below(5) as u8,
            exit_code_mod: rng.below(4) as u8,
            input_representation: rng.chance(0.6),
            performance: rng.chance(0.5),
            monotonic: rng.chance(0.7),
            ordering_mod: rng.below(4) as u8,
        }
    }

    fn run(&self, input: &[u8]) -> ExecutionOutcome {
        let output: Vec<u8> = match self.transform {
            0 => input.to_vec(),
            1 => input.iter().map(u8::to_ascii_uppercase).collect(),
            2 => {
                let mut sorted = input.to_vec();
                sorted.sort_unstable();
                sorted
            }
            3 => input.iter().rev().copied().collect(),
            4 => input.iter().copied().filter(|b| *b != b':').collect(),
            _ => b"constant".to_vec(),
        };
        let mut outcome = if self.fail_on_ff && input.contains(&0xFF) {
            ExecutionOutcome::failure("boom").with_output(output.clone())
        } else {
            ExecutionOutcome::success(output.clone())
        };
        if self.state_mod > 0 && input.len().is_multiple_of(usize::from(self.state_mod)) {
            outcome = outcome.with_state(vec![input.len() as u8]);
        }
        if self.side_effect_mod > 0
            && !input.is_empty()
            && input[0].is_multiple_of(self.side_effect_mod)
        {
            outcome = outcome.with_side_effects([format!("effect-{}", input[0] % 3)]);
        }
        if self.exit_code_mod > 0 && input.len() % usize::from(self.exit_code_mod) == 1 {
            outcome = outcome.with_exit_code(2);
        }
        if self.input_representation {
            outcome = outcome.with_input_representation(input.to_vec());
        }
        if self.performance && input.len() % 3 != 2 {
            outcome = outcome.with_performance_ns(1_000 + input.len() as u64 * 10);
        }
        if self.monotonic {
            outcome = outcome.with_monotonic_value(input.iter().map(|b| i64::from(*b)).sum());
        }
        if self.ordering_mod > 0 && output.len().is_multiple_of(usize::from(self.ordering_mod)) {
            outcome = outcome.with_ordering(["first", "second"]);
        }
        outcome
    }
}

// ------------------------------------------------------------- reference --

fn surfaces_of(semantics: &RequiredSemantics) -> Vec<VerificationSurface> {
    let explicit: Vec<VerificationSurface> = semantics.surfaces().copied().collect();
    if explicit.is_empty() {
        OBSERVABLE.to_vec()
    } else {
        explicit
    }
}

fn differs(
    left: &ExecutionOutcome,
    right: &ExecutionOutcome,
    surface: VerificationSurface,
) -> bool {
    match surface {
        VerificationSurface::Inputs => left.input_representation() != right.input_representation(),
        VerificationSurface::Outputs => left.output() != right.output(),
        VerificationSurface::State => left.state() != right.state(),
        VerificationSurface::SideEffects => left.side_effects() != right.side_effects(),
        VerificationSurface::Errors => left.error() != right.error(),
        VerificationSurface::ExitCodes => left.exit_code() != right.exit_code(),
        VerificationSurface::Ordering => left.ordering() != right.ordering(),
        VerificationSurface::Concurrency => left.concurrency() != right.concurrency(),
        VerificationSurface::Restart => left.restart() != right.restart(),
        VerificationSurface::Recovery => left.recovery() != right.recovery(),
        VerificationSurface::PerformanceWhenContractual => {
            left.performance_ns() != right.performance_ns()
        }
    }
}

fn differing_surfaces(
    semantics: &RequiredSemantics,
    left: &ExecutionOutcome,
    right: &ExecutionOutcome,
) -> Vec<VerificationSurface> {
    surfaces_of(semantics)
        .into_iter()
        .filter(|surface| differs(left, right, *surface))
        .collect()
}

fn missing(
    semantics: &RequiredSemantics,
    left: &ExecutionOutcome,
    right: &ExecutionOutcome,
) -> bool {
    semantics.surfaces().any(|surface| match surface {
        VerificationSurface::Inputs => {
            left.input_representation().is_none() || right.input_representation().is_none()
        }
        VerificationSurface::PerformanceWhenContractual => {
            left.performance_ns().is_none() || right.performance_ns().is_none()
        }
        _ => false,
    })
}

fn is_subsequence(part: &[u8], whole: &[u8]) -> bool {
    let mut position = 0;
    for byte in whole {
        if position < part.len() && part[position] == *byte {
            position += 1;
        }
    }
    position == part.len()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct Family {
    executions: u32,
    violations: u32,
    pressure: u32,
    retired: u32,
}

fn expected_family_update(
    families: &mut BTreeMap<MetamorphicRelation, Family>,
    run: &BTreeMap<MetamorphicRelation, (u32, u32)>,
    engine: &VerificationEngine,
    retired: &BTreeSet<String>,
) -> u64 {
    let mut decays = 0;
    for (relation, (executions, violations)) in run {
        let family = families.entry(*relation).or_insert(Family {
            pressure: 1,
            ..Family::default()
        });
        family.executions += executions;
        family.violations += violations;
        if *violations > 0 {
            family.pressure = family.pressure.saturating_add(*violations);
        } else if family.pressure > 1 {
            family.pressure -= 1;
            decays += 1;
        }
    }
    for (relation, family) in families.iter_mut() {
        family.retired = engine
            .tests()
            .filter(|test| test.relation() == *relation && retired.contains(test.id()))
            .count() as u32;
    }
    decays
}

/// The campaign's own record of the engine's state, kept in step with every
/// accepted transition so reports can be checked against it.
#[derive(Default)]
struct Bookkeeping {
    retired: BTreeSet<String>,
    locks: BTreeSet<String>,
    repairs: BTreeSet<String>,
    families: BTreeMap<MetamorphicRelation, Family>,
    decays: u64,
}

fn check_verify(
    engine: &mut VerificationEngine,
    semantics: &RequiredSemantics,
    executor: Executor,
    books: &mut Bookkeeping,
) -> Result<bool, String> {
    let Bookkeeping {
        retired,
        locks,
        repairs,
        families,
        decays,
    } = books;
    let tests: Vec<MetamorphicTest> = engine.tests().cloned().collect();
    let pressure_before: Vec<(MetamorphicRelation, u32)> = RELATIONS
        .iter()
        .map(|relation| (*relation, engine.family_pressure(*relation)))
        .collect();
    let expected_refusal = tests
        .iter()
        .filter(|test| !retired.contains(test.id()))
        .find(|test| !semantics.allows_relation(test.relation()))
        .map(|test| test.id().to_owned());
    let report = match engine.verify(|input| executor.run(input)) {
        Ok(report) => report,
        Err(VerificationError::RelationNotRequired { test_id, .. }) => {
            if expected_refusal.as_deref() != Some(test_id.as_str()) {
                return Err(format!(
                    "RelationNotRequired for {test_id}, reference expected {expected_refusal:?}"
                ));
            }
            let pressure_after: Vec<(MetamorphicRelation, u32)> = RELATIONS
                .iter()
                .map(|relation| (*relation, engine.family_pressure(*relation)))
                .collect();
            if pressure_after != pressure_before {
                return Err("a refused verify changed family pressure".into());
            }
            return Ok(false);
        }
        Err(error) => return Err(format!("unexpected verify error {error}")),
    };
    if let Some(test_id) = expected_refusal {
        return Err(format!("verify accepted disallowed relation of {test_id}"));
    }

    // Accounting.
    let executed: Vec<String> = tests
        .iter()
        .filter(|test| !retired.contains(test.id()))
        .map(|test| test.id().to_owned())
        .collect();
    if report.executed_test_ids() != executed.as_slice()
        || report.executed_tests() != executed.len()
    {
        return Err("executed tests differ from the non-retired tests".into());
    }
    if report.retired_tests() != retired.iter().cloned().collect::<Vec<_>>().as_slice() {
        return Err("retired tests differ".into());
    }
    if report.regression_locks() != locks.iter().cloned().collect::<Vec<_>>().as_slice() {
        return Err("regression locks differ".into());
    }
    let reported_repairs: BTreeSet<String> = report
        .repairs()
        .iter()
        .map(|repair| repair.test_id().to_owned())
        .collect();
    if &reported_repairs != repairs {
        return Err("repairs differ".into());
    }
    let inconclusive: BTreeSet<&str> = report
        .inconclusive_test_ids()
        .iter()
        .map(String::as_str)
        .collect();
    if inconclusive.len() != report.inconclusive_tests()
        || !inconclusive
            .iter()
            .all(|id| executed.iter().any(|e| e == id))
    {
        return Err("inconclusive accounting is inconsistent".into());
    }
    let violating: BTreeSet<&str> = report
        .violations()
        .iter()
        .map(|violation| violation.test_id())
        .collect();
    let expected_passed = executed
        .iter()
        .filter(|id| !inconclusive.contains(id.as_str()) && !violating.contains(id.as_str()))
        .count();
    if report.passed_tests() != expected_passed {
        return Err(format!(
            "passed_tests {} but {expected_passed} executed tests have no violation and are conclusive",
            report.passed_tests()
        ));
    }
    if report.passed() != (report.violations().is_empty() && report.inconclusive_tests() == 0) {
        return Err("passed() disagrees with its definition".into());
    }

    // Violations and minimization.
    let mut run_feedback: BTreeMap<MetamorphicRelation, (u32, u32)> = BTreeMap::new();
    for id in &executed {
        let test = tests.iter().find(|test| test.id() == id).unwrap();
        run_feedback.entry(test.relation()).or_default().0 += 1;
    }
    for violation in report.violations() {
        let test = tests
            .iter()
            .find(|test| test.id() == violation.test_id())
            .ok_or("violation names an unknown test")?;
        if retired.contains(test.id()) {
            return Err("violation names a retired test".into());
        }
        run_feedback.entry(test.relation()).or_default().1 += 1;
        if violation.relation() != test.relation() {
            return Err("violation relation differs from its test".into());
        }
        let (left, right) = (violation.left_input_index(), violation.right_input_index());
        if left >= test.inputs().len() || right >= test.inputs().len() || left == right {
            return Err("violation indices are out of range".into());
        }
        match violation.root_cause() {
            FailureCause::ObservableDivergence(surface) => {
                if violation.differing_surfaces().first() != Some(&surface) {
                    return Err("divergence cause is not the first differing surface".into());
                }
            }
            FailureCause::MonotonicityViolation => {
                if !violation.differing_surfaces().is_empty()
                    || test.relation() != MetamorphicRelation::Monotonicity
                {
                    return Err("monotonicity cause with differing surfaces".into());
                }
            }
            FailureCause::MissingContractualMeasurement(_) => {
                return Err("verify reported a missing measurement as a violation".into());
            }
        }
        let expected_surfaces = differing_surfaces(
            semantics,
            &executor.run(&test.inputs()[left]),
            &executor.run(&test.inputs()[right]),
        );
        if violation.differing_surfaces() != expected_surfaces.as_slice() {
            return Err(format!(
                "differing surfaces {:?} differ from the reference {expected_surfaces:?}",
                violation.differing_surfaces()
            ));
        }
        let Some(minimized) = violation.minimized_inputs() else {
            return Err("violation without minimized inputs".into());
        };
        if minimized.len() != test.inputs().len() {
            return Err("minimized inputs changed the input count".into());
        }
        for (index, (original, reduced)) in test.inputs().iter().zip(minimized).enumerate() {
            if index == left || index == right {
                if !is_subsequence(reduced, original) {
                    return Err("minimized input is not a subsequence of the original".into());
                }
            } else if reduced != original {
                return Err("minimization touched an input outside the violating pair".into());
            }
        }
        if violation.minimized_input() != Some(minimized[left].as_slice()) {
            return Err("minimized_input is not the left minimized input".into());
        }
        // The minimized inputs still fail the same way when verified afresh.
        let mut fresh = VerificationEngine::new(semantics.clone());
        fresh
            .add_test(
                MetamorphicTest::new(test.id(), test.relation(), minimized.to_vec())
                    .map_err(|error| format!("minimized inputs are not a valid test: {error}"))?,
            )
            .unwrap();
        let again = fresh
            .verify(|input| executor.run(input))
            .map_err(|error| format!("re-verification refused: {error}"))?;
        let reproduced = again.violations().iter().any(|repeat| {
            repeat.left_input_index() == left
                && repeat.right_input_index() == right
                && repeat.root_cause() == violation.root_cause()
                && repeat.differing_surfaces() == violation.differing_surfaces()
        });
        if !reproduced {
            return Err(format!(
                "minimized inputs {minimized:?} no longer reproduce the {:?} violation of {}",
                violation.root_cause(),
                test.id()
            ));
        }
    }

    // Family statistics.
    *decays += expected_family_update(families, &run_feedback, engine, retired);
    let reported: BTreeMap<MetamorphicRelation, Family> = report
        .family_statistics()
        .iter()
        .map(|statistics| {
            (
                statistics.relation(),
                Family {
                    executions: statistics.executions(),
                    violations: statistics.violations(),
                    pressure: statistics.pressure(),
                    retired: statistics.retired_tests(),
                },
            )
        })
        .collect();
    if &reported != families {
        return Err(format!(
            "family statistics {reported:?} differ from the reference {families:?}"
        ));
    }
    for (relation, family) in families.iter() {
        if engine.family_pressure(*relation) != family.pressure {
            return Err("family_pressure disagrees with the report".into());
        }
    }
    let mut prioritized: Vec<(MetamorphicRelation, u32)> = families
        .iter()
        .map(|(relation, family)| (*relation, family.pressure))
        .collect();
    prioritized.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let expected_order: Vec<MetamorphicRelation> = prioritized.into_iter().map(|p| p.0).collect();
    if engine.prioritized_relations() != expected_order {
        return Err("prioritized_relations order differs".into());
    }
    Ok(true)
}

fn check_differential(
    engine: &VerificationEngine,
    semantics: &RequiredSemantics,
    baseline: Executor,
    candidate: Executor,
    rng: &mut Rng,
) -> Result<(), String> {
    let cases: Vec<DifferentialCase> = (0..rng.below(5))
        .map(|index| {
            let length = rng.below(10);
            let input: Vec<u8> = (0..length)
                .map(|_| {
                    if rng.chance(0.15) {
                        0xFF
                    } else {
                        b"ab:CD"[rng.below(5)]
                    }
                })
                .collect();
            DifferentialCase::new(format!("case-{index}"), input).unwrap()
        })
        .collect();
    let report = engine.differential(
        cases.clone(),
        |input| baseline.run(input),
        |input| candidate.run(input),
    );
    if report.executed_cases() != cases.len() {
        return Err("differential executed count differs".into());
    }
    if report.passed_cases() + report.inconclusive_cases() + report.violations().len()
        != report.executed_cases()
    {
        return Err("differential accounting does not partition the cases".into());
    }
    if report.passed() != (report.violations().is_empty() && report.inconclusive_cases() == 0) {
        return Err("differential passed() disagrees with its definition".into());
    }
    let mut expected_inconclusive = 0;
    let mut expected_violations = Vec::new();
    for case in &cases {
        let left = baseline.run(case.input());
        let right = candidate.run(case.input());
        if missing(semantics, &left, &right) {
            expected_inconclusive += 1;
            continue;
        }
        let surfaces = differing_surfaces(semantics, &left, &right);
        if !surfaces.is_empty() {
            expected_violations.push((case.id().to_owned(), surfaces));
        }
    }
    if report.inconclusive_cases() != expected_inconclusive {
        return Err("differential inconclusive count differs from the reference".into());
    }
    let actual: Vec<(String, Vec<VerificationSurface>)> = report
        .violations()
        .iter()
        .map(|violation| {
            (
                violation.case_id().to_owned(),
                violation.differing_surfaces().to_vec(),
            )
        })
        .collect();
    if actual != expected_violations {
        return Err(format!(
            "differential violations {actual:?} differ from the reference {expected_violations:?}"
        ));
    }
    for violation in report.violations() {
        if violation.root_cause()
            != FailureCause::ObservableDivergence(violation.differing_surfaces()[0])
        {
            return Err("differential cause is not the first differing surface".into());
        }
        let Some(minimized) = violation.minimized_input() else {
            return Err("differential violation without a minimized input".into());
        };
        if !is_subsequence(minimized, violation.input()) {
            return Err("minimized differential input is not a subsequence".into());
        }
        let surfaces = differing_surfaces(
            semantics,
            &baseline.run(minimized),
            &candidate.run(minimized),
        );
        if surfaces != violation.differing_surfaces() {
            return Err("minimized differential input no longer differs the same way".into());
        }
    }
    Ok(())
}

fn random_input(rng: &mut Rng) -> Vec<u8> {
    let length = rng.below(12);
    (0..length)
        .map(|_| {
            if rng.chance(0.1) {
                0xFF
            } else {
                b"aAb:c"[rng.below(5)]
            }
        })
        .collect()
}

#[test]
fn random_operation_campaign_keeps_the_engine_consistent() {
    let sequences = env_u64(
        "BLERADAR_VERIFICATION_CAMPAIGN_SEQUENCES",
        DEFAULT_SEQUENCES,
    );
    let seed = env_u64("BLERADAR_VERIFICATION_CAMPAIGN_SEED", DEFAULT_SEED);
    let mut rng = Rng(seed | 1);
    let mut verified = 0u64;
    let mut refused = 0u64;
    let mut violations_seen = 0u64;
    let mut decays = 0u64;
    for seq in 0..sequences {
        let mut semantics = RequiredSemantics::new("campaign contract").unwrap();
        if rng.chance(0.3) {
            semantics = semantics.requires_all_observables();
        } else {
            for _ in 0..1 + rng.below(4) {
                semantics = semantics.requires_surface(SURFACES[rng.below(SURFACES.len())]);
            }
        }
        for _ in 0..1 + rng.below(3) {
            semantics = semantics.requires_relation(RELATIONS[rng.below(RELATIONS.len())]);
        }
        let executor = Executor::random(&mut rng);
        let candidate = Executor::random(&mut rng);
        let mut engine = VerificationEngine::new(semantics.clone());
        let mut books = Bookkeeping::default();
        for k in 0..OPS_PER_SEQUENCE {
            let op = rng.below(10);
            let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
                match op {
                    0..=2 => {
                        let relation = if rng.chance(0.85) {
                            let allowed: Vec<MetamorphicRelation> =
                                semantics.relations().copied().collect();
                            allowed[rng.below(allowed.len())]
                        } else {
                            RELATIONS[rng.below(RELATIONS.len())]
                        };
                        let count = if relation == MetamorphicRelation::Invariance {
                            2 + rng.below(3)
                        } else {
                            minimum_inputs(relation)
                        };
                        let inputs: Vec<Vec<u8>> =
                            (0..count).map(|_| random_input(&mut rng)).collect();
                        let id = format!("t{}", rng.below(6));
                        let test = MetamorphicTest::new(id.clone(), relation, inputs).unwrap();
                        let known = engine.tests().any(|t| t.id() == id);
                        match engine.add_test(test) {
                            Ok(()) if known => Err("duplicate test accepted".into()),
                            Err(VerificationError::DuplicateTest { .. }) if known => Ok(()),
                            Ok(()) => Ok(()),
                            Err(error) => Err(format!("add_test refused a new test: {error}")),
                        }
                    }
                    3 | 4 => {
                        let id = format!("t{}", rng.below(7));
                        let known = engine.tests().any(|t| t.id() == id);
                        let result = if rng.chance(0.7) {
                            engine
                                .retire_test(&id)
                                .map(|()| books.retired.insert(id.clone()))
                        } else {
                            engine
                                .reinstate_test(&id)
                                .map(|()| books.retired.remove(&id))
                        };
                        match result {
                            Ok(_) if known => Ok(()),
                            Err(VerificationError::MissingTest { .. }) if !known => Ok(()),
                            other => Err(format!("retire/reinstate {id}: {other:?}")),
                        }
                    }
                    5 => {
                        let id = format!("t{}", rng.below(7));
                        let known = engine.tests().any(|t| t.id() == id);
                        let relation = engine.tests().find(|t| t.id() == id).map_or(
                            MetamorphicRelation::Commutativity,
                            MetamorphicTest::relation,
                        );
                        let inputs: Vec<Vec<u8>> = (0..minimum_inputs(relation))
                            .map(|_| random_input(&mut rng))
                            .collect();
                        let lock_id = format!("lock-{}", rng.below(4));
                        let lock = RegressionLock::new(
                            lock_id.clone(),
                            id.clone(),
                            relation,
                            inputs,
                            "locked",
                        )
                        .unwrap();
                        let duplicate = books.locks.contains(&lock_id);
                        match engine.add_regression_lock(lock) {
                            Ok(()) if known && !duplicate => {
                                books.locks.insert(lock_id);
                                Ok(())
                            }
                            Err(VerificationError::MissingTest { .. }) if !known => Ok(()),
                            Err(VerificationError::DuplicateRegressionLock { .. })
                                if known && duplicate =>
                            {
                                Ok(())
                            }
                            other => Err(format!("add_regression_lock: {other:?}")),
                        }
                    }
                    6 => {
                        let id = format!("t{}", rng.below(7));
                        let known = engine.tests().any(|t| t.id() == id);
                        let duplicate = books.repairs.contains(&id);
                        match engine
                            .record_repair(RepairRecord::new(id.clone(), "repaired").unwrap())
                        {
                            Ok(()) if known && !duplicate => {
                                books.repairs.insert(id);
                                Ok(())
                            }
                            Err(VerificationError::MissingTest { .. }) if !known => Ok(()),
                            Err(VerificationError::DuplicateRepair { .. })
                                if known && duplicate =>
                            {
                                Ok(())
                            }
                            other => Err(format!("record_repair: {other:?}")),
                        }
                    }
                    7 | 8 => match check_verify(&mut engine, &semantics, executor, &mut books) {
                        Ok(true) => {
                            verified += 1;
                            Ok(())
                        }
                        Ok(false) => {
                            refused += 1;
                            Ok(())
                        }
                        Err(violation) => Err(violation),
                    },
                    _ => check_differential(&engine, &semantics, executor, candidate, &mut rng),
                }
            }));
            match outcome {
                Err(_) => panic!("seed={seed} sequence={seq} op={k}: engine operation panicked"),
                Ok(Err(violation)) => panic!("seed={seed} sequence={seq} op={k}: {violation}"),
                Ok(Ok(())) => {}
            }
        }
        violations_seen += books
            .families
            .values()
            .map(|f| u64::from(f.violations))
            .sum::<u64>();
        decays += books.decays;
    }
    assert!(
        verified > 0 && refused > 0 && violations_seen > 0 && decays > 0,
        "generators must exercise accepted runs, refused runs, violations and pressure decay: \
         verified={verified} refused={refused} violations={violations_seen} decays={decays}"
    );
}
