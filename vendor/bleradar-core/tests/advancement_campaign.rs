//! Differential campaign over `MetamorphicSoftwareAdvancementEngine`
//! (`docs/AUTONOMOUS_DECISIONS.md` #70): random proposals, executions and
//! baseline/candidate executors evaluated against a fixed normalization
//! contract, with the accept/reject decision, its rejection reasons, the
//! `Proposed → Accepted/Rejected → Integrated` state machine, `integrate`
//! gating, and `ranked_proposals`/`recompute_rankings` all checked against an
//! independent recomputation.
//!
//! The engine's decision is an AND over eight gates (baseline and candidate
//! semantics preserved, differential agreement, verification coverage,
//! measurable improvement, no unexplained material regression, falsification
//! resistance, reproducibility). Each gate's inputs are reproduced here: the
//! two verification reports and the differential report are recomputed with a
//! standalone `VerificationEngine` built identically (verify/differential are
//! themselves campaign-covered), and the benchmark, falsification and
//! reproducibility gates from the execution the engine was handed. The
//! expected rejection reasons are assembled in the engine's own source order
//! and compared for exact equality, so both the set and the ordering are
//! pinned. Scale with `BLERADAR_ADVANCEMENT_CAMPAIGN_SEQUENCES`, reseed with
//! `BLERADAR_ADVANCEMENT_CAMPAIGN_SEED`; a failure prints the seed.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use bleradar_core::{
    AdvancementError, AdvancementExecution, AdvancementFactors, AdvancementProposal,
    AdvancementRejection, AdvancementState, BenchmarkMetric, BenchmarkReport, DifferentialCase,
    ExecutionOutcome, FalsificationCheck, FalsificationFinding, FalsificationResult,
    FalsificationStatus, MetamorphicRelation, MetamorphicSoftwareAdvancementEngine,
    MetamorphicTest, MetricDirection, RequiredSemantics, VerificationEngine, VerificationSurface,
};

const DEFAULT_SEQUENCES: u64 = 400;
const OPS_PER_SEQUENCE: usize = 20;
const DEFAULT_SEED: u64 = 0x0517_2026_0910_ADEC;

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

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// One metamorphic test over a normalization-equivalence contract comparing
/// outputs: a correct executor strips `:` so both inputs normalize equal.
fn semantics() -> RequiredSemantics {
    RequiredSemantics::new("normalization contract")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_relation(MetamorphicRelation::NormalizationEquivalence)
}

fn verification_engine() -> VerificationEngine {
    let mut engine = VerificationEngine::new(semantics());
    engine
        .add_test(
            MetamorphicTest::new(
                "normalization-1",
                MetamorphicRelation::NormalizationEquivalence,
                vec![b"AA:BB".to_vec(), b"AABB".to_vec()],
            )
            .unwrap(),
        )
        .unwrap();
    engine
}

fn correct(input: &[u8]) -> ExecutionOutcome {
    ExecutionOutcome::success(
        input
            .iter()
            .copied()
            .filter(|b| *b != b':')
            .collect::<Vec<_>>(),
    )
}

/// Keeps `:` and uppercases, so the raw and normalized inputs diverge — a
/// normalization-equivalence violation.
fn broken(input: &[u8]) -> ExecutionOutcome {
    ExecutionOutcome::success(input.iter().map(u8::to_ascii_uppercase).collect::<Vec<_>>())
}

fn executor(is_broken: bool) -> fn(&[u8]) -> ExecutionOutcome {
    if is_broken { broken } else { correct }
}

#[derive(Clone)]
struct Plan {
    baseline_broken: bool,
    candidate_broken: bool,
    cases: Vec<DifferentialCase>,
    benchmark: BenchmarkReport,
    falsification: FalsificationResult,
    reproducible: bool,
}

fn random_plan(rng: &mut Rng) -> Plan {
    let cases: Vec<DifferentialCase> = (0..rng.below(4))
        .map(|index| {
            let input = if rng.chance(0.5) {
                b"AA:BB".to_vec()
            } else {
                b"AABB".to_vec()
            };
            DifferentialCase::new(format!("case-{index}"), input).unwrap()
        })
        .collect();
    let metrics: Vec<BenchmarkMetric> = (0..rng.below(4))
        .map(|index| {
            let direction = if rng.chance(0.5) {
                MetricDirection::HigherIsBetter
            } else {
                MetricDirection::LowerIsBetter
            };
            let mut metric = BenchmarkMetric::new(
                format!("m{index}"),
                rng.below(100) as u64,
                rng.below(100) as u64,
                direction,
            )
            .unwrap()
            .with_material_threshold(1 + rng.below(5) as u64);
            if rng.chance(0.4) {
                metric = metric.explained_by("explained");
            }
            metric
        })
        .collect();
    let falsification = if rng.chance(0.5) {
        FalsificationResult::resistant()
    } else {
        let status = match rng.below(3) {
            0 => FalsificationStatus::Resistant,
            1 => FalsificationStatus::Failed,
            _ => FalsificationStatus::Inconclusive,
        };
        let mut result = FalsificationResult::new(status);
        for _ in 0..rng.below(3) {
            result = result.with_finding(
                FalsificationFinding::new(
                    FalsificationCheck::CompleteReview,
                    rng.chance(0.5),
                    "detail",
                )
                .unwrap(),
            );
        }
        result
    };
    Plan {
        baseline_broken: rng.chance(0.3),
        candidate_broken: rng.chance(0.3),
        cases,
        benchmark: BenchmarkReport::new(metrics).unwrap(),
        falsification,
        reproducible: rng.chance(0.7),
    }
}

impl Plan {
    fn execution(&self) -> AdvancementExecution {
        AdvancementExecution::new(
            self.cases.clone(),
            self.benchmark.clone(),
            self.falsification.clone(),
            self.reproducible,
        )
    }

    /// The rejection reasons the engine must produce, assembled in its own
    /// source order so the comparison pins both the set and the ordering.
    fn expected_rejections(&self) -> Vec<AdvancementRejection> {
        let mut oracle = verification_engine();
        let baseline = oracle.verify(executor(self.baseline_broken)).unwrap();
        let candidate = oracle.verify(executor(self.candidate_broken)).unwrap();
        let differential = oracle.differential(
            self.cases.clone(),
            executor(self.baseline_broken),
            executor(self.candidate_broken),
        );
        let mut reasons = Vec::new();
        if !baseline.passed() {
            reasons.push(AdvancementRejection::BaselineSemanticsNotPreserved);
        }
        if !candidate.passed() {
            reasons.push(AdvancementRejection::CandidateSemanticsNotPreserved);
        }
        if !differential.passed() {
            reasons.push(AdvancementRejection::DifferentialMismatch);
        }
        if baseline.executed_tests() == 0
            || candidate.executed_tests() == 0
            || differential.executed_cases() == 0
        {
            reasons.push(AdvancementRejection::InsufficientVerificationCoverage);
        }
        if !self.benchmark.has_measurable_improvement() {
            reasons.push(AdvancementRejection::NoMeasurableImprovement);
        }
        if !self.benchmark.unexplained_material_regressions().is_empty() {
            reasons.push(AdvancementRejection::UnexplainedMaterialRegression);
        }
        if !self.falsification.is_resistant() {
            reasons.push(AdvancementRejection::FalsificationNotResistant);
        }
        if !self.reproducible {
            reasons.push(AdvancementRejection::NotReproducible);
        }
        reasons
    }
}

fn factors(rng: &mut Rng) -> AdvancementFactors {
    AdvancementFactors::new(
        rng.below(101) as u8,
        rng.below(101) as u8,
        rng.below(101) as u8,
        rng.below(101) as u8,
        1 + rng.below(100) as u8,
        1 + rng.below(100) as u8,
    )
    .unwrap()
}

fn expected_ranking(
    states: &BTreeMap<String, (AdvancementState, AdvancementFactors)>,
) -> Vec<String> {
    let mut live: Vec<(&String, AdvancementFactors)> = states
        .iter()
        .filter(|(_, (state, _))| {
            *state != AdvancementState::Rejected && *state != AdvancementState::Integrated
        })
        .map(|(id, (_, factors))| (id, *factors))
        .collect();
    live.sort_by(|left, right| {
        right
            .1
            .priority()
            .cmp(&left.1.priority())
            .then_with(|| left.0.cmp(right.0))
    });
    live.into_iter().map(|(id, _)| id.clone()).collect()
}

fn check_ranking(
    engine: &MetamorphicSoftwareAdvancementEngine,
    states: &BTreeMap<String, (AdvancementState, AdvancementFactors)>,
) -> Result<(), String> {
    let ranked: Vec<String> = engine
        .ranked_proposals()
        .iter()
        .map(|ranking| ranking.proposal_id().to_owned())
        .collect();
    if ranked != expected_ranking(states) {
        return Err(format!(
            "ranked_proposals {ranked:?} differ from the reference {:?}",
            expected_ranking(states)
        ));
    }
    let recomputed: Vec<String> = engine
        .recompute_rankings()
        .iter()
        .map(|ranking| ranking.proposal_id().to_owned())
        .collect();
    if recomputed != ranked {
        return Err("recompute_rankings differs from ranked_proposals".into());
    }
    for ranking in engine.ranked_proposals() {
        let (state, factors) = &states[ranking.proposal_id()];
        if ranking.state() != *state {
            return Err(format!(
                "ranking state for {} is wrong",
                ranking.proposal_id()
            ));
        }
        if ranking.priority() != factors.priority() {
            return Err("ranking priority differs from the proposal factors".into());
        }
    }
    Ok(())
}

#[test]
fn advancement_decisions_and_state_machine_agree_with_an_independent_reference() {
    let sequences = env_u64("BLERADAR_ADVANCEMENT_CAMPAIGN_SEQUENCES", DEFAULT_SEQUENCES);
    let seed = env_u64("BLERADAR_ADVANCEMENT_CAMPAIGN_SEED", DEFAULT_SEED);
    let mut rng = Rng(seed | 1);
    let mut accepted = 0u64;
    let mut rejected = 0u64;
    let mut integrated = 0u64;
    for seq in 0..sequences {
        let mut engine = MetamorphicSoftwareAdvancementEngine::new(verification_engine());
        // Track (state, factors) for every added proposal.
        let mut states: BTreeMap<String, (AdvancementState, AdvancementFactors)> = BTreeMap::new();
        for k in 0..OPS_PER_SEQUENCE {
            let op = rng.below(10);
            let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
                match op {
                    0..=3 => {
                        let id = format!("p{}", rng.below(6));
                        let factors = factors(&mut rng);
                        let proposal = AdvancementProposal::new(&id, "change", factors).unwrap();
                        let known = states.contains_key(&id);
                        match engine.add_proposal(proposal) {
                            Ok(()) if known => Err("duplicate proposal accepted".into()),
                            Err(AdvancementError::DuplicateProposal { .. }) if known => Ok(()),
                            Ok(()) => {
                                states.insert(id.clone(), (AdvancementState::Proposed, factors));
                                if engine.state(&id) != Some(AdvancementState::Proposed) {
                                    return Err("added proposal is not Proposed".into());
                                }
                                Ok(())
                            }
                            Err(error) => {
                                Err(format!("add_proposal refused a new proposal: {error}"))
                            }
                        }
                    }
                    4..=7 => {
                        let id = format!("p{}", rng.below(6));
                        let plan = random_plan(&mut rng);
                        let known_state = states.get(&id).map(|(state, _)| *state);
                        let result = engine.evaluate(
                            &id,
                            plan.execution(),
                            executor(plan.baseline_broken),
                            executor(plan.candidate_broken),
                        );
                        match (known_state, result) {
                            (None, Err(AdvancementError::MissingProposal { .. })) => Ok(()),
                            (None, other) => {
                                Err(format!("evaluate of unknown proposal: {other:?}"))
                            }
                            (
                                Some(AdvancementState::Accepted | AdvancementState::Integrated),
                                Err(AdvancementError::InvalidState { .. }),
                            ) => Ok(()),
                            (
                                Some(AdvancementState::Accepted | AdvancementState::Integrated),
                                other,
                            ) => Err(format!("evaluate of a settled proposal: {other:?}")),
                            (Some(_), Ok(decision)) => {
                                let expected = plan.expected_rejections();
                                if decision.rejection_reasons() != expected.as_slice() {
                                    return Err(format!(
                                        "rejection reasons {:?} differ from the reference {expected:?}",
                                        decision.rejection_reasons()
                                    ));
                                }
                                let expected_state = if expected.is_empty() {
                                    AdvancementState::Accepted
                                } else {
                                    AdvancementState::Rejected
                                };
                                if decision.accepted() != expected.is_empty()
                                    || decision.disposition() != expected_state
                                {
                                    return Err(
                                        "decision disposition disagrees with its reasons".into()
                                    );
                                }
                                if engine.state(&id) != Some(expected_state) {
                                    return Err("engine state differs from the decision".into());
                                }
                                if expected.is_empty() {
                                    accepted += 1;
                                } else {
                                    rejected += 1;
                                }
                                states.get_mut(&id).unwrap().0 = expected_state;
                                Ok(())
                            }
                            (Some(_), Err(error)) => Err(format!("evaluate refused: {error}")),
                        }
                    }
                    8 => {
                        let id = format!("p{}", rng.below(6));
                        let known_state = states.get(&id).map(|(state, _)| *state);
                        match (known_state, engine.integrate(&id)) {
                            (None, Err(AdvancementError::MissingProposal { .. })) => Ok(()),
                            (Some(AdvancementState::Accepted), Ok(_)) => {
                                if engine.state(&id) != Some(AdvancementState::Integrated) {
                                    return Err("integrated proposal is not Integrated".into());
                                }
                                integrated += 1;
                                states.get_mut(&id).unwrap().0 = AdvancementState::Integrated;
                                Ok(())
                            }
                            (Some(state), Err(AdvancementError::InvalidState { .. }))
                                if state != AdvancementState::Accepted =>
                            {
                                Ok(())
                            }
                            (state, other) => {
                                Err(format!("integrate of {id} in state {state:?}: {other:?}"))
                            }
                        }
                    }
                    _ => Ok(()),
                }?;
                check_ranking(&engine, &states)
            }));
            match outcome {
                Err(_) => {
                    panic!("seed={seed} sequence={seq} op={k}: advancement operation panicked")
                }
                Ok(Err(violation)) => panic!("seed={seed} sequence={seq} op={k}: {violation}"),
                Ok(Ok(())) => {}
            }
        }
    }
    assert!(
        accepted > 0 && rejected > 0 && integrated > 0,
        "generators must reach acceptance, rejection and integration: \
         accepted={accepted} rejected={rejected} integrated={integrated}"
    );
}
