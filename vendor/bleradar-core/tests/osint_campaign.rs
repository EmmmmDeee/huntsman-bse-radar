//! Random-operation campaign over `ExecutionFeedbackAdaptiveOsintSearchEngine`
//! (`docs/AUTONOMOUS_DECISIONS.md` #63): random `add_pivot` / `execute_result` /
//! `exhaust` / `recompute_rankings` sequences under random limits, with
//! feedback that carries conflicting sources, conflicting findings, duplicate
//! seeds, adapter failures (including an empty error message), and invalid
//! factors. Oracles after every operation: no panic; execution and pivot
//! counts never exceed the limits; an executed pivot is marked and can never
//! execute again; a refused operation leaves the engine and its evidence store
//! unchanged; every generated pivot id is fresh, `Proposed`, and carries its
//! parent; findings and the retrieval action are persisted; the ranking is
//! unique, `Proposed`-only, agrees with `next_pivot`/`has_ready_pivot`; family
//! statistics sum to the execution count; the evidence store validates.
//! Scale with `BLERADAR_OSINT_CAMPAIGN_SEQUENCES`, reseed with
//! `BLERADAR_OSINT_CAMPAIGN_SEED`; a failure prints the seed.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use bleradar_core::{
    EvidenceStore, ExecutionFeedbackAdaptiveOsintSearchEngine, RetrievalMethod, SearchFeedback,
    SearchFinding, SearchLimits, SearchOutcome, SearchPivot, SearchPivotSeed, SearchPivotState,
    SearchPriorityFactors, SearchRepresentation, Source, SourceType,
};

const DEFAULT_SEQUENCES: u64 = 100;
const OPS_PER_SEQUENCE: usize = 60;
const DEFAULT_SEED: u64 = 0x0517_2026_0910_C0DE;

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

const QUERIES: &[&str] = &["alpha", "beta", "gamma", "Delta", " alpha ", "épsilon"];
const NORMS: &[&str] = &["alpha", "beta", "delta"];
const OUTCOMES: &[SearchOutcome] = &[
    SearchOutcome::Useful,
    SearchOutcome::Contradictory,
    SearchOutcome::NoResults,
    SearchOutcome::Weak,
    SearchOutcome::Duplicate,
    SearchOutcome::Inconclusive,
];

fn representation(rng: &mut Rng) -> SearchRepresentation {
    SearchRepresentation::ALL[rng.below(SearchRepresentation::ALL.len())]
}
fn factors(rng: &mut Rng) -> Option<SearchPriorityFactors> {
    let cost = if rng.chance(0.05) {
        0
    } else {
        1 + rng.below(120) as u8
    };
    let risk = if rng.chance(0.05) {
        0
    } else {
        1 + rng.below(120) as u8
    };
    SearchPriorityFactors::new(
        rng.below(130) as u8,
        rng.below(130) as u8,
        rng.below(130) as u8,
        rng.below(130) as u8,
        rng.below(130) as u8,
        cost,
        risk,
    )
    .ok()
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Snapshot {
    executions: usize,
    pivots: usize,
    evidence_len: usize,
    states: BTreeMap<String, SearchPivotState>,
}

fn snapshot(
    engine: &ExecutionFeedbackAdaptiveOsintSearchEngine,
    known: &BTreeSet<String>,
) -> Snapshot {
    Snapshot {
        executions: engine.execution_count(),
        pivots: engine.pivot_count(),
        evidence_len: engine.evidence().len(),
        states: known
            .iter()
            .filter_map(|id| engine.pivot(id).map(|p| (id.clone(), p.state())))
            .collect(),
    }
}

fn consistency(
    engine: &ExecutionFeedbackAdaptiveOsintSearchEngine,
    limits: SearchLimits,
) -> Result<(), String> {
    if engine.execution_count() > limits.max_executions() {
        return Err(format!(
            "execution_count {} > max {}",
            engine.execution_count(),
            limits.max_executions()
        ));
    }
    if engine.pivot_count() > limits.max_pivots() {
        return Err(format!(
            "pivot_count {} > max {}",
            engine.pivot_count(),
            limits.max_pivots()
        ));
    }
    if engine.executions().count() != engine.execution_count() {
        return Err("executions() length != execution_count()".into());
    }
    let ranked = engine.ranked_pivots();
    let mut ids = BTreeSet::new();
    for r in &ranked {
        if !ids.insert(r.pivot_id().to_owned()) {
            return Err(format!("duplicate pivot in ranking: {}", r.pivot_id()));
        }
        match engine.pivot(r.pivot_id()) {
            Some(p) if p.state() == SearchPivotState::Proposed => {}
            other => {
                return Err(format!(
                    "ranked pivot {} is not proposed: {other:?}",
                    r.pivot_id()
                ));
            }
        }
    }
    match (engine.next_pivot(), ranked.first()) {
        (None, None) => {}
        (Some(p), Some(r)) if p.id() == r.pivot_id() => {}
        (a, b) => {
            return Err(format!(
                "next_pivot {:?} != first ranked {:?}",
                a.map(|p| p.id().to_owned()),
                b.map(|r| r.pivot_id().to_owned())
            ));
        }
    }
    if engine.has_ready_pivot() != !ranked.is_empty() {
        return Err("has_ready_pivot disagrees with ranking".into());
    }
    let stats_total: usize = engine
        .family_statistics()
        .iter()
        .map(|s| s.executions() as usize)
        .sum();
    if stats_total != engine.execution_count() {
        return Err(format!(
            "family statistics executions {stats_total} != execution_count {}",
            engine.execution_count()
        ));
    }
    engine
        .evidence()
        .validate()
        .map_err(|e| format!("evidence store invalid: {e}"))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn random_operation_campaign_keeps_the_engine_consistent() {
    let sequences = env_u64("BLERADAR_OSINT_CAMPAIGN_SEQUENCES", DEFAULT_SEQUENCES);
    let seed = env_u64("BLERADAR_OSINT_CAMPAIGN_SEED", DEFAULT_SEED);
    let mut rng = Rng(seed | 1);
    let mut executed_ok = 0u64;
    let mut refusals = 0u64;
    for seq in 0..sequences {
        let limits = SearchLimits::new(1 + rng.below(8), 1 + rng.below(12)).unwrap();
        let mut engine =
            ExecutionFeedbackAdaptiveOsintSearchEngine::with_limits(EvidenceStore::new(), limits);
        let mut known: BTreeSet<String> = BTreeSet::new();
        let mut ts = 100u64;
        for k in 0..OPS_PER_SEQUENCE {
            ts += rng.below(5) as u64;
            let before = snapshot(&engine, &known);
            let op = rng.below(10);
            let result: Result<Result<(), String>, _> =
                catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
                    if op < 3 {
                        // add_pivot
                        let id = format!("p{}", rng.below(8));
                        let Some(f) = factors(&mut rng) else {
                            return Ok(());
                        };
                        let mut pivot = match SearchPivot::new(
                            id.clone(),
                            QUERIES[rng.below(QUERIES.len())],
                            representation(&mut rng),
                            f,
                        ) {
                            Ok(p) => p,
                            Err(_) => return Ok(()),
                        };
                        if rng.chance(0.4) {
                            pivot = match pivot.with_normalization(NORMS[rng.below(NORMS.len())]) {
                                Ok(p) => p,
                                Err(_) => return Ok(()),
                            };
                        }
                        match engine.add_pivot(pivot) {
                            Ok(()) => {
                                known.insert(id.clone());
                                if engine.pivot_count() != before.pivots + 1 {
                                    return Err("add_pivot did not add exactly one".into());
                                }
                                if engine.pivot(&id).map(|p| p.state())
                                    != Some(SearchPivotState::Proposed)
                                {
                                    return Err("added pivot not proposed".into());
                                }
                            }
                            Err(e) => {
                                refusals += 1;
                                if snapshot(&engine, &known) != before {
                                    return Err(format!(
                                        "add_pivot {id} failed with {e} but mutated the engine"
                                    ));
                                }
                            }
                        }
                    } else if op < 8 {
                        // execute
                        let candidates: Vec<String> = known.iter().cloned().collect();
                        let id = if !candidates.is_empty() && rng.chance(0.85) {
                            candidates[rng.below(candidates.len())].clone()
                        } else {
                            format!("p{}", rng.below(8))
                        };
                        let seeds_planned = rng.below(4);
                        let findings_planned = rng.below(3);
                        let res = engine.execute_result(
                            &id,
                            ts,
                            |_pivot| -> Result<SearchFeedback, String> {
                                if rng.chance(0.1) {
                                    return Err(if rng.chance(0.2) {
                                        String::new()
                                    } else {
                                        "adapter timeout".into()
                                    });
                                }
                                let mut fb = if rng.chance(0.6) {
                                    SearchFeedback::classified(
                                        rng.below(3) as u32,
                                        rng.below(2) as u32,
                                        rng.below(2) as u32,
                                        rng.below(2) as u32,
                                        rng.below(2) as u32,
                                    )
                                } else {
                                    SearchFeedback::new(
                                        OUTCOMES[rng.below(OUTCOMES.len())],
                                        rng.below(4) as u32,
                                    )
                                };
                                if rng.chance(0.5) {
                                    fb = fb.with_independent_sources(rng.below(3) as u32);
                                }
                                for i in 0..findings_planned {
                                    let sid = format!("src{}", rng.below(3));
                                    let stype = if rng.chance(0.5) {
                                        SourceType::Website
                                    } else {
                                        SourceType::Api
                                    };
                                    let source = Source::new(sid, stype, RetrievalMethod::Search)
                                        .unwrap()
                                        .captured_at(ts);
                                    let fid = format!("finding{}", rng.below(4));
                                    let value = QUERIES[rng.below(QUERIES.len())];
                                    let mut finding =
                                        match SearchFinding::new(fid, value, source, ts) {
                                            Ok(f) => f,
                                            Err(_) => continue,
                                        };
                                    if rng.chance(0.5) {
                                        finding = finding
                                            .with_normalized_value(NORMS[rng.below(NORMS.len())]);
                                    }
                                    if i == 0 && rng.chance(0.3) {
                                        finding = match finding.in_dependency_group("group") {
                                            Ok(f) => f,
                                            Err(_) => continue,
                                        };
                                    }
                                    fb = fb.with_finding(finding);
                                }
                                for _ in 0..seeds_planned {
                                    let Some(f) = factors(&mut rng) else { continue };
                                    let mut seed = match SearchPivotSeed::new(
                                        QUERIES[rng.below(QUERIES.len())],
                                        representation(&mut rng),
                                        f,
                                    ) {
                                        Ok(s) => s,
                                        Err(_) => continue,
                                    };
                                    if rng.chance(0.4) {
                                        seed = match seed
                                            .with_normalization(NORMS[rng.below(NORMS.len())])
                                        {
                                            Ok(s) => s,
                                            Err(_) => continue,
                                        };
                                    }
                                    fb = fb.with_next_pivot(seed);
                                }
                                Ok(fb)
                            },
                        );
                        match res {
                            Ok(execution) => {
                                executed_ok += 1;
                                if execution.phases().len() != 7 {
                                    return Err(format!(
                                        "execution recorded {} phases",
                                        execution.phases().len()
                                    ));
                                }
                                if engine.execution_count() != before.executions + 1 {
                                    return Err("execution_count did not grow by one".into());
                                }
                                if engine.pivot(&id).map(|p| p.state())
                                    != Some(SearchPivotState::Executed)
                                {
                                    return Err("executed pivot not marked Executed".into());
                                }
                                let generated = execution.generated_pivot_ids();
                                if engine.pivot_count() != before.pivots + generated.len() {
                                    return Err("pivot_count != before + generated".into());
                                }
                                if generated.len() + execution.suppressed_pivots().len()
                                    > seeds_planned
                                {
                                    return Err("generated + suppressed exceed seeds".into());
                                }
                                for g in generated {
                                    if !known.insert(g.clone()) {
                                        return Err(format!("generated pivot id reused: {g}"));
                                    }
                                    match engine.pivot(g) {
                                        Some(p)
                                            if p.state() == SearchPivotState::Proposed
                                                && p.parent_id() == Some(id.as_str()) => {}
                                        other => {
                                            return Err(format!(
                                                "generated pivot {g} invalid: {other:?}"
                                            ));
                                        }
                                    }
                                }
                                for oid in execution.observation_ids() {
                                    if engine.evidence().observation(oid).is_none() {
                                        return Err(format!("finding {oid} not persisted"));
                                    }
                                }
                                if engine.evidence().action(execution.action_id()).is_none() {
                                    return Err("action not persisted".into());
                                }
                            }
                            Err(e) => {
                                refusals += 1;
                                if snapshot(&engine, &known) != before {
                                    return Err(format!(
                                        "execute {id} failed with {e} but mutated the engine"
                                    ));
                                }
                            }
                        }
                    } else if op < 9 {
                        let candidates: Vec<String> = known.iter().cloned().collect();
                        let id = if !candidates.is_empty() && rng.chance(0.8) {
                            candidates[rng.below(candidates.len())].clone()
                        } else {
                            "nope".to_string()
                        };
                        let was = engine.pivot(&id).map(|p| p.state());
                        match engine.exhaust(&id) {
                            Ok(()) => {
                                if was != Some(SearchPivotState::Proposed) {
                                    return Err(format!("exhaust accepted pivot in state {was:?}"));
                                }
                                if engine.pivot(&id).map(|p| p.state())
                                    != Some(SearchPivotState::Exhausted)
                                {
                                    return Err("exhausted pivot not marked".into());
                                }
                            }
                            Err(_) => {
                                refusals += 1;
                                if was == Some(SearchPivotState::Proposed) {
                                    return Err("exhaust refused a proposed pivot".into());
                                }
                                if snapshot(&engine, &known) != before {
                                    return Err("exhaust failed but mutated".into());
                                }
                            }
                        }
                    } else {
                        let _ = engine.recompute_rankings();
                    }
                    consistency(&engine, limits)
                }));
            match result {
                Err(_) => panic!("seed={seed} sequence={seq} op={k}: engine operation panicked"),
                Ok(Err(violation)) => panic!("seed={seed} sequence={seq} op={k}: {violation}"),
                Ok(Ok(())) => {}
            }
        }
    }
    assert!(
        executed_ok > 0 && refusals > 0,
        "generators must exercise both outcomes: executions={executed_ok} refusals={refusals}"
    );
}
