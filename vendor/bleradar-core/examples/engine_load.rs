//! Reproducible cost of loading the canonical-store engines
//! (`docs/AUTONOMOUS_DECISIONS.md` #66).
//!
//! Every engine persists into the `EvidenceStore` all-or-nothing. Before
//! decision #66 each `observe`/`correlate`/`record_feedback` cloned the whole
//! store to get that guarantee, so the cost of one operation grew with the
//! number of records already held (8,000 website observations took 21 s).
//! `EvidenceStore::transaction` journals changes instead, so the cost per
//! operation is flat. This example prints the per-operation cost at several
//! store sizes; run it before revisiting any transactional design:
//!
//! ```sh
//! cargo run --release -p bleradar-core --example engine_load
//! ```

use std::time::{Duration, Instant};

use bleradar_core::{
    EvidenceStore, ExecutionFeedbackAdaptiveOsintSearchEngine, InfrastructureKind,
    InfrastructureObservation, RetrievalMethod, SearchFeedback, SearchLimits, SearchOutcome,
    SearchPivot, SearchPriorityFactors, SearchRepresentation, Source, SourceType,
    TemporalMetamorphicInfrastructureCorrelationEngine, WebsiteFeatureKind,
    WebsiteLineageEcosystemAnalysisEngine, WebsiteObservation,
};

const SIZES: [usize; 4] = [1_000, 2_000, 4_000, 8_000];
const OSINT_EXECUTIONS: usize = 500;

fn source(index: usize) -> Source {
    Source::new(
        format!("source-{index}"),
        SourceType::Website,
        RetrievalMethod::Direct,
    )
    .expect("static source metadata is valid")
}

/// Number of distinct values shared between the two sides, so each value is
/// held by four observations per side and the correlation stays small.
fn shared_values(count: usize) -> usize {
    (count / 8).max(1)
}

fn per_operation(total: Duration, operations: usize) -> Duration {
    total / u32::try_from(operations.max(1)).unwrap_or(u32::MAX)
}

fn website(count: usize) -> (Duration, Duration) {
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    let started = Instant::now();
    for index in 0..count {
        let site = if index % 2 == 0 { "site-a" } else { "site-b" };
        let observation = WebsiteObservation::new(
            format!("observation-{index}"),
            site,
            WebsiteFeatureKind::PublicAsset,
            format!("asset-{}", (index / 2) % shared_values(count)),
            source(index),
            100 + index as u64,
        )
        .expect("static observation is valid");
        engine
            .observe(observation)
            .expect("distinct ids and sources are accepted");
    }
    let load = started.elapsed();
    let started = Instant::now();
    engine
        .correlate("site-a", "site-b")
        .expect("the two websites share assets");
    (load, started.elapsed())
}

fn infrastructure(count: usize) -> (Duration, Duration) {
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    let started = Instant::now();
    for index in 0..count {
        let node = if index % 2 == 0 { "node-a" } else { "node-b" };
        let observation = InfrastructureObservation::new(
            format!("observation-{index}"),
            node,
            InfrastructureKind::Certificate,
            format!("sha256:{}", (index / 2) % shared_values(count)),
            source(index),
            100 + index as u64,
        )
        .expect("static observation is valid");
        engine
            .observe(observation)
            .expect("distinct ids and sources are accepted");
    }
    let load = started.elapsed();
    let started = Instant::now();
    engine
        .correlate("node-a", "node-b")
        .expect("the two nodes share certificates");
    (load, started.elapsed())
}

fn osint(pivots: usize) -> Duration {
    let limits = SearchLimits::new(pivots, pivots).expect("positive limits");
    let mut engine =
        ExecutionFeedbackAdaptiveOsintSearchEngine::with_limits(EvidenceStore::new(), limits);
    for index in 0..pivots {
        let factors =
            SearchPriorityFactors::new(50, 50, 50, 50, 50, 50, 50).expect("static factors");
        let pivot = SearchPivot::new(
            format!("pivot-{index}"),
            format!("query-{index}"),
            SearchRepresentation::ALL[index % SearchRepresentation::ALL.len()],
            factors,
        )
        .expect("static pivot is valid");
        engine
            .add_pivot(pivot)
            .expect("distinct pivots are accepted");
    }
    let started = Instant::now();
    for index in 0..OSINT_EXECUTIONS.min(pivots) {
        engine
            .execute_result(&format!("pivot-{index}"), 100, |_| {
                Ok::<_, String>(SearchFeedback::new(SearchOutcome::Useful, 1))
            })
            .expect("a proposed pivot executes once");
    }
    per_operation(started.elapsed(), OSINT_EXECUTIONS.min(pivots))
}

/// A store holding `count` records, wrapped in a website engine, ready to hand
/// off to the next stage of a composed investigation.
fn loaded_engine(count: usize) -> WebsiteLineageEcosystemAnalysisEngine {
    let mut store = EvidenceStore::new();
    for index in 0..count {
        store
            .add_source(source(index))
            .expect("distinct sources are accepted");
    }
    WebsiteLineageEcosystemAnalysisEngine::new(store)
}

/// Cost of handing the canonical store to the next engine: cloning it out
/// (the only mechanism before `into_evidence`) versus moving it out.
fn handoff(count: usize) -> (Duration, Duration) {
    let borrow = loaded_engine(count);
    let started = Instant::now();
    let cloned = borrow.evidence().clone();
    let clone_cost = started.elapsed();
    std::hint::black_box(cloned);

    let owned = loaded_engine(count);
    let started = Instant::now();
    let moved = owned.into_evidence();
    let move_cost = started.elapsed();
    std::hint::black_box(moved);

    (clone_cost, move_cost)
}

fn main() {
    println!("engine load cost (release build recommended)");
    println!(
        "{:<8} {:>18} {:>16} {:>18} {:>16} {:>18}",
        "records",
        "website/observe",
        "website corr.",
        "infra/observe",
        "infra corr.",
        "osint/execute"
    );
    for count in SIZES {
        let (website_load, website_correlate) = website(count);
        let (infra_load, infra_correlate) = infrastructure(count);
        let osint_execute = osint(count);
        println!(
            "{count:<8} {:>18?} {:>16?} {:>18?} {:>16?} {:>18?}",
            per_operation(website_load, count),
            website_correlate,
            per_operation(infra_load, count),
            infra_correlate,
            osint_execute
        );
    }

    println!("\nengine hand-off cost (composing engines over one store)");
    println!(
        "{:<8} {:>18} {:>18}",
        "records", "evidence().clone()", "into_evidence()"
    );
    for count in SIZES {
        let (clone_cost, move_cost) = handoff(count);
        println!("{count:<8} {clone_cost:>18?} {move_cost:>18?}");
    }
}
