//! End-to-end composition of the OSINT, infrastructure, website and fusion
//! engines over one canonical `EvidenceStore`
//! (`docs/AUTONOMOUS_DECISIONS.md` #71).
//!
//! The README states that "other engines should write to this store rather
//! than maintaining parallel evidence histories", but every store-owning
//! engine took `EvidenceStore` by value and exposed only `evidence(&self)` /
//! `evidence_mut(&mut self)`, so a caller threading one investigation through
//! several engines had to `evidence().clone()` at each hand-off — an
//! O(store) copy that grew with the store (6.9 ms per hand-off at 16,000
//! records), or keep the parallel histories the design forbids. `into_evidence`
//! makes the documented composition reachable by moving the store from one
//! engine into the next at zero copy.
//!
//! This test threads a single store through an OSINT self-lookup, an
//! infrastructure correlation, a website lineage correlation and a fusion,
//! then validates the composed store and asserts that every engine's records
//! and both cross-engine relationship edges are present. It also proves that
//! moving the store between engines yields a byte-identical composed store to
//! cloning it at each hand-off, so `into_evidence` changes only the cost, not
//! the result.
//!
//! A third test pins a composition robustness property: when a later engine is
//! handed a store in which an earlier engine already wrote an observation id,
//! its colliding `observe` is refused transactionally, leaving the shared
//! store byte-identical (original record intact, no dangling entity) and valid.

use bleradar_core::{
    CalibratedEvidenceFusion, EvidenceAssessment, EvidenceQuality, EvidenceRole, EvidenceStore,
    ExecutionFeedbackAdaptiveOsintSearchEngine, Hypothesis, HypothesisKind, InfrastructureKind,
    InfrastructureObservation, Observation, RetrievalMethod, SearchFeedback, SearchFinding,
    SearchLimits, SearchOutcome, SearchPivot, SearchPriorityFactors, SearchRepresentation, Source,
    SourceType, TemporalMetamorphicInfrastructureCorrelationEngine, WebsiteFeatureKind,
    WebsiteLineageEcosystemAnalysisEngine, WebsiteObservation,
};

const OSINT_FINDING: &str = "finding-shared-email";
const OSINT_ACTION: &str = "osint-search:seed";
const INFRA_RELATIONSHIP: &str = "infrastructure-correlation:node-a:node-b:relationship";
const WEBSITE_RELATIONSHIP: &str = "website-lineage:site-a:site-b:relationship";

/// Grows the store with `filler` unrelated records so a clone hand-off has a
/// visible, store-sized cost that the move path avoids.
fn seed_filler(store: &mut EvidenceStore, filler: usize) {
    for index in 0..filler {
        let source = Source::new(
            format!("filler-{index}"),
            SourceType::Api,
            RetrievalMethod::Search,
        )
        .unwrap();
        store.add_source(source.clone()).unwrap();
        store
            .add_observation(
                Observation::from_source(format!("filler-obs-{index}"), "x", None, &source, 10)
                    .unwrap(),
            )
            .unwrap();
    }
}

/// Stage 1: an OSINT self-lookup that persists one finding and its retrieval
/// action into the store the engine was handed.
fn osint_stage(store: EvidenceStore) -> ExecutionFeedbackAdaptiveOsintSearchEngine {
    let factors = SearchPriorityFactors::new(80, 80, 80, 80, 80, 10, 10).unwrap();
    let mut osint = ExecutionFeedbackAdaptiveOsintSearchEngine::with_limits(
        store,
        SearchLimits::new(8, 12).unwrap(),
    );
    osint
        .add_pivot(
            SearchPivot::new(
                "seed",
                "synthetic handle",
                SearchRepresentation::Exact,
                factors,
            )
            .unwrap(),
        )
        .unwrap();
    osint
        .execute_result("seed", 200, |_pivot| -> Result<SearchFeedback, String> {
            let finding = SearchFinding::new(
                OSINT_FINDING,
                "user@synthetic.test",
                Source::new("osint-source", SourceType::Api, RetrievalMethod::Search).unwrap(),
                200,
            )
            .unwrap()
            .with_normalized_value("user@synthetic.test");
            Ok(SearchFeedback::new(SearchOutcome::Useful, 1).with_finding(finding))
        })
        .unwrap();
    osint
}

/// Stage 2: two infrastructure nodes sharing a certificate, correlated into a
/// persisted relationship edge.
fn infrastructure_stage(
    store: EvidenceStore,
) -> TemporalMetamorphicInfrastructureCorrelationEngine {
    let mut infra = TemporalMetamorphicInfrastructureCorrelationEngine::new(store);
    for node in ["node-a", "node-b"] {
        infra
            .observe(
                InfrastructureObservation::new(
                    format!("cert-{node}"),
                    node,
                    InfrastructureKind::Certificate,
                    "sha256:shared",
                    Source::new(
                        format!("infra-source-{node}"),
                        SourceType::Website,
                        RetrievalMethod::Direct,
                    )
                    .unwrap(),
                    300,
                )
                .unwrap(),
            )
            .unwrap();
    }
    infra.correlate("node-a", "node-b").unwrap();
    infra
}

/// Stage 3: two websites sharing a rare public asset, correlated into a
/// persisted lineage edge.
fn website_stage(store: EvidenceStore) -> WebsiteLineageEcosystemAnalysisEngine {
    let mut website = WebsiteLineageEcosystemAnalysisEngine::new(store);
    for site in ["site-a", "site-b"] {
        website
            .observe(
                WebsiteObservation::new(
                    format!("asset-{site}"),
                    site,
                    WebsiteFeatureKind::PublicAsset,
                    "assets/rare-logo.svg",
                    Source::new(
                        format!("web-source-{site}"),
                        SourceType::Website,
                        RetrievalMethod::Direct,
                    )
                    .unwrap(),
                    400,
                )
                .unwrap()
                .with_normalized_value("assets/rare-logo.svg"),
            )
            .unwrap();
    }
    website.correlate("site-a", "site-b").unwrap();
    website
}

/// Stage 4: a hypothesis and one supporting evidence item over a persisted
/// observation, fused. Returns the leading hypothesis id.
fn fusion_stage(store: &mut EvidenceStore) -> String {
    store
        .add_hypothesis(
            Hypothesis::new("h-operator", "one operator", HypothesisKind::Leading).unwrap(),
        )
        .unwrap();
    store
        .add_evidence(
            bleradar_core::Evidence::new(
                "ev-cert",
                "h-operator",
                "cert-node-a",
                EvidenceRole::Supporting,
            )
            .unwrap(),
        )
        .unwrap();
    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_assessment(EvidenceAssessment::new("ev-cert", EvidenceQuality::uniform(80)).unwrap())
        .unwrap();
    fusion.fuse(store).unwrap().leading_hypothesis().to_owned()
}

/// Threads one store through every stage, moving it between engines with
/// `into_evidence` (zero copy).
fn compose_by_move(filler: usize) -> (EvidenceStore, String) {
    let mut store = EvidenceStore::new();
    seed_filler(&mut store, filler);
    let store = osint_stage(store).into_evidence();
    let store = infrastructure_stage(store).into_evidence();
    let mut store = website_stage(store).into_evidence();
    let leading = fusion_stage(&mut store);
    (store, leading)
}

/// The same investigation, cloning the store at every engine hand-off — the
/// only mechanism available before `into_evidence`.
fn compose_by_clone(filler: usize) -> (EvidenceStore, String) {
    let mut store = EvidenceStore::new();
    seed_filler(&mut store, filler);
    let store = osint_stage(store).evidence().clone();
    let store = infrastructure_stage(store).evidence().clone();
    let mut store = website_stage(store).evidence().clone();
    let leading = fusion_stage(&mut store);
    (store, leading)
}

#[test]
fn one_canonical_store_threads_through_every_engine_and_validates() {
    let (store, leading) = compose_by_move(0);

    store
        .validate()
        .expect("the composed cross-engine store must be referentially valid");
    assert_eq!(leading, "h-operator");

    // Every engine's records live in the one store.
    assert!(
        store.observation(OSINT_FINDING).is_some(),
        "OSINT finding not persisted"
    );
    assert!(
        store.action(OSINT_ACTION).is_some(),
        "OSINT action not persisted"
    );
    assert!(
        store.entity("node-a").is_some(),
        "infrastructure node entity missing"
    );
    assert!(store.entity("site-a").is_some(), "website entity missing");
    assert!(
        store.relationship(INFRA_RELATIONSHIP).is_some(),
        "infrastructure correlation edge missing"
    );
    assert!(
        store.relationship(WEBSITE_RELATIONSHIP).is_some(),
        "website lineage edge missing"
    );
    assert!(store.hypothesis("h-operator").is_some());
    assert!(store.evidence("ev-cert").is_some());
}

#[test]
fn moving_the_store_between_engines_matches_cloning_it() {
    // `into_evidence` must change only the hand-off cost, not the result: the
    // composed store is identical whether the store is moved or cloned between
    // stages, at any store size.
    for filler in [0usize, 64, 512] {
        let (moved, moved_leading) = compose_by_move(filler);
        let (cloned, cloned_leading) = compose_by_clone(filler);
        assert_eq!(moved_leading, cloned_leading);
        assert_eq!(
            format!("{moved:?}"),
            format!("{cloned:?}"),
            "move-threaded and clone-threaded composed stores differ at filler={filler}"
        );
    }
}

#[test]
fn a_cross_engine_observation_id_collision_is_refused_without_corrupting_the_shared_store() {
    // When engines compose over one store, a later engine may be handed an
    // observation whose id an earlier engine already wrote. The later engine
    // must refuse the conflicting record transactionally: the shared store is
    // left exactly as it was — the original observation intact, no dangling
    // entity for the refused observation — and still valid.
    let store = osint_stage(EvidenceStore::new()).into_evidence();
    assert!(store.observation(OSINT_FINDING).is_some());
    let before = format!("{store:?}");

    let mut infra = TemporalMetamorphicInfrastructureCorrelationEngine::new(store);
    let colliding = InfrastructureObservation::new(
        OSINT_FINDING, // id already owned by the OSINT finding observation
        "node-collision",
        InfrastructureKind::Certificate,
        "infrastructure-value",
        Source::new(
            "infra-collision-source",
            SourceType::Website,
            RetrievalMethod::Direct,
        )
        .unwrap(),
        500,
    )
    .unwrap();
    let error = infra
        .observe(colliding)
        .expect_err("a conflicting cross-engine observation id must be refused");
    assert!(
        matches!(
            error,
            bleradar_core::InfrastructureError::ObservationConflict { .. }
        ),
        "expected ObservationConflict, got {error:?}"
    );

    let store = infra.into_evidence();
    assert_eq!(
        format!("{store:?}"),
        before,
        "a refused cross-engine observation must leave the shared store unchanged"
    );
    assert!(
        store.observation(OSINT_FINDING).is_some(),
        "original observation was dropped"
    );
    assert!(
        store.entity("node-collision").is_none(),
        "the refused observation left a dangling node entity"
    );
    store
        .validate()
        .expect("the shared store must remain valid after a refused observation");
}
