//! Regression tests for execution-feedback adaptive OSINT search.

use bleradar_core::{
    ActionStatus, ActionType, EvidenceStore, EvidenceValue,
    ExecutionFeedbackAdaptiveOsintSearchEngine, RetrievalMethod, SearchError, SearchFeedback,
    SearchFinding, SearchLimits, SearchOutcome, SearchPhase, SearchPivot, SearchPivotSeed,
    SearchPivotState, SearchPriorityFactors, SearchRepresentation, Source, SourceType,
};

fn factors() -> SearchPriorityFactors {
    SearchPriorityFactors::new(80, 70, 60, 50, 40, 10, 20).unwrap()
}

fn pivot(id: &str, query: &str, representation: SearchRepresentation) -> SearchPivot {
    SearchPivot::new(id, query, representation, factors()).unwrap()
}

fn seed(query: &str, representation: SearchRepresentation) -> SearchPivotSeed {
    SearchPivotSeed::new(query, representation, factors()).unwrap()
}

#[test]
fn all_search_representations_are_available_in_stable_order() {
    assert_eq!(SearchRepresentation::ALL.len(), 11);
    assert_eq!(
        SearchRepresentation::ALL
            .iter()
            .map(|representation| representation.as_str())
            .collect::<Vec<_>>(),
        vec![
            "exact",
            "normalized",
            "alias",
            "historical",
            "semantic",
            "structural",
            "temporal",
            "relational",
            "technical",
            "provenance",
            "graph_neighbor",
        ]
    );
}

#[test]
fn priority_uses_the_exact_information_to_risk_formula() {
    let factors = SearchPriorityFactors::new(100, 90, 80, 70, 60, 10, 20).unwrap();
    let priority = factors.priority();

    assert_eq!(priority.numerator(), 3_024_000_000);
    assert_eq!(priority.denominator(), 200);
    assert_eq!(priority.scaled(), 15_120_000_000_000);
    assert!(SearchPriorityFactors::new(100, 100, 100, 100, 100, 0, 1).is_err());
}

#[test]
fn classification_distinguishes_useful_weak_duplicate_and_inconclusive_results() {
    assert_eq!(
        SearchFeedback::classified(0, 0, 0, 0, 0).outcome(),
        SearchOutcome::NoResults
    );
    assert_eq!(
        SearchFeedback::classified(2, 1, 1, 0, 0).outcome(),
        SearchOutcome::Useful
    );
    assert_eq!(
        SearchFeedback::classified(2, 0, 0, 1, 0).outcome(),
        SearchOutcome::Duplicate
    );
    assert_eq!(
        SearchFeedback::classified(2, 0, 0, 0, 0).outcome(),
        SearchOutcome::Weak
    );
    assert_eq!(
        SearchFeedback::classified(2, 0, 1, 0, 0).outcome(),
        SearchOutcome::Inconclusive
    );
    assert_eq!(
        SearchFeedback::classified(2, 0, 1, 0, 1).outcome(),
        SearchOutcome::Contradictory
    );
    assert!(
        !SearchFeedback::failed("timeout")
            .unwrap()
            .outcome()
            .completed()
    );
}

#[test]
fn raw_queries_and_values_are_preserved_alongside_normalized_forms() {
    let pivot = SearchPivot::new("pivot-1", " AA:BB ", SearchRepresentation::Exact, factors())
        .unwrap()
        .with_normalization("aabb")
        .unwrap();
    assert_eq!(pivot.raw_query(), " AA:BB ");
    assert_eq!(pivot.normalized_query(), Some("aabb"));
    assert_eq!(pivot.query_for_execution(), "aabb");

    let source = Source::new("source-1", SourceType::Website, RetrievalMethod::Search).unwrap();
    let finding = SearchFinding::new("finding-1", " AA:BB ", source, 10)
        .unwrap()
        .with_normalized_value("aabb");
    assert_eq!(
        finding.raw_value(),
        &EvidenceValue::Text(" AA:BB ".to_owned())
    );
    assert_eq!(
        finding.normalized_value(),
        Some(&EvidenceValue::Text("aabb".to_owned()))
    );
}

#[test]
fn useful_feedback_increases_pressure_for_the_same_representation_family() {
    let mut engine = ExecutionFeedbackAdaptiveOsintSearchEngine::new(EvidenceStore::new());
    engine
        .add_pivot(pivot("exact-1", "first", SearchRepresentation::Exact))
        .unwrap();
    engine
        .add_pivot(pivot("exact-2", "second", SearchRepresentation::Exact))
        .unwrap();
    engine
        .add_pivot(pivot(
            "semantic-1",
            "description",
            SearchRepresentation::Semantic,
        ))
        .unwrap();

    let execution = engine
        .execute("exact-1", 10, |_| SearchFeedback::classified(1, 1, 1, 0, 0))
        .unwrap();
    assert_eq!(execution.feedback().outcome(), SearchOutcome::Useful);
    assert_eq!(engine.statistics(SearchRepresentation::Exact).useful(), 1);
    assert_eq!(
        engine
            .statistics(SearchRepresentation::Exact)
            .adaptive_pressure(),
        100
    );
    assert_eq!(engine.ranked_pivots()[0].pivot_id(), "exact-2");
    assert_eq!(engine.next_pivot().unwrap().id(), "exact-2");
}

#[test]
fn generated_pivots_keep_parent_provenance_and_suppress_duplicates() {
    let mut engine = ExecutionFeedbackAdaptiveOsintSearchEngine::new(EvidenceStore::new());
    engine
        .add_pivot(pivot("root", "root-query", SearchRepresentation::Exact))
        .unwrap();

    let normalized = seed("child-raw", SearchRepresentation::Normalized)
        .with_normalization("child-normalized")
        .unwrap();
    let duplicate_normalized = seed("different-raw", SearchRepresentation::Normalized)
        .with_normalization("child-normalized")
        .unwrap();
    let duplicate_root = seed("root-query", SearchRepresentation::Exact);
    let alias = seed("alternate", SearchRepresentation::Alias)
        .with_rationale("follow the discovered alias")
        .unwrap();

    let execution = engine
        .execute("root", 20, |_| {
            SearchFeedback::new(SearchOutcome::NoResults, 0)
                .with_next_pivot(normalized)
                .with_next_pivot(duplicate_normalized)
                .with_next_pivot(duplicate_root)
                .with_next_pivot(alias)
        })
        .unwrap();

    assert_eq!(
        execution.generated_pivot_ids(),
        &["root::pivot-0".to_owned(), "root::pivot-1".to_owned()]
    );
    assert_eq!(execution.suppressed_pivots().len(), 2);
    assert_eq!(engine.pivot_count(), 3);
    let child = engine.pivot("root::pivot-0").unwrap();
    assert_eq!(child.parent_id(), Some("root"));
    assert_eq!(child.raw_query(), "child-raw");
    assert_eq!(child.normalized_query(), Some("child-normalized"));
    assert_eq!(child.rationale(), "execution-feedback pivot");
    assert_eq!(
        engine.pivot("root::pivot-1").unwrap().rationale(),
        "follow the discovered alias"
    );
}

#[test]
fn findings_and_retrieval_actions_are_persisted_in_the_canonical_store() {
    let source = Source::new("web-source", SourceType::Website, RetrievalMethod::Search)
        .unwrap()
        .with_locator("https://example.test/search")
        .captured_at(5)
        .with_metadata("provider", "public-index");
    let finding = SearchFinding::new("observation-1", " AA:BB ", source.clone(), 30)
        .unwrap()
        .with_normalized_value("aabb")
        .in_dependency_group("provider-result")
        .unwrap();
    assert_eq!(finding.dependency_group(), Some("provider-result"));

    let mut engine = ExecutionFeedbackAdaptiveOsintSearchEngine::new(EvidenceStore::new());
    engine
        .add_pivot(pivot("search-1", "AA:BB", SearchRepresentation::Exact))
        .unwrap();
    let execution = engine
        .execute("search-1", 30, |_| {
            SearchFeedback::classified(1, 1, 1, 0, 0)
                .with_independent_sources(1)
                .with_finding(finding)
                .with_note("one source-backed result")
        })
        .unwrap();

    assert_eq!(
        execution.phases(),
        &[
            SearchPhase::Query,
            SearchPhase::Execute,
            SearchPhase::Observe,
            SearchPhase::Classify,
            SearchPhase::Update,
            SearchPhase::GenerateNextPivot,
            SearchPhase::Rank,
        ]
    );
    assert_eq!(execution.observation_ids(), &["observation-1".to_owned()]);
    let observation = engine.evidence().observation("observation-1").unwrap();
    assert_eq!(
        observation.raw_value(),
        &EvidenceValue::Text(" AA:BB ".to_owned())
    );
    assert_eq!(
        observation.normalized_value(),
        Some(&EvidenceValue::Text("aabb".to_owned()))
    );
    assert_eq!(observation.source(), "web-source");
    assert_eq!(observation.source_type(), &SourceType::Website);
    assert_eq!(observation.retrieval_method(), &RetrievalMethod::Search);
    assert_eq!(observation.first_seen(), 30);
    assert_eq!(observation.observed_at(), 30);
    assert_eq!(observation.last_seen(), 30);
    assert_eq!(engine.evidence().source("web-source").unwrap(), &source);

    let action = engine.evidence().action(execution.action_id()).unwrap();
    assert_eq!(action.kind(), &ActionType::Retrieve);
    assert_eq!(action.status(), ActionStatus::Succeeded);
    assert_eq!(action.target(), Some("search-1"));
    assert!(engine.evidence().validate().is_ok());
}

#[test]
fn failed_and_inconclusive_executions_are_retained_as_failed_actions() {
    let mut engine = ExecutionFeedbackAdaptiveOsintSearchEngine::new(EvidenceStore::new());
    engine
        .add_pivot(pivot("failed", "network", SearchRepresentation::Technical))
        .unwrap();
    engine
        .add_pivot(pivot(
            "inconclusive",
            "ambiguous",
            SearchRepresentation::Semantic,
        ))
        .unwrap();

    let failed = engine
        .execute_result("failed", 40, |_| -> Result<SearchFeedback, &'static str> {
            Err("network unavailable")
        })
        .unwrap();
    assert_eq!(failed.feedback().outcome(), SearchOutcome::Failed);
    assert_eq!(failed.feedback().error(), Some("network unavailable"));
    assert_eq!(
        engine
            .evidence()
            .action(failed.action_id())
            .unwrap()
            .status(),
        ActionStatus::Failed
    );

    let inconclusive = engine
        .execute("inconclusive", 50, |_| {
            SearchFeedback::new(SearchOutcome::Inconclusive, 1).with_note("ambiguous response")
        })
        .unwrap();
    assert_eq!(
        inconclusive.feedback().outcome(),
        SearchOutcome::Inconclusive
    );
    assert_eq!(
        engine
            .evidence()
            .action(inconclusive.action_id())
            .unwrap()
            .status(),
        ActionStatus::Failed
    );
    assert_eq!(
        engine.statistics(SearchRepresentation::Technical).failed(),
        1
    );
    assert_eq!(
        engine
            .statistics(SearchRepresentation::Semantic)
            .inconclusive(),
        1
    );
    assert_eq!(engine.execution_count(), 2);
}

#[test]
fn conflicting_source_metadata_is_rejected_without_partial_persistence() {
    let source = Source::new(
        "shared-source",
        SourceType::Website,
        RetrievalMethod::Search,
    )
    .unwrap();
    let conflicting_source = Source::new(
        "shared-source",
        SourceType::Archive,
        RetrievalMethod::Archive,
    )
    .unwrap();
    let first_finding = SearchFinding::new("first-observation", "one", source, 60).unwrap();
    let second_finding =
        SearchFinding::new("second-observation", "two", conflicting_source, 70).unwrap();

    let mut engine = ExecutionFeedbackAdaptiveOsintSearchEngine::new(EvidenceStore::new());
    engine
        .add_pivot(pivot("first", "one", SearchRepresentation::Exact))
        .unwrap();
    engine
        .add_pivot(pivot("second", "two", SearchRepresentation::Exact))
        .unwrap();
    engine
        .execute("first", 60, |_| {
            SearchFeedback::new(SearchOutcome::Useful, 1).with_finding(first_finding)
        })
        .unwrap();

    let error = engine
        .execute("second", 70, |_| {
            SearchFeedback::new(SearchOutcome::Useful, 1).with_finding(second_finding)
        })
        .unwrap_err();
    assert_eq!(
        error,
        SearchError::SourceConflict {
            source_id: "shared-source".to_owned()
        }
    );
    assert_eq!(engine.execution_count(), 1);
    assert!(
        engine
            .evidence()
            .observation("second-observation")
            .is_none()
    );
    assert_eq!(
        engine.pivot("second").unwrap().state(),
        SearchPivotState::Proposed
    );
}

#[test]
fn pivots_can_be_exhausted_without_becoming_executable() {
    let limits = SearchLimits::new(1, 1).unwrap();
    let mut engine =
        ExecutionFeedbackAdaptiveOsintSearchEngine::with_limits(EvidenceStore::new(), limits);
    engine
        .add_pivot(pivot(
            "retire",
            "retire-me",
            SearchRepresentation::Historical,
        ))
        .unwrap();
    engine.exhaust("retire").unwrap();

    assert_eq!(
        engine.pivot("retire").unwrap().state(),
        SearchPivotState::Exhausted
    );
    assert!(!engine.has_ready_pivot());
    assert!(matches!(
        engine.exhaust("retire"),
        Err(SearchError::InvalidState { .. })
    ));
}

#[test]
fn graph_neighbor_representation_can_be_used_as_a_pivots_representation() {
    let mut engine = ExecutionFeedbackAdaptiveOsintSearchEngine::new(EvidenceStore::new());
    engine
        .add_pivot(pivot(
            "neighbor-1",
            "neighboring-node",
            SearchRepresentation::GraphNeighbor,
        ))
        .unwrap();

    let execution = engine
        .execute("neighbor-1", 10, |candidate| {
            assert_eq!(
                candidate.representation(),
                SearchRepresentation::GraphNeighbor
            );
            SearchFeedback::classified(1, 1, 1, 0, 0)
        })
        .unwrap();

    assert_eq!(execution.feedback().outcome(), SearchOutcome::Useful);
    assert_eq!(
        engine.pivot("neighbor-1").unwrap().representation(),
        SearchRepresentation::GraphNeighbor
    );
    assert_eq!(
        engine
            .statistics(SearchRepresentation::GraphNeighbor)
            .useful(),
        1
    );
}

#[test]
fn exhausting_an_already_executed_pivot_is_rejected() {
    let mut engine = ExecutionFeedbackAdaptiveOsintSearchEngine::new(EvidenceStore::new());
    engine
        .add_pivot(pivot(
            "executed",
            "already-run",
            SearchRepresentation::Exact,
        ))
        .unwrap();
    engine
        .execute("executed", 10, |_| {
            SearchFeedback::classified(1, 1, 1, 0, 0)
        })
        .unwrap();
    assert_eq!(
        engine.pivot("executed").unwrap().state(),
        SearchPivotState::Executed
    );

    assert_eq!(
        engine.exhaust("executed"),
        Err(SearchError::InvalidState {
            pivot_id: "executed".to_owned(),
            state: SearchPivotState::Executed,
        })
    );
    // A rejected exhaustion attempt must leave the pivot's state untouched.
    assert_eq!(
        engine.pivot("executed").unwrap().state(),
        SearchPivotState::Executed
    );
}

#[test]
fn resource_limits_allow_up_to_the_configured_count_then_reject_the_next_attempt() {
    let limits = SearchLimits::new(2, 3).unwrap();
    let mut engine =
        ExecutionFeedbackAdaptiveOsintSearchEngine::with_limits(EvidenceStore::new(), limits);

    engine
        .add_pivot(pivot("pivot-1", "query-1", SearchRepresentation::Exact))
        .unwrap();
    engine
        .add_pivot(pivot("pivot-2", "query-2", SearchRepresentation::Exact))
        .unwrap();
    engine
        .add_pivot(pivot("pivot-3", "query-3", SearchRepresentation::Exact))
        .unwrap();
    assert_eq!(engine.pivot_count(), 3);

    assert_eq!(
        engine.add_pivot(pivot("pivot-4", "query-4", SearchRepresentation::Exact)),
        Err(SearchError::ResourceLimit {
            resource: "pivot",
            limit: 3,
        })
    );
    assert_eq!(engine.pivot_count(), 3);

    engine
        .execute("pivot-1", 10, |_| SearchFeedback::classified(1, 1, 1, 0, 0))
        .unwrap();
    engine
        .execute("pivot-2", 20, |_| SearchFeedback::classified(1, 1, 1, 0, 0))
        .unwrap();
    assert_eq!(engine.execution_count(), 2);

    assert_eq!(
        engine.execute("pivot-3", 30, |_| SearchFeedback::classified(1, 1, 1, 0, 0)),
        Err(SearchError::ResourceLimit {
            resource: "execution",
            limit: 2,
        })
    );
    assert_eq!(engine.execution_count(), 2);
    // The pivot itself must be untouched by the rejected execution attempt.
    assert_eq!(
        engine.pivot("pivot-3").unwrap().state(),
        SearchPivotState::Proposed
    );
}
