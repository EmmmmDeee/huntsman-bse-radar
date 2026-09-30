//! Regression tests for metamorphic software advancement gates.

use bleradar_core::{
    AdvancementError, AdvancementExecution, AdvancementFactors, AdvancementProposal,
    AdvancementRejection, AdvancementState, BenchmarkMetric, BenchmarkReport, DifferentialCase,
    ExecutionOutcome, FalsificationCheck, FalsificationFinding, FalsificationResult,
    FalsificationStatus, MetamorphicRelation, MetamorphicTest, MetricDirection, RequiredSemantics,
    VerificationEngine, VerificationSurface,
};

fn verification_engine() -> VerificationEngine {
    let semantics = RequiredSemantics::new("normalization contract")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_relation(MetamorphicRelation::NormalizationEquivalence);
    let test = MetamorphicTest::new(
        "normalization-1",
        MetamorphicRelation::NormalizationEquivalence,
        vec![b"AA:BB".to_vec(), b"AABB".to_vec()],
    )
    .unwrap();
    let mut engine = VerificationEngine::new(semantics);
    engine.add_test(test).unwrap();
    engine
}

fn execution() -> AdvancementExecution {
    let benchmark = BenchmarkReport::new([BenchmarkMetric::new(
        "throughput",
        10,
        20,
        MetricDirection::HigherIsBetter,
    )
    .unwrap()])
    .unwrap();
    AdvancementExecution::new(
        [DifferentialCase::new("case-1", b"AA:BB".to_vec()).unwrap()],
        benchmark,
        FalsificationResult::resistant(),
        true,
    )
}

fn normalize(input: &[u8]) -> ExecutionOutcome {
    ExecutionOutcome::success(
        input
            .iter()
            .copied()
            .filter(|byte| *byte != b':')
            .collect::<Vec<_>>(),
    )
}

#[test]
fn priority_formula_orders_low_cost_high_value_changes() {
    let factors = AdvancementFactors::new(100, 90, 80, 70, 10, 20).unwrap();
    assert_eq!(factors.priority().numerator(), 50_400_000);
    assert_eq!(factors.priority().denominator(), 200);

    let lower = AdvancementFactors::new(100, 90, 80, 70, 20, 20).unwrap();
    assert!(factors.priority() > lower.priority());
    assert!(AdvancementFactors::new(100, 100, 100, 100, 0, 1).is_err());
}

#[test]
fn accepted_change_requires_all_gates_and_integrates_explicitly() {
    let factors = AdvancementFactors::new(90, 90, 80, 90, 10, 10).unwrap();
    let proposal = AdvancementProposal::new(
        "normalize-fast",
        "normalize identifiers before comparison",
        factors,
    )
    .unwrap()
    .with_dependencies(["verification"])
    .limited_by("input normalization");
    let mut engine =
        bleradar_core::MetamorphicSoftwareAdvancementEngine::new(verification_engine());
    engine.add_proposal(proposal).unwrap();

    let decision = engine
        .evaluate("normalize-fast", execution(), normalize, normalize)
        .unwrap();

    assert!(decision.accepted());
    assert_eq!(
        engine.state("normalize-fast"),
        Some(AdvancementState::Accepted)
    );
    let remaining = engine.integrate("normalize-fast").unwrap();
    assert!(remaining.is_empty());
    let run = engine.run("normalize-fast").unwrap();
    assert_eq!(
        run.phases(),
        &[
            bleradar_core::AdvancementPhase::Verify,
            bleradar_core::AdvancementPhase::DifferentialExecute,
            bleradar_core::AdvancementPhase::Falsify,
            bleradar_core::AdvancementPhase::Benchmark,
            bleradar_core::AdvancementPhase::AcceptOrReject,
            bleradar_core::AdvancementPhase::Integrate,
            bleradar_core::AdvancementPhase::Recompute,
        ]
    );
}

#[test]
fn semantic_or_differential_failure_rejects_even_with_a_benchmark_gain() {
    let factors = AdvancementFactors::new(90, 90, 80, 90, 10, 10).unwrap();
    let proposal =
        AdvancementProposal::new("unsafe-change", "change output semantics", factors).unwrap();
    let mut engine = bleradar_core::SoftwareAdvancementEngine::new(verification_engine());
    engine.add_proposal(proposal).unwrap();

    let decision = engine
        .evaluate("unsafe-change", execution(), normalize, |input| {
            ExecutionOutcome::success(input)
        })
        .unwrap();

    assert!(!decision.accepted());
    assert_eq!(
        engine.state("unsafe-change"),
        Some(AdvancementState::Rejected)
    );
    assert!(
        decision
            .rejection_reasons()
            .contains(&AdvancementRejection::CandidateSemanticsNotPreserved)
    );
    assert!(
        decision
            .rejection_reasons()
            .contains(&AdvancementRejection::DifferentialMismatch)
    );
}

#[test]
fn unexplained_regression_and_nonreproducibility_are_rejections() {
    let factors = AdvancementFactors::new(90, 90, 80, 90, 10, 10).unwrap();
    let proposal =
        AdvancementProposal::new("regression", "faster but less reliable", factors).unwrap();
    let mut engine = bleradar_core::SoftwareAdvancementEngine::new(verification_engine());
    engine.add_proposal(proposal).unwrap();
    let benchmark = BenchmarkReport::new([
        BenchmarkMetric::new("throughput", 10, 20, MetricDirection::HigherIsBetter).unwrap(),
        BenchmarkMetric::new("errors", 1, 3, MetricDirection::LowerIsBetter).unwrap(),
    ])
    .unwrap();
    let execution = AdvancementExecution::new(
        [DifferentialCase::new("case-1", b"AA:BB".to_vec()).unwrap()],
        benchmark,
        FalsificationResult::resistant(),
        false,
    );

    let decision = engine
        .evaluate("regression", execution, normalize, normalize)
        .unwrap();

    assert!(!decision.accepted());
    assert!(
        decision
            .rejection_reasons()
            .contains(&AdvancementRejection::UnexplainedMaterialRegression)
    );
    assert!(
        decision
            .rejection_reasons()
            .contains(&AdvancementRejection::NotReproducible)
    );
}

#[test]
fn explained_material_regression_is_accepted_when_every_other_gate_passes() {
    let factors = AdvancementFactors::new(90, 90, 80, 90, 10, 10).unwrap();
    let proposal = AdvancementProposal::new(
        "traded-latency-for-throughput",
        "accepts higher latency for materially higher throughput",
        factors,
    )
    .unwrap();
    let mut engine = bleradar_core::SoftwareAdvancementEngine::new(verification_engine());
    engine.add_proposal(proposal).unwrap();
    let benchmark = BenchmarkReport::new([
        BenchmarkMetric::new("throughput", 10, 20, MetricDirection::HigherIsBetter).unwrap(),
        BenchmarkMetric::new("latency-ms", 5, 8, MetricDirection::LowerIsBetter)
            .unwrap()
            .explained_by("higher throughput batches more items, raising per-item latency"),
    ])
    .unwrap();
    assert_eq!(benchmark.material_regressions().len(), 1);
    assert!(benchmark.unexplained_material_regressions().is_empty());
    let execution = AdvancementExecution::new(
        [DifferentialCase::new("case-1", b"AA:BB".to_vec()).unwrap()],
        benchmark,
        FalsificationResult::resistant(),
        true,
    );

    let decision = engine
        .evaluate(
            "traded-latency-for-throughput",
            execution,
            normalize,
            normalize,
        )
        .unwrap();

    assert!(decision.accepted());
    assert!(decision.rejection_reasons().is_empty());
}

#[test]
fn ranked_proposals_orders_by_priority_and_excludes_rejected_proposals() {
    let low = AdvancementFactors::new(50, 50, 50, 50, 50, 50).unwrap();
    let high = AdvancementFactors::new(90, 90, 90, 90, 10, 10).unwrap();
    let mut engine =
        bleradar_core::MetamorphicSoftwareAdvancementEngine::new(verification_engine());
    engine
        .add_proposal(AdvancementProposal::new("b-proposal", "tied with a", low).unwrap())
        .unwrap();
    engine
        .add_proposal(AdvancementProposal::new("a-proposal", "tied with b", low).unwrap())
        .unwrap();
    engine
        .add_proposal(AdvancementProposal::new("c-proposal", "clearly higher value", high).unwrap())
        .unwrap();

    let ranked = engine.ranked_proposals();
    assert_eq!(
        ranked
            .iter()
            .map(bleradar_core::AdvancementRanking::proposal_id)
            .collect::<Vec<_>>(),
        vec!["c-proposal", "a-proposal", "b-proposal"]
    );

    // Rejecting the top-ranked proposal must remove it from the ranking
    // while leaving the still-active, equal-priority proposals in the
    // established tie-break (ascending id) order.
    let rejecting_execution = AdvancementExecution::new(
        Vec::<DifferentialCase>::new(),
        BenchmarkReport::new(Vec::new()).unwrap(),
        FalsificationResult::new(FalsificationStatus::Failed),
        false,
    );
    let decision = engine
        .evaluate("c-proposal", rejecting_execution, normalize, normalize)
        .unwrap();
    assert!(!decision.accepted());

    let ranked = engine.ranked_proposals();
    assert_eq!(
        ranked
            .iter()
            .map(bleradar_core::AdvancementRanking::proposal_id)
            .collect::<Vec<_>>(),
        vec!["a-proposal", "b-proposal"]
    );
}

#[test]
fn proposal_dependencies_and_limiter_are_recorded_and_retrievable() {
    let factors = AdvancementFactors::new(50, 50, 50, 50, 50, 50).unwrap();
    let bare = AdvancementProposal::new("bare", "no metadata recorded", factors).unwrap();
    assert!(bare.dependencies().is_empty());
    assert_eq!(bare.limiter(), None);

    let annotated = AdvancementProposal::new("annotated", "records model dependencies", factors)
        .unwrap()
        .with_dependencies(["model-dependency-a", "model-dependency-b"])
        .limited_by("awaiting upstream schema stabilization");
    assert_eq!(
        annotated.dependencies(),
        [
            "model-dependency-a".to_owned(),
            "model-dependency-b".to_owned()
        ]
    );
    assert_eq!(
        annotated.limiter(),
        Some("awaiting upstream schema stabilization")
    );
}

#[test]
fn falsification_result_requires_status_and_every_finding_to_pass() {
    // `resistant()` is a convenience constructor; the general path must
    // independently confirm both the enum status and the granular findings,
    // since a `Resistant` status with one failing check is not resistant.
    let mixed = FalsificationResult::new(FalsificationStatus::Resistant)
        .with_finding(
            FalsificationFinding::new(
                FalsificationCheck::StrongestAlternative,
                true,
                "no stronger alternative explanation was found",
            )
            .unwrap(),
        )
        .with_finding(
            FalsificationFinding::new(
                FalsificationCheck::UncertaintyPerturbation,
                false,
                "perturbing uncertain assumptions flipped the leading hypothesis",
            )
            .unwrap(),
        );
    assert_eq!(mixed.status(), FalsificationStatus::Resistant);
    assert_eq!(mixed.findings().len(), 2);
    assert!(!mixed.is_resistant());
    assert_eq!(
        mixed.findings()[1].check(),
        FalsificationCheck::UncertaintyPerturbation
    );
    assert!(!mixed.findings()[1].passed());
    assert_eq!(
        mixed.findings()[1].detail(),
        "perturbing uncertain assumptions flipped the leading hypothesis"
    );

    let inconclusive = FalsificationResult::new(FalsificationStatus::Inconclusive).with_finding(
        FalsificationFinding::new(
            FalsificationCheck::MissingExpectedEvidence,
            true,
            "an expected confirmation was never observed",
        )
        .unwrap(),
    );
    assert!(!inconclusive.is_resistant());
}

#[test]
fn falsification_finding_rejects_empty_detail() {
    assert_eq!(
        FalsificationFinding::new(FalsificationCheck::ContradictionSearch, false, ""),
        Err(AdvancementError::EmptyValue {
            field: "falsification detail"
        })
    );
}

#[test]
fn advancement_error_variants_cover_duplicate_missing_and_invalid_state_edge_cases() {
    assert_eq!(
        AdvancementFactors::new(100, 100, 100, 100, 100, 0),
        Err(AdvancementError::InvalidFactor {
            factor: "regression risk",
            value: 0,
        })
    );
    let factors = AdvancementFactors::new(50, 50, 50, 50, 50, 50).unwrap();
    assert_eq!(
        AdvancementProposal::new("", "description", factors),
        Err(AdvancementError::EmptyValue {
            field: "proposal id"
        })
    );
    assert_eq!(
        AdvancementProposal::new("id", "", factors),
        Err(AdvancementError::EmptyValue {
            field: "proposal description"
        })
    );
    assert_eq!(
        BenchmarkMetric::new("", 1, 2, MetricDirection::HigherIsBetter),
        Err(AdvancementError::EmptyValue {
            field: "benchmark metric name"
        })
    );
    assert_eq!(
        BenchmarkReport::new([
            BenchmarkMetric::new("throughput", 1, 2, MetricDirection::HigherIsBetter).unwrap(),
            BenchmarkMetric::new("throughput", 3, 4, MetricDirection::HigherIsBetter).unwrap(),
        ]),
        Err(AdvancementError::DuplicateMetric {
            metric: "throughput".to_owned()
        })
    );

    let mut engine = bleradar_core::SoftwareAdvancementEngine::new(verification_engine());
    engine
        .add_proposal(AdvancementProposal::new("dup", "first registration", factors).unwrap())
        .unwrap();
    assert_eq!(
        engine
            .add_proposal(AdvancementProposal::new("dup", "second registration", factors).unwrap()),
        Err(AdvancementError::DuplicateProposal {
            proposal_id: "dup".to_owned()
        })
    );
    assert_eq!(
        engine.evaluate("missing", execution(), normalize, normalize),
        Err(AdvancementError::MissingProposal {
            proposal_id: "missing".to_owned()
        })
    );
    assert_eq!(
        engine.integrate("missing"),
        Err(AdvancementError::MissingProposal {
            proposal_id: "missing".to_owned()
        })
    );
    // A `Proposed` proposal has not been accepted, so integration is invalid.
    assert_eq!(
        engine.integrate("dup"),
        Err(AdvancementError::InvalidState {
            proposal_id: "dup".to_owned(),
            state: AdvancementState::Proposed,
        })
    );

    let decision = engine
        .evaluate("dup", execution(), normalize, normalize)
        .unwrap();
    assert!(decision.accepted());
    // Re-evaluating an already-accepted proposal is invalid until it is
    // either integrated or a new proposal is registered.
    assert_eq!(
        engine.evaluate("dup", execution(), normalize, normalize),
        Err(AdvancementError::InvalidState {
            proposal_id: "dup".to_owned(),
            state: AdvancementState::Accepted,
        })
    );
}

#[test]
fn underlying_verification_engine_error_surfaces_as_an_advancement_error() {
    // A test registered for a relation the contract does not require causes
    // the shared verification engine to fail; `evaluate` must propagate that
    // as `AdvancementError::Verification`, not panic or silently continue.
    let semantics = RequiredSemantics::new("narrow contract")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_relation(MetamorphicRelation::NormalizationEquivalence);
    let mut verification = VerificationEngine::new(semantics);
    verification
        .add_test(
            MetamorphicTest::new(
                "wrong-relation",
                MetamorphicRelation::Idempotence,
                vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            )
            .unwrap(),
        )
        .unwrap();
    let factors = AdvancementFactors::new(50, 50, 50, 50, 50, 50).unwrap();
    let mut engine = bleradar_core::SoftwareAdvancementEngine::new(verification);
    engine
        .add_proposal(
            AdvancementProposal::new("misconfigured", "uses an unrequired relation", factors)
                .unwrap(),
        )
        .unwrap();

    let error = engine
        .evaluate("misconfigured", execution(), normalize, normalize)
        .unwrap_err();
    assert!(matches!(
        error,
        AdvancementError::Verification {
            error: bleradar_core::VerificationError::RelationNotRequired { .. }
        }
    ));
}
