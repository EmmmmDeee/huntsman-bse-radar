//! Regression tests for metamorphic and differential verification.

use bleradar_core::{
    DifferentialCase, EvidenceValue, ExecutionOutcome, FailureCause, MetamorphicRelation,
    MetamorphicTest, Observation, ProvenanceError, RegressionLock, RepairRecord, RequiredSemantics,
    RetrievalMethod, Source, SourceType, TestStatus, VerificationEngine, VerificationError,
    VerificationSurface,
};

fn semantics(relation: MetamorphicRelation) -> RequiredSemantics {
    RequiredSemantics::new("verification contract")
        .unwrap()
        .requires_all_observables()
        .requires_relation(relation)
}

/// A contract that only compares outputs, so passing cases are not
/// incidentally marked inconclusive by unset surfaces (such as the
/// contractual-performance measurement) that this relation does not exercise.
fn output_semantics(relation: MetamorphicRelation) -> RequiredSemantics {
    RequiredSemantics::new("output-only contract")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_relation(relation)
}

#[test]
fn generated_normalization_case_passes_and_records_family_feedback() {
    let test = MetamorphicTest::generated(
        "normalize-1",
        MetamorphicRelation::NormalizationEquivalence,
        b"AA:BB".to_vec(),
        |input| Ok(input.iter().copied().filter(|byte| *byte != b':').collect()),
    )
    .unwrap();
    let required = RequiredSemantics::new("normalization contract")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_relation(MetamorphicRelation::NormalizationEquivalence);
    let mut engine = VerificationEngine::new(required);
    engine.add_test(test).unwrap();

    let report = engine
        .verify(|input| {
            ExecutionOutcome::success(
                input
                    .iter()
                    .copied()
                    .filter(|byte| *byte != b':')
                    .map(|byte| byte.to_ascii_uppercase())
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap();

    assert!(report.passed());
    assert_eq!(report.executed_tests(), 1);
    assert_eq!(report.passed_tests(), 1);
    assert_eq!(
        engine.family_pressure(MetamorphicRelation::NormalizationEquivalence),
        1
    );
}

#[test]
fn idempotence_failure_is_minimized_and_classified() {
    let test = MetamorphicTest::new(
        "idempotence-1",
        MetamorphicRelation::Idempotence,
        vec![b"raw".to_vec(), b"once".to_vec(), b"twice".to_vec()],
    )
    .unwrap();
    let mut engine = VerificationEngine::new(semantics(MetamorphicRelation::Idempotence));
    engine.add_test(test).unwrap();

    let report = engine
        .verify(|input| {
            if input == b"twice" {
                ExecutionOutcome::success(b"different".to_vec())
            } else {
                ExecutionOutcome::success(input)
            }
        })
        .unwrap();

    assert!(!report.passed());
    assert_eq!(report.violations().len(), 1);
    let violation = &report.violations()[0];
    assert_eq!(
        violation.root_cause(),
        FailureCause::ObservableDivergence(VerificationSurface::Outputs)
    );
    assert!(violation.minimized_input().is_some());
    assert_eq!(violation.minimized_inputs().unwrap().len(), 3);
    assert_eq!(engine.family_pressure(MetamorphicRelation::Idempotence), 2);
}

#[test]
fn differential_report_keeps_required_side_effects_visible() {
    let required = RequiredSemantics::new("side effects")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_surface(VerificationSurface::SideEffects);
    let engine = VerificationEngine::new(required);
    let cases = vec![DifferentialCase::new("case-1", b"input".to_vec()).unwrap()];

    let report = engine.differential(
        cases,
        |_| ExecutionOutcome::success(b"same".to_vec()).with_side_effects(["write-a"]),
        |_| ExecutionOutcome::success(b"same".to_vec()).with_side_effects(["write-b"]),
    );

    assert!(!report.passed());
    assert_eq!(report.violations()[0].case_id(), "case-1");
    assert_eq!(
        report.violations()[0].root_cause(),
        FailureCause::ObservableDivergence(VerificationSurface::SideEffects)
    );
    assert_eq!(report.violations()[0].input(), b"input");
    assert!(report.violations()[0].minimized_input().is_some());
}

#[test]
fn repairs_locks_and_retirement_are_explicit_state_transitions() {
    let relation = MetamorphicRelation::PermutationEquivalence;
    let test = MetamorphicTest::new(
        "permutation-1",
        relation,
        vec![b"abc".to_vec(), b"cba".to_vec()],
    )
    .unwrap();
    let mut engine = VerificationEngine::new(semantics(relation));
    engine.add_test(test.clone()).unwrap();
    engine
        .record_repair(
            RepairRecord::new("permutation-1", "canonicalize before comparison").unwrap(),
        )
        .unwrap();
    engine
        .add_regression_lock(
            RegressionLock::new(
                "lock-1",
                "permutation-1",
                relation,
                test.inputs().to_owned(),
                "preserve permutation behavior",
            )
            .unwrap(),
        )
        .unwrap();
    engine.retire_test("permutation-1").unwrap();

    let report = engine
        .verify(|input| ExecutionOutcome::success(input))
        .unwrap();

    assert_eq!(report.executed_tests(), 0);
    assert_eq!(report.retired_tests(), &["permutation-1".to_owned()]);
    assert_eq!(report.regression_locks(), &["lock-1".to_owned()]);
    assert_eq!(report.repairs()[0].test_id(), "permutation-1");
}

#[test]
fn monotonicity_checks_outputs_and_contractual_measurements() {
    let required = RequiredSemantics::new("monotonic contract")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_relation(MetamorphicRelation::Monotonicity);
    let mut engine = VerificationEngine::new(required);
    engine
        .add_test(
            MetamorphicTest::new(
                "monotonic-1",
                MetamorphicRelation::Monotonicity,
                vec![b"low".to_vec(), b"high".to_vec()],
            )
            .unwrap(),
        )
        .unwrap();

    let report = engine
        .verify(|input| {
            ExecutionOutcome::success(input)
                .with_monotonic_value(10)
                .with_output(if input == b"low" { b"old" } else { b"new" })
        })
        .unwrap();
    assert_eq!(
        report.violations()[0].root_cause(),
        FailureCause::ObservableDivergence(VerificationSurface::Outputs)
    );

    let required = RequiredSemantics::new("measured monotonic contract")
        .unwrap()
        .requires_surface(VerificationSurface::PerformanceWhenContractual)
        .requires_relation(MetamorphicRelation::Monotonicity);
    let mut engine = VerificationEngine::new(required);
    engine
        .add_test(
            MetamorphicTest::new(
                "monotonic-2",
                MetamorphicRelation::Monotonicity,
                vec![b"low".to_vec(), b"high".to_vec()],
            )
            .unwrap(),
        )
        .unwrap();
    let report = engine
        .verify(|input| ExecutionOutcome::success(input).with_monotonic_value(10))
        .unwrap();
    assert_eq!(report.inconclusive_tests(), 1);
    assert!(!report.passed());
}

#[test]
fn verification_results_can_be_persisted_in_the_canonical_store() {
    let required = RequiredSemantics::new("persisted contract")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_relation(MetamorphicRelation::NormalizationEquivalence);
    let mut engine = VerificationEngine::new(required);
    engine
        .add_test(
            MetamorphicTest::new(
                "persisted-1",
                MetamorphicRelation::NormalizationEquivalence,
                vec![b"raw".to_vec(), b"RAW".to_vec()],
            )
            .unwrap(),
        )
        .unwrap();
    let report = engine
        .verify(|input| ExecutionOutcome::success(input.to_ascii_uppercase()))
        .unwrap();

    let source = Source::new(
        "verification-source",
        SourceType::Derived,
        RetrievalMethod::Direct,
    )
    .unwrap();
    let observation = Observation::from_source(
        "verification-observation",
        EvidenceValue::Text("raw".to_owned()),
        None,
        &source,
        1,
    )
    .unwrap();
    let mut store = bleradar_core::EvidenceStore::new();
    store.add_source(source).unwrap();
    store.add_observation(observation).unwrap();

    report
        .persist_test(
            &mut store,
            "persisted-1",
            "normalization preserves output",
            2,
            vec!["verification-observation".to_owned()],
            vec!["verification-observation".to_owned()],
        )
        .unwrap();
    assert_eq!(
        store.test("persisted-1").unwrap().status(),
        TestStatus::Passed
    );
}

#[test]
fn invariance_relation_compares_every_input_against_the_first() {
    // Invariance is the only relation compared as (first, every-other) rather
    // than a single (0, 1) pair, so it needs its own multi-input test vector.
    let relation = MetamorphicRelation::Invariance;
    let inputs = || vec![b"1".to_vec(), b"01".to_vec(), b"0001".to_vec()];

    let mut engine = VerificationEngine::new(output_semantics(relation));
    engine
        .add_test(MetamorphicTest::new("invariance-pass", relation, inputs()).unwrap())
        .unwrap();
    let report = engine
        .verify(|_input| ExecutionOutcome::success(b"1".to_vec()))
        .unwrap();
    assert!(report.passed());
    assert_eq!(report.executed_tests(), 1);

    let mut engine = VerificationEngine::new(output_semantics(relation));
    engine
        .add_test(MetamorphicTest::new("invariance-fail", relation, inputs()).unwrap())
        .unwrap();
    let report = engine
        .verify(|input| {
            if input == b"0001" {
                ExecutionOutcome::success(b"wrong".to_vec())
            } else {
                ExecutionOutcome::success(b"1".to_vec())
            }
        })
        .unwrap();
    assert_eq!(report.violations().len(), 1);
    let violation = &report.violations()[0];
    assert_eq!(violation.relation(), relation);
    assert_eq!(violation.left_input_index(), 0);
    assert_eq!(violation.right_input_index(), 2);
}

#[test]
fn pairwise_relations_pass_on_equivalent_outcomes_and_fail_on_divergent_ones() {
    // Commutativity, reversibility, round-trip, partition-recombination, and
    // permutation equivalence are each declared explicitly as a dedicated two
    // input test vector so every relation family is proven independently,
    // even though they share the same (0, 1) pairwise comparison.
    let relations = [
        MetamorphicRelation::Commutativity,
        MetamorphicRelation::Reversibility,
        MetamorphicRelation::RoundTripConsistency,
        MetamorphicRelation::PartitionRecombinationEquivalence,
        MetamorphicRelation::PermutationEquivalence,
    ];
    for relation in relations {
        let mut engine = VerificationEngine::new(output_semantics(relation));
        engine
            .add_test(
                MetamorphicTest::new(
                    format!("{relation:?}-pass"),
                    relation,
                    vec![b"left-form".to_vec(), b"right-form".to_vec()],
                )
                .unwrap(),
            )
            .unwrap();
        let report = engine
            .verify(|_input| ExecutionOutcome::success(b"canonical".to_vec()))
            .unwrap();
        assert!(
            report.passed(),
            "{relation:?} must pass when both forms observe identically"
        );
        assert_eq!(report.executed_tests(), 1);

        let mut engine = VerificationEngine::new(output_semantics(relation));
        engine
            .add_test(
                MetamorphicTest::new(
                    format!("{relation:?}-fail"),
                    relation,
                    vec![b"left-form".to_vec(), b"right-form".to_vec()],
                )
                .unwrap(),
            )
            .unwrap();
        let report = engine
            .verify(|input| ExecutionOutcome::success(input.to_vec()))
            .unwrap();
        assert_eq!(
            report.violations().len(),
            1,
            "{relation:?} must flag a divergent observable outcome"
        );
        assert_eq!(report.violations()[0].relation(), relation);
        assert_eq!(
            report.violations()[0].root_cause(),
            FailureCause::ObservableDivergence(VerificationSurface::Outputs)
        );
    }
}

#[test]
fn concurrency_restart_and_recovery_surfaces_are_compared_and_can_diverge() {
    let required = RequiredSemantics::new("lifecycle contract")
        .unwrap()
        .requires_surface(VerificationSurface::Concurrency)
        .requires_surface(VerificationSurface::Restart)
        .requires_surface(VerificationSurface::Recovery)
        .requires_relation(MetamorphicRelation::RoundTripConsistency);
    let mut engine = VerificationEngine::new(required);
    engine
        .add_test(
            MetamorphicTest::new(
                "lifecycle-pass",
                MetamorphicRelation::RoundTripConsistency,
                vec![b"a".to_vec(), b"b".to_vec()],
            )
            .unwrap(),
        )
        .unwrap();
    let report = engine
        .verify(|_input| {
            ExecutionOutcome::success(b"out".to_vec())
                .with_concurrency(["lock-acquired", "lock-released"])
                .with_restart(["state-reloaded"])
                .with_recovery(["resumed-from-checkpoint"])
        })
        .unwrap();
    assert!(report.passed());

    let required = RequiredSemantics::new("lifecycle contract")
        .unwrap()
        .requires_surface(VerificationSurface::Concurrency)
        .requires_surface(VerificationSurface::Restart)
        .requires_surface(VerificationSurface::Recovery)
        .requires_relation(MetamorphicRelation::RoundTripConsistency);
    let mut engine = VerificationEngine::new(required);
    engine
        .add_test(
            MetamorphicTest::new(
                "lifecycle-fail",
                MetamorphicRelation::RoundTripConsistency,
                vec![b"a".to_vec(), b"b".to_vec()],
            )
            .unwrap(),
        )
        .unwrap();
    let report = engine
        .verify(|input| {
            let recovery = if input == b"a" {
                vec!["resumed-from-checkpoint"]
            } else {
                vec!["replayed-from-scratch"]
            };
            ExecutionOutcome::success(b"out".to_vec())
                .with_concurrency(["lock-acquired", "lock-released"])
                .with_restart(["state-reloaded"])
                .with_recovery(recovery)
        })
        .unwrap();
    assert_eq!(report.violations().len(), 1);
    assert_eq!(
        report.violations()[0].root_cause(),
        FailureCause::ObservableDivergence(VerificationSurface::Recovery)
    );
    assert_eq!(
        report.violations()[0].baseline().recovery(),
        ["resumed-from-checkpoint".to_owned()]
    );
    assert_eq!(
        report.violations()[0].variant().recovery(),
        ["replayed-from-scratch".to_owned()]
    );
}

#[test]
fn generated_transformation_failure_is_reported_for_the_first_and_second_application() {
    assert_eq!(
        MetamorphicTest::generated(
            "gen-first-fails",
            MetamorphicRelation::NormalizationEquivalence,
            b"input".to_vec(),
            |_input| Err("first application failed".to_owned()),
        ),
        Err(VerificationError::TransformationFailed {
            test_id: "gen-first-fails".to_owned(),
            reason: "first application failed".to_owned(),
        })
    );

    // Idempotence applies the transform twice; the second application must
    // be attributable to the same test id even though it runs on different
    // input (the once-transformed output).
    assert_eq!(
        MetamorphicTest::generated(
            "gen-second-fails",
            MetamorphicRelation::Idempotence,
            b"input".to_vec(),
            |input| if input == b"input" {
                Ok(b"once".to_vec())
            } else {
                Err("second application failed".to_owned())
            },
        ),
        Err(VerificationError::TransformationFailed {
            test_id: "gen-second-fails".to_owned(),
            reason: "second application failed".to_owned(),
        })
    );
}

#[test]
fn canonical_store_error_wraps_test_construction_failures() {
    let required = RequiredSemantics::new("persisted contract")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_relation(MetamorphicRelation::NormalizationEquivalence);
    let mut engine = VerificationEngine::new(required);
    engine
        .add_test(
            MetamorphicTest::new(
                "persisted-empty-name",
                MetamorphicRelation::NormalizationEquivalence,
                vec![b"raw".to_vec(), b"RAW".to_vec()],
            )
            .unwrap(),
        )
        .unwrap();
    let report = engine
        .verify(|input| ExecutionOutcome::success(input.to_ascii_uppercase()))
        .unwrap();
    let mut store = bleradar_core::EvidenceStore::new();

    assert_eq!(
        report.persist_test(
            &mut store,
            "persisted-empty-name",
            "",
            1,
            Vec::new(),
            Vec::new()
        ),
        Err(VerificationError::CanonicalStore {
            error: ProvenanceError::EmptyValue { field: "test name" }
        })
    );
}

#[test]
fn canonical_store_error_wraps_store_insertion_failures() {
    let required = RequiredSemantics::new("persisted contract")
        .unwrap()
        .requires_surface(VerificationSurface::Outputs)
        .requires_relation(MetamorphicRelation::NormalizationEquivalence);
    let mut engine = VerificationEngine::new(required);
    engine
        .add_test(
            MetamorphicTest::new(
                "persisted-dangling",
                MetamorphicRelation::NormalizationEquivalence,
                vec![b"raw".to_vec(), b"RAW".to_vec()],
            )
            .unwrap(),
        )
        .unwrap();
    let report = engine
        .verify(|input| ExecutionOutcome::success(input.to_ascii_uppercase()))
        .unwrap();
    let mut store = bleradar_core::EvidenceStore::new();

    let error = report
        .persist_test(
            &mut store,
            "persisted-dangling",
            "normalization preserves output",
            1,
            vec!["missing-observation".to_owned()],
            Vec::new(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        VerificationError::CanonicalStore {
            error: ProvenanceError::MissingReference { .. }
        }
    ));
    assert!(store.test("persisted-dangling").is_none());
}
