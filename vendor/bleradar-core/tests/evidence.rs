//! Regression tests for the canonical evidence and provenance core.

use bleradar_core::{
    Artifact, ArtifactType, Claim, Confidence, Evidence, EvidenceRole, EvidenceStore,
    EvidenceValue, Hypothesis, HypothesisKind, Observation, ObservationTimeline, ProvenanceError,
    Representation, RepresentationType, RetrievalMethod, Source, SourceType, Test, TestType,
    Transformation, Verification,
};

fn source() -> Source {
    Source::new("source-1", SourceType::Sensor, RetrievalMethod::Direct).unwrap()
}

fn observation(source: &Source) -> Observation {
    Observation::from_source(
        "observation-1",
        EvidenceValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        Some(EvidenceValue::Text("deadbeef".to_owned())),
        source,
        100,
    )
    .unwrap()
}

#[test]
fn observation_keeps_raw_value_when_normalized() {
    let source = source();
    let original = observation(&source);
    let normalized = original
        .with_normalization("DE:AD:BE:EF", "normalization-1")
        .unwrap();

    assert_eq!(
        original.raw_value(),
        &EvidenceValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef])
    );
    assert_eq!(normalized.raw_value(), original.raw_value());
    assert_eq!(
        normalized.normalized_value(),
        Some(&EvidenceValue::Text("DE:AD:BE:EF".to_owned()))
    );
    assert_eq!(
        normalized.derivation_history(),
        &["normalization-1".to_owned()]
    );
}

#[test]
fn observation_timeline_is_ordered_and_extendable() {
    let source = source();
    let timeline = ObservationTimeline::new(10, 20, 30).unwrap();
    let observation = Observation::with_timeline(
        "observation-1",
        "raw",
        None,
        source.id(),
        SourceType::Sensor,
        RetrievalMethod::Direct,
        timeline,
    )
    .unwrap();
    let extended = observation.seen_at(40).unwrap();

    assert_eq!(observation.first_seen(), 10);
    assert_eq!(observation.observed_at(), 20);
    assert_eq!(observation.last_seen(), 30);
    assert_eq!(extended.last_seen(), 40);
    assert!(ObservationTimeline::new(30, 20, 40).is_err());
    assert_eq!(
        observation.seen_at(29),
        Err(ProvenanceError::InvalidTimeline {
            first_seen: 10,
            observed_at: 20,
            last_seen: 29,
        })
    );
}

#[test]
fn stored_observation_timeline_extension_is_atomic() {
    let source = source();
    let original = observation(&source);
    let mut store = EvidenceStore::new();
    store.add_source(source).unwrap();
    store.add_observation(original.clone()).unwrap();

    store
        .record_observation_seen_at(original.id(), 150)
        .unwrap();
    let extended = store.observation(original.id()).unwrap();
    assert_eq!(extended.first_seen(), 100);
    assert_eq!(extended.observed_at(), 100);
    assert_eq!(extended.last_seen(), 150);
    assert_eq!(extended.raw_value(), original.raw_value());
    assert_eq!(extended.normalized_value(), original.normalized_value());
    assert_eq!(extended.source(), original.source());
    assert_eq!(extended.derivation_history(), original.derivation_history());

    let before_failure = extended.clone();
    assert_eq!(
        store.record_observation_seen_at(original.id(), 149),
        Err(ProvenanceError::InvalidTimeline {
            first_seen: 100,
            observed_at: 100,
            last_seen: 149,
        })
    );
    assert_eq!(store.observation(original.id()), Some(&before_failure));
    assert!(matches!(
        store.record_observation_seen_at("missing-observation", 200),
        Err(ProvenanceError::MissingReference {
            record: "observation update",
            field: "observation",
            ..
        })
    ));
    assert_eq!(store.observation(original.id()), Some(&before_failure));
}

#[test]
fn feature_temporal_provenance_does_not_precede_observation() {
    let source = source();
    let observation = observation(&source);
    let too_early = bleradar_core::Feature::new("feature-early", "digest", "raw")
        .unwrap()
        .from_observation(observation.id())
        .created_at(99);
    let valid = bleradar_core::Feature::new("feature-valid", "digest", "raw")
        .unwrap()
        .from_observation(observation.id())
        .created_at(100);
    let mut store = EvidenceStore::new();
    store.add_source(source).unwrap();
    store.add_observation(observation).unwrap();

    assert!(matches!(
        store.add_feature(too_early),
        Err(ProvenanceError::TemporalViolation { .. })
    ));
    store.add_feature(valid).unwrap();
    assert_eq!(store.features_from_observation("observation-1").len(), 1);
    assert_eq!(store.observations_by_source("source-1").len(), 1);
    assert_eq!(store.observations_in_window(100, 100).len(), 1);
    assert_eq!(store.observations_in_window(101, 200).len(), 0);
}

#[test]
fn claim_trace_reaches_the_authoritative_source() {
    let source = source();
    let observation = observation(&source);
    let hypothesis =
        Hypothesis::new("hypothesis-1", "ordinary explanation", HypothesisKind::Null).unwrap();
    let claim = Claim::new(
        "claim-1",
        "the observed value has the ordinary explanation",
        hypothesis.id(),
    )
    .unwrap();
    let evidence = Evidence::new(
        "evidence-1",
        hypothesis.id(),
        observation.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();

    let mut store = EvidenceStore::new();
    store.add_source(source).unwrap();
    store.add_observation(observation).unwrap();
    store.add_hypothesis(hypothesis).unwrap();
    store.add_claim(claim).unwrap();
    store.add_evidence(evidence).unwrap();

    let trace = store.trace_claim("claim-1").unwrap();
    assert_eq!(
        trace.claim.statement(),
        "the observed value has the ordinary explanation"
    );
    assert_eq!(trace.hypothesis.id(), "hypothesis-1");
    assert_eq!(trace.evidence.len(), 1);
    assert_eq!(trace.evidence[0].observation.id(), "observation-1");
    assert_eq!(trace.evidence[0].source.id(), "source-1");
    assert_eq!(store.validate(), Ok(()));
}

#[test]
fn transformation_trace_contains_features_and_verification() {
    let source = source();
    let observation = observation(&source);
    let feature = bleradar_core::Feature::new("feature-1", "digest", "deadbeef")
        .unwrap()
        .from_observation(observation.id())
        .with_confidence(Confidence::new(90));
    let artifact = Artifact::new("artifact-1", ArtifactType::Digital).unwrap();
    let input = Representation::new("representation-raw", artifact.id(), RepresentationType::Raw)
        .unwrap()
        .with_feature(feature.id());
    let output = Representation::new(
        "representation-normalized",
        artifact.id(),
        RepresentationType::Normalized,
    )
    .unwrap()
    .with_feature(feature.id());
    let test = Test::new(
        "test-1",
        "normalization preserves digest",
        TestType::Provenance,
    )
    .unwrap()
    .completed(bleradar_core::TestStatus::Passed, 200);
    let verification = Verification::passed(vec!["test-1".to_owned()]).unwrap();
    let transformation = Transformation::new(
        "transformation-1",
        input.id(),
        output.id(),
        vec![feature.id().to_owned()],
        Vec::<String>::new(),
        verification,
    )
    .unwrap();

    let mut store = EvidenceStore::new();
    store.add_source(source).unwrap();
    store.add_observation(observation).unwrap();
    store.add_artifact(artifact).unwrap();
    store.add_feature(feature).unwrap();
    store.add_representation(input).unwrap();
    store.add_representation(output).unwrap();
    store.add_test(test).unwrap();
    store.add_transformation(transformation).unwrap();

    let trace = store.trace_transformation("transformation-1").unwrap();
    assert_eq!(trace.input_representation.id(), "representation-raw");
    assert_eq!(
        trace.output_representation.id(),
        "representation-normalized"
    );
    assert_eq!(trace.preserved_features[0].id(), "feature-1");
    assert_eq!(trace.verification_tests[0].id(), "test-1");
    assert_eq!(
        store
            .artifact("artifact-1")
            .unwrap()
            .representation_ids()
            .len(),
        2
    );
}

#[test]
fn overlapping_transformation_features_are_rejected() {
    let error = Transformation::new(
        "transformation-1",
        "input",
        "output",
        vec!["feature-1".to_owned()],
        vec!["feature-1".to_owned()],
        Verification::unverified(),
    )
    .unwrap_err();

    assert!(matches!(error, ProvenanceError::FeatureInBothSets { .. }));
}

#[test]
fn source_metadata_is_not_silently_changed() {
    let source = source();
    let observation = Observation::new(
        "observation-1",
        "raw",
        None,
        source.id(),
        SourceType::Document,
        RetrievalMethod::Direct,
        100,
    )
    .unwrap();
    let mut store = EvidenceStore::new();
    store.add_source(source).unwrap();

    assert!(matches!(
        store.add_observation(observation),
        Err(ProvenanceError::SourceMetadataMismatch { .. })
    ));
}

#[test]
fn unverified_transformation_is_stored_and_distinguishable_from_a_verified_one() {
    let source = source();
    let observation = observation(&source);
    let feature = bleradar_core::Feature::new("feature-1", "digest", "deadbeef")
        .unwrap()
        .from_observation(observation.id())
        .created_at(100);
    let artifact = Artifact::new("artifact-1", ArtifactType::Digital).unwrap();
    let input = Representation::new("representation-raw", artifact.id(), RepresentationType::Raw)
        .unwrap()
        .with_feature(feature.id());
    let output = Representation::new(
        "representation-normalized",
        artifact.id(),
        RepresentationType::Normalized,
    )
    .unwrap()
    .with_feature(feature.id());
    let unverified = Transformation::new(
        "transformation-unverified",
        input.id(),
        output.id(),
        vec![feature.id().to_owned()],
        Vec::<String>::new(),
        Verification::unverified(),
    )
    .unwrap();
    let test = Test::new(
        "test-1",
        "normalization preserves digest",
        TestType::Provenance,
    )
    .unwrap()
    .completed(bleradar_core::TestStatus::Passed, 200);
    let verified = Transformation::new(
        "transformation-verified",
        input.id(),
        output.id(),
        vec![feature.id().to_owned()],
        Vec::<String>::new(),
        Verification::passed(vec!["test-1".to_owned()]).unwrap(),
    )
    .unwrap();

    let mut store = EvidenceStore::new();
    store.add_source(source).unwrap();
    store.add_observation(observation).unwrap();
    store.add_artifact(artifact).unwrap();
    store.add_feature(feature).unwrap();
    store.add_representation(input).unwrap();
    store.add_representation(output).unwrap();
    store.add_test(test).unwrap();
    // An unverified transformation is accepted without any verification
    // tests attached — it must not be rejected as if it were an incomplete
    // "verified" transformation.
    store.add_transformation(unverified).unwrap();
    store.add_transformation(verified).unwrap();

    let unverified_trace = store
        .trace_transformation("transformation-unverified")
        .unwrap();
    let verified_trace = store
        .trace_transformation("transformation-verified")
        .unwrap();

    assert_eq!(
        unverified_trace.transformation.verification().status(),
        bleradar_core::VerificationStatus::Unverified
    );
    assert!(
        unverified_trace
            .transformation
            .verification()
            .test_ids()
            .is_empty()
    );
    assert!(unverified_trace.verification_tests.is_empty());
    assert_eq!(
        verified_trace.transformation.verification().status(),
        bleradar_core::VerificationStatus::Passed
    );
    assert_eq!(verified_trace.verification_tests[0].id(), "test-1");
    assert_ne!(
        unverified_trace.transformation.verification().status(),
        verified_trace.transformation.verification().status()
    );
}

#[test]
fn verification_passed_and_failed_reject_empty_test_ids() {
    assert_eq!(
        Verification::passed(Vec::<String>::new()),
        Err(ProvenanceError::EmptyValue {
            field: "verification test ids"
        })
    );
    assert_eq!(
        Verification::failed(Vec::<String>::new()),
        Err(ProvenanceError::EmptyValue {
            field: "verification test ids"
        })
    );
}

#[test]
fn verification_failed_records_status_and_optional_notes() {
    let verification = Verification::failed(vec!["test-2".to_owned()])
        .unwrap()
        .with_notes("normalization altered the checksum");

    assert_eq!(
        verification.status(),
        bleradar_core::VerificationStatus::Failed
    );
    assert_eq!(verification.test_ids(), ["test-2".to_owned()]);
    assert_eq!(
        verification.notes(),
        Some("normalization altered the checksum")
    );
    assert_eq!(Verification::unverified().notes(), None);
}

#[test]
fn constructors_reject_empty_and_whitespace_only_identifiers() {
    assert_eq!(
        Source::new("", SourceType::Sensor, RetrievalMethod::Direct),
        Err(ProvenanceError::EmptyValue { field: "source id" })
    );
    assert_eq!(
        Source::new("   ", SourceType::Sensor, RetrievalMethod::Direct),
        Err(ProvenanceError::EmptyValue { field: "source id" })
    );
    assert!(matches!(
        Observation::new(
            "",
            "raw",
            None,
            "source-1",
            SourceType::Sensor,
            RetrievalMethod::Direct,
            100,
        ),
        Err(ProvenanceError::EmptyValue {
            field: "observation id"
        })
    ));
    assert!(matches!(
        Observation::new(
            "observation-1",
            "raw",
            None,
            "",
            SourceType::Sensor,
            RetrievalMethod::Direct,
            100,
        ),
        Err(ProvenanceError::EmptyValue {
            field: "observation source"
        })
    ));
    assert!(matches!(
        Hypothesis::new("", "ordinary explanation", HypothesisKind::Null),
        Err(ProvenanceError::EmptyValue {
            field: "hypothesis id"
        })
    ));
    assert!(matches!(
        Hypothesis::new("hypothesis-1", "", HypothesisKind::Null),
        Err(ProvenanceError::EmptyValue {
            field: "hypothesis label"
        })
    ));
    assert!(matches!(
        Claim::new("", "statement", "hypothesis-1"),
        Err(ProvenanceError::EmptyValue { field: "claim id" })
    ));
    assert!(matches!(
        Evidence::new(
            "",
            "hypothesis-1",
            "observation-1",
            EvidenceRole::Supporting
        ),
        Err(ProvenanceError::EmptyValue {
            field: "evidence id"
        })
    ));
    assert!(matches!(
        Artifact::new("", ArtifactType::Digital),
        Err(ProvenanceError::EmptyValue {
            field: "artifact id"
        })
    ));
    assert!(matches!(
        Representation::new("", "artifact-1", RepresentationType::Raw),
        Err(ProvenanceError::EmptyValue {
            field: "representation id"
        })
    ));
    assert!(matches!(
        Test::new("", "name", TestType::Provenance),
        Err(ProvenanceError::EmptyValue { field: "test id" })
    ));
    assert!(matches!(
        bleradar_core::Feature::new("", "name", "value"),
        Err(ProvenanceError::EmptyValue {
            field: "feature id"
        })
    ));
    assert!(matches!(
        Transformation::new(
            "",
            "input",
            "output",
            Vec::<String>::new(),
            Vec::<String>::new(),
            Verification::unverified(),
        ),
        Err(ProvenanceError::EmptyValue {
            field: "transformation id"
        })
    ));
}

#[test]
fn duplicate_source_id_is_rejected_on_second_insert() {
    let mut store = EvidenceStore::new();
    store.add_source(source()).unwrap();

    assert!(matches!(
        store.add_source(source()),
        Err(ProvenanceError::DuplicateId {
            collection: "source",
            ..
        })
    ));
}

#[test]
fn claim_without_any_evidence_is_rejected_by_trace_and_validate() {
    let hypothesis =
        Hypothesis::new("hypothesis-1", "ordinary explanation", HypothesisKind::Null).unwrap();
    let claim = Claim::new(
        "claim-1",
        "the observed value has the ordinary explanation",
        hypothesis.id(),
    )
    .unwrap();
    let mut store = EvidenceStore::new();
    store.add_hypothesis(hypothesis).unwrap();
    store.add_claim(claim).unwrap();

    assert!(matches!(
        store.trace_claim("claim-1"),
        Err(ProvenanceError::ClaimWithoutEvidence { .. })
    ));
    assert!(matches!(
        store.validate(),
        Err(ProvenanceError::ClaimWithoutEvidence { .. })
    ));
}

#[test]
fn artifact_referencing_an_unregistered_entity_is_rejected() {
    let artifact = Artifact::new("artifact-1", ArtifactType::Digital)
        .unwrap()
        .for_entity("no-such-entity");
    let mut store = EvidenceStore::new();

    assert!(matches!(
        store.add_artifact(artifact),
        Err(ProvenanceError::MissingReference {
            record: "artifact",
            field: "entity",
            ..
        })
    ));
}

#[test]
fn transaction_keeps_every_change_on_success_and_undoes_every_change_on_error() {
    let source = source();
    let mut store = EvidenceStore::new();
    let kept: Result<(), ProvenanceError> = store.transaction(|store| {
        store.add_source(source.clone())?;
        store.add_entity(bleradar_core::Entity::new(
            "device-1",
            bleradar_core::EntityType::Device,
        )?)?;
        store.add_observation(observation(&source))
    });
    kept.unwrap();
    assert_eq!(store.len(), 3);

    let before = store.len();
    let undone: Result<(), ProvenanceError> = store.transaction(|store| {
        store.add_entity(bleradar_core::Entity::new(
            "device-2",
            bleradar_core::EntityType::Device,
        )?)?;
        store.add_artifact(Artifact::new("artifact-1", ArtifactType::Digital)?)?;
        // Duplicate observation id: the whole transaction fails.
        store.add_observation(observation(&source))
    });
    assert!(matches!(
        undone,
        Err(ProvenanceError::DuplicateId {
            collection: "observation",
            ..
        })
    ));
    assert_eq!(store.len(), before);
    assert!(store.entity("device-2").is_none());
    assert!(store.artifact("artifact-1").is_none());
    assert!(store.entity("device-1").is_some());
    store.validate().unwrap();
}

#[test]
fn nested_transaction_failure_undoes_only_the_inner_changes() {
    let source = source();
    let mut store = EvidenceStore::new();
    let outcome: Result<(), ProvenanceError> = store.transaction(|store| {
        store.add_source(source.clone())?;
        let inner: Result<(), ProvenanceError> = store.transaction(|store| {
            store.add_observation(observation(&source))?;
            Err(ProvenanceError::MissingReference {
                record: "test",
                record_id: "inner".to_owned(),
                field: "field",
                reference: "reference".to_owned(),
            })
        });
        assert!(inner.is_err());
        assert!(store.observation("observation-1").is_none());
        assert!(store.source("source-1").is_some());
        store.add_entity(bleradar_core::Entity::new(
            "device-1",
            bleradar_core::EntityType::Device,
        )?)
    });
    outcome.unwrap();
    assert!(store.source("source-1").is_some());
    assert!(store.entity("device-1").is_some());
    assert!(store.observation("observation-1").is_none());
    assert_eq!(store.len(), 2);
    store.validate().unwrap();

    // An outer failure undoes the surviving outer changes too.
    let outcome: Result<(), ProvenanceError> = store.transaction(|store| {
        store.add_observation(observation(&source))?;
        let inner: Result<(), ProvenanceError> = store.transaction(|store| {
            store.add_artifact(Artifact::new("artifact-1", ArtifactType::Digital)?)
        });
        inner?;
        Err(ProvenanceError::MissingReference {
            record: "test",
            record_id: "outer".to_owned(),
            field: "field",
            reference: "reference".to_owned(),
        })
    });
    assert!(outcome.is_err());
    assert!(store.observation("observation-1").is_none());
    assert!(store.artifact("artifact-1").is_none());
    assert_eq!(store.len(), 2);
}

#[test]
fn transaction_rollback_restores_in_place_updates() {
    let source = source();
    let mut store = EvidenceStore::new();
    store.add_source(source.clone()).unwrap();
    store.add_observation(observation(&source)).unwrap();
    store
        .add_artifact(Artifact::new("artifact-1", ArtifactType::Digital).unwrap())
        .unwrap();

    let outcome: Result<(), ProvenanceError> = store.transaction(|store| {
        store.record_observation_seen_at("observation-1", 500)?;
        store.add_representation(Representation::new(
            "representation-1",
            "artifact-1",
            RepresentationType::Raw,
        )?)?;
        assert_eq!(store.observation("observation-1").unwrap().last_seen(), 500);
        assert_eq!(
            store.artifact("artifact-1").unwrap().representation_ids(),
            &["representation-1".to_owned()]
        );
        Err(ProvenanceError::MissingReference {
            record: "test",
            record_id: "abort".to_owned(),
            field: "field",
            reference: "reference".to_owned(),
        })
    });
    assert!(outcome.is_err());
    assert_eq!(store.observation("observation-1").unwrap().last_seen(), 100);
    assert!(store.representation("representation-1").is_none());
    assert!(
        store
            .artifact("artifact-1")
            .unwrap()
            .representation_ids()
            .is_empty()
    );
    assert_eq!(store.len(), 3);
    store.validate().unwrap();
}

#[test]
fn panic_inside_a_transaction_rolls_back_and_leaves_the_store_usable() {
    let source = source();
    let mut store = EvidenceStore::new();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), ProvenanceError> = store.transaction(|store| {
            store.add_source(source.clone())?;
            panic!("adapter failure inside the transaction");
        });
    }));
    assert!(outcome.is_err());
    assert!(store.is_empty());

    // The journal is closed again: later refusals and successes behave normally.
    store.add_source(source.clone()).unwrap();
    assert!(store.add_source(source.clone()).is_err());
    let outcome: Result<(), ProvenanceError> =
        store.transaction(|store| store.add_observation(observation(&source)));
    outcome.unwrap();
    assert_eq!(store.len(), 2);
    store.validate().unwrap();
}
