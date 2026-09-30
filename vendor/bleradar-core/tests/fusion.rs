//! Regression tests for calibrated evidence fusion and falsification.

use bleradar_core::{
    CalibratedEvidenceFusion, DependencyKind, Evidence, EvidenceAssessment, EvidenceQuality,
    EvidenceRole, EvidenceStore, ExpectedEvidence, FusionError, Hypothesis, HypothesisKind,
    Observation, RetrievalMethod, Source, SourceType,
};

fn source(id: &str) -> Source {
    Source::new(id, SourceType::Document, RetrievalMethod::Direct).unwrap()
}

fn observation(id: &str, source: &Source, timestamp: u64) -> Observation {
    Observation::from_source(id, "raw", None, source, timestamp).unwrap()
}

fn uniform_assessment(id: &str, score: u8) -> EvidenceAssessment {
    EvidenceAssessment::new(id, EvidenceQuality::uniform(score)).unwrap()
}

#[test]
fn quality_keeps_all_calibration_dimensions_visible() {
    let quality = EvidenceQuality::new(100, 90, 80, 70, 60, 50, 40, 30, 20);

    assert_eq!(quality.reliability().value(), 100);
    assert_eq!(quality.specificity().value(), 90);
    assert_eq!(quality.rarity().value(), 80);
    assert_eq!(quality.discriminative_power().value(), 70);
    assert_eq!(quality.source_independence().value(), 60);
    assert_eq!(quality.temporal_compatibility().value(), 50);
    assert_eq!(quality.transformation_resistance().value(), 40);
    assert_eq!(quality.provenance_quality().value(), 30);
    assert_eq!(quality.reproducibility().value(), 20);
    assert_eq!(quality.calibrated_weight(), 60);
}

#[test]
fn dependent_reporting_is_counted_once() {
    let first_source = source("source-a");
    let second_source = source("source-b");
    let hypothesis =
        Hypothesis::new("hypothesis-1", "shared origin", HypothesisKind::Leading).unwrap();
    let first_observation = observation("observation-a", &first_source, 10);
    let second_observation = observation("observation-b", &second_source, 20);
    let first_evidence = Evidence::new(
        "evidence-a",
        hypothesis.id(),
        first_observation.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();
    let second_evidence = Evidence::new(
        "evidence-b",
        hypothesis.id(),
        second_observation.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();

    let mut store = EvidenceStore::new();
    store.add_source(first_source).unwrap();
    store.add_source(second_source).unwrap();
    store.add_hypothesis(hypothesis).unwrap();
    store.add_observation(first_observation).unwrap();
    store.add_observation(second_observation).unwrap();
    store.add_evidence(first_evidence).unwrap();
    store.add_evidence(second_evidence).unwrap();

    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_assessment(
            uniform_assessment("evidence-a", 80)
                .in_group("original-report")
                .with_dependency(DependencyKind::CopiedReporting),
        )
        .unwrap();
    fusion
        .add_assessment(
            uniform_assessment("evidence-b", 70)
                .in_group("original-report")
                .with_dependency(DependencyKind::CopiedReporting),
        )
        .unwrap();

    let result = fusion.fuse(&store).unwrap();
    let score = result.score("hypothesis-1").unwrap();
    assert_eq!(score.support_score(), 80);
    assert_eq!(score.supporting_evidence(), &["evidence-a".to_owned()]);
    assert_eq!(score.collapsed_evidence(), &["evidence-b".to_owned()]);
}

#[test]
fn same_source_is_conservative_without_explicit_group() {
    let source = source("source-a");
    let hypothesis =
        Hypothesis::new("hypothesis-1", "same source", HypothesisKind::Leading).unwrap();
    let first_observation = observation("observation-a", &source, 10);
    let second_observation = observation("observation-b", &source, 20);
    let first_evidence = Evidence::new(
        "evidence-a",
        hypothesis.id(),
        first_observation.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();
    let second_evidence = Evidence::new(
        "evidence-b",
        hypothesis.id(),
        second_observation.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();
    let mut store = EvidenceStore::new();
    store.add_source(source).unwrap();
    store.add_hypothesis(hypothesis).unwrap();
    store.add_observation(first_observation).unwrap();
    store.add_observation(second_observation).unwrap();
    store.add_evidence(first_evidence).unwrap();
    store.add_evidence(second_evidence).unwrap();

    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_assessment(uniform_assessment("evidence-a", 60))
        .unwrap();
    fusion
        .add_assessment(uniform_assessment("evidence-b", 90))
        .unwrap();

    let score = fusion
        .fuse(&store)
        .unwrap()
        .score("hypothesis-1")
        .unwrap()
        .clone();
    assert_eq!(score.support_score(), 90);
    assert_eq!(score.supporting_evidence(), &["evidence-b".to_owned()]);
    assert_eq!(score.collapsed_evidence(), &["evidence-a".to_owned()]);
}

#[test]
fn falsification_removes_base_rate_support_and_reports_gaps() {
    let leading = Hypothesis::new(
        "hypothesis-leading",
        "specific explanation",
        HypothesisKind::Leading,
    )
    .unwrap();
    let alternative = Hypothesis::new(
        "hypothesis-null",
        "ordinary explanation",
        HypothesisKind::Null,
    )
    .unwrap();
    let leading_source = source("source-leading");
    let base_rate_source = source("source-base-rate");
    let contradiction_source = source("source-contradiction");
    let alternative_source = source("source-alternative");
    let leading_observation = observation("observation-leading", &leading_source, 10);
    let base_rate_observation = observation("observation-base-rate", &base_rate_source, 20);
    let contradiction_observation =
        observation("observation-contradiction", &contradiction_source, 30);
    let alternative_observation = observation("observation-alternative", &alternative_source, 40);
    let leading_evidence = Evidence::new(
        "evidence-leading",
        leading.id(),
        leading_observation.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();
    let base_rate_evidence = Evidence::new(
        "evidence-base-rate",
        leading.id(),
        base_rate_observation.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();
    let contradiction_evidence = Evidence::new(
        "evidence-contradiction",
        leading.id(),
        contradiction_observation.id(),
        EvidenceRole::Contradicting,
    )
    .unwrap();
    let alternative_evidence = Evidence::new(
        "evidence-alternative",
        alternative.id(),
        alternative_observation.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();

    let mut store = EvidenceStore::new();
    for item in [
        leading_source,
        base_rate_source,
        contradiction_source,
        alternative_source,
    ] {
        store.add_source(item).unwrap();
    }
    store.add_hypothesis(leading).unwrap();
    store.add_hypothesis(alternative).unwrap();
    for item in [
        leading_observation,
        base_rate_observation,
        contradiction_observation,
        alternative_observation,
    ] {
        store.add_observation(item).unwrap();
    }
    for item in [
        leading_evidence,
        base_rate_evidence,
        contradiction_evidence,
        alternative_evidence,
    ] {
        store.add_evidence(item).unwrap();
    }

    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_assessment(uniform_assessment("evidence-leading", 90))
        .unwrap();
    fusion
        .add_assessment(
            uniform_assessment("evidence-base-rate", 80)
                .high_base_rate()
                .with_dependency(DependencyKind::CommonDataset),
        )
        .unwrap();
    fusion
        .add_assessment(uniform_assessment("evidence-contradiction", 20))
        .unwrap();
    fusion
        .add_assessment(uniform_assessment("evidence-alternative", 75))
        .unwrap();
    fusion
        .add_expected_evidence(
            ExpectedEvidence::new(
                "expected-leading-confirmation",
                "hypothesis-leading",
                "an independent confirmation",
            )
            .unwrap(),
        )
        .unwrap();

    let result = fusion.fuse(&store).unwrap();
    assert_eq!(result.leading_hypothesis(), "hypothesis-leading");
    let report = result.falsify(&fusion, &store).unwrap();
    assert_eq!(report.strongest_alternative(), Some("hypothesis-null"));
    assert_eq!(report.baseline().net_score(), 150);
    assert_eq!(report.without_high_base_rate().net_score(), 70);
    assert_eq!(report.without_strongest_support().net_score(), 60);
    assert_eq!(
        report.contradictory_evidence(),
        &["evidence-contradiction".to_owned()]
    );
    assert_eq!(report.removed_support(), Some("evidence-leading"));
    assert_eq!(report.missing_expected_evidence().len(), 1);
    assert!(!report.survives());
}

#[test]
fn leading_hypothesis_survives_falsification_when_support_is_robust() {
    // The prior falsification test only ever demonstrates rejection
    // (`!report.survives()`). Falsification resistance is a two-sided
    // claim: a well-supported hypothesis must also be able to withstand
    // every adversarial scenario and still report `survives() == true`.
    // This is that positive case: three independent, non-high-base-rate
    // supporting groups for the leading hypothesis, none of which alone
    // (nor high-base-rate removal, nor uncertainty perturbation) can drop
    // it below a weakly supported alternative.
    let leading = Hypothesis::new(
        "hypothesis-robust",
        "well-supported explanation",
        HypothesisKind::Leading,
    )
    .unwrap();
    let alternative = Hypothesis::new(
        "hypothesis-weak",
        "ordinary explanation",
        HypothesisKind::Null,
    )
    .unwrap();
    let source_a = source("source-robust-a");
    let source_b = source("source-robust-b");
    let source_c = source("source-robust-c");
    let source_alt = source("source-weak");
    let observation_a = observation("observation-robust-a", &source_a, 10);
    let observation_b = observation("observation-robust-b", &source_b, 20);
    let observation_c = observation("observation-robust-c", &source_c, 30);
    let observation_alt = observation("observation-weak", &source_alt, 40);
    let evidence_a = Evidence::new(
        "evidence-robust-a",
        leading.id(),
        observation_a.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();
    let evidence_b = Evidence::new(
        "evidence-robust-b",
        leading.id(),
        observation_b.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();
    let evidence_c = Evidence::new(
        "evidence-robust-c",
        leading.id(),
        observation_c.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();
    let evidence_alt = Evidence::new(
        "evidence-weak",
        alternative.id(),
        observation_alt.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();

    let mut store = EvidenceStore::new();
    for item in [source_a, source_b, source_c, source_alt] {
        store.add_source(item).unwrap();
    }
    store.add_hypothesis(leading).unwrap();
    store.add_hypothesis(alternative).unwrap();
    for item in [observation_a, observation_b, observation_c, observation_alt] {
        store.add_observation(item).unwrap();
    }
    for item in [evidence_a, evidence_b, evidence_c, evidence_alt] {
        store.add_evidence(item).unwrap();
    }

    let mut fusion = CalibratedEvidenceFusion::new();
    // None of these is high-base-rate and each comes from a distinct
    // source, so every group survives high-base-rate removal, and losing
    // any single one still leaves the other two ahead of the alternative.
    fusion
        .add_assessment(uniform_assessment("evidence-robust-a", 70))
        .unwrap();
    fusion
        .add_assessment(uniform_assessment("evidence-robust-b", 65))
        .unwrap();
    fusion
        .add_assessment(uniform_assessment("evidence-robust-c", 60))
        .unwrap();
    fusion
        .add_assessment(uniform_assessment("evidence-weak", 50))
        .unwrap();

    let result = fusion.fuse(&store).unwrap();
    assert_eq!(result.leading_hypothesis(), "hypothesis-robust");
    assert_eq!(result.score("hypothesis-robust").unwrap().net_score(), 195);

    let report = result.falsify(&fusion, &store).unwrap();
    // Dropping the single strongest group (70) still leaves 125 > 50.
    assert_eq!(report.without_strongest_support().net_score(), 125);
    // No evidence is high-base-rate, so removing it changes nothing.
    assert_eq!(report.without_high_base_rate().net_score(), 195);
    assert!(report.missing_expected_evidence().is_empty());
    assert!(report.contradictory_evidence().is_empty());
    assert!(
        report.survives(),
        "robustly and independently supported hypothesis should survive falsification"
    );
}

#[test]
fn fusion_rejects_unregistered_evidence() {
    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_assessment(uniform_assessment("missing", 50))
        .unwrap();

    assert_eq!(
        fusion.fuse(&EvidenceStore::new()),
        Err(FusionError::MissingEvidence {
            evidence_id: "missing".to_owned()
        })
    );
}

#[test]
fn fuse_hypotheses_rejects_an_unregistered_hypothesis_id() {
    // `fuse` derives its hypothesis set from registered evidence, so it can
    // never reference an unregistered hypothesis; `fuse_hypotheses` accepts
    // an explicit hypothesis list instead and must fail explicitly, not
    // panic or silently skip, when one of those ids has no matching
    // `Hypothesis` record in the store.
    let fusion = CalibratedEvidenceFusion::new();
    let store = EvidenceStore::new();

    assert_eq!(
        fusion.fuse_hypotheses(&store, &["unregistered-hypothesis".to_owned()]),
        Err(FusionError::MissingHypothesis {
            hypothesis_id: "unregistered-hypothesis".to_owned()
        })
    );
}

#[test]
fn fuse_hypotheses_orders_equal_net_score_hypotheses_by_id_ascending() {
    // Two hypotheses backed by equally weighted, single-source support tie
    // on `net_score`. The documented tie-break (ascending hypothesis id)
    // must decide the order deterministically instead of leaving it to
    // incidental sort stability.
    let hypothesis_zeta = Hypothesis::new(
        "hypothesis-zeta",
        "second alphabetically",
        HypothesisKind::Leading,
    )
    .unwrap();
    let hypothesis_alpha = Hypothesis::new(
        "hypothesis-alpha",
        "first alphabetically",
        HypothesisKind::Leading,
    )
    .unwrap();
    let source_zeta = source("source-tie-zeta");
    let source_alpha = source("source-tie-alpha");
    let observation_zeta = observation("observation-tie-zeta", &source_zeta, 10);
    let observation_alpha = observation("observation-tie-alpha", &source_alpha, 10);
    let evidence_zeta = Evidence::new(
        "evidence-tie-zeta",
        hypothesis_zeta.id(),
        observation_zeta.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();
    let evidence_alpha = Evidence::new(
        "evidence-tie-alpha",
        hypothesis_alpha.id(),
        observation_alpha.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();

    let mut store = EvidenceStore::new();
    store.add_source(source_zeta).unwrap();
    store.add_source(source_alpha).unwrap();
    store.add_hypothesis(hypothesis_zeta).unwrap();
    store.add_hypothesis(hypothesis_alpha).unwrap();
    store.add_observation(observation_zeta).unwrap();
    store.add_observation(observation_alpha).unwrap();
    store.add_evidence(evidence_zeta).unwrap();
    store.add_evidence(evidence_alpha).unwrap();

    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_assessment(uniform_assessment("evidence-tie-zeta", 50))
        .unwrap();
    fusion
        .add_assessment(uniform_assessment("evidence-tie-alpha", 50))
        .unwrap();

    // Hypotheses are requested in descending-id order so a passing result
    // cannot be an accident of input order.
    let result = fusion
        .fuse_hypotheses(
            &store,
            &["hypothesis-zeta".to_owned(), "hypothesis-alpha".to_owned()],
        )
        .unwrap();
    assert_eq!(
        result.scores()[0].net_score(),
        result.scores()[1].net_score()
    );
    assert_eq!(result.scores()[0].hypothesis(), "hypothesis-alpha");
    assert_eq!(result.scores()[1].hypothesis(), "hypothesis-zeta");
    assert_eq!(result.leading_hypothesis(), "hypothesis-alpha");
}

#[test]
fn perturbation_pass_scales_down_contribution_by_its_recorded_uncertainty() {
    // `with_uncertainty` documents that a non-zero value reduces the
    // assessment's weight specifically during falsification's uncertainty
    // perturbation pass. `ScoreOptions` is a private implementation detail,
    // so the only public surface that exercises it is
    // `FusionResult::falsify`'s `perturbed_uncertainty()` field.
    let src = source("source-uncertain");
    let hypothesis = Hypothesis::new(
        "hypothesis-uncertain",
        "single uncertain explanation",
        HypothesisKind::Leading,
    )
    .unwrap();
    let obs = observation("observation-uncertain", &src, 10);
    let evidence = Evidence::new(
        "evidence-uncertain",
        hypothesis.id(),
        obs.id(),
        EvidenceRole::Supporting,
    )
    .unwrap();

    let mut store = EvidenceStore::new();
    store.add_source(src).unwrap();
    store.add_hypothesis(hypothesis).unwrap();
    store.add_observation(obs).unwrap();
    store.add_evidence(evidence).unwrap();

    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_assessment(
            EvidenceAssessment::new("evidence-uncertain", EvidenceQuality::uniform(80))
                .unwrap()
                .with_uncertainty(50),
        )
        .unwrap();

    let result = fusion.fuse(&store).unwrap();
    let report = result.falsify(&fusion, &store).unwrap();

    assert_eq!(report.baseline().support_score(), 80);
    // 80 scaled by (100 - 50) / 100 == 40, not merely "some" reduction.
    assert_eq!(report.perturbed_uncertainty().support_score(), 40);
    assert!(report.perturbed_uncertainty().support_score() < report.baseline().support_score());
}

#[test]
fn contextual_evidence_never_contributes_to_support_or_contradiction() {
    let src = source("source-contextual");
    let hypothesis = Hypothesis::new(
        "hypothesis-contextual",
        "background information only",
        HypothesisKind::Leading,
    )
    .unwrap();
    let obs = observation("observation-contextual", &src, 10);
    let evidence = Evidence::new(
        "evidence-contextual",
        hypothesis.id(),
        obs.id(),
        EvidenceRole::Contextual,
    )
    .unwrap();

    let mut store = EvidenceStore::new();
    store.add_source(src).unwrap();
    store.add_hypothesis(hypothesis).unwrap();
    store.add_observation(obs).unwrap();
    store.add_evidence(evidence).unwrap();

    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_assessment(uniform_assessment("evidence-contextual", 90))
        .unwrap();

    let score = fusion
        .fuse(&store)
        .unwrap()
        .score("hypothesis-contextual")
        .unwrap()
        .clone();
    assert_eq!(score.support_score(), 0);
    assert_eq!(score.contradiction_score(), 0);
    assert!(score.supporting_evidence().is_empty());
    assert!(score.contradicting_evidence().is_empty());
    assert!(score.collapsed_evidence().is_empty());
}

#[test]
fn add_assessment_rejects_a_duplicate_evidence_id() {
    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_assessment(uniform_assessment("dup-evidence", 50))
        .unwrap();

    assert_eq!(
        fusion.add_assessment(uniform_assessment("dup-evidence", 10)),
        Err(FusionError::DuplicateAssessment {
            evidence_id: "dup-evidence".to_owned()
        })
    );
}

#[test]
fn add_expected_evidence_rejects_a_duplicate_expected_id() {
    let mut fusion = CalibratedEvidenceFusion::new();
    fusion
        .add_expected_evidence(
            ExpectedEvidence::new("expected-1", "hypothesis-1", "an independent confirmation")
                .unwrap(),
        )
        .unwrap();

    assert_eq!(
        fusion.add_expected_evidence(
            ExpectedEvidence::new("expected-1", "hypothesis-1", "a different description")
                .unwrap()
                .observed()
        ),
        Err(FusionError::DuplicateExpectedEvidence {
            expected_id: "expected-1".to_owned()
        })
    );
}

#[test]
fn fusion_error_variants_implement_display_and_error() {
    assert_eq!(
        FusionError::MissingHypothesis {
            hypothesis_id: "h1".to_owned()
        }
        .to_string(),
        "missing hypothesis `h1`"
    );
    assert_eq!(
        FusionError::NoHypotheses.to_string(),
        "no hypotheses were available for fusion"
    );

    // Confirm the type genuinely satisfies `std::error::Error`, not merely
    // `Display`, so callers can use it behind a `Box<dyn Error>`.
    let boxed: Box<dyn std::error::Error> = Box::new(FusionError::EmptyValue {
        field: "evidence id",
    });
    assert_eq!(boxed.to_string(), "evidence id must not be empty");
}
