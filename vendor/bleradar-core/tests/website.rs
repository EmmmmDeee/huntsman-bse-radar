//! Regression tests for website lineage and ecosystem analysis.

use bleradar_core::{
    EdgeType, EntityType, EvidenceStore, EvidenceValue, Observation, OperatorAssessment,
    RetrievalMethod, Source, SourceType, TemporalInterval, TemporalRelation, WebsiteError,
    WebsiteExplanation, WebsiteFactors, WebsiteFeatureKind, WebsiteLimits,
    WebsiteLineageEcosystemAnalysisEngine, WebsiteObservation, WebsitePhase, WebsiteSnapshot,
};

fn source(id: &str, provider: Option<&str>) -> Source {
    let source = Source::new(id, SourceType::Website, RetrievalMethod::Direct).unwrap();
    if let Some(provider) = provider {
        source.with_metadata("provider", provider)
    } else {
        source
    }
}

fn factors(score: u8) -> WebsiteFactors {
    WebsiteFactors::new(
        score, score, score, score, score, score, score, score, score,
    )
}

fn observation(
    id: &str,
    website_id: &str,
    kind: WebsiteFeatureKind,
    value: &str,
    source: Source,
    observed_at: u64,
) -> WebsiteObservation {
    WebsiteObservation::new(id, website_id, kind, value, source, observed_at)
        .unwrap()
        .with_normalized_value(value.to_ascii_lowercase())
        .with_factors(factors(100))
}

#[test]
fn snapshot_extracts_feature_families_and_preserves_raw_html() {
    let snapshot = WebsiteSnapshot::new(
        "snapshot-a",
        "site-a",
        "<html><head><script src='/app.js'></script></head><body><main>Rare public phrase for lineage analysis.</main></body></html>",
        source("snapshot-source", None),
        100,
    )
    .unwrap()
    .with_timeline(TemporalInterval::new(80, 100, 120).unwrap())
    .with_public_asset("assets/rare-logo.svg")
    .unwrap()
    .with_script_reference("/app.js")
    .unwrap()
    .with_style_reference("/app.css")
    .unwrap()
    .with_public_analytics_identifier("analytics-rare")
    .unwrap()
    .with_public_contact_information("public@example.test")
    .unwrap()
    .with_certificate("sha256:certificate")
    .unwrap()
    .with_outbound_link("https://partner.example")
    .unwrap()
    .with_application_characteristic("framework-x")
    .unwrap()
    .with_archived_state("archive:2026")
    .unwrap();

    let observations = snapshot.extract_observations().unwrap();
    assert!(
        observations
            .iter()
            .any(|observation| observation.kind() == WebsiteFeatureKind::NormalizedText)
    );
    assert!(
        observations
            .iter()
            .any(|observation| observation.kind() == WebsiteFeatureKind::DistinctivePhrase)
    );
    assert!(
        observations
            .iter()
            .any(|observation| observation.kind() == WebsiteFeatureKind::HtmlStructure)
    );
    for kind in WebsiteFeatureKind::ALL {
        if kind == WebsiteFeatureKind::NormalizedText
            || kind == WebsiteFeatureKind::DistinctivePhrase
            || kind == WebsiteFeatureKind::HtmlStructure
        {
            continue;
        }
        assert!(
            observations
                .iter()
                .any(|observation| observation.kind() == kind),
            "missing extracted {kind}"
        );
    }

    let text = observations
        .iter()
        .find(|observation| observation.kind() == WebsiteFeatureKind::NormalizedText)
        .unwrap();
    assert_eq!(
        text.raw_value(),
        &EvidenceValue::Text(
            "<html><head><script src='/app.js'></script></head><body><main>Rare public phrase for lineage analysis.</main></body></html>"
                .to_owned()
        )
    );
    assert_eq!(
        text.normalized_value(),
        Some(&EvidenceValue::Text(
            "rare public phrase for lineage analysis.".to_owned()
        ))
    );
    assert_eq!(text.first_seen(), 80);
    assert_eq!(text.last_seen(), 120);
}

#[test]
fn snapshot_observation_is_transactionally_persisted_as_website_evidence() {
    let snapshot = WebsiteSnapshot::new(
        "snapshot-a",
        "site-a",
        "<html><body>Public site content with enough words to normalize.</body></html>",
        source("snapshot-source", None),
        100,
    )
    .unwrap()
    .with_public_asset("assets/rare.svg")
    .unwrap();
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    let ids = engine.observe_snapshot(&snapshot).unwrap();
    assert_eq!(ids.len(), engine.observation_count());
    assert_eq!(
        engine.evidence().entity("site-a").unwrap().kind(),
        &EntityType::Website
    );
    assert!(engine.evidence().validate().is_ok());
}

#[test]
fn rare_assets_and_independent_sources_survive_falsification() {
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    for (id, site, source_id, value) in [
        ("asset-a", "site-a", "asset-a-source", "rare-logo.svg"),
        ("asset-b", "site-b", "asset-b-source", "rare-logo.svg"),
        (
            "asset-a-two",
            "site-a",
            "asset-a-two-source",
            "rare-font.woff2",
        ),
        (
            "asset-b-two",
            "site-b",
            "asset-b-two-source",
            "rare-font.woff2",
        ),
    ] {
        engine
            .observe(
                observation(
                    id,
                    site,
                    WebsiteFeatureKind::PublicAsset,
                    value,
                    source(source_id, None),
                    100,
                )
                .with_feature(format!("asset:{value}"))
                .unwrap(),
            )
            .unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.phases(),
        &[
            WebsitePhase::Capture,
            WebsitePhase::Normalize,
            WebsitePhase::Extract,
            WebsitePhase::TemporalAlign,
            WebsitePhase::Compare,
            WebsitePhase::Score,
            WebsitePhase::Falsify,
            WebsitePhase::Persist,
            WebsitePhase::Recompute,
        ]
    );
    assert_eq!(report.leading_explanation(), WebsiteExplanation::AssetReuse);
    assert!(report.falsification().survives());
    assert!(report.falsification().without_strongest_support().score() > 0);
    assert_eq!(report.temporal_relation(), TemporalRelation::Overlapping);
    assert_eq!(
        report.operator_assessment(),
        OperatorAssessment::NotEstablished
    );
    assert!(!report.common_operator_proven());
    assert_eq!(report.edge().edge_type(), EdgeType::Inferred);
    assert_eq!(
        report.edge().observation_ids(),
        &[
            "asset-a".to_owned(),
            "asset-a-two".to_owned(),
            "asset-b".to_owned(),
            "asset-b-two".to_owned()
        ]
    );
    let relationship = engine
        .evidence()
        .relationship(report.edge().relationship_id())
        .unwrap();
    assert_eq!(
        relationship.provenance().observations(),
        report.edge().observation_ids()
    );
}

#[test]
fn common_platform_support_is_downweighted_and_not_common_operator_proof() {
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    for (id, site, source_id) in [
        ("script-a", "site-a", "script-a-source"),
        ("script-b", "site-b", "script-b-source"),
        ("script-a-copy", "site-a", "script-a-copy-source"),
        ("script-b-copy", "site-b", "script-b-copy-source"),
    ] {
        engine
            .observe(
                observation(
                    id,
                    site,
                    WebsiteFeatureKind::ScriptReference,
                    "/common/framework.js",
                    source(source_id, Some("shared-cdn")),
                    100,
                )
                .in_dependency_group("shared-cdn")
                .unwrap(),
            )
            .unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    let platform = report.ranking(WebsiteExplanation::CommonPlatform).unwrap();
    assert_eq!(platform.independent_support(), 1);
    assert!(!platform.collapsed_pairs().is_empty());
    assert!(platform.has_high_base_rate_support());
    assert_eq!(report.falsification().without_high_base_rate().score(), 0);
    assert!(!report.falsification().survives());
    assert_eq!(report.edge().edge_type(), EdgeType::Contested);
    assert_eq!(
        report.operator_assessment(),
        OperatorAssessment::NotEstablished
    );
    assert!(!report.common_operator_proven());
}

#[test]
fn operational_relationship_remains_a_possible_operator_alternative() {
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    for (id, site, source_id, value) in [
        ("analytics-a", "site-a", "analytics-a-source", "G-RARE"),
        ("analytics-b", "site-b", "analytics-b-source", "G-RARE"),
        (
            "contact-a",
            "site-a",
            "contact-a-source",
            "public@example.test",
        ),
        (
            "contact-b",
            "site-b",
            "contact-b-source",
            "public@example.test",
        ),
    ] {
        let kind = if id.starts_with("analytics") {
            WebsiteFeatureKind::PublicAnalyticsIdentifier
        } else {
            WebsiteFeatureKind::PublicContactInformation
        };
        engine
            .observe(
                observation(id, site, kind, value, source(source_id, None), 100)
                    .with_feature(format!("{}:{value}", kind.as_str()))
                    .unwrap(),
            )
            .unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.leading_explanation(),
        WebsiteExplanation::OperationalRelationship,
        "{:?}",
        report.rankings()
    );
    assert_eq!(
        report.operator_assessment(),
        OperatorAssessment::PossibleCommonOperator
    );
    assert!(!report.common_operator_proven());
}

#[test]
fn snapshot_conflict_rolls_back_all_extracted_features() {
    let source = source("snapshot-source", None);
    let canonical = Observation::new(
        "snapshot-a:normalized-text",
        "different content",
        Some(EvidenceValue::Text("different content".to_owned())),
        source.id(),
        source.source_type().clone(),
        source.retrieval_method().clone(),
        100,
    )
    .unwrap();
    let mut evidence = EvidenceStore::new();
    evidence.add_source(source.clone()).unwrap();
    evidence.add_observation(canonical).unwrap();

    let snapshot = WebsiteSnapshot::new(
        "snapshot-a",
        "site-a",
        "<html><body>New content with enough words to normalize.</body></html>",
        source,
        100,
    )
    .unwrap()
    .with_public_asset("asset.svg")
    .unwrap();
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(evidence);
    let error = engine.observe_snapshot(&snapshot).unwrap_err();
    assert!(matches!(
        error,
        WebsiteError::ObservationConflict {
            observation_id
        } if observation_id == "snapshot-a:normalized-text"
    ));
    assert_eq!(engine.observation_count(), 0);
    assert!(
        engine
            .evidence()
            .observation("snapshot-a:normalized-text")
            .is_some()
    );
    assert!(
        engine
            .evidence()
            .observation("snapshot-a:public-asset-0")
            .is_none()
    );
}

#[test]
fn snapshot_conflict_on_the_last_observation_still_rolls_back_earlier_successes() {
    // The prior rollback test's conflict lands on the *first* extracted
    // observation, where there is nothing yet to roll back. This test
    // forces the conflict onto the *last* of four extracted observations,
    // so normalized-text, html-structure, and public-asset-0 all succeed on
    // the candidate engine clone before public-asset-1 aborts the batch —
    // proving the whole snapshot is still discarded, not just the failing
    // item, regardless of how many earlier items already succeeded.
    let source = source("snapshot-source", None);
    let canonical = Observation::new(
        "snapshot-b:public-asset-1",
        "different content",
        Some(EvidenceValue::Text("different content".to_owned())),
        source.id(),
        source.source_type().clone(),
        source.retrieval_method().clone(),
        100,
    )
    .unwrap();
    let mut evidence = EvidenceStore::new();
    evidence.add_source(source.clone()).unwrap();
    evidence.add_observation(canonical).unwrap();

    let snapshot = WebsiteSnapshot::new(
        "snapshot-b",
        "site-b",
        "<html><body>Alpha</body></html>",
        source,
        100,
    )
    .unwrap()
    .with_public_asset("asset-0.svg")
    .unwrap()
    .with_public_asset("asset-1.svg")
    .unwrap();
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(evidence);
    let error = engine.observe_snapshot(&snapshot).unwrap_err();
    assert!(matches!(
        error,
        WebsiteError::ObservationConflict {
            observation_id
        } if observation_id == "snapshot-b:public-asset-1"
    ));
    assert_eq!(engine.observation_count(), 0);
    assert!(
        engine
            .evidence()
            .observation("snapshot-b:normalized-text")
            .is_none()
    );
    assert!(
        engine
            .evidence()
            .observation("snapshot-b:html-structure")
            .is_none()
    );
    assert!(
        engine
            .evidence()
            .observation("snapshot-b:public-asset-0")
            .is_none()
    );
    assert!(
        engine
            .evidence()
            .observation("snapshot-b:public-asset-1")
            .is_some()
    );
}

#[test]
fn temporal_gap_limits_and_ranking_are_deterministic() {
    let limits = WebsiteLimits::new(10, 2)
        .unwrap()
        .with_maximum_temporal_gap(5);
    let mut first =
        WebsiteLineageEcosystemAnalysisEngine::with_limits(EvidenceStore::new(), limits);
    let mut second =
        WebsiteLineageEcosystemAnalysisEngine::with_limits(EvidenceStore::new(), limits);
    let observations = [
        observation(
            "a",
            "site-a",
            WebsiteFeatureKind::DistinctivePhrase,
            "same rare phrase",
            source("source-a", None),
            10,
        )
        .with_timeline(TemporalInterval::new(10, 10, 10).unwrap()),
        observation(
            "b",
            "site-b",
            WebsiteFeatureKind::DistinctivePhrase,
            "same rare phrase",
            source("source-b", None),
            13,
        )
        .with_timeline(TemporalInterval::new(13, 13, 13).unwrap()),
    ];
    first.observe(observations[0].clone()).unwrap();
    first.observe(observations[1].clone()).unwrap();
    second.observe(observations[1].clone()).unwrap();
    second.observe(observations[0].clone()).unwrap();

    let first_report = first.correlate("site-a", "site-b").unwrap();
    let second_report = second.correlate("site-a", "site-b").unwrap();
    assert_eq!(first_report, second_report);
    assert_eq!(
        first_report.temporal_relation(),
        TemporalRelation::Contiguous
    );
    assert!(matches!(
        first.correlate("site-a", "site-b"),
        Err(WebsiteError::DuplicateCorrelation { .. })
    ));
}

#[test]
fn unknown_is_never_the_leading_explanation_because_coincidence_always_dominates_it() {
    // Every comparable pair unconditionally produces both `Coincidence` and
    // `Unknown` with identical `group`/`high_base_rate` support fields
    // (`explanations_for`), so the two always corroborate across exactly
    // the same independent groups. Their only difference is per-pair
    // weight: `Coincidence` keeps `base_weight / 3` while `Unknown` keeps
    // the strictly smaller `base_weight / 4` (`explanation_weight`).
    // Because `strongest` is a per-explanation max taken over that same set
    // of pairs, `Coincidence`'s strongest weight, independent support, and
    // therefore score can never fall below `Unknown`'s, and ties favor
    // `Coincidence` (`explanation_order`). `Unknown` can therefore never be
    // the leading explanation here - unlike
    // `TemporalMetamorphicInfrastructureCorrelationEngine`, whose analogous
    // `Unknown` has no such always-co-present dominating sibling and can
    // legitimately lead (see
    // `unknown_leads_when_every_named_explanation_is_narrowly_and_independently_supported`
    // in `tests/infrastructure.rs`). This scenario mirrors that test's
    // three-independent-group construction, the most favorable shape for
    // `Unknown` to accumulate cross-group corroboration, and still
    // confirms `Unknown` cannot lead.
    let low = factors(20);
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    for (id, kind, value) in [
        (
            "phrase",
            WebsiteFeatureKind::DistinctivePhrase,
            "shared distinctive phrase",
        ),
        (
            "analytics",
            WebsiteFeatureKind::PublicAnalyticsIdentifier,
            "shared-analytics-id",
        ),
        (
            "archive",
            WebsiteFeatureKind::ArchivedState,
            "shared-archive-state",
        ),
    ] {
        for site in ["site-a", "site-b"] {
            let observation_id = format!("{id}-{site}");
            engine
                .observe(
                    observation(
                        &observation_id,
                        site,
                        kind,
                        value,
                        source(&format!("{observation_id}-source"), None),
                        100,
                    )
                    .with_factors(low),
                )
                .unwrap();
        }
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_ne!(
        report.leading_explanation(),
        WebsiteExplanation::Unknown,
        "{:?}",
        report.rankings()
    );

    let coincidence = report.ranking(WebsiteExplanation::Coincidence).unwrap();
    let unknown = report.ranking(WebsiteExplanation::Unknown).unwrap();
    assert_eq!(coincidence.independent_support(), 3);
    assert_eq!(unknown.independent_support(), 3);
    assert!(coincidence.score() >= unknown.score());
}

#[test]
fn common_template_leads_for_html_structure_matches() {
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    for (id, site, value) in [
        ("html-a", "site-a", "<html><body>structure</body></html>"),
        ("html-b", "site-b", "<html><body>structure</body></html>"),
    ] {
        engine
            .observe(
                observation(
                    id,
                    site,
                    WebsiteFeatureKind::HtmlStructure,
                    value,
                    source(&format!("{id}-source"), None),
                    100,
                )
                .with_feature("html-structure".to_owned())
                .unwrap(),
            )
            .unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.leading_explanation(),
        WebsiteExplanation::CommonTemplate,
        "{:?}",
        report.rankings()
    );
}

#[test]
fn content_reuse_leads_for_distinctive_phrase_matches() {
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    for (id, site, value) in [
        ("phrase-a", "site-a", "unique distinctive phrase"),
        ("phrase-b", "site-b", "unique distinctive phrase"),
    ] {
        engine
            .observe(
                observation(
                    id,
                    site,
                    WebsiteFeatureKind::DistinctivePhrase,
                    value,
                    source(&format!("{id}-source"), None),
                    100,
                )
                .with_feature("distinctive-phrase".to_owned())
                .unwrap(),
            )
            .unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.leading_explanation(),
        WebsiteExplanation::ContentReuse,
        "{:?}",
        report.rankings()
    );
}

#[test]
fn development_relationship_leads_for_script_reference_matches() {
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    for (id, site, value) in [
        ("script-a", "site-a", "/js/app.js"),
        ("script-b", "site-b", "/js/app.js"),
    ] {
        engine
            .observe(
                observation(
                    id,
                    site,
                    WebsiteFeatureKind::ScriptReference,
                    value,
                    source(&format!("{id}-source"), None),
                    100,
                )
                .with_feature("script-ref".to_owned())
                .unwrap(),
            )
            .unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.leading_explanation(),
        WebsiteExplanation::DevelopmentRelationship,
        "{:?}",
        report.rankings()
    );
}

#[test]
fn coincidence_leads_when_multiple_disjoint_named_explanations_compete_without_corroboration() {
    let low = factors(20);
    let limits = WebsiteLimits::new(100, 10)
        .unwrap()
        .with_maximum_temporal_gap(5);
    let mut engine =
        WebsiteLineageEcosystemAnalysisEngine::with_limits(EvidenceStore::new(), limits);

    // Pair 1: ArchivedState / ArchivedState -> DevelopmentRelationship, ContentReuse
    for (site, observed_at) in [("site-a", 10), ("site-b", 20)] {
        let id = format!("archive-{}", site);
        engine
            .observe(
                observation(
                    &id,
                    site,
                    WebsiteFeatureKind::ArchivedState,
                    "val-1",
                    source(&format!("{}-source", id), None),
                    observed_at,
                )
                .with_factors(low)
                .with_timeline(
                    TemporalInterval::new(observed_at, observed_at, observed_at).unwrap(),
                )
                .with_feature("archive-disjoint".to_owned())
                .unwrap(),
            )
            .unwrap();
    }

    // Pair 2: Certificate / Certificate -> OperationalRelationship, DevelopmentRelationship
    for (site, observed_at) in [("site-a", 10), ("site-b", 20)] {
        let id = format!("cert-{}", site);
        engine
            .observe(
                observation(
                    &id,
                    site,
                    WebsiteFeatureKind::Certificate,
                    "val-2",
                    source(&format!("{}-source", id), None),
                    observed_at,
                )
                .with_factors(low)
                .with_timeline(
                    TemporalInterval::new(observed_at, observed_at, observed_at).unwrap(),
                )
                .with_feature("cert-disjoint".to_owned())
                .unwrap(),
            )
            .unwrap();
    }

    // Pair 3: NormalizedText / NormalizedText -> ContentReuse, CommonTemplate
    for (site, observed_at) in [("site-a", 10), ("site-b", 20)] {
        let id = format!("text-{}", site);
        engine
            .observe(
                observation(
                    &id,
                    site,
                    WebsiteFeatureKind::NormalizedText,
                    "val-3",
                    source(&format!("{}-source", id), None),
                    observed_at,
                )
                .with_factors(low)
                .with_timeline(
                    TemporalInterval::new(observed_at, observed_at, observed_at).unwrap(),
                )
                .with_feature("text-disjoint".to_owned())
                .unwrap(),
            )
            .unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.leading_explanation(),
        WebsiteExplanation::Coincidence,
        "{:?}",
        report.rankings()
    );
}

#[test]
fn correlate_all_skips_pairs_already_correlated_in_either_direction_and_is_idempotent() {
    // Three websites sharing one rare public asset, so every pair is
    // comparable. One pair is correlated by hand in the reverse of key order
    // before the batch runs: `correlate_all` must neither duplicate it nor
    // abort on it, and a second batch must be a no-op instead of a
    // `DuplicateCorrelation` error.
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    for (index, site) in ["site-a", "site-b", "site-c"].into_iter().enumerate() {
        engine
            .observe(observation(
                &format!("asset-{site}"),
                site,
                WebsiteFeatureKind::PublicAsset,
                "assets/rare-logo.svg",
                source(&format!("source-{index}"), None),
                100,
            ))
            .unwrap();
    }
    engine.correlate("site-b", "site-a").unwrap();

    let reports = engine.correlate_all().unwrap();
    assert_eq!(
        reports
            .iter()
            .map(|report| report.edge().id())
            .collect::<Vec<_>>(),
        [
            "website-lineage:site-a:site-c",
            "website-lineage:site-b:site-c"
        ]
    );
    assert_eq!(engine.correlation_count(), 3);
    assert!(
        engine
            .correlation("website-lineage:site-b:site-a")
            .is_some()
    );
    assert!(
        engine
            .correlation("website-lineage:site-a:site-b")
            .is_none()
    );

    assert!(engine.correlate_all().unwrap().is_empty());
    assert_eq!(engine.correlation_count(), 3);
    engine.evidence().validate().unwrap();
}

#[test]
fn correlate_all_leaves_the_engine_unchanged_when_the_correlation_limit_is_hit() {
    // Three mutually comparable websites but room for only two correlations:
    // the third pair's `ResourceLimit` must roll back the whole batch, not
    // leave two arbitrary correlations behind.
    let limits = WebsiteLimits::new(10, 2).unwrap();
    let mut engine =
        WebsiteLineageEcosystemAnalysisEngine::with_limits(EvidenceStore::new(), limits);
    for (index, site) in ["site-a", "site-b", "site-c"].into_iter().enumerate() {
        engine
            .observe(observation(
                &format!("asset-{site}"),
                site,
                WebsiteFeatureKind::PublicAsset,
                "assets/rare-logo.svg",
                source(&format!("source-{index}"), None),
                100,
            ))
            .unwrap();
    }
    let evidence_len = engine.evidence().len();

    let error = engine.correlate_all().unwrap_err();
    assert_eq!(
        error,
        WebsiteError::ResourceLimit {
            resource: "correlations",
            limit: 2,
        }
    );
    assert_eq!(engine.correlation_count(), 0);
    assert_eq!(engine.evidence().len(), evidence_len);
    assert!(
        engine
            .evidence()
            .relationship("website-lineage:site-a:site-b:relationship")
            .is_none()
    );
    engine.evidence().validate().unwrap();
}

#[test]
fn ranking_arithmetic_survives_hundreds_of_independent_supports() {
    // 26 observations per website, each from its own source, so all 676
    // matching pairs are independent supports. The ranking previously summed
    // temporal compatibility in a `u16`, which overflowed at 656 overlapping
    // supports: a panic in debug builds and a silently wrong mean (3 instead
    // of 100) in release builds.
    let mut engine = WebsiteLineageEcosystemAnalysisEngine::new(EvidenceStore::new());
    for site in ["site-a", "site-b"] {
        for index in 0..26 {
            engine
                .observe(observation(
                    &format!("{site}-{index}"),
                    site,
                    WebsiteFeatureKind::Certificate,
                    "sha256:shared",
                    source(&format!("{site}-source-{index}"), None),
                    100,
                ))
                .unwrap();
        }
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    let leading = &report.rankings()[0];
    assert_eq!(leading.independent_support(), 676);
    assert_eq!(leading.temporal_compatibility().value(), 100);
    assert_eq!(report.confidence().value(), 100);
    assert_eq!(report.edge().observation_ids().len(), 52);
    engine.evidence().validate().unwrap();
}
