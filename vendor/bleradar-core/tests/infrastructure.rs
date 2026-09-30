//! Regression tests for temporal metamorphic infrastructure correlation.

use bleradar_core::{
    ControlAssessment, CorrelationFactors, EdgeType, EvidenceStore, EvidenceValue,
    InfrastructureError, InfrastructureExplanation, InfrastructureKind, InfrastructureLimits,
    InfrastructureObservation, InfrastructurePhase, RetrievalMethod, Source, SourceType,
    TemporalInterval, TemporalMetamorphicInfrastructureCorrelationEngine, TemporalRelation,
};

fn source(id: &str, provider: Option<&str>) -> Source {
    let source = Source::new(id, SourceType::Website, RetrievalMethod::Direct).unwrap();
    if let Some(provider) = provider {
        source.with_metadata("provider", provider)
    } else {
        source
    }
}

fn factors(score: u8) -> CorrelationFactors {
    CorrelationFactors::new(
        score, score, score, score, score, score, score, score, score,
    )
}

fn observation(
    id: &str,
    node_id: &str,
    kind: InfrastructureKind,
    value: &str,
    source: Source,
    observed_at: u64,
) -> InfrastructureObservation {
    InfrastructureObservation::new(id, node_id, kind, value, source, observed_at)
        .unwrap()
        .with_factors(factors(90))
}

#[test]
fn all_infrastructure_kinds_and_temporal_intervals_are_explicit() {
    assert_eq!(InfrastructureKind::ALL.len(), 11);
    assert_eq!(
        InfrastructureKind::ALL
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        vec![
            "domain",
            "dns",
            "ip_address",
            "asn",
            "certificate",
            "hosting_provider",
            "http_characteristic",
            "public_asset",
            "public_identifier",
            "application_structure",
            "archived_state",
        ]
    );

    let left = TemporalInterval::new(10, 20, 30).unwrap();
    let right = TemporalInterval::new(25, 30, 40).unwrap();
    assert!(left.overlaps(right));
    assert_eq!(left.intersection(right).unwrap().first_seen(), 25);
    assert_eq!(left.gap(right), 0);
    assert!(left.is_contiguous_with(TemporalInterval::at(100), 70));
    assert_eq!(
        TemporalInterval::new(30, 20, 40),
        Err(InfrastructureError::Provenance {
            error: bleradar_core::ProvenanceError::InvalidTimeline {
                first_seen: 30,
                observed_at: 20,
                last_seen: 40,
            }
        })
    );
}

#[test]
fn observations_preserve_raw_normalized_values_and_canonical_provenance() {
    let source = source("source-a", None)
        .with_locator("https://example.test/dns")
        .captured_at(10);
    let observation = observation(
        "dns-a",
        "site-a",
        InfrastructureKind::Dns,
        " 203.0.113.7 ",
        source.clone(),
        20,
    )
    .with_normalized_value("203.0.113.7")
    .with_interval(TemporalInterval::new(10, 20, 30).unwrap());

    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    engine.observe(observation.clone()).unwrap();
    let canonical = engine.evidence().observation("dns-a").unwrap();
    assert_eq!(
        canonical.raw_value(),
        &EvidenceValue::Text(" 203.0.113.7 ".to_owned())
    );
    assert_eq!(
        canonical.normalized_value(),
        Some(&EvidenceValue::Text("203.0.113.7".to_owned()))
    );
    assert_eq!(canonical.source(), "source-a");
    assert_eq!(canonical.first_seen(), 10);
    assert_eq!(canonical.last_seen(), 30);
    assert_eq!(
        engine.evidence().entity("site-a").unwrap().kind(),
        &bleradar_core::EntityType::Infrastructure
    );
}

#[test]
fn correlation_is_temporal_provenance_linked_and_deterministic() {
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    engine
        .observe(
            observation(
                "cert-a",
                "site-a",
                InfrastructureKind::Certificate,
                "sha256:rare",
                source("cert-source-a", None),
                20,
            )
            .with_normalized_value("sha256:rare")
            .with_interval(TemporalInterval::new(10, 20, 30).unwrap()),
        )
        .unwrap();
    engine
        .observe(
            observation(
                "cert-b",
                "site-b",
                InfrastructureKind::Certificate,
                "sha256:rare",
                source("cert-source-b", None),
                25,
            )
            .with_normalized_value("sha256:rare")
            .with_interval(TemporalInterval::new(15, 25, 35).unwrap()),
        )
        .unwrap();
    engine
        .observe(
            observation(
                "identifier-a",
                "site-a",
                InfrastructureKind::PublicIdentifier,
                "operator-id",
                source("identifier-source-a", None),
                22,
            )
            .with_normalized_value("operator-id"),
        )
        .unwrap();
    engine
        .observe(
            observation(
                "identifier-b",
                "site-b",
                InfrastructureKind::PublicIdentifier,
                "operator-id",
                source("identifier-source-b", None),
                27,
            )
            .with_normalized_value("operator-id"),
        )
        .unwrap();

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.phases(),
        &[
            InfrastructurePhase::Capture,
            InfrastructurePhase::Normalize,
            InfrastructurePhase::TemporalAlign,
            InfrastructurePhase::Compare,
            InfrastructurePhase::Score,
            InfrastructurePhase::Falsify,
            InfrastructurePhase::Persist,
            InfrastructurePhase::Recompute,
        ]
    );
    assert_eq!(
        report.leading_explanation(),
        InfrastructureExplanation::DirectTechnicalRelationship
    );
    assert_eq!(report.temporal_relation(), TemporalRelation::Overlapping);
    assert_eq!(
        report.control_assessment(),
        ControlAssessment::DirectTechnicalRelationship
    );
    assert!(!report.common_control_proven());
    assert!(report.falsification().survives());
    assert_eq!(report.edge().edge_type(), EdgeType::Inferred);

    let relationship = engine
        .evidence()
        .relationship(report.edge().relationship_id())
        .unwrap();
    assert_eq!(relationship.subject(), "site-a");
    assert_eq!(relationship.object(), "site-b");
    assert_eq!(
        relationship.provenance().observations(),
        &[
            "cert-a".to_owned(),
            "cert-b".to_owned(),
            "identifier-a".to_owned(),
            "identifier-b".to_owned()
        ]
    );
    assert_eq!(
        engine
            .evidence()
            .source("temporal-infrastructure-correlation")
            .unwrap()
            .source_type(),
        &SourceType::Derived
    );
}

#[test]
fn common_host_is_downweighted_and_dependent_sources_collapse() {
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    for (id, node, source_id) in [
        ("host-a-1", "site-a", "provider-a"),
        ("host-a-2", "site-a", "provider-a-copy"),
        ("host-b-1", "site-b", "provider-b"),
        ("host-b-2", "site-b", "provider-b-copy"),
    ] {
        let source = source(source_id, Some("same-provider"));
        let observation = observation(
            id,
            node,
            InfrastructureKind::HostingProvider,
            "shared-host",
            source,
            100,
        )
        .with_factors(factors(100))
        .in_dependency_group("hosting-provider")
        .unwrap();
        engine.observe(observation).unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    let host = report
        .ranking(InfrastructureExplanation::CommonHost)
        .unwrap();
    assert_eq!(host.independent_support(), 1);
    assert!(!host.collapsed_pairs().is_empty());
    assert!(host.has_high_base_rate_support());
    assert!(host.score() < 100);
    assert_eq!(report.falsification().without_high_base_rate().score(), 0);
    assert!(!report.falsification().survives());
    assert_eq!(report.edge().edge_type(), EdgeType::Contested);
    assert_eq!(
        report.control_assessment(),
        ControlAssessment::SharedInfrastructure
    );
}

#[test]
fn rare_features_and_independent_sources_raise_possible_administration_alternative() {
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    for (id, node, source_id, value) in [
        ("asset-a", "site-a", "asset-a-source", "asset-hash"),
        ("asset-b", "site-b", "asset-b-source", "asset-hash"),
        (
            "identifier-a",
            "site-a",
            "identifier-a-source",
            "operator-id",
        ),
        (
            "identifier-b",
            "site-b",
            "identifier-b-source",
            "operator-id",
        ),
    ] {
        let observation = observation(
            id,
            node,
            if id.starts_with("asset") {
                InfrastructureKind::PublicAsset
            } else {
                InfrastructureKind::PublicIdentifier
            },
            value,
            source(source_id, None),
            200,
        )
        .with_factors(factors(100));
        engine.observe(observation).unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    let administration = report
        .ranking(InfrastructureExplanation::PossibleCommonAdministration)
        .unwrap();
    assert!(administration.independent_support() >= 2);
    assert_ne!(
        report.control_assessment(),
        ControlAssessment::PossibleCommonAdministration
    );
    assert!(!report.common_control_proven());
}

#[test]
fn common_cms_leads_when_it_is_the_lowest_order_explanation_for_the_pair() {
    // A same-kind `HttpCharacteristic` pair only ever proposes
    // `CommonCms`/`CommonTemplate`/`SharedThirdPartyService` (plus the
    // universal `Unknown` floor); `CommonCms` has the lowest
    // `explanation_order` of that set, so it wins the resulting tie.
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    engine
        .observe(observation(
            "http-a",
            "site-a",
            InfrastructureKind::HttpCharacteristic,
            "x-powered-by:acme-cms",
            source("http-source-a", None),
            10,
        ))
        .unwrap();
    engine
        .observe(observation(
            "http-b",
            "site-b",
            InfrastructureKind::HttpCharacteristic,
            "x-powered-by:acme-cms",
            source("http-source-b", None),
            10,
        ))
        .unwrap();

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.leading_explanation(),
        InfrastructureExplanation::CommonCms
    );
    let cms = report
        .ranking(InfrastructureExplanation::CommonCms)
        .unwrap();
    let template = report
        .ranking(InfrastructureExplanation::CommonTemplate)
        .unwrap();
    let shared = report
        .ranking(InfrastructureExplanation::SharedThirdPartyService)
        .unwrap();
    // All three are derived from the same single pair with no per-explanation
    // weight distinction, so they tie on score; only the tie-break decides.
    assert_eq!(cms.score(), template.score());
    assert_eq!(cms.score(), shared.score());
}

#[test]
fn common_cdn_and_common_registrar_are_ranked_but_structurally_never_lead() {
    // `CommonCdn` is always co-inserted alongside `CommonHost` for the same
    // pairs, with an identical weight/group set, so their scores always
    // tie; `CommonHost` has the lower `explanation_order` and therefore
    // always wins. The same relationship holds between `CommonRegistrar`
    // and `DirectTechnicalRelationship`. Both variants are legitimately
    // ranked, inspectable alternatives, but can never become the leading
    // explanation while their dominating sibling is also a candidate — this
    // is a structural property of the classifier's tie-break, not a gap.
    let mut host_engine =
        TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    host_engine
        .observe(observation(
            "ip-a",
            "site-a",
            InfrastructureKind::IpAddress,
            "203.0.113.9",
            source("ip-source-a", None),
            10,
        ))
        .unwrap();
    host_engine
        .observe(observation(
            "ip-b",
            "site-b",
            InfrastructureKind::IpAddress,
            "203.0.113.9",
            source("ip-source-b", None),
            10,
        ))
        .unwrap();
    let host_report = host_engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        host_report.leading_explanation(),
        InfrastructureExplanation::CommonHost
    );
    let host = host_report
        .ranking(InfrastructureExplanation::CommonHost)
        .unwrap();
    let cdn = host_report
        .ranking(InfrastructureExplanation::CommonCdn)
        .unwrap();
    assert_eq!(host.score(), cdn.score());

    let mut registrar_engine =
        TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    registrar_engine
        .observe(observation(
            "domain-a",
            "site-a",
            InfrastructureKind::Domain,
            "shared.example",
            source("domain-source-a", None),
            10,
        ))
        .unwrap();
    registrar_engine
        .observe(observation(
            "domain-b",
            "site-b",
            InfrastructureKind::Domain,
            "shared.example",
            source("domain-source-b", None),
            10,
        ))
        .unwrap();
    let registrar_report = registrar_engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        registrar_report.leading_explanation(),
        InfrastructureExplanation::DirectTechnicalRelationship
    );
    let direct = registrar_report
        .ranking(InfrastructureExplanation::DirectTechnicalRelationship)
        .unwrap();
    let registrar = registrar_report
        .ranking(InfrastructureExplanation::CommonRegistrar)
        .unwrap();
    assert_eq!(direct.score(), registrar.score());
    let unknown = registrar_report
        .ranking(InfrastructureExplanation::Unknown)
        .unwrap();
    assert!(unknown.score() < registrar.score());
}

#[test]
fn shared_third_party_service_leads_for_cross_kind_pairs_outside_the_named_families() {
    // An IpAddress/Asn pair is not one of the explicitly modeled kind
    // combinations (unlike same-kind Ip/Ip, Asn/Asn, or the Domain/Dns/
    // Certificate/HostingProvider technical-relationship families), so it
    // falls through to the generic catch-all, which only ever proposes
    // `SharedThirdPartyService` (plus the universal `Unknown` floor).
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    engine
        .observe(observation(
            "ip-a",
            "site-a",
            InfrastructureKind::IpAddress,
            "shared-indicator",
            source("ip-source-a", None),
            10,
        ))
        .unwrap();
    engine
        .observe(observation(
            "asn-b",
            "site-b",
            InfrastructureKind::Asn,
            "shared-indicator",
            source("asn-source-b", None),
            10,
        ))
        .unwrap();

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.leading_explanation(),
        InfrastructureExplanation::SharedThirdPartyService
    );
    let leading = report
        .ranking(InfrastructureExplanation::SharedThirdPartyService)
        .unwrap();
    assert!(leading.score() > 0);
    let unknown = report.ranking(InfrastructureExplanation::Unknown).unwrap();
    assert!(unknown.score() < leading.score());
    assert!(
        report
            .ranking(InfrastructureExplanation::CommonCdn)
            .is_none()
    );
    assert!(
        report
            .ranking(InfrastructureExplanation::CommonHost)
            .is_none()
    );
}

#[test]
fn unknown_leads_when_every_named_explanation_is_narrowly_and_independently_supported() {
    // `Unknown` is inserted for every comparable pair, but only ever at half
    // that pair's base weight (`supports()`), while the same pair always
    // also produces at least one named explanation at *full* weight. A
    // single pair can therefore never let `Unknown` lead. `Unknown` can
    // only lead by out-accumulating cross-pair corroboration credit: it is
    // present in every independent group, while no single named explanation
    // repeats across more than a couple of them. This is a real, narrow
    // scenario (unlike `CommonCdn`/`CommonRegistrar`, which can never lead
    // regardless of construction because they always tie their dominating
    // sibling and lose the tie-break).
    //
    // Three temporally disjoint, independently sourced, independently
    // valued pairs are constructed, one per family:
    //   - Domain/Domain      -> {CommonRegistrar, DirectTechnicalRelationship}
    //   - IpAddress/IpAddress-> {CommonHost, CommonCdn, SharedThirdPartyService}
    //   - Domain/Certificate -> {DirectTechnicalRelationship} only
    // `DirectTechnicalRelationship` repeats across the first and third pair
    // (2-group corroboration); every other named explanation is supported
    // by exactly one pair (no corroboration). `Unknown` alone spans all
    // three independent groups, and its three-group corroboration bonus
    // outweighs its per-pair half-weight handicap enough to out-score even
    // `DirectTechnicalRelationship`.
    let low = CorrelationFactors::new(20, 20, 20, 20, 20, 20, 20, 20, 20);
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    for (left_id, right_id, value, left_kind, right_kind) in [
        (
            "domain-a",
            "domain-b",
            "shared-1",
            InfrastructureKind::Domain,
            InfrastructureKind::Domain,
        ),
        (
            "ip-a",
            "ip-b",
            "shared-2",
            InfrastructureKind::IpAddress,
            InfrastructureKind::IpAddress,
        ),
        (
            "cert-a",
            "cert-b",
            "shared-3",
            InfrastructureKind::Domain,
            InfrastructureKind::Certificate,
        ),
    ] {
        engine
            .observe(
                InfrastructureObservation::new(
                    left_id,
                    "site-a",
                    left_kind,
                    value,
                    source(&format!("{left_id}-source"), None),
                    0,
                )
                .unwrap()
                .with_factors(low),
            )
            .unwrap();
        engine
            .observe(
                InfrastructureObservation::new(
                    right_id,
                    "site-b",
                    right_kind,
                    value,
                    source(&format!("{right_id}-source"), None),
                    200_000_000,
                )
                .unwrap()
                .with_factors(low),
            )
            .unwrap();
    }

    let report = engine.correlate("site-a", "site-b").unwrap();
    assert_eq!(
        report.leading_explanation(),
        InfrastructureExplanation::Unknown
    );
    assert_eq!(report.control_assessment(), ControlAssessment::Unknown);

    let unknown = report.ranking(InfrastructureExplanation::Unknown).unwrap();
    assert_eq!(unknown.independent_support(), 3);
    let direct = report
        .ranking(InfrastructureExplanation::DirectTechnicalRelationship)
        .unwrap();
    assert_eq!(direct.independent_support(), 2);
    assert!(unknown.score() > direct.score());
    for narrow in [
        InfrastructureExplanation::CommonRegistrar,
        InfrastructureExplanation::CommonHost,
        InfrastructureExplanation::CommonCdn,
        InfrastructureExplanation::SharedThirdPartyService,
    ] {
        let ranking = report.ranking(narrow).unwrap();
        assert_eq!(ranking.independent_support(), 1);
        assert!(unknown.score() > ranking.score());
    }
}

#[test]
fn correlation_persistence_is_transactional_on_source_conflict() {
    let mut evidence = EvidenceStore::new();
    evidence
        .add_source(
            Source::new(
                "temporal-infrastructure-correlation",
                SourceType::Website,
                RetrievalMethod::Direct,
            )
            .unwrap(),
        )
        .unwrap();
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(evidence);
    engine
        .observe(observation(
            "ip-a",
            "site-a",
            InfrastructureKind::IpAddress,
            "203.0.113.8",
            source("ip-source-a", None),
            1,
        ))
        .unwrap();
    engine
        .observe(observation(
            "ip-b",
            "site-b",
            InfrastructureKind::IpAddress,
            "203.0.113.8",
            source("ip-source-b", None),
            1,
        ))
        .unwrap();

    let error = engine.correlate("site-a", "site-b").unwrap_err();
    assert_eq!(
        error,
        InfrastructureError::SourceConflict {
            source_id: "temporal-infrastructure-correlation".to_owned()
        }
    );
    assert_eq!(engine.correlation_count(), 0);
    assert!(
        engine
            .evidence()
            .relationship("infrastructure-correlation:site-a:site-b:relationship")
            .is_none()
    );
}

#[test]
fn limits_and_repeated_correlations_are_enforced() {
    let limits = InfrastructureLimits::new(2, 1).unwrap();
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::with_limits(
        EvidenceStore::new(),
        limits,
    );
    engine
        .observe(observation(
            "one",
            "site-a",
            InfrastructureKind::Domain,
            "a.example",
            source("one-source", None),
            1,
        ))
        .unwrap();
    engine
        .observe(observation(
            "two",
            "site-b",
            InfrastructureKind::Domain,
            "b.example",
            source("two-source", None),
            1,
        ))
        .unwrap();
    assert!(matches!(
        engine.observe(observation(
            "three",
            "site-c",
            InfrastructureKind::Domain,
            "c.example",
            source("three-source", None),
            1,
        )),
        Err(InfrastructureError::ResourceLimit {
            resource: "observations",
            limit: 2
        })
    ));
    assert!(matches!(
        engine.correlate("site-a", "site-b"),
        Err(InfrastructureError::NoComparableObservations { .. })
    ));
}

#[test]
fn edge_observation_ids_are_unique_and_sorted() {
    // One node-a certificate matches two independent node-b certificates, so
    // the same node-a observation supports two retained pairs. The edge and
    // its persisted provenance must cite it once, as the website engine
    // already did.
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    for (id, node, source_id) in [
        ("b-cert-2", "node-b", "source-b2"),
        ("a-cert", "node-a", "source-a"),
        ("b-cert-1", "node-b", "source-b1"),
    ] {
        engine
            .observe(observation(
                id,
                node,
                InfrastructureKind::Certificate,
                "sha256:shared",
                source(source_id, None),
                100,
            ))
            .unwrap();
    }

    let report = engine.correlate("node-a", "node-b").unwrap();
    assert_eq!(report.rankings()[0].independent_support(), 2);
    assert_eq!(
        report.edge().observation_ids(),
        &[
            "a-cert".to_owned(),
            "b-cert-1".to_owned(),
            "b-cert-2".to_owned()
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
fn correlate_all_skips_pairs_already_correlated_in_either_direction_and_is_idempotent() {
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    for (index, node) in ["node-a", "node-b", "node-c"].into_iter().enumerate() {
        engine
            .observe(observation(
                &format!("cert-{node}"),
                node,
                InfrastructureKind::Certificate,
                "sha256:shared",
                source(&format!("source-{index}"), None),
                100,
            ))
            .unwrap();
    }
    engine.correlate("node-b", "node-a").unwrap();

    let reports = engine.correlate_all().unwrap();
    assert_eq!(
        reports
            .iter()
            .map(|report| report.edge().id())
            .collect::<Vec<_>>(),
        [
            "infrastructure-correlation:node-a:node-c",
            "infrastructure-correlation:node-b:node-c"
        ]
    );
    assert_eq!(engine.correlation_count(), 3);
    assert!(
        engine
            .correlation("infrastructure-correlation:node-a:node-b")
            .is_none()
    );

    assert!(engine.correlate_all().unwrap().is_empty());
    assert_eq!(engine.correlation_count(), 3);
    engine.evidence().validate().unwrap();
}

#[test]
fn correlate_all_leaves_the_engine_unchanged_when_the_correlation_limit_is_hit() {
    let limits = InfrastructureLimits::new(10, 2).unwrap();
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::with_limits(
        EvidenceStore::new(),
        limits,
    );
    for (index, node) in ["node-a", "node-b", "node-c"].into_iter().enumerate() {
        engine
            .observe(observation(
                &format!("cert-{node}"),
                node,
                InfrastructureKind::Certificate,
                "sha256:shared",
                source(&format!("source-{index}"), None),
                100,
            ))
            .unwrap();
    }
    let evidence_len = engine.evidence().len();

    let error = engine.correlate_all().unwrap_err();
    assert_eq!(
        error,
        InfrastructureError::ResourceLimit {
            resource: "correlations",
            limit: 2,
        }
    );
    assert_eq!(engine.correlation_count(), 0);
    assert_eq!(engine.evidence().len(), evidence_len);
    assert!(
        engine
            .evidence()
            .relationship("infrastructure-correlation:node-a:node-b:relationship")
            .is_none()
    );
    engine.evidence().validate().unwrap();
}

#[test]
fn ranking_arithmetic_survives_hundreds_of_independent_supports() {
    let mut engine = TemporalMetamorphicInfrastructureCorrelationEngine::new(EvidenceStore::new());
    for node in ["node-a", "node-b"] {
        for index in 0..26 {
            engine
                .observe(observation(
                    &format!("{node}-{index}"),
                    node,
                    InfrastructureKind::Certificate,
                    "sha256:shared",
                    source(&format!("{node}-source-{index}"), None),
                    100,
                ))
                .unwrap();
        }
    }

    let report = engine.correlate("node-a", "node-b").unwrap();
    let leading = &report.rankings()[0];
    assert_eq!(leading.independent_support(), 676);
    assert_eq!(leading.temporal_compatibility().value(), 100);
    assert_eq!(report.confidence().value(), 100);
    assert_eq!(report.edge().observation_ids().len(), 52);
    engine.evidence().validate().unwrap();
}
