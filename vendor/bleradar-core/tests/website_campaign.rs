//! Random-operation campaign over `WebsiteLineageEcosystemAnalysisEngine`
//! (`docs/AUTONOMOUS_DECISIONS.md` #64): random `observe` /
//! `observe_snapshot` / bulk-observe / `correlate` / `correlate_all` /
//! `ranked_correlations` sequences under random limits and continuity windows,
//! with colliding observation ids, conflicting sources (same id, different
//! metadata), a canonical observation pre-seeded to conflict with an id the
//! generators reuse, empty identifiers, unknown and identical websites, and
//! bursts of up to 40 observations from distinct sources so one correlation
//! can carry 1,600 independent supports. Oracles after every operation: no
//! panic; observation and correlation counts never exceed the limits; a
//! refused operation leaves the observation set, the correlation set, and the
//! evidence store's length unchanged (`observe_snapshot` and `correlate_all`
//! are all-or-nothing); an accepted observation is retrievable, persisted, and
//! indexed under its website; an accepted correlation is persisted under the
//! derived id with its relationship, its leading explanation is the first
//! ranking with a positive score, rankings are score-ordered, confidences and
//! temporal compatibilities are within 0–100, `independent_support` equals the
//! retained pair count, cited observation ids are unique and belong to the two
//! websites; after `correlate_all` every comparable pair is correlated in one
//! direction; `ranked_correlations()` is complete and ordered by descending
//! confidence then id; the evidence store validates. Scale with
//! `BLERADAR_WEBSITE_CAMPAIGN_SEQUENCES`, reseed with
//! `BLERADAR_WEBSITE_CAMPAIGN_SEED`; a failure prints the seed.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use bleradar_core::{
    EvidenceStore, EvidenceValue, Observation, RetrievalMethod, Source, SourceType,
    TemporalInterval, WebsiteError, WebsiteFactors, WebsiteFeatureKind, WebsiteLimits,
    WebsiteLineageEcosystemAnalysisEngine, WebsiteObservation, WebsiteSnapshot,
};

const DEFAULT_SEQUENCES: u64 = 100;
const OPS_PER_SEQUENCE: usize = 60;
const DEFAULT_SEED: u64 = 0x0517_2026_0910_5EED;

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

const SITES: &[&str] = &["site-a", "site-b", "site-c", ""];
const VALUES: &[&str] = &["shared", "Shared", " shared ", "unique-1", "unique-2", "x"];
const HTML: &[&str] = &[
    "<html><body>Alpha</body></html>",
    "<html><head><script src='/app.js'></script></head><body><main>Rare public phrase for lineage analysis. Another distinctive sentence lives here too.</main></body></html>",
    "plain text without any tags at all",
    "<div><p>one two three four five six</p></div>",
    "",
    "<<>>",
];

fn source(rng: &mut Rng) -> Source {
    let id = format!("src{}", rng.below(4));
    let source_type = if rng.chance(0.5) {
        SourceType::Website
    } else {
        SourceType::Api
    };
    let mut source = Source::new(id, source_type, RetrievalMethod::Direct).unwrap();
    match rng.below(4) {
        0 => source = source.with_metadata("provider", format!("prov{}", rng.below(2))),
        1 => source = source.with_metadata("dataset", "ds"),
        _ => {}
    }
    if rng.chance(0.2) {
        source = source.captured_at(rng.below(50) as u64);
    }
    source
}

fn interval(rng: &mut Rng, ts: u64) -> TemporalInterval {
    if rng.chance(0.5) {
        TemporalInterval::at(ts)
    } else {
        let first = ts.saturating_sub(rng.below(20) as u64);
        let last = ts + rng.below(20) as u64;
        TemporalInterval::new(first, ts, last).unwrap()
    }
}

fn observation(rng: &mut Rng, ts: u64) -> Option<WebsiteObservation> {
    let id = if rng.chance(0.03) {
        String::new()
    } else {
        format!("o{}", rng.below(12))
    };
    let site = SITES[rng.below(SITES.len())];
    let kind = WebsiteFeatureKind::ALL[rng.below(WebsiteFeatureKind::ALL.len())];
    let value = VALUES[rng.below(VALUES.len())];
    let source = source(rng);
    let mut observation =
        WebsiteObservation::with_interval(id, site, kind, value, source, interval(rng, ts)).ok()?;
    if rng.chance(0.5) {
        observation = observation.with_normalized_value(value.trim().to_ascii_lowercase());
    }
    if rng.chance(0.3) {
        observation = observation
            .with_feature(format!(
                "{}:{}",
                kind.as_str(),
                value.trim().to_ascii_lowercase()
            ))
            .ok()?;
    }
    if rng.chance(0.2) {
        observation = observation
            .in_dependency_group(format!("g{}", rng.below(2)))
            .ok()?;
    }
    if rng.chance(0.3) {
        let s = rng.below(101) as u8;
        observation = observation.with_factors(WebsiteFactors::new(s, s, s, s, s, s, s, s, s));
    }
    if rng.chance(0.2) {
        observation = observation.high_base_rate();
    }
    if rng.chance(0.2) {
        observation = observation.with_uncertainty(rng.below(101) as u8);
    }
    Some(observation)
}

fn snapshot(rng: &mut Rng, ts: u64) -> Option<WebsiteSnapshot> {
    let id = format!("snap{}", rng.below(4));
    let site = SITES[rng.below(SITES.len())];
    let html = HTML[rng.below(HTML.len())];
    let mut snapshot = WebsiteSnapshot::new(id, site, html, source(rng), ts).ok()?;
    if rng.chance(0.5) {
        snapshot = snapshot.with_timeline(interval(rng, ts));
    }
    for _ in 0..rng.below(3) {
        snapshot = snapshot
            .with_public_asset(VALUES[rng.below(VALUES.len())])
            .ok()?;
    }
    if rng.chance(0.4) {
        snapshot = snapshot
            .with_public_analytics_identifier(VALUES[rng.below(VALUES.len())])
            .ok()?;
    }
    if rng.chance(0.3) {
        snapshot = snapshot
            .with_script_reference(VALUES[rng.below(VALUES.len())])
            .ok()?;
    }
    if rng.chance(0.3) {
        snapshot = snapshot
            .with_certificate(VALUES[rng.below(VALUES.len())])
            .ok()?;
    }
    if rng.chance(0.2) {
        snapshot = snapshot.in_dependency_group("g0").ok()?;
    }
    Some(snapshot)
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct State {
    observations: BTreeSet<String>,
    correlations: BTreeSet<String>,
    evidence_len: usize,
}

fn state(engine: &WebsiteLineageEcosystemAnalysisEngine) -> State {
    State {
        observations: engine.observations().map(|o| o.id().to_owned()).collect(),
        correlations: engine
            .correlations()
            .map(|c| c.edge().id().to_owned())
            .collect(),
        evidence_len: engine.evidence().len(),
    }
}

fn consistency(
    engine: &WebsiteLineageEcosystemAnalysisEngine,
    limits: WebsiteLimits,
) -> Result<(), String> {
    if engine.observation_count() > limits.max_observations() {
        return Err("observation_count exceeds the limit".into());
    }
    if engine.correlation_count() > limits.max_correlations() {
        return Err("correlation_count exceeds the limit".into());
    }
    if engine.observations().count() != engine.observation_count() {
        return Err("observations() disagrees with observation_count()".into());
    }
    if engine.correlations().count() != engine.correlation_count() {
        return Err("correlations() disagrees with correlation_count()".into());
    }
    let ranked = engine.ranked_correlations();
    if ranked.len() != engine.correlation_count() {
        return Err("ranked_correlations() is incomplete".into());
    }
    for pair in ranked.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        if a.confidence() < b.confidence()
            || (a.confidence() == b.confidence() && a.edge().id() >= b.edge().id())
        {
            return Err(format!(
                "ranking order broken: {} ({}) before {} ({})",
                a.edge().id(),
                a.confidence().value(),
                b.edge().id(),
                b.confidence().value()
            ));
        }
    }
    for report in engine.correlations() {
        let edge = report.edge();
        if edge.id() != format!("website-lineage:{}:{}", edge.subject(), edge.object()) {
            return Err(format!(
                "edge id {} is not derived from its ends",
                edge.id()
            ));
        }
        if engine
            .evidence()
            .relationship(edge.relationship_id())
            .is_none()
        {
            return Err(format!(
                "relationship {} is not persisted",
                edge.relationship_id()
            ));
        }
        let Some(first) = report.rankings().first() else {
            return Err("persisted report without rankings".into());
        };
        if first.explanation() != report.leading_explanation() {
            return Err("leading explanation is not the first ranking".into());
        }
        if first.score() == 0 {
            return Err("persisted correlation with a zero score".into());
        }
        if first.confidence() != report.confidence() {
            return Err("report confidence differs from the baseline ranking".into());
        }
        for pair in report.rankings().windows(2) {
            if pair[0].score() < pair[1].score() {
                return Err("rankings are not ordered by score".into());
            }
        }
        for ranking in report.rankings() {
            if ranking.confidence().value() > 100 || ranking.temporal_compatibility().value() > 100
            {
                return Err("confidence or temporal compatibility out of range".into());
            }
            if ranking.independent_support() != ranking.supporting_pairs().len() {
                return Err("independent_support differs from the retained pairs".into());
            }
        }
        let mut seen = BTreeSet::new();
        for id in edge.observation_ids() {
            if !seen.insert(id.clone()) {
                return Err(format!("edge cites observation {id} twice"));
            }
            let Some(observation) = engine.observation(id) else {
                return Err(format!("edge cites unknown observation {id}"));
            };
            if observation.website_id() != edge.subject()
                && observation.website_id() != edge.object()
            {
                return Err(format!("edge cites {id} from a third website"));
            }
        }
        if report.falsification().survives() && report.falsification().baseline().score() == 0 {
            return Err("falsification survives with a zero baseline".into());
        }
    }
    engine
        .evidence()
        .validate()
        .map_err(|error| format!("evidence store invalid: {error}"))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn pre_seeded_store(rng: &mut Rng) -> EvidenceStore {
    let mut store = EvidenceStore::new();
    if rng.chance(0.5) {
        let source = Source::new("src0", SourceType::Website, RetrievalMethod::Direct).unwrap();
        store.add_source(source.clone()).unwrap();
        let id = if rng.chance(0.5) {
            "o3"
        } else {
            "snap1:normalized-text"
        };
        store
            .add_observation(
                Observation::new(
                    id,
                    "different",
                    Some(EvidenceValue::Text("different".into())),
                    source.id(),
                    source.source_type().clone(),
                    source.retrieval_method().clone(),
                    100,
                )
                .unwrap(),
            )
            .unwrap();
    }
    store
}

#[test]
fn random_operation_campaign_keeps_the_engine_consistent() {
    let sequences = env_u64("BLERADAR_WEBSITE_CAMPAIGN_SEQUENCES", DEFAULT_SEQUENCES);
    let seed = env_u64("BLERADAR_WEBSITE_CAMPAIGN_SEED", DEFAULT_SEED);
    let mut rng = Rng(seed | 1);
    let mut successes = 0u64;
    let mut refusals = 0u64;
    let mut largest_support = 0usize;
    for seq in 0..sequences {
        let limits = WebsiteLimits::new(1 + rng.below(80), 1 + rng.below(12))
            .unwrap()
            .with_maximum_temporal_gap([0u64, 5, 86_400_000][rng.below(3)]);
        let store = pre_seeded_store(&mut rng);
        let mut engine = WebsiteLineageEcosystemAnalysisEngine::with_limits(store, limits);
        let mut ts = 100u64;
        for k in 0..OPS_PER_SEQUENCE {
            ts += rng.below(30) as u64;
            let before = state(&engine);
            let op = rng.below(12);
            let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
                if op < 4 {
                    let Some(observation) = observation(&mut rng, ts) else {
                        return Ok(());
                    };
                    let id = observation.id().to_owned();
                    let site = observation.website_id().to_owned();
                    match engine.observe(observation) {
                        Ok(()) => {
                            successes += 1;
                            if engine.observation_count() != before.observations.len() + 1 {
                                return Err("observe did not add exactly one".into());
                            }
                            if engine.observation(&id).is_none()
                                || engine.evidence().observation(&id).is_none()
                            {
                                return Err(format!("observation {id} not retrievable/persisted"));
                            }
                            if engine.evidence().entity(&site).is_none() {
                                return Err(format!("website entity {site} not persisted"));
                            }
                            if !engine.observations_for_website(&site).any(|o| o.id() == id) {
                                return Err(format!("observation {id} not indexed under {site}"));
                            }
                        }
                        Err(error) => {
                            refusals += 1;
                            if state(&engine) != before {
                                return Err(format!(
                                    "observe {id} refused with {error} but mutated the engine"
                                ));
                            }
                        }
                    }
                } else if op < 6 {
                    let Some(snapshot) = snapshot(&mut rng, ts) else {
                        return Ok(());
                    };
                    let expected = snapshot
                        .extract_observations()
                        .map(|v| v.len())
                        .unwrap_or(0);
                    match engine.observe_snapshot(&snapshot) {
                        Ok(ids) => {
                            successes += 1;
                            if ids.len() != expected {
                                return Err("snapshot ids differ from the extraction".into());
                            }
                            if engine.observation_count() != before.observations.len() + ids.len() {
                                return Err("snapshot did not add exactly its ids".into());
                            }
                            for id in &ids {
                                if engine.observation(id).is_none()
                                    || engine.evidence().observation(id).is_none()
                                {
                                    return Err(format!("snapshot id {id} not persisted"));
                                }
                            }
                        }
                        Err(error) => {
                            refusals += 1;
                            if state(&engine) != before {
                                return Err(format!(
                                    "observe_snapshot refused with {error} but mutated the engine"
                                ));
                            }
                        }
                    }
                } else if op < 7 {
                    // A burst of observations from distinct sources sharing one
                    // value, so a later correlation carries many independent
                    // supports.
                    let site = SITES[rng.below(3)];
                    let count = 1 + rng.below(40);
                    let kind = WebsiteFeatureKind::ALL[rng.below(WebsiteFeatureKind::ALL.len())];
                    for i in 0..count {
                        let source = Source::new(
                            format!("bulk-{site}-{i}-{}", rng.below(1000)),
                            SourceType::Website,
                            RetrievalMethod::Direct,
                        )
                        .unwrap();
                        let observation = WebsiteObservation::new(
                            format!("bulk-{site}-{k}-{i}"),
                            site,
                            kind,
                            "shared",
                            source,
                            ts,
                        )
                        .unwrap();
                        let before_one = state(&engine);
                        match engine.observe(observation) {
                            Ok(()) => successes += 1,
                            Err(error) => {
                                refusals += 1;
                                if state(&engine) != before_one {
                                    return Err(format!(
                                        "bulk observe refused with {error} but mutated the engine"
                                    ));
                                }
                                break;
                            }
                        }
                    }
                } else if op < 10 {
                    let left = SITES[rng.below(SITES.len())];
                    let right = if rng.chance(0.1) {
                        "unknown"
                    } else {
                        SITES[rng.below(SITES.len())]
                    };
                    match engine.correlate(left, right) {
                        Ok(report) => {
                            successes += 1;
                            largest_support =
                                largest_support.max(report.rankings()[0].independent_support());
                            let id = report.edge().id().to_owned();
                            if id != format!("website-lineage:{left}:{right}") {
                                return Err(format!("unexpected correlation id {id}"));
                            }
                            if engine.correlation_count() != before.correlations.len() + 1 {
                                return Err("correlate did not add exactly one".into());
                            }
                            match engine.correlation(&id) {
                                Some(persisted) if persisted.edge() == report.edge() => {}
                                _ => return Err("persisted report differs from the result".into()),
                            }
                            if report.phases().len() != 9 {
                                return Err("report does not record nine phases".into());
                            }
                        }
                        Err(error) => {
                            refusals += 1;
                            if state(&engine) != before {
                                return Err(format!(
                                    "correlate {left}/{right} refused with {error} but mutated the engine"
                                ));
                            }
                            if matches!(error, WebsiteError::SameWebsite { .. }) && left != right {
                                return Err("SameWebsite for different websites".into());
                            }
                        }
                    }
                } else if op < 11 {
                    match engine.correlate_all() {
                        Ok(reports) => {
                            successes += 1;
                            if engine.correlation_count()
                                != before.correlations.len() + reports.len()
                            {
                                return Err("correlate_all reports differ from the growth".into());
                            }
                            let sites: BTreeSet<String> = engine
                                .observations()
                                .map(|o| o.website_id().to_owned())
                                .collect();
                            let sites: Vec<String> = sites.into_iter().collect();
                            for (i, left) in sites.iter().enumerate() {
                                for right in sites.iter().skip(i + 1) {
                                    let forward = format!("website-lineage:{left}:{right}");
                                    let reverse = format!("website-lineage:{right}:{left}");
                                    if engine.correlation(&forward).is_some()
                                        || engine.correlation(&reverse).is_some()
                                    {
                                        continue;
                                    }
                                    let mut probe = engine.clone();
                                    match probe.correlate(left, right) {
                                        Err(WebsiteError::NoComparableObservations { .. })
                                        | Err(WebsiteError::ResourceLimit { .. }) => {}
                                        Ok(_) => {
                                            return Err(format!(
                                                "correlate_all left comparable pair {forward} uncorrelated"
                                            ));
                                        }
                                        Err(error) => {
                                            return Err(format!(
                                                "correlate_all left {forward} uncorrelated: {error}"
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            refusals += 1;
                            if state(&engine) != before {
                                return Err(format!(
                                    "correlate_all refused with {error} but mutated the engine"
                                ));
                            }
                        }
                    }
                } else {
                    let _ = engine.ranked_correlations();
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
        successes > 0 && refusals > 0,
        "generators must exercise both outcomes: successes={successes} refusals={refusals}"
    );
    assert!(
        largest_support > 655,
        "generators must reach a correlation with more independent supports than a u16 \
         temporal-compatibility sum could hold (largest={largest_support})"
    );
}
