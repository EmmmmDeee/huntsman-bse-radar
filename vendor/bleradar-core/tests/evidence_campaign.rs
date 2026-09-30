//! Random-operation campaign over the canonical `EvidenceStore`
//! (`docs/AUTONOMOUS_DECISIONS.md` #62): random insert/update sequences over a
//! deliberately small id space, so references collide, dangle, arrive out of
//! order, and violate the temporal/verification rules. Oracles: no panic;
//! after every operation `validate()` is green except for the documented
//! transient `ClaimWithoutEvidence` incompleteness (a claim may precede its
//! evidence; `trace_claim` must agree); a rejected operation leaves `len()`
//! unchanged; `trace_claim` and `observations_by_source` agree with a manual
//! recount; a `transaction` (nested up to two levels, holding one to four
//! random operations, aborted by error or by panic half of the time) leaves
//! the store's complete state exactly as it was when it does not commit and
//! loses nothing when it does. Scale with
//! `BLERADAR_EVIDENCE_CAMPAIGN_SEQUENCES` and reseed with
//! `BLERADAR_EVIDENCE_CAMPAIGN_SEED`; a failure prints the seed.

use std::panic::{AssertUnwindSafe, catch_unwind};

use bleradar_core::{
    Action, ActionType, Artifact, ArtifactType, Claim, Confidence, ConfidenceTarget,
    ConfidenceUpdate, EdgeType, Entity, EntityType, Event, EventType, Evidence, EvidenceRole,
    EvidenceStore, EvidenceValue, Feature, Hypothesis, HypothesisKind, Observation,
    ObservationTimeline, ProvenanceError, Relationship, RelationshipProvenance, Representation,
    RepresentationType, RetrievalMethod, Source, SourceType, Test, TestType, Transformation,
    Verification,
};

const DEFAULT_SEQUENCES: u64 = 100;
const OPS_PER_SEQUENCE: usize = 250;
const DEFAULT_SEED: u64 = 0xC0FF_EE00_2026_0910;

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

const N: usize = 5;
const PREFIXES: &[&str] = &[
    "s", "e", "a", "o", "f", "r", "t", "x", "v", "h", "c", "ev", "rel", "act", "cu",
];

fn id(rng: &mut Rng, prefix: &str) -> String {
    format!("{prefix}{}", rng.below(N))
}
fn any_id(rng: &mut Rng) -> String {
    let p = PREFIXES[rng.below(PREFIXES.len())];
    id(rng, p)
}
fn ids(rng: &mut Rng, prefix: &str, max: usize) -> Vec<String> {
    (0..rng.below(max + 1)).map(|_| id(rng, prefix)).collect()
}
fn source_type(rng: &mut Rng) -> SourceType {
    match rng.below(4) {
        0 => SourceType::Sensor,
        1 => SourceType::Website,
        2 => SourceType::Repository,
        _ => SourceType::Api,
    }
}
fn retrieval(rng: &mut Rng) -> RetrievalMethod {
    if rng.chance(0.5) {
        RetrievalMethod::Direct
    } else {
        RetrievalMethod::Search
    }
}
fn ts(rng: &mut Rng) -> u64 {
    match rng.below(4) {
        0 => 0,
        1 => u64::MAX - rng.below(3) as u64,
        _ => rng.below(1_000) as u64,
    }
}

/// A constructor rejection (empty id, feature in both sets, empty verification
/// test list, invalid timeline) is a legitimate typed refusal, not a store
/// operation: report it as a no-op step.
macro_rules! ctor {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(_) => return Ok(("ctor rejected".to_string(), Ok(()))),
        }
    };
}

/// Runs one operation; returns (description, result) — `Err(String)` from a
/// caught panic is reported separately.
fn step(
    rng: &mut Rng,
    store: &mut EvidenceStore,
) -> Result<(String, Result<(), ProvenanceError>), String> {
    step_at(rng, store, 0)
}

/// A random transaction holding one to four operations (some of them nested
/// transactions), committed or aborted at random; `Err` from the closure and
/// a panic inside it must both restore the store's complete state.
fn transaction_step(
    rng: &mut Rng,
    store: &mut EvidenceStore,
    depth: u8,
) -> Result<(String, Result<(), ProvenanceError>), String> {
    let before = format!("{store:?}");
    let len_before = store.len();
    let planned = 1 + rng.below(4);
    let abort = rng.chance(0.5);
    let poison = abort && rng.chance(0.2);
    let mut inconsistency: Option<String> = None;
    let mut len_inside = len_before;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        store.transaction(|store| {
            for _ in 0..planned {
                let result = if depth < 2 && rng.chance(0.3) {
                    transaction_step(rng, store, depth + 1)
                } else {
                    step_at(rng, store, depth + 1)
                };
                if let Err(violation) = result {
                    inconsistency = Some(violation);
                    break;
                }
            }
            len_inside = store.len();
            if poison {
                panic!("adapter failure inside a transaction");
            }
            if abort {
                Err(ProvenanceError::DuplicateId {
                    collection: "transaction",
                    id: "abort".to_owned(),
                })
            } else {
                Ok(())
            }
        })
    }));
    if let Some(violation) = inconsistency {
        return Err(violation);
    }
    match attempt {
        Err(_) if poison => {
            if format!("{store:?}") != before {
                return Err(format!(
                    "transaction (depth {depth}) panicked but the store changed"
                ));
            }
            Ok((
                format!("transaction depth {depth} panicked"),
                Err(ProvenanceError::DuplicateId {
                    collection: "transaction",
                    id: "panic".to_owned(),
                }),
            ))
        }
        Err(_) => Err(format!("transaction (depth {depth}) panicked unexpectedly")),
        Ok(Err(error)) => {
            if format!("{store:?}") != before || store.len() != len_before {
                return Err(format!(
                    "transaction (depth {depth}) aborted but the store changed"
                ));
            }
            Ok((format!("transaction depth {depth} aborted"), Err(error)))
        }
        Ok(Ok(())) => {
            if store.len() != len_inside || len_inside < len_before {
                return Err(format!(
                    "transaction (depth {depth}) committed but lost changes: {} inside, {} after",
                    len_inside,
                    store.len()
                ));
            }
            Ok((format!("transaction depth {depth} committed"), Ok(())))
        }
    }
}

fn step_at(
    rng: &mut Rng,
    store: &mut EvidenceStore,
    depth: u8,
) -> Result<(String, Result<(), ProvenanceError>), String> {
    let op = rng.below(19);
    if op == 18 {
        return transaction_step(rng, store, depth);
    }
    let t = ts(rng);
    let outcome: (String, Result<(), ProvenanceError>) = match op {
        0 => {
            let sid = id(rng, "s");
            let s =
                ctor!(Source::new(sid.clone(), source_type(rng), retrieval(rng))).captured_at(t);
            (format!("insert_source {sid}"), store.insert_source(s))
        }
        1 => {
            let eid = id(rng, "e");
            let e = ctor!(Entity::new(eid.clone(), EntityType::Device));
            (format!("insert_entity {eid}"), store.insert_entity(e))
        }
        2 => {
            let aid = id(rng, "a");
            let mut a = ctor!(Artifact::new(aid.clone(), ArtifactType::Digital));
            if rng.chance(0.5) {
                a = a.for_entity(id(rng, "e"));
            }
            if rng.chance(0.5) {
                a = a.from_source(id(rng, "s"));
            }
            (format!("insert_artifact {aid}"), store.insert_artifact(a))
        }
        3 => {
            let oid = id(rng, "o");
            let sid = id(rng, "s");
            let obs = if rng.chance(0.7) && store.source(&sid).is_some() {
                let src = store.source(&sid).cloned().unwrap();
                Observation::from_source(
                    oid.clone(),
                    EvidenceValue::text("raw"),
                    Some(EvidenceValue::text("norm")),
                    &src,
                    t,
                )
            } else {
                let timeline = ObservationTimeline::new(
                    t.min(t.saturating_add(1)),
                    t,
                    t.saturating_add(rng.below(3) as u64),
                );
                match timeline {
                    Ok(tl) => Observation::with_timeline(
                        oid.clone(),
                        "raw",
                        None::<EvidenceValue>,
                        sid.clone(),
                        source_type(rng),
                        retrieval(rng),
                        tl,
                    ),
                    Err(e) => Err(e),
                }
            };
            let mut obs = ctor!(obs);
            if rng.chance(0.3) {
                obs = ctor!(obs.with_derivation(id(rng, "x")));
            }
            (
                format!("insert_observation {oid} <- {sid}"),
                store.insert_observation(obs),
            )
        }
        4 => {
            let oid = id(rng, "o");
            (
                format!("record_observation_seen_at {oid} @{t}"),
                store.record_observation_seen_at(&oid, t),
            )
        }
        5 => {
            let fid = id(rng, "f");
            let mut f = ctor!(Feature::new(
                fid.clone(),
                "feature",
                EvidenceValue::text("v")
            ));
            if rng.chance(0.6) {
                f = f.from_observation(id(rng, "o"));
            }
            if rng.chance(0.5) {
                f = f.derived_from(ids(rng, "f", 2));
            }
            if rng.chance(0.5) {
                f = f.created_at(t);
            }
            (format!("insert_feature {fid}"), store.insert_feature(f))
        }
        6 => {
            let rid = id(rng, "r");
            let mut r = ctor!(Representation::new(
                rid.clone(),
                id(rng, "a"),
                RepresentationType::Raw
            ));
            if rng.chance(0.5) {
                r = r.with_features(ids(rng, "f", 2));
            }
            if rng.chance(0.4) {
                r = r.from_source(id(rng, "s"));
            }
            if rng.chance(0.4) {
                r = r.created_at(t);
            }
            (
                format!("insert_representation {rid}"),
                store.insert_representation(r),
            )
        }
        7 => {
            let tid = id(rng, "t");
            let test = ctor!(Test::new(tid.clone(), "test", TestType::Differential))
                .with_inputs(ids(rng, "o", 2))
                .with_outputs(ids(rng, "o", 2));
            (format!("insert_test {tid}"), store.insert_test(test))
        }
        8 => {
            let xid = id(rng, "x");
            let verification = match rng.below(4) {
                0 => Ok(Verification::unverified()),
                1 => Verification::passed(ids(rng, "t", 2)),
                2 => Verification::failed(ids(rng, "t", 2)),
                _ => Verification::passed(Vec::<String>::new()),
            };
            let verification = match verification {
                Ok(v) => v,
                Err(_) => return Ok(("verification ctor rejected".to_string(), Ok(()))),
            };
            let x = ctor!(Transformation::new(
                xid.clone(),
                id(rng, "r"),
                id(rng, "r"),
                ids(rng, "f", 2),
                ids(rng, "f", 2),
                verification
            ));
            (
                format!("insert_transformation {xid}"),
                store.insert_transformation(x),
            )
        }
        9 => {
            let vid = id(rng, "v");
            let mut ev = ctor!(Event::new(vid.clone(), EventType::Observed, t));
            if rng.chance(0.6) {
                ev = ev.involving(ids(rng, "e", 2));
            }
            if rng.chance(0.5) {
                ev = ev.from_source(id(rng, "s"));
            }
            (format!("insert_event {vid}"), store.insert_event(ev))
        }
        10 => {
            let hid = id(rng, "h");
            let h = ctor!(Hypothesis::new(hid.clone(), "h", HypothesisKind::Leading));
            (
                format!("insert_hypothesis {hid}"),
                store.insert_hypothesis(h),
            )
        }
        11 => {
            let cid = id(rng, "c");
            let c = ctor!(Claim::new(cid.clone(), "claim", id(rng, "h")));
            (format!("insert_claim {cid}"), store.insert_claim(c))
        }
        12 => {
            let evid = id(rng, "ev");
            let role = match rng.below(3) {
                0 => EvidenceRole::Supporting,
                1 => EvidenceRole::Contradicting,
                _ => EvidenceRole::Contextual,
            };
            let e = ctor!(Evidence::new(
                evid.clone(),
                id(rng, "h"),
                id(rng, "o"),
                role
            ));
            (format!("insert_evidence {evid}"), store.insert_evidence(e))
        }
        13 => {
            let relid = id(rng, "rel");
            let prov = ctor!(RelationshipProvenance::new(id(rng, "s"), t, "method"))
                .supporting(ids(rng, "ev", 2))
                .contradicting(ids(rng, "ev", 1));
            let rel = ctor!(Relationship::new(
                relid.clone(),
                any_id(rng),
                "related",
                any_id(rng),
                EdgeType::Observed,
                prov
            ));
            (
                format!("insert_relationship {relid}"),
                store.insert_relationship(rel),
            )
        }
        14 => {
            let actid = id(rng, "act");
            let mut act = ctor!(Action::new(actid.clone(), ActionType::Verify, "d", t));
            if rng.chance(0.6) {
                act = act.targeting(any_id(rng));
            }
            if rng.chance(0.6) {
                act = act.motivated_by(ids(rng, "ev", 2));
            }
            (format!("insert_action {actid}"), store.insert_action(act))
        }
        15 => {
            let cuid = id(rng, "cu");
            let (target_type, target_id) = match rng.below(5) {
                0 => (ConfidenceTarget::Claim, id(rng, "c")),
                1 => (ConfidenceTarget::Hypothesis, id(rng, "h")),
                2 => (ConfidenceTarget::Relationship, id(rng, "rel")),
                3 => (ConfidenceTarget::Observation, id(rng, "o")),
                _ => (ConfidenceTarget::Entity, id(rng, "e")),
            };
            let cu = ctor!(ConfidenceUpdate::new(
                cuid.clone(),
                target_type,
                target_id,
                Confidence::new(rng.below(101) as u8),
                Confidence::new(rng.below(101) as u8),
                "r",
                t
            ))
            .based_on(ids(rng, "ev", 2));
            (
                format!("insert_confidence_update {cuid}"),
                store.insert_confidence_update(cu),
            )
        }
        16 => {
            // Claim trace consistency: Ok iff the claim exists, its hypothesis exists, and at least one evidence links to that hypothesis.
            let cid = id(rng, "c");
            let expected = store
                .claim(&cid)
                .and_then(|c| store.hypothesis(c.hypothesis()).map(|h| h.id().to_owned()))
                .map(|hid| {
                    (0..N).any(|i| {
                        store
                            .evidence(&format!("ev{i}"))
                            .is_some_and(|e| e.hypothesis() == hid)
                    })
                });
            let traced = store.trace_claim(&cid);
            let ok = match (expected, &traced) {
                (Some(true), Ok(trace)) => !trace.evidence.is_empty(),
                (Some(false), Err(ProvenanceError::ClaimWithoutEvidence { .. })) => true,
                (None, Err(_)) => true,
                _ => false,
            };
            if !ok {
                return Err(format!(
                    "trace_claim({cid}) inconsistent: expected={expected:?} got={:?}",
                    traced.map(|t| t.evidence.len())
                ));
            }
            (format!("trace_claim {cid}"), Ok(()))
        }
        _ => {
            let sid = id(rng, "s");
            let by_source = store.observations_by_source(&sid).len();
            let manual = (0..N)
                .filter(|i| {
                    store
                        .observation(&format!("o{i}"))
                        .is_some_and(|o| o.source() == sid)
                })
                .count();
            if by_source != manual {
                return Err(format!(
                    "observations_by_source({sid}) = {by_source}, manual count = {manual}"
                ));
            }
            (format!("observations_by_source {sid}"), Ok(()))
        }
    };
    Ok(outcome)
}

/// `validate()` may only fail with `ClaimWithoutEvidence`, and only for a claim
/// that `trace_claim` also reports as evidence-less (transient incompleteness
/// while a claim precedes its evidence). Any other error is a violation.
fn validate_tolerant(store: &EvidenceStore) -> Result<(), String> {
    match store.validate() {
        Ok(()) => Ok(()),
        Err(ProvenanceError::ClaimWithoutEvidence { claim_id }) => {
            match store.trace_claim(&claim_id) {
                Err(ProvenanceError::ClaimWithoutEvidence { .. }) => Ok(()),
                other => Err(format!(
                    "validate reported claim {claim_id} without evidence but trace_claim gave {:?}",
                    other.map(|t| t.evidence.len())
                )),
            }
        }
        Err(e) => Err(format!("{e}")),
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn random_operation_campaign_keeps_the_store_consistent() {
    let sequences = env_u64("BLERADAR_EVIDENCE_CAMPAIGN_SEQUENCES", DEFAULT_SEQUENCES);
    let seed = env_u64("BLERADAR_EVIDENCE_CAMPAIGN_SEED", DEFAULT_SEED);
    let mut rng = Rng(seed | 1);
    let mut accepted = 0u64;
    let mut rejected = 0u64;
    for sequence in 0..sequences {
        let mut store = EvidenceStore::new();
        for k in 0..OPS_PER_SEQUENCE {
            let before = store.len();
            let stepped = catch_unwind(AssertUnwindSafe(|| step(&mut rng, &mut store)));
            let context = format!("seed={seed} sequence={sequence} op={k}");
            match stepped {
                Err(_) => panic!("{context}: store operation panicked"),
                Ok(Err(inconsistency)) => panic!("{context}: {inconsistency}"),
                Ok(Ok((description, Ok(())))) => {
                    accepted += 1;
                    if let Err(e) = validate_tolerant(&store) {
                        panic!("{context}: validate failed after accepted {description}: {e}");
                    }
                }
                Ok(Ok((description, Err(_)))) => {
                    rejected += 1;
                    assert_eq!(
                        store.len(),
                        before,
                        "{context}: rejected {description} mutated the store"
                    );
                    if let Err(e) = validate_tolerant(&store) {
                        panic!("{context}: validate failed after rejected {description}: {e}");
                    }
                }
            }
        }
    }
    // The generators must keep exercising both outcomes, or a green run
    // proves nothing.
    assert!(
        accepted > 0 && rejected > 0,
        "accepted={accepted} rejected={rejected}"
    );
}
