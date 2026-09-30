//! Differential campaign over `CalibratedEvidenceFusion`
//! (`docs/AUTONOMOUS_DECISIONS.md` #67): random valid stores (sources with
//! random metadata, observations, competing hypotheses, supporting /
//! contradicting / contextual evidence) fused under random assessments
//! (explicit and default independence groups, every dependency kind,
//! high-base-rate flags, uncertainty, unregistered evidence ids) and random
//! expected-evidence requirements (present, missing, unregistered
//! hypotheses). Every `fuse()` outcome is compared with an independent
//! reference scorer written from the module's documented rules: one
//! contribution per independence group (the first strongest wins), weights
//! from the nine-dimension calibration, scenario weights for the
//! high-base-rate removal and uncertainty perturbation, net = support −
//! contradiction, ordering by net score then hypothesis id, and the
//! falsification report's strongest alternative, strongest support group,
//! removed support, missing expected evidence and survival verdict. Errors
//! must be exactly the documented refusals. Scale with
//! `BLERADAR_FUSION_CAMPAIGN_ITERATIONS`, reseed with
//! `BLERADAR_FUSION_CAMPAIGN_SEED`; a failure prints the seed.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use bleradar_core::{
    CalibratedEvidenceFusion, DependencyKind, Evidence, EvidenceAssessment, EvidenceQuality,
    EvidenceRole, EvidenceStore, ExpectedEvidence, FusionError, FusionResult, Hypothesis,
    HypothesisKind, HypothesisScore, Observation, RetrievalMethod, Source, SourceType,
};

const DEFAULT_ITERATIONS: u64 = 2_000;
const DEFAULT_SEED: u64 = 0x0517_2026_0910_F05E;

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

const DEPENDENCIES: [DependencyKind; 6] = [
    DependencyKind::CopiedReporting,
    DependencyKind::CommonDataset,
    DependencyKind::CommonProvider,
    DependencyKind::CommonDependency,
    DependencyKind::DerivativeSource,
    DependencyKind::DuplicatedObservation,
];

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Builds a random store that always passes `validate()`.
fn random_store(rng: &mut Rng) -> EvidenceStore {
    let mut store = EvidenceStore::new();
    let mut sources = Vec::new();
    for index in 0..1 + rng.below(4) {
        let source_type = if rng.chance(0.5) {
            SourceType::Document
        } else {
            SourceType::Api
        };
        let source =
            Source::new(format!("s{index}"), source_type, RetrievalMethod::Direct).unwrap();
        store.add_source(source.clone()).unwrap();
        sources.push(source);
    }
    for index in 0..1 + rng.below(3) {
        let kind = match rng.below(3) {
            0 => HypothesisKind::Leading,
            1 => HypothesisKind::Alternative,
            _ => HypothesisKind::Null,
        };
        store
            .add_hypothesis(Hypothesis::new(format!("h{index}"), "competing origin", kind).unwrap())
            .unwrap();
    }
    let mut observations = Vec::new();
    for index in 0..1 + rng.below(8) {
        let source = &sources[rng.below(sources.len())];
        let observation = Observation::from_source(
            format!("o{index}"),
            "raw",
            None,
            source,
            rng.below(100) as u64,
        )
        .unwrap();
        store.add_observation(observation).unwrap();
        observations.push(format!("o{index}"));
    }
    let hypotheses: Vec<String> = (0..3)
        .map(|index| format!("h{index}"))
        .filter(|id| store.hypothesis(id).is_some())
        .collect();
    for index in 0..rng.below(13) {
        let role = match rng.below(5) {
            0 => EvidenceRole::Contradicting,
            1 => EvidenceRole::Contextual,
            _ => EvidenceRole::Supporting,
        };
        let evidence = Evidence::new(
            format!("e{index}"),
            hypotheses[rng.below(hypotheses.len())].clone(),
            observations[rng.below(observations.len())].clone(),
            role,
        )
        .unwrap();
        store.add_evidence(evidence).unwrap();
    }
    store.validate().unwrap();
    store
}

fn random_fusion(rng: &mut Rng) -> CalibratedEvidenceFusion {
    let mut fusion = CalibratedEvidenceFusion::new();
    for index in 0..rng.below(13) {
        if rng.chance(0.4) {
            continue;
        }
        let id = if rng.chance(0.03) {
            "e99".to_owned()
        } else {
            format!("e{index}")
        };
        let quality = if rng.chance(0.5) {
            EvidenceQuality::uniform(rng.below(101) as u8)
        } else {
            let mut dims = [0u8; 9];
            for dim in &mut dims {
                *dim = rng.below(101) as u8;
            }
            EvidenceQuality::new(
                dims[0], dims[1], dims[2], dims[3], dims[4], dims[5], dims[6], dims[7], dims[8],
            )
        };
        let mut assessment = EvidenceAssessment::new(id, quality).unwrap();
        match rng.below(4) {
            0 => assessment = assessment.in_group(format!("g{}", rng.below(2))),
            1 => assessment = assessment.in_group("  "),
            _ => {}
        }
        if rng.chance(0.5) {
            assessment = assessment.with_dependency(DEPENDENCIES[rng.below(DEPENDENCIES.len())]);
        }
        if rng.chance(0.3) {
            assessment = assessment.high_base_rate();
        }
        if rng.chance(0.4) {
            assessment = assessment.with_uncertainty(rng.below(101) as u8);
        }
        // Duplicate assessment ids are refused; ignore them like a caller would.
        let _ = fusion.add_assessment(assessment);
    }
    for index in 0..rng.below(3) {
        let hypothesis = if rng.chance(0.05) {
            "h9".to_owned()
        } else {
            format!("h{}", rng.below(3))
        };
        let expected = ExpectedEvidence::new(format!("x{index}"), hypothesis, "expected").unwrap();
        let expected = if rng.chance(0.5) {
            expected.observed()
        } else {
            expected.missing()
        };
        let _ = fusion.add_expected_evidence(expected);
    }
    fusion
}

// ------------------------------------------------------------- reference --

#[derive(Clone, Copy, Default)]
struct Scenario<'a> {
    remove_high_base_rate: bool,
    perturb_uncertainty: bool,
    skip_group: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Score {
    hypothesis: String,
    support: u32,
    contradiction: u32,
    net: i32,
    confidence: u8,
    supporting: Vec<String>,
    contradicting: Vec<String>,
    collapsed: Vec<String>,
}

struct Reference<'a> {
    store: &'a EvidenceStore,
    fusion: &'a CalibratedEvidenceFusion,
}

impl Reference<'_> {
    fn weight(assessment: &EvidenceAssessment, scenario: Scenario<'_>) -> u8 {
        if scenario.remove_high_base_rate && assessment.is_high_base_rate() {
            return 0;
        }
        let base = u32::from(assessment.quality().calibrated_weight());
        let uncertainty = if scenario.perturb_uncertainty {
            u32::from(assessment.uncertainty().value())
        } else {
            0
        };
        u8::try_from(base * (100 - uncertainty) / 100).unwrap()
    }

    fn group(&self, assessment: &EvidenceAssessment, evidence: &Evidence) -> String {
        if let Some(group) = assessment.independence_group() {
            return group.to_owned();
        }
        let observation = self.store.observation(evidence.observation()).unwrap();
        match assessment.dependency() {
            Some(DependencyKind::DuplicatedObservation) => {
                format!("observation:{}", observation.id())
            }
            _ => format!("source:{}", observation.source()),
        }
    }

    /// Reference score under the documented collapse rule: one contribution
    /// per independence group, the first strongest retained.
    fn score(&self, hypothesis: &str, scenario: Scenario<'_>) -> Result<Score, FusionError> {
        let mut support: BTreeMap<String, (String, u8)> = BTreeMap::new();
        let mut contradiction: BTreeMap<String, (String, u8)> = BTreeMap::new();
        let mut collapsed = Vec::new();
        for assessment in self.fusion.assessments() {
            let Some(evidence) = self.store.evidence(assessment.evidence_id()) else {
                return Err(FusionError::MissingEvidence {
                    evidence_id: assessment.evidence_id().to_owned(),
                });
            };
            if evidence.hypothesis() != hypothesis {
                continue;
            }
            let group = self.group(assessment, evidence);
            if scenario.skip_group == Some(group.as_str()) {
                continue;
            }
            let weight = Self::weight(assessment, scenario);
            if weight == 0 {
                continue;
            }
            let target = match evidence.role() {
                EvidenceRole::Supporting => &mut support,
                EvidenceRole::Contradicting => &mut contradiction,
                EvidenceRole::Contextual => continue,
            };
            match target.get(&group) {
                Some((_, previous)) if *previous >= weight => {
                    collapsed.push(evidence.id().to_owned());
                }
                Some((previous_id, _)) => {
                    collapsed.push(previous_id.clone());
                    target.insert(group, (evidence.id().to_owned(), weight));
                }
                None => {
                    target.insert(group, (evidence.id().to_owned(), weight));
                }
            }
        }
        let support_score: u32 = support.values().map(|(_, w)| u32::from(*w)).sum();
        let contradiction_score: u32 = contradiction.values().map(|(_, w)| u32::from(*w)).sum();
        let net =
            i32::try_from(support_score).unwrap() - i32::try_from(contradiction_score).unwrap();
        Ok(Score {
            hypothesis: hypothesis.to_owned(),
            support: support_score,
            contradiction: contradiction_score,
            net,
            confidence: u8::try_from(net.clamp(0, 100)).unwrap(),
            supporting: support.values().map(|(id, _)| id.clone()).collect(),
            contradicting: contradiction.values().map(|(id, _)| id.clone()).collect(),
            collapsed,
        })
    }

    fn fuse(
        &self,
        hypotheses: &[String],
        scenario: Scenario<'_>,
    ) -> Result<Vec<Score>, FusionError> {
        if hypotheses.is_empty() {
            return Err(FusionError::NoHypotheses);
        }
        let mut unique = BTreeSet::new();
        for hypothesis in hypotheses {
            if self.store.hypothesis(hypothesis).is_none() {
                return Err(FusionError::MissingHypothesis {
                    hypothesis_id: hypothesis.clone(),
                });
            }
            unique.insert(hypothesis.clone());
        }
        let mut scores = unique
            .iter()
            .map(|hypothesis| self.score(hypothesis, scenario))
            .collect::<Result<Vec<_>, _>>()?;
        scores.sort_by(|left, right| {
            right
                .net
                .cmp(&left.net)
                .then_with(|| left.hypothesis.cmp(&right.hypothesis))
        });
        Ok(scores)
    }

    /// Hypotheses `fuse()` considers: those of every assessed evidence item
    /// (the first unregistered item is an error) plus every expected item's.
    fn hypotheses(&self) -> Result<Vec<String>, FusionError> {
        let mut set = BTreeSet::new();
        for assessment in self.fusion.assessments() {
            let Some(evidence) = self.store.evidence(assessment.evidence_id()) else {
                return Err(FusionError::MissingEvidence {
                    evidence_id: assessment.evidence_id().to_owned(),
                });
            };
            set.insert(evidence.hypothesis().to_owned());
        }
        set.extend(
            self.fusion
                .expected_evidence()
                .map(|expected| expected.hypothesis().to_owned()),
        );
        Ok(set.into_iter().collect())
    }

    /// Strongest supporting group for a hypothesis: the highest first-strongest
    /// per-group weight, ties resolved towards the smallest group name.
    fn strongest_group(&self, hypothesis: &str) -> Option<String> {
        let mut groups: BTreeMap<String, u8> = BTreeMap::new();
        for assessment in self.fusion.assessments() {
            let evidence = self.store.evidence(assessment.evidence_id())?;
            if evidence.hypothesis() != hypothesis || evidence.role() != EvidenceRole::Supporting {
                continue;
            }
            let group = self.group(assessment, evidence);
            let weight = Self::weight(assessment, Scenario::default());
            let entry = groups.entry(group).or_insert(weight);
            if *entry < weight {
                *entry = weight;
            }
        }
        groups
            .iter()
            .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(left.0)))
            .map(|(group, _)| group.clone())
    }

    fn strongest_in_group(&self, hypothesis: &str, group: &str) -> Option<String> {
        self.fusion
            .assessments()
            .filter_map(|assessment| {
                let evidence = self.store.evidence(assessment.evidence_id())?;
                if evidence.hypothesis() != hypothesis
                    || evidence.role() != EvidenceRole::Supporting
                    || self.group(assessment, evidence) != group
                {
                    return None;
                }
                Some((
                    Self::weight(assessment, Scenario::default()),
                    evidence.id().to_owned(),
                ))
            })
            .max()
            .map(|(_, id)| id)
    }
}

fn same_score(actual: &HypothesisScore, expected: &Score) -> Result<(), String> {
    if actual.hypothesis() != expected.hypothesis
        || actual.support_score() != expected.support
        || actual.contradiction_score() != expected.contradiction
        || actual.net_score() != expected.net
        || actual.calibrated_confidence().value() != expected.confidence
        || actual.supporting_evidence() != expected.supporting.as_slice()
        || actual.contradicting_evidence() != expected.contradicting.as_slice()
        || actual.collapsed_evidence() != expected.collapsed.as_slice()
    {
        return Err(format!(
            "score for {} differs: engine {actual:?} reference {expected:?}",
            expected.hypothesis
        ));
    }
    Ok(())
}

fn same_result(actual: &FusionResult, expected: &[Score]) -> Result<(), String> {
    if actual.scores().len() != expected.len() {
        return Err(format!(
            "{} scores, reference {}",
            actual.scores().len(),
            expected.len()
        ));
    }
    for (score, reference) in actual.scores().iter().zip(expected) {
        same_score(score, reference)?;
    }
    if actual.leading_hypothesis() != expected[0].hypothesis {
        return Err("leading hypothesis is not the first score".into());
    }
    Ok(())
}

fn check(store: &EvidenceStore, fusion: &CalibratedEvidenceFusion) -> Result<bool, String> {
    let reference = Reference { store, fusion };
    let expected = reference
        .hypotheses()
        .and_then(|hypotheses| reference.fuse(&hypotheses, Scenario::default()));
    let result = fusion.fuse(store);
    let scores = match (result, expected) {
        (Err(actual), Err(expected)) => {
            if actual != expected {
                return Err(format!("refusal {actual:?}, reference {expected:?}"));
            }
            return Ok(false);
        }
        (Err(actual), Ok(_)) => return Err(format!("unexpected refusal {actual:?}")),
        (Ok(result), Err(expected)) => {
            return Err(format!(
                "fused {result:?} where the reference refuses with {expected:?}"
            ));
        }
        (Ok(result), Ok(scores)) => {
            same_result(&result, &scores)?;
            (result, scores)
        }
    };
    let (result, expected) = scores;
    let candidates: Vec<String> = expected.iter().map(|s| s.hypothesis.clone()).collect();
    let leading = expected[0].hypothesis.clone();

    // Explicit hypothesis fusion agrees with the reference for any subset,
    // including unregistered ids and an empty list.
    let mut subset: Vec<String> = candidates
        .iter()
        .filter(|_| store.len().is_multiple_of(2))
        .cloned()
        .collect();
    if subset.len() % 3 == 1 {
        subset.push("h9".to_owned());
    }
    match (
        fusion.fuse_hypotheses(store, &subset),
        reference.fuse(&subset, Scenario::default()),
    ) {
        (Ok(result), Ok(scores)) => same_result(&result, &scores)?,
        (Err(actual), Err(expected)) if actual == expected => {}
        (actual, expected) => {
            return Err(format!(
                "fuse_hypotheses {actual:?} disagrees with reference {expected:?}"
            ));
        }
    }

    let report = result
        .falsify(fusion, store)
        .map_err(|error| format!("falsify failed on a fused result: {error}"))?;
    if report.leading_hypothesis() != leading {
        return Err("falsification leads with a different hypothesis".into());
    }
    same_score(report.baseline(), &expected[0])?;
    let alternative = expected.get(1).map(|s| s.hypothesis.as_str());
    if report.strongest_alternative() != alternative {
        return Err(format!(
            "strongest alternative {:?}, reference {alternative:?}",
            report.strongest_alternative()
        ));
    }
    let strongest_group = reference.strongest_group(&leading);
    let scenarios = [
        Scenario {
            remove_high_base_rate: true,
            ..Scenario::default()
        },
        Scenario {
            skip_group: strongest_group.as_deref(),
            ..Scenario::default()
        },
        Scenario {
            perturb_uncertainty: true,
            ..Scenario::default()
        },
    ];
    let mut survives = report.missing_expected_evidence().is_empty();
    for (index, scenario) in scenarios.iter().enumerate() {
        let scores = reference
            .fuse(&candidates, *scenario)
            .map_err(|error| format!("reference scenario failed: {error:?}"))?;
        let expected = scores
            .iter()
            .find(|s| s.hypothesis == leading)
            .ok_or("leading hypothesis missing from a scenario")?;
        let actual = match index {
            0 => report.without_high_base_rate(),
            1 => report.without_strongest_support(),
            _ => report.perturbed_uncertainty(),
        };
        same_score(actual, expected).map_err(|m| format!("scenario {index}: {m}"))?;
        if scores[0].hypothesis != leading {
            survives = false;
        }
    }
    if report.survives() != survives {
        return Err(format!(
            "survives {} but the reference says {survives}",
            report.survives()
        ));
    }
    if report.contradictory_evidence() != expected[0].contradicting.as_slice() {
        return Err("contradictory evidence differs from the baseline".into());
    }
    let missing: Vec<&ExpectedEvidence> = fusion
        .expected_evidence()
        .filter(|expected| expected.hypothesis() == leading && !expected.is_present())
        .collect();
    if report
        .missing_expected_evidence()
        .iter()
        .collect::<Vec<_>>()
        != missing
    {
        return Err("missing expected evidence differs".into());
    }
    let removed = strongest_group
        .as_deref()
        .and_then(|group| reference.strongest_in_group(&leading, group));
    if report.removed_support() != removed.as_deref() {
        return Err(format!(
            "removed support {:?}, reference {removed:?}",
            report.removed_support()
        ));
    }
    Ok(true)
}

#[test]
fn fusion_and_falsification_agree_with_an_independent_reference_on_random_stores() {
    let iterations = env_u64("BLERADAR_FUSION_CAMPAIGN_ITERATIONS", DEFAULT_ITERATIONS);
    let seed = env_u64("BLERADAR_FUSION_CAMPAIGN_SEED", DEFAULT_SEED);
    let mut rng = Rng(seed | 1);
    let mut fused = 0u64;
    let mut refused = 0u64;
    for iteration in 0..iterations {
        let store = random_store(&mut rng);
        let fusion = random_fusion(&mut rng);
        let outcome = catch_unwind(AssertUnwindSafe(|| check(&store, &fusion)));
        match outcome {
            Err(_) => panic!("seed={seed} iteration={iteration}: fusion panicked"),
            Ok(Err(violation)) => panic!("seed={seed} iteration={iteration}: {violation}"),
            Ok(Ok(true)) => fused += 1,
            Ok(Ok(false)) => refused += 1,
        }
    }
    assert!(
        fused > 0 && refused > 0,
        "generators must exercise both outcomes: fused={fused} refused={refused}"
    );
}
