//! Property and fuzz-style regression tests for the ranking/scoring engines.
//!
//! These extend the deterministic, dependency-free fuzzing used by
//! `properties.rs` to exact-rational priorities, temporal intervals, and
//! bounded calibration averages.

use bleradar_core::{
    AdvancementFactors, CorrelationFactors, EvidenceQuality, SearchPriorityFactors,
    TemporalInterval, WebsiteFactors,
};

/// Deterministic xorshift64 generator.
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform in `[lo, hi]` (inclusive on both ends).
    fn range_u8(&mut self, lo: u8, hi: u8) -> u8 {
        lo + (self.next_u64() % (u64::from(hi - lo) + 1)) as u8
    }

    /// Uniform in `[lo, hi]` (inclusive on both ends).
    fn range_u64(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo + 1)
    }
}

fn sorted_triple(rng: &mut Rng) -> (u64, u64, u64) {
    let mut values = [
        rng.range_u64(0, 1_000_000),
        rng.range_u64(0, 1_000_000),
        rng.range_u64(0, 1_000_000),
    ];
    values.sort_unstable();
    (values[0], values[1], values[2])
}

#[test]
fn prop_temporal_interval_overlap_gap_and_contiguity_are_consistent() {
    let mut rng = Rng::new(0xf00d_face_1234_5678);
    for _ in 0..100_000 {
        let (a1, a2, a3) = sorted_triple(&mut rng);
        let (b1, b2, b3) = sorted_triple(&mut rng);
        let left = TemporalInterval::new(a1, a2, a3).unwrap();
        let right = TemporalInterval::new(b1, b2, b3).unwrap();

        assert_eq!(
            left.overlaps(right),
            right.overlaps(left),
            "overlap is not symmetric for {left:?} / {right:?}"
        );
        let gap = left.gap(right);
        assert_eq!(
            gap,
            right.gap(left),
            "gap is not symmetric for {left:?} / {right:?}"
        );
        assert_eq!(
            gap == 0,
            left.overlaps(right),
            "zero gap disagrees with overlap for {left:?} / {right:?}"
        );

        match left.intersection(right) {
            Some(intersection) => {
                assert!(left.overlaps(right), "intersection exists without overlap");
                assert!(intersection.first_seen() >= left.first_seen());
                assert!(intersection.first_seen() >= right.first_seen());
                assert!(intersection.last_seen() <= left.last_seen());
                assert!(intersection.last_seen() <= right.last_seen());
                assert!(intersection.first_seen() <= intersection.last_seen());
            }
            None => assert!(!left.overlaps(right), "overlap without an intersection"),
        }

        let maximum_gap = rng.range_u64(0, 1_000_000);
        assert_eq!(
            left.is_contiguous_with(right, maximum_gap),
            gap <= maximum_gap,
            "contiguity disagrees with the measured gap for {left:?} / {right:?}"
        );
    }
}

#[test]
fn prop_advancement_priority_is_monotonic_and_never_panics() {
    let mut rng = Rng::new(0x1357_9bdf_2468_ace0);
    for _ in 0..50_000 {
        let benefit = rng.range_u8(0, 100);
        let correctness = rng.range_u8(0, 100);
        let reachability = rng.range_u8(0, 100);
        let reversibility = rng.range_u8(0, 100);
        let cost = rng.range_u8(1, 100);
        let risk = rng.range_u8(1, 100);
        let base = AdvancementFactors::new(
            benefit,
            correctness,
            reachability,
            reversibility,
            cost,
            risk,
        )
        .unwrap();
        let _ = base.priority().scaled();

        let higher_benefit = benefit.saturating_add(rng.range_u8(0, 50)).min(100);
        let more_benefit = AdvancementFactors::new(
            higher_benefit,
            correctness,
            reachability,
            reversibility,
            cost,
            risk,
        )
        .unwrap();
        assert!(
            more_benefit.priority() >= base.priority(),
            "increasing expected net benefit from {benefit} to {higher_benefit} decreased priority"
        );

        let higher_cost = cost.saturating_add(rng.range_u8(0, 50)).min(100);
        let costlier = AdvancementFactors::new(
            benefit,
            correctness,
            reachability,
            reversibility,
            higher_cost,
            risk,
        )
        .unwrap();
        assert!(
            costlier.priority() <= base.priority(),
            "increasing implementation cost from {cost} to {higher_cost} increased priority"
        );
    }
}

#[test]
fn prop_search_priority_is_monotonic_and_never_panics() {
    let mut rng = Rng::new(0x2468_ace0_1357_9bdf);
    for _ in 0..50_000 {
        let gain = rng.range_u8(0, 100);
        let novelty = rng.range_u8(0, 100);
        let reachability = rng.range_u8(0, 100);
        let independence = rng.range_u8(0, 100);
        let provenance = rng.range_u8(0, 100);
        let cost = rng.range_u8(1, 100);
        let risk = rng.range_u8(1, 100);
        let base = SearchPriorityFactors::new(
            gain,
            novelty,
            reachability,
            independence,
            provenance,
            cost,
            risk,
        )
        .unwrap();
        let _ = base.priority().scaled();

        let higher_gain = gain.saturating_add(rng.range_u8(0, 50)).min(100);
        let more_gain = SearchPriorityFactors::new(
            higher_gain,
            novelty,
            reachability,
            independence,
            provenance,
            cost,
            risk,
        )
        .unwrap();
        assert!(
            more_gain.priority() >= base.priority(),
            "increasing expected information gain from {gain} to {higher_gain} decreased priority"
        );

        let higher_risk = risk.saturating_add(rng.range_u8(0, 50)).min(100);
        let riskier = SearchPriorityFactors::new(
            gain,
            novelty,
            reachability,
            independence,
            provenance,
            cost,
            higher_risk,
        )
        .unwrap();
        assert!(
            riskier.priority() <= base.priority(),
            "increasing failure risk from {risk} to {higher_risk} increased priority"
        );
    }
}

/// Nine calibrated dimensions used identically by the three quality types.
fn random_dimensions(rng: &mut Rng) -> [u8; 9] {
    [
        rng.range_u8(0, 255),
        rng.range_u8(0, 255),
        rng.range_u8(0, 255),
        rng.range_u8(0, 255),
        rng.range_u8(0, 255),
        rng.range_u8(0, 255),
        rng.range_u8(0, 255),
        rng.range_u8(0, 255),
        rng.range_u8(0, 255),
    ]
}

fn bump_one(dimensions: [u8; 9], index: usize, delta: u8) -> [u8; 9] {
    let mut bumped = dimensions;
    bumped[index] = bumped[index].saturating_add(delta);
    bumped
}

#[test]
fn prop_evidence_quality_calibrated_weight_is_bounded_and_monotonic() {
    let mut rng = Rng::new(0xdead_beef_cafe_f00d);
    for _ in 0..50_000 {
        let dimensions = random_dimensions(&mut rng);
        let quality = EvidenceQuality::new(
            dimensions[0],
            dimensions[1],
            dimensions[2],
            dimensions[3],
            dimensions[4],
            dimensions[5],
            dimensions[6],
            dimensions[7],
            dimensions[8],
        );
        let weight = quality.calibrated_weight();
        assert!(weight <= 100, "calibrated weight {weight} exceeds 100");

        let index = (rng.next_u64() % 9) as usize;
        let higher = bump_one(dimensions, index, rng.range_u8(0, 50));
        let higher_quality = EvidenceQuality::new(
            higher[0], higher[1], higher[2], higher[3], higher[4], higher[5], higher[6], higher[7],
            higher[8],
        );
        assert!(
            higher_quality.calibrated_weight() >= weight,
            "raising dimension {index} lowered the calibrated weight"
        );
    }
}

#[test]
fn prop_infrastructure_factors_calibrated_weight_is_bounded_and_monotonic() {
    let mut rng = Rng::new(0xbadc_0ffe_e0dd_f00d);
    for _ in 0..50_000 {
        let dimensions = random_dimensions(&mut rng);
        let factors = CorrelationFactors::new(
            dimensions[0],
            dimensions[1],
            dimensions[2],
            dimensions[3],
            dimensions[4],
            dimensions[5],
            dimensions[6],
            dimensions[7],
            dimensions[8],
        );
        let weight = factors.calibrated_weight();
        assert!(weight <= 100, "calibrated weight {weight} exceeds 100");

        let index = (rng.next_u64() % 9) as usize;
        let higher = bump_one(dimensions, index, rng.range_u8(0, 50));
        let higher_factors = CorrelationFactors::new(
            higher[0], higher[1], higher[2], higher[3], higher[4], higher[5], higher[6], higher[7],
            higher[8],
        );
        assert!(
            higher_factors.calibrated_weight() >= weight,
            "raising dimension {index} lowered the calibrated weight"
        );
    }
}

#[test]
fn prop_website_factors_calibrated_weight_is_bounded_and_monotonic() {
    let mut rng = Rng::new(0x1234_5678_9abc_def0);
    for _ in 0..50_000 {
        let dimensions = random_dimensions(&mut rng);
        let factors = WebsiteFactors::new(
            dimensions[0],
            dimensions[1],
            dimensions[2],
            dimensions[3],
            dimensions[4],
            dimensions[5],
            dimensions[6],
            dimensions[7],
            dimensions[8],
        );
        let weight = factors.calibrated_weight();
        assert!(weight <= 100, "calibrated weight {weight} exceeds 100");

        let index = (rng.next_u64() % 9) as usize;
        let higher = bump_one(dimensions, index, rng.range_u8(0, 50));
        let higher_factors = WebsiteFactors::new(
            higher[0], higher[1], higher[2], higher[3], higher[4], higher[5], higher[6], higher[7],
            higher[8],
        );
        assert!(
            higher_factors.calibrated_weight() >= weight,
            "raising dimension {index} lowered the calibrated weight"
        );
    }
}
