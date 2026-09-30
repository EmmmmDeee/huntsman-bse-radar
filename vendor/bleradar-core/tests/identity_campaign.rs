//! Randomized property campaign over the rotating-address identity resolver
//! (`bleradar_core::resolve`).
//!
//! A deterministic PRNG builds random advertisements and addresses, turns them
//! into [`DeviceIdentity`] values, and asserts the resolver's invariants over
//! hundreds of thousands of pairs:
//!
//! * **no panic** on any input;
//! * **symmetry** — the verdict does not depend on argument order;
//! * **reflexivity** — an identity never reads as `LikelyDifferent` from itself;
//! * **verdict/evidence coherence** — `LikelyDifferent` if and only if the
//!   contradiction set is non-empty (every "different" verdict records why);
//! * **never certain from a randomized address** — `LikelySame` requires both
//!   addresses to be the same public (globally administered) address;
//! * **correlation implies correlation** — two identities that share a non-`None`
//!   correlation id are at least `PossiblySame`, never different or insufficient.
//!
//! The falsification test at the end forges a mutant's `LikelySame` verdict for
//! a matching randomized pair and shows the invariant checker rejects it.

use bleradar_core::{
    AddressKind, DeviceIdentity, IdentityEvidence, IdentityMatch, MatchVerdict, adv, canonical_mac,
    resolve,
};

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
}

/// A random address whose first octet's U/L bit is set (randomized) or clear
/// (public) as requested, so the campaign controls the address kind it tests.
fn address(rng: &mut Rng, randomized: bool) -> String {
    let mut first = rng.byte();
    if randomized {
        first |= 0x02;
    } else {
        first &= !0x02;
    }
    let rest: [u8; 5] = [rng.byte(), rng.byte(), rng.byte(), rng.byte(), rng.byte()];
    let hex: String = core::iter::once(first)
        .chain(rest)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    canonical_mac(&hex).expect("valid mac")
}

/// A random advertisement drawn from a small pool of building blocks, so
/// collisions (the same evidence under two addresses) happen often enough to
/// exercise the correlation paths.
fn advert(rng: &mut Rng) -> Vec<u8> {
    const COMPANIES: [u16; 4] = [0x004C, 0x0059, 0x0006, 0xFFFF];
    const NAMES: [&str; 4] = ["", "Tag", "Widget", "Beacon"];
    let mut v = vec![0x02, 0x01, 0x06];
    if rng.below(4) != 0 {
        let company = COMPANIES[rng.below(4) as usize];
        let data_len = rng.below(6) as usize;
        let mut p = company.to_le_bytes().to_vec();
        for _ in 0..data_len {
            p.push((rng.below(3)) as u8); // small alphabet → frequent collisions
        }
        v.push(u8::try_from(p.len() + 1).unwrap());
        v.push(0xFF);
        v.extend_from_slice(&p);
    }
    let name = NAMES[rng.below(4) as usize];
    if !name.is_empty() {
        v.push(u8::try_from(name.len() + 1).unwrap());
        v.push(0x09);
        v.extend_from_slice(name.as_bytes());
    }
    let n_services = rng.below(3) as usize;
    if n_services > 0 {
        v.push(u8::try_from(n_services * 2 + 1).unwrap());
        v.push(0x03);
        for _ in 0..n_services {
            let uuid = 0x1800u16 + rng.below(4) as u16;
            v.extend_from_slice(&uuid.to_le_bytes());
        }
    }
    v
}

fn make(rng: &mut Rng) -> DeviceIdentity {
    let randomized = rng.below(2) == 0;
    let report = adv::decode(&advert(rng));
    let evidence = IdentityEvidence::from_advertisement(&report, None);
    DeviceIdentity::new(&address(rng, randomized), evidence).expect("valid identity")
}

fn check_pair(a: &DeviceIdentity, b: &DeviceIdentity) -> Result<(), String> {
    check_match(a, b, &resolve(a, b), &resolve(b, a), resolve(a, a).verdict)
}

/// Every invariant over the verdicts `ab`, `ba` and `self_match` a resolver
/// gave for `a`/`b` — separate from [`resolve`] so a forged (mutant) verdict
/// can be shown to fail it.
fn check_match(
    a: &DeviceIdentity,
    b: &DeviceIdentity,
    ab: &IdentityMatch,
    ba: &IdentityMatch,
    self_match: MatchVerdict,
) -> Result<(), String> {
    if ab.verdict != ba.verdict {
        return Err(format!(
            "asymmetric: {:?} vs {:?}\n  a={a:?}\n  b={b:?}",
            ab.verdict, ba.verdict
        ));
    }
    // Verdict/evidence coherence, both directions: every LikelyDifferent
    // records why (a field contradiction or different public addresses).
    if ab.contradictions.is_empty() == (ab.verdict == MatchVerdict::LikelyDifferent) {
        return Err(format!(
            "verdict {:?} incoherent with contradictions: {ab:?}",
            ab.verdict
        ));
    }
    // Never certain from a randomized address.
    if ab.verdict == MatchVerdict::LikelySame
        && !(a.address == b.address
            && a.address_kind == AddressKind::Public
            && b.address_kind == AddressKind::Public)
    {
        return Err(format!(
            "LikelySame without a shared public address:\n  a={a:?}\n  b={b:?}"
        ));
    }
    // Correlation implies at least PossiblySame — EXCEPT when both addresses are
    // public, where the stable hardware address is authoritative and two units
    // of the same model (identical evidence, different public MACs) are
    // correctly different. correlation_id groups rotating addresses; a public
    // address overrides that grouping.
    let (ca, cb) = (a.evidence.correlation_id(), b.evidence.correlation_id());
    let both_public =
        a.address_kind == AddressKind::Public && b.address_kind == AddressKind::Public;
    if ca.is_some() && ca == cb && !both_public {
        match ab.verdict {
            MatchVerdict::PossiblySame | MatchVerdict::LikelySame => {}
            other => {
                return Err(format!(
                    "shared correlation id {ca:?} but verdict {other:?}:\n  a={a:?}\n  b={b:?}"
                ));
            }
        }
    }
    // Reflexivity: an identity is never different from itself.
    if self_match == MatchVerdict::LikelyDifferent {
        return Err(format!("identity differs from itself: {a:?}"));
    }
    Ok(())
}

#[test]
fn resolver_invariants_hold_over_random_pairs() {
    const ITERATIONS: u64 = 300_000;
    let mut rng = Rng::new(0x1DEA_5EED_0000_0001);
    let mut counts = [0u64; 4];
    for _ in 0..ITERATIONS {
        let a = make(&mut rng);
        let mut b = make(&mut rng);
        // Two independently random addresses never collide, so a same-address
        // pair (the hardware-match and same-RPA paths) would otherwise go
        // untested: reuse a's address for one pair in six, keeping b's own
        // evidence (a device re-observed under the same address).
        if rng.below(6) == 0 {
            b = DeviceIdentity {
                address: a.address.clone(),
                address_kind: a.address_kind,
                evidence: b.evidence.clone(),
            };
        }
        let verdict = resolve(&a, &b).verdict;
        counts[match verdict {
            MatchVerdict::InsufficientEvidence => 0,
            MatchVerdict::LikelyDifferent => 1,
            MatchVerdict::PossiblySame => 2,
            MatchVerdict::LikelySame => 3,
        }] += 1;
        check_pair(&a, &b).expect("invariants hold");
    }
    // Every verdict must actually occur, or the campaign is not exercising the
    // resolver's whole decision surface.
    assert!(
        counts.iter().all(|&c| c > 100),
        "verdict coverage: {counts:?}"
    );
}

#[test]
fn falsification_certainty_from_a_randomized_address_is_caught() {
    // Two rotating addresses with identical distinctive evidence: the resolver
    // must call this PossiblySame, never LikelySame. A mutant that returned
    // LikelySame would violate the "never certain from a randomized address"
    // invariant check_pair enforces.
    let report = adv::decode(&[
        0x02, 0x01, 0x06, 0x05, 0xFF, 0x4C, 0x00, 0x01, 0x02, 0x03, 0x03, 0x0D, 0x18,
    ]);
    let ev = IdentityEvidence::from_advertisement(&report, Some("Tag"));
    let a = DeviceIdentity::new("42:11:22:33:44:55", ev.clone()).unwrap();
    let b = DeviceIdentity::new("7e:aa:bb:cc:dd:ee", ev).unwrap();
    assert_eq!(resolve(&a, &b).verdict, MatchVerdict::PossiblySame);
    check_pair(&a, &b).expect("the honest verdict passes the invariants");
    let self_match = resolve(&a, &a).verdict;
    let forged = IdentityMatch {
        verdict: MatchVerdict::LikelySame,
        ..resolve(&a, &b)
    };
    let err = check_match(&a, &b, &forged, &forged, self_match)
        .expect_err("a mutant's LikelySame from randomized addresses is rejected");
    assert!(
        err.contains("LikelySame without a shared public address"),
        "{err}"
    );
    // A mutant whose verdict depends on argument order is rejected too.
    let err = check_match(&a, &b, &resolve(&a, &b), &forged, self_match)
        .expect_err("an asymmetric mutant is rejected");
    assert!(err.starts_with("asymmetric"), "{err}");
}
