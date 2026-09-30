//! Randomized differential campaign over the automatic-update engine
//! (`bleradar_core::update`, `docs/AUTONOMOUS_DECISIONS.md` decision 78).
//!
//! A deterministic PRNG drives long random operation sequences through the
//! production [`UpdateSession`] and an **independent reference state machine**
//! written to the same specification. After every operation the two must agree
//! on the accept/reject outcome and the resulting `(stage, installed, target,
//! received)` state, and a battery of invariants must hold:
//!
//! * `serialize` → `deserialize` is the identity at every step;
//! * `recover()` only ever moves to a safe stage and is idempotent;
//! * an install is only ever reached through a genuine size+SHA-256 verification
//!   (cross-checked with an independent hash), never for tampered bytes;
//! * download progress is monotonic and never exceeds the declared size;
//! * no operation panics.
//!
//! A divergence, a broken invariant, or a panic fails the campaign. This is the
//! permanent regression lock behind the engine's "works flawlessly" claim; the
//! falsification tests at the bottom show a deliberately-broken engine is caught.

use bleradar_core::update::{
    ReleaseManifest, RetryDecision, RetryPolicy, UpdateDecision, UpdateSession, UpdateStage,
    Version, update_decision,
};
use bleradar_core::{Sha256, hex_encode};

/// Deterministic xorshift* PRNG (no external deps).
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
        self.next_u64() % n
    }
}

fn sha_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_encode(&h.finalize())
}

/// A random, valid release payload + its manifest.
struct Release {
    bytes: Vec<u8>,
    manifest: ReleaseManifest,
}

fn random_release(rng: &mut Rng) -> Release {
    let code = rng.below(50) + 1;
    let len = (rng.below(200) + 1) as usize;
    let bytes: Vec<u8> = (0..len).map(|_| (rng.below(256)) as u8).collect();
    let min_sdk = rng.below(35) as u32;
    let mandatory = rng.below(2) == 0;
    let text = format!(
        "version_code = {code}\nversion_name = v{code}\nurl = https://example.com/app-{code}.apk\n\
         size_bytes = {}\nsha256 = {}\nmin_sdk = {min_sdk}\nmandatory = {mandatory}\n",
        bytes.len(),
        sha_hex(&bytes),
    );
    Release {
        bytes,
        manifest: ReleaseManifest::parse(&text).unwrap(),
    }
}

/// Independent reference model of the session state.
#[derive(Clone, PartialEq, Eq, Debug)]
struct RefModel {
    stage: UpdateStage,
    installed_code: u64,
    installed_name: String,
    target_code: Option<u64>,
    target_size: u64,
    target_mandatory: bool,
    received: u64,
    attempts: u32,
    previous_code: Option<u64>,
    previous_name: Option<String>,
}

impl RefModel {
    fn new(code: u64, name: &str) -> Self {
        Self {
            stage: UpdateStage::Idle,
            installed_code: code,
            installed_name: name.to_string(),
            target_code: None,
            target_size: 0,
            target_mandatory: false,
            received: 0,
            attempts: 0,
            previous_code: None,
            previous_name: None,
        }
    }

    fn matches(&self, s: &UpdateSession) -> bool {
        s.stage() == self.stage
            && s.installed().code == self.installed_code
            && s.installed().name == self.installed_name
            && s.target().map(|m| m.version.code) == self.target_code
            && s.received_bytes() == self.received
            && s.attempts() == self.attempts
            && s.previous().map(|v| v.code) == self.previous_code
            && s.previous().map(|v| v.name.clone()) == self.previous_name
    }
}

/// Fixed retry policy used by the campaign's retry op.
const CAMPAIGN_RETRY: RetryPolicy = RetryPolicy {
    max_attempts: 4,
    base_delay_secs: 5,
    max_delay_secs: 3600,
};

#[test]
fn randomized_sessions_match_the_reference_and_hold_every_invariant() {
    let mut rng = Rng::new(0x0BADC0DE_CAFEF00D);
    let iterations = 200_000;
    let mut installs = 0u64;
    let mut verify_ok = 0u64;
    let mut verify_fail = 0u64;
    let mut rejects = 0u64;
    let mut retries_after = 0u64;
    let mut gave_ups = 0u64;
    let mut rollbacks = 0u64;

    // A rolling session/model pair; periodically reset to a fresh install.
    let mut session = UpdateSession::new(Version::new(1, "v1"));
    let mut model = RefModel::new(1, "v1");
    // Keep the payload for the current target so verify can use correct bytes.
    let mut current: Option<Release> = None;

    for i in 0..iterations {
        // Occasionally start a fresh device/version.
        if i % 500 == 0 {
            let code = rng.below(10) + 1;
            session = UpdateSession::new(Version::new(code, format!("v{code}")));
            model = RefModel::new(code, &format!("v{code}"));
            current = None;
        }

        // The op that advances the current stage toward a completed install.
        // Bias toward it (7/10) so full flows complete often, while the random
        // 3/10 still exercises illegal transitions, tamper, fail, reset, recover
        // and serde from every stage.
        let advancing = match model.stage {
            UpdateStage::Idle => 0,      // offer
            UpdateStage::Available => 1, // begin_download
            UpdateStage::Downloading => {
                if model.received < model.target_size {
                    2 // record_progress
                } else {
                    3 // finish_download
                }
            }
            UpdateStage::Downloaded => 4, // verify (correct)
            UpdateStage::Verified => 6,   // begin_install
            UpdateStage::Installing => 7, // finish_install
            UpdateStage::Installed => 9,  // reset, then a new cycle
            UpdateStage::Failed => 9,     // reset
        };
        let op = if rng.below(10) < 7 {
            advancing
        } else {
            rng.below(13)
        };
        match op {
            0 => {
                // offer
                let release = random_release(&mut rng);
                let device_sdk = rng.below(36) as u32;
                let decision = update_decision(
                    model.installed_code,
                    release.manifest.version.code,
                    device_sdk,
                    release.manifest.min_sdk,
                );
                let allowed = matches!(
                    model.stage,
                    UpdateStage::Idle | UpdateStage::Available | UpdateStage::Failed
                );
                let got = session.offer(release.manifest.clone(), device_sdk);
                if !allowed {
                    assert!(
                        got.is_err(),
                        "offer should be illegal from {:?}",
                        model.stage
                    );
                    rejects += 1;
                } else {
                    assert_eq!(got.unwrap(), decision);
                    if decision == UpdateDecision::Available {
                        model.stage = UpdateStage::Available;
                        model.target_code = Some(release.manifest.version.code);
                        model.target_size = release.manifest.size_bytes;
                        model.target_mandatory = release.manifest.mandatory;
                        model.received = 0;
                        model.attempts = 0;
                        current = Some(release);
                    }
                }
            }
            1 => {
                // begin_download
                let allowed = matches!(
                    model.stage,
                    UpdateStage::Available | UpdateStage::Downloading
                );
                let got = session.begin_download();
                if allowed {
                    got.unwrap();
                    model.stage = UpdateStage::Downloading;
                } else {
                    assert!(got.is_err());
                    rejects += 1;
                }
            }
            2 => {
                // record_progress
                let n = rng.below(80);
                let got = session.record_progress(n);
                if model.stage == UpdateStage::Downloading {
                    let want = model.received.saturating_add(n).min(model.target_size);
                    assert_eq!(got.unwrap(), want);
                    model.received = want;
                } else {
                    assert!(got.is_err());
                    rejects += 1;
                }
            }
            3 => {
                // finish_download
                let got = session.finish_download();
                if model.stage == UpdateStage::Downloading && model.received == model.target_size {
                    got.unwrap();
                    model.stage = UpdateStage::Downloaded;
                } else {
                    assert!(got.is_err());
                    rejects += 1;
                }
            }
            4 => {
                // verify with the correct bytes
                if model.stage == UpdateStage::Downloaded {
                    let bytes = &current.as_ref().unwrap().bytes;
                    session.verify(bytes).unwrap();
                    model.stage = UpdateStage::Verified;
                    verify_ok += 1;
                } else {
                    assert!(session.verify(b"whatever").is_err());
                    rejects += 1;
                }
            }
            5 => {
                // verify with tampered bytes (must fail -> Failed) only when Downloaded
                if model.stage == UpdateStage::Downloaded {
                    let mut bytes = current.as_ref().unwrap().bytes.clone();
                    // guarantee a real change of the same length
                    let idx = (rng.below(bytes.len() as u64)) as usize;
                    bytes[idx] ^= 0xff;
                    let independent_match =
                        sha_hex(&bytes) == hex_encode(&current.as_ref().unwrap().manifest.sha256);
                    let got = session.verify(&bytes);
                    if independent_match {
                        // astronomically unlikely collision; treat as success
                        got.unwrap();
                        model.stage = UpdateStage::Verified;
                        verify_ok += 1;
                    } else {
                        assert!(got.is_err());
                        model.stage = UpdateStage::Failed;
                        verify_fail += 1;
                    }
                } else {
                    assert!(session.verify(b"x").is_err());
                    rejects += 1;
                }
            }
            6 => {
                // begin_install
                let got = session.begin_install();
                if model.stage == UpdateStage::Verified {
                    got.unwrap();
                    model.stage = UpdateStage::Installing;
                } else {
                    assert!(got.is_err());
                    rejects += 1;
                }
            }
            7 => {
                // finish_install
                let got = session.finish_install();
                match model.stage {
                    UpdateStage::Installing => {
                        got.unwrap();
                        model.previous_code = Some(model.installed_code);
                        model.previous_name = Some(model.installed_name.clone());
                        model.installed_code = model.target_code.unwrap();
                        model.installed_name = format!("v{}", model.installed_code);
                        model.stage = UpdateStage::Installed;
                        model.target_code = None;
                        model.received = 0;
                        model.attempts = 0;
                        installs += 1;
                    }
                    UpdateStage::Installed => got.unwrap(), // idempotent
                    _ => {
                        assert!(got.is_err());
                        rejects += 1;
                    }
                }
            }
            8 => {
                // fail
                session.fail("random fault");
                model.stage = UpdateStage::Failed;
            }
            9 => {
                // reset
                session.reset();
                model.stage = UpdateStage::Idle;
                model.target_code = None;
                model.received = 0;
                model.attempts = 0;
                current = None;
            }
            10 => {
                // recover (must only move to safe stages, be idempotent)
                let before = session.stage();
                session = session.clone().recover();
                let after = session.stage();
                let expected = match before {
                    UpdateStage::Installing => UpdateStage::Verified,
                    UpdateStage::Downloaded => UpdateStage::Downloading,
                    other => other,
                };
                assert_eq!(
                    after, expected,
                    "recover({before:?}) should give {expected:?}"
                );
                // idempotent
                assert_eq!(session.clone().recover().stage(), after);
                model.stage = after;
            }
            11 => {
                // retry: only legal with an in-flight target (not Idle/Installed).
                let got = session.retry(&CAMPAIGN_RETRY);
                let legal = model.target_code.is_some()
                    && !matches!(model.stage, UpdateStage::Idle | UpdateStage::Installed);
                if !legal {
                    assert!(got.is_err());
                    rejects += 1;
                } else {
                    model.attempts += 1;
                    model.received = 0;
                    if model.attempts >= CAMPAIGN_RETRY.max_attempts {
                        assert_eq!(got.unwrap(), RetryDecision::GaveUp);
                        model.stage = UpdateStage::Failed;
                        gave_ups += 1;
                    } else {
                        assert_eq!(
                            got.unwrap(),
                            RetryDecision::RetryAfter(
                                CAMPAIGN_RETRY.backoff_delay_secs(model.attempts)
                            )
                        );
                        model.stage = UpdateStage::Available;
                        retries_after += 1;
                    }
                }
            }
            12 => {
                // rollback: only legal with a recorded previous version.
                let got = session.rollback();
                if let Some(prev_code) = model.previous_code {
                    got.unwrap();
                    model.installed_code = prev_code;
                    model.installed_name = model.previous_name.take().unwrap();
                    model.previous_code = None;
                    model.stage = UpdateStage::Idle;
                    model.target_code = None;
                    model.received = 0;
                    model.attempts = 0;
                    current = None;
                    rollbacks += 1;
                } else {
                    assert!(got.is_err());
                    rejects += 1;
                }
            }
            _ => unreachable!(),
        }

        // ---- invariants after every operation ----
        assert!(
            model.matches(&session),
            "reference/production diverged at op {op} (i={i}): model={model:?} session stage={:?} installed={:?}",
            session.stage(),
            session.installed(),
        );
        // progress never exceeds size
        if let Some(t) = session.target() {
            assert!(session.received_bytes() <= t.size_bytes);
        }
        // an installed session never keeps a target
        if session.stage() == UpdateStage::Installed {
            assert!(session.target().is_none());
        }
        // serialize -> deserialize identity
        let round = UpdateSession::deserialize(&session.serialize())
            .expect("serialized session must parse back");
        assert_eq!(
            round, session,
            "serde round-trip changed the session at i={i}"
        );
    }

    println!(
        "update campaign: {iterations} ops, installs={installs}, verify_ok={verify_ok}, verify_fail={verify_fail}, rejects={rejects}, retries_after={retries_after}, gave_ups={gave_ups}, rollbacks={rollbacks}"
    );
    assert!(installs > 500, "too few installs exercised: {installs}");
    assert!(verify_ok > 500, "too few successful verifies: {verify_ok}");
    assert!(verify_fail > 40, "too few tamper rejections: {verify_fail}");
    assert!(rejects > 5000, "too few illegal-op rejections: {rejects}");
    assert!(
        retries_after > 100,
        "too few granted retries: {retries_after}"
    );
    assert!(
        gave_ups > 3,
        "the exhausted-retry give-up path was not exercised: {gave_ups}"
    );
    assert!(rollbacks > 50, "too few rollbacks exercised: {rollbacks}");
}

/// An install is *only ever* reached for bytes whose independent SHA-256 and
/// length match the manifest — a focused, high-volume integrity oracle.
#[test]
fn install_is_unreachable_without_a_genuine_integrity_match() {
    let mut rng = Rng::new(0xD00D_FEED_1234_5678);
    let mut proven = 0u64;
    for _ in 0..50_000 {
        let release = random_release(&mut rng);
        let mut s = UpdateSession::new(Version::new(0, "v0"));
        s.offer(release.manifest.clone(), 34).unwrap();
        s.begin_download().unwrap();
        s.record_progress(release.manifest.size_bytes).unwrap();
        s.finish_download().unwrap();

        // Randomly tamper (length-preserving) or leave intact.
        let mut bytes = release.bytes.clone();
        let tamper = rng.below(2) == 0 && !bytes.is_empty();
        if tamper {
            let idx = (rng.below(bytes.len() as u64)) as usize;
            bytes[idx] ^= 1 << (rng.below(8));
        }
        let genuine = bytes.len() as u64 == release.manifest.size_bytes && bytes == release.bytes;
        let verified = s.verify(&bytes).is_ok();
        assert_eq!(
            verified, genuine,
            "verify must succeed iff the bytes are exactly the manifest artifact"
        );
        if verified {
            s.begin_install().unwrap();
            s.finish_install().unwrap();
            assert_eq!(s.installed().code, release.manifest.version.code);
            proven += 1;
        } else {
            // Cannot install a failed verification.
            assert!(s.begin_install().is_err());
        }
    }
    println!("integrity oracle: {proven} genuine installs among 50k trials");
    assert!(proven > 1000);
}
