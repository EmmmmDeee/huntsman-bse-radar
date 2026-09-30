//! Unit and invariant tests for the automatic-update engine
//! (`bleradar_core::update`, `docs/AUTONOMOUS_DECISIONS.md` decision 78).
//!
//! These lock every decision rule, integrity check, state transition, and the
//! restart/recovery behaviour. `tests/update_campaign.rs` exercises the same
//! surface over randomized sequences with independent oracles.

use bleradar_core::update::{
    ArtifactVerifier, DownloadConditions, DownloadPolicy, DownloadReadiness, ManifestFetchFailure,
    ManifestSourceDecision, NetworkType, ReleaseManifest, RetryDecision, RetryPolicy,
    UpdateDecision, UpdateError, UpdateSession, UpdateStage, Version, check_update,
    download_readiness, manifest_source_decision, should_check_for_update, update_decision,
    verify_artifact,
};
use bleradar_core::{Sha256, hex_encode};

/// Builds a manifest string whose `sha256` is the real digest of `bytes`.
fn manifest_text(code: u64, name: &str, bytes: &[u8], min_sdk: u32, mandatory: bool) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let hex = hex_encode(&h.finalize());
    format!(
        "version_code = {code}\nversion_name = {name}\nurl = https://example.com/app-{name}.apk\n\
         size_bytes = {}\nsha256 = {hex}\nmin_sdk = {min_sdk}\nmandatory = {mandatory}\n",
        bytes.len()
    )
}

fn manifest(code: u64, name: &str, bytes: &[u8], min_sdk: u32, mandatory: bool) -> ReleaseManifest {
    ReleaseManifest::parse(&manifest_text(code, name, bytes, min_sdk, mandatory)).unwrap()
}

// ---- decision rules ----

#[test]
fn update_decision_covers_every_outcome_and_boundaries() {
    assert_eq!(update_decision(41, 42, 34, 26), UpdateDecision::Available);
    assert_eq!(update_decision(42, 42, 34, 26), UpdateDecision::UpToDate);
    assert_eq!(
        update_decision(42, 41, 34, 26),
        UpdateDecision::DowngradeRefused
    );
    assert_eq!(
        update_decision(41, 42, 25, 26),
        UpdateDecision::IncompatibleOs
    );
    // device_sdk == min_sdk is compatible.
    assert_eq!(update_decision(41, 42, 26, 26), UpdateDecision::Available);
    // A downgrade is refused even on an incompatible OS (downgrade dominates).
    assert_eq!(
        update_decision(42, 41, 10, 26),
        UpdateDecision::DowngradeRefused
    );
}

#[test]
fn decision_ordinals_round_trip() {
    for d in [
        UpdateDecision::UpToDate,
        UpdateDecision::Available,
        UpdateDecision::DowngradeRefused,
        UpdateDecision::IncompatibleOs,
    ] {
        assert_eq!(UpdateDecision::from_ordinal(d.ordinal()), Some(d));
    }
    assert_eq!(UpdateDecision::from_ordinal(4), None);
    assert_eq!(UpdateDecision::from_ordinal(-1), None);
    assert!(UpdateDecision::Available.is_available());
    assert!(!UpdateDecision::UpToDate.is_available());
}

#[test]
fn check_update_matches_the_numeric_core() {
    let m = manifest(42, "1.2.3", b"payload!!", 26, false);
    assert_eq!(
        check_update(&Version::new(41, "1.2.2"), 34, &m),
        UpdateDecision::Available
    );
    assert_eq!(
        check_update(&Version::new(42, "1.2.3"), 34, &m),
        UpdateDecision::UpToDate
    );
    assert_eq!(
        check_update(&Version::new(41, "1.2.2"), 21, &m),
        UpdateDecision::IncompatibleOs
    );
}

// ---- manifest parsing ----

#[test]
fn manifest_round_trips_through_serialize() {
    let original = manifest(7, "0.7.0", b"the-apk-bytes", 24, true);
    let reparsed = ReleaseManifest::parse(&original.serialize()).unwrap();
    assert_eq!(original, reparsed);
}

#[test]
fn manifest_ignores_comments_and_blank_lines_and_reads_notes() {
    let text = format!(
        "# release channel: stable\n\n{}\nnotes = Fixes a crash on rotate = really\n",
        manifest_text(9, "9", b"x", 21, false).trim_end()
    );
    let m = ReleaseManifest::parse(&text).unwrap();
    assert_eq!(m.version, Version::new(9, "9"));
    // The value keeps everything after the first `=`.
    assert_eq!(m.notes, "Fixes a crash on rotate = really");
}

#[test]
fn manifest_rejects_each_missing_required_field() {
    let full = manifest_text(1, "1", b"z", 21, false);
    for key in [
        "version_code",
        "version_name",
        "url",
        "size_bytes",
        "sha256",
        "min_sdk",
        "mandatory",
    ] {
        let stripped: String = full
            .lines()
            .filter(|l| !l.starts_with(key))
            .collect::<Vec<_>>()
            .join("\n");
        let err = ReleaseManifest::parse(&stripped).unwrap_err();
        assert!(
            matches!(err, UpdateError::MissingField(k) if k == key),
            "removing {key} should be MissingField, got {err:?}"
        );
    }
}

#[test]
fn the_bundled_release_manifest_is_accepted_by_the_parser() {
    // The offline fallback the app ships (`assets/release_manifest.txt`) is
    // what this parser reads on every check the remote source cannot serve;
    // a bundled text the parser refused would leave a device with no manifest
    // at all. `cargo xtask check-app-version` holds its version to the
    // build's; this holds its parseability to the parser itself.
    let text = include_str!("../../../android/app/src/main/assets/release_manifest.txt");
    let manifest = ReleaseManifest::parse(text).expect("the bundled release manifest must parse");
    assert!(!manifest.version.name.is_empty());
    assert_eq!(
        ReleaseManifest::parse(&manifest.serialize()).unwrap(),
        manifest
    );
}

#[test]
fn manifest_rejects_duplicate_unknown_and_malformed() {
    let base = manifest_text(1, "1", b"z", 21, false);
    assert!(matches!(
        ReleaseManifest::parse(&format!("{base}min_sdk = 30\n")).unwrap_err(),
        UpdateError::DuplicateField("min_sdk")
    ));
    assert!(matches!(
        ReleaseManifest::parse(&format!("{base}channel = beta\n")).unwrap_err(),
        UpdateError::UnknownField(k) if k == "channel"
    ));
    assert!(matches!(
        ReleaseManifest::parse("version_code 1\n").unwrap_err(),
        UpdateError::MalformedLine(_)
    ));
    assert!(matches!(
        ReleaseManifest::parse(&base.replace("version_code = 1", "version_code = ten"))
            .unwrap_err(),
        UpdateError::MalformedField {
            key: "version_code",
            ..
        }
    ));
    assert!(matches!(
        ReleaseManifest::parse(&base.replace("mandatory = false", "mandatory = maybe"))
            .unwrap_err(),
        UpdateError::MalformedField {
            key: "mandatory",
            ..
        }
    ));
}

#[test]
fn manifest_enforces_https_nonzero_size_and_hex_hash() {
    let base = manifest_text(1, "1", b"z", 21, false);
    assert!(matches!(
        ReleaseManifest::parse(&base.replace("https://", "http://")).unwrap_err(),
        UpdateError::InsecureUrl
    ));
    assert!(matches!(
        ReleaseManifest::parse(&base.replace("size_bytes = 1", "size_bytes = 0")).unwrap_err(),
        UpdateError::EmptyArtifact
    ));
    // wrong length
    assert!(matches!(
        ReleaseManifest::parse(&base.replace(
            &hex_encode(&{
                let mut h = Sha256::new();
                h.update(b"z");
                h.finalize()
            }),
            "abcd"
        ))
        .unwrap_err(),
        UpdateError::MalformedField { key: "sha256", .. }
    ));
    // non-hex character in an otherwise 64-char field
    let bad_hash = "g".repeat(64);
    let good_hash = hex_encode(&{
        let mut h = Sha256::new();
        h.update(b"z");
        h.finalize()
    });
    assert!(matches!(
        ReleaseManifest::parse(&base.replace(&good_hash, &bad_hash)).unwrap_err(),
        UpdateError::MalformedField { key: "sha256", .. }
    ));
}

// ---- artifact integrity ----

#[test]
fn verify_artifact_accepts_the_exact_bytes_and_rejects_tampering() {
    let bytes = b"the-real-artifact-contents";
    let m = manifest(3, "3", bytes, 21, false);
    assert!(verify_artifact(bytes, &m).is_ok());

    // one flipped byte
    let mut tampered = bytes.to_vec();
    tampered[5] ^= 0x01;
    assert!(matches!(
        verify_artifact(&tampered, &m).unwrap_err(),
        UpdateError::HashMismatch
    ));
    // short
    assert!(matches!(
        verify_artifact(&bytes[..bytes.len() - 1], &m).unwrap_err(),
        UpdateError::SizeMismatch { .. }
    ));
    // long
    let mut longer = bytes.to_vec();
    longer.push(b'!');
    assert!(matches!(
        verify_artifact(&longer, &m).unwrap_err(),
        UpdateError::SizeMismatch { .. }
    ));
}

#[test]
fn streaming_verifier_matches_one_shot_and_rejects_overrun() {
    let bytes: Vec<u8> = (0..=250u8).cycle().take(4096).collect();
    let m = manifest(4, "4", &bytes, 21, false);

    let mut v = ArtifactVerifier::new(&m);
    for chunk in bytes.chunks(97) {
        v.feed(chunk).unwrap();
    }
    assert_eq!(v.received(), bytes.len() as u64);
    assert!(v.finish().is_ok());

    // Overrun is rejected mid-stream, before the extra bytes are hashed.
    let mut v = ArtifactVerifier::new(&m);
    v.feed(&bytes).unwrap();
    assert!(matches!(
        v.feed(b"extra").unwrap_err(),
        UpdateError::Overrun { .. }
    ));

    // Fewer bytes than declared -> SizeMismatch at finish.
    let mut v = ArtifactVerifier::new(&m);
    v.feed(&bytes[..100]).unwrap();
    assert!(matches!(
        v.finish().unwrap_err(),
        UpdateError::SizeMismatch { .. }
    ));
}

// ---- session lifecycle ----

fn drive_happy_path(bytes: &[u8]) -> UpdateSession {
    let mut s = UpdateSession::new(Version::new(41, "1.2.2"));
    let m = manifest(42, "1.2.3", bytes, 26, false);
    assert_eq!(s.offer(m, 34).unwrap(), UpdateDecision::Available);
    assert_eq!(s.stage(), UpdateStage::Available);
    s.begin_download().unwrap();
    for chunk in bytes.chunks(8).map(<[u8]>::len) {
        s.record_progress(chunk as u64).unwrap();
    }
    s.finish_download().unwrap();
    assert_eq!(s.stage(), UpdateStage::Downloaded);
    s.verify(bytes).unwrap();
    assert_eq!(s.stage(), UpdateStage::Verified);
    s.begin_install().unwrap();
    s.finish_install().unwrap();
    s
}

#[test]
fn happy_path_installs_and_adopts_the_new_version() {
    let bytes = b"a realistic apk payload of some length........";
    let s = drive_happy_path(bytes);
    assert_eq!(s.stage(), UpdateStage::Installed);
    assert_eq!(s.installed(), &Version::new(42, "1.2.3"));
    assert_eq!(s.target(), None);
    assert_eq!(s.received_bytes(), 0);
}

#[test]
fn offer_that_is_not_available_does_not_advance() {
    let mut s = UpdateSession::new(Version::new(42, "1.2.3"));
    // same version -> UpToDate, stays Idle
    let m = manifest(42, "1.2.3", b"x", 26, false);
    assert_eq!(s.offer(m, 34).unwrap(), UpdateDecision::UpToDate);
    assert_eq!(s.stage(), UpdateStage::Idle);
    assert_eq!(s.target(), None);
    // downgrade -> refused, stays Idle
    let older = manifest(41, "1.2.2", b"x", 26, false);
    assert_eq!(
        s.offer(older, 34).unwrap(),
        UpdateDecision::DowngradeRefused
    );
    assert_eq!(s.stage(), UpdateStage::Idle);
    // incompatible OS -> stays Idle
    let newer = manifest(43, "1.3.0", b"x", 99, false);
    assert_eq!(s.offer(newer, 34).unwrap(), UpdateDecision::IncompatibleOs);
    assert_eq!(s.stage(), UpdateStage::Idle);
}

#[test]
fn illegal_transitions_are_errors_not_panics() {
    let mut s = UpdateSession::new(Version::new(1, "1"));
    // From Idle: cannot download/verify/install.
    assert!(matches!(
        s.begin_download().unwrap_err(),
        UpdateError::IllegalTransition {
            from: "Idle",
            op: "begin_download"
        }
    ));
    assert!(matches!(
        s.record_progress(1).unwrap_err(),
        UpdateError::IllegalTransition {
            op: "record_progress",
            ..
        }
    ));
    assert!(matches!(
        s.verify(b"x").unwrap_err(),
        UpdateError::IllegalTransition { op: "verify", .. }
    ));
    assert!(matches!(
        s.begin_install().unwrap_err(),
        UpdateError::IllegalTransition {
            op: "begin_install",
            ..
        }
    ));
    assert!(matches!(
        s.finish_install().unwrap_err(),
        UpdateError::IllegalTransition {
            op: "finish_install",
            ..
        }
    ));
}

#[test]
fn cannot_finish_a_partial_download() {
    let bytes = b"0123456789";
    let mut s = UpdateSession::new(Version::new(1, "1"));
    s.offer(manifest(2, "2", bytes, 21, false), 30).unwrap();
    s.begin_download().unwrap();
    s.record_progress(4).unwrap();
    assert!(matches!(
        s.finish_download().unwrap_err(),
        UpdateError::SizeMismatch {
            expected: 10,
            actual: 4
        }
    ));
    assert_eq!(s.stage(), UpdateStage::Downloading);
}

#[test]
fn progress_is_monotonic_and_capped_at_size() {
    let bytes = b"0123456789";
    let mut s = UpdateSession::new(Version::new(1, "1"));
    s.offer(manifest(2, "2", bytes, 21, false), 30).unwrap();
    s.begin_download().unwrap();
    assert_eq!(s.record_progress(6).unwrap(), 6);
    // overshoot saturates at 10
    assert_eq!(s.record_progress(100).unwrap(), 10);
    s.finish_download().unwrap();
}

#[test]
fn verify_failure_moves_to_failed_and_blocks_install() {
    let bytes = b"correct-artifact";
    let mut s = UpdateSession::new(Version::new(1, "1"));
    s.offer(manifest(2, "2", bytes, 21, false), 30).unwrap();
    s.begin_download().unwrap();
    s.record_progress(bytes.len() as u64).unwrap();
    s.finish_download().unwrap();
    // wrong bytes of the right length
    let mut wrong = bytes.to_vec();
    wrong[0] ^= 0xff;
    assert!(matches!(
        s.verify(&wrong).unwrap_err(),
        UpdateError::HashMismatch
    ));
    assert_eq!(s.stage(), UpdateStage::Failed);
    assert!(s.fail_reason().is_some());
    // cannot install from Failed
    assert!(s.begin_install().is_err());
}

#[test]
fn finish_install_is_idempotent() {
    let bytes = b"payload-payload";
    let mut s = drive_happy_path(bytes);
    assert_eq!(s.stage(), UpdateStage::Installed);
    let before = s.clone();
    // A restart that re-runs the OS installer must not error.
    s.finish_install().unwrap();
    assert_eq!(s, before);
}

#[test]
fn mandatory_updates_cannot_be_deferred() {
    let mut s = UpdateSession::new(Version::new(1, "1"));
    assert!(s.can_defer()); // nothing in flight
    s.offer(manifest(2, "2", b"x", 21, true), 30).unwrap();
    assert!(!s.can_defer());
    let mut opt = UpdateSession::new(Version::new(1, "1"));
    opt.offer(manifest(2, "2", b"x", 21, false), 30).unwrap();
    assert!(opt.can_defer());
}

#[test]
fn reset_returns_to_idle_keeping_installed_version() {
    let bytes = b"halfway-there!!";
    let mut s = UpdateSession::new(Version::new(5, "5"));
    s.offer(manifest(6, "6", bytes, 21, false), 30).unwrap();
    s.begin_download().unwrap();
    s.record_progress(3).unwrap();
    s.reset();
    assert_eq!(s.stage(), UpdateStage::Idle);
    assert_eq!(s.installed(), &Version::new(5, "5"));
    assert_eq!(s.target(), None);
    assert_eq!(s.received_bytes(), 0);
}

// ---- persistence and recovery ----

#[test]
fn serialize_deserialize_round_trips_every_stage() {
    let bytes = b"an-artifact-for-persistence";
    let base = || {
        let mut s = UpdateSession::new(Version::new(41, "1.2.2"));
        s.offer(manifest(42, "1.2.3", bytes, 26, true), 34).unwrap();
        s
    };

    // Available
    let s = base();
    assert_eq!(UpdateSession::deserialize(&s.serialize()).unwrap(), s);

    // Downloading with partial progress
    let mut s = base();
    s.begin_download().unwrap();
    s.record_progress(10).unwrap();
    assert_eq!(UpdateSession::deserialize(&s.serialize()).unwrap(), s);

    // Verified
    let mut s = base();
    s.begin_download().unwrap();
    s.record_progress(bytes.len() as u64).unwrap();
    s.finish_download().unwrap();
    s.verify(bytes).unwrap();
    assert_eq!(UpdateSession::deserialize(&s.serialize()).unwrap(), s);

    // Installed (no target)
    let s = drive_happy_path(bytes);
    let round = UpdateSession::deserialize(&s.serialize()).unwrap();
    assert_eq!(round, s);

    // Failed
    let mut s = base();
    s.fail("network dropped");
    assert_eq!(UpdateSession::deserialize(&s.serialize()).unwrap(), s);

    // Idle
    let s = UpdateSession::new(Version::new(3, "3"));
    assert_eq!(UpdateSession::deserialize(&s.serialize()).unwrap(), s);
}

#[test]
fn deserialize_rejects_a_non_idle_stage_without_a_target() {
    let text = "stage = Verified\ninstalled_code = 1\ninstalled_name = 1\nreceived_bytes = 0\n";
    assert!(matches!(
        UpdateSession::deserialize(text).unwrap_err(),
        UpdateError::MalformedSession(_)
    ));
}

#[test]
fn recover_maps_interrupted_stages_to_safe_resumable_ones() {
    let bytes = b"recoverable-artifact-bytes";
    let base = || {
        let mut s = UpdateSession::new(Version::new(41, "1.2.2"));
        s.offer(manifest(42, "1.2.3", bytes, 26, false), 34)
            .unwrap();
        s
    };

    // Installing -> Verified (re-install idempotently)
    let mut s = base();
    s.begin_download().unwrap();
    s.record_progress(bytes.len() as u64).unwrap();
    s.finish_download().unwrap();
    s.verify(bytes).unwrap();
    s.begin_install().unwrap();
    assert_eq!(s.stage(), UpdateStage::Installing);
    let recovered = s.clone().recover();
    assert_eq!(recovered.stage(), UpdateStage::Verified);
    // recovery is idempotent
    assert_eq!(recovered.clone().recover(), recovered);

    // Downloaded -> Downloading (re-verify path)
    let mut s = base();
    s.begin_download().unwrap();
    s.record_progress(bytes.len() as u64).unwrap();
    s.finish_download().unwrap();
    assert_eq!(s.clone().recover().stage(), UpdateStage::Downloading);

    // Safe stages unchanged
    for safe in [
        UpdateStage::Idle,
        UpdateStage::Available,
        UpdateStage::Verified,
    ] {
        let mut s = base();
        match safe {
            UpdateStage::Idle => s.reset(),
            UpdateStage::Available => {}
            UpdateStage::Verified => {
                s.begin_download().unwrap();
                s.record_progress(bytes.len() as u64).unwrap();
                s.finish_download().unwrap();
                s.verify(bytes).unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(s.clone().recover().stage(), safe);
    }
}

#[test]
fn a_verified_session_survives_persist_recover_and_completes_install() {
    // Full "process restart mid-install" drill: install begins, the process is
    // killed, the persisted session is reloaded, recovered, and the install is
    // re-driven to completion.
    let bytes = b"survive-a-restart-mid-install!!";
    let mut s = UpdateSession::new(Version::new(41, "1.2.2"));
    s.offer(manifest(42, "1.2.3", bytes, 26, false), 34)
        .unwrap();
    s.begin_download().unwrap();
    s.record_progress(bytes.len() as u64).unwrap();
    s.finish_download().unwrap();
    s.verify(bytes).unwrap();
    s.begin_install().unwrap();

    // crash + restart
    let persisted = s.serialize();
    let mut resumed = UpdateSession::deserialize(&persisted).unwrap().recover();
    assert_eq!(resumed.stage(), UpdateStage::Verified);
    resumed.begin_install().unwrap();
    resumed.finish_install().unwrap();
    assert_eq!(resumed.stage(), UpdateStage::Installed);
    assert_eq!(resumed.installed(), &Version::new(42, "1.2.3"));
}

// ---- retry / backoff ----

#[test]
fn backoff_is_exponential_bounded_and_overflow_safe() {
    let p = RetryPolicy {
        max_attempts: 10,
        base_delay_secs: 5,
        max_delay_secs: 200,
    };
    assert_eq!(p.backoff_delay_secs(0), 5); // treated as attempt 1
    assert_eq!(p.backoff_delay_secs(1), 5);
    assert_eq!(p.backoff_delay_secs(2), 10);
    assert_eq!(p.backoff_delay_secs(3), 20);
    assert_eq!(p.backoff_delay_secs(4), 40);
    assert_eq!(p.backoff_delay_secs(5), 80);
    assert_eq!(p.backoff_delay_secs(6), 160);
    assert_eq!(p.backoff_delay_secs(7), 200); // clamped
    // Monotonic non-decreasing and never above the cap, even at huge attempts.
    let mut last = 0;
    for a in 1..=200u32 {
        let d = p.backoff_delay_secs(a);
        assert!(d >= last && d <= p.max_delay_secs, "attempt {a}: {d}");
        last = d;
    }
    assert_eq!(p.backoff_delay_secs(u32::MAX), 200);
    // A giant base still cannot overflow.
    let big = RetryPolicy {
        max_attempts: 3,
        base_delay_secs: u64::MAX / 2,
        max_delay_secs: u64::MAX,
    };
    assert_eq!(big.backoff_delay_secs(64), u64::MAX);
    assert_eq!(RetryPolicy::standard().max_attempts, 5);
}

#[test]
fn retry_re_arms_within_budget_then_gives_up() {
    let bytes = b"artifact-for-retry-drill";
    let policy = RetryPolicy {
        max_attempts: 3,
        base_delay_secs: 10,
        max_delay_secs: 1000,
    };
    let mut s = UpdateSession::new(Version::new(1, "1"));
    s.offer(manifest(2, "2", bytes, 21, false), 30).unwrap();
    s.begin_download().unwrap();
    s.record_progress(4).unwrap();
    assert_eq!(s.attempts(), 0);

    // First transient failure -> retry granted, re-armed to Available, progress reset.
    assert_eq!(s.retry(&policy).unwrap(), RetryDecision::RetryAfter(10));
    assert_eq!(s.stage(), UpdateStage::Available);
    assert_eq!(s.attempts(), 1);
    assert_eq!(s.received_bytes(), 0);
    assert!(s.target().is_some());

    // Second failure -> still within budget, backoff doubles.
    s.begin_download().unwrap();
    assert_eq!(s.retry(&policy).unwrap(), RetryDecision::RetryAfter(20));
    assert_eq!(s.attempts(), 2);

    // Third failure -> budget exhausted.
    s.begin_download().unwrap();
    assert_eq!(s.retry(&policy).unwrap(), RetryDecision::GaveUp);
    assert_eq!(s.stage(), UpdateStage::Failed);
    assert_eq!(s.attempts(), 3);
    assert!(s.fail_reason().is_some());
}

#[test]
fn retry_from_failed_verify_follows_backoff() {
    let bytes = b"the-correct-artifact-bytes!!";
    let policy = RetryPolicy::standard();
    let mut s = UpdateSession::new(Version::new(1, "1"));
    s.offer(manifest(2, "2", bytes, 21, false), 30).unwrap();
    s.begin_download().unwrap();
    s.record_progress(bytes.len() as u64).unwrap();
    s.finish_download().unwrap();
    // corrupt bytes -> verify fails to Failed
    let mut wrong = bytes.to_vec();
    wrong[0] ^= 0xff;
    assert!(s.verify(&wrong).is_err());
    assert_eq!(s.stage(), UpdateStage::Failed);
    // retry from Failed re-arms for another download
    assert_eq!(
        s.retry(&policy).unwrap(),
        RetryDecision::RetryAfter(policy.backoff_delay_secs(1))
    );
    assert_eq!(s.stage(), UpdateStage::Available);
    // and a clean re-download now verifies and installs
    s.begin_download().unwrap();
    s.record_progress(bytes.len() as u64).unwrap();
    s.finish_download().unwrap();
    s.verify(bytes).unwrap();
    s.begin_install().unwrap();
    s.finish_install().unwrap();
    assert_eq!(s.installed(), &Version::new(2, "2"));
}

#[test]
fn retry_is_illegal_without_an_in_flight_target() {
    let policy = RetryPolicy::standard();
    let mut idle = UpdateSession::new(Version::new(1, "1"));
    assert!(matches!(
        idle.retry(&policy).unwrap_err(),
        UpdateError::IllegalTransition { op: "retry", .. }
    ));
    // After a completed install there is nothing in flight to retry.
    let mut installed = UpdateSession::new(Version::new(1, "1"));
    installed
        .offer(manifest(2, "2", b"x", 21, false), 30)
        .unwrap();
    installed.begin_download().unwrap();
    installed.record_progress(1).unwrap();
    installed.finish_download().unwrap();
    installed.verify(b"x").unwrap();
    installed.begin_install().unwrap();
    installed.finish_install().unwrap();
    assert!(matches!(
        installed.retry(&policy).unwrap_err(),
        UpdateError::IllegalTransition { op: "retry", .. }
    ));
}

// ---- rollback to previous known-good ----

#[test]
fn rollback_reverts_to_the_previous_known_good_version() {
    let bytes = b"payload-vv";
    let mut s = drive_happy_path(bytes);
    assert_eq!(s.installed(), &Version::new(42, "1.2.3"));
    assert_eq!(s.previous(), Some(&Version::new(41, "1.2.2")));

    // A failed post-install health check triggers rollback to the prior version.
    s.rollback().unwrap();
    assert_eq!(s.stage(), UpdateStage::Idle);
    assert_eq!(s.installed(), &Version::new(41, "1.2.2"));
    assert_eq!(s.previous(), None);
    assert_eq!(s.target(), None);

    // Nothing left to roll back to.
    assert!(matches!(
        s.rollback().unwrap_err(),
        UpdateError::NothingToRollBack
    ));
}

#[test]
fn rollback_without_a_previous_version_is_an_error() {
    let mut fresh = UpdateSession::new(Version::new(5, "5"));
    assert!(matches!(
        fresh.rollback().unwrap_err(),
        UpdateError::NothingToRollBack
    ));
    assert_eq!(fresh.installed(), &Version::new(5, "5"));
}

#[test]
fn finish_install_records_the_prior_version_as_the_rollback_target() {
    let bytes = b"an-artifact!!";
    let mut s = UpdateSession::new(Version::new(10, "1.0"));
    assert_eq!(s.previous(), None);
    s.offer(manifest(11, "1.1", bytes, 21, false), 30).unwrap();
    s.begin_download().unwrap();
    s.record_progress(bytes.len() as u64).unwrap();
    s.finish_download().unwrap();
    s.verify(bytes).unwrap();
    s.begin_install().unwrap();
    s.finish_install().unwrap();
    assert_eq!(s.installed(), &Version::new(11, "1.1"));
    assert_eq!(s.previous(), Some(&Version::new(10, "1.0")));
}

// ---- re-check throttle ----

#[test]
fn should_check_for_update_respects_the_interval_and_clock_skew() {
    assert!(should_check_for_update(900, 0, 900)); // exactly the interval
    assert!(should_check_for_update(901, 0, 900));
    assert!(!should_check_for_update(899, 0, 900));
    assert!(!should_check_for_update(100, 1_000, 900)); // clock went backwards
    assert!(should_check_for_update(0, 0, 0)); // always-check policy
}

// ---- persistence of the new fields ----

#[test]
fn serde_round_trips_attempts_and_previous() {
    let bytes = b"round-trip-artifact";
    // A session mid-retry (attempts > 0) with a target.
    let mut s = UpdateSession::new(Version::new(3, "3"));
    s.offer(manifest(4, "4", bytes, 21, true), 30).unwrap();
    s.begin_download().unwrap();
    let _ = s.retry(&RetryPolicy::standard()).unwrap();
    assert_eq!(s.attempts(), 1);
    assert_eq!(UpdateSession::deserialize(&s.serialize()).unwrap(), s);

    // An installed session carrying a rollback target (previous = Some).
    let installed = drive_happy_path(bytes);
    assert!(installed.previous().is_some());
    let round = UpdateSession::deserialize(&installed.serialize()).unwrap();
    assert_eq!(round, installed);
    assert_eq!(round.previous(), Some(&Version::new(41, "1.2.2")));
}

// ---- pre-download condition gating ----

/// A baseline "everything is fine" snapshot other cases mutate one field of.
fn good_conditions() -> DownloadConditions {
    DownloadConditions {
        network: NetworkType::Unmetered,
        battery_percent: 80,
        charging: false,
        free_storage_bytes: 1_000_000_000,
    }
}

#[test]
fn download_readiness_covers_every_branch() {
    let policy = DownloadPolicy::conservative(); // Wi-Fi only, >=20%, no headroom
    let size = 40_000_000;

    assert_eq!(
        download_readiness(&good_conditions(), &policy, size),
        DownloadReadiness::Ready
    );
    assert!(download_readiness(&good_conditions(), &policy, size).is_ready());

    // No network.
    let no_net = DownloadConditions {
        network: NetworkType::None,
        ..good_conditions()
    };
    assert_eq!(
        download_readiness(&no_net, &policy, size),
        DownloadReadiness::NoNetwork
    );

    // Metered blocked by the conservative policy, allowed by a permissive one.
    let metered = DownloadConditions {
        network: NetworkType::Metered,
        ..good_conditions()
    };
    assert_eq!(
        download_readiness(&metered, &policy, size),
        DownloadReadiness::MeteredBlocked
    );
    let permissive = DownloadPolicy {
        allow_metered: true,
        ..policy
    };
    assert_eq!(
        download_readiness(&metered, &permissive, size),
        DownloadReadiness::Ready
    );

    // Low battery, unless charging.
    let low = DownloadConditions {
        battery_percent: 10,
        charging: false,
        ..good_conditions()
    };
    assert_eq!(
        download_readiness(&low, &policy, size),
        DownloadReadiness::LowBattery
    );
    let low_but_charging = DownloadConditions {
        charging: true,
        ..low
    };
    assert_eq!(
        download_readiness(&low_but_charging, &policy, size),
        DownloadReadiness::Ready
    );

    // Insufficient storage (artifact + headroom).
    let tight = DownloadConditions {
        free_storage_bytes: 30_000_000,
        ..good_conditions()
    };
    assert_eq!(
        download_readiness(&tight, &policy, size),
        DownloadReadiness::InsufficientStorage {
            needed: 40_000_000,
            free: 30_000_000,
        }
    );
    // Headroom is added on top of the artifact size.
    let with_headroom = DownloadPolicy {
        storage_headroom_bytes: 50_000_000,
        ..policy
    };
    let ample = DownloadConditions {
        free_storage_bytes: 80_000_000,
        ..good_conditions()
    };
    assert_eq!(
        download_readiness(&ample, &with_headroom, size),
        DownloadReadiness::InsufficientStorage {
            needed: 90_000_000,
            free: 80_000_000,
        }
    );
}

#[test]
fn download_readiness_boundaries_are_inclusive_where_documented() {
    let policy = DownloadPolicy {
        allow_metered: false,
        min_battery_percent: 20,
        storage_headroom_bytes: 0,
    };
    // battery exactly at the minimum is allowed.
    let at_min = DownloadConditions {
        battery_percent: 20,
        ..good_conditions()
    };
    assert!(download_readiness(&at_min, &policy, 10).is_ready());
    let below = DownloadConditions {
        battery_percent: 19,
        ..good_conditions()
    };
    assert_eq!(
        download_readiness(&below, &policy, 10),
        DownloadReadiness::LowBattery
    );
    // free storage exactly equal to needed is allowed.
    let exact = DownloadConditions {
        free_storage_bytes: 10,
        ..good_conditions()
    };
    assert!(download_readiness(&exact, &policy, 10).is_ready());
    let one_short = DownloadConditions {
        free_storage_bytes: 9,
        ..good_conditions()
    };
    assert_eq!(
        download_readiness(&one_short, &policy, 10),
        DownloadReadiness::InsufficientStorage {
            needed: 10,
            free: 9
        }
    );
    // storage need cannot overflow.
    let huge = DownloadPolicy {
        storage_headroom_bytes: u64::MAX,
        ..policy
    };
    assert_eq!(
        download_readiness(&good_conditions(), &huge, u64::MAX),
        DownloadReadiness::InsufficientStorage {
            needed: u64::MAX,
            free: 1_000_000_000,
        }
    );
}

#[test]
fn download_readiness_precedence_no_network_beats_all() {
    // A snapshot that fails every check must report the highest-precedence one.
    let policy = DownloadPolicy {
        allow_metered: false,
        min_battery_percent: 90,
        storage_headroom_bytes: u64::MAX,
    };
    let all_bad = DownloadConditions {
        network: NetworkType::None,
        battery_percent: 0,
        charging: false,
        free_storage_bytes: 0,
    };
    assert_eq!(
        download_readiness(&all_bad, &policy, 1),
        DownloadReadiness::NoNetwork
    );
    // With a metered network present, metered-blocked outranks battery/storage.
    let metered_bad = DownloadConditions {
        network: NetworkType::Metered,
        ..all_bad
    };
    assert_eq!(
        download_readiness(&metered_bad, &policy, 1),
        DownloadReadiness::MeteredBlocked
    );
    // Unmetered but flat battery and no storage -> battery outranks storage.
    let batt_bad = DownloadConditions {
        network: NetworkType::Unmetered,
        ..all_bad
    };
    assert_eq!(
        download_readiness(&batt_bad, &policy, 1),
        DownloadReadiness::LowBattery
    );
}

#[test]
fn download_readiness_gates_a_real_session_download() {
    // The engine offers the update, but the caller declines to download until
    // conditions are met, then proceeds — no illegal state, no failed download.
    let bytes = b"gated-artifact-payload";
    let policy = DownloadPolicy::conservative();
    let mut s = UpdateSession::new(Version::new(1, "1"));
    s.offer(manifest(2, "2", bytes, 21, false), 30).unwrap();

    let on_mobile = DownloadConditions {
        network: NetworkType::Metered,
        battery_percent: 90,
        charging: true,
        free_storage_bytes: 1_000_000,
    };
    assert!(!download_readiness(&on_mobile, &policy, bytes.len() as u64).is_ready());
    assert_eq!(s.stage(), UpdateStage::Available); // did not start downloading

    let on_wifi = DownloadConditions {
        network: NetworkType::Unmetered,
        ..on_mobile
    };
    assert!(download_readiness(&on_wifi, &policy, bytes.len() as u64).is_ready());
    s.begin_download().unwrap();
    s.record_progress(bytes.len() as u64).unwrap();
    s.finish_download().unwrap();
    s.verify(bytes).unwrap();
    s.begin_install().unwrap();
    s.finish_install().unwrap();
    assert_eq!(s.installed(), &Version::new(2, "2"));
}

#[test]
fn download_readiness_randomized_matches_an_independent_reference() {
    // A small deterministic sweep cross-checking the branch precedence against an
    // independently-written reference.
    let mut seed = 0x51ED_9E55_u64 | 1;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut ready = 0u32;
    let mut no_net = 0u32;
    let mut metered = 0u32;
    let mut low_batt = 0u32;
    let mut no_space = 0u32;
    for _ in 0..20_000 {
        let network = match next() % 3 {
            0 => NetworkType::None,
            1 => NetworkType::Metered,
            _ => NetworkType::Unmetered,
        };
        let conditions = DownloadConditions {
            network,
            battery_percent: (next() % 101) as u8,
            charging: next() % 2 == 0,
            free_storage_bytes: next() % 200,
        };
        let policy = DownloadPolicy {
            allow_metered: next() % 2 == 0,
            min_battery_percent: (next() % 101) as u8,
            storage_headroom_bytes: next() % 50,
        };
        let size = next() % 150;

        // Independent reference of the documented precedence.
        let needed = size.saturating_add(policy.storage_headroom_bytes);
        let expected = if conditions.network == NetworkType::None {
            DownloadReadiness::NoNetwork
        } else if conditions.network == NetworkType::Metered && !policy.allow_metered {
            DownloadReadiness::MeteredBlocked
        } else if !conditions.charging && conditions.battery_percent < policy.min_battery_percent {
            DownloadReadiness::LowBattery
        } else if conditions.free_storage_bytes < needed {
            DownloadReadiness::InsufficientStorage {
                needed,
                free: conditions.free_storage_bytes,
            }
        } else {
            DownloadReadiness::Ready
        };
        let got = download_readiness(&conditions, &policy, size);
        assert_eq!(
            got, expected,
            "conditions={conditions:?} policy={policy:?} size={size}"
        );
        match got {
            DownloadReadiness::Ready => ready += 1,
            DownloadReadiness::NoNetwork => no_net += 1,
            DownloadReadiness::MeteredBlocked => metered += 1,
            DownloadReadiness::LowBattery => low_batt += 1,
            DownloadReadiness::InsufficientStorage { .. } => no_space += 1,
        }
    }
    // Every outcome must actually occur in the sweep.
    assert!(ready > 0 && no_net > 0 && metered > 0 && low_batt > 0 && no_space > 0);
}

// ---- the remote manifest source ----

/// The documented rule, restated independently of the implementation: a
/// transport failure retries; an oversized or rejected body never does; an
/// answer uses the remote manifest on 2xx, retries on 408/425/429/5xx, and
/// falls back without a retry on everything else (404/410 above all: no
/// release published).
fn documented_manifest_source_decision(
    status: u16,
    failure: ManifestFetchFailure,
) -> ManifestSourceDecision {
    let transient = matches!(status, 408 | 425 | 429) || (500..=599).contains(&status);
    match failure {
        ManifestFetchFailure::Transport => ManifestSourceDecision::FallbackRetry,
        ManifestFetchFailure::TooLarge | ManifestFetchFailure::Rejected => {
            ManifestSourceDecision::FallbackNoRetry
        }
        ManifestFetchFailure::None if (200..=299).contains(&status) => {
            ManifestSourceDecision::UseRemote
        }
        ManifestFetchFailure::None if transient => ManifestSourceDecision::FallbackRetry,
        ManifestFetchFailure::None => ManifestSourceDecision::FallbackNoRetry,
    }
}

#[test]
fn manifest_source_decision_matches_the_documented_rule_for_every_status_and_failure() {
    use ManifestFetchFailure::{None, Rejected, TooLarge, Transport};
    use ManifestSourceDecision::{FallbackNoRetry, FallbackRetry, UseRemote};
    for status in 0..=1000u16 {
        for failure in [None, Transport, TooLarge, Rejected] {
            assert_eq!(
                manifest_source_decision(status, failure),
                documented_manifest_source_decision(status, failure),
                "status {status}, failure {failure:?}"
            );
        }
    }
    // The boundaries, named.
    assert_eq!(manifest_source_decision(199, None), FallbackNoRetry);
    assert_eq!(manifest_source_decision(200, None), UseRemote);
    assert_eq!(manifest_source_decision(299, None), UseRemote);
    // A remaining 3xx: a redirect the client refused to follow.
    assert_eq!(manifest_source_decision(300, None), FallbackNoRetry);
    assert_eq!(manifest_source_decision(404, None), FallbackNoRetry);
    assert_eq!(manifest_source_decision(410, None), FallbackNoRetry);
    assert_eq!(manifest_source_decision(408, None), FallbackRetry);
    assert_eq!(manifest_source_decision(429, None), FallbackRetry);
    assert_eq!(manifest_source_decision(499, None), FallbackNoRetry);
    assert_eq!(manifest_source_decision(500, None), FallbackRetry);
    assert_eq!(manifest_source_decision(599, None), FallbackRetry);
    assert_eq!(manifest_source_decision(600, None), FallbackNoRetry);
    assert_eq!(manifest_source_decision(0, None), FallbackNoRetry);
    assert_eq!(manifest_source_decision(0, Transport), FallbackRetry);
    assert_eq!(manifest_source_decision(200, TooLarge), FallbackNoRetry);
    assert_eq!(manifest_source_decision(200, Rejected), FallbackNoRetry);
    // The retry budget is never spent on a source without a release or one
    // that refuses the request.
    for status in [400u16, 401, 403, 404, 410, 451] {
        assert_ne!(
            manifest_source_decision(status, None),
            FallbackRetry,
            "{status}"
        );
    }
}
