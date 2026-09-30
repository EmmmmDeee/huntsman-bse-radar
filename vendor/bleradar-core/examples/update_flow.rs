//! End-to-end walk of the automatic-update engine over real bytes
//! (`bleradar_core::update`). Run with `cargo run -p bleradar-core --example update_flow`.
//!
//! This exercises the whole lifecycle against a real artifact and a real
//! SHA-256: build a payload, publish a manifest, check the update decision,
//! stream-download with integrity checking, verify, then survive a simulated
//! process crash mid-install (persist → restart → recover → finish). It also
//! shows the safety rails: tampered bytes are rejected, downgrades are refused,
//! and installing on too-old an OS is declined.

use bleradar_core::update::{
    ArtifactVerifier, DownloadConditions, DownloadPolicy, NetworkType, ReleaseManifest,
    RetryDecision, RetryPolicy, UpdateDecision, UpdateSession, UpdateStage, Version, check_update,
    download_readiness,
};
use bleradar_core::{Sha256, hex_encode};

fn sha_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_encode(&h.finalize())
}

fn manifest_text(code: u64, name: &str, bytes: &[u8], min_sdk: u32, mandatory: bool) -> String {
    format!(
        "version_code = {code}\nversion_name = {name}\nurl = https://downloads.example.com/app-{name}.apk\n\
         size_bytes = {}\nsha256 = {}\nmin_sdk = {min_sdk}\nmandatory = {mandatory}\n\
         notes = Security fixes and a faster radar sweep\n",
        bytes.len(),
        sha_hex(bytes),
    )
}

fn main() {
    // A realistic (small) artifact standing in for the downloaded APK.
    let artifact: Vec<u8> = (0..64 * 1024).map(|i| (i * 31 + 7) as u8).collect();
    let manifest =
        ReleaseManifest::parse(&manifest_text(42, "1.2.3", &artifact, 26, false)).unwrap();
    println!(
        "published release: v{} ({} bytes, sha256 {}…)",
        manifest.version.code,
        manifest.size_bytes,
        &hex_encode(&manifest.sha256)[..12]
    );

    let installed = Version::new(41, "1.2.2");
    println!("installed: v{} ({})", installed.code, installed.name);

    // 1. Decide.
    let decision = check_update(&installed, /* device_sdk */ 34, &manifest);
    println!("\n[check] decision = {decision:?}");
    assert_eq!(decision, UpdateDecision::Available);

    // 2. Drive the session with streaming integrity verification.
    let mut session = UpdateSession::new(installed);
    assert_eq!(
        session.offer(manifest.clone(), 34).unwrap(),
        UpdateDecision::Available
    );
    session.begin_download().unwrap();

    let mut verifier = ArtifactVerifier::new(&manifest);
    for chunk in artifact.chunks(4096) {
        verifier.feed(chunk).unwrap(); // rejects an over-long stream immediately
        session.record_progress(chunk.len() as u64).unwrap();
    }
    verifier.finish().unwrap();
    session.finish_download().unwrap();
    println!(
        "[download] {} / {} bytes, streaming SHA-256 OK",
        session.received_bytes(),
        manifest.size_bytes
    );

    session.verify(&artifact).unwrap();
    assert_eq!(session.stage(), UpdateStage::Verified);
    println!("[verify] size + SHA-256 match the manifest");

    // 3. Begin installing, then simulate a process crash.
    session.begin_install().unwrap();
    let persisted = session.serialize();
    println!(
        "\n[crash] process killed mid-install; {} bytes of session state persisted",
        persisted.len()
    );

    // 4. Restart: reload, recover, finish.
    let resumed = UpdateSession::deserialize(&persisted).unwrap();
    let mut resumed = resumed.recover();
    println!(
        "[restart] reloaded at stage {:?}, recovered to {:?}",
        UpdateStage::Installing,
        resumed.stage()
    );
    assert_eq!(resumed.stage(), UpdateStage::Verified);
    resumed.begin_install().unwrap();
    resumed.finish_install().unwrap();
    println!(
        "[install] complete; now running v{} ({})",
        resumed.installed().code,
        resumed.installed().name
    );
    assert_eq!(resumed.installed(), &Version::new(42, "1.2.3"));

    // 5. Idempotent re-install (a duplicate OS callback must not error).
    resumed.finish_install().unwrap();
    println!("[idempotent] repeated finish_install is a no-op");

    // 6. Safety rails.
    println!("\n[safety rails]");
    // tampered artifact
    let mut tampered = artifact.clone();
    tampered[1234] ^= 0x01;
    let mut s = UpdateSession::new(Version::new(41, "1.2.2"));
    s.offer(manifest.clone(), 34).unwrap();
    s.begin_download().unwrap();
    s.record_progress(manifest.size_bytes).unwrap();
    s.finish_download().unwrap();
    let err = s.verify(&tampered).unwrap_err();
    println!("  tampered artifact rejected: {err}");
    assert_eq!(s.stage(), UpdateStage::Failed);

    // downgrade
    let older = ReleaseManifest::parse(&manifest_text(40, "1.2.1", b"older", 26, false)).unwrap();
    println!(
        "  downgrade decision: {:?}",
        check_update(&Version::new(42, "1.2.3"), 34, &older)
    );

    // OS too old
    let needs_new_os =
        ReleaseManifest::parse(&manifest_text(43, "1.3.0", b"future", 34, false)).unwrap();
    println!(
        "  incompatible-OS decision: {:?}",
        check_update(&Version::new(42, "1.2.3"), 30, &needs_new_os)
    );

    // 6b. Pre-download gating: don't spend the user's mobile data or a low
    //     battery on a big download; wait for Wi-Fi.
    println!("\n[download gating]");
    let dl_policy = DownloadPolicy::conservative();
    let on_mobile = DownloadConditions {
        network: NetworkType::Metered,
        battery_percent: 30,
        charging: false,
        free_storage_bytes: 500 * 1024 * 1024,
    };
    println!(
        "  on mobile data: {:?} — holding",
        download_readiness(&on_mobile, &dl_policy, manifest.size_bytes)
    );
    let on_wifi = DownloadConditions {
        network: NetworkType::Unmetered,
        ..on_mobile
    };
    println!(
        "  on Wi-Fi: {:?} — proceed",
        download_readiness(&on_wifi, &dl_policy, manifest.size_bytes)
    );

    // 7. Transient-failure resilience: two download faults, retried with backoff,
    //    then a clean download that installs.
    println!("\n[retry with backoff]");
    let policy = RetryPolicy {
        max_attempts: 4,
        base_delay_secs: 15,
        max_delay_secs: 3600,
    };
    let mut r = UpdateSession::new(Version::new(41, "1.2.2"));
    r.offer(manifest.clone(), 34).unwrap();
    for fault in 1..=2 {
        r.begin_download().unwrap();
        r.record_progress(20_000).unwrap(); // partial, then the connection drops
        match r.retry(&policy).unwrap() {
            RetryDecision::RetryAfter(secs) => {
                println!(
                    "  download fault {fault}: retry after {secs}s (attempt {})",
                    r.attempts()
                );
            }
            RetryDecision::GaveUp => unreachable!(),
        }
    }
    // The next attempt succeeds.
    let faults = r.attempts();
    r.begin_download().unwrap();
    for chunk in artifact.chunks(4096) {
        r.record_progress(chunk.len() as u64).unwrap();
    }
    r.finish_download().unwrap();
    r.verify(&artifact).unwrap();
    r.begin_install().unwrap();
    r.finish_install().unwrap();
    println!(
        "  recovered after {faults} fault(s); installed v{}",
        r.installed().code
    );

    // 8. Bad-update recovery: a freshly-installed version fails its health check,
    //    so roll back to the previous known-good version.
    println!("\n[rollback]");
    println!(
        "  running v{} (rolled up from v{})",
        r.installed().code,
        r.previous().unwrap().code
    );
    r.rollback().unwrap();
    println!(
        "  health check failed → rolled back to v{}",
        r.installed().code
    );
    assert_eq!(r.installed(), &Version::new(41, "1.2.2"));

    println!("\nupdate_flow: OK");
}
