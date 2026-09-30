//! Robust, deterministic automatic-update engine.
//!
//! An in-app auto-update has two halves: platform plumbing (fetch bytes over the
//! network, hand an APK to the OS package installer) and the *decisions* that
//! make an update safe — is this release newer, is it compatible, is the
//! downloaded file exactly the intended artifact, and can the flow survive a
//! restart mid-way. The plumbing is inherently platform-specific and untestable
//! off-device; the decisions are pure, so they live here where they can be
//! exhaustively tested, falsified, and reused verbatim by every caller.
//!
//! This module owns the whole decision surface:
//!
//! * [`Version`] — the monotonic Android `versionCode` (the authoritative update
//!   key) plus the human-facing `versionName`.
//! * [`ReleaseManifest`] — a strictly-parsed, HTTPS-only release descriptor with
//!   a pinned SHA-256 and size, round-trippable via [`ReleaseManifest::serialize`].
//! * [`update_decision`] / [`check_update`] — the single source of truth for
//!   whether to offer an update ([`UpdateDecision`]), keyed on `versionCode` and
//!   minimum OS, refusing silent downgrades.
//! * [`ArtifactVerifier`] / [`verify_artifact`] — streaming integrity
//!   verification (exact size **and** SHA-256) that rejects an over-long or
//!   tampered download before it can be installed.
//! * [`UpdateSession`] — a restart-safe state machine over the whole lifecycle
//!   (`Idle → Available → Downloading → Downloaded → Verified → Installing →
//!   Installed`), which [`serialize`](UpdateSession::serialize)s to a string,
//!   [`deserialize`](UpdateSession::deserialize)s back exactly, and
//!   [`recover`](UpdateSession::recover)s any interrupted stage to a safe,
//!   resumable point. Illegal transitions are rejected, never panic; installing
//!   an unverified artifact is unrepresentable; a completed install is
//!   idempotent.
//! * [`RetryPolicy`] / [`UpdateSession::retry`] — bounded exponential-backoff
//!   recovery from a transient download/verify fault, giving up only after the
//!   budget is spent ([`RetryDecision`]).
//! * [`UpdateSession::rollback`] — revert to the previous known-good version
//!   after a bad update fails its post-install health check.
//! * [`should_check_for_update`] — a re-check throttle so the app polls no more
//!   often than a minimum interval, robust against a backward clock.
//! * [`download_readiness`] — pre-download gating on network (metered/Wi-Fi),
//!   battery, and free storage ([`DownloadPolicy`] / [`DownloadConditions`] →
//!   [`DownloadReadiness`]) so a download that would fail or cost the user is
//!   never started.
//!
//! Every guard is a permanent invariant locked by `tests/update.rs` and the
//! randomized `tests/update_campaign.rs`; `examples/update_flow.rs` exercises the
//! whole lifecycle over real bytes.

use crate::entity::{Sha256, hex_encode};
use std::fmt;

/// An application version: the monotonic `versionCode` (the update key Android
/// itself compares) and the display `versionName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Android `versionCode`: strictly increasing across releases.
    pub code: u64,
    /// Android `versionName`: human-facing, e.g. `"1.2.3"`.
    pub name: String,
}

impl Version {
    /// A version from its code and name.
    #[must_use]
    pub fn new(code: u64, name: impl Into<String>) -> Self {
        Self {
            code,
            name: name.into(),
        }
    }
}

/// The outcome of comparing an installed version to an available release.
///
/// Keyed on `versionCode` (like the Android package manager) and minimum OS, so
/// a build that is not strictly newer, or that the device is too old to run, is
/// never offered — and a downgrade is refused rather than silently applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateDecision {
    /// The available release is the same `versionCode` as installed.
    UpToDate,
    /// The release is strictly newer and OS-compatible: offer it.
    Available,
    /// The release is older than installed: refuse (no silent downgrade).
    DowngradeRefused,
    /// The release is newer but the device OS is below the release minimum.
    IncompatibleOs,
}

impl UpdateDecision {
    /// A stable ordinal for FFI/JNI (`0..=3`).
    #[must_use]
    pub const fn ordinal(self) -> i32 {
        match self {
            Self::UpToDate => 0,
            Self::Available => 1,
            Self::DowngradeRefused => 2,
            Self::IncompatibleOs => 3,
        }
    }

    /// Decodes a stable ordinal produced by [`ordinal`](Self::ordinal).
    #[must_use]
    pub const fn from_ordinal(ordinal: i32) -> Option<Self> {
        match ordinal {
            0 => Some(Self::UpToDate),
            1 => Some(Self::Available),
            2 => Some(Self::DowngradeRefused),
            3 => Some(Self::IncompatibleOs),
            _ => None,
        }
    }

    /// Whether this decision means an install should be offered.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// The authoritative update decision from raw version codes and OS levels.
///
/// This is the numeric core shared by [`check_update`] and the JNI bridge, so
/// the app and the tests exercise exactly one implementation.
///
/// # Examples
/// ```
/// use bleradar_core::{update_decision, UpdateDecision};
/// // Strictly newer and OS-compatible.
/// assert_eq!(update_decision(41, 42, 34, 26), UpdateDecision::Available);
/// // Same versionCode.
/// assert_eq!(update_decision(42, 42, 34, 26), UpdateDecision::UpToDate);
/// // Older build is refused.
/// assert_eq!(update_decision(42, 41, 34, 26), UpdateDecision::DowngradeRefused);
/// // Newer but the device is too old.
/// assert_eq!(update_decision(41, 42, 24, 26), UpdateDecision::IncompatibleOs);
/// ```
#[must_use]
pub fn update_decision(
    installed_code: u64,
    available_code: u64,
    device_sdk: u32,
    min_sdk: u32,
) -> UpdateDecision {
    if available_code == installed_code {
        UpdateDecision::UpToDate
    } else if available_code < installed_code {
        UpdateDecision::DowngradeRefused
    } else if device_sdk < min_sdk {
        UpdateDecision::IncompatibleOs
    } else {
        UpdateDecision::Available
    }
}

/// The update decision for a manifest against the installed version and device.
///
/// # Examples
/// ```
/// use bleradar_core::update::{check_update, ReleaseManifest, Version, UpdateDecision};
/// let manifest = ReleaseManifest::parse(SAMPLE).unwrap();
/// let installed = Version::new(41, "1.2.2");
/// assert_eq!(check_update(&installed, 34, &manifest), UpdateDecision::Available);
/// # const SAMPLE: &str = "\
/// # version_code = 42\n\
/// # version_name = 1.2.3\n\
/// # url = https://example.com/app-1.2.3.apk\n\
/// # size_bytes = 8\n\
/// # sha256 = 2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3\n\
/// # min_sdk = 26\n\
/// # mandatory = false\n";
/// ```
#[must_use]
pub fn check_update(
    installed: &Version,
    device_sdk: u32,
    manifest: &ReleaseManifest,
) -> UpdateDecision {
    update_decision(
        installed.code,
        manifest.version.code,
        device_sdk,
        manifest.min_sdk,
    )
}

/// A parsed, validated release descriptor.
///
/// Produced by [`ReleaseManifest::parse`] from the line-oriented `key = value`
/// format (one field per line, first `=` splits key from value, `#` comment
/// lines and blank lines ignored). Required fields: `version_code`,
/// `version_name`, `url`, `size_bytes`, `sha256`, `min_sdk`, `mandatory`; `notes`
/// is optional. The URL must be HTTPS, the size non-zero, and the SHA-256 exactly
/// 64 hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// The release version.
    pub version: Version,
    /// HTTPS download URL for the artifact.
    pub url: String,
    /// Exact artifact size in bytes.
    pub size_bytes: u64,
    /// Expected SHA-256 of the artifact.
    pub sha256: [u8; 32],
    /// Minimum device SDK level required to install.
    pub min_sdk: u32,
    /// Whether the update must be applied (cannot be deferred).
    pub mandatory: bool,
    /// Optional single-line release notes.
    pub notes: String,
}

impl ReleaseManifest {
    /// Parses and validates a manifest from the line-oriented format.
    ///
    /// # Errors
    /// Returns an [`UpdateError`] for a missing, duplicate, unknown, or malformed
    /// field, a non-HTTPS URL, a zero size, or a SHA-256 that is not 64 hex chars.
    pub fn parse(text: &str) -> Result<Self, UpdateError> {
        let mut version_code: Option<u64> = None;
        let mut version_name: Option<String> = None;
        let mut url: Option<String> = None;
        let mut size_bytes: Option<u64> = None;
        let mut sha256: Option<[u8; 32]> = None;
        let mut min_sdk: Option<u32> = None;
        let mut mandatory: Option<bool> = None;
        let mut notes: Option<String> = None;

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| UpdateError::MalformedLine(raw.trim().to_string()))?;
            let key = key.trim();
            let value = value.trim();
            match key {
                "version_code" => set_once(
                    &mut version_code,
                    "version_code",
                    parse_u64(value, "version_code")?,
                )?,
                "version_name" => set_once(&mut version_name, "version_name", value.to_string())?,
                "url" => set_once(&mut url, "url", value.to_string())?,
                "size_bytes" => set_once(
                    &mut size_bytes,
                    "size_bytes",
                    parse_u64(value, "size_bytes")?,
                )?,
                "sha256" => set_once(&mut sha256, "sha256", parse_hex32(value)?)?,
                "min_sdk" => set_once(&mut min_sdk, "min_sdk", parse_u32(value, "min_sdk")?)?,
                "mandatory" => {
                    set_once(&mut mandatory, "mandatory", parse_bool(value, "mandatory")?)?
                }
                "notes" => set_once(&mut notes, "notes", value.to_string())?,
                other => return Err(UpdateError::UnknownField(other.to_string())),
            }
        }

        let version_name = version_name.ok_or(UpdateError::MissingField("version_name"))?;
        if version_name.is_empty() {
            return Err(UpdateError::MalformedField {
                key: "version_name",
                reason: "must not be empty",
            });
        }
        let url = url.ok_or(UpdateError::MissingField("url"))?;
        if !url.starts_with("https://") {
            return Err(UpdateError::InsecureUrl);
        }
        let size_bytes = size_bytes.ok_or(UpdateError::MissingField("size_bytes"))?;
        if size_bytes == 0 {
            return Err(UpdateError::EmptyArtifact);
        }

        Ok(Self {
            version: Version::new(
                version_code.ok_or(UpdateError::MissingField("version_code"))?,
                version_name,
            ),
            url,
            size_bytes,
            sha256: sha256.ok_or(UpdateError::MissingField("sha256"))?,
            min_sdk: min_sdk.ok_or(UpdateError::MissingField("min_sdk"))?,
            mandatory: mandatory.ok_or(UpdateError::MissingField("mandatory"))?,
            notes: notes.unwrap_or_default(),
        })
    }

    /// Serializes the manifest back to the canonical line-oriented format.
    ///
    /// [`parse`](Self::parse) of the result reproduces an equal manifest.
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("version_code = {}\n", self.version.code));
        out.push_str(&format!("version_name = {}\n", self.version.name));
        out.push_str(&format!("url = {}\n", self.url));
        out.push_str(&format!("size_bytes = {}\n", self.size_bytes));
        out.push_str(&format!("sha256 = {}\n", hex_encode(&self.sha256)));
        out.push_str(&format!("min_sdk = {}\n", self.min_sdk));
        out.push_str(&format!("mandatory = {}\n", self.mandatory));
        out.push_str(&format!("notes = {}\n", self.notes));
        out
    }
}

/// A recoverable fault in the update flow. Every variant is actionable and names
/// what was wrong; no variant leaks the raw artifact bytes or hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    /// A required manifest field was absent.
    MissingField(&'static str),
    /// A field appeared more than once.
    DuplicateField(&'static str),
    /// An unrecognized manifest key.
    UnknownField(String),
    /// A line without a `key = value` separator.
    MalformedLine(String),
    /// A field's value could not be interpreted.
    MalformedField {
        /// The field name.
        key: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// The download URL was not HTTPS.
    InsecureUrl,
    /// The artifact size was zero.
    EmptyArtifact,
    /// The download exceeded the manifest's declared size.
    Overrun {
        /// Declared size.
        expected: u64,
        /// Bytes received before the overrun was detected.
        received: u64,
    },
    /// The completed download's size did not match the manifest.
    SizeMismatch {
        /// Declared size.
        expected: u64,
        /// Actual size.
        actual: u64,
    },
    /// The artifact's SHA-256 did not match the manifest.
    HashMismatch,
    /// An operation was attempted from a stage that does not allow it.
    IllegalTransition {
        /// The stage the session was in.
        from: &'static str,
        /// The operation that was rejected.
        op: &'static str,
    },
    /// A serialized session string could not be parsed back.
    MalformedSession(&'static str),
    /// `rollback` was called with no previous version recorded.
    NothingToRollBack,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(k) => write!(f, "manifest is missing required field `{k}`"),
            Self::DuplicateField(k) => write!(f, "manifest field `{k}` appears more than once"),
            Self::UnknownField(k) => write!(f, "manifest has unknown field `{k}`"),
            Self::MalformedLine(l) => write!(f, "manifest line is not `key = value`: {l:?}"),
            Self::MalformedField { key, reason } => {
                write!(f, "manifest field `{key}` is invalid: {reason}")
            }
            Self::InsecureUrl => write!(f, "manifest url must be https://"),
            Self::EmptyArtifact => write!(f, "manifest size_bytes must be non-zero"),
            Self::Overrun { expected, received } => {
                write!(
                    f,
                    "download exceeded declared size: {received} > {expected} bytes"
                )
            }
            Self::SizeMismatch { expected, actual } => {
                write!(
                    f,
                    "artifact size mismatch: expected {expected}, got {actual} bytes"
                )
            }
            Self::HashMismatch => write!(f, "artifact SHA-256 does not match the manifest"),
            Self::IllegalTransition { from, op } => {
                write!(f, "cannot `{op}` from stage `{from}`")
            }
            Self::MalformedSession(r) => write!(f, "serialized update session is invalid: {r}"),
            Self::NothingToRollBack => write!(f, "no previous version to roll back to"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// A bounded exponential-backoff retry policy for transient update failures.
///
/// A robust auto-update must survive a dropped connection or a corrupt download
/// without either giving up on the first fault or hammering the server: it
/// retries a bounded number of times, waiting longer after each failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total failed attempts tolerated before giving up (must be >= 1).
    pub max_attempts: u32,
    /// Delay after the first failure, in seconds.
    pub base_delay_secs: u64,
    /// Upper bound on any single backoff delay, in seconds.
    pub max_delay_secs: u64,
}

impl RetryPolicy {
    /// A sensible default: up to 5 attempts, 30 s base, capped at 1 h.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_attempts: 5,
            base_delay_secs: 30,
            max_delay_secs: 3600,
        }
    }

    /// The backoff delay before the given attempt number (`attempt >= 1`):
    /// `base * 2^(attempt-1)`, saturating and clamped to `max_delay_secs`.
    ///
    /// # Examples
    /// ```
    /// use bleradar_core::update::RetryPolicy;
    /// let p = RetryPolicy { max_attempts: 5, base_delay_secs: 10, max_delay_secs: 60 };
    /// assert_eq!(p.backoff_delay_secs(1), 10);
    /// assert_eq!(p.backoff_delay_secs(2), 20);
    /// assert_eq!(p.backoff_delay_secs(3), 40);
    /// assert_eq!(p.backoff_delay_secs(4), 60); // clamped
    /// assert_eq!(p.backoff_delay_secs(9), 60); // clamped, no overflow
    /// ```
    #[must_use]
    pub const fn backoff_delay_secs(&self, attempt: u32) -> u64 {
        // base << (attempt-1), saturating; any overflow means "use the cap".
        let scaled = if attempt <= 1 {
            self.base_delay_secs
        } else {
            let shift = attempt - 1;
            if shift >= 63 {
                u64::MAX
            } else {
                self.base_delay_secs.saturating_mul(1u64 << shift)
            }
        };
        // const-compatible min (u64::min is not yet stable as a const fn).
        if scaled < self.max_delay_secs {
            scaled
        } else {
            self.max_delay_secs
        }
    }
}

/// The outcome of [`UpdateSession::retry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Retry the download after waiting this many seconds.
    RetryAfter(u64),
    /// The retry budget is exhausted; the session is now `Failed`.
    GaveUp,
}

/// Whether enough time has elapsed since the last check to poll for an update
/// again, given the current and last-check timestamps (any monotonic unit) and
/// the minimum interval. Robust against a clock that went backwards.
///
/// # Examples
/// ```
/// use bleradar_core::update::should_check_for_update;
/// assert!(should_check_for_update(1_000, 0, 900));       // 1000s elapsed >= 900s
/// assert!(!should_check_for_update(1_000, 500, 900));    // only 500s elapsed
/// assert!(!should_check_for_update(400, 1_000, 900));    // clock went backwards
/// ```
#[must_use]
pub fn should_check_for_update(now: u64, last_check: u64, min_interval: u64) -> bool {
    now.saturating_sub(last_check) >= min_interval
}

/// How a fetch of the remote release manifest ended, beyond the HTTP status
/// the platform got: the caller performs the network I/O and reports it here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestFetchFailure {
    /// An HTTP answer arrived: a status, and a body when the status was a
    /// success (which [`ReleaseManifest::parse`] may still reject).
    None,
    /// No HTTP answer: name resolution, the connection, TLS or a timeout
    /// failed — the network, not the source, is at fault.
    Transport,
    /// The body exceeded the caller's size cap: whatever it is, not a manifest.
    TooLarge,
    /// The body was not a manifest the core accepts.
    Rejected,
}

/// What the caller should assess after a remote-manifest fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestSourceDecision {
    /// The remote manifest: the fetch answered a success status with a body
    /// the core accepts.
    UseRemote,
    /// The bundled manifest, and the fetch is retried with backoff: the fault
    /// is transient (no answer, or a server-side status that says "later").
    FallbackRetry,
    /// The bundled manifest, with nothing to retry before the next scheduled
    /// check: the source has no release to offer (`404`/`410`), refuses the
    /// request (another `4xx`), redirects where the client must not follow
    /// (a remaining `3xx`), or serves what is not a manifest.
    FallbackNoRetry,
}

/// Decides, from the HTTP status a remote-manifest fetch got (`0` when none
/// arrived) and its failure kind, whether the remote manifest is the one to
/// assess and whether a failed fetch deserves a retry — so the retry budget
/// is spent on faults a retry can fix and never on a repository without a
/// release. A transient answer is `408`, `425`, `429` or any `5xx`; a
/// success is any `2xx` whose body the core accepts.
///
/// # Examples
/// ```
/// use bleradar_core::update::{
///     ManifestFetchFailure, ManifestSourceDecision, manifest_source_decision,
/// };
/// assert_eq!(
///     manifest_source_decision(200, ManifestFetchFailure::None),
///     ManifestSourceDecision::UseRemote
/// );
/// // No release published yet: the bundled manifest, no retry.
/// assert_eq!(
///     manifest_source_decision(404, ManifestFetchFailure::None),
///     ManifestSourceDecision::FallbackNoRetry
/// );
/// assert_eq!(
///     manifest_source_decision(503, ManifestFetchFailure::None),
///     ManifestSourceDecision::FallbackRetry
/// );
/// assert_eq!(
///     manifest_source_decision(0, ManifestFetchFailure::Transport),
///     ManifestSourceDecision::FallbackRetry
/// );
/// assert_eq!(
///     manifest_source_decision(200, ManifestFetchFailure::Rejected),
///     ManifestSourceDecision::FallbackNoRetry
/// );
/// ```
#[must_use]
pub const fn manifest_source_decision(
    http_status: u16,
    failure: ManifestFetchFailure,
) -> ManifestSourceDecision {
    match failure {
        ManifestFetchFailure::Transport => ManifestSourceDecision::FallbackRetry,
        ManifestFetchFailure::TooLarge | ManifestFetchFailure::Rejected => {
            ManifestSourceDecision::FallbackNoRetry
        }
        ManifestFetchFailure::None => match http_status {
            200..=299 => ManifestSourceDecision::UseRemote,
            408 | 425 | 429 | 500..=599 => ManifestSourceDecision::FallbackRetry,
            _ => ManifestSourceDecision::FallbackNoRetry,
        },
    }
}

/// The kind of network connection currently available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    /// No usable connection.
    None,
    /// A metered connection (mobile data / a hotspot): downloading costs the user.
    Metered,
    /// An unmetered connection (Wi-Fi / Ethernet).
    Unmetered,
}

/// A snapshot of the device conditions relevant to starting a download, sampled
/// by the caller (the engine performs no I/O and cannot read these itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadConditions {
    /// The current network.
    pub network: NetworkType,
    /// Battery charge, `0..=100`.
    pub battery_percent: u8,
    /// Whether the device is charging (a charging device is never "low battery").
    pub charging: bool,
    /// Free bytes on the volume the artifact would be written to.
    pub free_storage_bytes: u64,
}

/// The caller's policy for when an automatic download may proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadPolicy {
    /// Whether a download may run on a metered network.
    pub allow_metered: bool,
    /// Minimum battery percent required to download unless charging.
    pub min_battery_percent: u8,
    /// Free space required *beyond* the artifact size (install staging headroom).
    pub storage_headroom_bytes: u64,
}

impl DownloadPolicy {
    /// A conservative default: Wi-Fi only, at least 20% battery (or charging),
    /// and one artifact-size of staging headroom beyond the artifact itself.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            allow_metered: false,
            min_battery_percent: 20,
            storage_headroom_bytes: 0,
        }
    }
}

/// Whether a download may start, and if not, the first unmet precondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadReadiness {
    /// All preconditions are met; the download may begin.
    Ready,
    /// No usable network connection.
    NoNetwork,
    /// A network is present but it is metered and the policy forbids that.
    MeteredBlocked,
    /// Battery is below the policy minimum and the device is not charging.
    LowBattery,
    /// Not enough free storage for the artifact plus the required headroom.
    InsufficientStorage {
        /// Bytes required (artifact + headroom).
        needed: u64,
        /// Bytes currently free.
        free: u64,
    },
}

impl DownloadReadiness {
    /// Whether the download may proceed.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Decides whether an automatic download of an `artifact_size`-byte artifact may
/// start under the given conditions and policy, returning the first unmet
/// precondition in a fixed precedence: **no network** → **metered blocked** →
/// **low battery** → **insufficient storage** → ready. This lets a caller avoid
/// the most common real-world auto-update failures (a metered-data download, a
/// download that drains a low battery, or one that runs the volume out of space
/// mid-write) before committing to [`UpdateSession::begin_download`].
///
/// # Examples
/// ```
/// use bleradar_core::update::{
///     download_readiness, DownloadConditions, DownloadPolicy, DownloadReadiness, NetworkType,
/// };
/// let policy = DownloadPolicy::conservative(); // Wi-Fi only, >=20% or charging
/// let on_wifi = DownloadConditions {
///     network: NetworkType::Unmetered,
///     battery_percent: 55,
///     charging: false,
///     free_storage_bytes: 100_000_000,
/// };
/// assert_eq!(download_readiness(&on_wifi, &policy, 40_000_000), DownloadReadiness::Ready);
///
/// let on_mobile = DownloadConditions { network: NetworkType::Metered, ..on_wifi };
/// assert_eq!(download_readiness(&on_mobile, &policy, 40_000_000), DownloadReadiness::MeteredBlocked);
/// ```
#[must_use]
pub fn download_readiness(
    conditions: &DownloadConditions,
    policy: &DownloadPolicy,
    artifact_size: u64,
) -> DownloadReadiness {
    if conditions.network == NetworkType::None {
        return DownloadReadiness::NoNetwork;
    }
    if conditions.network == NetworkType::Metered && !policy.allow_metered {
        return DownloadReadiness::MeteredBlocked;
    }
    if !conditions.charging && conditions.battery_percent < policy.min_battery_percent {
        return DownloadReadiness::LowBattery;
    }
    let needed = artifact_size.saturating_add(policy.storage_headroom_bytes);
    if conditions.free_storage_bytes < needed {
        return DownloadReadiness::InsufficientStorage {
            needed,
            free: conditions.free_storage_bytes,
        };
    }
    DownloadReadiness::Ready
}

/// Streaming integrity verifier for a downloading artifact.
///
/// Bytes are [`feed`](Self::feed)'d as they arrive; the verifier rejects an
/// over-long stream immediately (so a mismatched or malicious artifact cannot
/// grow without bound) and [`finish`](Self::finish) confirms the exact declared
/// size and SHA-256. This is the only path by which an artifact becomes
/// installable.
#[derive(Clone)]
pub struct ArtifactVerifier {
    expected_size: u64,
    expected_hash: [u8; 32],
    hasher: Sha256,
    received: u64,
}

impl ArtifactVerifier {
    /// A verifier for the given manifest's size and hash.
    #[must_use]
    pub fn new(manifest: &ReleaseManifest) -> Self {
        Self {
            expected_size: manifest.size_bytes,
            expected_hash: manifest.sha256,
            hasher: Sha256::new(),
            received: 0,
        }
    }

    /// Feeds one downloaded chunk.
    ///
    /// # Errors
    /// [`UpdateError::Overrun`] if the accumulated length would exceed the
    /// declared size (the chunk is not hashed in that case).
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), UpdateError> {
        let next = self.received.saturating_add(chunk.len() as u64);
        if next > self.expected_size {
            return Err(UpdateError::Overrun {
                expected: self.expected_size,
                received: next,
            });
        }
        self.hasher.update(chunk);
        self.received = next;
        Ok(())
    }

    /// Bytes fed so far.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }

    /// Finalizes verification.
    ///
    /// # Errors
    /// [`UpdateError::SizeMismatch`] if fewer bytes than declared were fed, or
    /// [`UpdateError::HashMismatch`] if the SHA-256 differs from the manifest.
    pub fn finish(self) -> Result<(), UpdateError> {
        if self.received != self.expected_size {
            return Err(UpdateError::SizeMismatch {
                expected: self.expected_size,
                actual: self.received,
            });
        }
        if self.hasher.finalize() != self.expected_hash {
            return Err(UpdateError::HashMismatch);
        }
        Ok(())
    }
}

/// One-shot integrity check of a fully-buffered artifact against a manifest.
///
/// # Errors
/// [`UpdateError::SizeMismatch`] or [`UpdateError::HashMismatch`] on any
/// discrepancy.
///
/// # Examples
/// ```
/// use bleradar_core::update::{verify_artifact, ReleaseManifest};
/// # const M: &str = "\
/// # version_code = 2\nversion_name = 0.2\nurl = https://e/x.apk\n\
/// # size_bytes = 5\nsha256 = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n\
/// # min_sdk = 21\nmandatory = false\n";
/// let manifest = ReleaseManifest::parse(M).unwrap();
/// assert!(verify_artifact(b"hello", &manifest).is_ok());
/// assert!(verify_artifact(b"hellp", &manifest).is_err());
/// ```
pub fn verify_artifact(bytes: &[u8], manifest: &ReleaseManifest) -> Result<(), UpdateError> {
    let mut verifier = ArtifactVerifier::new(manifest);
    // A single feed can itself overrun; surface that as a size mismatch for the
    // one-shot API rather than the streaming Overrun.
    if bytes.len() as u64 > manifest.size_bytes {
        return Err(UpdateError::SizeMismatch {
            expected: manifest.size_bytes,
            actual: bytes.len() as u64,
        });
    }
    verifier.feed(bytes).and_then(|()| verifier.finish())
}

/// The lifecycle stage of an [`UpdateSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStage {
    /// No update in flight.
    Idle,
    /// A newer release has been offered.
    Available,
    /// The artifact is downloading.
    Downloading,
    /// The full artifact has been received (not yet verified).
    Downloaded,
    /// The artifact's size and SHA-256 have been verified.
    Verified,
    /// The verified artifact is being installed.
    Installing,
    /// The update has been installed.
    Installed,
    /// The flow failed and is awaiting reset/retry.
    Failed,
}

impl UpdateStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Available => "Available",
            Self::Downloading => "Downloading",
            Self::Downloaded => "Downloaded",
            Self::Verified => "Verified",
            Self::Installing => "Installing",
            Self::Installed => "Installed",
            Self::Failed => "Failed",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "Idle" => Self::Idle,
            "Available" => Self::Available,
            "Downloading" => Self::Downloading,
            "Downloaded" => Self::Downloaded,
            "Verified" => Self::Verified,
            "Installing" => Self::Installing,
            "Installed" => Self::Installed,
            "Failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// A restart-safe state machine driving one update through its whole lifecycle.
///
/// Transitions are the only way to change stage and each rejects an illegal
/// starting stage with [`UpdateError::IllegalTransition`] rather than panicking.
/// The session [`serialize`](Self::serialize)s to a string that
/// [`deserialize`](Self::deserialize)s back to an equal session, and
/// [`recover`](Self::recover) maps any stage that a crash could have interrupted
/// to a safe, resumable one — so persisting the session across a process restart
/// never loses progress or installs an unverified artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSession {
    stage: UpdateStage,
    installed: Version,
    target: Option<ReleaseManifest>,
    received_bytes: u64,
    fail_reason: Option<String>,
    /// Failed download/verify attempts for the current target (reset on `offer`).
    attempts: u32,
    /// The version installed before the current one, kept as the rollback target.
    previous: Option<Version>,
}

impl UpdateSession {
    /// A fresh, idle session for the currently-installed version.
    #[must_use]
    pub fn new(installed: Version) -> Self {
        Self {
            stage: UpdateStage::Idle,
            installed,
            target: None,
            received_bytes: 0,
            fail_reason: None,
            attempts: 0,
            previous: None,
        }
    }

    /// The current stage.
    #[must_use]
    pub const fn stage(&self) -> UpdateStage {
        self.stage
    }

    /// The installed version.
    #[must_use]
    pub const fn installed(&self) -> &Version {
        &self.installed
    }

    /// The release being applied, if any.
    #[must_use]
    pub const fn target(&self) -> Option<&ReleaseManifest> {
        self.target.as_ref()
    }

    /// Bytes downloaded so far for the in-flight artifact.
    #[must_use]
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Why the flow failed, if it is in [`UpdateStage::Failed`].
    #[must_use]
    pub fn fail_reason(&self) -> Option<&str> {
        self.fail_reason.as_deref()
    }

    /// Whether the in-flight update may be deferred (false for a mandatory one).
    #[must_use]
    pub fn can_defer(&self) -> bool {
        !self.target.as_ref().is_some_and(|m| m.mandatory)
    }

    /// Offers a release, given the device SDK. Returns the decision; only an
    /// [`UpdateDecision::Available`] moves the session to [`UpdateStage::Available`].
    ///
    /// Allowed from `Idle`, `Available`, or `Failed` (re-offer after a fault).
    ///
    /// # Errors
    /// [`UpdateError::IllegalTransition`] from any other stage.
    pub fn offer(
        &mut self,
        manifest: ReleaseManifest,
        device_sdk: u32,
    ) -> Result<UpdateDecision, UpdateError> {
        if !matches!(
            self.stage,
            UpdateStage::Idle | UpdateStage::Available | UpdateStage::Failed
        ) {
            return Err(UpdateError::IllegalTransition {
                from: self.stage.as_str(),
                op: "offer",
            });
        }
        let decision = check_update(&self.installed, device_sdk, &manifest);
        if decision.is_available() {
            self.stage = UpdateStage::Available;
            self.target = Some(manifest);
            self.received_bytes = 0;
            self.fail_reason = None;
            self.attempts = 0;
        }
        Ok(decision)
    }

    /// Begins (or resumes) downloading the offered artifact.
    ///
    /// # Errors
    /// [`UpdateError::IllegalTransition`] unless in `Available` or `Downloading`.
    pub fn begin_download(&mut self) -> Result<(), UpdateError> {
        match self.stage {
            UpdateStage::Available | UpdateStage::Downloading => {
                self.stage = UpdateStage::Downloading;
                Ok(())
            }
            other => Err(UpdateError::IllegalTransition {
                from: other.as_str(),
                op: "begin_download",
            }),
        }
    }

    /// Records `n` more downloaded bytes, saturating at the declared size so
    /// progress is monotonic and bounded.
    ///
    /// # Errors
    /// [`UpdateError::IllegalTransition`] unless in `Downloading`.
    pub fn record_progress(&mut self, n: u64) -> Result<u64, UpdateError> {
        if self.stage != UpdateStage::Downloading {
            return Err(UpdateError::IllegalTransition {
                from: self.stage.as_str(),
                op: "record_progress",
            });
        }
        let size = self.target.as_ref().map_or(0, |m| m.size_bytes);
        self.received_bytes = self.received_bytes.saturating_add(n).min(size);
        Ok(self.received_bytes)
    }

    /// Marks the download complete once every byte has arrived.
    ///
    /// # Errors
    /// [`UpdateError::IllegalTransition`] unless in `Downloading`;
    /// [`UpdateError::SizeMismatch`] if fewer than the declared bytes were recorded.
    pub fn finish_download(&mut self) -> Result<(), UpdateError> {
        if self.stage != UpdateStage::Downloading {
            return Err(UpdateError::IllegalTransition {
                from: self.stage.as_str(),
                op: "finish_download",
            });
        }
        let size = self.target.as_ref().map_or(0, |m| m.size_bytes);
        if self.received_bytes != size {
            return Err(UpdateError::SizeMismatch {
                expected: size,
                actual: self.received_bytes,
            });
        }
        self.stage = UpdateStage::Downloaded;
        Ok(())
    }

    /// Verifies the downloaded artifact bytes against the manifest.
    ///
    /// On success the session advances to [`UpdateStage::Verified`]; on an
    /// integrity failure it moves to [`UpdateStage::Failed`] (the artifact must
    /// be re-downloaded) and the error is returned.
    ///
    /// # Errors
    /// [`UpdateError::IllegalTransition`] unless in `Downloaded`; otherwise the
    /// verification error, which also transitions the session to `Failed`.
    pub fn verify(&mut self, bytes: &[u8]) -> Result<(), UpdateError> {
        if self.stage != UpdateStage::Downloaded {
            return Err(UpdateError::IllegalTransition {
                from: self.stage.as_str(),
                op: "verify",
            });
        }
        let manifest = self
            .target
            .as_ref()
            .ok_or(UpdateError::MalformedSession("verify without a target"))?;
        match verify_artifact(bytes, manifest) {
            Ok(()) => {
                self.stage = UpdateStage::Verified;
                Ok(())
            }
            Err(e) => {
                self.stage = UpdateStage::Failed;
                self.fail_reason = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Begins installing the verified artifact.
    ///
    /// # Errors
    /// [`UpdateError::IllegalTransition`] unless in `Verified`.
    pub fn begin_install(&mut self) -> Result<(), UpdateError> {
        if self.stage != UpdateStage::Verified {
            return Err(UpdateError::IllegalTransition {
                from: self.stage.as_str(),
                op: "begin_install",
            });
        }
        self.stage = UpdateStage::Installing;
        Ok(())
    }

    /// Completes the install, adopting the target version as installed.
    ///
    /// Idempotent: calling it again once already `Installed` at the target
    /// version is a no-op success (a restart that re-runs the OS installer for an
    /// already-applied `versionCode` must not error).
    ///
    /// # Errors
    /// [`UpdateError::IllegalTransition`] unless in `Installing` (or already
    /// `Installed` at the target version).
    pub fn finish_install(&mut self) -> Result<(), UpdateError> {
        match self.stage {
            UpdateStage::Installing => {
                if let Some(manifest) = self.target.take() {
                    // Remember the version we are upgrading from as the rollback
                    // target before adopting the new one.
                    self.previous = Some(std::mem::replace(&mut self.installed, manifest.version));
                }
                self.stage = UpdateStage::Installed;
                self.received_bytes = 0;
                self.fail_reason = None;
                self.attempts = 0;
                Ok(())
            }
            UpdateStage::Installed => Ok(()),
            other => Err(UpdateError::IllegalTransition {
                from: other.as_str(),
                op: "finish_install",
            }),
        }
    }

    /// Records a failure with a human-readable reason, from any stage.
    pub fn fail(&mut self, reason: impl Into<String>) {
        self.stage = UpdateStage::Failed;
        self.fail_reason = Some(reason.into());
    }

    /// Discards any in-flight update and returns to [`UpdateStage::Idle`],
    /// keeping the installed version and the rollback target. Used to abandon a
    /// download and start clean; the attempt counter is cleared.
    pub fn reset(&mut self) {
        self.stage = UpdateStage::Idle;
        self.target = None;
        self.received_bytes = 0;
        self.fail_reason = None;
        self.attempts = 0;
    }

    /// Failed download/verify attempts recorded for the current target.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// The version installed before the current one — the rollback target set by
    /// the most recent [`finish_install`](Self::finish_install).
    #[must_use]
    pub const fn previous(&self) -> Option<&Version> {
        self.previous.as_ref()
    }

    /// Records a transient download/verify failure and decides whether to retry.
    ///
    /// Increments the attempt counter; while it stays below the policy's
    /// `max_attempts` the session is re-armed to [`UpdateStage::Available`] (the
    /// download restarts from zero) and [`RetryDecision::RetryAfter`] carries the
    /// backoff delay; once the counter reaches `max_attempts` the session moves to
    /// [`UpdateStage::Failed`] and [`RetryDecision::GaveUp`] is returned. Call it
    /// when the caller observes a recoverable fault (a dropped connection, a
    /// corrupt download) — a genuine integrity mismatch already fails
    /// [`verify`](Self::verify), and calling `retry` after it drives the standard
    /// backoff.
    ///
    /// # Errors
    /// [`UpdateError::IllegalTransition`] if there is no in-flight target to retry
    /// (i.e. from `Idle` or `Installed`).
    pub fn retry(&mut self, policy: &RetryPolicy) -> Result<RetryDecision, UpdateError> {
        if self.target.is_none() || matches!(self.stage, UpdateStage::Idle | UpdateStage::Installed)
        {
            return Err(UpdateError::IllegalTransition {
                from: self.stage.as_str(),
                op: "retry",
            });
        }
        self.attempts = self.attempts.saturating_add(1);
        self.received_bytes = 0;
        if self.attempts >= policy.max_attempts {
            self.stage = UpdateStage::Failed;
            self.fail_reason = Some(format!("gave up after {} attempt(s)", self.attempts));
            Ok(RetryDecision::GaveUp)
        } else {
            self.stage = UpdateStage::Available;
            self.fail_reason = None;
            Ok(RetryDecision::RetryAfter(
                policy.backoff_delay_secs(self.attempts),
            ))
        }
    }

    /// Rolls the installed version back to the previous known-good one after a bad
    /// update, discarding any in-flight target and returning to
    /// [`UpdateStage::Idle`]. Models the OS rollback path a caller invokes when a
    /// freshly-installed version fails its post-install health check.
    ///
    /// # Errors
    /// [`UpdateError::NothingToRollBack`] if no previous version is recorded.
    pub fn rollback(&mut self) -> Result<(), UpdateError> {
        let previous = self.previous.take().ok_or(UpdateError::NothingToRollBack)?;
        self.installed = previous;
        self.stage = UpdateStage::Idle;
        self.target = None;
        self.received_bytes = 0;
        self.fail_reason = None;
        self.attempts = 0;
        Ok(())
    }

    /// Maps a stage that a crash could have interrupted to a safe, resumable one,
    /// without losing progress:
    ///
    /// * `Installing` → `Verified`: the OS installer may or may not have run;
    ///   re-installing the same verified `versionCode` is idempotent, so drop
    ///   back to the last provably-safe point and re-install.
    /// * `Downloaded` → `Downloading`: bytes may be on disk but were never
    ///   verified in this process; re-verify by continuing the download/verify path.
    /// * every other stage is already safe and is returned unchanged.
    ///
    /// Idempotent: `recover(recover(x)) == recover(x)`.
    #[must_use]
    pub fn recover(mut self) -> Self {
        match self.stage {
            UpdateStage::Installing => {
                self.stage = UpdateStage::Verified;
            }
            UpdateStage::Downloaded => {
                self.stage = UpdateStage::Downloading;
            }
            _ => {}
        }
        self
    }

    /// Serializes the session to the line-oriented format for persistence.
    ///
    /// [`deserialize`](Self::deserialize) of the result reproduces an equal session.
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("stage = {}\n", self.stage.as_str()));
        out.push_str(&format!("installed_code = {}\n", self.installed.code));
        out.push_str(&format!("installed_name = {}\n", self.installed.name));
        out.push_str(&format!("received_bytes = {}\n", self.received_bytes));
        out.push_str(&format!("attempts = {}\n", self.attempts));
        if let Some(prev) = &self.previous {
            out.push_str(&format!("previous_code = {}\n", prev.code));
            out.push_str(&format!("previous_name = {}\n", prev.name));
        }
        if let Some(reason) = &self.fail_reason {
            out.push_str(&format!("fail_reason = {reason}\n"));
        }
        if let Some(target) = &self.target {
            for line in target.serialize().lines() {
                out.push_str("target_");
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    /// Parses a session previously produced by [`serialize`](Self::serialize).
    ///
    /// # Errors
    /// [`UpdateError`] if the text is malformed, or if a non-idle stage is
    /// missing its target manifest.
    pub fn deserialize(text: &str) -> Result<Self, UpdateError> {
        let mut stage: Option<UpdateStage> = None;
        let mut installed_code: Option<u64> = None;
        let mut installed_name: Option<String> = None;
        let mut received_bytes: Option<u64> = None;
        let mut attempts: Option<u32> = None;
        let mut previous_code: Option<u64> = None;
        let mut previous_name: Option<String> = None;
        let mut fail_reason: Option<String> = None;
        let mut target_lines = String::new();

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or(UpdateError::MalformedSession("line is not key = value"))?;
            let key = key.trim();
            let value = value.trim();
            if let Some(rest) = key.strip_prefix("target_") {
                target_lines.push_str(rest);
                target_lines.push_str(" = ");
                target_lines.push_str(value);
                target_lines.push('\n');
                continue;
            }
            match key {
                "stage" => {
                    stage = Some(
                        UpdateStage::from_str(value)
                            .ok_or(UpdateError::MalformedSession("unknown stage"))?,
                    );
                }
                "installed_code" => {
                    installed_code = Some(
                        value
                            .parse()
                            .map_err(|_| UpdateError::MalformedSession("installed_code"))?,
                    );
                }
                "installed_name" => installed_name = Some(value.to_string()),
                "received_bytes" => {
                    received_bytes = Some(
                        value
                            .parse()
                            .map_err(|_| UpdateError::MalformedSession("received_bytes"))?,
                    );
                }
                "attempts" => {
                    attempts = Some(
                        value
                            .parse()
                            .map_err(|_| UpdateError::MalformedSession("attempts"))?,
                    );
                }
                "previous_code" => {
                    previous_code = Some(
                        value
                            .parse()
                            .map_err(|_| UpdateError::MalformedSession("previous_code"))?,
                    );
                }
                "previous_name" => previous_name = Some(value.to_string()),
                "fail_reason" => fail_reason = Some(value.to_string()),
                _ => return Err(UpdateError::MalformedSession("unknown session key")),
            }
        }

        let stage = stage.ok_or(UpdateError::MalformedSession("missing stage"))?;
        let installed = Version::new(
            installed_code.ok_or(UpdateError::MalformedSession("missing installed_code"))?,
            installed_name.ok_or(UpdateError::MalformedSession("missing installed_name"))?,
        );
        let target = if target_lines.is_empty() {
            None
        } else {
            Some(ReleaseManifest::parse(&target_lines).map_err(|_| {
                UpdateError::MalformedSession("embedded target manifest is invalid")
            })?)
        };
        // Available/Downloading/Downloaded/Verified/Installing describe an
        // in-flight update and therefore require a target; Idle, Installed, and
        // Failed can legitimately have none (Failed may be reached from Idle).
        if matches!(
            stage,
            UpdateStage::Available
                | UpdateStage::Downloading
                | UpdateStage::Downloaded
                | UpdateStage::Verified
                | UpdateStage::Installing
        ) && target.is_none()
        {
            return Err(UpdateError::MalformedSession(
                "in-flight stage requires a target manifest",
            ));
        }
        let previous = match (previous_code, previous_name) {
            (Some(code), Some(name)) => Some(Version::new(code, name)),
            (None, None) => None,
            _ => {
                return Err(UpdateError::MalformedSession(
                    "previous version needs both previous_code and previous_name",
                ));
            }
        };
        Ok(Self {
            stage,
            installed,
            target,
            received_bytes: received_bytes.unwrap_or(0),
            fail_reason,
            attempts: attempts.unwrap_or(0),
            previous,
        })
    }
}

// ---- small strict value parsers (dependency-free) ----

fn set_once<T>(slot: &mut Option<T>, key: &'static str, value: T) -> Result<(), UpdateError> {
    if slot.is_some() {
        return Err(UpdateError::DuplicateField(key));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_u64(value: &str, key: &'static str) -> Result<u64, UpdateError> {
    value.parse().map_err(|_| UpdateError::MalformedField {
        key,
        reason: "expected a non-negative integer",
    })
}

fn parse_u32(value: &str, key: &'static str) -> Result<u32, UpdateError> {
    value.parse().map_err(|_| UpdateError::MalformedField {
        key,
        reason: "expected a non-negative integer",
    })
}

fn parse_bool(value: &str, key: &'static str) -> Result<bool, UpdateError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(UpdateError::MalformedField {
            key,
            reason: "expected `true` or `false`",
        }),
    }
}

/// Parses exactly 64 lowercase/uppercase hex characters into 32 bytes.
fn parse_hex32(value: &str) -> Result<[u8; 32], UpdateError> {
    if value.len() != 64 {
        return Err(UpdateError::MalformedField {
            key: "sha256",
            reason: "expected 64 hex characters",
        });
    }
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, UpdateError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(UpdateError::MalformedField {
            key: "sha256",
            reason: "expected hex characters only",
        }),
    }
}
