//! Huntsman Search Engine (HSE) entity model, ported dependency-free into this
//! crate from `hse-core` (see `docs/HSE_IMPORT.md`).
//!
//! The port preserves the architecture invariants of the original:
//!
//! - SHA-256 deterministic UIDs (`hex(SHA-256("<kind>:<identity-folded value>"))`),
//!   implemented with the in-crate [`Sha256`] so the workspace stays
//!   third-party-dependency-free.
//! - GREATEST-semantics merge (confidence, corroboration only ever increase).
//! - `C_eff = clamp(max(C × (1 + 0.15·ln n), 1 − (1−C)·0.65^(n−1)), 0.0, 1.0)`,
//!   where `n = source_count()` (distinct corroborating sources) — NOT the raw
//!   `corroboration` field, a separate per-module observation magnitude. See
//!   [`HseEntity::c_effective`] and [`HseEntity::source_count`].
//! - `classify()` is derived-only from `C_eff`.
//! - No unsafe, no third-party crates.
//!
//! Deliberate port adaptations, all behaviour-preserving for explicit inputs:
//!
//! - The type is named [`HseEntity`] (with [`HseEntityKind`], [`HseEvidence`],
//!   [`HseVerificationMethod`], [`HseClassification`], [`HseEntityRef`],
//!   [`HseEntityBuilder`]) because this crate's canonical evidence engine
//!   (`crate::evidence`) already owns the unprefixed `Entity`/`Evidence`/
//!   `EntityKind` names.
//! - Wall-clock timestamps are explicit constructor parameters
//!   (`recorded_at`/`observed_at`), so every value is fully deterministic and
//!   reproducible; [`decayed_confidence_at`][HseEntity::decayed_confidence_at]
//!   applies gamma decay against a caller-supplied "now".
//! - Serde serialization is not ported (it is presentation/storage glue, not
//!   engine semantics, and would violate the zero-dependency policy).
//! - Coordinates resolve to [`crate::geo::LatLon`], reused rather than
//!   duplicating a second geo type.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::BuildHasher;

use crate::coords;
use crate::tags;

/// Pure-integer FIPS 180-4 SHA-256 over a streaming byte input.
///
/// Dependency-free stand-in for the `sha2` crate used by the original module:
/// the workspace is intentionally third-party-free
/// (`docs/AUTONOMOUS_DECISIONS.md`, decision 9), and the UID contract only
/// needs the standard hash. Verified in tests against published FIPS vectors.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    /// A fresh hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed bytes into the hash.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut block_arr = [0u8; 64];
            block_arr.copy_from_slice(block);
            self.compress(&block_arr);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Finish and return the 32-byte digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        // Length is appended manually (not via `update`) so it is not counted
        // in `total_len`.
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);
        let mut out = [0u8; 32];
        for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *chunk = word.to_be_bytes();
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, &chunk) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(chunk);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Lowercase hex encoding of bytes — the `hex::encode` stand-in.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Tracking query-parameter keys that are safe to drop during URL
/// canonicalisation. The single definition shared by every URL-handling
/// consumer, so there is exactly one tracking-param list, not a mirror.
const URL_TRACKING_PARAMS: &[&str] = &[
    // Google / Ads
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "_ga",
    "_gl",
    // Facebook / Instagram / Meta
    "fbclid",
    "fb_action_ids",
    "fb_action_types",
    "fb_ref",
    "fb_source",
    "igshid",
    "igsh",
    "mibextid",
    // Microsoft / Bing, Twitter/X, Yandex
    "msclkid",
    "twclid",
    "ref_src",
    "ref_url",
    "yclid",
    // Email / marketing automation
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    "_hsenc",
    "_hsmi",
    "hsctatracking",
    "vero_id",
    "vero_conv",
    "oly_anon_id",
    "oly_enc_id",
    "wickedid",
    // Misc analytics
    "spm",
    "scm",
    "s_kwcid",
    "_openstat",
    "icid",
];

/// True when a query-parameter key is pure tracking and safe to drop during
/// URL canonicalisation: the `utm_*` family (case-insensitive prefix) or an
/// exact (case-insensitive) match in `URL_TRACKING_PARAMS`. Uses `get(..4)`
/// rather than slicing so a non-ASCII key can never panic on a char boundary.
#[must_use]
pub fn is_tracking_param_key(key: &str) -> bool {
    if key.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("utm_")) {
        return true;
    }
    URL_TRACKING_PARAMS
        .iter()
        .any(|p| key.eq_ignore_ascii_case(p))
}

// ─── Constants ───────────────────────────────────────────────────────────────

/// Corroboration boost coefficient (architecture invariant).
pub const CORROBORATION_COEFF: f64 = 0.15;

/// Residual-doubt decay per *additional* independent source in the
/// agreement model of [`HseEntity::c_effective`]. Each distinct corroborating
/// source shrinks the remaining doubt `(1 − confidence)` by this factor, so
/// independent agreement drives confidence toward certainty: at `0.65`, a
/// moderate finding (C=0.6) reaches ~0.74 at 2 sources and ~0.83 (Verified) at
/// 3 — which the purely-multiplicative model badly under-credits (0.66 / 0.73).
pub const CORROBORATION_DOUBT_DECAY: f64 = 0.65;

/// Confidence decay constant per hour (γ = 0.85).
pub const GAMMA_PER_HOUR: f64 = 0.85;

/// Confidence ceiling a **quarantined** entity is capped to: a finding sourced
/// from a record that does NOT match the scan target's identity (a stranger
/// from a broad breach/stealer search) is preserved as a lead at this strength
/// rather than discarded, but must never reach the correlated, default-view
/// tier. Deliberately below [`HseClassification::PROBABLE_MIN`] (0.40) so a
/// demoted entity always classifies as `Candidate`. The demotion itself is
/// [`HseEntity::demote_to_candidate`] — one definition shared by every pool
/// (the matcher that DECIDES a non-match lives with the caller, keeping "does
/// this match?" orthogonal to "tier it").
pub const CANDIDATE_CONF: f64 = 0.25;

/// Evidence "sources" that are deterministic self-enrichment passes the engine
/// runs over every entity of a given kind — NOT independent intelligence.
///
/// These are pure, deterministic transforms of the seed or of an entity already
/// in the graph, with no external observation of their own (a parse, a
/// canonicalisation, a permutation, a prefix-table classification). Their
/// evidence is still kept in the chain (the attributes are real and useful) and
/// still appears in [`HseEntity::evidence_sources`] for display; they are only
/// excluded from the *corroboration* count — see
/// [`HseEntity::corroborating_sources`]. Counting one as a corroborating source
/// let a pure guess present as "corroborated by N independent sources".
pub const ENRICHMENT_ONLY_SOURCES: &[&str] = &[
    "breach_timezone",
    "discord_snowflake",
    "email_canonical",
    "email_header_geo",
    "email_locale",
    "email_parse",
    "geo_domain_classifier",
    "geo_normalize",
    "name_intel",
    "payid",
    "phone_au",
    "phone_geo",
    "phone_intl",
    "seed",
    "structured_id",
    "url_extract",
    "username_variants",
];

/// True if `source` is a deterministic self-enrichment pass rather than an
/// independent intelligence source (see [`ENRICHMENT_ONLY_SOURCES`]).
#[inline]
#[must_use]
pub fn is_enrichment_source(source: &str) -> bool {
    ENRICHMENT_ONLY_SOURCES.contains(&source)
}

/// Canonical comparison form of a handle: ASCII-lowercased with the handle
/// separators (`.`, `_`, `-`) removed, so equivalent spellings across services
/// collapse to one token.
#[must_use]
pub fn canonical_handle(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '.' | '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Evidence source name of the recall pass — the local-database replay that
/// re-injects a prior scan's entity into the working set.
///
/// Recall is a SECOND look at the SAME prior observation, not a new independent
/// one, so it must never count toward cross-source corroboration. The recall
/// evidence is still attached (and shown in [`HseEntity::evidence_sources`])
/// for provenance; it just can't inflate [`HseEntity::source_count`] /
/// `c_effective`.
pub const RECALL_SOURCE: &str = "recall";

/// Evidence source name of the cross-scan history link — the pass that notes a
/// finding ALSO appears in an earlier scan in the local intelligence database.
///
/// Like [`RECALL_SOURCE`] this is provenance, not an independent observation: a
/// recurrence can't tell a re-scan of the same subject from a genuinely
/// separate sighting. The `cross_scan_history` evidence is kept and shown for
/// the analyst — it is what SURFACES the link between two investigations — but
/// it must never inflate [`HseEntity::source_count`] / `c_effective`.
pub const CROSS_SCAN_SOURCE: &str = "cross_scan_history";

/// Evidence source name of a breach-consensus grading pass.
///
/// The pass reads the evidence breach modules already attached and records how
/// many DISTINCT corpora attest each finding. It is a *summary of* those
/// observations, not a new one — counting it would let an entity corroborate
/// itself. The summary is attached (and is what the audit trail reads) but,
/// like [`RECALL_SOURCE`] and [`CROSS_SCAN_SOURCE`], it can never inflate
/// [`HseEntity::source_count`] / `c_effective`.
pub const CONSENSUS_SOURCE: &str = "breach_consensus";

/// Evidence source name emitted by a multipath-corroboration promotion pass.
///
/// This is a DERIVED signal: it records that two identity endpoints were found
/// connected across ≥2 edge-disjoint paths — it is NOT a new independent data
/// source. It may amplify an already-grounded entity's `source_count`, but it
/// must never be the sole reason an entity is considered corroborated (see
/// [`HseEntity::source_count`]).
pub const MULTIPATH_CORROBORATION_SOURCE: &str = "multipath_corroboration";

/// Evidence source name emitted by a cross-scan-corroboration promotion pass.
///
/// Same semantics as [`MULTIPATH_CORROBORATION_SOURCE`]: engine-derived signal,
/// not an independent observation.
pub const CROSS_SCAN_CORROBORATION_SOURCE: &str = "cross_scan_corroboration";

/// Evidence source name emitted by geo-corroboration promotion passes.
/// Engine-derived agreement signal, not an independent observation.
pub const GEO_CORROBORATION_SOURCE: &str = "geo_corroboration";

/// True if `source` is an engine **promotion pass** rather than an independent
/// observation. Promotion passes amplify entities that are already grounded by
/// real sources; they must never GROUND an entity by themselves.
///
/// This is distinct from [`is_non_corroborating_source`]: non-corroborating
/// sources are NEVER counted; promotion sources ARE counted, but only when the
/// entity already has at least one real corroborating source (the grounding
/// gate in [`HseEntity::source_count`]).
#[inline]
#[must_use]
pub fn is_promotion_source(source: &str) -> bool {
    source == MULTIPATH_CORROBORATION_SOURCE || source == CROSS_SCAN_CORROBORATION_SOURCE
}

/// True if `source` is an engine-derived corroboration signal — multipath,
/// cross-scan, or geo agreement — rather than an independent observation. Such
/// a signal records that existing sources agree, so counting it as its own
/// source family would manufacture a phantom orthogonal source family. Broader
/// than [`is_promotion_source`]: `geo_corroboration` still counts as a real
/// source for corroboration DEPTH, but must never add family BREADTH.
#[inline]
#[must_use]
pub fn is_engine_corroboration_source(source: &str) -> bool {
    source == MULTIPATH_CORROBORATION_SOURCE
        || source == CROSS_SCAN_CORROBORATION_SOURCE
        || source == GEO_CORROBORATION_SOURCE
}

/// True if `source` must NOT count toward cross-source corroboration — a
/// deterministic self-enrichment pass ([`ENRICHMENT_ONLY_SOURCES`]), the recall
/// replay ([`RECALL_SOURCE`]), the cross-scan history link
/// ([`CROSS_SCAN_SOURCE`]), or the breach-consensus summary
/// ([`CONSENSUS_SOURCE`]). All attach genuine, useful evidence, but none is an
/// independent observation, so none may inflate the corroboration count.
#[inline]
#[must_use]
pub fn is_non_corroborating_source(source: &str) -> bool {
    is_enrichment_source(source)
        || source == RECALL_SOURCE
        || source == CROSS_SCAN_SOURCE
        || source == CONSENSUS_SOURCE
}

// ─── EntityKind ──────────────────────────────────────────────────────────────

/// All value types an HSE entity can represent.
///
/// People-centric kinds (Person, Email, Phone, Username) are weighted highest
/// in module priority ordering. Infrastructure kinds are enrichment targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HseEntityKind {
    /// A person's name.
    Person,
    /// An email address.
    Email,
    /// A phone number.
    Phone,
    /// A username / handle.
    Username,
    /// A document / credential pair.
    Credential,
    /// An API key.
    ApiKey,
    /// A password (never stored in evidence output).
    Password,
    /// An IP address.
    IpAddress,
    /// A DNS domain.
    Domain,
    /// A URL.
    Url,
    /// An autonomous system number.
    Asn,
    /// A CIDR network block (`192.0.2.0/24`, `2001:db8::/48`). A scannable
    /// target that expands into its constituent host IPs (bounded).
    Cidr,
    /// A physical / postal address.
    Address,
    /// Geographic coordinates.
    Coordinates,
    /// An organisation name.
    Organisation,
    /// An Australian Business/Company Number.
    AbnAcn,
    /// A MAC address.
    MacAddress,
    /// A device identifier.
    DeviceId,
    /// A WiFi network name (SSID). A *unique* SSID is geolocatable via
    /// wardriving databases; generic/default names (`NETGEAR`, `iPhone`, …)
    /// are not.
    Ssid,
    /// A web-analytics / tracking identifier (Google Analytics `UA-`/`G-`, GTM
    /// `GTM-`, AdSense `ca-pub-`, Facebook Pixel, …). A shared ID across
    /// otherwise-unrelated sites is strong evidence of common ownership — a
    /// correlation node only, never a scannable target.
    TrackingId,
    /// A cryptocurrency wallet address (BTC/ETH/LTC/…). Case-sensitive
    /// (base58 / bech32 / 0x-hex) and the pivot point for chain-explorer
    /// enrichment.
    CryptoAddress,
    /// Catch-all for kinds outside the closed set.
    Other(String),
}

impl fmt::Display for HseEntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Person => f.write_str("person"),
            Self::Email => f.write_str("email"),
            Self::Phone => f.write_str("phone"),
            Self::Username => f.write_str("username"),
            Self::Credential => f.write_str("credential"),
            Self::ApiKey => f.write_str("api_key"),
            Self::Password => f.write_str("password"),
            Self::IpAddress => f.write_str("ip_address"),
            Self::Domain => f.write_str("domain"),
            Self::Url => f.write_str("url"),
            Self::Asn => f.write_str("asn"),
            Self::Cidr => f.write_str("cidr"),
            Self::Address => f.write_str("address"),
            Self::Coordinates => f.write_str("coordinates"),
            Self::Organisation => f.write_str("organisation"),
            Self::AbnAcn => f.write_str("abn_acn"),
            Self::MacAddress => f.write_str("mac_address"),
            Self::DeviceId => f.write_str("device_id"),
            Self::Ssid => f.write_str("ssid"),
            Self::TrackingId => f.write_str("tracking_id"),
            Self::CryptoAddress => f.write_str("crypto_address"),
            Self::Other(s) => write!(f, "other:{s}"),
        }
    }
}

// ─── Classification ───────────────────────────────────────────────────────────

/// Derived-only classification tier from `C_eff`.
///
/// Never set directly — always call [`HseEntity::classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HseClassification {
    /// `C_eff < 0.40`
    Candidate,
    /// `0.40 ≤ C_eff < 0.75`
    Probable,
    /// `C_eff ≥ 0.75`
    Verified,
}

impl HseClassification {
    /// Lower bound of the Verified tier: `C_eff ≥ VERIFIED_MIN`.
    ///
    /// The tier ladder's single source of truth (with [`Self::PROBABLE_MIN`]).
    pub const VERIFIED_MIN: f64 = 0.75;
    /// Lower bound of the Probable tier: `C_eff ≥ PROBABLE_MIN` (and below
    /// [`Self::VERIFIED_MIN`]). Below this is Candidate.
    pub const PROBABLE_MIN: f64 = 0.40;

    /// The tier for an effective confidence — the canonical ladder. A
    /// non-finite `c_eff` (never produced by `c_effective`, which clamps)
    /// fails both bounds and lands in `Candidate`, the conservative tier.
    #[inline]
    #[must_use]
    pub fn from_c_eff(c_eff: f64) -> Self {
        if c_eff >= Self::VERIFIED_MIN {
            Self::Verified
        } else if c_eff >= Self::PROBABLE_MIN {
            Self::Probable
        } else {
            Self::Candidate
        }
    }

    /// The tier's stable label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "CANDIDATE",
            Self::Probable => "PROBABLE",
            Self::Verified => "VERIFIED",
        }
    }

    /// Stable, dense tier rank (0 = Candidate, 1 = Probable, 2 = Verified).
    ///
    /// This is the finite tier ladder intended to back a bounded best-first
    /// expansion: with a `(target, tier)` visited-set an entity is expanded at
    /// most once per rank, and because there are exactly
    /// [`HseClassification::COUNT`] ranks, total expansions are bounded by
    /// `entities × COUNT`.
    #[inline]
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Candidate => 0,
            Self::Probable => 1,
            Self::Verified => 2,
        }
    }

    /// Number of distinct confidence tiers. Fixed and finite — the
    /// multiplier in the halting bound `expansions ≤ entities × COUNT`.
    pub const COUNT: u8 = 3;
}

impl fmt::Display for HseClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Evidence ────────────────────────────────────────────────────────────────

/// Verification method for account ownership or data derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HseVerificationMethod {
    /// Account email matches a known entity's email.
    EmailLinked,
    /// Platform-native verification (checkmark, badge, official status).
    PlatformVerified,
    /// Activity proof: recent posts, followers, creation signals.
    ActivityProof,
    /// Self-disclosure: bio, pinned post, or explicit linking to other identity.
    SelfDisclosed,
    /// Account linked to another entity's profile.
    LinkedProfile,
    /// Unverified handle enumeration (present on platform, ownership unknown).
    Unverified,
}

/// A single piece of evidence attached to an HSE entity.
#[derive(Debug, Clone)]
pub struct HseEvidence {
    /// Module that produced this evidence.
    pub source: String,
    /// Human-readable summary / label for the record (not the raw data itself).
    pub summary: String,
    /// Raw key/value pairs from the module — the FULL source record, preserved
    /// verbatim for traceability. `BTreeMap` (not `HashMap`) so the serialised
    /// evidence has a stable, sorted key order — identical findings must
    /// produce byte-identical output (reproducibility / hashable evidence
    /// chains), and HashMap iteration order is randomised per instance.
    pub attributes: BTreeMap<String, String>,
    /// Unix timestamp (seconds) when evidence was recorded. Explicit (never
    /// captured from a wall clock inside this crate) so every value is
    /// reproducible.
    pub recorded_at: u64,
    /// Verification status for account/handle ownership. None if not applicable.
    /// Marked at evidence creation and propagated through correlations to gate
    /// account-attribution rules — prevents unverified accounts from being
    /// linked to persons.
    pub verification: Option<HseVerificationMethod>,
    /// True if this evidence represents a derivation or inference rather than
    /// a direct observation. Inferred data (e.g., names permuted from
    /// usernames, coordinates calculated from addresses) must be
    /// confidence-capped and should decay confidence in downstream
    /// correlations.
    pub is_inferred: bool,
    /// Id of the scan that produced this evidence. Backfilled from the owning
    /// entity in [`HseEntity::add_evidence`] when not set explicitly, so
    /// per-record provenance survives multi-scan merges.
    pub scan_id: String,
}

impl HseEvidence {
    /// A new evidence record with empty attributes, recorded at
    /// `recorded_at` (Unix seconds).
    pub fn new(source: impl Into<String>, summary: impl Into<String>, recorded_at: u64) -> Self {
        Self {
            source: source.into(),
            summary: summary.into(),
            attributes: BTreeMap::new(),
            recorded_at,
            verification: None,
            is_inferred: false,
            scan_id: String::new(),
        }
    }

    /// Attach a key/value attribute, **accumulating** rather than clobbering
    /// when the key is already present.
    ///
    /// Operator full-fidelity policy: a repeated key must not silently lose its
    /// earlier value — e.g. several breach rows folded into one evidence
    /// record, each carrying a different `gender`, `date_of_birth`, or
    /// `country`. On collision the new value is appended after `"; "`,
    /// **de-duplicated** so re-asserting an identical value is idempotent and
    /// the merged cell never bloats with repeats. The first-seen value stays
    /// first and single-set callers — the overwhelming majority — are
    /// byte-for-byte unchanged.
    #[must_use]
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let value = value.into();
        match self.attributes.get_mut(&key) {
            Some(existing) => {
                if !existing.split("; ").any(|seen| seen == value) {
                    existing.push_str("; ");
                    existing.push_str(&value);
                }
            }
            None => {
                self.attributes.insert(key, value);
            }
        }
        self
    }

    /// Attach several **optional** attributes in one call: each pair whose
    /// value is `Some` and trims to a non-empty string is added via
    /// [`with_attr`](Self::with_attr) (so its accumulate-on-collision semantics
    /// are unchanged); `None` or blank values are skipped.
    #[must_use]
    pub fn with_optional_attrs<'a>(
        mut self,
        attrs: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
    ) -> Self {
        for (k, v) in attrs {
            if let Some(v) = v.map(str::trim).filter(|s| !s.is_empty()) {
                self = self.with_attr(k, v);
            }
        }
        self
    }

    /// The individual values behind `key` — the **inverse of
    /// [`with_attr`](Self::with_attr)'s accumulation**, and the only correct
    /// way to read an attribute that can hold more than one.
    ///
    /// [`with_attr`](Self::with_attr) and `merge_evidence_attrs` join colliding
    /// values with `"; "`, so a key that looks single-valued at the call site
    /// can hold `"alice; bob_work"` by the time a rule reads it. A consumer
    /// that reads `attributes.get(key)` whole then sees ONE opaque string:
    /// identity rules counting distinct accounts silently count 1 where there
    /// are 2, and their firing gate can never be met.
    ///
    /// Yields trimmed, non-empty parts; absent keys yield nothing.
    ///
    /// ```
    /// use bleradar_core::HseEvidence;
    ///
    /// let ev = HseEvidence::new("oathnet", "Breach on ForumX", 1_700_000_000)
    ///     .with_attr("username", "alice")
    ///     .with_attr("username", "bob_work");
    /// assert_eq!(ev.attr_values("username").collect::<Vec<_>>(), ["alice", "bob_work"]);
    /// assert_eq!(ev.attr_values("absent").count(), 0);
    /// ```
    pub fn attr_values<'a>(&'a self, key: &str) -> impl Iterator<Item = &'a str> + 'a {
        self.attributes
            .get(key)
            .into_iter()
            .flat_map(|v| v.split("; "))
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// Set the verification status for this evidence (used to mark account
    /// ownership verification).
    #[must_use]
    pub fn with_verification(mut self, v: HseVerificationMethod) -> Self {
        self.verification = Some(v);
        self
    }

    /// Mark this evidence as inferred/derived rather than directly observed.
    #[must_use]
    pub fn with_inferred(mut self, inferred: bool) -> Self {
        self.is_inferred = inferred;
        self
    }
}

// ─── Entity ───────────────────────────────────────────────────────────────────

/// Core HSE entity.
///
/// # UID derivation
/// `uid = hex(SHA-256(kind_str + ":" + identity_fold(normalised_value)))`
///
/// # Confidence formula
/// `C_eff = clamp(max(confidence × (1 + 0.15·ln n), 1 − (1−confidence)·0.65^(n−1)), 0, 1)`,
/// where `n = source_count()` — the count of DISTINCT corroborating sources,
/// floored at 1. **Not** the raw `corroboration` field below, which is a
/// separate summed observation magnitude that never drives `C_eff` directly.
/// See [`HseEntity::c_effective`] and [`HseEntity::source_count`].
///
/// # GREATEST-semantics merge
/// `confidence` and `corroboration` only ever increase during merge.
#[derive(Debug, Clone)]
pub struct HseEntity {
    /// Deterministic SHA-256 UID.
    pub uid: String,
    /// Value kind.
    pub kind: HseEntityKind,
    /// Normalised canonical value.
    pub value: String,
    /// Raw / display value (may differ from normalised).
    pub raw_value: String,
    /// Base confidence ∈ [0, 1].
    pub confidence: f64,
    /// Raw observation-magnitude counter (≥ 1): seeded per-module (e.g. a
    /// breach-count, an engine-agreement count) and summed on every
    /// GREATEST-semantics merge via [`Self::absorb`] — never deduplicated by
    /// source. **This is not a count of independent sources** and does not
    /// drive [`Self::c_effective`]; that uses [`Self::source_count`] instead.
    /// Retained as a ranking/diagnostics signal.
    pub corroboration: u32,
    /// Decay timestamp (Unix seconds). Used to compute time-decay.
    pub observed_at: u64,
    /// Evidence chain (append-only via `add_evidence`).
    pub evidence: Vec<HseEvidence>,
    /// Arbitrary tag bag (e.g. "au:breach", "geoint"); canonical spellings live
    /// in [`crate::tags`].
    pub tags: Vec<String>,
    /// Scan ID this entity was first seen in.
    pub scan_id: String,
    /// Expansion **generation**: how many recursive expansion rounds from the
    /// seed this entity was first discovered — its distance, in pivots, from
    /// the queried subject. `0` = the seed round (found directly by scanning
    /// the subject), `N` = surfaced by pivoting on a generation-`N-1` entity.
    /// Merge preserves the EARLIEST generation an entity entered the graph at.
    pub generation: u32,
}

impl HseEntity {
    // ── Construction ────────────────────────────────────────────────────────

    /// Create a new entity observed at `observed_at` (Unix seconds).
    /// `confidence` is clamped to [0, 1]; a non-finite confidence sanitises to
    /// 0.0 (never NaN, so the frontier's total-order determinism and the
    /// saturating `c_effective()` model are preserved).
    ///
    /// The timestamp is an explicit parameter rather than a hidden wall-clock
    /// read so every constructed value is deterministic and reproducible.
    pub fn new(
        kind: HseEntityKind,
        value: impl Into<String>,
        confidence: f64,
        scan_id: impl Into<String>,
        observed_at: u64,
    ) -> Self {
        let value = value.into();
        let normalised = normalise(&kind, &value);
        let uid = derive_uid(&kind, &normalised);
        Self {
            uid,
            kind,
            value: normalised,
            raw_value: value,
            confidence: if confidence.is_finite() {
                confidence.clamp(0.0, 1.0)
            } else {
                0.0
            },
            corroboration: 1,
            observed_at,
            evidence: Vec::new(),
            tags: Vec::new(),
            scan_id: scan_id.into(),
            // Modules never know their expansion round, so every freshly-built
            // entity starts at the seed generation; the engine re-stamps a
            // genuinely-new entity with the round it was actually born in.
            generation: 0,
        }
    }

    // ── Derived metrics ──────────────────────────────────────────────────────

    /// Number of DISTINCT corroborating sources backing this entity — the
    /// true cross-correlation signal that drives the C_eff boost.
    ///
    /// This is the grounded distinct-`evidence.source` count (minus the
    /// non-corroborating passes, with the promotion-source grounding gate),
    /// computed without allocating a `HashSet`, floored at 1. When no
    /// corroborating evidence is attached (synthetic/test entities, an entity
    /// constructed before its evidence, or one carrying only enrichment
    /// evidence) it falls back to the stored `corroboration` field so an
    /// explicitly-set strength value is still honoured.
    ///
    /// Why not the `corroboration` field directly: that field is the summed
    /// *observation magnitude* (e.g. a verified-breach count, an
    /// engine-agreement count). Summed within-module counts are NOT a count of
    /// independent sources, so using them to boost C_eff over-credited
    /// single-source findings (a 5-breach hit looked like "5 independent
    /// sources"). The `corroboration` field is retained as the
    /// observation-magnitude signal for ranking/diagnostics; it does not drive
    /// C_eff.
    #[inline]
    #[must_use]
    pub fn source_count(&self) -> u32 {
        // Count DISTINCT corroborating sources WITHOUT allocating a `HashSet`.
        // This runs for every entity on the merge/dedup hot path (via
        // `c_effective`/`classify`), so building and dropping a
        // `HashSet<&str>` on every call would be pure overhead. A source is
        // counted exactly once, at its first occurrence: for each record we
        // scan only the evidence *before* it for the same source. Entity
        // evidence chains are short (a handful of sources), so this O(k²)
        // scan over tiny `k` beats hashing + heap allocation.
        //
        // GROUNDING GATE: promotion-pass sources (`multipath_corroboration`,
        // `cross_scan_corroboration`) are tracked separately and only COUNT
        // when the entity is already independently grounded. They re-fire
        // every scan, so a value the engine merely DERIVED (a name→email
        // permutation, an inferred handle — the `derived` tag) whose lone real
        // source is its own generator must NOT be lifted into apparent
        // cross-source agreement. Gate: for observed entities (no `derived`
        // tag) 1 real source suffices; for derived entities we require ≥2 real
        // (corroborating, non-promotion) sources before promotion counts. If
        // the generator is itself non-corroborating (e.g. `name_intel`), it
        // does not contribute to `real`, so external confirmation is needed
        // regardless.
        let derived = self.has_tag(tags::DERIVED);
        let mut real: u32 = 0;
        let mut promo: u32 = 0;
        for (i, ev) in self.evidence.iter().enumerate() {
            let s = ev.source.as_str();
            if is_non_corroborating_source(s) {
                continue;
            }
            if self.evidence[..i]
                .iter()
                .any(|prev| prev.source == ev.source)
            {
                continue; // duplicate source — only count first occurrence
            }
            if is_promotion_source(s) {
                promo += 1;
            } else {
                real += 1;
            }
        }
        // For observed entities: 1 real source satisfies the gate.
        // For derived entities: need ≥2 real corroborating sources before
        // promotion passes count. Non-corroborating generators (e.g.
        // `name_intel`) do not contribute to `real`, so they do not satisfy
        // the gate alone.
        let grounded = real >= if derived { 2 } else { 1 };
        let distinct = real + if grounded { promo } else { 0 };
        if distinct > 0 {
            // Evidence is attached: distinct *corroborating* sources is the
            // authoritative cross-correlation count. The summed `corroboration`
            // magnitude is deliberately NOT allowed to inflate it (that was the
            // original bug), and deterministic self-enrichment passes are
            // excluded so they can't fabricate agreement.
            distinct
        } else if self.evidence.is_empty() {
            // No evidence at all (synthetic/test entity, or constructed
            // pre-evidence): fall back to the explicitly-set field so a
            // deliberate strength value is still honoured.
            self.corroboration.max(1)
        } else {
            // Evidence EXISTS but every record is non-corroborating — a
            // deterministic enrichment pass and/or a `recall` replay. Such an
            // entity is NOT cross-corroborated, so it counts as ONE source.
            // The stored `corroboration` magnitude must NOT resurrect it:
            // recall ratchets that field up by one every re-scan. A genuine
            // hit attaches a corroborating source and takes the `distinct`
            // branch.
            1
        }
    }

    /// Cross-source effective confidence — the stronger of two models over the
    /// number of DISTINCT corroborating sources `n` (see
    /// [`Self::source_count`], floored at 1):
    ///
    /// * **Multiplicative** (legacy): `confidence × (1 + 0.15·ln n)` — a
    ///   gentle, sharply-diminishing boost.
    /// * **Independent-agreement** (noisy-OR):
    ///   `1 − (1 − confidence)·γ^(n−1)` with `γ =
    ///   [`CORROBORATION_DOUBT_DECAY`] — each *additional* independent source
    ///   shrinks the residual doubt, so N sources agreeing on a finding drive
    ///   confidence toward certainty.
    ///
    /// `C_eff = clamp(max(multiplicative, agreement), 0, 1)`.
    ///
    /// At `n = 1` both models equal `confidence`, so a single-source entity is
    /// unchanged. `max` keeps the result monotonic and never below the legacy
    /// value, so the change only ever *adds* confidence for genuinely
    /// multi-sourced entities.
    ///
    /// ```
    /// use bleradar_core::{HseEntity, HseEntityKind};
    ///
    /// // Single source (no evidence attached → n = 1): C_eff equals confidence.
    /// let e = HseEntity::new(HseEntityKind::Email, "x@example.com", 0.6, "scan", 0);
    /// assert_eq!(e.source_count(), 1);
    /// assert!((e.c_effective() - 0.6).abs() < 1e-9);
    /// ```
    #[inline]
    #[must_use]
    pub fn c_effective(&self) -> f64 {
        self.c_effective_with_source_count(self.source_count())
    }

    /// [`Self::c_effective`] computed from an already-known
    /// distinct-corroborating source count `n`. Callers that have already paid
    /// for [`Self::source_count`] — itself an O(k²) scan of the evidence chain
    /// — pass it here instead of forcing a recompute. `c_effective()` is
    /// exactly `c_effective_with_source_count(self.source_count())`, so the
    /// C_eff formula is single-sourced and the two can never drift apart.
    #[inline]
    #[must_use]
    pub fn c_effective_with_source_count(&self, n: u32) -> f64 {
        // Floor the source count at 1: a lone observation IS one source, and
        // [`Self::source_count`] already never yields 0. Guarding here makes
        // this public method TOTAL — without it, `n = 0` drives
        // `ln(0) = -inf` (and `γ^(n-1) = γ^-1`) and returns a value BELOW the
        // base `confidence` (or a NaN when `confidence == 0`), violating the
        // model's `C_eff ≥ confidence`, bounded-`[0,1]` invariant. At the
        // floored `n = 1` both terms equal `confidence`, so corroboration can
        // only ever ADD confidence, never subtract it.
        let n = f64::from(n.max(1));
        let multiplicative = self.confidence * CORROBORATION_COEFF.mul_add(n.ln(), 1.0);
        let residual_doubt = (1.0 - self.confidence) * CORROBORATION_DOUBT_DECAY.powf(n - 1.0);
        let agreement = 1.0 - residual_doubt;
        multiplicative.max(agreement).clamp(0.0, 1.0)
    }

    /// [`Self::c_effective`] discounted by expansion **depth-decay**: each
    /// generation (pivot) away from the seed multiplies confidence by `base`
    /// (`0 < base ≤ 1`), so a finding `N` hops out is scaled by `base^N`. A
    /// gen-0 (seed-round) entity is unchanged (`base^0 = 1`), and `base = 1.0`
    /// is a total no-op at any depth. Models the intuition that every pivot
    /// adds drift, so seed-adjacent leads are inherently more trustworthy than
    /// ones reached far down a chain of pivots.
    ///
    /// Pure; `base` is supplied by the caller. Only consulted when an opt-in
    /// depth-decay expansion policy is enabled, so the raw
    /// [`Self::c_effective`] every correlation/display/gate reads is untouched
    /// unless an operator deliberately turns the policy on.
    #[inline]
    #[must_use]
    pub fn c_effective_depth_decayed(&self, base: f64) -> f64 {
        (self.c_effective() * base.powf(f64::from(self.generation))).clamp(0.0, 1.0)
    }

    /// Derived classification tier from [`Self::c_effective`]: `Verified` at ≥
    /// [`HseClassification::VERIFIED_MIN`] (0.75), `Probable` at ≥
    /// [`HseClassification::PROBABLE_MIN`] (0.40), else `Candidate`.
    ///
    /// Never stored — always recomputed, so a tier can only ever rise as
    /// merges add corroboration.
    ///
    /// ```
    /// use bleradar_core::{HseClassification, HseEntity, HseEntityKind};
    ///
    /// let mk = |c| HseEntity::new(HseEntityKind::Email, "x@example.com", c, "scan", 0).classify();
    /// assert_eq!(mk(0.90), HseClassification::Verified);
    /// assert_eq!(mk(0.50), HseClassification::Probable);
    /// assert_eq!(mk(0.20), HseClassification::Candidate);
    /// ```
    #[inline]
    #[must_use]
    pub fn classify(&self) -> HseClassification {
        HseClassification::from_c_eff(self.c_effective())
    }

    /// The entity's current confidence tier — alias for [`Self::classify`]
    /// that names the role the value is intended to play in a tier-aware
    /// bounded best-first expansion (key the visited-set on
    /// `(target, tier_rank)` and re-queue at most once per tier when a merge
    /// lifts the entity).
    #[inline]
    #[must_use]
    pub fn tier(&self) -> HseClassification {
        self.classify()
    }

    /// Gamma-decayed confidence at `now` (Unix seconds) over the time elapsed
    /// since `observed_at`. Pure: returns the decayed confidence without
    /// mutating. `now` is an explicit parameter rather than a wall-clock read
    /// so the value is reproducible.
    #[must_use]
    pub fn decayed_confidence_at(&self, now: u64) -> f64 {
        let hours_elapsed = now.saturating_sub(self.observed_at) as f64 / 3600.0;
        (self.confidence * GAMMA_PER_HOUR.powf(hours_elapsed)).clamp(0.0, 1.0)
    }

    /// Mutate confidence in place using gamma decay at `now` (Unix seconds).
    pub fn apply_decay_at(&mut self, now: u64) {
        self.confidence = self.decayed_confidence_at(now);
    }

    // ── Evidence ────────────────────────────────────────────────────────────

    /// Append evidence. Secrets must be stripped before calling.
    ///
    /// Backfills `scan_id` from the owning entity when the evidence wasn't
    /// stamped with one, so per-record provenance survives multi-scan merges.
    pub fn add_evidence(&mut self, mut ev: HseEvidence) {
        if ev.scan_id.is_empty() {
            ev.scan_id.clone_from(&self.scan_id);
        }
        self.evidence.push(ev);
    }

    // ── Tags ────────────────────────────────────────────────────────────────

    /// Add one tag (de-duped).
    pub fn tag(&mut self, t: impl Into<String>) {
        let t = t.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }

    /// Quarantine this entity into the `Candidate` tier: cap its confidence at
    /// [`CANDIDATE_CONF`] and stamp the `candidate` tag. Idempotent (the tag
    /// de-dupes; the cap is a `min`). The single, orthogonal definition of
    /// "this finding doesn't identify the subject, keep it but out of the
    /// full-confidence view".
    pub fn demote_to_candidate(&mut self) {
        self.confidence = self.confidence.min(CANDIDATE_CONF);
        self.tag(tags::CANDIDATE);
    }

    /// True when the entity carries tag `t`.
    #[must_use]
    pub fn has_tag(&self, t: &str) -> bool {
        self.tags.iter().any(|x| x == t)
    }

    /// True when this entity was extracted *only* from search-snippet
    /// recycling and nothing else has confirmed it — the lowest-reliability
    /// discovery path (a value scraped from the text of whatever page a search
    /// engine returned for a recycled query). One independent corroborating
    /// source lifts [`Self::source_count`] past 1 and the entity expands
    /// normally.
    #[inline]
    #[must_use]
    pub fn is_uncorroborated_recycled(&self) -> bool {
        self.has_tag(tags::RECYCLED) && self.source_count() < 2
    }

    /// True for a speculative identifier *permuted from the subject's name*
    /// (`name-derived` email/username guesses, e.g. `firstname.lastname@
    /// provider`) that no *reliable* independent source has yet corroborated.
    ///
    /// A breach / registry / profile source counts as corroboration — but two
    /// source classes deliberately do NOT: the derivation's own enrichment /
    /// non-corroborating passes, and a bare search-snippet hit (search is
    /// asked to look up the very permutation it then "confirms" — circular).
    /// Cheap: short-circuits on the first reliable source, no allocation.
    #[must_use]
    pub fn is_uncorroborated_name_permutation(&self) -> bool {
        self.has_tag(tags::NAME_DERIVED)
            && !self.evidence.iter().any(|ev| {
                let s = ev.source.as_str();
                !is_non_corroborating_source(s) && s != "search_engines"
            })
    }

    // ── Evidence helpers ────────────────────────────────────────────────────

    /// The distinct evidence-source names attached to this entity.
    #[must_use]
    pub fn evidence_sources(&self) -> std::collections::HashSet<&str> {
        self.evidence.iter().map(|ev| ev.source.as_str()).collect()
    }

    /// Distinct evidence sources that represent *independent* intelligence —
    /// [`Self::evidence_sources`] minus the non-corroborating passes (the
    /// deterministic self-enrichment ones in [`ENRICHMENT_ONLY_SOURCES`] and
    /// the [`RECALL_SOURCE`] memory replay; see
    /// [`is_non_corroborating_source`]). This is the honest cross-correlation
    /// set that drives [`Self::source_count`]/[`Self::c_effective`].
    ///
    /// GROUNDING GATE — identical to the one [`Self::source_count`] applies,
    /// so the SET and the COUNT can never disagree about whether an entity is
    /// independently corroborated. Promotion passes
    /// (`multipath_corroboration`, `cross_scan_corroboration`) re-fire every
    /// scan and must never GROUND an entity by themselves (see
    /// [`is_promotion_source`]): they join the set only once the entity
    /// already holds enough REAL sources — 1 normally, 2 when it is `derived`
    /// (its lone real source is its own generator).
    #[must_use]
    pub fn corroborating_sources(&self) -> std::collections::HashSet<&str> {
        let derived = self.has_tag(tags::DERIVED);
        let mut real: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut promo: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for ev in &self.evidence {
            let s = ev.source.as_str();
            if is_non_corroborating_source(s) {
                continue;
            }
            if is_promotion_source(s) {
                promo.insert(s);
            } else {
                real.insert(s);
            }
        }
        if real.len() >= if derived { 2 } else { 1 } {
            real.extend(promo);
        }
        real
    }

    /// Distinct `(source, summary)` evidence identities that represent
    /// *independent* intelligence — the record-level counterpart of
    /// [`Self::corroborating_sources`], for consumers that need to tell two
    /// different findings from the same module apart.
    #[must_use]
    pub fn corroborating_records(&self) -> std::collections::HashSet<(&str, &str)> {
        self.evidence
            .iter()
            .filter(|ev| !is_non_corroborating_source(ev.source.as_str()))
            .map(|ev| (ev.source.as_str(), ev.summary.as_str()))
            .collect()
    }

    /// True when any attached evidence came from `source`.
    #[must_use]
    pub fn has_evidence_from(&self, source: &str) -> bool {
        self.evidence.iter().any(|ev| ev.source == source)
    }

    // ── GREATEST-semantics merge ─────────────────────────────────────────────

    /// Put the evidence chain and tag bag in their canonical order: evidence
    /// sorted by `(source, summary)` and tags sorted — stable, so pre-existing
    /// order breaks exact ties. Merge produces a canonical order already (see
    /// [`Self::absorb`]); this exists for entities built up by hand, so an
    /// entity built by merging the same module results in different orders
    /// (as concurrent completion-order dispatch does) finalises to identical
    /// evidence + tag ordering.
    pub fn canonicalize_order(&mut self) {
        self.evidence.sort_by(|a, b| {
            a.source
                .cmp(&b.source)
                .then_with(|| a.summary.cmp(&b.summary))
        });
        self.tags.sort();
    }

    /// Merge another entity into this one (GREATEST semantics).
    ///
    /// Deterministic regardless of merge order: the lexicographically smaller
    /// `raw_value` wins, the better-ranked display `value` wins (see
    /// `prefers_display`), confidence takes the max, corroboration sums,
    /// `observed_at` takes the latest, evidence folds deduplicated by
    /// `(source, summary)`.
    pub fn merge(&mut self, mut other: Self) {
        debug_assert_eq!(self.uid, other.uid, "merge: UID mismatch");
        if self.uid != other.uid {
            return;
        }
        // Canonical PROVENANCE spelling: the lexicographically smaller
        // raw_value, so the as-supplied string a source sent is independent of
        // merge order. Under concurrent dispatch, results merge in completion
        // order, so keeping `self`'s would leak that order into the persisted
        // dossier (Determinism Requirement). `min` is commutative, so any
        // merge order — and any pairing — yields the same raw_value.
        if other.raw_value < self.raw_value {
            std::mem::swap(&mut self.raw_value, &mut other.raw_value);
        }
        // Canonical DISPLAY value, under the same Determinism Requirement.
        // `identity_fold` makes `uid` insensitive to case and whitespace runs
        // for Person/Organisation while `normalise` leaves `value` alone, so
        // those two kinds are the only ones where same-UID observations can
        // disagree on `value`.
        if prefers_display(&other.value, &self.value) {
            std::mem::swap(&mut self.value, &mut other.value);
        }
        self.absorb(other);
    }

    /// Fold another entity's corroborating **signal** into this one —
    /// confidence (max), corroboration (sum), recency (max), deduplicated
    /// evidence and tags — without touching identity
    /// (`uid`/`value`/`raw_value`).
    ///
    /// Note the division of labour: [`merge`](Self::merge) canonicalises the
    /// two spelling fields (`raw_value`, `value`) BEFORE delegating here, so
    /// this function can treat all three identity fields as settled and fold
    /// only signal.
    ///
    /// This is the identity-preserving core of [`merge`](Self::merge), exposed
    /// for the rare case of intentionally combining two entities with
    /// DIFFERENT UIDs that nonetheless denote the same real-world thing — e.g.
    /// collapsing `Address` entities for one locality (`"X, NSW"` and
    /// `"X, NSW 2582"`), which `merge` would refuse because their UIDs differ.
    /// The caller is responsible for having decided the two are the same;
    /// `absorb` only fuses their evidence. Commutative in
    /// confidence/corroboration/evidence/tags, so folding a group in any order
    /// yields the same result.
    pub fn absorb(&mut self, other: Self) {
        self.confidence = f64::max(self.confidence, other.confidence).clamp(0.0, 1.0);
        self.corroboration = self
            .corroboration
            .saturating_add(other.corroboration)
            .max(1);
        self.observed_at = u64::max(self.observed_at, other.observed_at);
        // `generation` is deliberately NOT merged here: it is engine-assigned
        // in monotonic round order (a genuinely-new entity is stamped with the
        // round it was born in AFTER insertion), while every module-built
        // `other` still carries the meaningless default `0`. Taking a min
        // would let a later round's re-emission (`other.generation == 0`)
        // reset an existing entity's real generation back to the seed.
        // Keeping `self`'s value preserves the earliest generation the entity
        // actually entered the graph — the invariant the engine relies on
        // (merges only ever fold `other` INTO the pre-existing,
        // earlier-or-equal entity).
        //
        // Deduplicate evidence by (source, summary) to prevent accumulation
        // across live iterations or re-scans — a repeated observation by the
        // SAME source with the SAME summary is the same record, not new
        // corroboration. BUT it may carry attributes the existing record lacks
        // (an updated breach dump, a richer re-scan), so on a match MERGE the
        // new attributes in rather than dropping the record.
        // `merge_evidence_attrs` keeps the fold deterministic (smaller value
        // wins a key conflict) and idempotent. Small inputs (the overwhelming
        // common case — a handful of rows) use a linear find; large ones use a
        // `(source, summary)→index` map so the fold stays linear under
        // re-scan / live-mode accumulation. Both branches yield identical
        // results.
        if self.evidence.len() * other.evidence.len() <= 256 {
            for ev in other.evidence {
                match self
                    .evidence
                    .iter_mut()
                    .find(|e| e.source == ev.source && e.summary == ev.summary)
                {
                    Some(existing) => merge_evidence_attrs(existing, ev),
                    None => self.evidence.push(ev),
                }
            }
        } else {
            // Index compact identity fingerprints instead of cloning every
            // source and summary. Each bucket retains all matching indices and
            // the lookup verifies the original strings, so hash collisions
            // cannot merge unrelated evidence.
            let identity_hash_builder = std::collections::hash_map::RandomState::new();
            // Existing rows establish the minimum useful capacity. Incoming
            // rows grow the map only when they introduce unique identities,
            // avoiding an upper-bound allocation when a batch is mostly
            // duplicates.
            let mut index: HashMap<u64, EvidenceIdentityBucket> =
                HashMap::with_capacity(self.evidence.len());
            for (i, evidence) in self.evidence.iter().enumerate() {
                index
                    .entry(evidence_identity_hash(
                        &identity_hash_builder,
                        &evidence.source,
                        &evidence.summary,
                    ))
                    .and_modify(|bucket| bucket.push(i))
                    .or_insert_with(|| EvidenceIdentityBucket::new(i));
            }
            self.evidence.reserve(other.evidence.len());
            for ev in other.evidence {
                let identity_hash =
                    evidence_identity_hash(&identity_hash_builder, &ev.source, &ev.summary);
                // A randomized 64-bit fingerprint makes multi-entry buckets
                // exceptional; the exact comparison is the collision-safe path.
                let existing_index = index.get(&identity_hash).and_then(|bucket| {
                    bucket.indices().find(|&i| {
                        self.evidence[i].source == ev.source
                            && self.evidence[i].summary == ev.summary
                    })
                });
                match existing_index {
                    Some(i) => merge_evidence_attrs(&mut self.evidence[i], ev),
                    None => {
                        index
                            .entry(identity_hash)
                            .and_modify(|bucket| bucket.push(self.evidence.len()))
                            .or_insert_with(|| EvidenceIdentityBucket::new(self.evidence.len()));
                        self.evidence.push(ev);
                    }
                }
            }
        }
        // `candidate` is a confidence-TIER quarantine stamped by
        // `demote_to_candidate`, not an accumulating multi-source label like an
        // ordinary tag — views filter entities purely on this tag, so blindly
        // unioning it would let a stranger's non-matching, low-confidence
        // observation of the SAME uid silently quarantine an
        // otherwise-verified entity. Confidence already resolves to the max of
        // the two sides above; tag status must track that: skip carrying the
        // tag itself over in the general union below, then promote `self` out
        // of quarantine the moment `other` was NOT itself a candidate — a
        // single non-candidate corroboration is enough, symmetric with the
        // confidence rule.
        let other_is_candidate = other.tags.iter().any(|t| t == tags::CANDIDATE);
        // `derived` marks an entity whose OWN evidence is a deterministic
        // derivation of the seed (see `ENRICHMENT_ONLY_SOURCES`'s doc),
        // consulted fresh on every call by `source_count`'s GROUNDING GATE to
        // require a stricter 2-real-source bar before a promotion pass counts.
        // Like `candidate` above, it must not be a plain accumulating tag:
        // wholesale-unioning it would let merging in an unrelated, low-value
        // derived duplicate (contributing NOTHING to real evidence — e.g. a
        // restatement by a derivation module) retroactively raise the
        // grounding bar on a genuinely observed entity.
        let other_is_derived = other.tags.iter().any(|t| t == tags::DERIVED);
        for t in other.tags {
            if t != tags::CANDIDATE && t != tags::DERIVED {
                self.tag(t);
            }
        }
        if !other_is_candidate {
            self.tags.retain(|t| t != tags::CANDIDATE);
        }
        if !other_is_derived {
            self.tags.retain(|t| t != tags::DERIVED);
        }
    }

    /// Fluent builder for the common entity-emission shape.
    pub fn builder(
        kind: HseEntityKind,
        value: impl Into<String>,
        confidence: f64,
        scan_id: impl Into<String>,
        observed_at: u64,
    ) -> HseEntityBuilder {
        HseEntityBuilder {
            entity: Self::new(kind, value, confidence, scan_id, observed_at),
        }
    }
}

/// Fluent builder for the common entity-emission shape. Construct via
/// [`HseEntity::builder`]. Every method mirrors the equivalent `HseEntity`
/// mutation exactly, so the result is indistinguishable from building the
/// entity by hand — this is ergonomics, not new behaviour.
#[must_use = "an HseEntityBuilder does nothing until `.build()`"]
pub struct HseEntityBuilder {
    entity: HseEntity,
}

impl HseEntityBuilder {
    /// Add one tag (de-duped, exactly like [`HseEntity::tag`]).
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.entity.tag(t);
        self
    }

    /// Add several tags in order.
    pub fn tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for t in tags {
            self.entity.tag(t);
        }
        self
    }

    /// Append one piece of evidence (order-preserving, like
    /// [`HseEntity::add_evidence`]). Secrets must be stripped before calling,
    /// same contract as the underlying method.
    pub fn evidence(mut self, ev: HseEvidence) -> Self {
        self.entity.add_evidence(ev);
        self
    }

    /// Finish and return the built [`HseEntity`].
    #[must_use]
    pub fn build(self) -> HseEntity {
        self.entity
    }
}

// ─── EntityRef ───────────────────────────────────────────────────────────────

/// Lightweight handle referencing an entity by UID and kind.
/// Used in module I/O to avoid cloning full entities.
#[derive(Debug, Clone)]
pub struct HseEntityRef {
    /// The referenced entity's UID.
    pub uid: String,
    /// The referenced entity's kind.
    pub kind: HseEntityKind,
    /// The referenced entity's normalised value.
    pub value: String,
}

impl From<&HseEntity> for HseEntityRef {
    fn from(e: &HseEntity) -> Self {
        Self {
            uid: e.uid.clone(),
            kind: e.kind.clone(),
            value: e.value.clone(),
        }
    }
}

impl fmt::Display for HseEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}) C={:.3} C_eff={:.3} corr={} → {}",
            self.kind,
            self.value,
            self.uid.get(..8).unwrap_or(&self.uid),
            self.confidence,
            self.c_effective(),
            self.corroboration,
            self.classify(),
        )
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Index bucket that stores the common single fingerprint match inline and
/// allocates only when a real hash collision creates additional candidates.
struct EvidenceIdentityBucket {
    first: usize,
    collisions: Vec<usize>,
}

impl EvidenceIdentityBucket {
    fn new(first: usize) -> Self {
        Self {
            first,
            collisions: Vec::new(),
        }
    }

    fn push(&mut self, index: usize) {
        self.collisions.push(index);
    }

    fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        std::iter::once(self.first).chain(self.collisions.iter().copied())
    }
}

/// Compact fingerprint for an evidence `(source, summary)` identity.
///
/// The per-merge randomized state resists adversarial collision batches.
/// Callers must still resolve every collision by comparing both original
/// strings.
fn evidence_identity_hash(
    state: &std::collections::hash_map::RandomState,
    source: &str,
    summary: &str,
) -> u64 {
    state.hash_one((source, summary))
}

/// Fold `incoming`'s attributes into `existing`, accumulating repeated keys
/// with `"; "` joins exactly like [`HseEvidence::with_attr`]'s collision
/// semantics, so the merge is deterministic (the value set union is sorted by
/// the `BTreeSet`) and idempotent.
fn merge_evidence_attrs(existing: &mut HseEvidence, incoming: HseEvidence) {
    for (k, v) in incoming.attributes {
        match existing.attributes.get_mut(&k) {
            Some(cur) => {
                if cur != &v {
                    let mut parts: std::collections::BTreeSet<String> =
                        cur.split("; ").map(String::from).collect();
                    parts.extend(v.split("; ").map(String::from));
                    *cur = parts.into_iter().collect::<Vec<_>>().join("; ");
                }
            }
            None => {
                existing.attributes.insert(k, v);
            }
        }
    }
}

/// Fold a normalised value into the form that defines **identity**, as
/// distinct from the form that is **displayed**.
///
/// For most kinds these coincide and this borrows unchanged. For free-text
/// NAME kinds they must not: a person's identity does not depend on the
/// capitalisation or the run of spaces a particular source happened to emit,
/// but the display value very much does. [`normalise`] cannot do this job,
/// because its output IS the display value (`HseEntity::value`) — its
/// catch-all arm is `value.trim()`, so `Person` receives no folding
/// whatsoever, and without this fold three sightings of one person
/// (`"Jeremy Stewart"`, `"jeremy stewart"`, `"Jeremy  Stewart"`) fork into
/// three graph nodes, each carrying only the evidence of the source that
/// spelled it that way.
///
/// Excluded on purpose:
/// * `Ssid` — Wi-Fi network names are case-SENSITIVE by IEEE 802.11; folding
///   them would merge two genuinely different networks.
/// * `Address` — real address equivalence needs component parsing
///   (`Street`/`St`, unit notation), not case folding.
/// * Every identifier kind — `Email`, `Username`, `Domain`, `Phone`,
///   `IpAddress`, `MacAddress`, `Url`, `Coordinates` — already normalises to a
///   canonical form in [`normalise`], where identity and display legitimately
///   coincide.
fn identity_fold<'a>(kind: &HseEntityKind, normalised: &'a str) -> std::borrow::Cow<'a, str> {
    match kind {
        HseEntityKind::Person | HseEntityKind::Organisation => {
            // `split_whitespace` collapses runs AND trims, so "Jeremy
            // Stewart" and " Jeremy  Stewart " reach the same key.
            let folded = normalised
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            if folded == normalised {
                std::borrow::Cow::Borrowed(normalised)
            } else {
                std::borrow::Cow::Owned(folded)
            }
        }
        _ => std::borrow::Cow::Borrowed(normalised),
    }
}

/// Rank a display spelling for canonical selection — **lower is preferred**.
///
/// Ranking rather than a bare lexicographic `min`, because `min` would pick
/// `"ACME  CORP"` over `"Acme Corp"` (ASCII upper sorts before lower) and keep
/// the doubled space. Uncased scripts (CJK, Arabic) have neither upper nor
/// lower, so they land in the middle rank together and are separated by the
/// lexicographic tiebreak — still deterministic.
fn display_rank(value: &str) -> u8 {
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mixed_case = value.chars().any(char::is_lowercase) && value.chars().any(char::is_uppercase);
    match (collapsed == value, mixed_case) {
        (true, true) => 0,  // clean spacing, mixed case — "Jeremy Stewart"
        (true, false) => 1, // clean spacing, but SHOUTED or all-lower
        (false, _) => 2,    // internal whitespace runs — "Jeremy  Stewart"
    }
}

/// True when `candidate` is the better canonical display spelling of two
/// same-UID observations. A strict total order over `(rank, bytes)`, so it is
/// commutative and associative: any merge order, and any pairing, selects the
/// same winner.
fn prefers_display(candidate: &str, current: &str) -> bool {
    (display_rank(candidate), candidate) < (display_rank(current), current)
}

/// Derive a deterministic SHA-256 UID from kind + normalised value.
///
/// Format: `hex(SHA-256("<kind_str>:<identity_fold(normalised_value)>"))`.
///
/// The fold lives HERE rather than in [`HseEntity::new`] because `derive_uid`
/// is not the private helper of one constructor — it is the single
/// authoritative definition every caller (seed derivation, dispatch, history)
/// shares, so a seed typed as `Jeremy Stewart` and a module-emitted
/// `jeremy stewart` must reach the same node.
///
/// Migration note: `Person` and `Organisation` UIDs computed by an
/// implementation without `identity_fold` do not match those computed with
/// it, so entities persisted under a mixed-case spelling are reachable only by
/// re-scanning. Every other kind is bit-for-bit unchanged.
#[must_use]
pub fn derive_uid(kind: &HseEntityKind, normalised_value: &str) -> String {
    let normalised_value = &*identity_fold(kind, normalised_value);
    // Stream the `Display` of `<kind>` straight into the hasher through
    // [`HashWrite`] so the per-entity hot path (every `HseEntity::new`)
    // allocates NO intermediate `String`. The bytes hashed are byte-identical
    // to `format!("{kind}:")`, so existing UIDs are unchanged.
    use fmt::Write as _;
    let mut h = Sha256::new();
    match kind {
        HseEntityKind::Other(s) => {
            // Unlike every fixed-string kind (drawn from a small closed set
            // that never contains `:`), `Other`'s inner name is
            // attacker/scrape controlled and can itself contain `:`. Hashing
            // `"other:{s}:{value}"` via the plain Display path below is
            // ambiguous at the name/value boundary: Other("a") with value
            // "b:c" and Other("a:b") with value "c" both produce the identical
            // preimage "other:a:b:c" and therefore the SAME uid.
            // Length-prefixing `s` fixes the split point unambiguously — this
            // changes ONLY `Other`'s hash preimage (hence only its UIDs);
            // every other kind's byte-identical Display-based path below is
            // untouched.
            let _ = write!(HashWrite(&mut h), "other:{}:", s.len());
            h.update(s.as_bytes());
            h.update(b":");
        }
        _ => {
            let _ = write!(HashWrite(&mut h), "{kind}:");
        }
    }
    h.update(normalised_value.as_bytes());
    hex_encode(&h.finalize())
}

/// Mint an entity UID from a **raw, un-normalised** value — the single entry
/// point for the two-step `normalise` → [`derive_uid`] contract. Folding the
/// two steps here means a caller with a raw operator/target string can never
/// accidentally hash a value that skipped [`normalise`] — which would land it
/// in the graph under a UID no module's emitted entity shares.
///
/// The result is byte-identical to `derive_uid(kind, &normalise(kind, value))`,
/// so this preserves the SHA-256-deterministic-UID invariant exactly.
#[must_use]
pub fn uid_for(kind: &HseEntityKind, value: &str) -> String {
    derive_uid(kind, &normalise(kind, value))
}

/// A [`fmt::Write`] shim that streams formatted text straight into a SHA-256
/// hasher, so a value's `Display` can be hashed with no intermediate `String`
/// allocation. `write_str` is infallible here (updating a hasher never fails).
struct HashWrite<'a>(&'a mut Sha256);

impl fmt::Write for HashWrite<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.update(s.as_bytes());
        Ok(())
    }
}

/// Canonicalise a URL query string for dedup: drop pure-tracking params (see
/// [`is_tracking_param_key`]) and sort the survivors so that `?a=1&b=2` and
/// `?b=2&a=1` — the same resource in a different order — key to one UID.
/// Empty segments are dropped. Returns `""` when every param was tracking
/// (the caller then omits the `?` entirely).
///
/// Parameter *values* are preserved byte-for-byte (only keys are matched
/// case-insensitively): a value like `?v=AbC123` on YouTube is
/// case-significant and must never be folded.
fn normalise_url_query(query: &str) -> String {
    // Keys and values are trimmed: whitespace is never valid inside a query,
    // and untrimmed whitespace at the end of the last parameter would survive
    // one pass (inside the query) and be removed by the next (now the end of
    // the whole string) — one value, two UIDs. Invisible for any valid URL.
    let mut kept: Vec<String> = query
        .split('&')
        .map(|seg| match seg.split_once('=') {
            Some((key, value)) => format!("{}={}", key.trim(), value.trim()),
            None => seg.trim().to_string(),
        })
        .filter(|seg| !seg.is_empty())
        .filter(|seg| {
            let key = seg.split('=').next().unwrap_or(seg);
            !is_tracking_param_key(key)
        })
        .collect();
    kept.sort_unstable();
    kept.join("&")
}

/// Invisible format / zero-width characters that are never part of a real
/// identifier: BOM `U+FEFF`, zero-width space `U+200B`, ZWNJ/ZWJ
/// `U+200C`/`U+200D`, word-joiner `U+2060`.
const FORMAT_NOISE: [char; 5] = ['\u{feff}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}'];

/// Strip [`FORMAT_NOISE`] from an identifier value. Being non-whitespace,
/// these chars survive `trim` and silently fork one value's SHA-256 UID — a
/// BOM an exporter prepended (`\u{feff}alice@x.com`), a zero-width space in a
/// scraped handle — fragmenting one identity across two nodes. They never
/// occur in a real email / username / domain, so removal is loss-free.
/// Borrows when the input is clean (the overwhelmingly common case), so the
/// hot normalize path allocates only for the rare dirty value.
fn strip_format_noise(s: &str) -> std::borrow::Cow<'_, str> {
    if s.contains(FORMAT_NOISE) {
        std::borrow::Cow::Owned(s.chars().filter(|c| !FORMAT_NOISE.contains(c)).collect())
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// Round `lat`/`lon` to 6 dp and format as the canonical `"lat,lon"` string
/// that decides a `Coordinates` entity's UID, collapsing IEEE negative zero
/// (`+ 0.0`) so a point on the equator/meridian can't fragment onto two UIDs
/// by the sign of zero. The SINGLE authority for the geo-UID precision +
/// negative-zero-collapse rule: both `Coordinates` normalisation paths below
/// (the bare-decimal fast path and the [`coords::parse`] richer-notation path)
/// call it, so a change to the rounding rule can never edit only one and
/// silently fork one physical point onto two UIDs.
fn fmt_coord_6dp(lat: f64, lon: f64) -> String {
    let lat = (lat * 1e6).round() / 1e6 + 0.0;
    let lon = (lon * 1e6).round() / 1e6 + 0.0;
    format!("{lat:.6},{lon:.6}")
}

/// Normalise a value for a given kind.
///
/// - Email → lowercase, trim, strip surrounding quotes, cut escape/whitespace
///   tails
/// - Domain → lowercase, trim, strip trailing dot and `www.` prefixes
/// - Username → lowercase, trim, strip surrounding quotes + leading `@`
///   (EXCEPT a 27-char all-ASCII-alphanumeric value — a base62 structured-ID
///   shape like a KSUID, where case is significant — which is trimmed/
///   sigil-stripped but NOT case-folded, so its encoded data survives intact)
/// - IpAddress → canonical `IpAddr` form (IPv4-mapped IPv6 folds to IPv4)
/// - MacAddress → lower-case colon-separated when 12 hex digits
/// - Coordinates → canonical `"lat,lon"` at 6 dp via `fmt_coord_6dp`,
///   accepting any notation [`crate::coords::parse`] understands
/// - Phone → strip non-digits (keep leading `+`)
/// - Url → lowercase scheme/host, trim trailing `/` from path, drop fragment,
///   drop tracking params, sort remaining query params
/// - Everything else → trim
#[must_use]
pub fn normalise(kind: &HseEntityKind, value: &str) -> String {
    match kind {
        HseEntityKind::Email => {
            // Breach dumps sometimes append a literal escape tail
            // (`…@gmail.com\r\n` — the four characters `\ r \ n`, NOT real
            // whitespace that `trim` would catch) or embed stray whitespace.
            // A real address contains neither a backslash nor internal
            // whitespace, so cut at the first of either before folding —
            // otherwise the junk tail fragments one address across two UIDs.
            // Strip invisible format / zero-width noise first (a BOM an
            // exporter prepended, a zero-width space mid-value) — removal, not
            // the cut below, because the noise can sit *before* the `@`.
            let cleaned = strip_format_noise(value.trim());
            // Re-trim AFTER stripping: a leading BOM/zero-width char is NOT
            // whitespace, so the `value.trim()` above stops at it and leaves
            // any whitespace/control byte sitting BEHIND it in place.
            let cleaned = cleaned.trim();
            let cut = cleaned
                .find(|c: char| c == '\\' || c.is_whitespace() || c.is_control())
                .unwrap_or(cleaned.len());
            let head = cleaned[..cut].trim_matches(['"', '\'', '`']);
            head.to_lowercase()
        }
        HseEntityKind::Username => {
            let noise_free = strip_format_noise(value.trim());
            let cleaned = noise_free
                .trim_start_matches(|c: char| {
                    matches!(c, '@' | '"' | '\'' | '`') || c.is_whitespace()
                })
                .trim_end_matches(|c: char| matches!(c, '"' | '\'' | '`') || c.is_whitespace());
            if cleaned.len() == 27 && cleaned.bytes().all(|b| b.is_ascii_alphanumeric()) {
                cleaned.to_string()
            } else {
                cleaned.to_lowercase()
            }
        }
        HseEntityKind::Domain => {
            let cleaned = strip_format_noise(value.trim());
            let cleaned = cleaned.trim();
            // Unicode-aware lowercase: a `char::to_lowercase` can widen (e.g.
            // `İ`), so build a fresh string rather than lowercasing in place.
            let mut s = String::with_capacity(cleaned.len());
            for c in cleaned.chars() {
                s.extend(c.to_lowercase());
            }
            let len = s
                .trim_end_matches(|c: char| c == '.' || c.is_whitespace())
                .len();
            s.truncate(len);
            // Peel repeated `www.` prefixes (`www.www.example.com`) together
            // with any whitespace a peel exposes (`www. www.example.com`), but
            // never to an empty host. Trimming inside the loop keeps the result
            // a fixed point: a `www.` uncovered by the trim is peeled in the
            // same pass instead of surviving to fork the host onto a second
            // UID when it is normalised again.
            let mut host = s.as_str();
            loop {
                let trimmed = host.trim_start();
                match trimmed.strip_prefix("www.") {
                    Some(rest) if !rest.trim_start().is_empty() => host = rest,
                    _ => {
                        host = trimmed;
                        break;
                    }
                }
            }
            if host.len() != s.len() {
                s = host.to_string();
            }
            s
        }
        HseEntityKind::Phone => {
            let trimmed = value.trim();
            let mut out = String::with_capacity(trimmed.len());
            let mut chars = trimmed.chars().peekable();
            if chars.peek() == Some(&'+') {
                out.push('+');
                chars.next();
            }
            for c in chars {
                if c.is_ascii_digit() {
                    out.push(c);
                }
            }
            out
        }
        HseEntityKind::IpAddress => {
            let trimmed = value.trim();
            if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
                match ip {
                    std::net::IpAddr::V6(v6) => {
                        // Fold IPv4-mapped IPv6 (`::ffff:192.0.2.1`) to the
                        // plain IPv4 spelling so one address keys one UID.
                        if let Some(v4) = v6.to_ipv4_mapped() {
                            return v4.to_string();
                        }
                        ip.to_string()
                    }
                    _ => ip.to_string(),
                }
            } else {
                trimmed.to_string()
            }
        }
        HseEntityKind::MacAddress => {
            let trimmed = value.trim();
            let hex: String = trimmed
                .chars()
                .filter(char::is_ascii_hexdigit)
                .flat_map(char::to_lowercase)
                .collect();
            if hex.len() == 12 {
                format!(
                    "{}:{}:{}:{}:{}:{}",
                    &hex[0..2],
                    &hex[2..4],
                    &hex[4..6],
                    &hex[6..8],
                    &hex[8..10],
                    &hex[10..12]
                )
            } else {
                trimmed.to_lowercase()
            }
        }
        HseEntityKind::Coordinates => {
            let trimmed = value.trim();
            // Fast path: a bare `"lat, lon"` decimal pair. It must pass the
            // same validity gate as every `coords::parse` notation
            // (`LatLon::new`: finite AND in range), or an impossible pair such
            // as `100,2000` — which `coords::parse` rejects — would be minted
            // into a canonical-looking coordinate string.
            if let Some((lat_s, lon_s)) = trimmed.split_once(',')
                && let (Ok(lat), Ok(lon)) =
                    (lat_s.trim().parse::<f64>(), lon_s.trim().parse::<f64>())
                && let Ok(point) = crate::geo::LatLon::new(lat, lon)
            {
                return fmt_coord_6dp(point.lat(), point.lon());
            }
            // Rich notations: DMS/DDM, geo: URI, Plus Code, Maidenhead.
            if let Some(p) = coords::parse(trimmed) {
                return fmt_coord_6dp(p.point.lat(), p.point.lon());
            }
            trimmed.to_string()
        }
        HseEntityKind::Url => {
            let trimmed = value.trim();
            let lower = trimmed.to_lowercase();
            let (scheme, rest) = if lower.starts_with("https://") {
                ("https", &trimmed[8..])
            } else if lower.starts_with("http://") {
                ("http", &trimmed[7..])
            } else {
                return trimmed.to_string();
            };
            let no_frag = rest.split('#').next().unwrap_or(rest);
            let (host_and_path, query) = match no_frag.split_once('?') {
                Some((hp, q)) => (hp, Some(q)),
                None => (no_frag, None),
            };
            let (host, path) = host_and_path.split_once('/').unwrap_or((host_and_path, ""));
            // Whitespace is never valid inside a URL, but the canonical form
            // must still be a fixed point: strip it from the host and from
            // both ends of the path before the trailing-slash removal, or a
            // `\t/` tail survives one pass (the slash is stripped, the tab is
            // kept) and is trimmed away by the next — one value, two UIDs.
            let host_lower: String = host.trim().chars().flat_map(char::to_lowercase).collect();
            let mut path_trimmed = path.trim();
            loop {
                let next = path_trimmed.trim_end_matches('/').trim_end();
                if next == path_trimmed {
                    break;
                }
                path_trimmed = next;
            }
            let mut out = if path_trimmed.is_empty() {
                format!("{scheme}://{host_lower}")
            } else {
                format!("{scheme}://{host_lower}/{path_trimmed}")
            };
            if let Some(q) = query {
                let cleaned = normalise_url_query(q);
                if !cleaned.is_empty() {
                    out.push('?');
                    out.push_str(&cleaned);
                }
            }
            out
        }
        _ => value.trim().to_string(),
    }
}

/// The distinct evidence-source names across a set of entities — the modules /
/// providers that contributed to this collection. `BTreeSet` gives a
/// deduplicated, sorted, reproducible view. **Pure.**
///
/// This is the single primitive every "which sources/modules produced this
/// scan" surface reduces through, so the source set is computed one way
/// everywhere and the surfaces cannot diverge.
#[must_use]
pub fn evidence_sources(entities: &[HseEntity]) -> std::collections::BTreeSet<&str> {
    entities
        .iter()
        .flat_map(|e| e.evidence.iter().map(|ev| ev.source.as_str()))
        .collect()
}

/// The **expansion timeline**: how many entities were first discovered in each
/// expansion generation ([`HseEntity::generation`]), ordered from the seed
/// outward. Generation 0 is the seed round (found directly by scanning the
/// subject); each later generation is one pivot further out along its
/// derivation trail. The shape of this distribution is the scan's expansion
/// curve — the working graph growing round by round, then converging as leads
/// are exhausted or pruned. Pure; returns a `BTreeMap` so generations are
/// already in order.
#[must_use]
pub fn expansion_timeline(entities: &[HseEntity]) -> std::collections::BTreeMap<u32, usize> {
    let mut hist = std::collections::BTreeMap::new();
    for e in entities {
        *hist.entry(e.generation).or_insert(0) += 1;
    }
    hist
}

/// Generate a unique scan ID: `hex(SHA-256("<kind>:<value>:<unix_secs>:<
/// nanos>:<seq>"))`.
///
/// NOT deterministic across calls for the same target — the caller-supplied
/// `unix_secs` timestamp plus `nanos` and a process-wide monotonic counter
/// are mixed in so each invocation produces a fresh id. The counter
/// guarantees uniqueness within a run even at same-nanosecond creation;
/// `nanos` separates ids across a restart that resets the counter.
#[must_use]
pub fn scan_id(kind: &str, value: &str, unix_secs: u64, nanos: u32) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update(b":");
    h.update(value.as_bytes());
    h.update(b":");
    h.update(&unix_secs.to_be_bytes());
    h.update(&nanos.to_be_bytes());
    h.update(&SEQ.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    hex_encode(&h.finalize())
}
