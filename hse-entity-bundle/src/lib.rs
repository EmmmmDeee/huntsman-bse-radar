//! HSE `hse-core` entity-bundle v1 — UID preimage and GREATEST merge.
//!
//! Independent of `bleradar-core` / HSE workspace so it compiles on rustc 1.75.
//! UID bytes match `hse-core::derive_uid` on HSE `81caa593`:
//! `sha256("{kind}:{normalised}")` with snake_case kind.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HSE_BUNDLE_SCHEMA: &str = "hse-core.entity-bundle.v1";
pub const HSE_SOURCE: &str = "hse_bse_radar";
pub const HSE_CORE_PIN: &str = "81caa5930c1b57b6e65ed20b9226a8b3d1266809";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HseBundle {
    pub schema: String,
    pub hse_rev: String,
    pub radar_rev: String,
    pub sweep_id: String,
    pub entities: Vec<HseEntity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HseEntity {
    pub uid: String,
    pub kind: String,
    pub value: String,
    pub raw_value: String,
    pub confidence: f64,
    pub corroboration: u32,
    pub observed_at: u64,
    pub evidence: Vec<HseEvidence>,
    pub tags: Vec<String>,
    pub scan_id: String,
    pub generation: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HseEvidence {
    pub source: String,
    pub summary: String,
    pub attributes: BTreeMap<String, String>,
    pub recorded_at: u64,
}

pub fn derive_uid(kind: &str, normalised: &str) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update(b":");
    h.update(normalised.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(T[(b >> 4) as usize] as char);
        out.push(T[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn normalise_mac(value: &str) -> String {
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

pub fn normalise_coordinates(lat: f64, lon: f64) -> String {
    format!("{lat:.6},{lon:.6}")
}

pub fn entity(
    kind: &str,
    raw: &str,
    normalised: String,
    tags: Vec<String>,
    attrs: BTreeMap<String, String>,
    scan_id: &str,
    observed_at: u64,
    summary: String,
    confidence: f64,
) -> HseEntity {
    HseEntity {
        uid: derive_uid(kind, &normalised),
        kind: kind.to_string(),
        raw_value: raw.to_string(),
        value: normalised,
        confidence,
        corroboration: 1,
        observed_at,
        evidence: vec![HseEvidence {
            source: HSE_SOURCE.into(),
            summary,
            attributes: attrs,
            recorded_at: observed_at,
        }],
        tags,
        scan_id: scan_id.to_string(),
        generation: 0,
    }
}

pub fn empty_bundle(sweep_id: &str) -> HseBundle {
    HseBundle {
        schema: HSE_BUNDLE_SCHEMA.into(),
        hse_rev: HSE_CORE_PIN.into(),
        radar_rev: String::new(),
        sweep_id: sweep_id.into(),
        entities: Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UidDrift {
    pub uid: String,
    pub expected: String,
}

pub fn verify_uids(bundle: &HseBundle) -> Result<(), Vec<UidDrift>> {
    let mut bad = Vec::new();
    for e in &bundle.entities {
        let expected = derive_uid(&e.kind, &e.value);
        if expected != e.uid {
            bad.push(UidDrift {
                uid: e.uid.clone(),
                expected,
            });
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad)
    }
}

pub fn absorb_entity(into: &mut HseEntity, incoming: HseEntity) {
    if incoming.confidence > into.confidence {
        into.confidence = incoming.confidence;
    }
    into.corroboration = into.corroboration.saturating_add(incoming.corroboration);
    if incoming.observed_at > into.observed_at {
        into.observed_at = incoming.observed_at;
    }
    for ev in incoming.evidence {
        if !into.evidence.iter().any(|x| {
            x.source == ev.source && x.summary == ev.summary && x.recorded_at == ev.recorded_at
        }) {
            into.evidence.push(ev);
        }
    }
    for t in incoming.tags {
        if !into.tags.iter().any(|x| x == &t) {
            into.tags.push(t);
        }
    }
}

pub fn merge_bundles(mut base: HseBundle, extra: HseBundle) -> HseBundle {
    for incoming in extra.entities {
        if let Some(existing) = base.entities.iter_mut().find(|e| e.uid == incoming.uid) {
            absorb_entity(existing, incoming);
        } else {
            base.entities.push(incoming);
        }
    }
    if extra.sweep_id != base.sweep_id && !extra.sweep_id.is_empty() {
        base.sweep_id = format!("{}+{}", base.sweep_id, extra.sweep_id);
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac_entity(scan: &str, when: u64) -> HseEntity {
        entity(
            "mac_address",
            "3C-5A-B4-11-22-01",
            normalise_mac("3C-5A-B4-11-22-01"),
            vec!["wifi".into()],
            BTreeMap::new(),
            scan,
            when,
            "radio sighting".into(),
            0.55,
        )
    }

    #[test]
    fn mac_uid_matches_hse_core_preimage() {
        let uid = derive_uid("mac_address", "3c:5a:b4:11:22:01");
        assert_eq!(uid, derive_uid("mac_address", &normalise_mac("3C-5A-B4-11-22-01")));
        assert_eq!(
            uid,
            "c2bcd0276caa3b99522d4908470141ae9ca846d357cbffe6ff8a9f289edd157b",
        );
    }

    #[test]
    fn device_and_geo_uids() {
        assert_eq!(
            derive_uid("device_id", "505-1-1234-567890"),
            "0f8518938ea5b887a7d2a3f0a913940372361baf0c16af99576affa4e4259401",
        );
        let geo = normalise_coordinates(-27.4698, 153.0251);
        assert_eq!(geo, "-27.469800,153.025100");
        assert_eq!(
            derive_uid("coordinates", &geo),
            "ce8a32e39cc362b5e8118b41616637cd6ad73c85162ef817f1dde572887d12db",
        );
    }

    #[test]
    fn verify_rejects_tampered_uid() {
        let mut b = empty_bundle("t");
        b.entities.push(mac_entity("t", 1));
        assert!(verify_uids(&b).is_ok());
        b.entities[0].uid = "deadbeef".into();
        assert!(verify_uids(&b).is_err());
    }

    #[test]
    fn merge_same_mac_raises_corroboration() {
        let mut a = empty_bundle("a");
        a.entities.push(mac_entity("a", 10));
        let mut b = empty_bundle("b");
        b.entities.push(mac_entity("b", 20));
        let m = merge_bundles(a, b);
        let mac = m.entities.iter().find(|e| e.kind == "mac_address").unwrap();
        assert_eq!(mac.corroboration, 2);
        assert_eq!(mac.observed_at, 20);
        assert_eq!(m.entities.len(), 1);
        assert!(verify_uids(&m).is_ok());
        assert_eq!(m.sweep_id, "a+b");
    }

    #[test]
    fn merge_keeps_distinct_uids() {
        let mut a = empty_bundle("a");
        a.entities.push(mac_entity("a", 1));
        let mut b = empty_bundle("b");
        b.entities.push(entity(
            "ssid",
            "HomeNet",
            "HomeNet".into(),
            vec!["wifi-ssid".into()],
            BTreeMap::new(),
            "b",
            1,
            "ssid".into(),
            0.55,
        ));
        let m = merge_bundles(a, b);
        assert_eq!(m.entities.len(), 2);
    }
}
