//! HSE `hse-core` entity-bundle export.
//!
//! UIDs are SHA-256 of `"{kind}:{normalised}"` with `EntityKind`'s snake_case
//! Display, matching `hse-core::derive_uid` on HSE `81caa593` (`hse-core` 5992b8b).
//! This crate does not depend on `hse-core` (edition 2024 / sha2 0.11 / HSE
//! workspace). Kind coverage here is only MacAddress, DeviceId, Ssid,
//! Coordinates — the radios this adapter actually observes.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::Ledger;

pub const HSE_BUNDLE_SCHEMA: &str = "hse-core.entity-bundle.v1";
pub const HSE_SOURCE: &str = "hse_bse_radar";
pub const HSE_CORE_PIN: &str = "81caa5930c1b57b6e65ed20b9226a8b3d1266809";

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HseBundle {
    pub schema: String,
    pub hse_rev: String,
    pub radar_rev: String,
    pub sweep_id: String,
    pub entities: Vec<HseEntity>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, PartialEq)]
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

fn confidence(tags: &[String]) -> f64 {
    if tags.iter().any(|t| t == "track:randomized" || t == "track:RANDOMIZED") {
        0.35
    } else if tags.iter().any(|t| t.starts_with("track:unknown") || t == "track:UNKNOWN") {
        0.30
    } else {
        0.55
    }
}

fn entity(
    kind: &str,
    raw: &str,
    normalised: String,
    tags: Vec<String>,
    attrs: BTreeMap<String, String>,
    scan_id: &str,
    observed_at: u64,
    summary: String,
) -> HseEntity {
    let conf = confidence(&tags);
    HseEntity {
        uid: derive_uid(kind, &normalised),
        kind: kind.to_string(),
        raw_value: raw.to_string(),
        value: normalised,
        confidence: conf,
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

pub fn bundle_from_ledger(ledger: &Ledger) -> HseBundle {
    let observed = if ledger.observed_epoch < 0 {
        0
    } else {
        ledger.observed_epoch as u64
    };
    let mut entities = Vec::new();
    for e in &ledger.entities {
        match e.kind.as_str() {
            "mac_address" => {
                let norm = normalise_mac(&e.value);
                let attrs: BTreeMap<_, _> = e.attrs.iter().cloned().collect();
                entities.push(entity(
                    "mac_address",
                    &e.value,
                    norm,
                    e.tags.clone(),
                    attrs,
                    &ledger.sweep_id,
                    observed,
                    format!("radio sighting {}", e.value),
                ));
            }
            "device_id" => {
                let norm = e.value.trim().to_string();
                let attrs: BTreeMap<_, _> = e.attrs.iter().cloned().collect();
                entities.push(entity(
                    "device_id",
                    &e.value,
                    norm,
                    e.tags.clone(),
                    attrs,
                    &ledger.sweep_id,
                    observed,
                    format!("cell identity {}", e.value),
                ));
            }
            _ => {}
        }
        if e.kind == "mac_address" {
            if let Some((_, ssid)) = e.attrs.iter().find(|(k, _)| k == "ssid") {
                if !ssid.is_empty() {
                    let norm = ssid.trim().to_string();
                    let mut attrs = BTreeMap::new();
                    attrs.insert("bssid".into(), e.value.clone());
                    entities.push(entity(
                        "ssid",
                        ssid,
                        norm,
                        vec!["wifi-ssid".into()],
                        attrs,
                        &ledger.sweep_id,
                        observed,
                        format!("ssid on {}", e.value),
                    ));
                }
            }
        }
    }
    if let Some(fix) = &ledger.fix {
        let norm = normalise_coordinates(fix.latitude, fix.longitude);
        let raw = format!("{},{}", fix.latitude, fix.longitude);
        let mut attrs = BTreeMap::new();
        if let Some(a) = fix.accuracy_m {
            attrs.insert("accuracy_m".into(), a.to_string());
        }
        if let Some(p) = &fix.provider {
            attrs.insert("provider".into(), p.clone());
        }
        entities.push(entity(
            "coordinates",
            &raw,
            norm,
            vec!["geoint".into()],
            attrs,
            &ledger.sweep_id,
            observed,
            "operator GPS fix".into(),
        ));
    }
    HseBundle {
        schema: HSE_BUNDLE_SCHEMA.into(),
        hse_rev: HSE_CORE_PIN.into(),
        radar_rev: crate::PINNED_RADAR_REV.into(),
        sweep_id: ledger.sweep_id.clone(),
        entities,
    }
}

/// Keep the compiler happy when attrs on MAC already live in the entity bag;
/// SSID is also taken from the sighting name when the attr is missing.
pub fn attach_ssid_from_sightings(ledger: &Ledger, bundle: &mut HseBundle) {
    for s in &ledger.sightings {
        if s.radio != "wifi" {
            continue;
        }
        let Some(name) = s.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) else {
            continue;
        };
        if bundle.entities.iter().any(|e| e.kind == "ssid" && e.value == name) {
            continue;
        }
        let mut attrs = BTreeMap::new();
        attrs.insert("bssid".into(), s.key.clone());
        bundle.entities.push(entity(
            "ssid",
            name,
            name.to_string(),
            vec!["wifi-ssid".into()],
            attrs,
            &ledger.sweep_id,
            if ledger.observed_epoch < 0 {
                0
            } else {
                ledger.observed_epoch as u64
            },
            format!("ssid on {}", s.key),
        ));
    }
}

pub fn export_hse(ledger: &Ledger) -> HseBundle {
    let mut bundle = bundle_from_ledger(ledger);
    attach_ssid_from_sightings(ledger, &mut bundle);
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SensorInputs, ingest};

    #[test]
    fn mac_uid_matches_hse_core_preimage() {
        let uid = derive_uid("mac_address", "3c:5a:b4:11:22:01");
        assert_eq!(uid, derive_uid("mac_address", &normalise_mac("3C-5A-B4-11-22-01")));
        assert_eq!(
            uid,
            "c2bcd0276caa3b99522d4908470141ae9ca846d357cbffe6ff8a9f289edd157b"
        );
    }

    #[test]
    fn export_emits_hse_kinds_from_termux_and_gps() {
        let wifi = br#"[{"bssid":"3c:5a:b4:11:22:01","ssid":"HomeNet","rssi":-48,"frequency":2437,"capabilities":"[WPA2-PSK-CCMP][ESS]"}]"#;
        let cell = br#"[{"type":"lte","registered":true,"mcc":505,"mnc":1,"tac":1234,"ci":567890,"dbm":-91}]"#;
        let gps = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":12.5,"provider":"gps"}"#;
        let l = ingest(
            "t",
            42,
            SensorInputs {
                wifi: Some(wifi),
                bluetooth: None,
                cell: Some(cell),
                gps: Some(gps),
                radar_wifi: None,
                radar_devices: None,
            },
        );
        let b = export_hse(&l);
        assert_eq!(b.schema, HSE_BUNDLE_SCHEMA);
        assert_eq!(b.hse_rev, HSE_CORE_PIN);
        let kinds: Vec<_> = b.entities.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"mac_address"));
        assert!(kinds.contains(&"ssid"));
        assert!(kinds.contains(&"device_id"));
        assert!(kinds.contains(&"coordinates"));
        let mac = b.entities.iter().find(|e| e.kind == "mac_address").unwrap();
        assert_eq!(
            mac.uid,
            "c2bcd0276caa3b99522d4908470141ae9ca846d357cbffe6ff8a9f289edd157b"
        );
        let tower = b.entities.iter().find(|e| e.kind == "device_id").unwrap();
        assert_eq!(
            tower.uid,
            "0f8518938ea5b887a7d2a3f0a913940372361baf0c16af99576affa4e4259401"
        );
        let geo = b.entities.iter().find(|e| e.kind == "coordinates").unwrap();
        assert_eq!(geo.value, "-27.469800,153.025100");
        assert_eq!(
            geo.uid,
            "ce8a32e39cc362b5e8118b41616637cd6ad73c85162ef817f1dde572887d12db"
        );
        assert!(b.entities.iter().all(|e| e.evidence.iter().all(|ev| ev.source == HSE_SOURCE)));
    }
}
