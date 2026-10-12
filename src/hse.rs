//! HSE `hse-core` entity-bundle export. The bundle types, UIDs and normalisers come from the
//! `hse-entity-bundle` crate, the one definition of the `hse-core.entity-bundle.v1` format. This
//! module turns a radar ledger into a bundle; `tests/bundle_golden.rs` pins the bytes it writes.

use std::collections::BTreeMap;

pub use hse_entity_bundle::{
    HSE_BUNDLE_SCHEMA, HSE_CORE_PIN, HSE_SOURCE, HseBundle, HseEntity, HseEvidence, derive_uid,
    normalise_coordinates, normalise_mac,
};

use crate::Ledger;

fn confidence(tags: &[String]) -> f64 {
    if tags
        .iter()
        .any(|t| t == "track:randomized" || t == "track:RANDOMIZED")
    {
        0.35
    } else if tags
        .iter()
        .any(|t| t.starts_with("track:unknown") || t == "track:UNKNOWN")
    {
        0.30
    } else {
        0.55
    }
}

/// The sweep an exported entity belongs to: the ledger's sweep id and its observation time. Every
/// entity of one export shares both, so they travel together. A ledger that recorded a negative
/// epoch is read as time zero.
struct Sweep<'a> {
    id: &'a str,
    observed_at: u64,
}

impl<'a> Sweep<'a> {
    fn of(ledger: &'a Ledger) -> Self {
        Self {
            id: &ledger.sweep_id,
            observed_at: u64::try_from(ledger.observed_epoch).unwrap_or(0),
        }
    }
}

fn entity(
    kind: &str,
    raw: &str,
    normalised: String,
    tags: Vec<String>,
    attrs: BTreeMap<String, String>,
    sweep: &Sweep<'_>,
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
        observed_at: sweep.observed_at,
        evidence: vec![HseEvidence {
            source: HSE_SOURCE.into(),
            summary,
            attributes: attrs,
            recorded_at: sweep.observed_at,
        }],
        tags,
        scan_id: sweep.id.to_string(),
        generation: 0,
    }
}

pub fn bundle_from_ledger(ledger: &Ledger) -> HseBundle {
    let sweep = Sweep::of(ledger);
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
                    &sweep,
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
                    &sweep,
                    format!("cell identity {}", e.value),
                ));
            }
            _ => {}
        }
        if e.kind == "mac_address"
            && let Some((_, ssid)) = e.attrs.iter().find(|(k, _)| k == "ssid")
            && !ssid.is_empty()
        {
            let norm = ssid.trim().to_string();
            let mut attrs = BTreeMap::new();
            attrs.insert("bssid".into(), e.value.clone());
            entities.push(entity(
                "ssid",
                ssid,
                norm,
                vec!["wifi-ssid".into()],
                attrs,
                &sweep,
                format!("ssid on {}", e.value),
            ));
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
            &sweep,
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
    let sweep = Sweep::of(ledger);
    for s in &ledger.sightings {
        if s.radio != "wifi" {
            continue;
        }
        let Some(name) = s.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) else {
            continue;
        };
        if bundle
            .entities
            .iter()
            .any(|e| e.kind == "ssid" && e.value == name)
        {
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
            &sweep,
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
        assert_eq!(
            uid,
            derive_uid("mac_address", &normalise_mac("3C-5A-B4-11-22-01"))
        );
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
        assert!(
            b.entities
                .iter()
                .all(|e| e.evidence.iter().all(|ev| ev.source == HSE_SOURCE))
        );
    }

    #[test]
    fn every_exported_entity_carries_the_sweep_id_and_its_clamped_time() {
        // Every entity of one export shares the ledger's sweep id and observation time, and a
        // ledger that recorded a negative epoch exports as time zero, not a wrapped value.
        let wifi =
            br#"[{"bssid":"3c:5a:b4:11:22:01","ssid":"HomeNet","rssi":-48,"frequency":2437}]"#;
        let mut l = ingest(
            "sweep-seed",
            42,
            SensorInputs {
                wifi: Some(wifi),
                bluetooth: None,
                cell: None,
                gps: None,
                radar_wifi: None,
                radar_devices: None,
            },
        );
        let b = export_hse(&l);
        assert!(!b.entities.is_empty());
        for e in &b.entities {
            assert_eq!(e.scan_id, l.sweep_id, "{}", e.kind);
            assert_eq!(e.observed_at, 42, "{}", e.kind);
            assert!(
                e.evidence.iter().all(|ev| ev.recorded_at == 42),
                "{}",
                e.kind
            );
        }

        l.observed_epoch = -5;
        let b = export_hse(&l);
        for e in &b.entities {
            assert_eq!(
                e.observed_at, 0,
                "a negative epoch exports as zero: {}",
                e.kind
            );
            assert!(
                e.evidence.iter().all(|ev| ev.recorded_at == 0),
                "{}",
                e.kind
            );
        }
    }
}
