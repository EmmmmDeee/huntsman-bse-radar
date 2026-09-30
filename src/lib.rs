//! HSE ↔ BLE Radar Termux adapter.
//!
//! Owns transport only: parse Termux sensor JSON, call `bleradar-core` sweep
//! rules, emit a versioned sighting ledger HSE can ingest. Does not copy HSE
//! module code and does not reimplement radar math.

pub mod hse;

use std::time::{SystemTime, UNIX_EPOCH};

use bleradar_core::{
    AddressTrackability, BleAddressType, CellRadio, ProximityBand, WifiSecurity,
    ble_address_trackability, is_numeric_segment, is_real_device_address, sighting_key, tower_id,
    usable_cell_identity, usable_dbm, wifi_observation,
};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "hse-bse-radar.sighting-ledger.v1";
pub const SOURCE: &str = "hse-bse-radar";
pub const PINNED_RADAR_REV: &str = "d0b1e8d09621abde6ff3c7b1b9d7927a95e6f7fc";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ledger {
    pub schema: String,
    pub radar_rev: String,
    pub sweep_id: String,
    pub observed_epoch: i64,
    pub fix: Option<Fix>,
    pub entities: Vec<LedgerEntity>,
    pub sightings: Vec<Sighting>,
    pub skipped: Vec<Skipped>,
    pub sensors: SensorStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SensorStatus {
    pub wifi: SensorOutcome,
    pub bluetooth: SensorOutcome,
    pub cell: SensorOutcome,
    pub gps: SensorOutcome,
    pub radar_wifi: SensorOutcome,
    pub radar_devices: SensorOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SensorOutcome {
    Observed { count: usize },
    Empty,
    MissingTool,
    Unparseable { reason: String },
}

impl Default for SensorOutcome {
    fn default() -> Self {
        Self::Empty
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fix {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_m: Option<f64>,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerEntity {
    pub kind: String,
    pub value: String,
    pub tags: Vec<String>,
    pub attrs: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sighting {
    pub key: String,
    pub radio: String,
    pub name: Option<String>,
    pub signal_dbm: Option<f64>,
    pub observed_epoch: i64,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub raw_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Skipped {
    pub sensor: String,
    pub reason: String,
    pub raw: String,
}

#[derive(Debug, Deserialize)]
struct WifiAp {
    bssid: String,
    ssid: Option<String>,
    rssi: Option<i64>,
    frequency: Option<i64>,
    #[serde(alias = "channelWidth", alias = "channel_width")]
    channel_width: Option<String>,
    capabilities: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BtDevice {
    address: String,
    name: Option<String>,
    #[serde(rename = "type")]
    bt_type: Option<String>,
    #[serde(alias = "bondState", alias = "bond_state")]
    bond_state: Option<String>,
    #[serde(alias = "addressType", alias = "address_type")]
    address_type: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct CellRow {
    #[serde(rename = "type")]
    cell_type: Option<String>,
    registered: Option<bool>,
    mcc: Option<serde_json::Value>,
    mnc: Option<serde_json::Value>,
    cid: Option<i64>,
    ci: Option<i64>,
    nci: Option<i64>,
    lac: Option<i64>,
    tac: Option<i64>,
    dbm: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GpsRow {
    latitude: Option<f64>,
    longitude: Option<f64>,
    accuracy: Option<f64>,
    provider: Option<String>,
}

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn sweep_id(seed: &str, epoch: i64) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
    h.update(b"|");
    h.update(epoch.to_le_bytes());
    let d = h.finalize();
    format!("sweep-{}", hex(&d[..8]))
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

fn proximity_str(band: ProximityBand) -> &'static str {
    match band {
        ProximityBand::Immediate => "immediate",
        ProximityBand::Near => "near",
        ProximityBand::Mid => "mid",
        ProximityBand::Far => "far",
    }
}

fn track_str(t: AddressTrackability) -> &'static str {
    match t {
        AddressTrackability::Trackable => "trackable",
        AddressTrackability::Randomized => "randomized",
        AddressTrackability::Unknown => "unknown",
    }
}

fn security_str(s: WifiSecurity) -> &'static str {
    s.label()
}

fn json_num(v: Option<&serde_json::Value>) -> String {
    match v {
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::String(s)) => s.trim().to_string(),
        _ => String::new(),
    }
}

fn is_blank(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| b.is_ascii_whitespace())
}

pub struct SensorInputs<'a> {
    pub wifi: Option<&'a [u8]>,
    pub bluetooth: Option<&'a [u8]>,
    pub cell: Option<&'a [u8]>,
    pub gps: Option<&'a [u8]>,
    pub radar_wifi: Option<&'a [u8]>,
    pub radar_devices: Option<&'a [u8]>,
}

pub fn ingest(seed: &str, epoch: i64, inputs: SensorInputs<'_>) -> Ledger {
    let mut ledger = Ledger {
        schema: SCHEMA.to_string(),
        radar_rev: PINNED_RADAR_REV.to_string(),
        sweep_id: sweep_id(seed, epoch),
        observed_epoch: epoch,
        fix: None,
        entities: Vec::new(),
        sightings: Vec::new(),
        skipped: Vec::new(),
        sensors: SensorStatus::default(),
    };

    match inputs.gps {
        None => ledger.sensors.gps = SensorOutcome::MissingTool,
        Some(b) if is_blank(b) => ledger.sensors.gps = SensorOutcome::Empty,
        Some(b) => match parse_gps(b) {
            Ok(fix) => {
                ledger.sensors.gps = SensorOutcome::Observed { count: 1 };
                ledger.fix = Some(fix);
            }
            Err(reason) => {
                ledger.sensors.gps = SensorOutcome::Unparseable { reason };
            }
        },
    }

    match inputs.wifi {
        None => ledger.sensors.wifi = SensorOutcome::MissingTool,
        Some(b) if is_blank(b) => ledger.sensors.wifi = SensorOutcome::Empty,
        Some(b) => match serde_json::from_slice::<Vec<WifiAp>>(b) {
            Ok(aps) => {
                let before = ledger.entities.len();
                for ap in aps {
                    ingest_wifi(&mut ledger, ap, epoch);
                }
                let n = ledger.entities.len() - before;
                ledger.sensors.wifi = if n == 0 {
                    SensorOutcome::Empty
                } else {
                    SensorOutcome::Observed { count: n }
                };
            }
            Err(e) => {
                ledger.sensors.wifi = SensorOutcome::Unparseable {
                    reason: e.to_string(),
                };
            }
        },
    }

    match inputs.bluetooth {
        None => ledger.sensors.bluetooth = SensorOutcome::MissingTool,
        Some(b) if is_blank(b) => ledger.sensors.bluetooth = SensorOutcome::Empty,
        Some(b) => match serde_json::from_slice::<Vec<BtDevice>>(b) {
            Ok(devs) => {
                let before = ledger.sightings.len();
                for dev in devs {
                    ingest_bt(&mut ledger, dev, epoch);
                }
                let n = ledger.sightings.len() - before;
                ledger.sensors.bluetooth = if n == 0 {
                    SensorOutcome::Empty
                } else {
                    SensorOutcome::Observed { count: n }
                };
            }
            Err(e) => {
                ledger.sensors.bluetooth = SensorOutcome::Unparseable {
                    reason: e.to_string(),
                };
            }
        },
    }

    match inputs.cell {
        None => ledger.sensors.cell = SensorOutcome::MissingTool,
        Some(b) if is_blank(b) => ledger.sensors.cell = SensorOutcome::Empty,
        Some(b) => match serde_json::from_slice::<Vec<CellRow>>(b) {
            Ok(cells) => {
                let before = ledger.entities.len();
                for cell in cells {
                    ingest_cell(&mut ledger, cell, epoch);
                }
                let n = ledger.entities.len() - before;
                ledger.sensors.cell = if n == 0 {
                    SensorOutcome::Empty
                } else {
                    SensorOutcome::Observed { count: n }
                };
            }
            Err(e) => {
                ledger.sensors.cell = SensorOutcome::Unparseable {
                    reason: e.to_string(),
                };
            }
        },
    }

    match inputs.radar_wifi {
        None => ledger.sensors.radar_wifi = SensorOutcome::MissingTool,
        Some(b) if is_blank(b) => ledger.sensors.radar_wifi = SensorOutcome::Empty,
        Some(b) => match ingest_radar_wifi(&mut ledger, b, epoch) {
            Ok(0) => ledger.sensors.radar_wifi = SensorOutcome::Empty,
            Ok(n) => ledger.sensors.radar_wifi = SensorOutcome::Observed { count: n },
            Err(reason) => {
                ledger.sensors.radar_wifi = SensorOutcome::Unparseable { reason };
            }
        },
    }

    match inputs.radar_devices {
        None => ledger.sensors.radar_devices = SensorOutcome::MissingTool,
        Some(b) if is_blank(b) => ledger.sensors.radar_devices = SensorOutcome::Empty,
        Some(b) => match ingest_radar_devices(&mut ledger, b, epoch) {
            Ok(0) => ledger.sensors.radar_devices = SensorOutcome::Empty,
            Ok(n) => ledger.sensors.radar_devices = SensorOutcome::Observed { count: n },
            Err(reason) => {
                ledger.sensors.radar_devices = SensorOutcome::Unparseable { reason };
            }
        },
    }

    if let Some(fix) = ledger.fix.clone() {
        for s in &mut ledger.sightings {
            if s.lat.is_none() {
                s.lat = Some(fix.latitude);
                s.lon = Some(fix.longitude);
            }
        }
    }

    ledger
}

fn ingest_wifi(ledger: &mut Ledger, ap: WifiAp, epoch: i64) {
    let Some(obs) = wifi_observation(
        &ap.bssid,
        ap.capabilities.as_deref(),
        ap.rssi,
        ap.frequency,
    ) else {
        ledger.skipped.push(Skipped {
            sensor: "wifi".into(),
            reason: "not_a_real_device_address".into(),
            raw: ap.bssid,
        });
        return;
    };
    let Some(key) = sighting_key(&ap.bssid) else {
        return;
    };
    let ssid = ap
        .ssid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut tags = vec![
        "wifi-ap".into(),
        format!("track:{}", track_str(obs.trackability)),
        format!("security:{}", security_str(obs.security)),
    ];
    if obs.enterprise {
        tags.push("enterprise".into());
    }
    if let Some(ch) = obs.channel {
        tags.push(format!("channel:{ch}"));
    }
    if let Some(band) = obs.proximity {
        tags.push(format!("proximity:{}", proximity_str(band)));
    }

    let mut attrs = vec![("bssid".into(), key.clone())];
    if let Some(s) = &ssid {
        attrs.push(("ssid".into(), s.clone()));
    }
    if let Some(r) = ap.rssi {
        attrs.push(("rssi_dbm".into(), r.to_string()));
    }
    if let Some(f) = ap.frequency {
        attrs.push(("frequency_mhz".into(), f.to_string()));
    }
    if let Some(w) = ap
        .channel_width
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        attrs.push(("channel_width".into(), w.to_string()));
    }

    ledger.entities.push(LedgerEntity {
        kind: "mac_address".into(),
        value: key.clone(),
        tags: tags.clone(),
        attrs: attrs.clone(),
    });
    if let Some(s) = &ssid {
        ledger.entities.push(LedgerEntity {
            kind: "ssid".into(),
            value: s.clone(),
            tags: vec!["wifi-ap".into()],
            attrs: vec![("bssid".into(), key.clone())],
        });
    }
    ledger.sightings.push(Sighting {
        key,
        radio: "wifi".into(),
        name: ssid,
        signal_dbm: ap.rssi.map(|v| v as f64),
        observed_epoch: epoch,
        lat: None,
        lon: None,
        raw_type: None,
    });
}

fn ingest_bt(ledger: &mut Ledger, dev: BtDevice, epoch: i64) {
    if !is_real_device_address(&dev.address) {
        ledger.skipped.push(Skipped {
            sensor: "bluetooth".into(),
            reason: "not_a_real_device_address".into(),
            raw: dev.address,
        });
        return;
    }
    let Some(key) = sighting_key(&dev.address) else {
        return;
    };
    let addr_type = match dev.address_type {
        Some(code) => BleAddressType::from_android(code),
        None => BleAddressType::Unknown,
    };
    let track = ble_address_trackability(&dev.address, addr_type);
    let name = dev
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let bt_type = dev.bt_type.as_deref().unwrap_or("unknown");
    let radio = if bt_type.eq_ignore_ascii_case("le") {
        "ble"
    } else {
        "bt_classic"
    };

    ledger.entities.push(LedgerEntity {
        kind: "mac_address".into(),
        value: key.clone(),
        tags: vec![
            "bluetooth".into(),
            format!("bt-{}", bt_type.to_ascii_lowercase()),
            format!("track:{}", track_str(track)),
            format!(
                "bond:{}",
                dev.bond_state
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_ascii_lowercase()
            ),
        ],
        attrs: vec![
            ("address".into(), key.clone()),
            (
                "name".into(),
                name.clone().unwrap_or_else(|| "<unknown>".into()),
            ),
        ],
    });
    ledger.sightings.push(Sighting {
        key,
        radio: radio.into(),
        name,
        signal_dbm: None,
        observed_epoch: epoch,
        lat: None,
        lon: None,
        raw_type: dev.bt_type,
    });
}

fn ingest_cell(ledger: &mut Ledger, cell: CellRow, epoch: i64) {
    let radio = CellRadio::from_type(cell.cell_type.as_deref());
    let cid = match radio {
        CellRadio::Lte => usable_cell_identity(cell.ci),
        CellRadio::Nr => usable_cell_identity(cell.nci),
        _ => usable_cell_identity(cell.cid).or_else(|| usable_cell_identity(cell.ci)),
    };
    let Some(cid) = cid else {
        ledger.skipped.push(Skipped {
            sensor: "cell".into(),
            reason: "identity_unavailable".into(),
            raw: cell.cell_type.unwrap_or_default(),
        });
        return;
    };
    let mcc = json_num(cell.mcc.as_ref());
    let mnc = json_num(cell.mnc.as_ref());
    if !is_numeric_segment(&mcc) || !is_numeric_segment(&mnc) {
        ledger.skipped.push(Skipped {
            sensor: "cell".into(),
            reason: "non_numeric_plmn".into(),
            raw: format!("{mcc}/{mnc}"),
        });
        return;
    }
    let area = usable_cell_identity(cell.tac)
        .or_else(|| usable_cell_identity(cell.lac))
        .unwrap_or(0);
    let id = tower_id(&mcc, &mnc, area, cid);
    let dbm = usable_dbm(cell.dbm);
    let mut tags = vec!["cell-tower".into(), radio.tech_tag().into()];
    if cell.registered.unwrap_or(false) {
        tags.push("registered".into());
    }
    let mut attrs = vec![
        ("tower_id".into(), id.clone()),
        ("mcc".into(), mcc),
        ("mnc".into(), mnc),
        ("cid".into(), cid.to_string()),
    ];
    if let Some(dbm) = dbm {
        attrs.push(("dbm".into(), dbm.to_string()));
    }
    ledger.entities.push(LedgerEntity {
        kind: "device_id".into(),
        value: id.clone(),
        tags,
        attrs,
    });
    ledger.sightings.push(Sighting {
        key: id,
        radio: "cellular".into(),
        name: None,
        signal_dbm: dbm.map(|v| v as f64),
        observed_epoch: epoch,
        lat: None,
        lon: None,
        raw_type: cell.cell_type,
    });
}

fn parse_gps(bytes: &[u8]) -> Result<Fix, String> {
    let row: GpsRow = serde_json::from_slice(bytes).or_else(|_| {
        let rows: Vec<GpsRow> = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        rows.into_iter()
            .next()
            .ok_or_else(|| "empty gps array".to_string())
    })?;
    match (row.latitude, row.longitude) {
        (Some(latitude), Some(longitude))
            if latitude.abs() <= 90.0 && longitude.abs() <= 180.0 =>
        {
            Ok(Fix {
                latitude,
                longitude,
                accuracy_m: row.accuracy,
                provider: row.provider,
            })
        }
        _ => Err("missing or out-of-range coordinates".into()),
    }
}

#[derive(Debug, Deserialize)]
struct RadarWifiDoc {
    access_points: Vec<RadarAp>,
    #[serde(default)]
    dropped: u64,
}

#[derive(Debug, Deserialize)]
struct RadarAp {
    bssid: String,
    ssid: Option<String>,
    rssi_dbm: Option<i64>,
    frequency_mhz: Option<i64>,
    channel: Option<i64>,
    proximity: Option<String>,
    security: Option<String>,
    enterprise: Option<serde_json::Value>,
    trackability: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RadarDevicesDoc {
    devices: Vec<RadarDevice>,
}

#[derive(Debug, Deserialize)]
struct RadarDevice {
    address: String,
    name: Option<String>,
    rssi_dbm: Option<f64>,
    proximity: Option<String>,
    trackability: Option<String>,
    manufacturer: Option<String>,
    beacon: Option<String>,
    identity_key: Option<String>,
}

fn ingest_radar_wifi(ledger: &mut Ledger, bytes: &[u8], epoch: i64) -> Result<usize, String> {
    let doc: RadarWifiDoc = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let dropped = doc.dropped;
    if dropped > 0 {
        ledger.skipped.push(Skipped {
            sensor: "radar_wifi".into(),
            reason: "radar_dropped_rows".into(),
            raw: dropped.to_string(),
        });
    }
    let before = ledger.sightings.len();
    for ap in doc.access_points {
        if let Some(ent) = ap.enterprise.as_ref() {
            if !ent.is_boolean() && !ent.is_null() {
                return Err(format!("malformed enterprise on {}", ap.bssid));
            }
        }
        let Some(key) = sighting_key(&ap.bssid) else {
            ledger.skipped.push(Skipped {
                sensor: "radar_wifi".into(),
                reason: "not_a_real_device_address".into(),
                raw: ap.bssid,
            });
            continue;
        };
        let enterprise = ap.enterprise.as_ref().and_then(serde_json::Value::as_bool) == Some(true);
        let ssid = ap
            .ssid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let mut tags = vec!["wifi-ap".into(), "radar-api".into()];
        if let Some(t) = ap.trackability.as_deref() {
            tags.push(format!("track:{}", t.to_ascii_lowercase()));
        }
        if let Some(s) = ap.security.as_deref() {
            tags.push(format!("security:{s}"));
        }
        if enterprise {
            tags.push("enterprise".into());
        }
        if let Some(ch) = ap.channel.filter(|c| *c > 0) {
            tags.push(format!("channel:{ch}"));
        }
        if let Some(p) = ap.proximity.as_deref() {
            tags.push(format!("proximity:{}", p.to_ascii_lowercase()));
        }
        ledger.entities.push(LedgerEntity {
            kind: "mac_address".into(),
            value: key.clone(),
            tags,
            attrs: vec![("bssid".into(), key.clone())],
        });
        ledger.sightings.push(Sighting {
            key,
            radio: "wifi".into(),
            name: ssid,
            signal_dbm: ap.rssi_dbm.map(|v| v as f64),
            observed_epoch: epoch,
            lat: None,
            lon: None,
            raw_type: ap.frequency_mhz.map(|f| format!("{f}MHz")),
        });
    }
    Ok(ledger.sightings.len() - before)
}

fn ingest_radar_devices(ledger: &mut Ledger, bytes: &[u8], epoch: i64) -> Result<usize, String> {
    let doc: RadarDevicesDoc = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let before = ledger.sightings.len();
    for dev in doc.devices {
        let Some(key) = sighting_key(&dev.address) else {
            ledger.skipped.push(Skipped {
                sensor: "radar_devices".into(),
                reason: "not_a_real_device_address".into(),
                raw: dev.address,
            });
            continue;
        };
        let name = dev
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let mut tags = vec!["bluetooth".into(), "radar-api".into()];
        if let Some(t) = dev.trackability.as_deref() {
            tags.push(format!("track:{}", t.to_ascii_lowercase()));
        }
        if let Some(p) = dev.proximity.as_deref() {
            tags.push(format!("proximity:{}", p.to_ascii_lowercase()));
        }
        let mut attrs = vec![("address".into(), key.clone())];
        if let Some(m) = dev.manufacturer.as_deref() {
            attrs.push(("manufacturer".into(), m.to_string()));
        }
        if let Some(b) = dev.beacon.as_deref() {
            attrs.push(("beacon".into(), b.to_string()));
        }
        if let Some(k) = dev.identity_key.as_deref() {
            attrs.push(("identity_key".into(), k.to_string()));
        }
        ledger.entities.push(LedgerEntity {
            kind: "mac_address".into(),
            value: key.clone(),
            tags,
            attrs,
        });
        ledger.sightings.push(Sighting {
            key,
            radio: "ble".into(),
            name,
            signal_dbm: dev.rssi_dbm,
            observed_epoch: epoch,
            lat: None,
            lon: None,
            raw_type: dev.beacon,
        });
    }
    Ok(ledger.sightings.len() - before)
}

/// Stretch the sweep period on a discharging low battery. Charging keeps the
/// requested period. A missing reading never shortens the period.
pub fn sweep_interval_secs(requested: u64, battery_pct: Option<u8>, charging: bool) -> u64 {
    let base = requested.max(5);
    if charging {
        return base;
    }
    match battery_pct {
        Some(p) if p <= 20 => base.max(90),
        Some(p) if p <= 40 => base.max(45),
        _ => base,
    }
}

/// Read a Termux/Android sysfs battery if present.
pub fn read_battery() -> (Option<u8>, bool) {
    let cap = std::fs::read_to_string("/sys/class/power_supply/battery/capacity")
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let status = std::fs::read_to_string("/sys/class/power_supply/battery/status")
        .unwrap_or_default();
    let charging = status.trim().eq_ignore_ascii_case("charging")
        || status.trim().eq_ignore_ascii_case("full");
    (cap, charging)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIFI: &[u8] = br#"[
      {"bssid":"3c:5a:b4:11:22:01","ssid":"HomeNet","rssi":-48,"frequency":2437,"capabilities":"[WPA2-PSK-CCMP][ESS]"},
      {"bssid":"00:00:00:00:00:00","ssid":"ghost","rssi":-20,"frequency":2412},
      {"bssid":"02:00:00:00:00:00","ssid":"masked","rssi":-30,"frequency":2412},
      {"bssid":"aa:bb:cc:dd:ee:01","ssid":"PhoneHotspot","rssi":5,"frequency":2412}
    ]"#;

    const BT: &[u8] = br#"[
      {"address":"4c:11:22:33:44:55","name":"Watch","type":"le","addressType":1},
      {"address":"00:00:00:00:00:00","name":"null"},
      {"address":"a4:c1:38:00:11:22","name":"Speaker","type":"classic"}
    ]"#;

    const CELL: &[u8] = br#"[
      {"type":"lte","registered":true,"mcc":505,"mnc":1,"tac":1234,"ci":567890,"dbm":-91},
      {"type":"lte","mcc":505,"mnc":1,"ci":2147483647,"dbm":2147483647}
    ]"#;

    const GPS: &[u8] = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":12.5,"provider":"gps"}"#;

    #[test]
    fn placeholder_wifi_is_skipped_and_corrupt_rssi_is_not_near() {
        let l = ingest("t", 1, SensorInputs { wifi: Some(WIFI), bluetooth: None, cell: None, gps: None, radar_wifi: None, radar_devices: None });
        let macs: Vec<_> = l.entities.iter().filter(|e| e.kind == "mac_address").map(|e| e.value.as_str()).collect();
        assert!(macs.contains(&"3c:5a:b4:11:22:01"));
        assert!(macs.contains(&"aa:bb:cc:dd:ee:01"));
        assert!(!macs.iter().any(|m| *m == "00:00:00:00:00:00"));
        let home = l.entities.iter().find(|e| e.value == "3c:5a:b4:11:22:01").unwrap();
        assert!(home.tags.iter().any(|t| t == "security:WPA2"));
        assert!(home.tags.iter().any(|t| t == "channel:6"));
        assert!(home.tags.iter().any(|t| t.starts_with("proximity:")));
        let hot = l.entities.iter().find(|e| e.value == "aa:bb:cc:dd:ee:01").unwrap();
        assert!(hot.tags.iter().any(|t| t == "track:randomized"));
        assert!(!hot.tags.iter().any(|t| t.contains("proximity:immediate") || t.contains("proximity:near")));
        assert_eq!(l.skipped.iter().filter(|s| s.sensor == "wifi").count(), 2);
    }

    #[test]
    fn ble_random_resolvable_is_not_filed_as_hardware() {
        let l = ingest("t", 1, SensorInputs { wifi: None, bluetooth: Some(BT), cell: None, gps: None, radar_wifi: None, radar_devices: None });
        let watch = l.entities.iter().find(|e| e.value == "4c:11:22:33:44:55").unwrap();
        assert!(watch.tags.iter().any(|t| t == "track:randomized"));
        let speaker = l.entities.iter().find(|e| e.value == "a4:c1:38:00:11:22").unwrap();
        assert!(speaker.tags.iter().any(|t| t == "track:trackable"));
        assert!(l.skipped.iter().any(|s| s.raw == "00:00:00:00:00:00"));
    }

    #[test]
    fn lte_uses_ci_and_drops_android_unavailable() {
        let l = ingest("t", 1, SensorInputs { wifi: None, bluetooth: None, cell: Some(CELL), gps: None, radar_wifi: None, radar_devices: None });
        assert_eq!(l.entities.iter().filter(|e| e.kind == "device_id").count(), 1);
        assert_eq!(l.entities[0].value, "505-1-1234-567890");
        assert!(l.entities[0].tags.iter().any(|t| t == "registered"));
        assert!(l.sightings[0].signal_dbm == Some(-91.0));
        assert!(l.skipped.iter().any(|s| s.reason == "identity_unavailable"));
    }

    #[test]
    fn gps_stamps_sightings_and_blank_sensors_are_empty_not_errors() {
        let l = ingest(
            "t",
            42,
            SensorInputs { wifi: Some(WIFI), bluetooth: Some(b" \n"), cell: None, gps: Some(GPS), radar_wifi: None, radar_devices: None },
        );
        assert_eq!(l.sensors.cell, SensorOutcome::MissingTool);
        assert_eq!(l.sensors.bluetooth, SensorOutcome::Empty);
        assert!(l.fix.as_ref().unwrap().latitude < 0.0);
        assert!(l.sightings.iter().all(|s| s.lat == Some(-27.4698)));
        assert_eq!(l.schema, SCHEMA);
        assert_eq!(l.radar_rev, PINNED_RADAR_REV);
    }

    #[test]
    fn silence_about_wifi_security_is_unknown() {
        let raw = br#"[{"bssid":"3c:5a:b4:11:22:01","rssi":-60,"frequency":2412}]"#;
        let l = ingest("t", 1, SensorInputs { wifi: Some(raw), bluetooth: None, cell: None, gps: None, radar_wifi: None, radar_devices: None });
        let e = l.entities.iter().find(|e| e.kind == "mac_address").unwrap();
        assert!(e.tags.iter().any(|t| t == "security:?"));
    }

    const RADAR_WIFI: &[u8] = br#"{"access_points":[
      {"bssid":"3c:5a:b4:11:22:01","ssid":"HomeNet","frequency_mhz":2437,"channel":6,"rssi_dbm":-48,"reliability":"VERY_HIGH_PLUS","proximity":"IMMEDIATE","security":"WPA2","enterprise":false,"trackability":"TRACKABLE","last_seen_ms":1,"first_seen_ms":1,"visits":2},
      {"bssid":"3c:5a:b4:11:22:04","ssid":"CorpNet","frequency_mhz":5745,"channel":149,"rssi_dbm":-60,"reliability":"VERY_HIGH","proximity":"NEAR","security":"WPA2","enterprise":true,"trackability":"TRACKABLE","last_seen_ms":1,"first_seen_ms":1,"visits":2},
      {"bssid":"02:00:00:00:00:00","ssid":"masked","frequency_mhz":2412,"channel":1,"rssi_dbm":-40,"reliability":"VERY_HIGH","proximity":"NEAR","security":"OPEN","enterprise":false,"trackability":"TRACKABLE","last_seen_ms":1,"first_seen_ms":null,"visits":null}
    ],"state":"active","dropped":2,"native_available":true,"timestamp_ms":1}"#;

    const RADAR_DEVICES: &[u8] = br#"{"devices":[
      {"address":"3C:5A:B4:11:22:01","name":"Tag Alpha","distance_m":1.234,"rssi_dbm":-61.4,"proximity":"NEAR","trackability":"TRACKABLE","company_id":"004c","manufacturer":"Apple, Inc.","beacon":"iBeacon","services":null,"identity_key":"3c:5a:b4:11:22:01","first_seen_ms":1,"visits":2,"trend":"STRONGER","freshness":"LIVE","confidence_percent":87,"last_seen_ago_ms":420},
      {"address":"AA:BB:CC:DD:EE","name":null,"distance_m":null,"rssi_dbm":-90.2,"proximity":"FAR","trackability":"UNKNOWN","company_id":null,"manufacturer":null,"beacon":null,"services":null,"identity_key":null,"first_seen_ms":null,"visits":null,"trend":"UNKNOWN","freshness":"STALE","confidence_percent":0,"last_seen_ago_ms":75000}
    ],"scanning":true,"native_available":true,"timestamp_ms":1}"#;

    #[test]
    fn radar_api_wifi_drops_placeholders_and_keeps_enterprise() {
        let l = ingest("t", 1, SensorInputs {
            wifi: None, bluetooth: None, cell: None, gps: None,
            radar_wifi: Some(RADAR_WIFI), radar_devices: None,
        });
        let macs: Vec<_> = l.entities.iter().filter(|e| e.kind == "mac_address").map(|e| e.value.as_str()).collect();
        assert!(macs.contains(&"3c:5a:b4:11:22:01"));
        assert!(macs.contains(&"3c:5a:b4:11:22:04"));
        assert!(!macs.iter().any(|m| *m == "02:00:00:00:00:00"));
        let corp = l.entities.iter().find(|e| e.value == "3c:5a:b4:11:22:04").unwrap();
        assert!(corp.tags.iter().any(|t| t == "enterprise"));
        assert!(l.skipped.iter().any(|s| s.reason == "radar_dropped_rows"));
    }

    #[test]
    fn radar_api_devices_drop_truncated_mac() {
        let l = ingest("t", 1, SensorInputs {
            wifi: None, bluetooth: None, cell: None, gps: None,
            radar_wifi: None, radar_devices: Some(RADAR_DEVICES),
        });
        assert!(l.entities.iter().any(|e| e.value == "3c:5a:b4:11:22:01" && e.tags.iter().any(|t| t == "radar-api")));
        assert!(l.skipped.iter().any(|s| s.sensor == "radar_devices" && s.raw == "AA:BB:CC:DD:EE"));
        let tag = l.entities.iter().find(|e| e.value == "3c:5a:b4:11:22:01").unwrap();
        assert!(tag.attrs.iter().any(|(k, v)| k == "manufacturer" && v == "Apple, Inc."));
    }

    #[test]
    fn radar_wifi_malformed_enterprise_is_unparseable() {
        let raw = br#"{"access_points":[{"bssid":"3c:5a:b4:11:22:01","ssid":"x","frequency_mhz":2437,"channel":6,"rssi_dbm":-48,"security":"WPA2","enterprise":"yes","trackability":"TRACKABLE"}]}"#;
        let l = ingest("t", 1, SensorInputs {
            wifi: None, bluetooth: None, cell: None, gps: None,
            radar_wifi: Some(raw), radar_devices: None,
        });
        match l.sensors.radar_wifi {
            SensorOutcome::Unparseable { reason } => assert!(reason.contains("enterprise")),
            other => panic!("{other:?}"),
        }
        assert!(l.entities.is_empty());
    }

    #[test]
    fn low_battery_never_shortens_the_requested_interval() {
        assert_eq!(sweep_interval_secs(30, Some(15), false), 90);
        assert_eq!(sweep_interval_secs(30, Some(15), true), 30);
        assert_eq!(sweep_interval_secs(120, Some(10), false), 120);
        assert_eq!(sweep_interval_secs(30, None, false), 30);
    }
}
