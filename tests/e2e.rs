use std::process::Command;

#[test]
fn binary_ingests_fixtures_to_a_ledger() {
    let root = env!("CARGO_MANIFEST_DIR");
    let bin = env!("CARGO_BIN_EXE_hse-radar");
    let out = std::env::temp_dir().join("hse-radar-e2e.json");
    let status = Command::new(bin)
        .args([
            "ingest",
            "--wifi",
            &format!("{root}/fixtures/wifi.json"),
            "--bt",
            &format!("{root}/fixtures/bluetooth.json"),
            "--cell",
            &format!("{root}/fixtures/cell.json"),
            "--gps",
            &format!("{root}/fixtures/gps.json"),
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .expect("spawn");
    assert!(status.success());
    let raw = std::fs::read_to_string(&out).expect("ledger written");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("json");
    assert_eq!(v["schema"], "hse-bse-radar.sighting-ledger.v1");
    assert_eq!(
        v["radar_rev"],
        "d0b1e8d09621abde6ff3c7b1b9d7927a95e6f7fc"
    );
    assert!(v["entities"].as_array().unwrap().len() >= 4);
    assert!(v["skipped"].as_array().unwrap().iter().any(|s| s["raw"] == "00:00:00:00:00:00"));
}

#[test]
fn binary_ingests_radar_api_fixtures() {
    let root = env!("CARGO_MANIFEST_DIR");
    let bin = env!("CARGO_BIN_EXE_hse-radar");
    let out = std::env::temp_dir().join("hse-radar-api-e2e.json");
    let wifi = format!("{root}/fixtures/radar-wifi.json");
    let devices = format!("{root}/fixtures/radar-devices.json");
    std::fs::write(
        &wifi,
        r#"{"access_points":[{"bssid":"3c:5a:b4:11:22:01","ssid":"HomeNet","frequency_mhz":2437,"channel":6,"rssi_dbm":-48,"security":"WPA2","enterprise":false,"trackability":"TRACKABLE"}],"dropped":0}"#,
    )
    .unwrap();
    std::fs::write(
        &devices,
        r#"{"devices":[{"address":"3C:5A:B4:11:22:01","name":"Tag Alpha","rssi_dbm":-61.4,"proximity":"NEAR","trackability":"TRACKABLE","manufacturer":"Apple, Inc.","beacon":"iBeacon"}]}"#,
    )
    .unwrap();
    let status = Command::new(bin)
        .args([
            "ingest",
            "--radar-wifi",
            wifi.as_str(),
            "--radar-devices",
            devices.as_str(),
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(v["entities"].as_array().unwrap().len() >= 2);
}

#[test]
fn doctor_exits_zero() {
    let bin = env!("CARGO_BIN_EXE_hse-radar");
    let status = Command::new(bin).arg("doctor").status().unwrap();
    assert!(status.success());
}
