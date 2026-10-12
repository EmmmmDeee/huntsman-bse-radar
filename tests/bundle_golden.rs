//! The bundle the adapter exports is a wire format that other tools read, so its bytes are pinned
//! to `tests/golden/hse-bundle.v1.json`. A change to the output fails here. A deliberate change
//! needs a new golden file and a new schema string, so consumers can tell the formats apart.

use huntsman_bse_radar::hse::export_hse;
use huntsman_bse_radar::{SensorInputs, ingest};

const GOLDEN: &str = include_str!("golden/hse-bundle.v1.json");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn the_exported_bundle_is_the_golden_file_byte_for_byte() {
    let (wifi, bt, cell, gps, rw, rd) = (
        fixture("wifi.json"),
        fixture("bluetooth.json"),
        fixture("cell.json"),
        fixture("gps.json"),
        fixture("radar-wifi.json"),
        fixture("radar-devices.json"),
    );
    // The clock is fixed, so the sweep id and every observation time are the same on every run.
    let ledger = ingest(
        "golden-sweep",
        1_800_000_000,
        SensorInputs {
            wifi: Some(wifi.as_slice()),
            bluetooth: Some(bt.as_slice()),
            cell: Some(cell.as_slice()),
            gps: Some(gps.as_slice()),
            radar_wifi: Some(rw.as_slice()),
            radar_devices: Some(rd.as_slice()),
        },
    );
    let mut json = serde_json::to_string_pretty(&export_hse(&ledger)).unwrap();
    json.push('\n');
    assert_eq!(json, GOLDEN, "the exported bundle changed");
}
