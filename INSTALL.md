# HSE BSE Radar — Termux install

Adapter only. Full Huntsman Search Engine remains:

https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-

Install HSE with its own installer. This crate is the Termux-side BLE Radar seam
using `bleradar-core` at `d0b1e8d09621abde6ff3c7b1b9d7927a95e6f7fc` (radar `main`
2026-09-30). HSE `1.41.0` is still pinned to `98c4b089…` and does not yet call
`wifi_observation` or `ble_address_trackability`.

## Termux (aarch64, no root)

Use F-Droid Termux, not Play Store.

```bash
pkg update
pkg install rust clang git termux-api
# grant Termux:API location + nearby devices in Android settings
tar xf hse-bse-radar.zip
cd hse-bse-radar
cargo test --offline || cargo test
cargo build --profile fast
cp target/fast/hse-radar "$PREFIX/bin/hse-radar"
hse-radar doctor
hse-radar ingest --wifi fixtures/wifi.json --bt fixtures/bluetooth.json --cell fixtures/cell.json --gps fixtures/gps.json
hse-radar ingest --radar-wifi fixtures/radar-wifi.json --radar-devices fixtures/radar-devices.json
hse-radar serve --bind 127.0.0.1:8088 --radar-url http://127.0.0.1:8080

```

Open `http://127.0.0.1:8088` on the phone. Loopback only.

`hse-radar sweep --interval 30 --out ~/.hse/radar` writes one ledger JSON per
tick. Missing Termux tools report `MissingTool`; they do not invent devices.

## What this does not do

- Does not replace the 194-module HSE binary.
- Does not harvest credentials or scan third-party networks beyond the
  operator's own radios.
- Does not push to HSE `main` (HSE push gate requires `scripts/gate.sh` on
  that tree).
