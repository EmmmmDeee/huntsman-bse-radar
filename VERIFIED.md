# Verified record — HSE BSE Radar adapter 0.1.0

Date: 2026-09-30

## Recovered objective


Deliver a functional Termux-compatible Huntsman radar integration that
preserves HSE contracts and uses BLE Radar (`bleradar-core`) as the single
authority for reading rules.

## Facts

- HSE 1.41.0 already exists at EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust- (`81caa593`).
- HSE pins `bleradar-core` to `98c4b089f481883445001af8262c440f3115367b`.
- BLE Radar `main` is `d0b1e8d09621abde6ff3c7b1b9d7927a95e6f7fc` (this session).
- HSE `signal_radar` maps Termux JSON onto entities; Wi-Fi security/enterprise
  and BLE address-type trackability are not called (`wifi_observation`,
  `ble_address_trackability`).
- This sandbox is x86_64 with Rust 1.98.1. It is not Termux aarch64.

## Highest-impact limit attacked

Stale / incomplete seam: HSE still classifies BLE trackability by the Wi-Fi
U/L bit and does not apply `wifi_observation`. Rebuilding the 194-module
engine here is not reproducible under present constraints (no HSE worktree
gate, 8500+ tests, proprietary push hook).

## Candidates

1. Bump HSE pin + patch `signal_radar` on HSE main — highest product value,
   blocked: cannot run `scripts/gate.sh` on the HSE tree in this session.
2. Standalone adapter on current `bleradar-core` with fixtures and a
   loopback UI — executable here.
3. Rewrite HSE from scratch — dominated; would be an unverified fork.

Accepted (2).

## Falsification

- Placeholder `00:00:00:00:00:00` / `02:00:00:00:00:00` must not become
  entities. Observed: skipped.
- Positive Wi-Fi RSSI must not band as near/immediate. Observed: no proximity tag.
- Resolvable-private BLE `4c:11:22:33:44:55` with Android addressType=1 must
  be `track:randomized` (U/L bit would call it hardware). Observed: randomized.
- LTE identity from `ci`, Android `Integer.MAX_VALUE` dropped. Observed:
  one tower `505-1-1234-567890`, nci=0 skipped.
- Missing Termux tools are `MissingTool`, not hits. Observed: `hse-radar doctor`.

## Executed

- Rust crate: `artifacts/hse-bse-radar`
- Binary: `hse-radar`
- Command: `CARGO_TARGET_DIR=/tmp/hse-bse-target cargo test`
- Result: 7 passed, 0 failed (5 lib + 2 e2e)

## Claim

PARTIAL — adapter is verified end-to-end on host fixtures and the current
radar library. Not verified: on-device Termux aarch64 radios, HSE pin bump,
or the 194-module `hse` binary itself (already shipped upstream; not rebuilt).

## Residual

- On-device Termux run is NOT APPLICABLE in this sandbox.
- Pushing HSE main is a hard external blocker (gate + AGENTS.md issued query).
- Credential harvest (HSE RULE 3) is NOT APPLICABLE here.
