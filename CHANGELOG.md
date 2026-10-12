# Changelog

All notable changes to this crate are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The crate (`huntsman-bse-radar`, version `0.1.0` in `Cargo.toml`) has no stable release and no
git tags. A build is identified by its commit, and `hse-radar --version` prints the crate version
and the pinned BLE Radar revision. Each output format names its version in its schema string:
`hse-bse-radar.sighting-ledger.v1` for the ledger and `hse-core.entity-bundle.v1` for the bundle.
A change to either format gets a new schema string.

## [Unreleased]

### Added

- `hse-radar --version` (also `-V` and `version`) prints the crate version and the pinned BLE
  Radar revision.
- A CI job that runs the test suites on the declared minimum Rust version, 1.98.0.
- `tests/bundle_golden.rs` pins the exported bundle byte for byte.

### Changed

- `serve` answers only the `Host` values `127.0.0.1`, `localhost` and `[::1]` (any port). Any
  other name gets `403`.
- Paths match exactly. An unknown path gets `404`; it used to get the page.
- `--radar-url` must be exactly a loopback name. `127.0.0.1.example.com` and
  `127.0.0.1@example.com` are refused.
- `serve` prints the address it bound, so `--bind 127.0.0.1:0` reports its port.
- A Termux:API tool that gives no answer within 30 s is stopped, and its sensor is reported as
  `MissingTool`. The limit is set by `HSE_RADAR_TOOL_TIMEOUT_SECS`.
- Each connection has its own thread, at most 16 at a time. A further connection gets `503` with
  `Retry-After: 1`.

### Fixed

- A radio's name is shown as text in the page. It used to be assigned as markup, so a name could
  run script there.
- The page loads while the first sweep is still running, and says so until the sweep ends.
- A connection that sends nothing no longer holds up other requests.

### Refactored

- The bundle types, UIDs and normalisers come from the `hse-entity-bundle` crate, the one
  definition of the `hse-core.entity-bundle.v1` format. The exported bytes are unchanged, as
  `tests/bundle_golden.rs` shows.
- Every clippy finding is fixed (`-D warnings` on every target), and the crate is rustfmt-clean.
