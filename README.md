# huntsman-bse-radar

Termux adapter between [Huntsman Search Engine](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-) and [HSE BLE Radar](https://github.com/EmmmmDeee/HSE-BLE-API-).

This repository is the seam. It does not replace the 194-module `hse` binary.
Reading rules live in vendored `bleradar-core` (`d0b1e8d09621abde6ff3c7b1b9d7927a95e6f7fc`).

## Commands

```
hse-radar ingest --wifi FILE [--bt FILE] [--cell FILE] [--gps FILE]
                 [--radar-wifi FILE] [--radar-devices FILE] [-o FILE]
hse-radar sweep  [--interval SECS] [--out DIR] [--radar-url http://127.0.0.1:8080]
hse-radar serve  [--bind 127.0.0.1:8088] [--interval SECS] [--radar-url URL]
hse-radar doctor
```

`--radar-url` is loopback-only (Radar `ApiHttpServer.DEFAULT_PORT` = 8080).
Low battery stretches the sweep interval; it never shortens it.

Install: see `INSTALL.md`. Config template: `radar.toml.example`.
Verified claims: `VERIFIED.md`.
