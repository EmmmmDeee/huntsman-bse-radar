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

`serve` opens its port at once and runs the first sweep behind it; the page says
"sweeping…" until that sweep ends. Each connection is served on its own thread
(16 at a time, then `503`), so a connection that sends nothing, as a phone
browser's speculative ones do, holds up only itself. Only loopback peers are
answered, and only for `Host: 127.0.0.1`, `localhost` or `[::1]` (any other name
gets `403`). The page is static, shows every name as text and never as markup,
and its `Content-Security-Policy` allows no inline script and no connection to
another origin.

A Termux:API tool that gives no answer in 30 s is stopped and its sensor is
reported `MissingTool`. `HSE_RADAR_TOOL_TIMEOUT_SECS` changes the limit.

Install: see `INSTALL.md`. Config template: `radar.toml.example`.
Verified claims: `VERIFIED.md`.
