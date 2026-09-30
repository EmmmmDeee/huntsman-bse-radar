//! `hse-radar` — Termux CLI for the HSE / BLE Radar adapter.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use huntsman_bse_radar::{
    Ledger, SensorInputs, ingest, now_epoch, read_battery, sweep_interval_secs,
};

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    let code = match cmd.as_str() {
        "ingest" => cmd_ingest(&args.collect::<Vec<_>>()),
        "sweep" => cmd_sweep(&args.collect::<Vec<_>>()),
        "serve" => cmd_serve(&args.collect::<Vec<_>>()),
        "doctor" => cmd_doctor(),
        "help" | "-h" | "--help" => {
            print_help();
            0
        }
        other => {
            eprintln!("unknown command: {other}");
            print_help();
            2
        }
    };
    std::process::exit(code);
}

fn print_help() {
    eprintln!(
        "hse-radar — Huntsman / BLE Radar Termux adapter\n\n\
         Commands:\n\
           ingest --wifi FILE [--bt FILE] [--cell FILE] [--gps FILE]\n\
                  [--radar-wifi FILE] [--radar-devices FILE] [-o FILE]\n\
           sweep  [--interval SECS] [--out DIR] [--radar-url URL]\n\
           serve  [--bind 127.0.0.1:8088] [--interval SECS] [--radar-url URL]\n\
           doctor\n\n\
         Sensors are the operator's own radios via Termux:API, or the BLE Radar\n\
         loopback API (GET /api/wifi and GET /api/devices on 127.0.0.1:8080).\n\
         Missing tools degrade to MissingTool — never a fabricated hit."
    );
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
}

fn read_opt(path: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    match path {
        None => Ok(None),
        Some(p) => fs::read(p).map(Some).map_err(|e| format!("{p}: {e}")),
    }
}

fn cmd_ingest(args: &[String]) -> i32 {
    let wifi = match read_opt(flag(args, "--wifi")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let bt = match read_opt(flag(args, "--bt")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let cell = match read_opt(flag(args, "--cell")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let gps = match read_opt(flag(args, "--gps")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let radar_wifi = match read_opt(flag(args, "--radar-wifi")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let radar_devices = match read_opt(flag(args, "--radar-devices")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if wifi.is_none()
        && bt.is_none()
        && cell.is_none()
        && gps.is_none()
        && radar_wifi.is_none()
        && radar_devices.is_none()
    {
        eprintln!("ingest needs at least one input file");
        return 2;
    }
    let epoch = now_epoch();
    let ledger = ingest(
        "cli-ingest",
        epoch,
        SensorInputs {
            wifi: wifi.as_deref(),
            bluetooth: bt.as_deref(),
            cell: cell.as_deref(),
            gps: gps.as_deref(),
            radar_wifi: radar_wifi.as_deref(),
            radar_devices: radar_devices.as_deref(),
        },
    );
    let json = serde_json::to_string_pretty(&ledger).expect("ledger serializes");
    if let Some(out) = flag(args, "-o").or_else(|| flag(args, "--out")) {
        if let Err(e) = fs::write(out, &json) {
            eprintln!("{out}: {e}");
            return 1;
        }
    } else {
        println!("{json}");
    }
    0
}

fn which(bin: &str) -> bool {
    env::var_os("PATH")
        .map(|p| env::split_paths(&p).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

fn run_tool(bin: &str) -> Option<Vec<u8>> {
    if !which(bin) {
        return None;
    }
    let out = Command::new(bin)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    if out.stdout.iter().all(|b| b.is_ascii_whitespace()) {
        Some(Vec::new())
    } else {
        Some(out.stdout)
    }
}

fn live_sweep(seed: &str, radar_url: Option<&str>) -> Ledger {
    let wifi = run_tool("termux-wifi-scaninfo");
    let bt = run_tool("termux-bluetooth-scaninfo");
    let cell = run_tool("termux-telephony-cellinfo");
    let gps = run_tool("termux-location");
    let radar_wifi = radar_url.and_then(|base| http_get_loopback(&format!("{base}/api/wifi")));
    let radar_devices = radar_url.and_then(|base| http_get_loopback(&format!("{base}/api/devices")));
    ingest(
        seed,
        now_epoch(),
        SensorInputs {
            wifi: wifi.as_deref(),
            bluetooth: bt.as_deref(),
            cell: cell.as_deref(),
            gps: gps.as_deref(),
            radar_wifi: radar_wifi.as_deref(),
            radar_devices: radar_devices.as_deref(),
        },
    )
}

fn http_get_loopback(url: &str) -> Option<Vec<u8>> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = rest.split_once('/')?;
    let path = format!("/{path}");
    if !hostport.starts_with("127.0.0.1") && !hostport.starts_with("localhost") {
        return None;
    }
    let mut stream = TcpStream::connect(hostport).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1)?;
    Some(body.as_bytes().to_vec())
}

fn cmd_sweep(args: &[String]) -> i32 {
    let requested: u64 = flag(args, "--interval")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let (pct, charging) = read_battery();
    let interval = sweep_interval_secs(requested, pct, charging);
    let radar_url = flag(args, "--radar-url");
    let out_dir = flag(args, "--out").map(PathBuf::from);
    if let Some(dir) = &out_dir {
        let _ = fs::create_dir_all(dir);
    }
    println!("sweep every {interval}s battery={pct:?} charging={charging} (Ctrl-C to stop)");
    loop {
        let ledger = live_sweep("cli-sweep", radar_url);
        let line = format!(
            "{} wifi={:?} bt={:?} cell={:?} gps={:?} entities={} sightings={} skipped={}",
            ledger.sweep_id,
            ledger.sensors.wifi,
            ledger.sensors.bluetooth,
            ledger.sensors.cell,
            ledger.sensors.gps,
            ledger.entities.len(),
            ledger.sightings.len(),
            ledger.skipped.len()
        );
        println!("{line}");
        if let Some(dir) = &out_dir {
            let path = dir.join(format!("{}.json", ledger.sweep_id));
            let _ = fs::write(path, serde_json::to_vec_pretty(&ledger).unwrap_or_default());
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

fn cmd_doctor() -> i32 {
    println!("hse-radar doctor");
    println!("radar_rev {}", huntsman_bse_radar::PINNED_RADAR_REV);
    for bin in [
        "termux-wifi-scaninfo",
        "termux-bluetooth-scaninfo",
        "termux-telephony-cellinfo",
        "termux-location",
    ] {
        println!(
            "{bin}: {}",
            if which(bin) { "present" } else { "missing (sensor will report MissingTool)" }
        );
    }
    0
}

fn cmd_serve(args: &[String]) -> i32 {
    let bind = flag(args, "--bind").unwrap_or("127.0.0.1:8088");
    let requested: u64 = flag(args, "--interval")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let (pct, charging) = read_battery();
    let interval = sweep_interval_secs(requested, pct, charging);
    let radar_url = flag(args, "--radar-url").map(str::to_string);
    let state = Arc::new(Mutex::new(live_sweep("serve", radar_url.as_deref())));
    {
        let state = Arc::clone(&state);
        let radar_url = radar_url.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(interval));
                let next = live_sweep("serve", radar_url.as_deref());
                if let Ok(mut g) = state.lock() {
                    *g = next;
                }
            }
        });
    }
    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {bind}: {e}");
            return 1;
        }
    };
    println!("hse-radar ui http://{bind}  (loopback only)");
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else { continue };
        let peer_ok = stream
            .peer_addr()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        if !peer_ok {
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            continue;
        }
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let path = req.split_whitespace().nth(1).unwrap_or("/");
        if path.starts_with("/api/ledger") {
            let body = state
                .lock()
                .ok()
                .and_then(|g| serde_json::to_vec_pretty(&*g).ok())
                .unwrap_or_else(|| b"{}".to_vec());
            reply(&mut stream, "application/json", &body);
        } else {
            reply(&mut stream, "text/html; charset=utf-8", UI.as_bytes());
        }
    }
    0
}

fn reply(stream: &mut TcpStream, ctype: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
}

const UI: &str = r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>HSE Radar</title>
<style>
:root{--bg:#0a0b0d;--ink:#121418;--steel:#b8c4d4;--paper:#eceef1;--sage:#6fbf9a;--alarm:#c4513c;--brass:#c4a15a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--paper);font:16px/1.4 system-ui,sans-serif}
header{padding:16px;background:var(--ink);position:sticky;top:0}
h1{margin:0;font-size:20px;letter-spacing:.04em}
.meta{color:var(--steel);font-size:13px;margin-top:6px}
main{padding:12px}
.card{background:var(--ink);border-radius:14px;padding:14px;margin:10px 0}
.row{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid #1c1f26;min-height:44px;align-items:center}
.row:last-child{border:0}
.tag{font-size:11px;color:var(--sage);letter-spacing:.06em;text-transform:uppercase}
.bad{color:var(--alarm)}
.muted{color:var(--steel)}
</style></head>
<body>
<header><h1>HUNTSMAN RADAR</h1><div class="meta" id="meta">loading…</div></header>
<main id="root"></main>
<script>
async function load(){
  const r = await fetch('/api/ledger');
  const j = await r.json();
  document.getElementById('meta').textContent =
    (j.sweep_id||'')+' · '+((j.sightings||[]).length)+' sightings · rev '+(j.radar_rev||'').slice(0,8);
  const rows = (j.sightings||[]).map(s =>
    '<div class="row"><div><div>'+esc(s.name||s.key)+'</div><div class="muted">'+esc(s.radio)+
    (s.signal_dbm==null?'':' · '+s.signal_dbm+' dBm')+'</div></div><div class="tag">'+esc(s.key)+'</div></div>'
  ).join('') || '<div class="muted">No sightings this sweep. On Termux install Termux:API and grant location / nearby devices.</div>';
  const skip = (j.skipped||[]).map(s =>
    '<div class="row"><div class="bad">'+esc(s.reason)+'</div><div class="muted">'+esc(s.raw)+'</div></div>'
  ).join('');
  document.getElementById('root').innerHTML =
    '<div class="card"><div class="tag">Sightings</div>'+rows+'</div>'+
    (skip?'<div class="card"><div class="tag">Skipped</div>'+skip+'</div>':'');
}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({ '&':'&','<':'<','>':'>','"':'"'}[c]))}
load(); setInterval(load, 4000);
</script></body></html>
"#;

#[allow(dead_code)]
fn _keep_path_ty(_: &Path) {}
