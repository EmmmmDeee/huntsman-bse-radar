//! `hse-radar` — Termux CLI for the HSE / BLE Radar adapter.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use huntsman_bse_radar::hse::export_hse;
use huntsman_bse_radar::web::{self, Route};
use huntsman_bse_radar::{
    Ledger, PINNED_RADAR_REV, SCHEMA, SensorInputs, SensorStatus, ingest, now_epoch, read_battery,
    sweep_interval_secs,
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
                  [--radar-wifi FILE] [--radar-devices FILE]\n\
                  [-o FILE] [--hse-out FILE]\n\
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
    if let Some(hse_out) = flag(args, "--hse-out") {
        let bundle = export_hse(&ledger);
        let body = serde_json::to_string_pretty(&bundle).expect("hse bundle serializes");
        if let Err(e) = fs::write(hse_out, body) {
            eprintln!("{hse_out}: {e}");
            return 1;
        }
    }
    0
}

fn which(bin: &str) -> bool {
    env::var_os("PATH")
        .map(|p| env::split_paths(&p).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

/// How long a Termux:API tool may take before it is stopped. A tool that never answers (the API app
/// is missing, or it waits on a permission prompt) must not stop a sweep, or the page behind it.
const DEFAULT_TOOL_TIMEOUT_SECS: u64 = 30;

fn tool_timeout() -> Duration {
    let secs = env::var("HSE_RADAR_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_TOOL_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Runs a Termux:API tool. `None` when the tool is missing or gave no answer in time; the sensor is
/// then reported as `MissingTool`, never as a hit.
fn run_tool(bin: &str) -> Option<Vec<u8>> {
    if !which(bin) {
        return None;
    }
    let mut child = Command::new(bin)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = sender.send(buf);
    });
    let answer = receiver.recv_timeout(tool_timeout());
    // Finished or not, the tool is done with here.
    let _ = child.kill();
    let _ = child.wait();
    let Ok(out) = answer else {
        eprintln!("hse-radar: {bin} gave no answer in time; its sensor is reported as MissingTool");
        return None;
    };
    if out.iter().all(u8::is_ascii_whitespace) {
        Some(Vec::new())
    } else {
        Some(out)
    }
}

fn live_sweep(seed: &str, radar_url: Option<&str>) -> Ledger {
    let wifi = run_tool("termux-wifi-scaninfo");
    let bt = run_tool("termux-bluetooth-scaninfo");
    let cell = run_tool("termux-telephony-cellinfo");
    let gps = run_tool("termux-location");
    let radar_wifi = radar_url.and_then(|base| http_get_loopback(&format!("{base}/api/wifi")));
    let radar_devices =
        radar_url.and_then(|base| http_get_loopback(&format!("{base}/api/devices")));
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

/// The most a loopback API reply may be.
const MAX_LOOPBACK_BODY: u64 = 4 * 1024 * 1024;

fn http_get_loopback(url: &str) -> Option<Vec<u8>> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest.split_once('/')?;
    let (host, port) = web::loopback_target(authority)?;
    // `localhost` may resolve to ::1 first while the API listens on 127.0.0.1 only, so every address
    // is tried, as `TcpStream::connect` does.
    let mut stream = (host, port)
        .to_socket_addrs()
        .ok()?
        .find_map(|address| TcpStream::connect_timeout(&address, Duration::from_secs(2)).ok())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let req = format!("GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    Read::take(&mut stream, MAX_LOOPBACK_BODY)
        .read_to_end(&mut buf)
        .ok()?;
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some(buf[split + 4..].to_vec())
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
            if which(bin) {
                "present"
            } else {
                "missing (sensor will report MissingTool)"
            }
        );
    }
    0
}

/// Connections served at once. A phone browser opens speculative ones that send nothing, so each
/// connection has its own thread and one that stays silent holds up only itself.
const MAX_CONNECTIONS: usize = 16;
const CONNECTION_STACK_BYTES: usize = 256 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_DEADLINE: Duration = Duration::from_secs(8);
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// What the page shows until the first sweep ends: no sightings and no sweep id.
fn waiting_ledger() -> Ledger {
    Ledger {
        schema: SCHEMA.to_string(),
        radar_rev: PINNED_RADAR_REV.to_string(),
        sweep_id: String::new(),
        observed_epoch: now_epoch(),
        fix: None,
        entities: Vec::new(),
        sightings: Vec::new(),
        skipped: Vec::new(),
        sensors: SensorStatus::default(),
    }
}

fn cmd_serve(args: &[String]) -> i32 {
    let bind = flag(args, "--bind").unwrap_or("127.0.0.1:8088");
    let requested: u64 = flag(args, "--interval")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let (pct, charging) = read_battery();
    let interval = sweep_interval_secs(requested, pct, charging);
    let radar_url = flag(args, "--radar-url").map(str::to_string);
    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {bind}: {e}");
            return 1;
        }
    };
    // The page is up before the first sweep ends, so a slow sensor never keeps it away.
    let state = Arc::new(Mutex::new(waiting_ledger()));
    {
        let state = Arc::clone(&state);
        thread::spawn(move || {
            loop {
                let next = live_sweep("serve", radar_url.as_deref());
                if let Ok(mut g) = state.lock() {
                    *g = next;
                }
                thread::sleep(Duration::from_secs(interval));
            }
        });
    }
    // The address actually bound, so `--bind 127.0.0.1:0` reports the port it got.
    let shown = listener
        .local_addr()
        .map_or_else(|_| bind.to_string(), |address| address.to_string());
    println!("hse-radar ui http://{shown}  (loopback only)");
    let live = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        serve_on_a_thread(stream, &state, &live);
    }
    0
}

/// One of the `MAX_CONNECTIONS` places; dropping it frees it, also when the handler panics.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_on_a_thread(stream: TcpStream, state: &Arc<Mutex<Ledger>>, live: &Arc<AtomicUsize>) {
    if live.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
        live.fetch_sub(1, Ordering::AcqRel);
        refuse_busy(stream);
        return;
    }
    let slot = Slot(Arc::clone(live));
    let state = Arc::clone(state);
    // The thread owns the stream; this copy lets a failed spawn still answer the client.
    let fallback = stream.try_clone().ok();
    let spawned = thread::Builder::new()
        .name("serve-connection".into())
        .stack_size(CONNECTION_STACK_BYTES)
        .spawn(move || {
            let _slot = slot;
            handle_connection(stream, &state);
        });
    if spawned.is_err()
        && let Some(stream) = fallback
    {
        refuse_busy(stream);
    }
}

fn refuse_busy(mut stream: TcpStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let _ = stream.write_all(&web::reply(
        503,
        "text/plain; charset=utf-8",
        b"busy\n",
        false,
    ));
}

/// The head of a request, up to the blank line. `None` when the client sent nothing useful in time.
fn read_head(stream: &mut TcpStream) -> Option<String> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while buf.len() < MAX_REQUEST_BYTES && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let left = deadline.checked_duration_since(Instant::now())?;
        stream.set_read_timeout(Some(left.min(READ_TIMEOUT))).ok()?;
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

fn handle_connection(mut stream: TcpStream, state: &Mutex<Ledger>) {
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    let loopback = stream
        .peer_addr()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(false);
    if !loopback {
        let _ = stream.write_all(&web::reply(
            403,
            "text/plain; charset=utf-8",
            b"forbidden\n",
            false,
        ));
        return;
    }
    let Some(head) = read_head(&mut stream) else {
        return;
    };
    let dynamic = |route: Route| -> Vec<u8> {
        let ledger = state.lock().ok();
        let body = match (route, ledger) {
            (Route::HseEntities, Some(g)) => serde_json::to_vec_pretty(&export_hse(&g)).ok(),
            (_, Some(g)) => serde_json::to_vec_pretty(&*g).ok(),
            (_, None) => None,
        };
        body.unwrap_or_else(|| b"{}".to_vec())
    };
    let _ = stream.write_all(&web::answer(&head, &dynamic));
}

#[allow(dead_code)]
fn _keep_path_ty(_: &Path) {}
