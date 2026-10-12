//! `hse-radar serve` against the real binary, with stand-ins for the Termux:API tools. These are the
//! things a phone browser does to the page: it opens speculative connections that send nothing, it
//! loads the page while a sensor is still being read, and a nearby radio can name itself anything.
#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const HOSTILE_SSID: &str = "<img src=x onerror=__pwned=1>";

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
    // Kept open so the server never writes to a closed pipe.
    _stdout: BufReader<ChildStdout>,
}

impl Server {
    /// Starts `hse-radar serve` with `termux-wifi-scaninfo` replaced by `wifi_tool`, a shell script body.
    fn start(name: &str, wifi_tool: &str, env: &[(&str, &str)], extra: &[String]) -> Self {
        let dir =
            std::env::temp_dir().join(format!("hse-radar-serve-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let tool = bin.join("termux-wifi-scaninfo");
        fs::write(&tool, format!("#!/bin/sh\n{wifi_tool}\n")).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_hse-radar"))
            .args(["serve", "--bind", "127.0.0.1:0"])
            .args(extra)
            .current_dir(&dir)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("HOME", &dir)
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child = child;
        // The server reports the port it bound; asking the OS for a free one first and passing it
        // on would let two tests that run together be handed the same port.
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut announced = String::new();
        stdout.read_line(&mut announced).unwrap();
        let port = announced
            .trim()
            .split("http://127.0.0.1:")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|port| port.parse().ok())
            .unwrap_or_else(|| panic!("the server did not announce its port: {announced:?}"));
        Self {
            child,
            port,
            dir,
            _stdout: stdout,
        }
    }

    /// One request, answered in full or not at all within `wait`.
    fn get(&self, host: &str, path: &str, wait: Duration) -> std::io::Result<String> {
        let mut client = TcpStream::connect(("127.0.0.1", self.port))?;
        client.set_read_timeout(Some(wait))?;
        client.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )?;
        let mut reply = String::new();
        match client.read_to_string(&mut reply) {
            Err(error) if error.kind() == ErrorKind::ConnectionReset && !reply.is_empty() => {}
            outcome => {
                outcome?;
            }
        }
        Ok(reply)
    }

    fn get_local(&self, path: &str) -> std::io::Result<String> {
        self.get(
            &format!("127.0.0.1:{}", self.port),
            path,
            Duration::from_secs(3),
        )
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn body_of(reply: &str) -> &str {
    reply.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn hostile_wifi() -> String {
    format!(
        "cat <<'EOF'\n[{{\"bssid\":\"3c:5a:b4:11:22:01\",\"ssid\":\"{HOSTILE_SSID}\",\"rssi\":-48,\"frequency\":2437}}]\nEOF"
    )
}

#[test]
fn the_page_and_its_files_are_served_under_the_policy() {
    let server = Server::start("files", &hostile_wifi(), &[], &[]);
    for (path, kind) in [
        ("/", "text/html"),
        ("/app.js", "text/javascript"),
        ("/app.css", "text/css"),
    ] {
        let reply = server.get_local(path).unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{path}: {reply}");
        assert!(reply.contains(&format!("Content-Type: {kind}")), "{path}");
        assert!(
            reply.contains("Content-Security-Policy: default-src 'none'; script-src 'self';"),
            "{path}"
        );
    }
    assert!(
        server
            .get_local("/favicon.ico")
            .unwrap()
            .starts_with("HTTP/1.1 204")
    );
    assert!(
        server
            .get_local("/nowhere")
            .unwrap()
            .starts_with("HTTP/1.1 404")
    );
}

#[test]
fn an_idle_connection_does_not_hold_up_the_page() {
    // A browser opens connections ahead of the request and sends nothing on them. The server used to
    // read one connection at a time, with no timeout, so the page never loaded behind one.
    let server = Server::start("idle", &hostile_wifi(), &[], &[]);
    let _idle = [
        TcpStream::connect(("127.0.0.1", server.port)).unwrap(),
        TcpStream::connect(("127.0.0.1", server.port)).unwrap(),
    ];
    let started = Instant::now();
    let reply = server
        .get_local("/")
        .expect("the page was answered while other connections sat idle");
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_request_for_another_host_name_is_refused() {
    // DNS rebinding: a page on another name that resolves to 127.0.0.1 sends its own name as Host.
    let server = Server::start("host", &hostile_wifi(), &[], &[]);
    let own = format!("127.0.0.1:{}", server.port);
    let wait = Duration::from_secs(3);
    for host in [own.as_str(), "localhost:8088", "[::1]:8088"] {
        let reply = server.get(host, "/api/ledger", wait).unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{host}: {reply}");
    }
    for host in [
        "rebind.example.com",
        "127.0.0.1.example.com",
        "127.0.0.1@example.com",
    ] {
        let reply = server.get(host, "/api/ledger", wait).unwrap();
        assert!(
            reply.starts_with("HTTP/1.1 403 Forbidden"),
            "{host}: {reply}"
        );
        assert!(!reply.contains("sweep_id"), "{host}: the ledger was served");
    }
}

#[test]
fn a_radio_name_is_served_as_data() {
    let server = Server::start("name", &hostile_wifi(), &[], &[]);
    let started = Instant::now();
    let ledger = loop {
        let reply = server.get_local("/api/ledger").unwrap();
        if reply.contains(HOSTILE_SSID) {
            break reply;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no sweep: {reply}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(ledger.contains("Content-Type: application/json"));
    let json: serde_json::Value = serde_json::from_str(body_of(&ledger)).unwrap();
    assert_eq!(json["sightings"][0]["name"], HOSTILE_SSID);
}

#[test]
fn the_page_is_up_while_the_first_sweep_is_still_running() {
    // The listener used to open only after the first sweep, so a slow sensor kept the page away.
    let slow = format!("sleep 3\n{}", hostile_wifi());
    let server = Server::start("slow-first", &slow, &[], &[]);
    let waiting = server.get_local("/api/ledger").unwrap();
    assert!(waiting.starts_with("HTTP/1.1 200 OK"), "{waiting}");
    let json: serde_json::Value = serde_json::from_str(body_of(&waiting)).unwrap();
    assert_eq!(
        json["sweep_id"], "",
        "the first sweep cannot have ended yet"
    );
    assert_eq!(json["sightings"], serde_json::json!([]));
    assert!(
        server
            .get_local("/")
            .unwrap()
            .starts_with("HTTP/1.1 200 OK")
    );

    let started = Instant::now();
    loop {
        let reply = server.get_local("/api/ledger").unwrap();
        let json: serde_json::Value = serde_json::from_str(body_of(&reply)).unwrap();
        if json["sweep_id"] != "" {
            assert_eq!(json["sightings"][0]["name"], HOSTILE_SSID);
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the sweep never ended"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_tool_that_never_answers_is_stopped_and_reported_missing() {
    let server = Server::start(
        "hung-tool",
        "exec sleep 600",
        &[("HSE_RADAR_TOOL_TIMEOUT_SECS", "1")],
        &[],
    );
    let started = Instant::now();
    loop {
        let reply = server.get_local("/api/ledger").unwrap();
        let json: serde_json::Value = serde_json::from_str(body_of(&reply)).unwrap();
        if json["sweep_id"] != "" {
            assert_eq!(json["sensors"]["wifi"], "MissingTool");
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the sweep waited for a tool that never answers"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The sweep reads the BLE Radar loopback API at `http://{host}:{port}`.
fn read_loopback_api(name: &str, host: &str) {
    // The reply was cut at its second blank line, and a body can hold one between JSON members.
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_port = api.local_addr().unwrap().port();
    let body = "{\"access_points\":[{\"bssid\":\"3c:5a:b4:11:22:01\",\"ssid\":\"HomeNet\",\
        \"frequency_mhz\":2437,\"channel\":6,\"rssi_dbm\":-48,\"security\":\"WPA2\",\
        \"enterprise\":false,\"trackability\":\"TRACKABLE\"}],\r\n\r\n\"dropped\":0}";
    std::thread::spawn(move || {
        for stream in api.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    let server = Server::start(
        name,
        "echo '[]'",
        &[],
        &[
            "--radar-url".to_owned(),
            format!("http://{host}:{api_port}"),
        ],
    );
    let started = Instant::now();
    loop {
        let reply = server.get_local("/api/ledger").unwrap();
        let json: serde_json::Value = serde_json::from_str(body_of(&reply)).unwrap();
        if json["sweep_id"] != "" {
            assert_eq!(
                json["sensors"]["radar_wifi"],
                serde_json::json!({ "Observed": { "count": 1 } })
            );
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the sweep never ended"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_loopback_api_reply_is_read_whole() {
    read_loopback_api("radar-api-ip", "127.0.0.1");
}

#[test]
fn a_loopback_api_is_found_by_the_name_localhost() {
    read_loopback_api("radar-api-name", "localhost");
}
