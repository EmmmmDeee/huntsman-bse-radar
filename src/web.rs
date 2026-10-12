//! The web page of `hse-radar serve`: the page and its assets, the headers every reply carries, and
//! which requests are answered. The sockets and threads are in `main.rs`. What is decided here is
//! pure, so the tests reach it without a socket.
//!
//! Names of access points and BLE devices come from radios anyone nearby can run, so the page never
//! parses them as markup (it sets them with `textContent`), and the policy below stops a page that
//! somehow did from running a script or sending anything out.

/// What a reply may load. The page has no inline script or style and reaches nothing outside its own
/// origin: markup that got into it from a radio could not run, and nothing it ran could send data out.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
    style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>HSE Radar</title>
<link rel="stylesheet" href="/app.css">
</head>
<body>
<header><h1>HUNTSMAN RADAR</h1><div class="meta" id="meta">loading…</div></header>
<main id="root"></main>
<script src="/app.js"></script>
</body></html>
"#;

pub const APP_CSS: &str = r"
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
";

/// Everything that comes from a radio or a sensor is set as text, never parsed as markup.
pub const APP_JS: &str = r"'use strict';
const meta = document.getElementById('meta');
const root = document.getElementById('root');
let loading = false;

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function sightingRow(s) {
  const left = el('div');
  left.append(el('div', '', s.name || s.key));
  left.append(el('div', 'muted', s.radio + (s.signal_dbm == null ? '' : ' · ' + s.signal_dbm + ' dBm')));
  const row = el('div', 'row');
  row.append(left, el('div', 'tag', s.key));
  return row;
}

function skippedRow(s) {
  const row = el('div', 'row');
  row.append(el('div', 'bad', s.reason), el('div', 'muted', s.raw));
  return row;
}

function card(title, rows) {
  const box = el('div', 'card');
  box.append(el('div', 'tag', title), ...rows);
  return box;
}

async function load() {
  if (loading) return;
  loading = true;
  try {
    const r = await fetch('/api/ledger', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    const sightings = j.sightings || [];
    const skipped = j.skipped || [];
    meta.textContent = (j.sweep_id || 'sweeping…') + ' · ' + sightings.length + ' sightings · rev ' + (j.radar_rev || '').slice(0, 8);
    const rows = sightings.map(sightingRow);
    if (rows.length === 0) {
      rows.push(el('div', 'muted', j.sweep_id
        ? 'No sightings this sweep. On Termux install Termux:API and grant location / nearby devices.'
        : 'The first sweep is running.'));
    }
    const cards = [card('Sightings', rows)];
    if (skipped.length > 0) cards.push(card('Skipped', skipped.map(skippedRow)));
    root.replaceChildren(...cards);
  } catch (e) {
    meta.textContent = 'offline · ' + e.message;
  } finally {
    loading = false;
  }
}

load();
setInterval(load, 4000);
";

/// What a request path asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Index,
    Script,
    Style,
    Favicon,
    Ledger,
    HseEntities,
    NotFound,
}

/// The route for a request target; a query string is ignored.
#[must_use]
pub fn route(target: &str) -> Route {
    match target.split('?').next().unwrap_or(target) {
        "/" | "/index.html" => Route::Index,
        "/app.js" => Route::Script,
        "/app.css" => Route::Style,
        "/favicon.ico" => Route::Favicon,
        "/api/ledger" => Route::Ledger,
        "/api/hse-entities" => Route::HseEntities,
        _ => Route::NotFound,
    }
}

/// The parts of the request the server acts on.
#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub host: Option<&'a str>,
}

/// Reads the request line and the `Host` header from the head of a request.
#[must_use]
pub fn parse_request(head: &str) -> Option<Request<'_>> {
    let mut lines = head.split("\r\n");
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let host = lines.take_while(|line| !line.is_empty()).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host").then_some(value.trim())
    });
    Some(Request {
        method,
        target,
        host,
    })
}

/// A host name and the port that goes with it, from `name`, `name:port`, `[v6]` or `[v6]:port`.
fn split_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    let (name, port) = if authority.starts_with('[') {
        let (name, rest) = authority.split_at(authority.find(']')? + 1);
        if rest.is_empty() {
            (name, None)
        } else {
            (name, Some(rest.strip_prefix(':')?))
        }
    } else {
        match authority.split_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => None,
        Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
            Some(digits.parse::<u16>().ok()?)
        }
        Some(_) => return None,
    };
    Some((name, port))
}

fn is_loopback_name(name: &str) -> bool {
    name == "127.0.0.1" || name == "[::1]" || name.eq_ignore_ascii_case("localhost")
}

/// Whether a `Host` header names this machine. A page on another name that resolves to 127.0.0.1
/// (DNS rebinding) sends its own name here, and gets no answer. The port is not compared, so a
/// forwarded port still works.
#[must_use]
pub fn host_allowed(host: Option<&str>) -> bool {
    host.and_then(split_authority)
        .is_some_and(|(name, _)| is_loopback_name(name))
}

/// The host and port to connect to for the authority of a loopback URL, or `None` for anything else.
/// A prefix test would accept `127.0.0.1.example.com` and `127.0.0.1@example.com`.
#[must_use]
pub fn loopback_target(authority: &str) -> Option<(&str, u16)> {
    let (name, port) = split_authority(authority)?;
    let port = port.filter(|port| *port != 0)?;
    is_loopback_name(name).then(|| (name.trim_start_matches('[').trim_end_matches(']'), port))
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// A complete reply. Every reply carries the same security headers, so none can be left out.
#[must_use]
pub fn reply(status: u16, content_type: &str, body: &[u8], head_only: bool) -> Vec<u8> {
    let retry_after = if status == 503 {
        "Retry-After: 1\r\n"
    } else {
        ""
    };
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         {retry_after}Cache-Control: no-store\r\nContent-Security-Policy: {CONTENT_SECURITY_POLICY}\r\n\
         X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len(),
    );
    let mut out = head.into_bytes();
    if !head_only {
        out.extend_from_slice(body);
    }
    out
}

fn text(status: u16, message: &str, head_only: bool) -> Vec<u8> {
    reply(
        status,
        "text/plain; charset=utf-8",
        message.as_bytes(),
        head_only,
    )
}

/// The reply to the head of a request. `dynamic` supplies the body of the two JSON routes.
#[must_use]
pub fn answer(head: &str, dynamic: &dyn Fn(Route) -> Vec<u8>) -> Vec<u8> {
    let Some(request) = parse_request(head) else {
        return text(400, "bad request\n", false);
    };
    let head_only = match request.method {
        "GET" => false,
        "HEAD" => true,
        _ => return text(405, "method not allowed\n", false),
    };
    if !host_allowed(request.host) {
        return text(403, "forbidden host\n", head_only);
    }
    let html = "text/html; charset=utf-8";
    match route(request.target) {
        Route::Index => reply(200, html, INDEX_HTML.as_bytes(), head_only),
        Route::Script => reply(
            200,
            "text/javascript; charset=utf-8",
            APP_JS.as_bytes(),
            head_only,
        ),
        Route::Style => reply(
            200,
            "text/css; charset=utf-8",
            APP_CSS.as_bytes(),
            head_only,
        ),
        Route::Favicon => reply(204, "image/x-icon", b"", head_only),
        found @ (Route::Ledger | Route::HseEntities) => reply(
            200,
            "application/json; charset=utf-8",
            &dynamic(found),
            head_only,
        ),
        Route::NotFound => text(404, "not found\n", head_only),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_dynamic(_: Route) -> Vec<u8> {
        b"{}".to_vec()
    }

    fn status_line(reply: &[u8]) -> String {
        String::from_utf8_lossy(reply)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    #[test]
    fn only_a_host_that_names_this_machine_is_allowed() {
        for host in [
            "127.0.0.1:8088",
            "127.0.0.1",
            "localhost:8088",
            "LocalHost:1",
            "[::1]:8088",
            "[::1]",
        ] {
            assert!(host_allowed(Some(host)), "{host}");
        }
        for host in [
            "rebind.example.com",
            "rebind.example.com:8088",
            "127.0.0.1.example.com",
            "127.0.0.1.example.com:8088",
            "127.0.0.1@example.com",
            "localhost.example.com:80",
            "example.com:127.0.0.1",
            "0.0.0.0:8088",
            "127.0.0.1:",
            "127.0.0.1:99999",
            "127.0.0.1:80:90",
            "[::1",
            "[::1]x",
            "::1",
            "",
        ] {
            assert!(!host_allowed(Some(host)), "{host}");
        }
        assert!(!host_allowed(None), "a request without a Host header");
    }

    #[test]
    fn a_loopback_target_is_the_whole_authority_and_nothing_longer() {
        assert_eq!(loopback_target("127.0.0.1:8080"), Some(("127.0.0.1", 8080)));
        assert_eq!(loopback_target("localhost:8080"), Some(("localhost", 8080)));
        assert_eq!(loopback_target("[::1]:8080"), Some(("::1", 8080)));
        for authority in [
            "127.0.0.1",
            "127.0.0.1:0",
            "127.0.0.1.example.com:80",
            "127.0.0.1@example.com:80",
            "localhost.example.com:80",
            "example.com:80",
            "10.0.0.1:80",
            "127.0.0.1:+80",
            "",
        ] {
            assert_eq!(loopback_target(authority), None, "{authority}");
        }
    }

    #[test]
    fn requests_are_routed_by_path_alone() {
        assert_eq!(route("/"), Route::Index);
        assert_eq!(route("/?x=1"), Route::Index);
        assert_eq!(route("/app.js"), Route::Script);
        assert_eq!(route("/app.css"), Route::Style);
        assert_eq!(route("/favicon.ico"), Route::Favicon);
        assert_eq!(route("/api/ledger?t=1"), Route::Ledger);
        assert_eq!(route("/api/hse-entities"), Route::HseEntities);
        // A prefix used to be enough, and any other path got the page.
        assert_eq!(route("/api/ledger/extra"), Route::NotFound);
        assert_eq!(route("/api/nothing"), Route::NotFound);
    }

    #[test]
    fn the_host_header_is_found_whatever_its_case() {
        let request =
            parse_request("GET /x HTTP/1.1\r\nACCEPT: */*\r\nhOsT:  127.0.0.1:8088 \r\n\r\n")
                .expect("a request");
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/x");
        assert_eq!(request.host, Some("127.0.0.1:8088"));
        assert_eq!(parse_request("").map(|r| r.method), None);
        // A Host-looking line after the blank line belongs to the body.
        let request =
            parse_request("GET / HTTP/1.1\r\n\r\nHost: localhost\r\n").expect("a request");
        assert_eq!(request.host, None);
    }

    #[test]
    fn every_reply_carries_the_security_headers() {
        let dynamic = |_| b"{\"sweep_id\":\"x\"}".to_vec();
        for target in [
            "/",
            "/app.js",
            "/app.css",
            "/favicon.ico",
            "/api/ledger",
            "/nope",
        ] {
            let request = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n");
            let reply = String::from_utf8(answer(&request, &dynamic)).unwrap();
            for header in [
                "Cache-Control: no-store\r\n",
                "X-Content-Type-Options: nosniff\r\n",
                "Referrer-Policy: no-referrer\r\n",
                "Cross-Origin-Resource-Policy: same-origin\r\n",
            ] {
                assert!(reply.contains(header), "{target}: {header}");
            }
            assert!(
                reply.contains(&format!(
                    "Content-Security-Policy: {CONTENT_SECURITY_POLICY}\r\n"
                )),
                "{target}"
            );
        }
        for refused in [
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            "garbage",
        ] {
            let reply = String::from_utf8(answer(refused, &no_dynamic)).unwrap();
            assert!(reply.contains("Content-Security-Policy:"), "{refused}");
        }
    }

    #[test]
    fn requests_are_answered_or_refused_by_method_host_and_path() {
        let get = |request: &str| status_line(&answer(request, &no_dynamic));
        assert_eq!(
            get("GET / HTTP/1.1\r\nHost: localhost:1\r\n\r\n"),
            "HTTP/1.1 200 OK"
        );
        assert_eq!(
            get("GET /favicon.ico HTTP/1.1\r\nHost: localhost:1\r\n\r\n"),
            "HTTP/1.1 204 No Content"
        );
        assert_eq!(
            get("GET /nope HTTP/1.1\r\nHost: localhost:1\r\n\r\n"),
            "HTTP/1.1 404 Not Found"
        );
        assert_eq!(
            get("GET / HTTP/1.1\r\nHost: rebind.example.com\r\n\r\n"),
            "HTTP/1.1 403 Forbidden"
        );
        assert_eq!(get("GET / HTTP/1.1\r\n\r\n"), "HTTP/1.1 403 Forbidden");
        assert_eq!(
            get("POST / HTTP/1.1\r\nHost: localhost:1\r\n\r\n"),
            "HTTP/1.1 405 Method Not Allowed"
        );
        assert_eq!(get("\r\n\r\n"), "HTTP/1.1 400 Bad Request");
    }

    #[test]
    fn head_has_the_length_of_get_and_no_body() {
        let request =
            |method: &str| format!("{method} /app.js HTTP/1.1\r\nHost: localhost:1\r\n\r\n");
        let get = String::from_utf8(answer(&request("GET"), &no_dynamic)).unwrap();
        let head = String::from_utf8(answer(&request("HEAD"), &no_dynamic)).unwrap();
        let length = |reply: &str| {
            reply
                .lines()
                .find(|line| line.starts_with("Content-Length:"))
                .map(str::to_owned)
        };
        assert_eq!(length(&get), length(&head));
        assert!(head.ends_with("\r\n\r\n"));
        assert!(get.ends_with(APP_JS));
    }

    #[test]
    fn the_json_routes_serve_what_the_server_supplies() {
        let dynamic = |route| match route {
            Route::Ledger => b"LEDGER".to_vec(),
            Route::HseEntities => b"BUNDLE".to_vec(),
            other => panic!("not a dynamic route: {other:?}"),
        };
        let request = |target: &str| format!("GET {target} HTTP/1.1\r\nHost: localhost:1\r\n\r\n");
        assert!(answer(&request("/api/ledger"), &dynamic).ends_with(b"\r\n\r\nLEDGER"));
        assert!(answer(&request("/api/hse-entities"), &dynamic).ends_with(b"\r\n\r\nBUNDLE"));
    }

    #[test]
    fn the_page_never_parses_what_a_radio_sent_as_markup() {
        // The names in the ledger come from radios anyone nearby can run. The script builds the page
        // with `textContent`; none of these ways of turning a string into markup may come back.
        for forbidden in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "createContextualFragment",
            "DOMParser",
            "eval(",
            "new Function",
            "setTimeout(\"",
            "setInterval(\"",
        ] {
            assert!(!APP_JS.contains(forbidden), "the script uses {forbidden}");
        }
        assert!(APP_JS.contains("textContent"));
        // The page itself is static: no inline script, no inline style, no event handler.
        assert_eq!(INDEX_HTML.matches("<script").count(), 1);
        assert!(INDEX_HTML.contains("<script src=\"/app.js\"></script>"));
        assert!(!INDEX_HTML.contains("<style"));
        assert!(!INDEX_HTML.contains(" on"));
        assert!(!INDEX_HTML.contains("style=\""));
    }

    #[test]
    fn the_policy_allows_nothing_but_the_pages_own_files() {
        for directive in [
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ] {
            assert!(CONTENT_SECURITY_POLICY.contains(directive), "{directive}");
        }
        for loosened in [
            "unsafe-inline",
            "unsafe-eval",
            "http:",
            "https:",
            "data:",
            "*",
        ] {
            assert!(!CONTENT_SECURITY_POLICY.contains(loosened), "{loosened}");
        }
    }
}
