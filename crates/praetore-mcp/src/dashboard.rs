//! `praetore-mcp dashboard`: a local web view of the receipts journal, the
//! pending approvals and the active policy, served on 127.0.0.1 only.
//!
//! The page (HTML, CSS and JS) is embedded in the binary; nothing is loaded
//! from the network. Every `/api/state` request reads the home again and
//! runs [`receipts::verify_journal`], the function behind `praetore-mcp
//! verify`, so the verification status shown is exactly what `verify`
//! reports.
//!
//! By default the server is read-only: only GET is accepted and nothing is
//! written under the home. With [`Session`] (`dashboard --approvals`) it
//! also accepts `POST /api/approve` and `POST /api/reject`, which call
//! [`crate::approvals::decide`], the same function as `praetore-mcp
//! approve` / `reject`. Those requests need the session token printed on
//! the terminal at startup, an `Origin` of this listener and a JSON body.

use crate::{
    gate::PATH_CHECK_CONTEXT_KEY,
    journal,
    receipts::{self, Check, LineVerdict, VerifyReport},
    store::{self, ACTION_TYPE, Home},
};
use praetore_core::{DecisionOutcome, Evidence, Policy, PolicyEffect};
use rand_core::{OsRng, RngCore};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const DEFAULT_PORT: u16 = 8787;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Largest POST body. A decision body carries the canonical arguments the
/// page showed; the approval record itself is capped at 48 KiB.
const MAX_BODY_BYTES: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const INDEX_HTML: &str = include_str!("dashboard/index.html");
const APP_JS: &str = include_str!("dashboard/app.js");
const APP_CSS: &str = include_str!("dashboard/app.css");

/// No network origin besides this server; no inline script or style.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The approval session of `dashboard --approvals`: a random token minted
/// in this process, never written to disk. The terminal prints it once in
/// the URL fragment (`#s=`), which the browser does not send in requests;
/// the page keeps it in `sessionStorage` (that tab only) and sends it as
/// `Authorization: Bearer`.
#[derive(Clone)]
pub struct Session {
    token: [u8; 32],
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session")
    }
}

impl Session {
    pub fn random() -> Self {
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        Self { token }
    }

    /// Lowercase hex, as it goes in the URL fragment and the header.
    pub fn token_hex(&self) -> String {
        hex::encode(self.token)
    }

    fn accepts(&self, presented: &str) -> bool {
        let Ok(bytes) = hex::decode(presented) else {
            return false;
        };
        if bytes.len() != self.token.len() {
            return false;
        }
        // Constant time over the 32 bytes.
        bytes
            .iter()
            .zip(self.token.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

/// Binds the dashboard listener on 127.0.0.1:`port` (0 picks a free port).
pub fn bind(port: u16) -> Result<TcpListener, String> {
    bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

/// Binds `addr` only if it is 127.0.0.1. Any other address (0.0.0.0, ::,
/// ::1, a LAN address) is refused before a socket is opened.
pub fn bind_addr(addr: SocketAddr) -> Result<TcpListener, String> {
    if addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(format!(
            "the dashboard only listens on 127.0.0.1, refusing {}",
            addr.ip()
        ));
    }
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("cannot read the listening address: {e}"))?;
    if local.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(format!(
            "the dashboard only listens on 127.0.0.1, the socket is on {}",
            local.ip()
        ));
    }
    Ok(listener)
}

/// Serves requests one at a time. Stops after `max_requests` when given
/// (tests); otherwise runs until the process is stopped.
pub fn serve(
    listener: &TcpListener,
    home: &Home,
    expected_head: Option<&str>,
    max_requests: Option<usize>,
) -> Result<(), String> {
    serve_with(listener, home, expected_head, None, max_requests)
}

/// [`serve`], with approvals from the page when `session` is given.
pub fn serve_with(
    listener: &TcpListener,
    home: &Home,
    expected_head: Option<&str>,
    session: Option<&Session>,
    max_requests: Option<usize>,
) -> Result<(), String> {
    let port = listener
        .local_addr()
        .map_err(|e| format!("cannot read the listening address: {e}"))?
        .port();
    for (index, stream) in listener.incoming().enumerate() {
        if let Ok(stream) = stream {
            // A failed connection only affects that client.
            let _ = handle(stream, home, expected_head, session, port);
        }
        if max_requests.is_some_and(|max| index + 1 >= max) {
            break;
        }
    }
    Ok(())
}

fn handle(
    mut stream: TcpStream,
    home: &Home,
    expected_head: Option<&str>,
    session: Option<&Session>,
    port: u16,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break Some(at + 4);
        }
        if buffer.len() > MAX_REQUEST_BYTES {
            break None;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let mut too_large = buffer.len() > MAX_REQUEST_BYTES && header_end.is_none();
    if let Some(end) = header_end {
        // Only a POST with approvals on carries a body worth reading.
        let wanted = content_length(&String::from_utf8_lossy(&buffer[..end]));
        if let Some(length) = wanted {
            if length > MAX_BODY_BYTES {
                too_large = true;
            } else if session.is_some() {
                while buffer.len() < end + length {
                    let read = stream.read(&mut chunk)?;
                    if read == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                }
            }
        }
    }
    let response = if too_large {
        Response::text(431, "request too large")
    } else {
        respond_with(
            &String::from_utf8_lossy(&buffer),
            home,
            expected_head,
            session,
            port,
        )
    };
    stream.write_all(&response.to_bytes())?;
    stream.flush()
}

/// An HTTP response.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            415 => "Unsupported Media Type",
            431 => "Request Header Fields Too Large",
            _ => "Error",
        };
        let mut out = format!(
            "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: {CSP}\r\nConnection: close\r\n\r\n",
            self.status,
            self.content_type,
            self.body.len()
        )
        .into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

fn content_length(head: &str) -> Option<usize> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())?
    })
}

fn header<'a>(head: &'a str, wanted: &str) -> Option<&'a str> {
    head.split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case(wanted)
                .then(|| value.trim())
        })
}

/// Answers one raw request on a read-only server. Only GET; the Host header
/// must name this loopback listener (so a page on another site cannot read
/// it through a DNS name that points at 127.0.0.1).
pub fn respond(request: &str, home: &Home, expected_head: Option<&str>, port: u16) -> Response {
    respond_with(request, home, expected_head, None, port)
}

/// [`respond`], plus `POST /api/approve` and `POST /api/reject` when a
/// session is given.
pub fn respond_with(
    request: &str,
    home: &Home,
    expected_head: Option<&str>,
    session: Option<&Session>,
    port: u16,
) -> Response {
    let (head, body) = request.split_once("\r\n\r\n").unwrap_or((request, ""));
    let mut request_line = head.split("\r\n").next().unwrap_or("").split(' ');
    let (Some(method), Some(target)) = (request_line.next(), request_line.next()) else {
        return Response::text(400, "bad request");
    };
    let allowed_hosts = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    if !header(head, "host").is_some_and(|host| allowed_hosts.iter().any(|allowed| allowed == host))
    {
        return Response::text(403, "host not allowed");
    }
    let path = target.split(['?', '#']).next().unwrap_or("");
    if method == "POST" {
        return match session {
            None => Response::text(405, "read-only: GET only"),
            Some(session) => post(path, head, body, home, session, port),
        };
    }
    if method != "GET" {
        return Response::text(405, "GET only");
    }
    match path {
        "/" | "/index.html" => Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: INDEX_HTML.as_bytes().to_vec(),
        },
        "/app.js" => Response {
            status: 200,
            content_type: "text/javascript; charset=utf-8",
            body: APP_JS.as_bytes().to_vec(),
        },
        "/app.css" => Response {
            status: 200,
            content_type: "text/css; charset=utf-8",
            body: APP_CSS.as_bytes().to_vec(),
        },
        "/api/state" => Response {
            status: 200,
            content_type: "application/json; charset=utf-8",
            body: {
                let mut value = state(home, expected_head);
                value["approvals_from_page"] = Value::Bool(session.is_some());
                serde_json::to_vec(&value).unwrap_or_default()
            },
        },
        _ => Response::text(404, "not found"),
    }
}

fn json_response(status: u16, value: &Value) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8",
        body: serde_json::to_vec(value).unwrap_or_default(),
    }
}

/// A decision from the page. The checks run before anything is read from
/// the body: Origin of this listener (a page on another site cannot send
/// it), a JSON content type (a cross-site form cannot send it without a
/// preflight this server never answers), then the session token.
fn post(path: &str, head: &str, body: &str, home: &Home, session: &Session, port: u16) -> Response {
    let outcome = match path {
        "/api/approve" => crate::approvals::HumanOutcome::Approve,
        "/api/reject" => crate::approvals::HumanOutcome::Reject,
        _ => return Response::text(404, "not found"),
    };
    let allowed_origins = [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
    ];
    if !header(head, "origin").is_some_and(|o| allowed_origins.iter().any(|a| a == o)) {
        return Response::text(403, "origin not allowed");
    }
    let json_type = header(head, "content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
    });
    if !json_type {
        return Response::text(415, "application/json only");
    }
    let token = header(head, "authorization").and_then(|value| value.strip_prefix("Bearer "));
    if !token.is_some_and(|token| session.accepts(token.trim())) {
        return Response::text(401, "missing or wrong session token");
    }
    if content_length(head) != Some(body.len()) {
        return Response::text(400, "body length does not match Content-Length");
    }
    let request: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return Response::text(400, "body is not JSON"),
    };
    let field = |key: &str| request.get(key).and_then(Value::as_str).map(str::to_owned);
    let (Some(id), Some(server), Some(tool), Some(evidence_id), Some(arguments)) = (
        field("approval_id"),
        field("server"),
        field("tool"),
        field("evidence_id"),
        field("arguments_canonical"),
    ) else {
        return Response::text(
            400,
            "body needs approval_id, server, tool, evidence_id and arguments_canonical",
        );
    };
    // What the page showed. `decide` refuses to sign if the pending call
    // no longer matches it, as with `approve` at a terminal.
    let shown = crate::approvals::PendingCall {
        server,
        tool,
        expires_at: String::new(),
        evidence_id,
        arguments_canonical: arguments,
    };
    match crate::approvals::decide(home, &id, outcome, Some(&shown)) {
        Ok(decided) => json_response(
            200,
            &json!({
                "ok": true,
                "approval_id": decided.approval_id,
                "outcome": decided.outcome,
                "server": decided.server,
                "tool": decided.tool,
                "expires_at": decided.expires_at,
                "approver_key_id": decided.approver_key_id,
            }),
        ),
        Err(error) => json_response(409, &json!({"ok": false, "error": error})),
    }
}

/// Pending approvals with the full canonical arguments, the same text
/// `approve` prints before it asks for confirmation.
fn pending_view(home: &Home) -> Value {
    match crate::approvals::list_pending(home) {
        Ok(list) => Value::Array(
            list.into_iter()
                .map(|item| {
                    let full = crate::approvals::pending_call(home, &item.approval_id);
                    json!({
                        "approval_id": item.approval_id,
                        "server": item.server,
                        "tool": item.tool,
                        "expires_at": item.expires_at,
                        "evidence_id": item.evidence_id,
                        "arguments_canonical": full.as_ref().ok().map(|c| c.arguments_canonical.clone()),
                        "error": full.err(),
                    })
                })
                .collect(),
        ),
        Err(error) => json!({"error": error}),
    }
}

/// Everything the page shows, read from the home now.
pub fn state(home: &Home, expected_head: Option<&str>) -> Value {
    let generated_at_utc = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let approval_status = crate::approvals::status_by_evidence(home).unwrap_or_default();
    let (verify, lines) = match receipts::verify_journal(home, expected_head) {
        Ok(mut report) => {
            let lines = std::mem::take(&mut report.lines);
            (verify_view(&report, home, expected_head), lines)
        }
        Err(error) => {
            // Pins or journal unreadable: show the receipts, not verified.
            let lines = receipts::read_journal(home)
                .map(|lines| {
                    lines
                        .into_iter()
                        .map(|line| LineVerdict {
                            parse_error: journal::parse_line(&line.text).err(),
                            file: line.file,
                            line_number: line.line_number,
                            text: line.text,
                            checks: None,
                            order: None,
                            verified: false,
                        })
                        .collect()
                })
                .unwrap_or_default();
            (json!({"status": "error", "error": error}), lines)
        }
    };
    let receipts: Vec<Value> = lines
        .iter()
        .map(|line| receipt_view(line, &approval_status))
        .collect();
    let count = |label: &str| receipts.iter().filter(|r| r["decision"] == label).count();
    let enforce_receipts = receipts.iter().filter(|r| r["mode"] == "enforce").count();
    json!({
        "generated_at_utc": generated_at_utc,
        "home": home.root.display().to_string(),
        "summary": {
            "total": receipts.len(),
            "allow": count("ALLOW"),
            "deny": count("DENY"),
            "require_approval": count("REQUIRE_APPROVAL"),
            "unreadable": receipts.iter().filter(|r| r["parse_error"].is_string()).count(),
            "enforce_receipts": enforce_receipts,
        },
        "policy": policy_view(home, enforce_receipts),
        "pending": pending_view(home),
        "verify": verify,
        "receipts": receipts,
    })
}

fn verify_view(report: &VerifyReport, home: &Home, expected_head: Option<&str>) -> Value {
    json!({
        "status": if report.failures.is_empty() { "ok" } else { "fail" },
        "total": report.total,
        "verified": report.ok,
        "failed": report.failures.len(),
        "failures": report.failures,
        "chained": report.chained,
        "unchained": report.unchained,
        "head": report.head.map(|head| json!({"next_seq": head.seq, "prev": head.prev.to_string()})),
        "expected_head": expected_head,
        "attester_pin": home.attester_pin().display().to_string(),
        "issuer_pins": home.issuer_pins().display().to_string(),
        "approval": {
            "decisions": report.approval_decisions,
            "executions": report.approval_executions,
            "head": report.approval_head,
        },
    })
}

fn check_view(check: Option<&Check>) -> Value {
    match check {
        None => json!({"status": "not_run", "error": null}),
        Some(check) => json!({"status": check.label(), "error": check.detail()}),
    }
}

/// The view of one journal line: the table columns, the three signatures
/// with their key ids and the result of each check `verify` ran.
pub fn receipt_view(line: &LineVerdict, approval_status: &BTreeMap<String, String>) -> Value {
    let raw: Value = serde_json::from_str(&line.text).unwrap_or(Value::Null);
    let location = json!({"file": line.file.display().to_string(), "line": line.line_number});
    let entry = match journal::parse_line(&line.text) {
        Ok(entry) => entry,
        Err(error) => {
            return json!({
                "location": location,
                "parse_error": line.parse_error.clone().unwrap_or(error),
                "verified": false,
                "raw_text": line.text,
                "raw": raw,
            });
        }
    };
    let evidence = &entry.evidence;
    let checks = line.checks.as_ref();
    let outcome = evidence.decision.outcome;
    let rules: Vec<&str> = evidence
        .decision
        .contributions
        .iter()
        .filter(|c| c.outcome == outcome)
        .map(|c| c.rule_id.as_str())
        .collect();
    let parameters = &evidence.action.parameters;
    let arguments = if parameters.get("arguments_omitted") == Some(&Value::Bool(true)) {
        json!({
            "omitted": true,
            "sha256": parameters.get("arguments_sha256"),
            "bytes": parameters.get("arguments_bytes"),
        })
    } else {
        parameters.get("arguments").cloned().unwrap_or(Value::Null)
    };
    let evidence_id = evidence.evidence_id.to_string();
    let mode = receipts::mode_of(evidence);
    let approval = approval_status.get(&evidence_id).cloned().or_else(|| {
        (outcome == DecisionOutcome::RequireApproval).then(|| {
            if mode == Some("observe") {
                "enforce would ask".to_owned()
            } else {
                "held".to_owned()
            }
        })
    });
    let mut other_checks = Map::new();
    if let Some(checks) = checks {
        for (name, check) in [
            ("shape", &checks.shape),
            ("authority_subject", &checks.authority_subject),
            ("audience", &checks.audience),
            ("mode", &checks.mode),
        ] {
            other_checks.insert(name.into(), check_view(Some(check)));
        }
    }
    json!({
        "location": location,
        "parse_error": null,
        "verified": line.verified,
        "seq": entry.position.map(|p| p.seq),
        "prev": entry.position.map(|p| p.prev.to_string()),
        "order": line.order,
        "decided_at": evidence.decided_at,
        "server": evidence.action.target,
        "tool": tool_of(evidence),
        "arguments": arguments,
        "decision": receipts::decision_label(outcome),
        "rule": if rules.is_empty() { Value::Null } else { Value::String(rules.join(",")) },
        "mode": mode,
        "evidence_id": evidence_id,
        "approval": approval,
        "policy_digest": evidence.policy_digest,
        "path_check": evidence.context.get(PATH_CHECK_CONTEXT_KEY),
        "signatures": {
            "agent": {
                "agent_id": evidence.agent.id.as_uuid().to_string(),
                "subject_key_hash": evidence.authority.subject_key_hash,
                "check": check_view(checks.map(|c| &c.agent_intent)),
            },
            "attester": {
                "key_id": evidence.attester_key_id,
                "check": check_view(checks.map(|c| &c.attester_signature)),
            },
            "authority": {
                "issuer": evidence.authority.issuer,
                "key_id": evidence.authority.issuer_key_id,
                "authority_id": serde_json::to_value(&evidence.authority.id).unwrap_or(Value::Null),
                "check": check_view(checks.map(|c| &c.authority_signature)),
            },
        },
        "checks": other_checks,
        "raw_text": line.text,
        "raw": raw,
    })
}

fn tool_of(evidence: &Evidence) -> Value {
    match evidence.action.parameters.get("tool") {
        Some(Value::String(tool)) => Value::String(tool.clone()),
        Some(other) => Value::String(other.to_string()),
        None => Value::Null,
    }
}

/// Ids of the ALLOW rules that match every `tools/call`: no server, no
/// condition on the parameters or the context.
pub fn allow_all_rules(policy: &Policy) -> Vec<String> {
    policy
        .rules
        .iter()
        .filter(|rule| {
            matches!(rule.effect, PolicyEffect::Allow)
                && rule.action_type == ACTION_TYPE
                && rule.target.is_none()
                && rule.parameter_conditions.is_empty()
                && rule.context_conditions.is_empty()
        })
        .map(|rule| rule.id.clone())
        .collect()
}

fn policy_view(home: &Home, enforce_receipts: usize) -> Value {
    match store::load_policy(home) {
        Ok(policy) => {
            let allow_all = allow_all_rules(&policy);
            json!({
                "status": "ok",
                "path": home.policy().display().to_string(),
                "id": policy.id,
                "version": policy.version,
                "digest": policy.digest().ok(),
                "rules": policy.rules.len(),
                "warn_allow_all_enforce": !allow_all.is_empty() && enforce_receipts > 0,
                "allow_all_rules": allow_all,
                "rules_detail": serde_json::to_value(&policy.rules).unwrap_or(Value::Null),
            })
        }
        Err(error) => json!({
            "status": "error",
            "path": home.policy().display().to_string(),
            "error": error,
        }),
    }
}
