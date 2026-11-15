//! `praetore-mcp dashboard`: a read-only local web view of the receipts
//! journal, the calls waiting for approval and the active policy, served on
//! 127.0.0.1 only.
//!
//! The page (HTML, CSS and JS) is embedded in the binary; nothing is loaded
//! from the network. Every `/api/state` request reads the home again and
//! runs [`receipts::verify_journal`], the function behind `praetore-mcp
//! verify`, so the verification status shown is exactly what `verify`
//! reports. Nothing is written under the home.

use crate::{
    gate::PATH_CHECK_CONTEXT_KEY,
    journal,
    receipts::{self, Check, LineVerdict, VerifyReport},
    store::{self, Home},
};
use praetore_core::{DecisionOutcome, Evidence, Policy};
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
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const INDEX_HTML: &str = include_str!("dashboard/index.html");
const APP_JS: &str = include_str!("dashboard/app.js");
const APP_CSS: &str = include_str!("dashboard/app.css");

/// No network origin besides this server; no inline script or style.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

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
    let port = listener
        .local_addr()
        .map_err(|e| format!("cannot read the listening address: {e}"))?
        .port();
    for (index, stream) in listener.incoming().enumerate() {
        if let Ok(stream) = stream {
            // A failed connection only affects that client.
            let _ = handle(stream, home, expected_head, port);
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
    port: u16,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
        if buffer.len() > MAX_REQUEST_BYTES {
            break;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let response = if buffer.len() > MAX_REQUEST_BYTES {
        Response::text(431, "request too large")
    } else {
        respond(&String::from_utf8_lossy(&buffer), home, expected_head, port)
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
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
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

/// Answers one raw request. Only GET; the Host header must name this
/// loopback listener (so a page on another site cannot read it through a
/// DNS name that points at 127.0.0.1).
pub fn respond(request: &str, home: &Home, expected_head: Option<&str>, port: u16) -> Response {
    let mut lines = request.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target)) = (request_line.next(), request_line.next()) else {
        return Response::text(400, "bad request");
    };
    let hosts: Vec<&str> = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("host")
                .then(|| value.trim())
        })
        .collect();
    // More than one Host is ambiguous: a proxy and this listener could
    // read different ones. Refused whatever the values and their order.
    if hosts.len() > 1 {
        return Response::text(400, "more than one Host header");
    }
    let allowed_hosts = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    if !hosts
        .first()
        .is_some_and(|host| allowed_hosts.iter().any(|allowed| allowed == host))
    {
        return Response::text(403, "host not allowed");
    }
    if method != "GET" {
        return Response::text(405, "read-only: GET only");
    }
    let path = target.split(['?', '#']).next().unwrap_or("");
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
            body: serde_json::to_vec(&state(home, expected_head)).unwrap_or_default(),
        },
        _ => Response::text(404, "not found"),
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

/// Calls waiting for approval, with the full canonical arguments (the text
/// `approve` prints before it asks for confirmation). Read only: deciding
/// stays with `praetore-mcp approve` / `reject` in a terminal.
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

/// Ids of the allow-all rules, as `policy check` and `policy coverage`
/// find them ([`crate::policy::is_allow_all`]): ALLOW rules that match
/// every `tools/call`, or every one of a server.
pub fn allow_all_rules(policy: &Policy) -> Vec<String> {
    policy
        .rules
        .iter()
        .filter(|rule| crate::policy::is_allow_all(rule))
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
