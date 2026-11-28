//! `praetore-mcp dashboard`: a read-only local web view of the receipts
//! journal, the calls waiting for approval and the active policy, served on
//! 127.0.0.1 only.
//!
//! The page (HTML, CSS and JS) is embedded in the binary; nothing is loaded
//! from the network. The verification status comes from
//! [`receipts::verify_journal`], the function behind `praetore-mcp verify`,
//! so it is exactly what `verify` reports. Its result is kept in memory
//! between requests while none of the files it reads has changed (see
//! [`Cache`]); `/api/state` then sends one page of receipts, not the whole
//! journal. Nothing is written under the home.
//!
//! The Sessions view lists the session reports in `DIR/reports/` (the
//! pair written at close, with the pairs `report` wrote later grouped
//! under it) and `/reports/<file>` serves one of them for download. The
//! dashboard reads them only: it does not write, regenerate or sign one.

use crate::{
    gate::{DenyEffect, PATH_CHECK_CONTEXT_KEY},
    journal,
    receipts::{self, Assurance, Check, ExpectedHeads, LineVerdict, VerifyReport},
    report,
    store::{self, Home},
};
use praetore_core::{DecisionOutcome, Evidence, Policy};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
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
    expected: ExpectedHeads<'_>,
    max_requests: Option<usize>,
) -> Result<(), String> {
    let port = listener
        .local_addr()
        .map_err(|e| format!("cannot read the listening address: {e}"))?
        .port();
    let mut cache = Cache::default();
    for (index, stream) in listener.incoming().enumerate() {
        if let Ok(stream) = stream {
            // A failed connection only affects that client.
            let _ = handle(stream, home, expected, port, &mut cache);
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
    expected: ExpectedHeads<'_>,
    port: u16,
    cache: &mut Cache,
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
        respond_with(
            &String::from_utf8_lossy(&buffer),
            home,
            expected,
            port,
            cache,
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
    /// `Content-Disposition`, for a report served as a download.
    pub disposition: Option<String>,
}

impl Response {
    fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes().to_vec(),
            disposition: None,
        }
    }

    fn json(value: &Value) -> Self {
        Self {
            status: 200,
            content_type: "application/json; charset=utf-8",
            body: serde_json::to_vec(value).unwrap_or_default(),
            disposition: None,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Content Too Large",
            431 => "Request Header Fields Too Large",
            _ => "Error",
        };
        // A 204 has no content: it carries no Content-Length and no
        // Content-Type (RFC 9110 section 8.6).
        let mut content = if self.status == 204 {
            String::new()
        } else {
            format!(
                "Content-Type: {}\r\nContent-Length: {}\r\n",
                self.content_type,
                self.body.len()
            )
        };
        if let Some(disposition) = &self.disposition {
            content.push_str(&format!("Content-Disposition: {disposition}\r\n"));
        }
        let mut out = format!(
            "HTTP/1.1 {} {reason}\r\n{content}Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: {CSP}\r\nConnection: close\r\n\r\n",
            self.status,
        )
        .into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

/// Answers one raw request with a fresh [`Cache`].
pub fn respond(request: &str, home: &Home, expected_head: Option<&str>, port: u16) -> Response {
    respond_with(
        request,
        home,
        ExpectedHeads {
            receipts: expected_head,
            approvals: None,
        },
        port,
        &mut Cache::default(),
    )
}

/// Answers one raw request. Only GET; the Host header must name this
/// loopback listener (so a page on another site cannot read it through a
/// DNS name that points at 127.0.0.1).
pub fn respond_with(
    request: &str,
    home: &Home,
    expected: ExpectedHeads<'_>,
    port: u16,
    cache: &mut Cache,
) -> Response {
    let mut lines = request.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target)) = (request_line.next(), request_line.next()) else {
        return Response::text(400, "bad request");
    };
    let headers: Vec<(&str, &str)> = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim(), value.trim()))
        })
        .collect();
    let named = |wanted: &str| -> Vec<&str> {
        headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| *value)
            .collect()
    };
    let hosts = named("host");
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
    // A browser names the page that made a request in Origin (on every
    // request but a same-origin GET). Any other page is refused.
    let origins = named("origin");
    let allowed_origins = allowed_hosts.map(|host| format!("http://{host}"));
    if origins.len() > 1
        || origins
            .first()
            .is_some_and(|origin| !allowed_origins.iter().any(|allowed| allowed == origin))
    {
        return Response::text(403, "origin not allowed");
    }
    if method != "GET" {
        return Response::text(405, "read-only: GET only");
    }
    let target = target.split('#').next().unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match path {
        "/" | "/index.html" => Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: INDEX_HTML.as_bytes().to_vec(),
            disposition: None,
        },
        "/app.js" => Response {
            status: 200,
            content_type: "text/javascript; charset=utf-8",
            body: APP_JS.as_bytes().to_vec(),
            disposition: None,
        },
        "/app.css" => Response {
            status: 200,
            content_type: "text/css; charset=utf-8",
            body: APP_CSS.as_bytes().to_vec(),
            disposition: None,
        },
        "/api/state" => match Query::parse(query) {
            Ok(query) => {
                let reports = cache.reports(home);
                let snapshot = cache.get(home, expected);
                let mut state = page_state(home, snapshot, &query);
                state["reports"] = reports;
                Response::json(&state)
            }
            Err(error) => Response::text(400, &error),
        },
        "/api/receipt" => {
            let id = query_pairs(query).ok().and_then(|pairs| {
                pairs
                    .into_iter()
                    .find_map(|(key, value)| (key == "id").then_some(value))
            });
            let snapshot = cache.get(home, expected);
            match id.and_then(|id| snapshot.by_evidence.get(&id).copied()) {
                Some(index) => {
                    let approval_status =
                        crate::approvals::status_by_evidence(home).unwrap_or_default();
                    Response::json(&receipt_view(&snapshot.lines[index], &approval_status))
                }
                None => Response::text(404, "no such receipt"),
            }
        }
        // Browsers ask for /favicon.ico on their own. The page has no icon;
        // an empty answer keeps that request out of the console as a 404.
        "/favicon.ico" => Response::text(204, ""),
        _ => match path.strip_prefix("/reports/") {
            Some(name) => serve_report(home, name),
            None => Response::text(404, "not found"),
        },
    }
}

/// Receipts per page of `/api/state` when the request names no `limit`.
pub const DEFAULT_PAGE: usize = 100;
/// Largest `limit` accepted.
pub const MAX_PAGE: usize = 500;
/// Receipts the live view draws one by one.
const RECENT: usize = 40;
const APPROVAL_HISTORY: usize = 30;
/// Activity buckets are 15 minutes wide: every UTC offset in use is a
/// multiple of 15 minutes, so the page can regroup them by local hour or
/// day without splitting a bucket.
const BUCKET_SECONDS: i64 = 15 * 60;
const ACTIVITY_DAYS: i64 = 14;

/// The result of [`receipts::verify_journal`], kept between requests.
///
/// It is reused only while every file `verify` reads (the journal files,
/// the attester and issuer pins, the approver pin and the approval
/// journal) has the same length, modification time, change time and inode
/// as when it was verified. Any write changes the change time, which a
/// process cannot set back, so a rewrite of the same size with the old
/// modification time is verified again. Without change times (not Unix)
/// nothing is reused.
#[derive(Default)]
pub struct Cache {
    snapshot: Option<Snapshot>,
    verifications: usize,
    /// SHA-256 and header of each report file, by path, kept while the
    /// file has the same stamp.
    report_files: HashMap<PathBuf, (Vec<FileStamp>, Option<ReportFile>)>,
}

impl Cache {
    /// The current snapshot, verified again if a file changed.
    pub fn get(&mut self, home: &Home, expected: ExpectedHeads<'_>) -> &Snapshot {
        // Stamped before reading: a write during verification changes the
        // stamp, and the next request verifies again.
        let stamps = stamps(home);
        let fresh = matches!(
            (&self.snapshot, &stamps),
            (Some(snapshot), Some(stamps)) if snapshot.stamps.as_ref() == Some(stamps)
        );
        if !fresh {
            self.verifications += 1;
            self.snapshot = Some(Snapshot::read(home, expected, stamps));
        }
        self.snapshot.as_ref().expect("set above")
    }

    /// How many times the journal was verified (tests).
    pub fn verifications(&self) -> usize {
        self.verifications
    }

    /// The session reports in `DIR/reports/` ([`reports_view`]), reading
    /// again only the files that changed.
    pub fn reports(&mut self, home: &Home) -> Value {
        let mut seen = HashMap::new();
        let view = reports_view(home, |path, name| {
            // Whether a PDF is listed depends on its JSON too.
            let mut stamps = vec![stamp(path)];
            if let Some(json) = json_of_pdf(name) {
                stamps.push(stamp(&path.with_file_name(json)));
            }
            let file = match self.report_files.remove(path) {
                Some((old, file))
                    if old == stamps && stamps.iter().all(|stamp| stamp.meta.is_some()) =>
                {
                    file
                }
                _ => ReportFile::read(home, name),
            };
            seen.insert(path.to_path_buf(), (stamps, file.clone()));
            file
        });
        self.report_files = seen;
        view
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FileStamp {
    path: PathBuf,
    meta: Option<(u64, Option<SystemTime>, [i64; 4])>,
}

#[cfg(not(unix))]
fn stamp(path: &Path) -> FileStamp {
    // No change time: nothing is reused.
    FileStamp {
        path: path.to_path_buf(),
        meta: None,
    }
}

#[cfg(unix)]
fn stamp(path: &Path) -> FileStamp {
    use std::os::unix::fs::MetadataExt;
    FileStamp {
        path: path.to_path_buf(),
        meta: fs::metadata(path).ok().map(|m| {
            (
                m.len(),
                m.modified().ok(),
                [m.ctime(), m.ctime_nsec(), m.ino() as i64, m.dev() as i64],
            )
        }),
    }
}

/// The files `verify` reads, stamped; `None` when they cannot be listed or
/// the platform has no change time.
fn stamps(home: &Home) -> Option<Vec<FileStamp>> {
    #[cfg(unix)]
    {
        let mut paths = journal::journal_files(&home.receipts_dir()).ok()?;
        paths.extend([
            home.attester_pin(),
            home.issuer_pins(),
            home.approver_pin(),
            home.root.join("approvals").join("journal.jsonl"),
        ]);
        Some(paths.iter().map(|path| stamp(path)).collect())
    }
    #[cfg(not(unix))]
    {
        let _ = home;
        None
    }
}

/// One journal line, indexed for the filters.
struct Row {
    decision: Option<&'static str>,
    /// For a DENY: whether the call was blocked or forwarded.
    deny_effect: Option<DenyEffect>,
    tool: Option<String>,
    decided_at: Option<OffsetDateTime>,
    enforce: bool,
}

/// What `verify` found, with the lines in journal order.
pub struct Snapshot {
    stamps: Option<Vec<FileStamp>>,
    verify: Value,
    lines: Vec<LineVerdict>,
    rows: Vec<Row>,
    by_evidence: HashMap<String, usize>,
}

impl Snapshot {
    fn read(home: &Home, expected: ExpectedHeads<'_>, stamps: Option<Vec<FileStamp>>) -> Self {
        let (verify, lines) = match receipts::verify_journal_with(home, expected) {
            Ok(mut report) => {
                let lines = std::mem::take(&mut report.lines);
                (verify_view(&report, home, expected), lines)
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
        let mut by_evidence = HashMap::new();
        let rows = lines
            .iter()
            .enumerate()
            .map(|(index, line)| match journal::parse_line(&line.text) {
                Ok(entry) => {
                    let evidence = &entry.evidence;
                    by_evidence.insert(evidence.evidence_id.to_string(), index);
                    Row {
                        decision: Some(receipts::decision_label(evidence.decision.outcome)),
                        deny_effect: receipts::deny_effect(evidence),
                        tool: tool_of(evidence).as_str().map(str::to_owned),
                        decided_at: evidence
                            .decided_at
                            .as_deref()
                            .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok()),
                        enforce: receipts::mode_of(evidence) == Some("enforce"),
                    }
                }
                Err(_) => Row {
                    decision: None,
                    deny_effect: None,
                    tool: None,
                    decided_at: None,
                    enforce: false,
                },
            })
            .collect();
        Self {
            stamps,
            verify,
            lines,
            rows,
            by_evidence,
        }
    }

    fn summary(&self, pending: usize) -> Value {
        let count = |label: &str| {
            self.rows
                .iter()
                .filter(|r| r.decision == Some(label))
                .count()
        };
        let denied = |effect: DenyEffect| {
            self.rows
                .iter()
                .filter(|r| r.deny_effect == Some(effect))
                .count()
        };
        json!({
            "total": self.rows.len(),
            "allow": count("ALLOW"),
            // Decisions. A DENY is a blocked call only in `blocked`.
            "deny": count("DENY"),
            "blocked": denied(DenyEffect::Blocked),
            "deny_not_applied": denied(DenyEffect::NotApplied),
            "require_approval": count("REQUIRE_APPROVAL"),
            "unreadable": self.rows.iter().filter(|r| r.decision.is_none()).count(),
            "enforce_receipts": self.enforce_receipts(),
            // Read from approvals/pending: not signed, not checked by verify.
            "pending_unsigned": pending,
        })
    }

    fn enforce_receipts(&self) -> usize {
        self.rows.iter().filter(|r| r.enforce).count()
    }

    /// Calls per tool, most used first.
    fn tools(&self) -> Value {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for tool in self.rows.iter().filter_map(|r| r.tool.as_deref()) {
            *counts.entry(tool).or_default() += 1;
        }
        let mut counts: Vec<(&str, usize)> = counts.into_iter().collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        Value::Array(
            counts
                .into_iter()
                .map(|(tool, count)| json!({"tool": tool, "count": count}))
                .collect(),
        )
    }

    /// Decisions per 15-minute UTC bucket over the last 14 days.
    fn activity(&self, now: OffsetDateTime) -> Value {
        let since = now.unix_timestamp() - ACTIVITY_DAYS * 86_400;
        let mut buckets: BTreeMap<i64, [usize; 3]> = BTreeMap::new();
        for row in &self.rows {
            let (Some(at), Some(decision)) = (row.decided_at, row.decision) else {
                continue;
            };
            let at = at.unix_timestamp();
            if at < since {
                continue;
            }
            let slot = match decision {
                "ALLOW" => 0,
                "DENY" => 1,
                _ => 2,
            };
            buckets
                .entry(at - at.rem_euclid(BUCKET_SECONDS))
                .or_default()[slot] += 1;
        }
        json!({
            "bucket_seconds": BUCKET_SECONDS,
            "buckets": buckets
                .into_iter()
                .map(|(start, [allow, deny, ask])| json!({
                    "start": start, "ALLOW": allow, "DENY": deny, "REQUIRE_APPROVAL": ask,
                }))
                .collect::<Vec<_>>(),
        })
    }

    /// Journal indexes of the lines that match `query`, newest first.
    fn matching(&self, query: &Query) -> Vec<usize> {
        let needle = query.q.as_ref().map(|q| q.to_lowercase());
        (0..self.rows.len())
            .rev()
            .filter(|&index| {
                let row = &self.rows[index];
                if query.decision.is_some() && row.decision != query.decision.as_deref() {
                    return false;
                }
                if query.tool.is_some() && row.tool != query.tool {
                    return false;
                }
                if query.from.is_some() || query.to.is_some() {
                    let Some(at) = row.decided_at else {
                        return false;
                    };
                    if query.from.is_some_and(|from| at < from)
                        || query.to.is_some_and(|to| at > to)
                    {
                        return false;
                    }
                }
                match &needle {
                    Some(needle) => self.lines[index].text.to_lowercase().contains(needle),
                    None => true,
                }
            })
            .collect()
    }
}

/// The filters and the page of an `/api/state` request.
#[derive(Debug, Default)]
pub struct Query {
    pub decision: Option<String>,
    pub tool: Option<String>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
    pub q: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

impl Query {
    /// Parses `decision`, `tool`, `from`, `to` (RFC 3339), `q`, `offset`
    /// and `limit`. Unknown keys and bad values are refused.
    pub fn parse(query: &str) -> Result<Self, String> {
        let mut out = Self {
            limit: DEFAULT_PAGE,
            ..Self::default()
        };
        let time = |key: &str, value: &str| {
            OffsetDateTime::parse(value, &Rfc3339)
                .map_err(|_| format!("bad {key}: not an RFC 3339 time"))
        };
        for (key, value) in query_pairs(query)? {
            if value.is_empty() {
                continue;
            }
            match key.as_str() {
                "decision" => {
                    if !["ALLOW", "DENY", "REQUIRE_APPROVAL"].contains(&value.as_str()) {
                        return Err("bad decision".into());
                    }
                    out.decision = Some(value);
                }
                "tool" => out.tool = Some(value),
                "from" => out.from = Some(time("from", &value)?),
                "to" => out.to = Some(time("to", &value)?),
                "q" => out.q = Some(value),
                "offset" => out.offset = value.parse().map_err(|_| "bad offset")?,
                "limit" => {
                    out.limit = value
                        .parse()
                        .ok()
                        .filter(|limit| (1..=MAX_PAGE).contains(limit))
                        .ok_or("bad limit")?;
                }
                _ => return Err("unknown query parameter".into()),
            }
        }
        Ok(out)
    }
}

/// `application/x-www-form-urlencoded` pairs of a query string.
fn query_pairs(query: &str) -> Result<Vec<(String, String)>, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((percent_decode(key)?, percent_decode(value)?))
        })
        .collect()
}

fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes
                    .get(index + 1..index + 3)
                    .and_then(|hex| std::str::from_utf8(hex).ok())
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                    .ok_or("bad percent escape")?;
                out.push(hex);
                index += 2;
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8(out).map_err(|_| "query is not UTF-8".into())
}

/// What `/api/state` sends: the counts, the verification status, the
/// policy and the pending calls, plus one page of receipts that match the
/// query, newest first.
pub fn page_state(home: &Home, snapshot: &Snapshot, query: &Query) -> Value {
    let now = OffsetDateTime::now_utc();
    let approval_status = crate::approvals::status_by_evidence_at(home, now).unwrap_or_default();
    // A held call carries, once a person decided it, the time of that
    // decision from the approval journal (not the time of the receipt).
    let decided_at = crate::approvals::decided_at_by_evidence(home);
    let view = |index: usize| {
        let mut row = receipt_view(&snapshot.lines[index], &approval_status);
        if row["decision"] == "REQUIRE_APPROVAL" {
            let at = row["evidence_id"]
                .as_str()
                .and_then(|id| decided_at.get(id))
                .cloned();
            row["approval_decided_at"] = json!(at);
        }
        row
    };
    let newest_first = || (0..snapshot.rows.len()).rev();
    let recent: Vec<Value> = newest_first()
        .filter(|&i| snapshot.rows[i].decision.is_some())
        .take(RECENT)
        .map(view)
        .collect();
    let approval_history: Vec<Value> = newest_first()
        .filter(|&i| snapshot.rows[i].decision == Some("REQUIRE_APPROVAL"))
        .take(APPROVAL_HISTORY)
        .map(view)
        .collect();
    let matching = snapshot.matching(query);
    let receipts: Vec<Value> = matching
        .iter()
        .skip(query.offset)
        .take(query.limit)
        .map(|&index| view(index))
        .collect();
    let pending = pending_view(home, snapshot, &approval_status);
    let pending_count = pending.as_array().map_or(0, Vec::len);
    let format = |at: &Option<OffsetDateTime>| at.and_then(|at| at.format(&Rfc3339).ok());
    json!({
        "generated_at_utc": now.format(&Rfc3339).unwrap_or_default(),
        "home": home.root.display().to_string(),
        "summary": snapshot.summary(pending_count),
        "policy": policy_view(home, snapshot.enforce_receipts()),
        "pending": pending,
        "verify": snapshot.verify,
        "tools": snapshot.tools(),
        "activity": snapshot.activity(now),
        "recent": recent,
        "approval_history": approval_history,
        "page": {
            "offset": query.offset,
            "limit": query.limit,
            "matching": matching.len(),
            "filters": {
                "decision": query.decision,
                "tool": query.tool,
                "from": format(&query.from),
                "to": format(&query.to),
                "q": query.q,
            },
            "receipts": receipts,
        },
    })
}

/// Largest report file the dashboard reads or serves.
pub const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;

/// A report file opened for reading, with the metadata of the open file.
struct OpenReport {
    file: fs::File,
    len: u64,
}

/// Why a report file is not opened.
enum Refused {
    /// Not there, not a report name, not a plain file of this user in
    /// `DIR/reports/`: 404.
    NotFound,
    /// Over [`MAX_REPORT_BYTES`]: 413.
    TooLarge,
}

/// Whether an open file may be read as a report: a regular file with a
/// single link (a hard link to another file of the home, a key for
/// example, has two), owned by `euid`, the user this process runs as.
pub fn servable(nlink: u64, uid: u32, euid: u32, is_file: bool) -> bool {
    is_file && nlink == 1 && uid == euid
}

/// Opens the report file `name` in `DIR/reports/` if it may be read:
///
/// * `name` is exactly a report file name ([`report::parse_report_name`]);
/// * it is opened without following a symlink at its name (`O_NOFOLLOW`,
///   Linux and macOS), so a symlink is refused whatever it points at;
/// * the open file is a regular file with one link (a hard link to another
///   file of the home, a key for example, has two) owned by the user this
///   process runs as;
/// * its real path, with every symlink on the way resolved, is in the real
///   `DIR/reports/`, and is the file that was opened (same device and
///   inode);
/// * it is at most [`MAX_REPORT_BYTES`].
fn open_report(home: &Home, name: &str) -> Result<OpenReport, Refused> {
    report::parse_report_name(name).ok_or(Refused::NotFound)?;
    let dir = home
        .root
        .canonicalize()
        .map_err(|_| Refused::NotFound)?
        .join("reports");
    let path = dir.join(name);
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path).map_err(|_| Refused::NotFound)?;
    let meta = file.metadata().map_err(|_| Refused::NotFound)?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let may = {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        servable(meta.nlink(), meta.uid(), euid, meta.is_file())
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let may = meta.is_file();
    if !may {
        return Err(Refused::NotFound);
    }
    // `reports` (or a directory above it) may be a symlink to somewhere
    // else; the file is read only if it really is in DIR/reports.
    let real = path.canonicalize().map_err(|_| Refused::NotFound)?;
    if real.parent() != Some(dir.as_path()) {
        return Err(Refused::NotFound);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let there = fs::metadata(&real).map_err(|_| Refused::NotFound)?;
        if (there.dev(), there.ino()) != (meta.dev(), meta.ino()) {
            return Err(Refused::NotFound);
        }
    }
    if meta.len() > MAX_REPORT_BYTES {
        return Err(Refused::TooLarge);
    }
    Ok(OpenReport {
        file,
        len: meta.len(),
    })
}

impl OpenReport {
    /// The whole file, at most [`MAX_REPORT_BYTES`].
    fn read_all(mut self) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.len as usize);
        (&mut self.file)
            .take(MAX_REPORT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_REPORT_BYTES {
            return Err(std::io::Error::other("report too large"));
        }
        Ok(bytes)
    }
}

/// A report file [`load_report`] accepted.
struct Report {
    pdf: bool,
    body: Vec<u8>,
    /// The header of a JSON report; `None` for a PDF.
    header: Option<Value>,
}

/// The name of the JSON file next to the PDF `name`; `None` for a JSON.
fn json_of_pdf(name: &str) -> Option<String> {
    name.strip_suffix(".pdf").map(|stem| format!("{stem}.json"))
}

/// The report file `name`, if the dashboard lists and serves it: it passes
/// [`open_report`] and its content is a report. A JSON file is one JSON
/// document whose `schema` is [`report::SCHEMA`], with a `header` object; a
/// PDF starts with `%PDF` and the JSON next to it is accepted too. The
/// Sessions view ([`reports_view`]) and `GET /reports/` ([`serve_report`])
/// both take their files from here, so every file listed downloads.
fn load_report(home: &Home, name: &str) -> Result<Report, Refused> {
    let body = open_report(home, name)?
        .read_all()
        .map_err(|_| Refused::NotFound)?;
    if let Some(json) = json_of_pdf(name) {
        return if body.starts_with(b"%PDF") && load_report(home, &json).is_ok() {
            Ok(Report {
                pdf: true,
                body,
                header: None,
            })
        } else {
            Err(Refused::NotFound)
        };
    }
    let document: Value = serde_json::from_slice(&body).map_err(|_| Refused::NotFound)?;
    if document["schema"] != report::SCHEMA || !document["header"].is_object() {
        return Err(Refused::NotFound);
    }
    Ok(Report {
        pdf: false,
        header: Some(document["header"].clone()),
        body,
    })
}

/// `GET /reports/<name>`: the report file [`load_report`] accepts, as a
/// download; 413 when it is over [`MAX_REPORT_BYTES`], 404 otherwise.
fn serve_report(home: &Home, name: &str) -> Response {
    let report = match load_report(home, name) {
        Ok(report) => report,
        Err(Refused::TooLarge) => return Response::text(413, "report too large"),
        Err(Refused::NotFound) => return Response::text(404, "no such report"),
    };
    Response {
        status: 200,
        content_type: if report.pdf {
            "application/pdf"
        } else {
            "application/json"
        },
        body: report.body,
        // `name` is a report file name here: letters, digits, `-` and `.`.
        disposition: Some(format!("attachment; filename=\"{name}\"")),
    }
}

/// What the Sessions view shows of one report file.
#[derive(Clone)]
struct ReportFile {
    bytes: u64,
    /// JSON files only.
    sha256: Option<String>,
    header: Option<Value>,
}

impl ReportFile {
    /// What the view shows of `name`; `None` when [`load_report`] refuses
    /// it, and then it is not listed.
    fn read(home: &Home, name: &str) -> Option<Self> {
        let report = load_report(home, name).ok()?;
        Some(Self {
            bytes: report.body.len() as u64,
            sha256: (!report.pdf).then(|| hex::encode(Sha256::digest(&report.body))),
            header: report.header,
        })
    }
}

/// One close report and the pairs `report` wrote from it, by file name.
#[derive(Default)]
struct ReportGroup {
    session_id: String,
    json: Option<Listed>,
    pdf: Option<Listed>,
    /// `<now UTC>` of the file name -> (json, pdf).
    regenerated: BTreeMap<String, (Option<Listed>, Option<Listed>)>,
}

/// A file name in `DIR/reports/` and what [`load_report`] read of it.
type Listed = (String, ReportFile);

/// The assurance level a report header records, for the Sessions chip.
/// [`Assurance::Anchored`] comes only from a header whose
/// `verify.assurance` is exactly its label. A report written before the
/// level existed has no `assurance`: its "passed" may have had no heads, so
/// it is UNANCHORED, and any other result is FAIL. A value this version does
/// not know is FAIL.
fn header_assurance(verify: &Value) -> Assurance {
    let unanchored = || Assurance::Unanchored {
        missing: Vec::new(),
    };
    match verify.get("assurance") {
        None | Some(Value::Null) => {
            if verify["result"] == "failed" {
                Assurance::Failed
            } else {
                unanchored()
            }
        }
        Some(Value::String(label)) if label == Assurance::Anchored.label() => Assurance::Anchored,
        Some(Value::String(label)) if label == unanchored().label() => unanchored(),
        Some(_) => Assurance::Failed,
    }
}

/// The fields of a report header the Sessions view shows.
fn header_summary(header: &Value) -> Value {
    json!({
        "praetore_mcp_version": header["praetore_mcp_version"],
        "agent": header["agent"],
        "server": header["server"],
        "mode": header["mode"],
        "started_at": header["started_at"],
        "ended_at": header["ended_at"],
        "generated_at": header["generated_at"],
        "seq": header["seq"],
        "summary": header["summary"],
        "verify": {
            "result": header["verify"]["result"],
            "assurance": header_assurance(&header["verify"]).label(),
            "session_receipts": header["verify"]["session_receipts"],
            "session_verified": header["verify"]["session_verified"],
        },
    })
}

/// The session reports in `DIR/reports/`, newest session first. Each item
/// is a report written at close with its JSON (size and SHA-256) and PDF,
/// and under it, apart, the pairs `praetore-mcp report` wrote later
/// (`.regen-`), oldest first. `file` reads one file (cached by
/// [`Cache::reports`]) and is `None` for a file [`load_report`] refuses,
/// which is left out: every file listed downloads.
fn reports_view(home: &Home, mut file: impl FnMut(&Path, &str) -> Option<ReportFile>) -> Value {
    let Ok(root) = home.root.canonicalize() else {
        return json!({"items": [], "error": null});
    };
    let dir = root.join("reports");
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return json!({"items": [], "error": null});
        }
        Err(error) => {
            return json!({"items": [], "error": format!("cannot read reports/: {error}")});
        }
    };
    let mut groups: BTreeMap<String, ReportGroup> = BTreeMap::new();
    for entry in entries.filter_map(Result::ok) {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(parsed) = report::parse_report_name(&name) else {
            continue;
        };
        let Some(read) = file(&dir.join(&name), &name) else {
            continue;
        };
        let group = groups.entry(parsed.close_stem.clone()).or_default();
        group.session_id = parsed.session_id.clone();
        let slot = match &parsed.regenerated_at {
            None => (&mut group.json, &mut group.pdf),
            Some(at) => {
                let pair = group.regenerated.entry(at.clone()).or_default();
                (&mut pair.0, &mut pair.1)
            }
        };
        let listed = Some((name, read));
        if parsed.pdf {
            *slot.1 = listed;
        } else {
            *slot.0 = listed;
        }
    }
    let describe = |json: &Option<Listed>, pdf: &Option<Listed>| {
        json!({
            "header": json.as_ref().and_then(|(_, f)| f.header.as_ref()).map(header_summary),
            "json": json.as_ref().map(|(name, f)| json!({
                "name": name, "bytes": f.bytes, "sha256": f.sha256,
            })),
            "pdf": pdf.as_ref().map(|(name, f)| json!({"name": name, "bytes": f.bytes})),
        })
    };
    let items: Vec<Value> = groups
        .iter()
        .rev()
        .map(|(stem, group)| {
            let mut item = describe(&group.json, &group.pdf);
            item["session_id"] = json!(group.session_id);
            item["stem"] = json!(stem);
            item["regenerations"] = group
                .regenerated
                .iter()
                .map(|(at, (json_name, pdf_name))| {
                    let mut regen = describe(json_name, pdf_name);
                    regen["regenerated_at"] = json!(at);
                    regen
                })
                .collect();
            item
        })
        .collect();
    json!({"items": items, "error": null})
}

/// Everything, read and verified now, with every receipt in journal order.
/// The page uses [`page_state`]; this is the whole view, for tests.
pub fn state(home: &Home, expected_head: Option<&str>) -> Value {
    state_with(
        home,
        ExpectedHeads {
            receipts: expected_head,
            approvals: None,
        },
    )
}

/// [`state`] with both expected heads, as `dashboard --expected-head
/// --expected-approval-head` passes them.
pub fn state_with(home: &Home, expected: ExpectedHeads<'_>) -> Value {
    let snapshot = Snapshot::read(home, expected, None);
    let approval_status = crate::approvals::status_by_evidence(home).unwrap_or_default();
    let receipts: Vec<Value> = snapshot
        .lines
        .iter()
        .map(|line| receipt_view(line, &approval_status))
        .collect();
    let pending = pending_view(home, &snapshot, &approval_status);
    let pending_count = pending.as_array().map_or(0, Vec::len);
    json!({
        "generated_at_utc": OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default(),
        "home": home.root.display().to_string(),
        "summary": snapshot.summary(pending_count),
        "policy": policy_view(home, snapshot.enforce_receipts()),
        "pending": pending,
        "verify": snapshot.verify,
        "receipts": receipts,
        "reports": reports_view(home, |_, name| ReportFile::read(home, name)),
    })
}

/// Calls waiting for approval, with the full canonical arguments (the text
/// `approve` prints before it asks for confirmation) and the receipt of the
/// held call. A pending file is not signed and `verify` does not check it:
/// each item says so with `signed: false`. Read only: deciding stays with
/// `praetore-mcp approve` / `reject` in a terminal.
/// The calls that can still be decided: those `status`
/// ([`crate::approvals::status_by_evidence_at`]) calls `pending`. An expired
/// one is left out here and labeled `expired` on its receipt, from the same
/// map, so the list and the labels cannot disagree.
fn pending_view(home: &Home, snapshot: &Snapshot, status: &BTreeMap<String, String>) -> Value {
    match crate::approvals::list_pending(home) {
        Ok(list) => Value::Array(
            list.into_iter()
                .filter(|item| {
                    status.get(&item.evidence_id).map(String::as_str) == Some("pending")
                })
                .map(|item| {
                    let full = crate::approvals::pending_call(home, &item.approval_id);
                    let receipt = snapshot
                        .by_evidence
                        .get(&item.evidence_id)
                        .map(|&index| receipt_view(&snapshot.lines[index], status));
                    // The page shows and copies these strings as they are.
                    let commands =
                        crate::approvals::DecisionCommands::new(home, &item.approval_id);
                    json!({
                        "approval_id": item.approval_id,
                        "server": item.server,
                        "tool": item.tool,
                        "expires_at": item.expiry.text(),
                        "commands": {"approve": commands.approve, "reject": commands.reject},
                        "evidence_id": item.evidence_id,
                        "signed": false,
                        "arguments_canonical": full.as_ref().ok().map(|c| c.arguments_canonical.clone()),
                        "error": full.err(),
                        "receipt": receipt,
                    })
                })
                .collect(),
        ),
        Err(error) => json!({"error": error}),
    }
}

fn verify_view(report: &VerifyReport, home: &Home, expected: ExpectedHeads<'_>) -> Value {
    json!({
        "status": if report.failures.is_empty() { "ok" } else { "fail" },
        // What `status: ok` is worth: "anchored" only when both journals
        // were compared with a head given to `dashboard`; "unanchored" is
        // the result `verify` reports with exit 3.
        "assurance": match report.assurance() {
            crate::receipts::Assurance::Anchored => "anchored",
            crate::receipts::Assurance::Unanchored { .. } => "unanchored",
            crate::receipts::Assurance::Failed => "failed",
        },
        "total": report.total,
        "verified": report.ok,
        "failed": report.failures.len(),
        "failures": report.failures,
        "chained": report.chained,
        "unchained": report.unchained,
        "head": report.head.map(|head| json!({"next_seq": head.seq, "prev": head.prev.to_string()})),
        "expected_head": expected.receipts,
        "attester_pin": home.attester_pin().display().to_string(),
        "issuer_pins": home.issuer_pins().display().to_string(),
        "approval": {
            "decisions": report.approval_decisions,
            "executions": report.approval_executions,
            "head": report.approval_head,
            "expected_head": expected.approvals,
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
        // For a DENY: "blocked" or "not_applied" (observe forwarded it).
        "deny_effect": receipts::deny_effect(evidence).map(DenyEffect::label),
        "rule": if rules.is_empty() { Value::Null } else { Value::String(rules.join(",")) },
        // Signed with the receipt: which rule, the default deny or an
        // engine guard decided. Absent on receipts older than schema v4.
        "decided_by": evidence.decision.decided_by().and_then(|by| serde_json::to_value(by).ok()),
        "reason": evidence.decision.reason,
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
        "raw": raw,
    })
}

fn tool_of(evidence: &Evidence) -> Value {
    if let Some(label) =
        crate::unparsed::reader_label(&evidence.action.action_type, &evidence.action.parameters)
    {
        return Value::String(label);
    }
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

#[cfg(test)]
mod tests {
    use super::{APP_JS, header_assurance, header_summary};
    use crate::gate::{DenyEffect, Mode};
    use crate::receipts::Assurance;
    use serde_json::json;

    /// Every level of `verify`. The match fails to compile when a level is
    /// added, so the page's table below cannot fall behind it.
    fn every_level() -> [Assurance; 3] {
        let levels = [
            Assurance::Anchored,
            Assurance::Unanchored {
                missing: vec!["--expected-head"],
            },
            Assurance::Failed,
        ];
        for level in &levels {
            match level {
                Assurance::Anchored | Assurance::Unanchored { .. } | Assurance::Failed => {}
            }
        }
        levels
    }

    /// The page describes a DENY only through its DENY_EFFECT table, and
    /// that table has exactly the effects of `DenyEffect`. Only `blocked`
    /// is drawn as blocked.
    #[test]
    fn the_page_knows_every_deny_effect_and_calls_only_blocked_blocked() {
        let mut labels = Vec::new();
        for mode in [Mode::Observe, Mode::Enforce] {
            for unclassified in [false, true] {
                let effect = DenyEffect::of(mode, unclassified);
                match effect {
                    DenyEffect::Blocked | DenyEffect::NotApplied => {}
                }
                if !labels.contains(&effect.label()) {
                    labels.push(effect.label());
                }
            }
        }
        labels.sort_unstable();
        let table = APP_JS
            .split("const DENY_EFFECT = {")
            .nth(1)
            .and_then(|rest| rest.split("};").next())
            .expect("app.js has the DENY_EFFECT table");
        let keys: Vec<&str> = table
            .lines()
            .filter_map(|line| line.trim().split_once(':').map(|(key, _)| key))
            .collect();
        assert_eq!(keys, labels, "app.js DENY_EFFECT and gate::DenyEffect");
        for line in table.lines().filter(|line| !line.trim().is_empty()) {
            let blocked = line.trim().starts_with("blocked:");
            assert_eq!(line.contains("\"e_blocked\""), blocked, "{line}");
            assert_eq!(line.contains("\"l_deny\""), blocked, "{line}");
        }
    }

    #[test]
    fn the_sessions_header_carries_the_assurance_level_the_page_knows() {
        let table = APP_JS
            .split("const ASSURANCE_CHIP = {")
            .nth(1)
            .and_then(|rest| rest.split("};").next())
            .expect("app.js has the ASSURANCE_CHIP table");
        let keys: Vec<&str> = table
            .lines()
            .filter_map(|line| line.trim().split_once(':').map(|(key, _)| key))
            .collect();
        let labels: Vec<&str> = every_level().iter().map(Assurance::label).collect();
        assert_eq!(
            keys, labels,
            "app.js ASSURANCE_CHIP and receipts::Assurance"
        );
        // Only OK is drawn green.
        for line in table.lines() {
            assert_eq!(
                line.contains("\"chip ok\""),
                line.trim().starts_with("OK:"),
                "{line}"
            );
        }
        for level in every_level() {
            let header = json!({ "verify": { "result": "passed", "assurance": level.label() } });
            assert_eq!(
                header_summary(&header)["verify"]["assurance"],
                level.label()
            );
        }
    }

    #[test]
    fn a_report_without_the_level_is_never_ok() {
        let level = |verify: serde_json::Value| header_assurance(&verify).label();
        // Reports written before `assurance` existed.
        assert_eq!(level(json!({ "result": "passed" })), "UNANCHORED");
        assert_eq!(
            level(json!({ "result": "passed", "assurance": null })),
            "UNANCHORED"
        );
        assert_eq!(level(json!({ "result": "failed" })), "FAIL");
        assert_eq!(level(json!({})), "UNANCHORED");
        assert_eq!(level(json!(null)), "UNANCHORED");
        // Only the exact label is OK; anything else this version does not
        // know is FAIL.
        assert_eq!(
            level(json!({ "result": "passed", "assurance": "OK" })),
            "OK"
        );
        for other in [
            json!("ok"),
            json!("passed"),
            json!(true),
            json!(0),
            json!(["OK"]),
        ] {
            assert_eq!(
                level(json!({ "result": "passed", "assurance": other })),
                "FAIL",
                "{other}"
            );
        }
        // What /api/state sends for a header without the level.
        let header = json!({ "verify": { "result": "passed", "session_receipts": 1 } });
        assert_eq!(header_summary(&header)["verify"]["assurance"], "UNANCHORED");
    }
}
