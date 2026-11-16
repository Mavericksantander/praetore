//! The Sessions view of `praetore-mcp dashboard`: the session reports in
//! `DIR/reports/` listed with their regenerations grouped apart, and
//! `GET /reports/<file>` serving one for download, read-only, on loopback,
//! for exact report file names inside `DIR/reports/` only.

use praetore_mcp::{dashboard, store::Home};
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::SystemTime,
};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_praetore-mcp")
}

fn fake_server() -> PathBuf {
    let path = Path::new(bin())
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.exists(),
        "{} missing: run via `cargo test`",
        path.display()
    );
    path
}

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn wrap_one_call(dir: &str, text: &str) {
    let calls = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text": text}}}),
    ];
    let input: String = calls.iter().map(|c| format!("{c}\n")).collect();
    let server = fake_server();
    let out = run(
        &[
            "wrap",
            "--dir",
            dir,
            "--name",
            "fake",
            "--mode",
            "enforce",
            "--",
            server.to_str().unwrap(),
        ],
        &input,
    );
    assert!(out.status.success(), "{out:?}");
}

/// Two sessions, each with its close report; the second one regenerated
/// once with `praetore-mcp report --last`.
fn home_with_reports() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let dir = root.to_str().unwrap();
    assert!(run(&["init", "--dir", dir], "").status.success());
    let out = run(
        &[
            "policy",
            "allow",
            "--id",
            "allow-echo",
            "--server",
            "fake",
            "--tool",
            "echo",
            "--dir",
            dir,
        ],
        "",
    );
    assert!(out.status.success(), "{out:?}");
    wrap_one_call(dir, "one");
    // Report file names carry the start second: keep the sessions apart.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    wrap_one_call(dir, "two");
    let out = run(&["report", "--dir", dir, "--last"], "");
    assert!(out.status.success(), "{out:?}");
    (temp, Home::new(root))
}

fn reports(home: &Home) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(home.root.join("reports"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn close_json(home: &Home) -> String {
    reports(home)
        .into_iter()
        .find(|name| name.ends_with(".json") && !name.contains(".regen-"))
        .unwrap()
}

fn get(home: &Home, target: &str) -> dashboard::Response {
    request(home, "GET", target, "")
}

fn request(home: &Home, method: &str, target: &str, extra: &str) -> dashboard::Response {
    let raw = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n{extra}\r\n");
    dashboard::respond(&raw, home, None, 8787)
}

fn http(port: u16, request: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn snapshot(dir: &Path) -> BTreeMap<PathBuf, (u64, SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let meta = fs::symlink_metadata(entry.path()).unwrap();
            if meta.is_dir() {
                stack.push(entry.path());
            }
            out.insert(entry.path(), (meta.len(), meta.modified().unwrap()));
        }
    }
    out
}

/// The value of the only header `name` in `head`.
fn header<'a>(head: &'a str, name: &str) -> &'a str {
    let values: Vec<&str> = head
        .split("\r\n")
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .collect();
    assert_eq!(values.len(), 1, "{name} in {head}");
    values[0]
}

#[test]
fn pdf_and_json_download_byte_for_byte_with_attachment_headers() {
    let (_temp, home) = home_with_reports();
    let before = snapshot(&home.root);
    let names = reports(&home);
    assert_eq!(names.len(), 6, "{names:?}");
    let listener = dashboard::bind(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = home.clone();
    let count = names.len();
    let server = std::thread::spawn(move || {
        dashboard::serve(&listener, &served, None, Some(count)).unwrap();
    });
    for name in &names {
        let response = http(
            port,
            &format!("GET /reports/{name} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = std::str::from_utf8(&response[..split]).unwrap();
        let body = &response[split + 4..];
        assert!(head.starts_with("HTTP/1.1 200 "), "{name}: {head}");
        assert_eq!(
            body,
            fs::read(home.root.join("reports").join(name)).unwrap(),
            "{name}"
        );
        let pdf = name.ends_with(".pdf");
        assert_eq!(
            header(head, "Content-Type"),
            if pdf {
                "application/pdf"
            } else {
                "application/json"
            }
        );
        assert_eq!(
            header(head, "Content-Disposition"),
            format!("attachment; filename=\"{name}\"")
        );
        assert_eq!(header(head, "X-Content-Type-Options"), "nosniff");
        assert_eq!(header(head, "Cache-Control"), "no-store");
        assert_eq!(header(head, "Content-Length"), body.len().to_string());
    }
    server.join().unwrap();
    assert_eq!(
        before,
        snapshot(&home.root),
        "the dashboard wrote under DIR"
    );
}

#[test]
fn names_that_are_not_exactly_a_report_file_are_404() {
    let (temp, home) = home_with_reports();
    let good = close_json(&home);
    let stem = good.strip_suffix(".json").unwrap();
    // Files a bad name could reach, all present.
    fs::write(home.root.join("reports").join("notes.txt"), "x").unwrap();
    fs::write(temp.path().join("outside.json"), "{}").unwrap();
    for target in [
        "/reports/".to_owned(),
        "/reports/notes.txt".to_owned(),
        "/reports/../config.toml".to_owned(),
        "/reports/../policy.json".to_owned(),
        "/reports/..".to_owned(),
        "/reports/%2e%2e".to_owned(),
        "/reports/%2e%2e%2fpolicy.json".to_owned(),
        "/reports/..%2fpolicy.json".to_owned(),
        "/reports/..%2f..%2foutside.json".to_owned(),
        format!("/reports/{stem}%2ejson"),
        format!("/reports/x%2f{good}"),
        format!("/reports/./{good}"),
        format!("/reports//{good}"),
        format!("/reports/{good}/"),
        format!("/reports/{}", good.to_uppercase()),
        format!("/reports/{stem}.JSON"),
        format!("/reports/{stem}.txt"),
        format!("/reports/{stem}.json.bak"),
        format!("/reports/{stem}.regen-.json"),
        format!("/reports/{stem}.regen-20260101T000000Z.regen-20260101T000000Z.json"),
        format!("/reports/x{good}"),
        "/reports/session-20260101T000000Z-0123abcg.json".to_owned(),
        "/reports/session-20260101T000000-0123abcd.json".to_owned(),
        "/reports/session-20260101T000000Z-0123abc.json".to_owned(),
        // A valid name for a file that does not exist.
        "/reports/session-20260101T000000Z-0123abcd.pdf".to_owned(),
        "/reports/session-20260101T000000Z-0123abcd.regen-20260101T000001Z.json".to_owned(),
    ] {
        let response = get(&home, &target);
        assert_eq!(response.status, 404, "{target}");
        assert!(response.disposition.is_none(), "{target}");
        assert!(response.body.len() < 64, "{target}");
    }
    // The good name itself is served, through the same function.
    assert_eq!(get(&home, &format!("/reports/{good}")).status, 200);
}

#[cfg(unix)]
#[test]
fn symlinks_and_directories_are_not_served() {
    use std::os::unix::fs::symlink;
    let (temp, home) = home_with_reports();
    let reports = home.root.join("reports");
    // Named before any symlink is added (they sort first).
    let real_pdf = reports.join(close_json(&home).replace(".json", ".pdf"));
    assert!(real_pdf.is_file());
    let secret = temp.path().join("secret.json");
    fs::write(&secret, "secret").unwrap();
    // A report name that is a symlink to a file outside DIR/reports.
    let linked = "session-20260101T000000Z-0123abcd.json";
    symlink(&secret, reports.join(linked)).unwrap();
    assert_eq!(get(&home, &format!("/reports/{linked}")).status, 404);
    // A symlink to a real report inside DIR/reports is still a symlink.
    let inner = "session-20260101T000000Z-0123abce.pdf";
    symlink(&real_pdf, reports.join(inner)).unwrap();
    assert_eq!(get(&home, &format!("/reports/{inner}")).status, 404);
    // A directory with a report name.
    let dir_name = "session-20260101T000000Z-0123abcf.json";
    fs::create_dir(reports.join(dir_name)).unwrap();
    assert_eq!(get(&home, &format!("/reports/{dir_name}")).status, 404);
    // None of them is listed either.
    let state = dashboard::state(&home, None);
    let listed = state["reports"].to_string();
    for name in [linked, inner, dir_name] {
        assert!(!listed.contains(name), "{name} listed");
    }
}

/// `DIR/reports` itself a symlink to a directory elsewhere: every file
/// name in it is a regular file and a valid report name, but none is in
/// DIR/reports. Only the canonical path check refuses them.
#[cfg(unix)]
#[test]
fn files_outside_dir_reports_are_not_served_when_reports_is_a_symlink() {
    let (temp, home) = home_with_reports();
    let reports = home.root.join("reports");
    let elsewhere = temp.path().join("elsewhere");
    fs::rename(&reports, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &reports).unwrap();
    let names = reports_in(&elsewhere);
    assert_eq!(names.len(), 6);
    for name in &names {
        let response = get(&home, &format!("/reports/{name}"));
        assert_eq!(
            response.status, 404,
            "{name} served from outside DIR/reports"
        );
    }
    assert_eq!(dashboard::state(&home, None)["reports"]["items"], json!([]));
    // Back in place, the same files are served.
    fs::remove_file(&reports).unwrap();
    fs::rename(&elsewhere, &reports).unwrap();
    for name in &names {
        assert_eq!(
            get(&home, &format!("/reports/{name}")).status,
            200,
            "{name}"
        );
    }
}

fn reports_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn reports_are_get_only_and_need_this_host_and_no_other_origin() {
    let (_temp, home) = home_with_reports();
    let target = format!("/reports/{}", close_json(&home));
    for method in ["POST", "PUT", "DELETE", "PATCH", "HEAD"] {
        assert_eq!(request(&home, method, &target, "").status, 405, "{method}");
    }
    let foreign = dashboard::respond(
        &format!("GET {target} HTTP/1.1\r\nHost: attacker.example\r\n\r\n"),
        &home,
        None,
        8787,
    );
    assert_eq!(foreign.status, 403);
    let rebound = dashboard::respond(
        &format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:8788\r\n\r\n"),
        &home,
        None,
        8787,
    );
    assert_eq!(rebound.status, 403);
    for (origin, status) in [
        ("Origin: http://127.0.0.1:8787\r\n", 200),
        ("Origin: http://localhost:8787\r\n", 200),
        ("Origin: http://attacker.example\r\n", 403),
        ("Origin: null\r\n", 403),
        ("Origin: http://127.0.0.1:8788\r\n", 403),
        (
            "Origin: http://127.0.0.1:8787\r\nOrigin: http://attacker.example\r\n",
            403,
        ),
    ] {
        assert_eq!(
            request(&home, "GET", &target, origin).status,
            status,
            "{origin:?}"
        );
        // The same check for the state the page reads.
        assert_eq!(
            request(&home, "GET", "/api/state", origin).status,
            status,
            "{origin:?}"
        );
    }
}

#[test]
fn the_state_lists_close_reports_with_regenerations_grouped_apart() {
    let (_temp, home) = home_with_reports();
    let mut cache = dashboard::Cache::default();
    let raw = "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n\r\n";
    let response = dashboard::respond_with(raw, &home, None, 8787, &mut cache);
    assert_eq!(response.status, 200);
    let state: Value = serde_json::from_slice(&response.body).unwrap();
    let items = state["reports"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{}", state["reports"]);
    // Newest session first; the regeneration is under it, not an item.
    let (newest, oldest) = (&items[0], &items[1]);
    assert!(newest["stem"].as_str() > oldest["stem"].as_str());
    assert_eq!(oldest["regenerations"], json!([]));
    let regens = newest["regenerations"].as_array().unwrap();
    assert_eq!(regens.len(), 1);
    let stem = newest["stem"].as_str().unwrap();
    let regen_json = regens[0]["json"]["name"].as_str().unwrap();
    assert!(
        regen_json.starts_with(&format!("{stem}.regen-")),
        "{regen_json}"
    );
    assert_eq!(
        regens[0]["pdf"]["name"],
        regen_json.replace(".json", ".pdf")
    );
    for item in items {
        let stem = item["stem"].as_str().unwrap();
        assert_eq!(item["json"]["name"], format!("{stem}.json"));
        assert_eq!(item["pdf"]["name"], format!("{stem}.pdf"));
        assert_eq!(item["session_id"], &stem[stem.len() - 8..]);
        // The SHA-256 shown is the file's.
        let bytes = fs::read(home.root.join("reports").join(format!("{stem}.json"))).unwrap();
        assert_eq!(
            item["json"]["sha256"],
            hex::encode(sha2::Sha256::digest(&bytes))
        );
        let header = &item["header"];
        assert_eq!(header["server"], "fake");
        assert_eq!(header["mode"], "enforce");
        assert_eq!(header["verify"]["result"], "passed");
        assert_eq!(header["summary"]["allow"], 1);
        assert!(header["agent"].is_string() && header["started_at"].is_string());
        assert!(header["ended_at"].is_string());
    }
    assert_eq!(regens[0]["header"]["verify"]["result"], "passed");
    // A second request reads only what changed; the answer is the same.
    let again = dashboard::respond_with(raw, &home, None, 8787, &mut cache);
    let again: Value = serde_json::from_slice(&again.body).unwrap();
    assert_eq!(again["reports"], state["reports"]);
}

/// A hard link to a key of the home, with a report name, in DIR/reports:
/// a regular file, in place, of this user, but with two links. Not served,
/// not listed.
#[cfg(unix)]
#[test]
fn a_hard_link_to_a_key_with_a_report_name_is_404() {
    let (_temp, home) = home_with_reports();
    let key = home.root.join("keys").join("approver.local-dev.key");
    assert!(key.is_file());
    let name = "session-20260101T000000Z-0123abcd.json";
    fs::hard_link(&key, home.root.join("reports").join(name)).unwrap();
    let response = get(&home, &format!("/reports/{name}"));
    assert_eq!(response.status, 404);
    let secret = fs::read(&key).unwrap();
    assert!(
        !response
            .body
            .windows(secret.len().min(16))
            .any(|w| secret.starts_with(w))
    );
    let pdf = "session-20260101T000000Z-0123abcd.pdf";
    fs::hard_link(&key, home.root.join("reports").join(pdf)).unwrap();
    assert_eq!(get(&home, &format!("/reports/{pdf}")).status, 404);
    let listed = dashboard::state(&home, None)["reports"].to_string();
    assert!(!listed.contains("0123abcd"), "{listed}");
}

/// A symlink with a report name that points at a real report in the same
/// DIR/reports: the target is a regular file with one link, of this user,
/// whose real path is in DIR/reports. Only opening without following the
/// name (O_NOFOLLOW) refuses it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_symlink_to_a_real_report_is_refused_by_not_following_it() {
    let (_temp, home) = home_with_reports();
    let reports = home.root.join("reports");
    let close = close_json(&home);
    let stem = close.strip_suffix(".json").unwrap();
    // Names `report` could have written, next to the real files.
    for (link, target) in [
        (format!("{stem}.regen-20990101T000000Z.json"), close.clone()),
        (
            format!("{stem}.regen-20990101T000000Z.pdf"),
            format!("{stem}.pdf"),
        ),
    ] {
        std::os::unix::fs::symlink(reports.join(&target), reports.join(&link)).unwrap();
        assert_eq!(get(&home, &format!("/reports/{target}")).status, 200);
        assert_eq!(
            get(&home, &format!("/reports/{link}")).status,
            404,
            "{link}"
        );
    }
}

#[test]
fn a_file_over_the_size_limit_is_413_and_nothing_is_read() {
    let (_temp, home) = home_with_reports();
    let name = "session-20260101T000000Z-0123abcd.json";
    let file = fs::File::create(home.root.join("reports").join(name)).unwrap();
    // Sparse: no 64 MiB written to disk.
    file.set_len(dashboard::MAX_REPORT_BYTES + 1).unwrap();
    let response = get(&home, &format!("/reports/{name}"));
    assert_eq!(response.status, 413);
    assert!(response.body.len() < 64);
    assert!(response.disposition.is_none());
    // At the limit it is read, and refused as not a report.
    file.set_len(dashboard::MAX_REPORT_BYTES).unwrap();
    assert_eq!(get(&home, &format!("/reports/{name}")).status, 404);
}

#[test]
fn only_report_contents_are_served() {
    let (_temp, home) = home_with_reports();
    let reports = home.root.join("reports");
    let close = close_json(&home);
    let stem = close.strip_suffix(".json").unwrap();
    let cases: [(&str, &[u8]); 8] = [
        // A PDF whose JSON opens but is not a report.
        ("session-20260101T000000Z-00000007.json", b"{}"),
        ("session-20260101T000000Z-00000007.pdf", b"%PDF-1.7\n"),
        (
            "session-20260101T000000Z-00000001.json",
            b"{\"schema\":\"something-else/1\"}",
        ),
        // The report schema, but no header.
        (
            "session-20260101T000000Z-00000006.json",
            b"{\"schema\":\"praetore-mcp.session-report/1\",\"receipts\":[]}",
        ),
        ("session-20260101T000000Z-00000002.json", b"not json"),
        // A report header line alone, cut where the receipts begin.
        (
            "session-20260101T000000Z-00000003.json",
            b"{\"schema\":\"praetore-mcp.session-report/1\",\"receipts\":[",
        ),
        // A PDF without its JSON.
        ("session-20260101T000000Z-00000004.pdf", b"%PDF-1.7\n"),
        // Not a PDF, though its JSON is there.
        ("session-20260101T000000Z-00000005.pdf", b"PK\x03\x04"),
    ];
    fs::write(
        reports.join("session-20260101T000000Z-00000005.json"),
        fs::read(reports.join(&close)).unwrap(),
    )
    .unwrap();
    for (name, bytes) in cases {
        fs::write(reports.join(name), bytes).unwrap();
        assert_eq!(
            get(&home, &format!("/reports/{name}")).status,
            404,
            "{name}"
        );
    }
    // A real report, header and all, under another schema.
    let mut other: Value =
        serde_json::from_slice(&fs::read(reports.join(&close)).unwrap()).unwrap();
    assert!(other["header"].is_object());
    other["schema"] = json!("praetore-mcp.session-report/2");
    let name = "session-20260101T000000Z-00000008.json";
    fs::write(reports.join(name), serde_json::to_vec(&other).unwrap()).unwrap();
    assert_eq!(get(&home, &format!("/reports/{name}")).status, 404);
    // The real pair is served.
    assert_eq!(get(&home, &format!("/reports/{close}")).status, 200);
    assert_eq!(get(&home, &format!("/reports/{stem}.pdf")).status, 200);
    // A real PDF whose JSON is gone is no longer served.
    fs::remove_file(reports.join(&close)).unwrap();
    assert_eq!(get(&home, &format!("/reports/{stem}.pdf")).status, 404);
}

/// Every file name the Sessions view lists, regenerations included.
fn listed_names(reports: &Value) -> Vec<String> {
    let mut names = Vec::new();
    let mut add = |entry: &Value| {
        for kind in ["json", "pdf"] {
            if let Some(name) = entry[kind]["name"].as_str() {
                names.push(name.to_owned());
            }
        }
    };
    for item in reports["items"].as_array().unwrap() {
        add(item);
        for regen in item["regenerations"].as_array().unwrap() {
            add(regen);
        }
    }
    names.sort();
    names
}

/// The names in DIR/reports that `GET /reports/` serves (200).
fn served_names(home: &Home) -> Vec<String> {
    reports(home)
        .into_iter()
        .filter(|name| get(home, &format!("/reports/{name}")).status == 200)
        .collect()
}

fn api_reports(home: &Home, cache: &mut dashboard::Cache) -> Value {
    let raw = "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n\r\n";
    let response = dashboard::respond_with(raw, home, None, 8787, cache);
    assert_eq!(response.status, 200);
    serde_json::from_slice::<Value>(&response.body).unwrap()["reports"].clone()
}

/// The Sessions view lists a file exactly when `GET /reports/` serves it,
/// for every kind of file in DIR/reports that is refused, with and without
/// the cache of the running server; a PDF leaves the list when its JSON
/// stops being a report.
#[test]
fn the_view_lists_exactly_the_files_the_download_serves() {
    let (_temp, home) = home_with_reports();
    let reports = home.root.join("reports");
    let close = close_json(&home);
    let stem = close.strip_suffix(".json").unwrap().to_owned();
    let real = fs::read(reports.join(&close)).unwrap();
    let header_line = real.split(|b| *b == b'\n').next().unwrap().to_vec();
    let mut cases: Vec<(String, Vec<u8>)> = vec![
        (
            "session-20260101T000000Z-00000001.json".into(),
            b"{\"schema\":\"something-else/1\",\"header\":{}}".to_vec(),
        ),
        (
            "session-20260101T000000Z-00000002.json".into(),
            b"not json".to_vec(),
        ),
        ("session-20260101T000000Z-00000003.json".into(), header_line),
        (
            "session-20260101T000000Z-00000004.pdf".into(),
            b"%PDF-1.7\n".to_vec(),
        ),
        (
            "session-20260101T000000Z-00000005.json".into(),
            real.clone(),
        ),
        (
            "session-20260101T000000Z-00000005.pdf".into(),
            b"PK\x03\x04".to_vec(),
        ),
        (
            "session-20260101T000000Z-00000006.json".into(),
            b"{\"schema\":\"something-else/1\"}".to_vec(),
        ),
        (
            "session-20260101T000000Z-00000006.pdf".into(),
            b"%PDF-1.7\n".to_vec(),
        ),
    ];
    cases.sort();
    for (name, bytes) in &cases {
        fs::write(reports.join(name), bytes).unwrap();
    }
    let big = fs::File::create(reports.join("session-20260101T000000Z-00000007.json")).unwrap();
    big.set_len(dashboard::MAX_REPORT_BYTES + 1).unwrap();
    #[cfg(unix)]
    {
        let key = home.root.join("keys").join("approver.local-dev.key");
        fs::hard_link(&key, reports.join("session-20260101T000000Z-00000008.json")).unwrap();
        std::os::unix::fs::symlink(
            reports.join(&close),
            reports.join(format!("{stem}.regen-20990101T000000Z.json")),
        )
        .unwrap();
    }
    let served = served_names(&home);
    assert!(
        served.contains(&close) && served.contains(&format!("{stem}.pdf")),
        "{served:?}"
    );
    assert!(served.contains(&"session-20260101T000000Z-00000005.json".to_owned()));
    let mut cache = dashboard::Cache::default();
    assert_eq!(
        listed_names(&dashboard::state(&home, None)["reports"]),
        served
    );
    assert_eq!(listed_names(&api_reports(&home, &mut cache)), served);
    // The JSON of a listed PDF stops being a report: both leave the list,
    // in the cached view too.
    fs::write(reports.join(&close), b"{\"schema\":\"something-else/1\"}").unwrap();
    let served = served_names(&home);
    assert!(!served.contains(&format!("{stem}.pdf")), "{served:?}");
    assert_eq!(listed_names(&api_reports(&home, &mut cache)), served);
    assert_eq!(
        listed_names(&dashboard::state(&home, None)["reports"]),
        served
    );
}

/// The rule `open_report` applies to the metadata of the open file, on
/// its own: the other user's file is the case a test cannot create
/// without root.
#[test]
fn servable_needs_a_regular_file_with_one_link_of_this_user() {
    assert!(dashboard::servable(1, 501, 501, true));
    assert!(!dashboard::servable(2, 501, 501, true), "a second link");
    assert!(!dashboard::servable(1, 0, 501, true), "another user's file");
    assert!(
        !dashboard::servable(1, 502, 501, true),
        "another user's file"
    );
    assert!(
        !dashboard::servable(1, 501, 501, false),
        "not a regular file"
    );
    assert!(!dashboard::servable(0, 501, 501, true), "no link");
}
