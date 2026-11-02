//! HighAssurance receipts: every receipt records a signed decision time, a
//! signed request is claimed once in the replay store (each hook invocation
//! builds a new request, so this does not deduplicate tool calls), the store
//! fails closed, and hook state created before this change is refused with a
//! pointer to `init`.
//!
//! The tests at the top level use only `initialize`, `authorize` and
//! `verify_receipts`; [`guard`] tests the replay store directly.

use std::path::PathBuf;

use super::*;
use crate::high_assurance::REPLAY_DIR;

pub(crate) struct State {
    pub(crate) root: PathBuf,
    pub(crate) state: PathBuf,
}

impl State {
    pub(crate) fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "praetore-claude-hook-ha-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let root = fs::canonicalize(&base).unwrap();
        let state = root.join("state");
        initialize(&state, &root, 30).unwrap();
        Self { root, state }
    }

    pub(crate) fn input(&self, agent: Option<&str>, tool: &str, tool_input: Value) -> HookInput {
        let mut input = json!({
            "tool_name": tool,
            "tool_input": tool_input,
            "tool_use_id": "toolu_ha",
            "cwd": self.root.display().to_string(),
        });
        if let Some(agent) = agent {
            input["agent_type"] = json!(agent);
        }
        serde_json::from_value(input).unwrap()
    }

    pub(crate) fn read(&self, agent: Option<&str>) -> HookInput {
        let file = format!("{}/README.md", self.root.display());
        self.input(agent, "Read", json!({ "file_path": file }))
    }

    pub(crate) fn receipts(&self) -> Vec<Evidence> {
        match fs::read_to_string(self.state.join(RECEIPTS_FILE)) {
            Ok(text) => text
                .lines()
                .map(|line| {
                    let record: Value = serde_json::from_str(line).unwrap();
                    Evidence::from_json(&record["evidence"].to_string()).unwrap()
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn replay(&self) -> PathBuf {
        self.state.join(REPLAY_DIR)
    }
}

impl Drop for State {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(self.replay(), fs::Permissions::from_mode(0o700));
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Every outcome the hook signs, the `unclassified` DENY included, is
/// HighAssurance evidence with `decided_at`, and the authority verifies
/// against the issuer pin at that instant: what `praetore-verify evidence
/// --require-decision-time` requires (checked end to end by
/// `verify.sh <bundle> --require-decision-time` in CI).
#[test]
fn every_receipt_records_a_signed_decision_time() {
    let s = State::new("decided-at");
    let calls = [
        (s.read(Some("explorer")), DecisionOutcome::Allow),
        (
            s.input(Some("planner"), "Bash", json!({ "command": "ls" })),
            DecisionOutcome::Deny,
        ),
        (
            s.input(None, "Bash", json!({ "command": "git push" })),
            DecisionOutcome::RequireApproval,
        ),
        (
            s.input(None, "safety:hold", json!({})),
            DecisionOutcome::Deny,
        ),
        (s.read(Some("general-purpose")), DecisionOutcome::Deny),
    ];
    for (input, expected) in &calls {
        let verdict = authorize(&s.state, input).unwrap();
        assert_eq!(verdict.outcome, *expected, "{}", input.tool_name);
        assert!(verdict.evidence_id.is_some(), "{}", input.tool_name);
    }

    let pin = TrustedAuthorityIssuer::from_pin_json(
        &fs::read_to_string(s.state.join(ISSUER_PIN_FILE)).unwrap(),
    )
    .unwrap();
    let receipts = s.receipts();
    assert_eq!(receipts.len(), calls.len());
    for evidence in &receipts {
        assert!(
            evidence.is_high_assurance_shape(),
            "{}",
            evidence.evidence_id
        );
        assert_eq!(evidence.evaluation_mode.as_deref(), Some("high_assurance"));
        let decided_at = OffsetDateTime::parse(evidence.decided_at.as_deref().unwrap(), &Rfc3339)
            .expect("decided_at is RFC 3339");
        let intent = evidence.intent_v2.as_ref().unwrap();
        assert_eq!(intent.audience, high_assurance::AUDIENCE);
        // The check praetore-verify makes with --issuer-pins.
        pin.verify_authority_at(&evidence.authority, decided_at)
            .unwrap();
    }
    let unclassified = &receipts[3];
    assert_eq!(unclassified.action.action_type, "safety:hold");
    assert_eq!(
        unclassified.decision.reason,
        praetore_core::UNCLASSIFIED_DENY_REASON
    );
    verify_receipts(&s.state).unwrap();
}

/// A declared Safety tool still gets no decision and no receipt, and claims
/// nothing in the replay store.
#[test]
fn declared_safety_tool_gets_no_receipt_and_no_claim() {
    let s = State::new("safety");
    let policy = load_policy(&s.state)
        .unwrap()
        .with_action_class("safety:halt", praetore_core::ActionClass::Safety);
    fs::write(
        s.state.join(POLICY_FILE),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
    let verdict = authorize(&s.state, &s.input(None, "safety:halt", json!({}))).unwrap();
    assert!(verdict.not_governed);
    assert!(s.receipts().is_empty());
    assert_eq!(fs::read_dir(s.replay()).unwrap().count(), 0);
}

/// Hook state written before HighAssurance receipts (no replay store) is
/// refused: no evaluation, no receipt, and the message points to `init`.
/// A declared Safety tool is still answered (G7).
#[test]
fn state_without_a_replay_store_is_refused_with_a_pointer_to_init() {
    let s = State::new("old-state");
    fs::remove_dir(s.replay()).unwrap();
    for input in [
        s.read(Some("explorer")),
        s.input(None, "safety:hold", json!({})),
    ] {
        let error = authorize(&s.state, &input).expect_err("old state evaluated");
        let message = error.to_string();
        assert!(
            message.contains("predates HighAssurance receipts"),
            "{message}"
        );
        assert!(message.contains("praetore-claude-hook init"), "{message}");
        assert_eq!(fail_closed(error).outcome, DecisionOutcome::Deny);
    }
    assert!(s.receipts().is_empty());
}

/// Adds an extended ACL entry granting everyone write access (macOS).
#[cfg(target_os = "macos")]
fn add_acl(path: &Path) {
    let status = std::process::Command::new("/bin/chmod")
        .arg("+a")
        .arg("everyone allow add_file,add_subdirectory,delete_child")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "chmod +a {}", path.display());
}

/// The replay store is unavailable (replaced by a file, a symlink, opened to
/// other users, not writable, an extended ACL entry on macOS) or the state
/// directory is writable by others: every call is denied without a receipt.
#[test]
fn unavailable_replay_store_fails_closed() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    for broken in [
        "file",
        "symlink",
        "open-permissions",
        "read-only",
        "state-0777",
        "state-group-write",
        "acl",
        "state-acl",
    ] {
        let s = State::new(&format!("unavailable-{broken}"));
        let replay = s.replay();
        match broken {
            "file" => {
                fs::remove_dir(&replay).unwrap();
                fs::write(&replay, "").unwrap();
            }
            #[cfg(unix)]
            "symlink" => {
                let elsewhere = s.root.join("elsewhere");
                fs::create_dir(&elsewhere).unwrap();
                fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
                fs::remove_dir(&replay).unwrap();
                std::os::unix::fs::symlink(&elsewhere, &replay).unwrap();
            }
            #[cfg(unix)]
            "open-permissions" => {
                fs::set_permissions(&replay, fs::Permissions::from_mode(0o755)).unwrap();
            }
            #[cfg(unix)]
            "read-only" => {
                fs::set_permissions(&replay, fs::Permissions::from_mode(0o500)).unwrap();
            }
            #[cfg(unix)]
            "state-0777" => {
                fs::set_permissions(&s.state, fs::Permissions::from_mode(0o777)).unwrap();
            }
            #[cfg(unix)]
            "state-group-write" => {
                fs::set_permissions(&s.state, fs::Permissions::from_mode(0o720)).unwrap();
            }
            #[cfg(target_os = "macos")]
            "acl" => add_acl(&replay),
            #[cfg(target_os = "macos")]
            "state-acl" => add_acl(&s.state),
            _ => continue,
        }
        let result = authorize(&s.state, &s.read(Some("explorer")));
        let error = result.expect_err(broken);
        let expected = match broken {
            "acl" | "state-acl" => "extended ACL entries",
            "state-0777" | "state-group-write" | "open-permissions" => "group/other permissions",
            _ => "",
        };
        // ACL cases run only on macOS (other platforms `continue` above).
        assert!(error.to_string().contains(expected), "{broken}: {error}");
        // Shown with --nocapture: CI checks that the ACL cases ran on macOS.
        println!("replay store case {broken}: denied: {error}");
        assert_eq!(
            fail_closed(error).outcome,
            DecisionOutcome::Deny,
            "{broken}"
        );
        assert!(s.receipts().is_empty(), "{broken}: receipt appended");
    }
}

/// The receipt cannot be written after the claim: the hook denies (fail
/// closed). The claim stays without a receipt; it names a request id that is
/// never reused, so it blocks nothing.
#[test]
fn unwritable_receipts_journal_denies_and_leaves_an_orphan_claim() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let s = State::new("receipts-read-only");
    assert_eq!(
        authorize(&s.state, &s.read(Some("explorer")))
            .unwrap()
            .outcome,
        DecisionOutcome::Allow
    );
    let journal = s.state.join(RECEIPTS_FILE);
    #[cfg(unix)]
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o400)).unwrap();
    let error = authorize(&s.state, &s.read(Some("explorer"))).expect_err("receipt written");
    assert_eq!(fail_closed(error).outcome, DecisionOutcome::Deny);
    assert_eq!(s.receipts().len(), 1, "no receipt for the denied call");
    let claims = fs::read_dir(s.replay().join(uuid::Uuid::nil().to_string()))
        .unwrap()
        .map(|agent| fs::read_dir(agent.unwrap().path()).unwrap().count())
        .sum::<usize>();
    assert_eq!(claims, 2, "the denied call's claim stays (orphan)");
}

/// The `tool_use_id` is signed in the receipt context: editing it in the
/// receipt breaks the signatures, and editing only the unsigned copy in the
/// `receipts.jsonl` line is caught by `verify`.
#[test]
fn tool_use_id_is_signed_and_tampering_fails() {
    let s = State::new("tool-use-id-signed");
    authorize(&s.state, &s.read(Some("explorer"))).unwrap();
    let evidence = &s.receipts()[0];
    assert_eq!(evidence.context[TOOL_USE_ID_CLAIM], "toolu_ha");
    verify_receipts(&s.state).unwrap();

    let journal = s.state.join(RECEIPTS_FILE);
    let original = fs::read_to_string(&journal).unwrap();
    for (what, edit) in [
        ("signed copy", "\"claude.tool_use_id\":\"toolu_ha\""),
        ("unsigned copy", "\"tool_use_id\":\"toolu_ha\""),
    ] {
        assert_eq!(original.matches(edit).count(), 1, "{what}");
        fs::write(
            &journal,
            original.replace(edit, &edit.replace("toolu_ha", "toolu_xx")),
        )
        .unwrap();
        assert!(
            verify_receipts(&s.state).is_err(),
            "{what} edited, verify passed"
        );
    }
}

/// A re-delivered tool call (same `tool_use_id`) is evaluated again and
/// allowed: each delivery is a separate decision with its own receipt.
/// `verify` passes and reports the repeat as a warning.
#[test]
fn same_tool_use_id_twice_is_allowed_and_reported() {
    let s = State::new("tool-use-id-twice");
    for _ in 0..2 {
        let verdict = authorize(&s.state, &s.read(Some("explorer"))).unwrap();
        assert_eq!(verdict.outcome, DecisionOutcome::Allow);
    }
    assert_eq!(s.receipts().len(), 2);
    let report = verify_receipts(&s.state).unwrap();
    assert_eq!(report.repeated_tool_use_ids(), vec![("toolu_ha", 2)]);
    let warning = report.repeated_tool_use_id_warning().unwrap();
    assert!(
        warning.starts_with("WARNING: 1 tool_use_id values"),
        "{warning}"
    );
    assert!(warning.contains("toolu_ha (x2)"), "{warning}");
}

/// A missing or empty `tool_use_id` is evaluated normally and no key is
/// signed: the absence is covered by the signature, and `verify` counts
/// such receipts separately (an absence is not a repeat). Claude Code
/// always sends one; the hook does not deny without it because it is not a
/// replay key.
#[test]
fn missing_tool_use_id_is_recorded_as_absent() {
    let s = State::new("tool-use-id-missing");
    let mut missing = s.read(Some("explorer"));
    missing.tool_use_id = None;
    let mut empty = s.read(Some("explorer"));
    empty.tool_use_id = Some(json!(""));
    for input in [missing, empty] {
        let verdict = authorize(&s.state, &input).unwrap();
        assert_eq!(verdict.outcome, DecisionOutcome::Allow);
    }
    for evidence in s.receipts() {
        assert!(!evidence.context.contains_key(TOOL_USE_ID_CLAIM));
    }
    let report = verify_receipts(&s.state).unwrap();
    assert_eq!(report.without_tool_use_id, 2);
    assert!(report.repeated_tool_use_ids().is_empty());
}

/// An oversized `tool_use_id` is rejected like an oversized agent or
/// session id: evaluated as `unregistered` and denied, with a signed
/// receipt that records the rejection (key and length, not the value).
/// Control characters in an accepted id are signed as sent and escaped in
/// the warning.
#[test]
fn tool_use_id_is_bounded_and_escaped() {
    let s = State::new("tool-use-id-bounds");
    let mut long = s.read(Some("explorer"));
    long.tool_use_id = Some(json!("x".repeat(129)));
    let verdict = authorize(&s.state, &long).unwrap();
    assert_eq!(verdict.outcome, DecisionOutcome::Deny);
    assert_eq!(verdict.deny_class, Some(DenyClass::Unregistered));
    let rejected = &s.receipts()[0].context["praetore.claim_rejected"];
    assert_eq!(rejected["key"], TOOL_USE_ID_CLAIM);
    assert_eq!(rejected["bytes"], 129);

    let mut odd = s.read(Some("explorer"));
    odd.tool_use_id = Some(json!("toolu_\u{202e}x\n"));
    for _ in 0..2 {
        authorize(&s.state, &odd).unwrap();
    }
    assert_eq!(
        s.receipts()[1].context[TOOL_USE_ID_CLAIM],
        "toolu_\u{202e}x\n"
    );
    let warning = verify_receipts(&s.state)
        .unwrap()
        .repeated_tool_use_id_warning()
        .unwrap();
    assert!(
        !warning.contains('\u{202e}') && !warning.contains('\n'),
        "{warning:?}"
    );
}

/// The `receipts.jsonl` line carries an unsigned copy of the tool_use_id
/// only when the receipt signs it. A rejected (oversized) id leaves no raw
/// copy; adding one fails `verify` and `export`. `export` takes the id only
/// from the signed context.
#[test]
fn unsigned_tool_use_id_copy_only_when_signed() {
    let s = State::new("tool-use-id-wrapper");
    authorize(&s.state, &s.read(Some("explorer"))).unwrap();
    let mut long = s.read(Some("explorer"));
    long.tool_use_id = Some(json!("y".repeat(200)));
    authorize(&s.state, &long).unwrap();
    let journal = s.state.join(RECEIPTS_FILE);
    let lines: Vec<Value> = fs::read_to_string(&journal)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["tool_use_id"], "toolu_ha");
    assert!(lines[1].get("tool_use_id").is_none(), "{}", lines[1]);
    assert!(
        !fs::read_to_string(&journal)
            .unwrap()
            .contains(&"y".repeat(200))
    );
    verify_receipts(&s.state).unwrap();
    let out = s.root.join("bundle");
    export_bundle(&s.state, &out).unwrap();
    let index: Vec<Value> =
        serde_json::from_slice(&fs::read(out.join("index.json")).unwrap()).unwrap();
    assert_eq!(index[0]["tool_use_id"], "toolu_ha");
    assert!(index[1]["tool_use_id"].is_null());

    // An unsigned copy on the line that signs none: refused.
    let mut forged = lines.clone();
    forged[1]["tool_use_id"] = json!("toolu_ha");
    let text: String = forged.iter().map(|line| format!("{line}\n")).collect();
    fs::write(&journal, text).unwrap();
    let error = verify_receipts(&s.state).unwrap_err().to_string();
    assert!(error.contains("1 receipts failed"), "{error}");
    let error = export_bundle(&s.state, &s.root.join("bundle-2"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("signs no tool_use_id"), "{error}");

    // An absent copy on a line that signs one is fine.
    let mut dropped = lines;
    dropped[0].as_object_mut().unwrap().remove("tool_use_id");
    let text: String = dropped.iter().map(|line| format!("{line}\n")).collect();
    fs::write(&journal, text).unwrap();
    verify_receipts(&s.state).unwrap();
}

/// A numeric tool_use_id is signed as its canonical text; any other JSON
/// type is rejected like an oversized id (evaluated as `unregistered`,
/// signed Deny, `praetore.claim_rejected` with the key and the JSON type,
/// never the value). Unparseable input fails closed with a fixed message
/// that does not echo input values.
#[test]
fn tool_use_id_of_any_json_type_is_handled() {
    let s = State::new("tool-use-id-types");
    let mut number = s.read(Some("explorer"));
    number.tool_use_id = Some(json!(12345));
    assert_eq!(
        authorize(&s.state, &number).unwrap().outcome,
        DecisionOutcome::Allow
    );
    assert_eq!(s.receipts()[0].context[TOOL_USE_ID_CLAIM], "12345");

    for (value, kind) in [
        (json!({ "secret": "zzz-value" }), "object"),
        (json!(["zzz-value"]), "array"),
        (json!(true), "boolean"),
    ] {
        let mut input = s.read(Some("explorer"));
        input.tool_use_id = Some(value);
        let verdict = authorize(&s.state, &input).unwrap();
        assert_eq!(verdict.outcome, DecisionOutcome::Deny, "{kind}");
        assert_eq!(verdict.deny_class, Some(DenyClass::Unregistered));
        let evidence = s.receipts().pop().unwrap();
        let rejected = &evidence.context["praetore.claim_rejected"];
        assert_eq!(rejected["key"], TOOL_USE_ID_CLAIM);
        assert_eq!(rejected["type"], kind);
        assert!(!evidence.to_json().unwrap().contains("zzz-value"), "{kind}");
    }
    verify_receipts(&s.state).unwrap();

    // The whole event parses with a non-string tool_use_id.
    let event = br#"{"tool_name":"Read","tool_input":{},"tool_use_id":{"a":1}}"#;
    assert!(parse_hook_input(event).is_ok());
    // An event that does not parse: fixed text, no input value in it.
    for bad in [
        &br#"{"tool_name":12345678,"tool_input":{}}"#[..],
        br#"{"tool_name":"Read","agent_type":"zzz-value-1"#,
        br#""zzz-value""#,
    ] {
        let message = fail_closed(parse_hook_input(bad).err().unwrap()).reason;
        assert!(
            !message.contains("12345678") && !message.contains("zzz-value"),
            "{message}"
        );
        assert!(
            message.contains("not a valid PreToolUse event"),
            "{message}"
        );
    }
}

/// Replay store, tested directly.
mod guard {
    use std::sync::{Arc, Barrier};

    use praetore_core::{ReplayGuard, ReplayGuardError};
    use uuid::Uuid;

    use super::*;
    use crate::high_assurance::{FileReplayGuard, engine};

    /// The explorer's signed request to read README.md, as `authorize`
    /// builds it.
    fn signed_request(s: &State, policy: &Policy) -> AuthorizationRequest {
        let agents = s.state.join(AGENTS_DIR);
        let profile: AgentProfile =
            serde_json::from_slice(&fs::read(agents.join("explorer.json")).unwrap()).unwrap();
        let identity = AgentIdentity::from_json(&profile.identity.to_string()).unwrap();
        let authority = Authority::from_json(&profile.authority.to_string()).unwrap();
        let key =
            AgentKeyPair::from_secret_bytes(&read_secret(&agents.join("explorer.key")).unwrap());
        let action = Action::new(
            "claude:read",
            None,
            json!({
                "path": format!("{}/README.md", s.root.display()),
                PROFILE_CONSTRAINT: "explorer",
            }),
        )
        .unwrap()
        .with_capability("fs:read");
        let action = policy.classify(action).unwrap().into_mission().unwrap();
        let mut request = AuthorizationRequest::new(identity, authority, action)
            .unwrap()
            .with_context("agent", json!("explorer"))
            .with_context("profile", json!("explorer"));
        sign_intent(&mut request, &key, policy).unwrap();
        request
    }

    fn hook_engine(s: &State) -> praetore_core::engine::AuthorizationEngine {
        let pin = TrustedAuthorityIssuer::from_pin_json(
            &fs::read_to_string(s.state.join(ISSUER_PIN_FILE)).unwrap(),
        )
        .unwrap();
        let attester = EvidenceAttesterKey::from_secret_bytes(
            &read_secret(&s.state.join(ATTESTER_KEY_FILE)).unwrap(),
        );
        engine(&s.state, load_policy(&s.state).unwrap(), pin, attester).unwrap()
    }

    /// The same signed request is evaluated once. A second evaluation, by
    /// the same engine or by a new one over the same state (the next hook
    /// process), is refused as a replay.
    #[test]
    fn replaying_the_same_request_is_refused() {
        let s = State::new("replay");
        let request = signed_request(&s, &load_policy(&s.state).unwrap());

        let first = hook_engine(&s).evaluate(request.clone()).unwrap();
        assert_eq!(first.decision.outcome, DecisionOutcome::Allow);
        assert!(first.decided_at.is_some());

        let again = hook_engine(&s).evaluate(request.clone()).unwrap_err();
        assert!(matches!(again, PraetoreError::ReplayDetected), "{again:?}");
        let engine = hook_engine(&s);
        assert!(matches!(
            engine.evaluate(request.clone()),
            Err(PraetoreError::ReplayDetected)
        ));
        // The claim is a file named after the request, under its agent.
        let claim = s
            .replay()
            .join(Uuid::nil().to_string())
            .join(request.agent.id.as_uuid().to_string())
            .join(request.request_id.to_string());
        assert!(claim.is_file(), "{}", claim.display());
    }

    /// The store is unavailable: the guard reports `Unavailable`, never a
    /// successful claim, and the engine returns no evidence.
    #[test]
    fn guard_reports_unavailable_when_the_store_is() {
        let s = State::new("guard-unavailable");
        let request = signed_request(&s, &load_policy(&s.state).unwrap());
        let engine = hook_engine(&s);
        fs::remove_dir(s.replay()).unwrap();
        let guard = FileReplayGuard::new(&s.state);
        assert_eq!(
            guard.claim_once(Uuid::nil(), Uuid::new_v4(), Uuid::new_v4()),
            Err(ReplayGuardError::Unavailable)
        );
        // The engine was built while the store existed; it still refuses.
        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::ReplayGuardUnavailable)
        ));
    }

    /// Many concurrent claims of one request, each through its own guard
    /// (as separate hook processes would): exactly one succeeds.
    #[test]
    fn concurrent_claims_of_one_request_succeed_exactly_once() {
        const RACERS: usize = 32;
        let s = State::new("concurrent");
        let (tenant, agent, request) = (Uuid::nil(), Uuid::new_v4(), Uuid::new_v4());
        let barrier = Arc::new(Barrier::new(RACERS));
        let results: Vec<_> = (0..RACERS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let state = s.state.clone();
                std::thread::spawn(move || {
                    let guard = FileReplayGuard::new(&state);
                    barrier.wait();
                    guard.claim_once(tenant, agent, request)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let won = results.iter().filter(|r| r.is_ok()).count();
        let refused = results
            .iter()
            .filter(|r| **r == Err(ReplayGuardError::AlreadyClaimed))
            .count();
        assert_eq!((won, refused), (1, RACERS - 1), "{results:?}");
    }

    /// Concurrent hook calls (distinct requests) all get a receipt, each
    /// with its own claim.
    #[test]
    fn concurrent_hook_calls_each_claim_their_own_request() {
        const CALLS: usize = 8;
        let s = State::new("concurrent-calls");
        let barrier = Arc::new(Barrier::new(CALLS));
        let handles: Vec<_> = (0..CALLS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let state = s.state.clone();
                let input = s.read(Some("explorer"));
                std::thread::spawn(move || {
                    barrier.wait();
                    authorize(&state, &input)
                        .map(|v| v.outcome)
                        .map_err(|e| e.to_string())
                })
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), Ok(DecisionOutcome::Allow));
        }
        let agents: Vec<_> = fs::read_dir(s.replay().join(Uuid::nil().to_string()))
            .unwrap()
            .collect();
        assert_eq!(agents.len(), 1, "one agent directory (explorer)");
        let claims = fs::read_dir(agents[0].as_ref().unwrap().path())
            .unwrap()
            .count();
        assert_eq!(claims, CALLS);
        assert_eq!(s.receipts().len(), CALLS);
    }

    /// A store or state directory owned by another user is refused (the
    /// check is run with another uid, since tests cannot chown).
    #[test]
    fn directory_owned_by_another_user_is_refused() {
        use crate::high_assurance::{Access, check_directory_owned_by, current_uid};
        let s = State::new("owner");
        for (path, access) in [
            (s.replay(), Access::Private),
            (s.state.clone(), Access::NoForeignWrite),
        ] {
            check_directory_owned_by(&path, access, current_uid()).unwrap();
            let error = check_directory_owned_by(&path, access, current_uid() + 1).unwrap_err();
            assert!(error.to_string().contains("not by this user"), "{error}");
        }
    }

    /// `acl_get_entry` failures fail closed: only `EINVAL` reads as "no
    /// entries".
    #[test]
    fn acl_entry_status_fails_closed() {
        use crate::high_assurance::first_entry_status;
        assert!(first_entry_status(0, None).unwrap());
        assert!(first_entry_status(0, Some(libc::ENOMEM)).unwrap());
        assert!(!first_entry_status(-1, Some(libc::EINVAL)).unwrap());
        for (status, errno) in [
            (-1, Some(libc::ENOMEM)),
            (-1, Some(libc::EIO)),
            (-1, Some(libc::EPERM)),
            (-1, None),
            (1, None),
            (-2, Some(libc::EINVAL)),
        ] {
            assert!(
                first_entry_status(status, errno).is_err(),
                "{status} {errno:?}"
            );
        }
    }

    /// The real call on macOS: no ACL, an ACL entry, and every entry
    /// removed again.
    #[cfg(target_os = "macos")]
    #[test]
    fn acl_check_reads_real_acls() {
        use crate::high_assurance::acl::has_extended_entries;
        let s = State::new("acl-real");
        let dir = s.replay();
        assert!(!has_extended_entries(&dir).unwrap());
        super::add_acl(&dir);
        assert!(has_extended_entries(&dir).unwrap());
        let status = std::process::Command::new("/bin/chmod")
            .arg("-N")
            .arg(&dir)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!has_extended_entries(&dir).unwrap());
        println!("acl check on macOS: none, entry, removed: ok");
    }
}
