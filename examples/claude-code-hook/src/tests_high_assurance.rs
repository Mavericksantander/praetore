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

struct State {
    root: PathBuf,
    state: PathBuf,
}

impl State {
    fn new(name: &str) -> Self {
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

    fn input(&self, agent: Option<&str>, tool: &str, tool_input: Value) -> HookInput {
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

    fn read(&self, agent: Option<&str>) -> HookInput {
        let file = format!("{}/README.md", self.root.display());
        self.input(agent, "Read", json!({ "file_path": file }))
    }

    fn receipts(&self) -> Vec<Evidence> {
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
}
