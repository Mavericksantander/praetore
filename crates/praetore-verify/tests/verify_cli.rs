use praetore_core::{
    action::Action,
    authority::Authority,
    authorization::AuthorizationRequest,
    decision::Decision,
    engine::TrustedAuthorityIssuer,
    evidence::EvidenceAttesterKey,
    identity::{AgentId, AgentKeyPair},
    policy::Policy,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct TestFiles {
    directory: PathBuf,
    evidence: PathBuf,
    tampered_evidence: PathBuf,
    attester_pin: PathBuf,
    wrong_attester_pin: PathBuf,
    issuer_pins: PathBuf,
    authority: PathBuf,
    agent: PathBuf,
    wrong_agent: PathBuf,
    policy: PathBuf,
    attester_public_key: String,
}

impl TestFiles {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "praetore-verify-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&directory).unwrap();

        let agent_key = AgentKeyPair::from_secret_bytes(&[1; 32]);
        let issuer_key = AgentKeyPair::from_secret_bytes(&[2; 32]);
        let attester = EvidenceAttesterKey::from_secret_bytes(&[3; 32]);
        let wrong_attester = EvidenceAttesterKey::from_secret_bytes(&[4; 32]);
        let agent = agent_key.identity(AgentId::new());
        let mut authority =
            Authority::new(agent.id.clone(), "test-issuer", vec!["data:read".into()]);
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let action = Action::new("read_data", Some("db".into()), json!({"table": "users"}))
            .unwrap()
            .with_capability("data:read");
        let mut request = AuthorizationRequest::new(agent, authority.clone(), action).unwrap();
        request.sign_intent(&agent_key).unwrap();
        let mut evidence = request.attest(Decision::allow("fixture decision")).unwrap();
        evidence.bind_policy_digest("ab".repeat(32)).unwrap();
        evidence.sign(&attester).unwrap();

        let mut tampered = evidence.clone();
        tampered.decision.reason.push_str(" altered");

        let policy = Policy::new("fixture-policy", 1, vec![]);
        let issuer_pin = TrustedAuthorityIssuer::new("test-issuer", issuer_key.public_key())
            .unwrap()
            .export_pin_json()
            .unwrap();
        let attester_public_key = hex::encode(attester.public_key().unwrap().as_bytes());
        let wrong_attester_public_key =
            hex::encode(wrong_attester.public_key().unwrap().as_bytes());

        let files = Self {
            evidence: directory.join("evidence.json"),
            tampered_evidence: directory.join("evidence-tampered.json"),
            attester_pin: directory.join("attester-pin.hex"),
            wrong_attester_pin: directory.join("wrong-attester-pin.hex"),
            issuer_pins: directory.join("issuer-pins.jsonl"),
            authority: directory.join("authority.json"),
            agent: directory.join("agent.json"),
            wrong_agent: directory.join("wrong-agent.json"),
            policy: directory.join("policy.json"),
            directory,
            attester_public_key,
        };
        fs::write(&files.evidence, evidence.to_json().unwrap()).unwrap();
        fs::write(
            &files.tampered_evidence,
            serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        fs::write(
            &files.attester_pin,
            format!("{}\n", files.attester_public_key),
        )
        .unwrap();
        fs::write(
            &files.wrong_attester_pin,
            format!("{wrong_attester_public_key}\n"),
        )
        .unwrap();
        fs::write(&files.issuer_pins, format!("{issuer_pin}\n")).unwrap();
        fs::write(&files.authority, serde_json::to_vec(&authority).unwrap()).unwrap();
        fs::write(&files.agent, serde_json::to_vec(&evidence.agent).unwrap()).unwrap();
        let wrong_agent_key = AgentKeyPair::from_secret_bytes(&[5; 32]);
        let wrong_agent = wrong_agent_key.identity(evidence.agent.id.clone());
        fs::write(
            &files.wrong_agent,
            serde_json::to_vec(&wrong_agent).unwrap(),
        )
        .unwrap();
        fs::write(&files.policy, serde_json::to_vec(&policy).unwrap()).unwrap();

        if std::env::var_os("UPDATE_PYTHON_FIXTURE").is_some() {
            let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../packages/praetore-python/tests/fixtures");
            fs::create_dir_all(&fixtures).unwrap();
            fs::write(
                fixtures.join("evidence-valid.json"),
                evidence.to_json().unwrap(),
            )
            .unwrap();
            fs::write(
                fixtures.join("evidence-tampered.json"),
                serde_json::to_vec(&tampered).unwrap(),
            )
            .unwrap();
            fs::write(
                fixtures.join("attester-public-key.hex"),
                &files.attester_public_key,
            )
            .unwrap();
        }
        if std::env::var_os("UPDATE_FUZZ_CORPUS").is_some() {
            let fuzz_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
            let evidence_corpus = fuzz_root.join("evidence_verify");
            fs::create_dir_all(&evidence_corpus).unwrap();
            let mut evidence_input = evidence.to_json().unwrap().into_bytes();
            evidence_input.push(0);
            evidence_input.extend_from_slice(files.attester_public_key.as_bytes());
            fs::write(
                evidence_corpus.join("known-attested-evidence"),
                evidence_input,
            )
            .unwrap();

            let authority_corpus = fuzz_root.join("authority_verify");
            fs::create_dir_all(&authority_corpus).unwrap();
            let mut authority_input = serde_json::to_vec(&authority).unwrap();
            authority_input.push(0);
            authority_input.extend_from_slice(issuer_pin.as_bytes());
            fs::write(
                authority_corpus.join("known-signed-authority"),
                authority_input,
            )
            .unwrap();
        }

        files
    }

    fn write_path(&self, path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }
}

impl Drop for TestFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn run(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(args)
        .output()
        .unwrap()
}

fn json_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn evidence_command_verifies_trusted_signature_intent_and_authority() {
    let files = TestFiles::new();
    let args = vec![
        "evidence".into(),
        "--evidence".into(),
        files.write_path(&files.evidence),
        "--attester-pin".into(),
        files.write_path(&files.attester_pin),
        "--issuer-pins".into(),
        files.write_path(&files.issuer_pins),
        "--require-intent".into(),
        "--format".into(),
        "json".into(),
    ];
    let output = run(&args);

    assert!(output.status.success());
    let summary = json_output(&output);
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["code"], "OK");
    assert_eq!(summary["details"]["intent_verified"], true);
    assert_eq!(summary["details"]["authority_verified"], true);
}

#[test]
fn evidence_command_rejects_tampered_documents_and_wrong_pins() {
    let files = TestFiles::new();
    for (evidence_path, attester_path, expected_code) in [
        (
            &files.tampered_evidence,
            &files.attester_pin,
            "EVIDENCE_FAIL",
        ),
        (&files.evidence, &files.wrong_attester_pin, "AUTH_FAIL"),
    ] {
        let output = run(&[
            "evidence".into(),
            "--evidence".into(),
            files.write_path(evidence_path),
            "--attester-pin".into(),
            files.write_path(attester_path),
            "--format".into(),
            "json".into(),
        ]);
        assert!(!output.status.success());
        let summary = json_output(&output);
        assert_eq!(summary["ok"], false);
        assert_eq!(summary["code"], expected_code);
    }

    let output = run(&[
        "evidence".into(),
        "--evidence".into(),
        files.write_path(&files.evidence),
        "--attester-pin".into(),
        files.write_path(&files.attester_pin),
        "--require-intent".into(),
        "--format".into(),
        "json".into(),
    ]);
    assert!(!output.status.success());
    assert_eq!(json_output(&output)["code"], "TRUST_STORE_FAIL");
}

#[test]
fn authority_and_policy_digest_commands_verify_and_report_stable_results() {
    let files = TestFiles::new();
    let authority = run(&[
        "authority".into(),
        "--authority".into(),
        files.write_path(&files.authority),
        "--agent".into(),
        files.write_path(&files.agent),
        "--issuer-pins".into(),
        files.write_path(&files.issuer_pins),
        "--now".into(),
        "2026-10-24T00:00:00Z".into(),
        "--format".into(),
        "json".into(),
    ]);
    assert!(authority.status.success());
    let authority_summary = json_output(&authority);
    assert_eq!(authority_summary["code"], "OK");
    assert_eq!(
        authority_summary["details"]["subject_identity_verified"],
        true
    );

    let wrong_agent = run(&[
        "authority".into(),
        "--authority".into(),
        files.write_path(&files.authority),
        "--agent".into(),
        files.write_path(&files.wrong_agent),
        "--issuer-pins".into(),
        files.write_path(&files.issuer_pins),
        "--now".into(),
        "2026-10-24T00:00:00Z".into(),
        "--format".into(),
        "json".into(),
    ]);
    assert!(!wrong_agent.status.success());
    assert_eq!(json_output(&wrong_agent)["code"], "AUTHORITY_VERIFY_FAIL");

    let policy = run(&[
        "policy-digest".into(),
        "--policy".into(),
        files.write_path(&files.policy),
        "--format".into(),
        "json".into(),
    ]);
    assert!(policy.status.success());
    let output = json_output(&policy);
    assert_eq!(output["details"]["policy_id"], "fixture-policy");
    assert_eq!(output["details"]["digest"].as_str().unwrap().len(), 64);
}
