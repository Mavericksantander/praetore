use praetore_core::{
    PraetoreError,
    authority::Authority,
    engine::TrustedAuthorityIssuer,
    evidence::Evidence,
    identity::{AgentIdentity, VerifiedPublicKey},
    journal_chain::{ChainLink, MAX_CHAIN_BYTES, verify_chain},
    policy::Policy,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashSet},
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_INPUT_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Text,
}

#[derive(Debug, Serialize)]
struct Summary {
    ok: bool,
    command: &'static str,
    code: &'static str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    details: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug)]
struct CliError {
    code: &'static str,
}

impl CliError {
    fn usage() -> Self {
        Self { code: "USAGE" }
    }

    fn from_core(error: PraetoreError) -> Self {
        Self { code: error.code() }
    }
}

#[derive(Debug)]
enum Command {
    Evidence {
        evidence: PathBuf,
        attester_pin: PathBuf,
        issuer_pins: Option<PathBuf>,
        require_intent: bool,
        policy: Option<PathBuf>,
    },
    Journal {
        journal: PathBuf,
        attester_pin: PathBuf,
        expected_head: Option<String>,
        policy: Option<PathBuf>,
    },
    PolicyDigest {
        policy: PathBuf,
    },
    Receipt {
        receipt: PathBuf,
        execution_pin: PathBuf,
        key_id: String,
        evidence_attester_pin: PathBuf,
    },
    Authority {
        authority: PathBuf,
        agent: Option<PathBuf>,
        issuer_pins: PathBuf,
        now: Option<String>,
    },
}

fn main() {
    let result = env::args().skip(1).collect::<Vec<_>>();
    if matches!(result.as_slice(), [flag] if flag == "--help" || flag == "-h") {
        println!(
            "Usage:\n  praetore-verify evidence --evidence PATH --attester-pin HEX_FILE [--issuer-pins JSONL] [--require-intent] [--policy PATH] [--format json|text]\n  praetore-verify journal --journal JSONL --attester-pin HEX_FILE [--expected-head HEX] [--policy PATH] [--format json|text]\n  praetore-verify policy-digest --policy PATH [--format json|text]\n  praetore-verify receipt --receipt PATH --execution-pin HEX_FILE --key-id ID --evidence-attester-pin HEX_FILE [--format json|text]\n  praetore-verify authority --authority PATH --issuer-pins JSONL [--agent PATH] [--now RFC3339] [--format json|text]\n\nThe evidence command verifies a historical receipt's integrity and attester signature; with --policy it also requires the receipt to record that policy's digest (receipts without a digest fail). With --issuer-pins it checks the embedded authority (issuer pin, signature, subject binding, not-before and expiry) at the receipt's signed decision time (decided_at, HighAssurance receipts) and reports it as authority_checked_at; receipts that record no decision time are checked at the verifier's current time (authority_checked_at_source=verifier_clock). This shows the authority was valid when the decision was recorded, not that it is valid now, and the decision time is only as trustworthy as the attester key that signed it. The journal command verifies a hash-linked JSONL export (see docs/proposals/journal-chain-jsonl.md) and every receipt's signature; with --expected-head it also requires the final link to equal that value. It does not establish current authorization, freshness, replay state, or permission to execute an action.\n\nAttester pin files contain a lowercase 32-byte Ed25519 public-key hex value. Issuer pin files contain one compact exported pin JSON document per line."
        );
        return;
    }
    let (summary, format) = match parse_command(&result) {
        Ok((command, format)) => match execute(command, OffsetDateTime::now_utc()) {
            Ok(summary) => (summary, format),
            Err(error) => (
                Summary {
                    ok: false,
                    command: command_name(&result),
                    code: error.code,
                    details: BTreeMap::new(),
                },
                format,
            ),
        },
        Err(error) => (
            Summary {
                ok: false,
                command: command_name(&result),
                code: error.code,
                details: BTreeMap::new(),
            },
            requested_format(&result).unwrap_or(OutputFormat::Text),
        ),
    };

    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(&summary).unwrap_or_else(|_| {
                    r#"{"ok":false,"command":"unknown","code":"INTERNAL"}"#.into()
                })
            );
        }
        OutputFormat::Text => {
            print!(
                "{} {} {}",
                if summary.ok { "OK" } else { "ERROR" },
                summary.command,
                summary.code
            );
            for (key, value) in &summary.details {
                print!(
                    " {key}={}",
                    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
                );
            }
            println!();
        }
    }

    if !summary.ok {
        process::exit(1);
    }
}

fn parse_command(args: &[String]) -> Result<(Command, OutputFormat), CliError> {
    let command_name = args.first().ok_or_else(CliError::usage)?;
    let mut values = BTreeMap::<String, Option<String>>::new();
    let mut format = OutputFormat::Text;
    let mut format_seen = false;
    let mut index = 1;

    while index < args.len() {
        let flag = &args[index];
        if flag == "--format" {
            if format_seen {
                return Err(CliError::usage());
            }
            format_seen = true;
            index += 1;
            format = match args.get(index).map(String::as_str) {
                Some("json") => OutputFormat::Json,
                Some("text") => OutputFormat::Text,
                _ => return Err(CliError::usage()),
            };
        } else if flag == "--require-intent" {
            if values.insert(flag.clone(), None).is_some() {
                return Err(CliError::usage());
            }
        } else if flag.starts_with("--") {
            index += 1;
            let value = args.get(index).ok_or_else(CliError::usage)?.clone();
            if value.starts_with("--") {
                return Err(CliError::usage());
            }
            if values.insert(flag.clone(), Some(value)).is_some() {
                return Err(CliError::usage());
            }
        } else {
            return Err(CliError::usage());
        }
        index += 1;
    }

    let path = |flag: &str| -> Result<PathBuf, CliError> {
        values
            .get(flag)
            .and_then(Option::as_ref)
            .map(PathBuf::from)
            .ok_or_else(CliError::usage)
    };
    let optional_path = |flag: &str| -> Option<PathBuf> {
        values.get(flag).and_then(Option::as_ref).map(PathBuf::from)
    };

    let command = match command_name.as_str() {
        "evidence" => {
            if values.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "--evidence"
                        | "--attester-pin"
                        | "--issuer-pins"
                        | "--require-intent"
                        | "--policy"
                )
            }) {
                return Err(CliError::usage());
            }
            Command::Evidence {
                evidence: path("--evidence")?,
                attester_pin: path("--attester-pin")?,
                issuer_pins: optional_path("--issuer-pins"),
                require_intent: values.contains_key("--require-intent"),
                policy: optional_path("--policy"),
            }
        }
        "receipt" => {
            if values.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "--receipt" | "--execution-pin" | "--key-id" | "--evidence-attester-pin"
                )
            }) {
                return Err(CliError::usage());
            }
            Command::Receipt {
                receipt: path("--receipt")?,
                execution_pin: path("--execution-pin")?,
                key_id: values
                    .get("--key-id")
                    .and_then(Option::as_ref)
                    .cloned()
                    .ok_or_else(CliError::usage)?,
                evidence_attester_pin: path("--evidence-attester-pin")?,
            }
        }
        "journal" => {
            if values.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "--journal" | "--attester-pin" | "--expected-head" | "--policy"
                )
            }) {
                return Err(CliError::usage());
            }
            Command::Journal {
                journal: path("--journal")?,
                attester_pin: path("--attester-pin")?,
                expected_head: match values.get("--expected-head") {
                    None => None,
                    Some(Some(value)) => Some(value.clone()),
                    Some(None) => return Err(CliError::usage()),
                },
                policy: optional_path("--policy"),
            }
        }
        "policy-digest" => {
            if values.keys().any(|key| key != "--policy") {
                return Err(CliError::usage());
            }
            Command::PolicyDigest {
                policy: path("--policy")?,
            }
        }
        "authority" => {
            if values.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "--authority" | "--agent" | "--issuer-pins" | "--now"
                )
            }) {
                return Err(CliError::usage());
            }
            Command::Authority {
                authority: path("--authority")?,
                agent: optional_path("--agent"),
                issuer_pins: path("--issuer-pins")?,
                now: values.get("--now").and_then(Option::as_ref).cloned(),
            }
        }
        _ => return Err(CliError::usage()),
    };
    Ok((command, format))
}

/// `verifier_now` is the verifier's clock. The evidence command uses it for
/// the authority check only when the receipt records no signed decision time
/// (see [`authority_check_time`]); the authority command uses it when `--now`
/// is absent. Tests pass a fixed instant.
fn execute(command: Command, verifier_now: OffsetDateTime) -> Result<Summary, CliError> {
    let mut details = BTreeMap::new();
    let command_name = match command {
        Command::Evidence {
            evidence,
            attester_pin,
            issuer_pins,
            require_intent,
            policy,
        } => {
            let policy = policy.as_deref().map(read_policy).transpose()?;
            let evidence =
                Evidence::from_json(&read_limited(&evidence)?).map_err(CliError::from_core)?;
            let attester = read_attester_pin(&attester_pin)?;
            evidence
                .verify_attester_signature(&attester)
                .map_err(CliError::from_core)?;
            if let Some(policy) = &policy {
                verify_receipt_policy(&evidence, policy)?;
                details.insert("policy_verified".into(), serde_json::Value::Bool(true));
            }
            if let Some(pin_path) = issuer_pins {
                let (checked_at, source) = authority_check_time(&evidence, verifier_now)?;
                verify_evidence_authority(&evidence, &read_issuer_pins(&pin_path)?, checked_at)?;
                details.insert("authority_verified".into(), serde_json::Value::Bool(true));
                details.insert(
                    "authority_checked_at".into(),
                    serde_json::Value::String(format_rfc3339(checked_at)?),
                );
                details.insert(
                    "authority_checked_at_source".into(),
                    serde_json::Value::String(source.into()),
                );
            } else if require_intent {
                return Err(CliError {
                    code: "TRUST_STORE_FAIL",
                });
            }
            if require_intent {
                evidence
                    .verify_agent_intent()
                    .map_err(CliError::from_core)?;
            }
            details.insert(
                "intent_verified".into(),
                serde_json::Value::Bool(require_intent),
            );
            details.insert(
                "verification_scope".into(),
                serde_json::Value::String("historical_receipt_integrity_and_attestation".into()),
            );
            details.insert(
                "current_authorization".into(),
                serde_json::Value::Bool(false),
            );
            details.insert(
                "evidence_id".into(),
                serde_json::Value::String(evidence.evidence_id.to_string()),
            );
            "evidence"
        }
        Command::Receipt {
            receipt,
            execution_pin,
            key_id,
            evidence_attester_pin,
        } => {
            let public_key = read_attester_pin(&execution_pin)?;
            let evidence_attester = read_attester_pin(&evidence_attester_pin)?;
            let receipt = praetore_receipt::verify_gateway_receipt_json(
                &read_limited(&receipt)?,
                &public_key,
                &key_id,
                &evidence_attester,
            )
            .map_err(|error| CliError {
                code: match error {
                    praetore_receipt::ExecutionAttestationError::InvalidPayload => {
                        "RECEIPT_INVALID"
                    }
                    praetore_receipt::ExecutionAttestationError::InvalidEvidenceSignature => {
                        "RECEIPT_EVIDENCE_SIGNATURE_INVALID"
                    }
                    _ => "RECEIPT_SIGNATURE_INVALID",
                },
            })?;
            let attestation = &receipt.execution_attestation;
            details.insert(
                "schema_version".into(),
                serde_json::Value::Number(attestation.schema_version.into()),
            );
            details.insert(
                "execution".into(),
                serde_json::to_value(receipt.execution).unwrap_or_default(),
            );
            details.insert(
                "not_dispatched_reason".into(),
                serde_json::to_value(attestation.not_dispatched_reason).unwrap_or_default(),
            );
            details.insert(
                "verification_scope".into(),
                serde_json::Value::String("historical_execution_attestation".into()),
            );
            details.insert(
                "current_authorization".into(),
                serde_json::Value::Bool(false),
            );
            "receipt"
        }
        Command::Journal {
            journal,
            attester_pin,
            expected_head,
            policy,
        } => {
            let expected_head = expected_head
                .as_deref()
                .map(|value| {
                    ChainLink::from_hex(value).ok_or(CliError {
                        code: "INVALID_REQUEST",
                    })
                })
                .transpose()?;
            let policy = policy.as_deref().map(read_policy).transpose()?;
            let attester = read_attester_pin(&attester_pin)?;
            let text = read_limited_to(&journal, MAX_CHAIN_BYTES)?;
            let chain = verify_chain(&text, &attester, policy.as_ref(), expected_head.as_ref())
                .map_err(|error| {
                    eprintln!("journal: {error}");
                    CliError { code: error.code() }
                })?;
            details.insert(
                "entries".into(),
                serde_json::Value::Number(chain.entries.get().into()),
            );
            details.insert(
                "head".into(),
                serde_json::Value::String(chain.head.to_hex()),
            );
            details.insert(
                "expected_head_verified".into(),
                serde_json::Value::Bool(expected_head.is_some()),
            );
            details.insert(
                "policy_verified".into(),
                serde_json::Value::Bool(policy.is_some()),
            );
            details.insert(
                "verification_scope".into(),
                serde_json::Value::String("historical_journal_integrity_and_attestation".into()),
            );
            "journal"
        }
        Command::PolicyDigest { policy } => {
            let policy = Policy::from_json(&read_limited(&policy)?).map_err(CliError::from_core)?;
            details.insert(
                "policy_id".into(),
                serde_json::Value::String(policy.id.clone()),
            );
            details.insert(
                "policy_version".into(),
                serde_json::Value::Number(policy.version.into()),
            );
            details.insert(
                "digest".into(),
                serde_json::Value::String(policy.digest().map_err(CliError::from_core)?),
            );
            "policy-digest"
        }
        Command::Authority {
            authority,
            agent,
            issuer_pins,
            now,
        } => {
            let authority =
                Authority::from_json(&read_limited(&authority)?).map_err(CliError::from_core)?;
            let now = parse_now(now.as_deref(), verifier_now)?;
            let pins = read_issuer_pins(&issuer_pins)?;
            verify_authority(&authority, &pins, now)?;
            let subject_identity_verified = if let Some(agent_path) = agent {
                let agent = AgentIdentity::from_json(&read_limited(&agent_path)?)
                    .map_err(CliError::from_core)?;
                authority
                    .verify_subject_identity(&agent)
                    .map_err(CliError::from_core)?;
                true
            } else {
                false
            };
            details.insert("issuer".into(), serde_json::Value::String(authority.issuer));
            details.insert(
                "subject_identity_verified".into(),
                serde_json::Value::Bool(subject_identity_verified),
            );
            "authority"
        }
    };
    Ok(Summary {
        ok: true,
        command: command_name,
        code: "OK",
        details,
    })
}

fn read_policy(path: &Path) -> Result<Policy, CliError> {
    Policy::from_json(&read_limited(path)?).map_err(CliError::from_core)
}

fn verify_receipt_policy(evidence: &Evidence, policy: &Policy) -> Result<(), CliError> {
    evidence.verify_policy(policy).map_err(|_| CliError {
        code: "POLICY_MISMATCH",
    })
}

fn read_limited(path: &Path) -> Result<String, CliError> {
    read_limited_to(path, MAX_INPUT_BYTES)
}

fn read_limited_to(path: &Path, limit: usize) -> Result<String, CliError> {
    let file = fs::File::open(path).map_err(|_| CliError { code: "INPUT_IO" })?;
    let mut bytes = Vec::with_capacity(limit.min(MAX_INPUT_BYTES) + 1);
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError { code: "INPUT_IO" })?;
    if bytes.len() > limit {
        return Err(CliError {
            code: "INPUT_TOO_LARGE",
        });
    }
    String::from_utf8(bytes).map_err(|_| CliError {
        code: "INPUT_INVALID_UTF8",
    })
}

fn read_attester_pin(path: &Path) -> Result<VerifiedPublicKey, CliError> {
    let text = read_limited(path)?;
    let encoded = text.trim();
    if encoded.len() != 64 || encoded.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(CliError {
            code: "TRUST_STORE_FAIL",
        });
    }
    let key = hex::decode(encoded).map_err(|_| CliError {
        code: "TRUST_STORE_FAIL",
    })?;
    VerifiedPublicKey::from_bytes(&key).map_err(|_| CliError {
        code: "TRUST_STORE_FAIL",
    })
}

fn read_issuer_pins(path: &Path) -> Result<Vec<TrustedAuthorityIssuer>, CliError> {
    let text = read_limited(path)?;
    let mut pins = Vec::new();
    let mut key_ids = HashSet::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let pin = TrustedAuthorityIssuer::from_pin_json(line).map_err(CliError::from_core)?;
        if !key_ids.insert(pin.key_id().to_owned()) {
            return Err(CliError {
                code: "TRUST_STORE_FAIL",
            });
        }
        pins.push(pin);
    }
    if pins.is_empty() {
        return Err(CliError {
            code: "TRUST_STORE_FAIL",
        });
    }
    Ok(pins)
}

fn verify_evidence_authority(
    evidence: &Evidence,
    pins: &[TrustedAuthorityIssuer],
    now: OffsetDateTime,
) -> Result<(), CliError> {
    evidence
        .authority
        .verify_subject_identity(&evidence.agent)
        .map_err(CliError::from_core)?;
    verify_authority(&evidence.authority, pins, now)
}

fn verify_authority(
    authority: &Authority,
    pins: &[TrustedAuthorityIssuer],
    now: OffsetDateTime,
) -> Result<(), CliError> {
    let known_issuer = pins.iter().any(|pin| pin.issuer() == authority.issuer);
    let pin = pins
        .iter()
        .find(|pin| {
            pin.issuer() == authority.issuer
                && authority.issuer_key_id.as_deref() == Some(pin.key_id())
        })
        .ok_or(CliError {
            code: if known_issuer {
                "AUTHORITY_VERIFY_FAIL"
            } else {
                "TRUST_STORE_FAIL"
            },
        })?;
    pin.verify_authority_at(authority, now)
        .map_err(CliError::from_core)
}

fn parse_now(
    value: Option<&str>,
    verifier_now: OffsetDateTime,
) -> Result<OffsetDateTime, CliError> {
    match value {
        Some(value) => OffsetDateTime::parse(value, &Rfc3339).map_err(|_| CliError {
            code: "INVALID_REQUEST",
        }),
        None => Ok(verifier_now),
    }
}

/// The instant at which the evidence command checks the receipt's embedded
/// authority (issuer pin validity, authority signature, `not_before` and
/// `not_after`), and where it came from.
///
/// HighAssurance receipts record `decided_at`: the engine's trusted clock at
/// evaluation, the instant it checked the authority. It is covered by the
/// context hash and the attester signature (verified before this is called),
/// and `Evidence::from_json` requires it to be canonical RFC 3339 inside the
/// agent-signed intent window. It is only as trustworthy as the attester
/// key: whoever holds that key can sign any `decided_at`.
///
/// Receipts without HighAssurance metadata (v1, and v3/v4 without it) record
/// no signed time, so the check falls back to the verifier's clock, as before.
fn authority_check_time(
    evidence: &Evidence,
    verifier_now: OffsetDateTime,
) -> Result<(OffsetDateTime, &'static str), CliError> {
    if !evidence.is_high_assurance_shape() {
        return Ok((verifier_now, "verifier_clock"));
    }
    evidence
        .decided_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .map(|decided_at| (decided_at, "receipt_decided_at"))
        .ok_or(CliError {
            code: "EVIDENCE_FAIL",
        })
}

fn format_rfc3339(value: OffsetDateTime) -> Result<String, CliError> {
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| CliError { code: "INTERNAL" })
}

fn command_name(args: &[String]) -> &'static str {
    match args.first().map(String::as_str) {
        Some("evidence") => "evidence",
        Some("journal") => "journal",
        Some("policy-digest") => "policy-digest",
        Some("authority") => "authority",
        Some("receipt") => "receipt",
        _ => "unknown",
    }
}

fn requested_format(args: &[String]) -> Option<OutputFormat> {
    args.windows(2)
        .find(|pair| pair[0] == "--format")
        .and_then(|pair| match pair[1].as_str() {
            "json" => Some(OutputFormat::Json),
            "text" => Some(OutputFormat::Text),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_parser_rejects_unknown_and_duplicate_options() {
        let unknown = vec![
            "policy-digest".into(),
            "--policy".into(),
            "policy.json".into(),
            "--trust-me".into(),
        ];
        assert_eq!(parse_command(&unknown).unwrap_err().code, "USAGE");

        let duplicate = vec![
            "policy-digest".into(),
            "--policy".into(),
            "one.json".into(),
            "--policy".into(),
            "two.json".into(),
        ];
        assert_eq!(parse_command(&duplicate).unwrap_err().code, "USAGE");
    }

    #[test]
    fn parses_text_and_json_output_modes() {
        let args = vec![
            "policy-digest".into(),
            "--policy".into(),
            "policy.json".into(),
            "--format".into(),
            "json".into(),
        ];
        assert_eq!(parse_command(&args).unwrap().1, OutputFormat::Json);
    }

    /// Verifies the first receipt of a committed Claude Code hook evidence
    /// set as `verify.sh` does, with the verifier clock fixed at `now`.
    fn verify_committed_set(set: &str, now: &str) -> Result<Summary, CliError> {
        let set = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/claude-code-hook/evidence")
            .join(set);
        let mut receipts = fs::read_dir(set.join("evidence"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        receipts.sort();
        execute(
            Command::Evidence {
                evidence: receipts[0].clone(),
                attester_pin: set.join("attester-public-key.hex"),
                issuer_pins: Some(set.join("issuer-pins.jsonl")),
                require_intent: true,
                policy: Some(set.join("policy.json")),
            },
            OffsetDateTime::parse(now, &Rfc3339).unwrap(),
        )
    }

    #[test]
    fn committed_sets_record_no_decision_time_and_use_the_verifier_clock() {
        // 03 (authority until 2036) verifies on 2027-02-01.
        let summary =
            verify_committed_set("03-bundle-demo-reproducible", "2027-02-01T00:00:00Z").unwrap();
        assert_eq!(
            summary.details["authority_checked_at"],
            "2027-02-01T00:00:00Z"
        );
        assert_eq!(
            summary.details["authority_checked_at_source"],
            "verifier_clock"
        );

        // 04 and 05 are v1 receipts without `decided_at`: no signed time to
        // check against, so they keep the verifier-clock behaviour and stop
        // verifying on 2027-01-29, when their issuer pin and authority
        // expire. The pin is checked first, hence TRUST_STORE_FAIL.
        for set in ["04-sesion-real-bloqueada-web-fetch", "05-sesion-real-final"] {
            let summary = verify_committed_set(set, "2027-01-29T00:00:00Z").unwrap();
            assert_eq!(
                summary.details["authority_checked_at_source"],
                "verifier_clock"
            );
            assert_eq!(
                verify_committed_set(set, "2027-02-01T00:00:00Z")
                    .unwrap_err()
                    .code,
                "TRUST_STORE_FAIL"
            );
        }
    }
}
