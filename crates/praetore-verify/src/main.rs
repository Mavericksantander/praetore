use praetore_core::{
    PraetoreError,
    authority::Authority,
    engine::TrustedAuthorityIssuer,
    evidence::Evidence,
    identity::{AgentIdentity, VerifiedPublicKey},
    journal_chain::{
        ChainLink, ExpectedDatabaseHead, JournalKind, MAX_CHAIN_BYTES, verify_journal_report,
        verify_journal_with_attesters,
    },
    policy::RecordedPolicy,
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
        require_decision_time: bool,
        policy: Option<PathBuf>,
    },
    Journal {
        journal: PathBuf,
        /// One or more pins (repeated `--attester-pin`): the retired and the
        /// current attester key across a rotation.
        attester_pins: Vec<PathBuf>,
        expected_head: Option<String>,
        policy: Option<PathBuf>,
        database_journal: Option<PathBuf>,
        expected_database_head: Option<String>,
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
            "Usage:\n  praetore-verify evidence --evidence PATH --attester-pin HEX_FILE [--issuer-pins JSONL] [--require-intent] [--require-decision-time] [--policy PATH] [--format json|text]\n  praetore-verify journal --journal JSONL --attester-pin HEX_FILE [--attester-pin HEX_FILE ...] [--expected-head HEX] [--policy PATH] [--database-journal JSONL | --expected-database-head HEX] [--format json|text]\n  praetore-verify policy-digest --policy PATH [--format json|text]\n  praetore-verify receipt --receipt PATH --execution-pin HEX_FILE --key-id ID --evidence-attester-pin HEX_FILE [--format json|text]\n  praetore-verify authority --authority PATH --issuer-pins JSONL [--agent PATH] [--now RFC3339] [--format json|text]\n\nThe evidence command verifies a historical receipt's integrity and attester signature; with --policy it also requires the receipt to record that policy's digest (receipts without a digest fail). A --policy document may be policy format 1 (written before G7) or format 2; it is only digested and compared, never evaluated. With --issuer-pins it checks the embedded authority (issuer pin, signature, subject binding, not-before and expiry) at the receipt's signed decision time (decided_at, HighAssurance receipts) and reports it as authority_checked_at; receipts that record no decision time are checked at the verifier's current time (authority_checked_at_source=verifier_clock); with --require-decision-time such receipts fail with DECISION_TIME_MISSING instead. This shows the authority was valid when the decision was recorded, not that it is valid now, and the decision time is only as trustworthy as the attester key that signed it: the issuer pin is also checked at decided_at, and the attester pin has no validity window. The journal command verifies a hash-linked JSONL export (see docs/proposals/journal-chain-jsonl.md) and every receipt's signature; with --expected-head it also requires the final link to equal that value. A database journal (storage records, from `praetore journal-export --database`) is verified the same way; with --database-journal (verified too) or --expected-database-head, a tenant journal must reference that database head. --attester-pin may be repeated (up to 16 keys) for a chain that spans an attester key rotation: each entry must be signed by the pinned key its key id names, so pin the retired key as well as the current one. --policy applies to receipts; with a database journal it fails with INVALID_REQUEST. It does not establish current authorization, freshness, replay state, or permission to execute an action.\n\nAttester pin files contain a lowercase 32-byte Ed25519 public-key hex value. Issuer pin files contain one compact exported pin JSON document per line."
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
            // The authority time source comes first so a reader cannot miss
            // whether the check used the receipt's signed decision time or
            // the verifier's clock.
            let source = summary.details.get("authority_checked_at_source");
            // Text is for people: values are JSON-encoded, then characters
            // that render invisibly or reorder text (zero-width, bidi,
            // control) are written as `\u{XXXX}` so an action type or tool
            // name cannot pass for another. JSON output stays exact.
            let text = |value: &serde_json::Value| {
                praetore_core::display::escape_invisible(
                    &serde_json::to_string(value).unwrap_or_else(|_| "null".into()),
                )
            };
            if let Some(source) = source {
                print!(" authority_checked_at_source={}", text(source));
            }
            for (key, value) in &summary.details {
                if source.is_some() && key == "authority_checked_at_source" {
                    continue;
                }
                print!(" {key}={}", text(value));
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
    let mut journal_pins = Vec::new();
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
        } else if flag == "--require-intent" || flag == "--require-decision-time" {
            if values.insert(flag.clone(), None).is_some() {
                return Err(CliError::usage());
            }
        } else if flag.starts_with("--") {
            index += 1;
            let value = args.get(index).ok_or_else(CliError::usage)?.clone();
            if value.starts_with("--") {
                return Err(CliError::usage());
            }
            // `journal` takes several attester pins (a chain that spans a
            // key rotation); every other flag is given at most once.
            if command_name == "journal" && flag == "--attester-pin" {
                if journal_pins.len() == MAX_ATTESTER_PINS {
                    return Err(CliError::usage());
                }
                journal_pins.push(PathBuf::from(value));
                index += 1;
                continue;
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
                        | "--require-decision-time"
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
                require_decision_time: values.contains_key("--require-decision-time"),
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
                    "--journal"
                        | "--attester-pin"
                        | "--expected-head"
                        | "--policy"
                        | "--database-journal"
                        | "--expected-database-head"
                )
            }) || (values.contains_key("--database-journal")
                && values.contains_key("--expected-database-head"))
            {
                return Err(CliError::usage());
            }
            Command::Journal {
                journal: path("--journal")?,
                attester_pins: if journal_pins.is_empty() {
                    return Err(CliError::usage());
                } else {
                    journal_pins
                },
                expected_head: match values.get("--expected-head") {
                    None => None,
                    Some(Some(value)) => Some(value.clone()),
                    Some(None) => return Err(CliError::usage()),
                },
                policy: optional_path("--policy"),
                database_journal: optional_path("--database-journal"),
                expected_database_head: match values.get("--expected-database-head") {
                    None => None,
                    Some(Some(value)) => Some(value.clone()),
                    Some(None) => return Err(CliError::usage()),
                },
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
            require_decision_time,
            policy,
        } => {
            let policy = policy.as_deref().map(read_policy).transpose()?;
            let evidence =
                Evidence::from_json(&read_limited(&evidence)?).map_err(CliError::from_core)?;
            let attester = read_attester_pin(&attester_pin)?;
            evidence
                .verify_attester_signature(&attester)
                .map_err(CliError::from_core)?;
            // What the receipt is about, exactly as signed (JSON output is
            // exact; `--format text` escapes invisible characters).
            details.insert(
                "receipt_action_type".into(),
                serde_json::Value::String(evidence.action.action_type.clone()),
            );
            if let Some(tool) = evidence
                .action
                .parameters
                .get("tool")
                .filter(|t| t.is_string())
            {
                details.insert("receipt_tool".into(), tool.clone());
            }
            details.insert(
                "receipt_decision".into(),
                serde_json::to_value(evidence.decision.outcome).unwrap_or(serde_json::Value::Null),
            );
            if let Some(decided_by) = evidence.decision.decided_by() {
                details.insert(
                    "receipt_decided_by".into(),
                    serde_json::to_value(decided_by).unwrap_or(serde_json::Value::Null),
                );
            }
            if require_decision_time && !evidence.is_high_assurance_shape() {
                return Err(CliError {
                    code: "DECISION_TIME_MISSING",
                });
            }
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
            attester_pins,
            expected_head,
            policy,
            database_journal,
            expected_database_head,
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
            let attesters = read_attester_pins(&attester_pins)?;
            let expected_database = match (&database_journal, &expected_database_head) {
                (Some(path), _) => {
                    let text = read_limited_to(path, MAX_CHAIN_BYTES)?;
                    let summary =
                        verify_journal_with_attesters(&text, &attesters, None, None, None)
                            .map_err(|error| {
                                eprintln!("database journal: {error}");
                                CliError { code: error.code() }
                            })?;
                    if summary.kind != JournalKind::Database {
                        eprintln!("database journal: not a database journal");
                        return Err(CliError {
                            code: "INVALID_REQUEST",
                        });
                    }
                    Some(ExpectedDatabaseHead {
                        head: summary.head.head,
                        entries: Some(summary.head.entries),
                    })
                }
                (None, Some(value)) => Some(ExpectedDatabaseHead {
                    head: ChainLink::from_hex(value).ok_or(CliError {
                        code: "INVALID_REQUEST",
                    })?,
                    entries: None,
                }),
                (None, None) => None,
            };
            let text = read_limited_to(&journal, MAX_CHAIN_BYTES)?;
            let report = verify_journal_report(
                &text,
                &attesters,
                policy.as_ref(),
                expected_head.as_ref(),
                expected_database.as_ref(),
            )
            .map_err(|error| {
                eprintln!("journal: {error}");
                CliError { code: error.code() }
            })?;
            let summary = report.summary;
            let chain = summary.head;
            // Which pinned key signed how many entries: with several pins,
            // entries signed by a retired key after a rotation show here.
            details.insert(
                "attester_key_ids".into(),
                serde_json::Value::Object(
                    report
                        .signed_by
                        .iter()
                        .map(|(key_id, entries)| (key_id.clone(), (*entries).into()))
                        .collect(),
                ),
            );
            let (kind, database_head) = match summary.kind {
                JournalKind::Database => ("database", None),
                JournalKind::Tenant { database_head } => ("tenant", database_head),
            };
            details.insert("kind".into(), serde_json::Value::String(kind.into()));
            details.insert(
                "database_head".into(),
                database_head.map_or(serde_json::Value::Null, |reference| {
                    serde_json::json!({
                        "entries": reference.entries.get(),
                        "head": reference.head.to_hex(),
                    })
                }),
            );
            details.insert(
                "database_head_verified".into(),
                serde_json::Value::Bool(expected_database.is_some()),
            );
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
            let policy = read_policy(&policy)?;
            details.insert(
                "policy_id".into(),
                serde_json::Value::String(policy.id().to_owned()),
            );
            details.insert(
                "policy_version".into(),
                serde_json::Value::Number(policy.version().into()),
            );
            details.insert(
                "policy_format_version".into(),
                serde_json::Value::Number(policy.format_version().into()),
            );
            details.insert(
                "digest".into(),
                serde_json::Value::String(policy.digest().to_owned()),
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

/// Reads a policy document as historical evidence recorded it: format 1
/// (before G7) or format 2. The verifier only digests it and compares the
/// digest with the one a receipt recorded; it never evaluates it.
fn read_policy(path: &Path) -> Result<RecordedPolicy, CliError> {
    RecordedPolicy::from_json(&read_limited(path)?).map_err(CliError::from_core)
}

fn verify_receipt_policy(evidence: &Evidence, policy: &RecordedPolicy) -> Result<(), CliError> {
    evidence
        .verify_recorded_policy(policy)
        .map_err(|_| CliError {
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

/// Most attester pins one `journal` run accepts.
const MAX_ATTESTER_PINS: usize = 16;

/// Reads every pin; the same key given twice is a trust-store error.
fn read_attester_pins(paths: &[PathBuf]) -> Result<Vec<VerifiedPublicKey>, CliError> {
    let mut keys: Vec<VerifiedPublicKey> = Vec::with_capacity(paths.len());
    for path in paths {
        let key = read_attester_pin(path)?;
        if keys.contains(&key) {
            eprintln!("attester pin {} repeats a key", path.display());
            return Err(CliError {
                code: "TRUST_STORE_FAIL",
            });
        }
        keys.push(key);
    }
    Ok(keys)
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
/// no signed time, so the check falls back to the verifier's clock, as before,
/// unless `--require-decision-time` rejected them earlier with
/// `DECISION_TIME_MISSING`.
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
        verify_committed_set_with(set, now, false)
    }

    fn verify_committed_set_with(
        set: &str,
        now: &str,
        require_decision_time: bool,
    ) -> Result<Summary, CliError> {
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
                require_decision_time,
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

    #[test]
    fn require_decision_time_rejects_committed_sets_without_decided_at() {
        // 03 holds v4 receipts without HighAssurance metadata, 04 and 05 v1
        // receipts. None records a signed decision time.
        for set in [
            "03-bundle-demo-reproducible",
            "04-sesion-real-bloqueada-web-fetch",
            "05-sesion-real-final",
        ] {
            assert_eq!(
                verify_committed_set_with(set, "2026-11-01T00:00:00Z", true)
                    .unwrap_err()
                    .code,
                "DECISION_TIME_MISSING"
            );
            // Without the flag the result is unchanged.
            assert!(verify_committed_set_with(set, "2026-11-01T00:00:00Z", false).is_ok());
        }
    }

    #[test]
    fn require_decision_time_is_only_accepted_by_the_evidence_command() {
        let journal = vec![
            "journal".into(),
            "--journal".into(),
            "chain.jsonl".into(),
            "--attester-pin".into(),
            "pin.hex".into(),
            "--require-decision-time".into(),
        ];
        assert_eq!(parse_command(&journal).unwrap_err().code, "USAGE");
    }
}
