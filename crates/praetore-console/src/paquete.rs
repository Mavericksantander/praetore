//! D3: the compliance package. A `.tar.gz` built on this computer that a
//! third party can check with `praetore-verify` without trusting the
//! console: the tenant's signed journal (the same export as `praetore
//! journal-export --tenant`, from the shared code in
//! `praetore_replay_postgres::journal_export`), the configured policy and its
//! digest (`RecordedPolicy`, as the engine and `praetore-verify
//! policy-digest` compute it), the attester pins, `SHA256SUMS` and a plain
//! `LEEME.txt`. Since D3.1 it also carries the tenant's approval, rejection,
//! expiration and execution receipts (`approvals.jsonl`, read in the same
//! snapshot as the journal) and the execution and approver pins that verify
//! them; every record is verified with `praetore_receipt::outcomes`, the
//! code `praetore-verify outcomes` runs, before anything is archived.
//!
//! Every piece is read and checked before anything is archived; a missing or
//! unreadable piece means no package at all. Only public keys are written:
//! pins are parsed and re-encoded, a pin that is the approver's key is
//! refused, and so is a pin that verified no entry of the export (a secret
//! key's bytes can decode as a public key, but cannot verify its own
//! signatures).

use crate::ApproverSigner;
use praetore_core::{
    VerifiedPublicKey, journal_chain::verify_journal_receipts, policy::RecordedPolicy,
};
use praetore_receipt::outcomes::{
    KeyPin, MAX_OUTCOME_PINS, Outcome, OutcomeError, OutcomeKeys, OutcomeReport, verify_outcomes,
    write_outcomes,
};
use praetore_replay_postgres::journal_export::{TenantExport, parse_attester_pin};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

/// Folder every file of the package sits in.
pub const PACK_DIR: &str = "praetore-compliance";
/// Name the browser saves the package under.
pub const PACK_FILENAME: &str = "praetore-compliance.tar.gz";

pub const README_FILE: &str = "LEEME.txt";
pub const JOURNAL_FILE: &str = "journal.jsonl";
pub const POLICY_FILE: &str = "policy.json";
pub const POLICY_DIGEST_FILE: &str = "policy-digest.txt";
pub const EXPORT_FILE: &str = "export.json";
pub const SUMS_FILE: &str = "SHA256SUMS";
/// D3.1: the approval, rejection, expiration and execution receipts.
pub const OUTCOMES_FILE: &str = "approvals.jsonl";

/// Most attester pins, as `praetore journal-export`.
pub const MAX_ATTESTER_PINS: usize = 16;
const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_PIN_BYTES: u64 = 4096;

/// `attester-pin-1.hex`, `attester-pin-2.hex`, ... in configuration order.
pub fn pin_file_name(index: usize) -> String {
    format!("attester-pin-{}.hex", index + 1)
}

/// `execution-pin-1.json`, ... or `approver-pin-1.json`, ... in
/// configuration order.
pub fn key_pin_file_name(role: PinRole, index: usize) -> String {
    match role {
        PinRole::Execution => format!("execution-pin-{}.json", index + 1),
        PinRole::Approver => format!("approver-pin-{}.json", index + 1),
    }
}

/// The two kinds of key pin `approvals.jsonl` is verified with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRole {
    /// Gateway execution keys: execution and expiration receipts.
    Execution,
    /// Human approver keys: approve and reject decisions.
    Approver,
}

impl PinRole {
    pub fn variable(self) -> &'static str {
        match self {
            Self::Execution => "PRAETORE_CONSOLE_EXECUTION_PIN_FILES",
            Self::Approver => "PRAETORE_CONSOLE_APPROVER_PIN_FILES",
        }
    }

    fn log_name(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Approver => "approver",
        }
    }
}

/// Where the policy and the pins are read from, at each download.
#[derive(Debug, Clone)]
pub struct PackSettings {
    policy_file: PathBuf,
    attester_pin_files: Vec<PathBuf>,
    execution_pin_files: Vec<PathBuf>,
    approver_pin_files: Vec<PathBuf>,
}

#[derive(Debug)]
pub enum PackConfigError {
    NoPins,
    TooManyPins,
}

impl std::fmt::Display for PackConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPins => f.write_str("el paquete de compliance necesita al menos un pin"),
            Self::TooManyPins => write!(
                f,
                "el paquete de compliance acepta a lo más {MAX_ATTESTER_PINS} pins de cada tipo"
            ),
        }
    }
}

impl std::error::Error for PackConfigError {}

impl PackSettings {
    pub fn new(
        policy_file: PathBuf,
        attester_pin_files: Vec<PathBuf>,
    ) -> Result<Self, PackConfigError> {
        if attester_pin_files.is_empty() {
            return Err(PackConfigError::NoPins);
        }
        if attester_pin_files.len() > MAX_ATTESTER_PINS {
            return Err(PackConfigError::TooManyPins);
        }
        Ok(Self {
            policy_file,
            attester_pin_files,
            execution_pin_files: Vec::new(),
            approver_pin_files: Vec::new(),
        })
    }

    /// D3.1: the execution and approver pins (0 to 16 of each) that verify
    /// `approvals.jsonl`. With at least one of them the package carries
    /// `approvals.jsonl`, all or nothing; with none it is the D3 package.
    pub fn with_outcome_pins(
        mut self,
        execution_pin_files: Vec<PathBuf>,
        approver_pin_files: Vec<PathBuf>,
    ) -> Result<Self, PackConfigError> {
        if execution_pin_files.len() > MAX_OUTCOME_PINS
            || approver_pin_files.len() > MAX_OUTCOME_PINS
        {
            return Err(PackConfigError::TooManyPins);
        }
        self.execution_pin_files = execution_pin_files;
        self.approver_pin_files = approver_pin_files;
        Ok(self)
    }

    /// Whether the package carries `approvals.jsonl`: at least one
    /// execution or approver pin is configured.
    pub fn includes_outcomes(&self) -> bool {
        !self.execution_pin_files.is_empty() || !self.approver_pin_files.is_empty()
    }

    fn key_pin_files(&self, role: PinRole) -> &[PathBuf] {
        match role {
            PinRole::Execution => &self.execution_pin_files,
            PinRole::Approver => &self.approver_pin_files,
        }
    }
}

/// The tenant's chain and its approval and execution records, exported in
/// one read-only snapshot.
pub trait JournalExportStore: Send + Sync + 'static {
    fn tenant_id(&self) -> Uuid;
    /// `Err` carries the detail for the console's log, never for the page.
    fn export_tenant(
        &self,
        attesters: &[VerifiedPublicKey],
    ) -> Result<(TenantExport, Vec<Outcome>), String>;
}

pub struct CompliancePack {
    settings: PackSettings,
    store: Arc<dyn JournalExportStore>,
}

impl CompliancePack {
    pub fn new(settings: PackSettings, store: Arc<dyn JournalExportStore>) -> Self {
        Self { settings, store }
    }
}

/// Why no package was produced. Each has a plain message for the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackError {
    Policy,
    Pins,
    PinIsApproverKey,
    /// A configured pin verified no receipt and no storage record: it is
    /// not needed, and it may be the wrong file (a secret, say). `index` is
    /// the first such pin in configuration order; `more` when others too.
    PinUnused {
        index: usize,
        more: bool,
    },
    /// Another download is still being built.
    Busy,
    Journal,
    Archive,
    /// D3.1: an execution or approver pin file could not be read, is not a
    /// pin, or repeats a key or key id.
    KeyPins {
        role: PinRole,
    },
    /// An execution pin is the approver's key, or an approver pin is the
    /// approver's secret.
    KeyPinIsApproverKey {
        role: PinRole,
    },
    /// A record names a key id no configured pin has.
    OutcomeKeyMissing,
    /// A record does not verify, is not bound to its journal request, or
    /// contradicts another record of the same request.
    Outcomes,
    OutcomesTooLarge,
}

impl PackError {
    pub fn message(self) -> std::borrow::Cow<'static, str> {
        match self {
            Self::PinUnused { index, more } => format!(
                "La {} clave configurada como clave pública del atestador (en el orden de PRAETORE_CONSOLE_ATTESTER_PIN_FILES) no verifica ningún registro: sobra o es un archivo equivocado.{} No se generó ningún paquete.",
                ordinal(index),
                if more { " Puede haber más claves en la misma situación." } else { "" }
            )
            .into(),
            Self::KeyPins { role } => format!(
                "No se pudieron leer las claves configuradas en {}: cada archivo debe ser un pin JSON con key_id y public_key_hex, sin repetir clave ni key_id. No se generó ningún paquete.",
                role.variable()
            )
            .into(),
            Self::KeyPinIsApproverKey { role: PinRole::Execution } => {
                "Una de las claves configuradas como clave pública de ejecución del gateway es la clave del aprobador. No se generó ningún paquete.".into()
            }
            Self::KeyPinIsApproverKey { role: PinRole::Approver } => {
                "Una de las claves configuradas como clave pública de aprobador es la clave privada del aprobador de esta consola. No se generó ningún paquete.".into()
            }
            other => other.fixed_message().into(),
        }
    }

    fn fixed_message(self) -> &'static str {
        match self {
            Self::Policy => {
                "No se pudo leer la política configurada en la consola. No se generó ningún paquete."
            }
            Self::Pins => {
                "No se pudieron leer las claves públicas del atestador configuradas en la consola. No se generó ningún paquete."
            }
            Self::PinIsApproverKey => {
                "Una de las claves configuradas como clave pública del atestador es la clave del aprobador. No se generó ningún paquete."
            }
            Self::PinUnused { .. } | Self::KeyPins { .. } | Self::KeyPinIsApproverKey { .. } => {
                unreachable!("message() words it")
            }
            Self::OutcomeKeyMissing => {
                "Un recibo de aprobación o de ejecución está firmado con una clave que no está configurada: agrégala en PRAETORE_CONSOLE_EXECUTION_PIN_FILES o PRAETORE_CONSOLE_APPROVER_PIN_FILES. No se generó ningún paquete."
            }
            Self::Outcomes => {
                "Un recibo de aprobación, rechazo, vencimiento o ejecución no verifica con las claves configuradas, no corresponde a su solicitud del registro o contradice otro recibo de la misma solicitud. No se generó ningún paquete."
            }
            Self::OutcomesTooLarge => {
                "Los recibos de aprobación y de ejecución son demasiado grandes para un paquete. No se generó ningún paquete."
            }
            Self::Busy => "Ya se está armando un paquete. Espera a que termine.",
            Self::Journal => {
                "No se pudo exportar el registro firmado: la base no respondió, no hay registros, el registro es demasiado grande para una exportación, o alguna firma no corresponde a las claves del atestador configuradas. No se generó ningún paquete."
            }
            Self::Archive => "No se pudo armar el paquete. No se generó ningún paquete.",
        }
    }

    fn log_name(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Pins => "attester_pins",
            Self::PinIsApproverKey => "attester_pin_is_approver_key",
            Self::PinUnused { .. } => "attester_pin_unused",
            Self::Busy => "busy",
            Self::Journal => "journal_export",
            Self::Archive => "archive",
            Self::KeyPins { .. } => "key_pins",
            Self::KeyPinIsApproverKey { .. } => "key_pin_is_approver_key",
            Self::OutcomeKeyMissing => "outcome_key_missing",
            Self::Outcomes => "outcomes",
            Self::OutcomesTooLarge => "outcomes_too_large",
        }
    }
}

/// Everything that goes into the package, already read and checked.
pub struct PackContents {
    pub tenant_id: Uuid,
    pub generated_at: OffsetDateTime,
    pub export: TenantExport,
    /// The policy file exactly as read.
    pub policy_json: String,
    pub policy: RecordedPolicy,
    pub pins: Vec<VerifiedPublicKey>,
    /// D3.1: `None` when no execution or approver pin is configured; the
    /// package is then the D3 one, without `approvals.jsonl`.
    pub outcomes: Option<PackOutcomes>,
}

/// D3.1: `approvals.jsonl`, verified, and the pins that verified it.
#[derive(Debug, Clone, Default)]
pub struct PackOutcomes {
    pub text: String,
    pub report: OutcomeReport,
    /// Only the configured pins that verified at least one record.
    pub execution_pins: Vec<KeyPin>,
    pub approver_pins: Vec<KeyPin>,
    /// Configured pins that verified no record: left out of the package.
    pub omitted_execution_pins: usize,
    pub omitted_approver_pins: usize,
}

pub struct PackFile {
    /// Path inside the archive, under [`PACK_DIR`].
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Reads every piece, then archives. Nothing is archived unless every piece
/// was read and checked.
pub fn generate(
    pack: &CompliancePack,
    approver: Option<&ApproverSigner>,
    now: OffsetDateTime,
) -> Result<Vec<u8>, PackError> {
    let result =
        collect(pack, approver, now).and_then(|contents| archive(&pack_files(&contents)?, now));
    if let Err(error) = &result {
        tracing::warn!(
            failure = error.log_name(),
            "compliance package not generated"
        );
    }
    result
}

fn collect(
    pack: &CompliancePack,
    approver: Option<&ApproverSigner>,
    now: OffsetDateTime,
) -> Result<PackContents, PackError> {
    let policy_json = read_limited(&pack.settings.policy_file, MAX_POLICY_BYTES)
        .map_err(|()| PackError::Policy)?;
    let policy = RecordedPolicy::from_json(&policy_json).map_err(|_| PackError::Policy)?;
    let mut pins: Vec<VerifiedPublicKey> =
        Vec::with_capacity(pack.settings.attester_pin_files.len());
    for path in &pack.settings.attester_pin_files {
        let text = read_limited(path, MAX_PIN_BYTES).map_err(|()| PackError::Pins)?;
        let pin = parse_attester_pin(&text).map_err(|_| PackError::Pins)?;
        if approver.is_some_and(|signer| signer.is_key_material(&pin.as_bytes())) {
            return Err(PackError::PinIsApproverKey);
        }
        if pins.contains(&pin) {
            return Err(PackError::Pins);
        }
        pins.push(pin);
    }
    let execution_pins = read_key_pins(pack, PinRole::Execution, approver)?;
    let approver_pins = read_key_pins(pack, PinRole::Approver, approver)?;
    let (export, records) = pack.store.export_tenant(&pins).map_err(|detail| {
        tracing::warn!(%detail, "compliance package: journal export failed");
        PackError::Journal
    })?;
    // Every pin must have verified an entry: only then is it known to be the
    // public key of a signer, and not some other 32-byte value.
    if let Some(&index) = export.unused_attesters.first() {
        let path = &pack.settings.attester_pin_files[index];
        tracing::warn!(
            position = index + 1,
            path = %path.display(),
            unused = export.unused_attesters.len(),
            "compliance package: attester pin verified no entry"
        );
        return Err(PackError::PinUnused {
            index,
            more: export.unused_attesters.len() > 1,
        });
    }
    let outcomes = if pack.settings.includes_outcomes() {
        Some(collect_outcomes(
            pack,
            &export,
            &records,
            &pins,
            execution_pins,
            approver_pins,
        )?)
    } else {
        None
    };
    Ok(PackContents {
        tenant_id: pack.store.tenant_id(),
        generated_at: now,
        export,
        policy_json,
        policy,
        pins,
        outcomes,
    })
}

/// D3.1: every record is checked against the receipts of the chain just
/// exported, with the code `praetore-verify outcomes` runs. A pin that
/// verified no record is left out of the package and logged.
fn collect_outcomes(
    pack: &CompliancePack,
    export: &TenantExport,
    records: &[Outcome],
    pins: &[VerifiedPublicKey],
    execution_pins: Vec<KeyPin>,
    approver_pins: Vec<KeyPin>,
) -> Result<PackOutcomes, PackError> {
    let (_, receipts) = verify_journal_receipts(&export.text, pins, None).map_err(|error| {
        tracing::warn!(%error, "compliance package: exported journal does not verify");
        PackError::Journal
    })?;
    let text = write_outcomes(records).map_err(|_| PackError::OutcomesTooLarge)?;
    let report = verify_outcomes(
        &text,
        &receipts,
        &OutcomeKeys {
            evidence_attesters: pins,
            execution: &execution_pins,
            approvers: &approver_pins,
        },
    )
    .map_err(|error| {
        tracing::warn!(
            code = error.code(),
            %error,
            "compliance package: approval or execution record does not verify"
        );
        match error {
            OutcomeError::UnknownKey { .. } => PackError::OutcomeKeyMissing,
            OutcomeError::TooLarge => PackError::OutcomesTooLarge,
            _ => PackError::Outcomes,
        }
    })?;
    let keep = |role: PinRole, configured: Vec<KeyPin>, unused: &[usize]| -> Vec<KeyPin> {
        for &index in unused {
            tracing::warn!(
                role = role.log_name(),
                position = index + 1,
                path = %pack.settings.key_pin_files(role)[index].display(),
                "compliance package: key pin verified no record; left out of the package"
            );
        }
        configured
            .into_iter()
            .enumerate()
            .filter(|(index, _)| !unused.contains(index))
            .map(|(_, pin)| pin)
            .collect()
    };
    let omitted_execution_pins = report.unused_execution_pins.len();
    let omitted_approver_pins = report.unused_approver_pins.len();
    let execution_pins = keep(
        PinRole::Execution,
        execution_pins,
        &report.unused_execution_pins,
    );
    let approver_pins = keep(
        PinRole::Approver,
        approver_pins,
        &report.unused_approver_pins,
    );
    Ok(PackOutcomes {
        text,
        report,
        execution_pins,
        approver_pins,
        omitted_execution_pins,
        omitted_approver_pins,
    })
}

/// Execution or approver pins, parsed. Only public keys pass: an execution
/// pin that is the approver's key, or an approver pin that is its secret, is
/// refused; any other wrong 32 bytes verify no record and are left out.
fn read_key_pins(
    pack: &CompliancePack,
    role: PinRole,
    approver: Option<&ApproverSigner>,
) -> Result<Vec<KeyPin>, PackError> {
    let mut pins: Vec<KeyPin> = Vec::new();
    for path in pack.settings.key_pin_files(role) {
        let text = read_limited(path, MAX_PIN_BYTES).map_err(|()| PackError::KeyPins { role })?;
        let pin = KeyPin::from_json(&text).map_err(|_| PackError::KeyPins { role })?;
        let bytes = pin.public_key.as_bytes();
        let is_approver_key = approver.is_some_and(|signer| match role {
            PinRole::Execution => signer.is_key_material(&bytes),
            PinRole::Approver => signer.is_secret(&bytes),
        });
        if is_approver_key {
            return Err(PackError::KeyPinIsApproverKey { role });
        }
        if pins
            .iter()
            .any(|other| other.key_id == pin.key_id || other.public_key == pin.public_key)
        {
            return Err(PackError::KeyPins { role });
        }
        pins.push(pin);
    }
    Ok(pins)
}

fn read_limited(path: &Path, max: u64) -> Result<String, ()> {
    let file = fs::File::open(path).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > max {
        return Err(());
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.len() as u64 > max {
        return Err(());
    }
    String::from_utf8(bytes).map_err(|_| ())
}

/// `export.json`'s note when the package has no `approvals.jsonl`.
pub const NOT_CONFIGURED_NOTE: &str = "Esta consola no está configurada para incluir los recibos de aprobación y de ejecución: PRAETORE_CONSOLE_EXECUTION_PIN_FILES y PRAETORE_CONSOLE_APPROVER_PIN_FILES no están configuradas. El paquete no trae approvals.jsonl.";

/// The package files in archive order, `SHA256SUMS` last; it covers every
/// other file.
pub fn pack_files(contents: &PackContents) -> Result<Vec<PackFile>, PackError> {
    let generated_at = contents
        .generated_at
        .replace_nanosecond(0)
        .map_err(|_| PackError::Archive)?
        .format(&Rfc3339)
        .map_err(|_| PackError::Archive)?;
    let pin_names: Vec<String> = (0..contents.pins.len()).map(pin_file_name).collect();
    let mut files = vec![
        file(
            README_FILE,
            readme(contents, &generated_at, &pin_names).into_bytes(),
        ),
        file(JOURNAL_FILE, contents.export.text.clone().into_bytes()),
    ];
    if let Some(outcomes) = &contents.outcomes {
        files.push(file(OUTCOMES_FILE, outcomes.text.clone().into_bytes()));
    }
    files.extend([
        file(POLICY_FILE, contents.policy_json.clone().into_bytes()),
        file(
            POLICY_DIGEST_FILE,
            format!("{}\n", contents.policy.digest()).into_bytes(),
        ),
    ]);
    for (name, pin) in pin_names.iter().zip(&contents.pins) {
        files.push(file(
            name,
            format!("{}\n", hex::encode(pin.as_bytes())).into_bytes(),
        ));
    }
    let key_pin_names = |role: PinRole, pins: &[KeyPin]| -> Vec<String> {
        (0..pins.len())
            .map(|index| key_pin_file_name(role, index))
            .collect()
    };
    let (execution_pins, approver_pins) = contents
        .outcomes
        .as_ref()
        .map_or((&[][..], &[][..]), |outcomes| {
            (&outcomes.execution_pins[..], &outcomes.approver_pins[..])
        });
    let execution_names = key_pin_names(PinRole::Execution, execution_pins);
    let approver_names = key_pin_names(PinRole::Approver, approver_pins);
    for (name, pin) in execution_names
        .iter()
        .zip(execution_pins)
        .chain(approver_names.iter().zip(approver_pins))
    {
        files.push(file(name, pin.to_json().into_bytes()));
    }
    let outcomes_json = match &contents.outcomes {
        None => serde_json::json!({
            "included": false,
            "note": NOT_CONFIGURED_NOTE,
        }),
        Some(outcomes) => {
            let report = &outcomes.report;
            serde_json::json!({
                "included": true,
                "file": OUTCOMES_FILE,
                "records": report.counts.approvals
                    + report.counts.rejections
                    + report.counts.expirations
                    + report.counts.execution_receipts,
                "approvals": report.counts.approvals,
                "rejections": report.counts.rejections,
                "expirations": report.counts.expirations,
                "execution_receipts": report.counts.execution_receipts,
                "execution_receipts_by_state": report.counts.by_execution,
                "held_requests": report.held.len(),
                "held_by_outcome": held_by_outcome(report),
                "omitted_execution_pins": outcomes.omitted_execution_pins,
                "omitted_approver_pins": outcomes.omitted_approver_pins,
            })
        }
    };
    let export = serde_json::json!({
        "format": "praetore-compliance-pack",
        "format_version": 1,
        "tenant_id": contents.tenant_id.to_string(),
        "generated_at": generated_at,
        "generator": format!("praetore-console {}", env!("CARGO_PKG_VERSION")),
        "journal": {
            "file": JOURNAL_FILE,
            "source": format!("praetore journal-export --tenant {}", contents.tenant_id),
            "entries": contents.export.head.entries.get(),
            "decision_receipts": decision_receipts(&contents.export),
            "head": contents.export.head.head.to_hex(),
            "database_head": contents.export.database_head.map(|reference| serde_json::json!({
                "entries": reference.entries.get(),
                "head": reference.head.to_hex(),
            })),
        },
        "policy": {
            "file": POLICY_FILE,
            "id": contents.policy.id(),
            "version": contents.policy.version(),
            "format_version": contents.policy.format_version(),
            "digest": contents.policy.digest(),
        },
        "attester_pins": pin_names,
        "outcomes": outcomes_json,
        "execution_pins": execution_names,
        "approver_pins": approver_names,
    });
    let mut export = serde_json::to_string_pretty(&export).map_err(|_| PackError::Archive)?;
    export.push('\n');
    files.push(file(EXPORT_FILE, export.into_bytes()));
    let mut sums = String::new();
    for entry in &files {
        let name = entry
            .name
            .strip_prefix(&format!("{PACK_DIR}/"))
            .ok_or(PackError::Archive)?;
        sums.push_str(&format!(
            "{}  {name}\n",
            hex::encode(Sha256::digest(&entry.bytes))
        ));
    }
    files.push(file(SUMS_FILE, sums.into_bytes()));
    Ok(files)
}

fn file(name: &str, bytes: Vec<u8>) -> PackFile {
    PackFile {
        name: format!("{PACK_DIR}/{name}"),
        bytes,
    }
}

/// A gzip-compressed ustar archive: the folder, then each file, mode 0644,
/// owner 0:0, modification time `mtime`.
pub fn archive(files: &[PackFile], mtime: OffsetDateTime) -> Result<Vec<u8>, PackError> {
    let mtime = u64::try_from(mtime.unix_timestamp()).map_err(|_| PackError::Archive)?;
    let gzip = flate2::GzBuilder::new().write(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gzip);
    builder.mode(tar::HeaderMode::Deterministic);
    let mut folder = tar::Header::new_ustar();
    folder.set_entry_type(tar::EntryType::Directory);
    folder.set_mode(0o755);
    folder.set_size(0);
    folder.set_uid(0);
    folder.set_gid(0);
    folder.set_mtime(mtime);
    folder.set_cksum();
    builder
        .append_data(&mut folder, format!("{PACK_DIR}/"), std::io::empty())
        .map_err(|_| PackError::Archive)?;
    for entry in files {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(entry.bytes.len() as u64);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(mtime);
        header.set_cksum();
        builder
            .append_data(&mut header, &entry.name, entry.bytes.as_slice())
            .map_err(|_| PackError::Archive)?;
    }
    let mut gzip = builder.into_inner().map_err(|_| PackError::Archive)?;
    gzip.flush().map_err(|_| PackError::Archive)?;
    gzip.finish().map_err(|_| PackError::Archive)
}

fn readme(contents: &PackContents, generated_at: &str, pin_names: &[String]) -> String {
    let tenant = contents.tenant_id;
    let receipts = decision_receipts(&contents.export);
    let head = contents.export.head.head.to_hex();
    let digest = contents.policy.digest();
    let pins = pin_names
        .iter()
        .map(|name| format!("--attester-pin {name}"))
        .collect::<Vec<_>>()
        .join(" ");
    let repository = env!("CARGO_PKG_REPOSITORY");
    let version = env!("CARGO_PKG_VERSION");
    let counted = if receipts == 1 {
        "1 recibo de decisión".to_owned()
    } else {
        format!("{receipts} recibos de decisión")
    };
    let lines = match &contents.export.database_head {
        Some(reference) => format!(
            "Tiene {counted}. La primera línea no es un recibo: es la\n    \
             referencia (database_head) a la cadena de la base de datos, que dice\n    \
             cuántos registros tenía esa cadena, de toda la base: {}.\n    \
             Después, cada línea encadena con la anterior un recibo de decisión",
            reference.entries
        ),
        None => {
            format!("Tiene {counted}. Cada línea encadena con la anterior un recibo de decisión")
        }
    };
    let database = match &contents.export.database_head {
        Some(reference) => format!(
            "La primera línea de journal.jsonl referencia el head de la cadena de la base\n\
             de datos (los registros de almacenamiento de toda la base, {} en el momento\n\
             de la exportación). Esa cadena no va en el paquete, así que esa referencia\n\
             no se puede comprobar con él.",
            reference.entries
        ),
        None => "Esta exportación no referencia la cadena de la base de datos: la base no\n\
                 tenía registros de almacenamiento."
            .to_owned(),
    };
    let outcomes = outcomes_readme(contents, pin_names);
    let database_complete = if contents.export.database_head.is_some() {
        "\n\nComo journal.jsonl referencia la cadena de la base, pida aparte el head\n\
         de esa cadena por el mismo tipo de canal y páselo con\n\
         --expected-database-head."
    } else {
        ""
    };
    format!(
        "\
PAQUETE DE COMPLIANCE DE PRÆTORE
================================

Generado por la consola local de PRÆTORE (praetore-console {version})
el {generated_at} (UTC), para el tenant {tenant}.


QUÉ CONTIENE
------------

journal.jsonl
    El registro firmado de este tenant: la salida de
        praetore journal-export --tenant {tenant}
    para el estado de la base en el momento de la exportación, producida por
    el mismo código. {lines}
    firmado por el atestador: lo que la política resolvió para cada
    solicitud (permitir, denegar o retener para aprobación). No trae la
    aprobación o el rechazo de una persona ni el resultado de la ejecución:
    {journal_tail}

policy.json
    El archivo de política configurado en la consola, copiado tal cual.

policy-digest.txt
    El digest de esa política (SHA-256 de su JSON canónico), calculado como
    lo calculan el motor y `praetore-verify policy-digest`:
        {digest}

{pin_list}
    Las claves públicas Ed25519 del atestador configuradas en la consola.
    Cada una verificó al menos un recibo de journal.jsonl o un registro de
    la cadena de la base, que no va en el paquete.
{outcomes_contents}
export.json
    Los datos de la exportación: tenant, hora, cantidad de líneas, head
    {export_tail}

SHA256SUMS
    El SHA-256 de cada uno de los archivos anteriores.

El paquete no contiene claves privadas.


CÓMO VERIFICARLO
----------------

No hace falta confiar en la consola que lo generó.

1. Los archivos. Dentro de esta carpeta:
       sha256sum -c SHA256SUMS
   o, en macOS:
       shasum -a 256 -c SHA256SUMS
   Esto detecta un archivo dañado o cambiado sin recalcular SHA256SUMS. No es
   una firma: quien cambie un archivo puede recalcular SHA256SUMS.

2. Construya praetore-verify desde main, en un commit que incluya este
   {step2_since}
       git clone {repository}
       cd praetore
       cargo build --release --locked -p praetore-verify
   El programa queda en target/release/praetore-verify.
   Use praetore-verify construido desde main. El praetore-verify de v0.3.3
   también acepta este journal.jsonl, pero no muestra tenant_id ni avisa
   {step2_old}

3. El registro y sus firmas:
       praetore-verify journal --journal journal.jsonl {pins}
   Comprueba cada enlace de la cadena, la firma de cada recibo con esas
   claves y que todos los recibos nombran el mismo tenant. Ese tenant sale
   como tenant_id en la salida: compárelo usted con el de este archivo y el
   de export.json ({tenant}); el comando no los compara.
   Sin --expected-head el comando avisa head_not_anchored: un subconjunto
   de los recibos, truncado, reordenado o reencadenado, también verifica.
   El head de esta exportación es
       {head}
   (también en export.json), pero viene del mismo operador que el paquete.
   Vea \"¿Está completo?\".

4. La política:
       praetore-verify policy-digest --policy policy.json
   debe dar el digest de policy-digest.txt. Y
       praetore-verify journal --journal journal.jsonl {pins} --policy policy.json
   exige además que cada recibo registre el digest de esta política. Si una
   parte del registro se decidió con otra política (por ejemplo, antes de un
   cambio de política), este comando falla aunque el registro esté íntegro.
{outcomes_step}

¿ESTÁ COMPLETO?
---------------

Sin más, este paquete prueba integridad y firmas, no completitud. Para saber
que no faltan ni se reordenaron recibos, compare el head con uno obtenido
fuera del control del operador y páselo con --expected-head: un head que
usted anotó antes, uno publicado, o el de una exportación que usted mismo
corra con acceso de solo lectura.{database_complete}


LAS CLAVES
----------

Los archivos de pin vienen de la configuración de la consola: los eligió el
operador. Con solo esos archivos, la verificación muestra que el registro es
coherente con esas claves, no que lo firmó el atestador que usted espera.
Obtenga las claves públicas del atestador por otro canal y compárelas con
estos archivos.{keys_tail}


LO QUE ESTE PAQUETE NO PRUEBA
-----------------------------

- No prueba que el agente no tuvo un camino fuera del gateway. Una acción
  que no pasó por el gateway no aparece en este registro.
- No prueba nada de lo ocurrido antes del primer registro ni después de la
  exportación ({generated_at}).
- No prueba que el registro esté completo: sin un head anclado fuera del
  control del operador, un subconjunto de los recibos (truncado,
  reordenado o reencadenado) también verifica.
{not_proven}- No prueba que una acción permitida o aprobada tuvo efecto fuera del
  gateway: los recibos muestran lo que el gateway decidió y registró.
- No prueba que el gateway usó policy.json: es el archivo configurado en la
  consola. Cada recibo registra el digest de la política con que se decidió;
  el paso 4 los compara.
- No prueba que una autorización siga vigente, ni autoriza nada.
- {database}
",
        pin_list = pin_names.join("\n"),
        database = database.replace('\n', "\n  "),
        journal_tail = outcomes.journal_tail,
        outcomes_contents = outcomes.contents,
        export_tail = outcomes.export_tail,
        step2_since = outcomes.step2_since,
        step2_old = outcomes.step2_old,
        outcomes_step = outcomes.step,
        keys_tail = outcomes.keys_tail,
        not_proven = outcomes.not_proven,
    )
}

/// The parts of `LEEME.txt` that depend on whether the package carries
/// `approvals.jsonl`.
struct OutcomesReadme {
    journal_tail: &'static str,
    /// Description of `approvals.jsonl` and its pins, framed by line
    /// breaks, or nothing.
    contents: String,
    export_tail: &'static str,
    step2_since: &'static str,
    step2_old: &'static str,
    /// Step 5 framed by line breaks, or nothing.
    step: String,
    keys_tail: &'static str,
    not_proven: &'static str,
}

/// The `LEEME.txt` of a package without `approvals.jsonl`: the D3 text,
/// saying the console is not configured to include those receipts.
fn without_outcomes_readme() -> OutcomesReadme {
    OutcomesReadme {
        journal_tail: "esta consola no está configurada para incluir esos recibos en el\n    \
                       paquete.",
        contents: String::new(),
        export_tail: "de la cadena y digest de la política.",
        step2_since: "paquete de compliance (P-002 D3), o desde un release posterior a v0.3.3:",
        step2_old: "head_not_anchored, que el paso 3 usa. Además, v0.3.3 rechaza con\n   \
                    RECEIPT_INVALID los recibos de ejecución schema v5 (awaiting_approval) y\n   \
                    las razones approved_claim_expired y approval_rejected; esos recibos no\n   \
                    van en este paquete.",
        step: String::new(),
        keys_tail: "",
        not_proven: "\
- No muestra si una solicitud retenida fue aprobada, rechazada, venció o
  se ejecutó: journal.jsonl trae solo la decisión de la política. Esta
  consola no está configurada para incluir los recibos de aprobación y de
  ejecución en el paquete.
",
    }
}

/// The `approvals.jsonl` parts of `LEEME.txt`: what the file holds and how
/// to verify it (step 5).
fn outcomes_readme(contents: &PackContents, attester_names: &[String]) -> OutcomesReadme {
    let Some(outcomes) = &contents.outcomes else {
        return without_outcomes_readme();
    };
    let counts = &outcomes.report.counts;
    let records =
        counts.approvals + counts.rejections + counts.expirations + counts.execution_receipts;
    let held = outcomes.report.held.len();
    let mut description = if records == 0 {
        "approvals.jsonl\n    \
         Los recibos de aprobación, rechazo, vencimiento y ejecución de este\n    \
         tenant. Este tenant no tiene ninguno: el archivo está vacío."
            .to_owned()
    } else {
        format!(
            "approvals.jsonl\n    \
             Los recibos de aprobación, rechazo, vencimiento y ejecución de este\n    \
             tenant, uno por línea, tal como los guardó el gateway, leídos en el\n    \
             mismo momento que journal.jsonl. Tiene {records} registros: {} \
             aprobaciones,\n    {} rechazos, {} vencimientos y {} recibos de ejecución. Cada\n    \
             registro nombra el agent_id y el request_id de su solicitud en\n    \
             journal.jsonl. Los recibos de ejecución traen la salida del adaptador\n    \
             de cada acción ejecutada, porque su firma la cubre: revísela antes de\n    \
             compartir el paquete.",
            counts.approvals, counts.rejections, counts.expirations, counts.execution_receipts
        )
    };
    let execution_names: Vec<String> = (0..outcomes.execution_pins.len())
        .map(|index| key_pin_file_name(PinRole::Execution, index))
        .collect();
    let approver_names: Vec<String> = (0..outcomes.approver_pins.len())
        .map(|index| key_pin_file_name(PinRole::Approver, index))
        .collect();
    if !execution_names.is_empty() {
        description.push_str(&format!(
            "\n\n{}\n    \
             Las claves públicas de ejecución del gateway configuradas en la\n    \
             consola, cada una con su key_id. Firman los recibos de ejecución y\n    \
             de vencimiento. Cada una verificó al menos un registro de\n    \
             approvals.jsonl.",
            execution_names.join("\n")
        ));
    }
    if !approver_names.is_empty() {
        description.push_str(&format!(
            "\n\n{}\n    \
             Las claves públicas de los aprobadores configuradas en la consola,\n    \
             cada una con su key_id. Firman las decisiones de aprobar o rechazar.\n    \
             Cada una verificó al menos una decisión de approvals.jsonl. El\n    \
             gateway ata cada aprobador a un tenant; el archivo de pin no: compruebe\n    \
             por otro canal que estas claves son de aprobadores de este tenant.",
            approver_names.join("\n")
        ));
    }
    let omitted = outcomes.omitted_execution_pins + outcomes.omitted_approver_pins;
    if omitted > 0 {
        description.push_str(&format!(
            "\n\n    {} configurada{} en la consola no verificó ningún registro de\n    \
             approvals.jsonl y no va en el paquete (export.json las cuenta en\n    \
             omitted_execution_pins y omitted_approver_pins).",
            if omitted == 1 {
                "Una clave"
            } else {
                "Más de una clave"
            },
            if omitted == 1 { "" } else { "s" },
        ));
    }
    let flags = attester_names
        .iter()
        .map(|name| format!("--attester-pin {name}"))
        .chain(
            execution_names
                .iter()
                .map(|name| format!("--execution-pin {name}")),
        )
        .chain(
            approver_names
                .iter()
                .map(|name| format!("--approver-pin {name}")),
        )
        .collect::<Vec<_>>()
        .join(" ");
    let breakdown = held_by_outcome(&outcomes.report)
        .iter()
        .map(|(outcome, count)| format!("{count} {outcome}"))
        .collect::<Vec<_>>()
        .join(", ");
    let held_line = match held {
        0 => "Esta exportación no tiene solicitudes retenidas.".to_owned(),
        1 => format!("Esta exportación tiene 1 solicitud retenida: {breakdown}."),
        _ => format!("Esta exportación tiene {held} solicitudes retenidas: {breakdown}."),
    };
    let step = format!(
        "\
5. Cómo terminó cada solicitud:
       praetore-verify outcomes --outcomes approvals.jsonl --journal journal.jsonl {flags}
   Primero verifica journal.jsonl como el paso 3. Después comprueba cada
   registro de approvals.jsonl: la firma de cada decisión con la clave del
   aprobador que nombra y contra la solicitud de journal.jsonl que aprueba o
   rechaza; la firma de cada recibo de vencimiento y de ejecución con la
   clave de ejecución; que la evidencia dentro de cada recibo de ejecución
   es el recibo de journal.jsonl de la misma solicitud; y que los registros
   de una solicitud no se contradicen (por ejemplo, una ejecución sin
   aprobación). Un solo registro que falle hace fallar el comando.
   La salida trae counts (cuántos registros hay de cada tipo) y held: una
   fila por cada solicitud retenida de journal.jsonl, en su orden, con
   agent_id, request_id, evidence_id y outcome:
       pending                    sin decisión ni vencimiento registrados
       rejected                   una persona la rechazó
       expired                    venció sin decisión (recibo de vencimiento)
       approved_pending_dispatch  aprobada, sin ejecución registrada
       approved_executed          aprobada y ejecutada
       approved_failed            aprobada; la ejecución falló
       approved_outcome_unknown   aprobada; el resultado no se conoce aún
       approved_not_dispatched    aprobada y cerrada sin ejecutarse
                                  (vea not_dispatched_reason)
       not_dispatched             cerrada sin ejecutarse y sin decisión
   Para cruzar una solicitud retenida de journal.jsonl con su desenlace,
   busque su request_id (o su evidence_id) en held. Con --format json la
   salida es un solo objeto JSON; held está en details.
   El orden de las líneas de approvals.jsonl no se verifica: el desenlace de
   cada solicitud no depende de él. Una clave que no verificó ningún registro
   no hace fallar el comando: sale en unused_execution_pins o
   unused_approver_pins.
   {held_line}
   Acepta --expected-head como el paso 3."
    );
    OutcomesReadme {
        journal_tail: "esos recibos van en approvals.jsonl.",
        contents: format!("\n{description}\n"),
        export_tail: "de la cadena, digest de la política y cuántos registros de cada tipo\n    \
                      trae approvals.jsonl.",
        step2_since: "paquete de compliance con approvals.jsonl (P-002 D3.1), o desde un\n   \
                      release posterior a v0.3.3:",
        step2_old: "head_not_anchored, que el paso 3 usa, y no tiene el comando outcomes del\n   \
                    paso 5. Además, v0.3.3 rechaza con RECEIPT_INVALID los recibos de\n   \
                    ejecución schema v5 (awaiting_approval) y las razones\n   \
                    approved_claim_expired y approval_rejected, que approvals.jsonl puede\n   \
                    traer.",
        step: format!("\n{step}\n"),
        keys_tail: " Lo mismo vale para las claves de ejecución y de aprobación:\n\
                    compare su public_key_hex y su key_id con los que usted obtenga por otro\n\
                    canal.",
        not_proven: "\
- No prueba que approvals.jsonl esté completo. Sus registros no van
  encadenados: uno quitado no deja rastro en journal.jsonl, así que una
  solicitud aprobada o ejecutada puede aparecer como pending,
  approved_pending_dispatch o not_dispatched.
- Una solicitud retenida que aparece como pending puede seguir pendiente o
  haber vencido sin que el gateway lo haya registrado todavía: el gateway
  firma el vencimiento cuando lo detecta, no cuando ocurre.
",
    }
}

/// Held requests by outcome code, as `praetore-verify outcomes` reports
/// them (`held_by_outcome`).
fn held_by_outcome(report: &OutcomeReport) -> std::collections::BTreeMap<&'static str, u64> {
    let mut counts = std::collections::BTreeMap::new();
    for held in &report.held {
        *counts.entry(held.outcome.as_str()).or_default() += 1;
    }
    counts
}

/// "primera", "segunda", ... for a position counted from zero, up to
/// [`MAX_ATTESTER_PINS`]: the page names a pin without digits.
pub fn ordinal(index: usize) -> &'static str {
    const NAMES: [&str; MAX_ATTESTER_PINS] = [
        "primera",
        "segunda",
        "tercera",
        "cuarta",
        "quinta",
        "sexta",
        "séptima",
        "octava",
        "novena",
        "décima",
        "undécima",
        "duodécima",
        "decimotercera",
        "decimocuarta",
        "decimoquinta",
        "decimosexta",
    ];
    NAMES.get(index).copied().unwrap_or("última")
}

/// Decision receipts in the chain: every line but the database reference.
pub fn decision_receipts(export: &TenantExport) -> u64 {
    export.head.entries.get() - u64::from(export.database_head.is_some())
}
