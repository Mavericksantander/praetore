//! D3: the compliance package. A `.tar.gz` built on this computer that a
//! third party can check with `praetore-verify` without trusting the
//! console: the tenant's signed journal (the same export as `praetore
//! journal-export --tenant`, from the shared code in
//! `praetore_replay_postgres::journal_export`), the configured policy and its
//! digest (`RecordedPolicy`, as the engine and `praetore-verify
//! policy-digest` compute it), the attester pins, `SHA256SUMS` and a plain
//! `LEEME.txt`.
//!
//! Every piece is read and checked before anything is archived; a missing or
//! unreadable piece means no package at all. Only public keys are written:
//! pins are parsed and re-encoded, a pin that is the approver's key is
//! refused, and so is a pin that verified no entry of the export (a secret
//! key's bytes can decode as a public key, but cannot verify its own
//! signatures).

use crate::ApproverSigner;
use praetore_core::{VerifiedPublicKey, policy::RecordedPolicy};
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

/// Most attester pins, as `praetore journal-export`.
pub const MAX_ATTESTER_PINS: usize = 16;
const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_PIN_BYTES: u64 = 4096;

/// `attester-pin-1.hex`, `attester-pin-2.hex`, ... in configuration order.
pub fn pin_file_name(index: usize) -> String {
    format!("attester-pin-{}.hex", index + 1)
}

/// Where the policy and the attester pins are read from, at each download.
#[derive(Debug, Clone)]
pub struct PackSettings {
    policy_file: PathBuf,
    attester_pin_files: Vec<PathBuf>,
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
                "el paquete de compliance acepta a lo más {MAX_ATTESTER_PINS} pins"
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
        })
    }
}

/// The tenant's chain, exported in one read-only snapshot.
pub trait JournalExportStore: Send + Sync + 'static {
    fn tenant_id(&self) -> Uuid;
    /// `Err` carries the detail for the console's log, never for the page.
    fn export_tenant(&self, attesters: &[VerifiedPublicKey]) -> Result<TenantExport, String>;
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
    /// not needed, and it may be the wrong file (a secret, say).
    PinUnused,
    Journal,
    Archive,
}

impl PackError {
    pub fn message(self) -> &'static str {
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
            Self::PinUnused => {
                "Una de las claves configuradas como clave pública del atestador no verifica ningún registro: sobra o es un archivo equivocado. No se generó ningún paquete."
            }
            Self::Journal => {
                "No se pudo exportar el registro firmado: la base no respondió, no hay registros, hay más de los que caben en una exportación, o alguna firma no corresponde a las claves del atestador configuradas. No se generó ningún paquete."
            }
            Self::Archive => "No se pudo armar el paquete. No se generó ningún paquete.",
        }
    }

    fn log_name(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Pins => "attester_pins",
            Self::PinIsApproverKey => "attester_pin_is_approver_key",
            Self::PinUnused => "attester_pin_unused",
            Self::Journal => "journal_export",
            Self::Archive => "archive",
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
    let export = pack.store.export_tenant(&pins).map_err(|detail| {
        tracing::warn!(%detail, "compliance package: journal export failed");
        PackError::Journal
    })?;
    // Every pin must have verified an entry: only then is it known to be the
    // public key of a signer, and not some other 32-byte value.
    if !export.unused_attesters.is_empty() {
        return Err(PackError::PinUnused);
    }
    Ok(PackContents {
        tenant_id: pack.store.tenant_id(),
        generated_at: now,
        export,
        policy_json,
        policy,
        pins,
    })
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
        file(POLICY_FILE, contents.policy_json.clone().into_bytes()),
        file(
            POLICY_DIGEST_FILE,
            format!("{}\n", contents.policy.digest()).into_bytes(),
        ),
    ];
    for (name, pin) in pin_names.iter().zip(&contents.pins) {
        files.push(file(
            name,
            format!("{}\n", hex::encode(pin.as_bytes())).into_bytes(),
        ));
    }
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
    let entries = contents.export.head.entries.get();
    let head = contents.export.head.head.to_hex();
    let digest = contents.policy.digest();
    let pins = pin_names
        .iter()
        .map(|name| format!("--attester-pin {name}"))
        .collect::<Vec<_>>()
        .join(" ");
    let repository = env!("CARGO_PKG_REPOSITORY");
    let version = env!("CARGO_PKG_VERSION");
    let database = if contents.export.database_head.is_some() {
        "La primera línea de journal.jsonl referencia el head de la cadena de la base\n\
         de datos (los registros de almacenamiento de toda la base). Esa cadena no va\n\
         en el paquete, así que esa referencia no se puede comprobar con él."
    } else {
        "Esta exportación no referencia la cadena de la base de datos: la base no\n\
         tenía registros de almacenamiento."
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
    el mismo código. Tiene {entries} entradas. Cada línea encadena con la
    anterior un recibo de decisión firmado por el atestador: lo que la
    política resolvió para cada solicitud (permitir, denegar o retener para
    aprobación). No trae la aprobación o el rechazo de una persona ni el
    resultado de la ejecución: esos recibos no van en este paquete.

policy.json
    El archivo de política configurado en la consola, copiado tal cual.

policy-digest.txt
    El digest de esa política (SHA-256 de su JSON canónico), calculado como
    lo calculan el motor y `praetore-verify policy-digest`:
        {digest}

{pin_list}
    Las claves públicas Ed25519 del atestador configuradas en la consola.
    Cada una verificó al menos una entrada de la exportación.

export.json
    Los datos de la exportación: tenant, hora, cantidad de entradas, head
    de la cadena y digest de la política.

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

2. Construya praetore-verify desde la rama main:
       git clone {repository}
       cd praetore
       cargo build --release --locked -p praetore-verify
   El programa queda en target/release/praetore-verify. El praetore-verify
   de v0.3.3 rechaza los recibos schema v5 (el recibo de ejecución
   `awaiting_approval` de una solicitud retenida) y la razón
   `approved_claim_expired`, con RECEIPT_INVALID. Esos son recibos de
   ejecución y no van en este paquete; aun así, use el de main, que conoce
   los formatos que el gateway escribe hoy.

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
   Para saber que no faltan ni se reordenaron registros, compárelo con un
   head obtenido por un canal que el operador no controle y páselo con
   --expected-head.

4. La política:
       praetore-verify policy-digest --policy policy.json
   debe dar el digest de policy-digest.txt. Y
       praetore-verify journal --journal journal.jsonl {pins} --policy policy.json
   exige además que cada recibo registre el digest de esta política. Si una
   parte del registro se decidió con otra política (por ejemplo, antes de un
   cambio de política), este comando falla aunque el registro esté íntegro.


LAS CLAVES
----------

Los archivos de pin vienen de la configuración de la consola: los eligió el
operador. Con solo esos archivos, la verificación muestra que el registro es
coherente con esas claves, no que lo firmó el atestador que usted espera.
Obtenga las claves públicas del atestador por otro canal y compárelas con
estos archivos.


LO QUE ESTE PAQUETE NO PRUEBA
-----------------------------

- No prueba que el agente no tuvo un camino fuera del gateway. Una acción
  que no pasó por el gateway no aparece en este registro.
- No prueba nada de lo ocurrido antes del primer registro ni después de la
  exportación ({generated_at}).
- No prueba que el registro esté completo: sin un head anclado fuera del
  control del operador, un subconjunto de los recibos (truncado,
  reordenado o reencadenado) también verifica.
- No muestra si una solicitud retenida fue aprobada, rechazada, venció o
  se ejecutó: journal.jsonl trae solo la decisión de la política. Los
  recibos de aprobación y de ejecución no van en este paquete.
- No prueba que una acción permitida o aprobada tuvo efecto fuera del
  gateway: los recibos muestran lo que el gateway decidió y registró.
- No prueba que el gateway usó policy.json: es el archivo configurado en la
  consola. Cada recibo registra el digest de la política con que se decidió;
  el paso 4 los compara.
- No prueba que una autorización siga vigente, ni autoriza nada.
- {database}
- El praetore-verify de v0.3.3 rechaza los recibos schema v5 (recibos de
  ejecución, que este paquete no trae): use uno construido desde main.
",
        pin_list = pin_names.join("\n"),
        database = database.replace('\n', "\n  "),
    )
}
