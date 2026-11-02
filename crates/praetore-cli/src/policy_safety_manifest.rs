//! `praetore policy safety-manifest --policy PATH --key HEX_FILE --output
//! NEW_FILE [--attester-pin HEX_FILE] [--issued-at RFC3339] [--format
//! json|text]` (G2): writes the signed safety namespace manifest of a
//! format 2 policy.
//!
//! It never overwrites, and a failed write leaves nothing at the output
//! path: the manifest is written and synced to a temporary file in the same
//! directory, then hard-linked to the output name, which fails if the name
//! exists (even as a dangling symlink), and the temporary file is removed.
//!
//! The key file holds the 32-byte secret of the safety namespace key as 64
//! lowercase hex characters (one final newline allowed). It is read with
//! [`crate::secret_file::read_private_file`]: not a symlink, a regular file
//! owned by the current user, no group or other permission bits, at most
//! 128 bytes. It must be its own key, not the evidence attester key or the
//! authority issuer key; with `--attester-pin`, the same public key is
//! refused (`SameKeyForBothRoles`).
//!
//! JSON output is exact (a policy id is printed as it is, invisible
//! characters included) by design; text output escapes them.

use praetore_core::{
    Policy, SafetyNamespaceKey, SafetyNamespaceManifest, display::escape_invisible,
    safety_namespace::ensure_distinct_keys,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_KEY_FILE_BYTES: u64 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Text,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub policy: PathBuf,
    pub key: PathBuf,
    pub output: PathBuf,
    pub attester_pin: Option<PathBuf>,
    pub issued_at: Option<String>,
    pub format: Format,
}

pub fn parse(mut args: impl Iterator<Item = String>) -> CliResult<Args> {
    let (mut policy, mut key, mut output, mut attester_pin, mut issued_at, mut format) =
        (None, None, None, None, None, None);
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--policy" => &mut policy,
            "--key" => &mut key,
            "--output" => &mut output,
            "--attester-pin" => &mut attester_pin,
            "--issued-at" => &mut issued_at,
            "--format" => &mut format,
            _ => return Err(format!("unexpected argument: {flag}").into()),
        };
        let value = args.next().ok_or(format!("missing value for {flag}"))?;
        if slot.replace(value).is_some() {
            return Err(format!("{flag} given twice").into());
        }
    }
    let usage = "praetore policy safety-manifest needs --policy <path> --key <hex file> --output <new file>";
    Ok(Args {
        policy: policy.ok_or(usage)?.into(),
        key: key.ok_or(usage)?.into(),
        output: output.ok_or(usage)?.into(),
        attester_pin: attester_pin.map(PathBuf::from),
        issued_at,
        format: match format.as_deref() {
            None | Some("text") => Format::Text,
            Some("json") => Format::Json,
            Some(_) => return Err("--format must be json or text".into()),
        },
    })
}

fn read_policy(path: &Path) -> CliResult<Policy> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES {
        return Err("the policy must be a regular file no larger than 1 MiB".into());
    }
    let mut text = String::new();
    fs::File::open(path)?
        .take(MAX_POLICY_BYTES + 1)
        .read_to_string(&mut text)?;
    Ok(Policy::from_json(&text)?)
}

fn read_key(path: &Path) -> CliResult<SafetyNamespaceKey> {
    let contents = crate::secret_file::read_private_file(path, MAX_KEY_FILE_BYTES)
        .map_err(|error| format!("the key file {} {error}", path.display()))?;
    let encoded = contents.strip_suffix(b"\n").unwrap_or(&contents);
    if encoded.len() != 64
        || !encoded
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("the key must be 64 lowercase hex characters (a 32-byte secret)".into());
    }
    let secret: [u8; 32] = hex::decode(encoded)?
        .try_into()
        .map_err(|_| "the key must be a 32-byte secret")?;
    Ok(SafetyNamespaceKey::from_secret_bytes(&secret))
}

/// Writes `contents` to `path`, which must not exist, so that `path` either
/// does not appear or holds every byte: a temporary file in the same
/// directory is written and synced, then hard-linked to `path` (`link`
/// fails if `path` exists, also as a dangling symlink, so it never
/// replaces anything), and removed.
pub(crate) fn write_new_file(path: &Path, contents: &[u8]) -> CliResult<()> {
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} does not name a file", path.display()))?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let temporary = directory.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let written = (|| -> CliResult<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary, path)
            .map_err(|error| format!("cannot create {}: {error}", path.display()).into())
    })();
    let _ = fs::remove_file(&temporary);
    written?;
    // Persist the new directory entry. Best effort: the file is complete
    // either way.
    if let Ok(directory) = fs::File::open(directory) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn issued_at(value: Option<&str>) -> CliResult<OffsetDateTime> {
    match value {
        Some(text) => OffsetDateTime::parse(text, &Rfc3339)
            .map_err(|_| "--issued-at must be an RFC 3339 timestamp".into()),
        None => Ok(OffsetDateTime::now_utc().replace_nanosecond(0)?),
    }
}

/// The summary printed after the manifest is written.
fn summary(
    manifest: &SafetyNamespaceManifest,
    key: &SafetyNamespaceKey,
    output: &Path,
) -> CliResult<Value> {
    Ok(json!({
        "ok": true,
        "command": "policy safety-manifest",
        "output": output.to_string_lossy(),
        "policy_id": manifest.policy_id(),
        "policy_version": manifest.policy_version(),
        "policy_digest": manifest.policy_digest(),
        "safety_actions": manifest.safety_actions(),
        "issued_at": manifest.issued_at(),
        "key_id": manifest.key_id(),
        "public_key": hex::encode(key.public_key()?.as_bytes()),
    }))
}

/// `OK policy safety-manifest key=value ...`; values are JSON-encoded, then
/// invisible characters are written as `\u{XXXX}` (a policy id or a path
/// may contain them).
pub fn text_line(summary: &Value) -> String {
    let mut line = String::from("OK policy safety-manifest");
    for (key, value) in summary.as_object().into_iter().flatten() {
        if key == "ok" || key == "command" {
            continue;
        }
        line.push_str(&format!(" {key}={}", escape_invisible(&value.to_string())));
    }
    line
}

/// Builds the manifest and writes it to `args.output`, which must not exist.
/// Nothing is written when the policy, the key or the time is invalid.
pub fn write(args: &Args) -> CliResult<Value> {
    let policy = read_policy(&args.policy)?;
    let key = read_key(&args.key)?;
    if let Some(pin) = &args.attester_pin {
        let attester = crate::journal_export::read_attester_pin(pin)?;
        ensure_distinct_keys(&key.public_key()?, &attester)?;
    }
    let manifest =
        SafetyNamespaceManifest::from_policy(&policy, issued_at(args.issued_at.as_deref())?, &key)?;
    // Never overwrite: an existing file may be the manifest an executor
    // already holds.
    write_new_file(&args.output, manifest.to_file()?.as_bytes())?;
    summary(&manifest, &key, &args.output)
}

pub fn run(args: Args) -> CliResult<()> {
    let summary = write(&args)?;
    match args.format {
        Format::Json => println!("{summary}"),
        Format::Text => println!("{}", text_line(&summary)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> CliResult<Args> {
        parse(list.iter().map(|s| s.to_string()))
    }

    #[test]
    fn arguments_are_parsed_strictly() {
        let parsed = args(&["--policy", "p", "--key", "k", "--output", "o"]).unwrap();
        assert_eq!(
            parsed,
            Args {
                policy: "p".into(),
                key: "k".into(),
                output: "o".into(),
                attester_pin: None,
                issued_at: None,
                format: Format::Text,
            }
        );
        assert!(args(&["--policy", "p", "--key", "k"]).is_err());
        assert!(
            args(&[
                "--policy", "p", "--policy", "p", "--key", "k", "--output", "o"
            ])
            .is_err()
        );
        assert!(args(&["--policy", "p", "--key", "k", "--output", "o", "--force"]).is_err());
        assert!(
            args(&[
                "--policy", "p", "--key", "k", "--output", "o", "--format", "yaml"
            ])
            .is_err()
        );
        assert_eq!(
            args(&[
                "--format", "json", "--policy", "p", "--key", "k", "--output", "o"
            ])
            .unwrap()
            .format,
            Format::Json
        );
    }

    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "praetore-write-new-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn write_new_file_never_replaces_and_leaves_no_temporary_file() {
        let directory = temporary_directory();
        let path = directory.join("manifest.json");
        write_new_file(&path, b"first\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first\n");
        let error = write_new_file(&path, b"second\n").unwrap_err();
        assert!(error.to_string().contains("cannot create"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), b"first\n");

        #[cfg(unix)]
        {
            // A dangling symlink at the output name is not followed.
            let target = directory.join("elsewhere");
            let link = directory.join("link.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(write_new_file(&link, b"x").is_err());
            assert!(!target.exists());
        }

        // A failed write leaves nothing: here the directory does not exist.
        let missing = directory.join("missing").join("manifest.json");
        assert!(write_new_file(&missing, b"x").is_err());
        assert!(!missing.exists());

        let names: Vec<String> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|name| !name.ends_with(".tmp")),
            "{names:?}"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn text_output_escapes_invisible_characters() {
        let line = text_line(&json!({
            "ok": true,
            "command": "policy safety-manifest",
            "policy_id": "ops\u{200b}",
            "safety_actions": ["safety:halt"],
        }));
        assert_eq!(
            line,
            "OK policy safety-manifest policy_id=\"ops\\u{200b}\" safety_actions=[\"safety:halt\"]"
        );
    }
}
