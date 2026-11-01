//! `praetore policy safety-manifest --policy PATH --key HEX_FILE --output
//! NEW_FILE [--issued-at RFC3339] [--format json|text]` (G2): writes the
//! signed safety namespace manifest of a format 2 policy. It never
//! overwrites: an existing output file is an error and is left unchanged.
//!
//! The key file holds the 32-byte secret of the safety namespace key as 64
//! lowercase hex characters, with owner-only permissions. It must be its
//! own key, not the evidence attester key or the authority issuer key.

use praetore_core::{
    Policy, SafetyNamespaceKey, SafetyNamespaceManifest, display::escape_invisible,
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
    pub issued_at: Option<String>,
    pub format: Format,
}

pub fn parse(mut args: impl Iterator<Item = String>) -> CliResult<Args> {
    let (mut policy, mut key, mut output, mut issued_at, mut format) =
        (None, None, None, None, None);
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--policy" => &mut policy,
            "--key" => &mut key,
            "--output" => &mut output,
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
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_KEY_FILE_BYTES {
        return Err("the key must be a regular file no larger than 128 bytes".into());
    }
    crate::check_private_permissions(path, &metadata)?;
    let text = fs::read_to_string(path)?;
    let encoded = text.trim();
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("the key must be 64 lowercase hex characters (a 32-byte secret)".into());
    }
    let secret: [u8; 32] = hex::decode(encoded)?
        .try_into()
        .map_err(|_| "the key must be a 32-byte secret")?;
    Ok(SafetyNamespaceKey::from_secret_bytes(&secret))
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
    let manifest =
        SafetyNamespaceManifest::from_policy(&policy, issued_at(args.issued_at.as_deref())?, &key)?;
    let mut text = manifest.to_json()?;
    text.push('\n');
    // Never overwrite: an existing file may be the manifest an executor
    // already holds.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .map_err(|error| format!("cannot create {}: {error}", args.output.display()))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
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
