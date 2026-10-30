//! Command-line interface (hand-parsed; the workspace has no clap).

use crate::{
    gate::Mode,
    install::{self, Client, WrapTarget},
    json::JsonValue,
    receipts, relay,
    store::{self, Home, InitOutcome},
};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

const USAGE: &str = "praetore-mcp: put PRÆTORE in front of any stdio MCP server

Usage:
  praetore-mcp init      [--dir DIR]
  praetore-mcp wrap      [--dir DIR] [--name SERVER] [--mode observe|enforce] -- <command> [args...]
  praetore-mcp install   [--client claude-desktop|cursor|vscode] [--config FILE] [--dir DIR]
                         [--mode observe|enforce] [--dry-run] [--yes]
  praetore-mcp uninstall [--client claude-desktop|cursor|vscode] [--config FILE] [--dry-run] [--yes]
  praetore-mcp receipts  [--dir DIR] [--tail N]
  praetore-mcp verify    [--dir DIR]

DIR defaults to $PRAETORE_MCP_HOME, then ~/.praetore/mcp.
Keys created by `init` are LOCAL/DEV keys. Observe mode records decisions but
never blocks; enforce mode blocks DENY and REQUIRE_APPROVAL decisions.";

#[derive(Debug, Default)]
struct Parsed {
    values: BTreeMap<String, String>,
    flags: Vec<String>,
    rest: Vec<String>,
}

fn parse(
    args: &[String],
    with_value: &[&str],
    flags: &[&str],
    allow_rest: bool,
) -> Result<Parsed, String> {
    let mut parsed = Parsed::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" && allow_rest {
            parsed.rest = args[index + 1..].to_vec();
            return Ok(parsed);
        }
        if with_value.contains(&arg.as_str()) {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{arg} needs a value"))?;
            if parsed.values.insert(arg.clone(), value.clone()).is_some() {
                return Err(format!("{arg} given twice"));
            }
            index += 2;
        } else if flags.contains(&arg.as_str()) {
            parsed.flags.push(arg.clone());
            index += 1;
        } else {
            return Err(format!("unexpected argument {arg:?}"));
        }
    }
    Ok(parsed)
}

impl Parsed {
    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
    fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
    fn home(&self) -> Result<Home, String> {
        store::resolve_home(self.value("--dir").map(Path::new)).map(Home::new)
    }
    fn mode(&self) -> Result<Mode, String> {
        match self.value("--mode") {
            None => Ok(Mode::Observe),
            Some(value) => Mode::parse(value)
                .ok_or_else(|| format!("--mode must be observe or enforce, got {value:?}")),
        }
    }
}

pub fn run(args: &[String]) -> i32 {
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return 2;
    };
    let result = match command.as_str() {
        "init" => cmd_init(rest),
        "wrap" => cmd_wrap(rest),
        "install" => cmd_install(rest, false),
        "uninstall" => cmd_install(rest, true),
        "receipts" => cmd_receipts(rest),
        "verify" => cmd_verify(rest),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(0)
        }
        "-V" | "--version" => {
            println!("praetore-mcp {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("praetore-mcp: {error}");
            2
        }
    }
}

fn cmd_init(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["--dir"], &[], false)?;
    let home = parsed.home()?;
    match store::init(&home)? {
        InitOutcome::AlreadyInitialized => {
            println!(
                "praetore-mcp: {} is already initialized; nothing was changed.",
                home.root.display()
            );
        }
        InitOutcome::Created => {
            println!("praetore-mcp: initialized {}", home.root.display());
            println!();
            println!("  LOCAL/DEV keys (0600, never printed):");
            println!("    {}", home.issuer_key().display());
            println!("    {}", home.agent_key().display());
            println!("    {}", home.attester_key().display());
            println!("  trust files for third-party verification (praetore-verify formats):");
            println!("    {}", home.issuer_pins().display());
            println!("    {}", home.attester_pin().display());
            println!("  signed authority: {}", home.authority().display());
            println!(
                "  policy (v2, allows every tools/call): {}",
                home.policy().display()
            );
            println!("  receipts journal: {}", home.receipts_dir().display());
            println!();
            println!("  These are LOCAL/DEV keys for one machine. They are not a production PKI.");
            println!("  Next: praetore-mcp install --dry-run");
        }
    }
    Ok(0)
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name == name.trim()
        && !name.chars().any(char::is_control)
}

fn cmd_wrap(args: &[String]) -> Result<i32, String> {
    let parsed = parse(
        args,
        &["--dir", "--name", "--mode"],
        &[install::ORIGINAL_ARGS_ABSENT],
        true,
    )?;
    let Some((command, command_args)) = parsed.rest.split_first() else {
        return Err("wrap needs `-- <command> [args...]`".into());
    };
    let name = match parsed.value("--name") {
        Some(name) => name.to_owned(),
        None => {
            let file = command.rsplit(['/', '\\']).next().unwrap_or(command);
            file.strip_suffix(".exe").unwrap_or(file).to_owned()
        }
    };
    if !valid_server_name(&name) {
        return Err(format!(
            "invalid server name {name:?} (1-128 printable characters)"
        ));
    }
    Ok(relay::run(relay::WrapOptions {
        home: parsed.home()?,
        name,
        mode: parsed.mode()?,
        command: command.clone(),
        args: command_args.to_vec(),
    }))
}

fn confirm(path: &Path, yes: bool) -> bool {
    if yes {
        return true;
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "praetore-mcp: not modifying {} without confirmation; re-run with --yes",
            path.display()
        );
        return false;
    }
    eprint!("Apply these changes to {}? [y/N] ", path.display());
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    if std::io::stdin().lock().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn backup_path(path: &Path) -> PathBuf {
    let now = time::OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".praetore-backup-{stamp}"));
    let mut candidate = path.with_file_name(&name);
    let mut counter = 1;
    while candidate.exists() {
        let mut numbered = name.clone();
        numbered.push(format!("-{counter}"));
        candidate = path.with_file_name(numbered);
        counter += 1;
    }
    candidate
}

/// Backs up, then atomically replaces `path`, keeping its permissions.
fn write_with_backup(path: &Path, original: &str, updated: &str) -> Result<PathBuf, String> {
    let backup = backup_path(path);
    fs::copy(path, &backup)
        .map_err(|e| format!("cannot write backup {}: {e}", backup.display()))?;
    // Verify the backup is byte-identical before touching the original.
    if fs::read_to_string(&backup).ok().as_deref() != Some(original) {
        return Err(format!(
            "backup {} does not match the original; aborting",
            backup.display()
        ));
    }
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".praetore-tmp-{}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let result = (|| -> std::io::Result<()> {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(updated.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&tmp, fs::metadata(path)?.permissions())?;
        fs::rename(&tmp, path)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot update {}: {error}", path.display()));
    }
    Ok(backup)
}

fn cmd_install(args: &[String], uninstall: bool) -> Result<i32, String> {
    let with_value: &[&str] = if uninstall {
        &["--client", "--config"]
    } else {
        &["--client", "--config", "--dir", "--mode"]
    };
    let parsed = parse(args, with_value, &["--dry-run", "--yes"], false)?;
    let dry_run = parsed.flag("--dry-run");
    let client = parsed
        .value("--client")
        .map(|c| {
            Client::parse(c)
                .ok_or_else(|| format!("unknown client {c:?} (claude-desktop, cursor, vscode)"))
        })
        .transpose()?;

    let targets: Vec<(Client, PathBuf)> = match (parsed.value("--config"), client) {
        (Some(_), None) => return Err("--config needs --client to know the file format".into()),
        (Some(path), Some(client)) => vec![(client, PathBuf::from(path))],
        (None, client) => {
            let clients: Vec<Client> = client.map_or(Client::ALL.to_vec(), |c| vec![c]);
            let mut found = Vec::new();
            for client in clients {
                for path in client.default_paths() {
                    if path.is_file() {
                        found.push((client, path));
                    } else {
                        println!("  ({}: no config at {})", client.name(), path.display());
                    }
                }
            }
            found
        }
    };
    if targets.is_empty() {
        println!("praetore-mcp: no MCP client configuration found; nothing to do.");
        return Ok(0);
    }

    let wrap_target = if uninstall {
        None
    } else {
        let home = parsed.home()?;
        if !home.is_initialized() {
            if dry_run {
                eprintln!(
                    "praetore-mcp: note: {} is not initialized yet; run `praetore-mcp init` before installing",
                    home.root.display()
                );
            } else {
                return Err(format!(
                    "{} is not initialized; run `praetore-mcp init` first",
                    home.root.display()
                ));
            }
        }
        let exe = std::env::current_exe()
            .and_then(|exe| exe.canonicalize())
            .map_err(|e| format!("cannot locate the praetore-mcp executable: {e}"))?;
        Some(WrapTarget {
            exe: exe
                .to_str()
                .ok_or("praetore-mcp executable path is not UTF-8")?
                .to_owned(),
            dir: home
                .root
                .to_str()
                .ok_or("home directory path is not UTF-8")?
                .to_owned(),
            mode: parsed.mode()?,
        })
    };

    let mut code = 0;
    for (client, path) in targets {
        let original = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("praetore-mcp: cannot read {}: {error}", path.display());
                code = 1;
                continue;
            }
        };
        let mut doc = match JsonValue::parse(&original) {
            Ok(doc) => doc,
            Err(error) => {
                eprintln!(
                    "praetore-mcp: {} is not strict JSON ({error}); comments/trailing commas are not supported, file NOT modified",
                    path.display()
                );
                code = 1;
                continue;
            }
        };
        let changes = match &wrap_target {
            Some(target) => install::wrap_config(&mut doc, client, target),
            None => install::unwrap_config(&mut doc, client),
        };
        print!(
            "[{}] {}",
            client.name(),
            install::render_changes(&path, &changes)
        );
        if !changes.iter().any(install::Change::is_modification) {
            println!("  nothing to change");
            continue;
        }
        if dry_run {
            println!("  dry run: file not modified");
            continue;
        }
        if !confirm(&path, parsed.flag("--yes")) {
            code = 1;
            continue;
        }
        let updated = install::render_document(&doc, &original);
        match write_with_backup(&path, &original, &updated) {
            Ok(backup) => println!(
                "  updated; backup at {}\n  restart {} to apply",
                backup.display(),
                client.name()
            ),
            Err(error) => {
                eprintln!("praetore-mcp: {error}");
                code = 1;
            }
        }
    }
    Ok(code)
}

fn cmd_receipts(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["--dir", "--tail"], &[], false)?;
    let tail = match parsed.value("--tail") {
        None => 20,
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| format!("--tail must be a number, got {value:?}"))?,
    };
    let lines = receipts::read_journal(&parsed.home()?)?;
    if lines.is_empty() {
        println!("no receipts yet");
        return Ok(0);
    }
    print!("{}", receipts::render_table(&lines, tail));
    Ok(0)
}

fn cmd_verify(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["--dir"], &[], false)?;
    let home = parsed.home()?;
    let report = receipts::verify_journal(&home)?;
    for failure in &report.failures {
        println!("{failure}");
    }
    let join = |map: &BTreeMap<_, usize>| {
        map.iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let by_mode: BTreeMap<&str, usize> = report
        .by_mode
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .collect();
    println!(
        "{} {} receipts: {} verified, {} failed | mode: {} | decision: {}",
        if report.failures.is_empty() {
            "OK"
        } else {
            "FAIL"
        },
        report.total,
        report.ok,
        report.failures.len(),
        join(&by_mode),
        join(&report.by_decision)
    );
    println!(
        "checked: integrity hash, attester signature ({}), agent intent signature, authority signature against {} at decision time, praetore.mode binding",
        home.attester_pin().display(),
        home.issuer_pins().display()
    );
    println!("observe receipts record a decision that was NOT enforced.");
    Ok(if report.failures.is_empty() { 0 } else { 1 })
}
