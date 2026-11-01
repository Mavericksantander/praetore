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
  praetore-mcp policy list   [--dir DIR]
  praetore-mcp policy check  [--dir DIR]
  praetore-mcp policy deny|require-approval|allow --id ID [--server NAME] [--tool NAME]
                         [--arg-exact KEY=VALUE]... [--arg-path-prefix KEY=/abs/path]...
                         [--arg-prefix KEY=VALUE]... [--any-tool] [--dir DIR]
  praetore-mcp policy remove --id ID [--dir DIR]

  praetore-mcp <command> --help
  praetore-mcp --version

DIR defaults to $PRAETORE_MCP_HOME, then ~/.praetore/mcp.
Keys created by `init` are LOCAL/DEV keys. Observe mode records decisions but
never blocks; enforce mode blocks DENY and REQUIRE_APPROVAL decisions. If the
home cannot be loaded (e.g. no `init`), `wrap` refuses every tools/call in
both modes.

Exit codes:
  0    success (also --help and --version)
  1    the command ran and found a problem: `verify` found a failed receipt,
       `policy check` found an invalid policy or engine, or `install` /
       `uninstall` could not read, parse or write a config (or was not
       confirmed)
  2    usage error, or the command could not run (message on stderr)
  wrap exits with the MCP server's exit code; 127 if the server cannot be
       started, 1 if it was killed by a signal";

const INIT_HELP: &str = "Usage: praetore-mcp init [--dir DIR]

Creates LOCAL/DEV Ed25519 keys (0600), a signed authority, trust pins for
praetore-verify, a v2 policy that allows every tools/call, and the receipts
journal under DIR. Running it again on an initialized DIR changes nothing.

  --dir DIR   home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)";

const WRAP_HELP: &str = "Usage: praetore-mcp wrap [--dir DIR] [--name SERVER] [--mode observe|enforce] -- <command> [args...]

Starts the stdio MCP server <command> and relays its stdio. Every tools/call
is evaluated and recorded as a signed receipt. Everything after `--` is
passed to the server unchanged (including any --help).

  --dir DIR     home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)
  --name SERVER server name used in policy rules and receipts
                (default: the command's file name)
  --mode MODE   observe (default): forward every call, record the decision
                enforce: block DENY and REQUIRE_APPROVAL with an MCP tool error

Exit code: the server's; 127 if it cannot be started, 1 if it was killed by
a signal, 2 on a usage error.";

const INSTALL_HELP: &str = "Usage: praetore-mcp install [--client claude-desktop|cursor|vscode] [--config FILE] [--dir DIR]
                            [--mode observe|enforce] [--dry-run] [--yes]

Rewrites the stdio servers of an MCP client config so they run through
`praetore-mcp wrap`. A timestamped backup is written next to each file first.
Without --client, every detected client is processed.

  --client NAME  claude-desktop, cursor or vscode
  --config FILE  config file to edit (needs --client)
  --dir DIR      home passed to `wrap` (must be initialized)
  --mode MODE    mode passed to `wrap` (default observe)
  --dry-run      show the changes, write nothing
  --yes          do not ask for confirmation

Exit code: 0 on success or nothing to do, 1 if a config could not be read,
parsed or written, or was not confirmed, 2 on a usage error.";

const UNINSTALL_HELP: &str = "Usage: praetore-mcp uninstall [--client claude-desktop|cursor|vscode] [--config FILE] [--dry-run] [--yes]

Restores the original commands of servers wrapped by `install`. A timestamped
backup is written next to each file first.

  --client NAME  claude-desktop, cursor or vscode
  --config FILE  config file to edit (needs --client)
  --dry-run      show the changes, write nothing
  --yes          do not ask for confirmation

Exit code: 0 on success or nothing to do, 1 if a config could not be read,
parsed or written, or was not confirmed, 2 on a usage error.";

const RECEIPTS_HELP: &str = "Usage: praetore-mcp receipts [--dir DIR] [--tail N]

Prints the last N receipts of the journal as a table (default 20).

  --dir DIR   home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)
  --tail N    number of receipts to show";

const VERIFY_HELP: &str = "Usage: praetore-mcp verify [--dir DIR]

Checks every receipt in the journal: integrity hash, attester signature,
agent intent signature, authority signature against the issuer pins at
decision time, and the praetore.mode binding.

  --dir DIR   home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)

Exit code: 0 if every receipt verifies, 1 if any fails, 2 if the journal
cannot be read.";

const POLICY_HELP: &str = "Usage:
  praetore-mcp policy list   [--dir DIR]
  praetore-mcp policy check  [--dir DIR]
  praetore-mcp policy deny|require-approval|allow --id ID [--server NAME] [--tool NAME]
                         [--arg-exact KEY=VALUE]... [--arg-path-prefix KEY=/abs/path]...
                         [--arg-prefix KEY=VALUE]... [--any-tool] [--dir DIR]
  praetore-mcp policy remove --id ID [--dir DIR]

Reads and edits DIR/policy.json. Every change is re-validated and a backup is
written first. Running MCP clients must be restarted to load a change.
--arg-path-prefix is a lexical match: symlinks are not resolved.

Exit code: 0 on success, 1 if `check` finds an invalid policy or engine,
2 on a usage error or a rejected change.";

fn help_for(command: &str) -> Option<&'static str> {
    Some(match command {
        "init" => INIT_HELP,
        "wrap" => WRAP_HELP,
        "install" => INSTALL_HELP,
        "uninstall" => UNINSTALL_HELP,
        "receipts" => RECEIPTS_HELP,
        "verify" => VERIFY_HELP,
        "policy" => POLICY_HELP,
        _ => return None,
    })
}

/// `-h`/`--help` among a command's own options; anything after `--` belongs
/// to the wrapped server and is ignored.
fn wants_help(args: &[String]) -> bool {
    args.iter()
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "-h" || arg == "--help")
}

#[derive(Debug, Default)]
struct Parsed {
    values: BTreeMap<String, String>,
    /// Repeatable options, in command-line order.
    multi: Vec<(String, String)>,
    flags: Vec<String>,
    rest: Vec<String>,
}

fn parse(
    args: &[String],
    with_value: &[&str],
    flags: &[&str],
    allow_rest: bool,
) -> Result<Parsed, String> {
    parse_multi(args, with_value, &[], flags, allow_rest)
}

fn parse_multi(
    args: &[String],
    with_value: &[&str],
    repeatable: &[&str],
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
        } else if repeatable.contains(&arg.as_str()) {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{arg} needs a value"))?;
            parsed.multi.push((arg.clone(), value.clone()));
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
    if let Some(help) = help_for(command)
        && wants_help(rest)
    {
        println!("{help}");
        return 0;
    }
    let result = match command.as_str() {
        "init" => cmd_init(rest),
        "wrap" => cmd_wrap(rest),
        "install" => cmd_install(rest, false),
        "uninstall" => cmd_install(rest, true),
        "receipts" => cmd_receipts(rest),
        "verify" => cmd_verify(rest),
        "policy" => cmd_policy(rest),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(0)
        }
        "-V" | "--version" | "version" => {
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

pub(crate) fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
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
            "invalid server name {name:?} (1-128 printable characters, not starting with '-')"
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
            install::dedup_targets(found)
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
            exe: install::strip_verbatim_prefix(
                exe.to_str()
                    .ok_or("praetore-mcp executable path is not UTF-8")?,
            ),
            dir: install::strip_verbatim_prefix(
                home.root
                    .to_str()
                    .ok_or("home directory path is not UTF-8")?,
            ),
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
        match crate::fsutil::write_with_backup(&path, &original, &updated) {
            Ok((real, backup)) => println!(
                "  updated{}; backup at {}\n  restart {} to apply",
                if real == path {
                    String::new()
                } else {
                    format!(" {} (symlink target)", real.display())
                },
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

/// Exclusive lock for policy read-modify-write (O_EXCL lock file, removed on
/// drop). Prevents lost updates between concurrent `policy` commands.
struct PolicyLock(PathBuf);

impl PolicyLock {
    fn acquire(home: &Home) -> Result<Self, String> {
        let path = home.root.join("policy.json.lock");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", std::process::id());
                Ok(Self(path))
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(format!(
                "another `praetore-mcp policy` command is running (lock {}); if none is, remove that file",
                path.display()
            )),
            Err(error) => Err(format!("cannot create lock {}: {error}", path.display())),
        }
    }
}

impl Drop for PolicyLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn read_policy(home: &Home) -> Result<(String, praetore_core::Policy), String> {
    let path = home.policy();
    let text =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let policy = praetore_core::Policy::from_json(&text).map_err(|e| {
        format!(
            "{} is invalid ({e}); fix it (see `praetore-mcp policy check`) or restore a backup",
            path.display()
        )
    })?;
    Ok((text, policy))
}

fn save_policy(home: &Home, original: &str, updated: &str) -> Result<(), String> {
    let (_, backup) = crate::fsutil::write_with_backup(&home.policy(), original, updated)?;
    let digest = praetore_core::Policy::from_json(updated)
        .and_then(|p| p.digest())
        .map_err(|e| format!("written policy failed to re-validate: {e}"))?;
    println!(
        "updated {} (digest {digest}); backup at {}",
        home.policy().display(),
        backup.display()
    );
    Ok(())
}

fn cmd_policy(args: &[String]) -> Result<i32, String> {
    use crate::policy::{self, ArgOperator, RuleSpec};
    let Some((sub, rest)) = args.split_first() else {
        return Err(format!("policy needs a subcommand\n\n{USAGE}"));
    };
    let code = match sub.as_str() {
        "list" => {
            let parsed = parse(rest, &["--dir"], &[], false)?;
            let (_, policy) = read_policy(&parsed.home()?)?;
            print!("{}", policy::render_list(&policy));
            0
        }
        "check" => {
            let parsed = parse(rest, &["--dir"], &[], false)?;
            let home = parsed.home()?;
            let path = home.policy();
            let text = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            match praetore_core::Policy::from_json(&text).and_then(|p| p.digest().map(|d| (p, d))) {
                Err(error) => {
                    println!("INVALID {}: {error}", path.display());
                    if matches!(
                        error,
                        praetore_core::PraetoreError::PolicyFormatUnsupported { found: 1, .. }
                    ) {
                        println!(
                            "hint: policy format 1 was written before G7, and until it is migrated every tool call is refused. Add \"format_version\": 2 and \"action_classes\": {{\"{}\": \"Mission\"}}, or run `praetore policy classify --policy {}` to propose the table (see docs/policy-language.md); the digest changes, so receipts already written keep verifying only against the old document.",
                            crate::store::ACTION_TYPE,
                            path.display()
                        );
                    }
                    1
                }
                Ok((parsed_policy, digest)) => {
                    let warnings = policy::lint(&parsed_policy);
                    for warning in &warnings {
                        println!("warning: {warning}");
                    }
                    // Build the same engine `wrap` builds, so key/pin/policy
                    // problems surface here instead of as refused calls.
                    let engine = if home.is_initialized() {
                        crate::gate::Gate::load(&home, Mode::Observe).map(|_| ())
                    } else {
                        Err(format!("{} is not initialized", home.root.display()))
                    };
                    match engine {
                        Ok(()) => {
                            println!(
                                "OK {} policy {} v{}: {} rule(s), digest {digest}, {} warning(s); HighAssurance engine starts",
                                path.display(),
                                parsed_policy.id,
                                parsed_policy.version,
                                parsed_policy.rules.len(),
                                warnings.len()
                            );
                            0
                        }
                        Err(error) => {
                            println!("INVALID engine: {error}");
                            1
                        }
                    }
                }
            }
        }
        "remove" => {
            let parsed = parse(rest, &["--dir", "--id"], &[], false)?;
            let id = parsed.value("--id").ok_or("policy remove needs --id")?;
            let home = parsed.home()?;
            let _lock = PolicyLock::acquire(&home)?;
            let (original, current) = read_policy(&home)?;
            let updated = policy::remove_rule(&current, id)?;
            save_policy(&home, &original, &updated)?;
            println!("removed rule {id:?}");
            0
        }
        effect_name => {
            let Some(effect) = policy::parse_effect(effect_name) else {
                return Err(format!(
                    "unknown policy subcommand {effect_name:?} (list, check, deny, require-approval, allow, remove)"
                ));
            };
            let parsed = parse_multi(
                rest,
                &["--dir", "--id", "--server", "--tool"],
                &["--arg-exact", "--arg-path-prefix", "--arg-prefix"],
                &["--any-tool"],
                false,
            )?;
            let mut conditions = Vec::new();
            for (flag, value) in &parsed.multi {
                let operator = match flag.as_str() {
                    "--arg-exact" => ArgOperator::Exact,
                    "--arg-path-prefix" => ArgOperator::PathPrefix,
                    _ => ArgOperator::Prefix,
                };
                conditions.push(policy::parse_arg(value, operator)?);
            }
            let spec = RuleSpec {
                id: parsed
                    .value("--id")
                    .ok_or("policy rules need --id")?
                    .to_owned(),
                server: parsed.value("--server").map(str::to_owned),
                tool: parsed.value("--tool").map(str::to_owned),
                args: conditions,
                any_tool: parsed.flag("--any-tool"),
            };
            let rule = policy::build_rule(effect, &spec)?;
            let home = parsed.home()?;
            let _lock = PolicyLock::acquire(&home)?;
            let (original, current) = read_policy(&home)?;
            let updated = policy::add_rule(&current, rule)?;
            save_policy(&home, &original, &updated)?;
            println!("added {effect_name} rule {:?}", spec.id);
            if let Ok(saved) = praetore_core::Policy::from_json(&updated) {
                let rule_tag = format!("rule {:?}:", spec.id);
                for warning in policy::lint(&saved) {
                    if warning.starts_with(&rule_tag) {
                        println!("warning: {warning}");
                    }
                }
            }
            0
        }
    };
    println!("{}", policy::RESTART_REMINDER);
    Ok(code)
}
