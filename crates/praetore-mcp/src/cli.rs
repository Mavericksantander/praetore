//! Command-line interface (hand-parsed; the workspace has no clap).

use crate::shown::Show;
use crate::{
    gate::Mode,
    install::{self, Client, WrapTarget},
    json::JsonValue,
    receipts, relay,
    store::{self, Home, InitOutcome},
};
use rand_core::{OsRng, RngCore};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

const USAGE: &str = "praetore-mcp: put PRÆTORE in front of any stdio MCP server

Usage:
  praetore-mcp init      [--dir DIR]
  praetore-mcp wrap      [--dir DIR] [--name SERVER] [--mode observe|enforce] [--no-report]
                         -- <command> [args...]
  praetore-mcp install   [--client claude-desktop|cursor|vscode] [--config FILE] [--dir DIR]
                         [--mode observe|enforce] [--dry-run] [--yes]
  praetore-mcp uninstall [--client claude-desktop|cursor|vscode] [--config FILE] [--dry-run] [--yes]
  praetore-mcp receipts  [--dir DIR] [--tail N]
  praetore-mcp verify    [--dir DIR] [--expected-head HEX] [--expected-approval-head HEX]
  praetore-mcp dashboard [--dir DIR] [--port N] [--expected-head HEX] [--expected-approval-head HEX]
  praetore-mcp report    [--dir DIR] [--session ID | --last]
  praetore-mcp approvals [--dir DIR]
  praetore-mcp approve   <id> [--dir DIR]
  praetore-mcp reject    <id> [--dir DIR]
  praetore-mcp policy list   [--dir DIR]
  praetore-mcp policy check  [--dir DIR]
  praetore-mcp policy coverage [--dir DIR] [--server NAME] -- <command> [args...]
  praetore-mcp policy deny|require-approval|allow --id ID [--server NAME] [--tool NAME]
                         [--arg-exact KEY=VALUE]... [--arg-path-prefix KEY=/abs/path]...
                         [--arg-prefix KEY=VALUE]... [--any-tool] [--dir DIR]
  praetore-mcp policy remove --id ID [--dir DIR]

  praetore-mcp <command> --help
  praetore-mcp --version

DIR defaults to $PRAETORE_MCP_HOME, then ~/.praetore/mcp.
Keys created by `init` are LOCAL/DEV keys, including a separate approver
key. The policy written by `init` has no rules: in enforce mode every
tools/call is denied until a `policy allow` rule allows it. Observe mode
records a DENY and forwards the call; it still refuses unclassified
calls and unparseable lines that may name a safety* tool. Enforce mode
blocks DENY. A
REQUIRE_APPROVAL call is not forwarded until someone runs `approve`
for that exact call. `approve` reads a confirmation from an interactive
terminal; that check is cooperative (a process that can act as this user
can still approve). If the home cannot be loaded (e.g. no `init`), `wrap`
refuses every tools/call in both modes.

Exit codes:
  0    success (also --help and --version)
  1    the command ran and found a problem: `verify` found a failed receipt,
       `report` wrote a report that says verify failed, `policy check`
       found an invalid policy or engine, `policy coverage` found a tool
       allowed only by an allow-all rule, or `install` / `uninstall` could
       not read, parse or write a config (or was not confirmed)
  2    usage error, or the command could not run (message on stderr)
  wrap exits with the MCP server's exit code; 127 if the server cannot be
       started, 1 if the server was killed by a signal. SIGINT or SIGTERM
       to wrap ends wrap by that signal";

const INIT_HELP: &str = "Usage: praetore-mcp init [--dir DIR]

Creates LOCAL/DEV Ed25519 keys (0600), a signed authority, trust pins for
praetore-verify, a v2 policy with no rules, and the receipts journal under
DIR. The approver key is separate from the issuer, agent and attester keys.

With no rules, every tools/call is denied by default in enforce mode. Only
tools/call is evaluated: initialize, tools/list and the rest of the MCP
traffic pass, so a client can start the server and list its tools. Observe
mode records a DENY and forwards the call, but it still refuses a tools/call
the policy does not classify, a client line it cannot parse that may name a
safety* tool, and every tools/call when the home cannot be loaded (before
init, for example). Allow tools with
`praetore-mcp policy allow --id ID --server NAME --tool NAME`.

Running init again on an initialized DIR adds the approver key when it is
missing and otherwise changes nothing. If its policy still has an allow-all
rule (`allow-all-mcp-tool-calls`, written by init up to 0.3.4), init prints a
warning with the command to remove it and leaves the policy unchanged.

  --dir DIR   home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)";

const WRAP_HELP: &str =
    "Usage: praetore-mcp wrap [--dir DIR] [--name SERVER] [--mode observe|enforce] [--no-report]
                         -- <command> [args...]

Starts the stdio MCP server <command> and relays its stdio. Every tools/call
is evaluated and recorded as a signed receipt. Everything after `--` is
passed to the server unchanged (including any --help).

  --dir DIR     home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)
  --name SERVER server name used in policy rules and receipts
                (default: the command's file name)
  --mode MODE   observe (default): forward every call, record the decision
                enforce: block DENY. REQUIRE_APPROVAL is not forwarded until
                `praetore-mcp approve <id>` for that exact call
  --no-report   do not write the session report (same as `report = false`
                in DIR/config.toml)

When the session ends (the client or the server closes, or SIGINT/SIGTERM
on macOS and Linux) and it recorded at least one receipt, a report of the
session is written to DIR/reports/ as session-<start UTC>-<id>.json and
.pdf; see `praetore-mcp report --help`. The report is a view of the journal:
it changes no decision, and if it cannot be written the reason goes to
stderr and the exit code is the same.

SIGINT and SIGTERM (macOS and Linux): with the report on, wrap waits up to
300 ms for the server to end, forwards the signal to it, waits up to 2 s
more, kills it if it is still running, writes the report, and then ends by
that same signal. A second signal ends wrap at once, without the report.
With --no-report (or `report = false`) wrap installs no handler and the
signal ends it at once, as in 0.3.5. A signal that was already ignored
when wrap started stays ignored.

Exit code: the server's; 127 if it cannot be started, 1 if the server was
killed by a signal, 2 on a usage error. Ended by SIGINT or SIGTERM, wrap
terminates by that signal (no exit code).";

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

const APPROVALS_HELP: &str = "Usage: praetore-mcp approvals [--dir DIR]

Lists pending local approvals: id, server, tool, a short form of the
arguments, and when the pending call expires. Default lifetime is 10
minutes (PRAETORE_MCP_APPROVAL_TTL_SECONDS, or DIR/approvals/ttl-seconds,
an integer from 1 to 86400).

  --dir DIR   home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)";

const APPROVE_HELP: &str = "Usage: praetore-mcp approve <id> [--dir DIR]

Approves one pending call. Requires an interactive terminal: it prints a
short code and waits for that code on stdin. Without a terminal it signs
nothing. The check is cooperative. A process that can act as this user can
open a terminal and approve. It is not a guarantee that a person reviewed
the call.

The approval is signed with the local approver key, is bound to the server,
tool and canonical arguments of that pending call, expires at the pending
call's deadline, and authorizes one later matching tools/call.

  --dir DIR   home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)";

const REJECT_HELP: &str = "Usage: praetore-mcp reject <id> [--dir DIR]

Rejects one pending call. The call is not forwarded. A later attempt asks
for a new approval. The rejection is signed with the local approver key.

  --dir DIR   home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)";

const VERIFY_HELP: &str =
    "Usage: praetore-mcp verify [--dir DIR] [--expected-head HEX] [--expected-approval-head HEX]

Checks every receipt in the journal: integrity hash, attester signature,
agent intent signature, authority signature against the issuer pins at
decision time, and the praetore.mode binding. Checks the order of the
journal too: each entry carries a sequence number and the hash link of the
previous one, so an entry removed, duplicated or reordered before the last
one is reported. Prints the head (entry count and last link).

Also checks DIR/approvals/journal.jsonl when it exists: the approver
signature, that the decision is bound to the held receipt, that an
execution is inside the expiry window and bound to the same call, and that
one approval was not used twice. Homes without that file (v0.3.3 and
earlier) still verify.

  --dir DIR            home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)
  --expected-head HEX  head printed by an earlier run and kept somewhere the
                       wrapped servers cannot write: the journal must end at
                       it. Without it, entries removed at the end of the
                       journal are not detected.
  --expected-approval-head HEX
                       approval head printed by an earlier run (the line
                       `approval journal: ... head HEX`), kept the same way:
                       approvals/journal.jsonl must end at it. Without it,
                       records removed at the end of that journal, or the
                       whole file, are not detected.

Entries written by an earlier praetore-mcp version (unchained) are verified
one by one and counted apart; they may only come before the first chained
entry.

Exit code: 0 if every receipt verifies, 1 if any fails, 2 if the journal
cannot be read.";

const DASHBOARD_HELP: &str =
    "Usage: praetore-mcp dashboard [--dir DIR] [--port N] [--expected-head HEX] [--expected-approval-head HEX]

Serves a read-only page over the receipts journal at http://127.0.0.1:N/
(127.0.0.1 only, never another address). It shows what the agent is doing
now (calls waiting for approval, with the `approve` / `reject` commands to
run in a terminal, and the latest decisions) and, apart, the full log, each
receipt (full JSON, path_check, the agent, attester and authority
signatures with their key ids), the active policy's rules and the result of
the same checks `verify` runs, per receipt and for the whole journal, with
the journal head. The Sessions view lists the session reports in
DIR/reports/ (the regenerated ones grouped under the report written at
close) and downloads them from /reports/<file>; only exact report file
names inside DIR/reports/ are served. The page refreshes itself every few
seconds while it is visible. It is embedded in the binary and loads nothing
from the network. Nothing is written under DIR: no report is written,
regenerated or signed. Each refresh reads DIR again. Stop it with Ctrl-C.

Any local process of any user can open the page and read what it shows
(tool names and arguments included): run it only while you use it.

  --dir DIR            home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)
  --port N             TCP port on 127.0.0.1 (default 8787; 0 picks a free port)
  --expected-head HEX  passed to the same check as `verify --expected-head`
  --expected-approval-head HEX
                       passed to the same check as `verify --expected-approval-head`

Exit code: 2 on a usage error or if the port cannot be opened; otherwise it
runs until stopped.";

const REPORT_HELP: &str = "Usage: praetore-mcp report [--dir DIR] [--session ID | --last]

Writes a new report of one `wrap` session from the journal as it is now:
DIR/reports/session-<start UTC>-<id>.regen-<now UTC>.json and .pdf. It
writes a new pair next to the original; the report written at close is
never replaced. The new header names it in `regenerated_from`. The session
is the one named by ID (the eight characters after the start time in the
file name) or, by default and with --last, the one that closed last; only
the reports written at close are looked at. Its receipts are read from the
journal as it is now and `verify` runs again; the two journal heads shown
are the ones recorded when the session closed.

The JSON file has a header (praetore-mcp version, agent, server, mode, seq
range, both journal heads, the result of verify) and the session's receipts,
each one the journal line copied byte for byte. The PDF shows the same
session for a person: summary, calls, approvals, the result of verify, both
heads and the SHA-256 of the JSON file. If verify fails the PDF says so on
its first page and both files are still written.

The report is a view. It signs nothing and does not change the journal.
A session can be regenerated only if it wrote a report (not after
`wrap --no-report` or `report = false`).

  --dir DIR      home directory (default $PRAETORE_MCP_HOME, then ~/.praetore/mcp)
  --session ID   session id
  --last         the most recent session (default)

Exit code: 0 if the report was written and verify passed, 1 if it was
written and says verify failed, 2 if it could not be written.";

const POLICY_HELP: &str = "Usage:
  praetore-mcp policy list   [--dir DIR]
  praetore-mcp policy check  [--dir DIR]
  praetore-mcp policy coverage [--dir DIR] [--server NAME] -- <command> [args...]
  praetore-mcp policy deny|require-approval|allow --id ID [--server NAME] [--tool NAME]
                         [--arg-exact KEY=VALUE]... [--arg-path-prefix KEY=/abs/path]...
                         [--arg-prefix KEY=VALUE]... [--any-tool] [--dir DIR]
  praetore-mcp policy remove --id ID [--dir DIR]

Reads and edits DIR/policy.json. Every change is re-validated and a backup is
written first. Running MCP clients must be restarted to load a change.
--arg-path-prefix: `wrap` resolves the argument through the filesystem first;
a value that does not resolve to itself (a symlink, `.`/`..`, a missing parent)
or is ambiguous (case or Unicode normalization) matches every
DENY/REQUIRE_APPROVAL path rule on that key and no ALLOW path rule.
`policy deny|require-approval|allow` and `policy check` resolve each prefix
and warn when it resolves to another path: write resolved prefixes.

`policy coverage` starts the MCP server given after `--`, sends initialize
and tools/list (no tools/call), closes it, and prints for each tool what the
policy decides: the rule that applies or default deny, and whether a rule
depends on an argument. Tools allowed only by an allow-all rule are listed
apart. --server is the name `wrap --name` uses (default: the command's file
name). It writes nothing under DIR.

Exit code: 0 on success, 1 if `check` finds an invalid policy or engine or
`coverage` finds a tool allowed only by an allow-all rule, 2 on a usage
error, a rejected change, or a server that cannot be started or does not
answer.";

fn help_for(command: &str) -> Option<&'static str> {
    Some(match command {
        "init" => INIT_HELP,
        "wrap" => WRAP_HELP,
        "install" => INSTALL_HELP,
        "uninstall" => UNINSTALL_HELP,
        "receipts" => RECEIPTS_HELP,
        "verify" => VERIFY_HELP,
        "dashboard" => DASHBOARD_HELP,
        "report" => REPORT_HELP,
        "approvals" => APPROVALS_HELP,
        "approve" => APPROVE_HELP,
        "reject" => REJECT_HELP,
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
        "dashboard" => cmd_dashboard(rest),
        "report" => cmd_report(rest),
        "approvals" => cmd_approvals(rest),
        "approve" => cmd_decide(rest, crate::approvals::HumanOutcome::Approve),
        "reject" => cmd_decide(rest, crate::approvals::HumanOutcome::Reject),
        "policy" => cmd_policy(rest),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(0)
        }
        "-V" | "--version" | "version" => {
            println!("praetore-mcp {}", crate::report::BUILD_VERSION);
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
    let outcome = store::init(&home)?;
    match outcome {
        InitOutcome::AlreadyInitialized => {
            println!(
                "praetore-mcp: {} is already initialized; nothing was changed.",
                home.root.shown()
            );
        }
        InitOutcome::ApproverKeyAdded => {
            println!(
                "praetore-mcp: added a local approver key to {}. Existing keys, authority, policy and receipts were not changed.",
                home.root.shown()
            );
            println!("    {}", home.approver_key().shown());
            println!("    {}", home.approver_pin().shown());
        }
        InitOutcome::Created => {
            println!("praetore-mcp: initialized {}", home.root.shown());
            println!();
            println!("  LOCAL/DEV keys (0600, never printed):");
            println!("    {}", home.issuer_key().shown());
            println!("    {}", home.agent_key().shown());
            println!("    {}", home.attester_key().shown());
            println!("    {}", home.approver_key().shown());
            println!("  trust files for third-party verification (praetore-verify formats):");
            println!("    {}", home.issuer_pins().shown());
            println!("    {}", home.attester_pin().shown());
            println!("    {}", home.approver_pin().shown());
            println!("  signed authority: {}", home.authority().shown());
            println!(
                "  policy (v2, no rules: default deny): {}",
                home.policy().shown()
            );
            println!("  receipts journal: {}", home.receipts_dir().shown());
            println!();
            println!("  These are LOCAL/DEV keys for one machine. They are not a production PKI.");
            println!(
                "  In enforce mode every tools/call is denied unless a rule allows it. Observe"
            );
            println!("  mode records a DENY and forwards the call, but still refuses unclassified");
            println!("  calls. To allow a tool:");
            let program = crate::commands::program();
            let dir = dir_suffix(&home);
            println!("    {program} policy allow --id ID --server NAME --tool NAME{dir}");
            println!("  To see what the policy decides for each tool of a server:");
            println!("    {program} policy coverage --server NAME{dir} -- <server command>");
            println!("  Next: {program} install --dry-run{dir}");
        }
    }
    if !matches!(outcome, InitOutcome::Created) {
        warn_allow_all(&home);
    }
    Ok(0)
}

/// An existing home may still have the allow-all rule `init` used to write.
/// It is left in place; the warning says how to remove it.
fn warn_allow_all(home: &Home) {
    let Ok(text) = fs::read_to_string(home.policy()) else {
        return;
    };
    let Ok(policy) = praetore_core::Policy::from_json(&text) else {
        return;
    };
    for rule in policy
        .rules
        .iter()
        .filter(|rule| crate::policy::is_allow_all(rule))
    {
        let id = crate::proxy::display_safe(&rule.id);
        let program = crate::commands::program();
        let dir = dir_suffix(home);
        println!(
            "praetore-mcp: warning: {} has the allow-all rule {id:?}: every tools/call that no other rule matches is ALLOWED, including tools no rule names. init now writes a default-deny policy but did not change this one. To deny by default, allow the tools you want (`{program} policy allow --id ID --server NAME --tool NAME{dir}`; `{program} policy coverage{dir} -- <server command>` lists what each tool gets), then run:\n    {program} policy remove --id {id}{dir}",
            home.policy().shown(),
        );
    }
}

/// ` --dir DIR`, so a printed command acts on the same home whatever
/// PRAETORE_MCP_HOME is where it runs. DIR is absolute and quoted
/// ([`crate::commands`]).
fn dir_suffix(home: &Home) -> String {
    format!(" --dir {}", crate::commands::dir(&home.root))
}

pub(crate) fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name.len() <= 128
        && name == name.trim()
        && !name.chars().any(char::is_control)
}

/// The server name `wrap` uses without `--name`: the command's file name.
fn default_server_name(command: &str) -> String {
    let file = command.rsplit(['/', '\\']).next().unwrap_or(command);
    file.strip_suffix(".exe").unwrap_or(file).to_owned()
}

fn cmd_wrap(args: &[String]) -> Result<i32, String> {
    let parsed = parse(
        args,
        &["--dir", "--name", "--mode"],
        &[install::ORIGINAL_ARGS_ABSENT, "--no-report"],
        true,
    )?;
    let Some((command, command_args)) = parsed.rest.split_first() else {
        return Err("wrap needs `-- <command> [args...]`".into());
    };
    let name = parsed
        .value("--name")
        .map_or_else(|| default_server_name(command), str::to_owned);
    if !valid_server_name(&name) {
        return Err(format!(
            "invalid server name {name:?} (1-128 printable characters, not starting with '-')"
        ));
    }
    let home = parsed.home()?;
    let (config, warnings) = crate::config::load(&home);
    for warning in warnings {
        eprintln!("praetore-mcp: warning: {warning}");
    }
    // Fail closed at startup: a bad approval window must not wait for the
    // first held call to show up, and must never fall back to a default.
    crate::approvals::approval_ttl(&home)
        .map_err(|error| format!("approval TTL: {error}; wrap did not start"))?;
    Ok(relay::run(relay::WrapOptions {
        home,
        name,
        mode: parsed.mode()?,
        command: command.clone(),
        args: command_args.to_vec(),
        report: config.report && !parsed.flag("--no-report"),
    }))
}

fn confirm(path: &Path, yes: bool) -> bool {
    if yes {
        return true;
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "praetore-mcp: not modifying {} without confirmation; re-run with --yes",
            path.shown()
        );
        return false;
    }
    eprint!("Apply these changes to {}? [y/N] ", path.shown());
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
                        println!("  ({}: no config at {})", client.name(), path.shown());
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
                    "praetore-mcp: note: {} is not initialized yet; run `{}` before installing",
                    home.root.shown(),
                    crate::commands::command("init", &home.root)
                );
            } else {
                return Err(format!(
                    "{} is not initialized; run `{}` first",
                    home.root.shown(),
                    crate::commands::command("init", &home.root)
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
                eprintln!("praetore-mcp: cannot read {}: {error}", path.shown());
                code = 1;
                continue;
            }
        };
        let mut doc = match JsonValue::parse(&original) {
            Ok(doc) => doc,
            Err(error) => {
                eprintln!(
                    "praetore-mcp: {} is not strict JSON ({error}); comments/trailing commas are not supported, file NOT modified",
                    path.shown()
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
                    format!(" {} (symlink target)", real.shown())
                },
                backup.shown(),
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
    let home = parsed.home()?;
    let lines = receipts::read_journal(&home)?;
    if lines.is_empty() {
        println!("no receipts yet");
        return Ok(0);
    }
    let status = crate::approvals::status_by_evidence(&home)?;
    print!("{}", receipts::render_table(&lines, tail, &status));
    Ok(0)
}

fn cmd_verify(args: &[String]) -> Result<i32, String> {
    let parsed = parse(
        args,
        &["--dir", "--expected-head", "--expected-approval-head"],
        &[],
        false,
    )?;
    let home = parsed.home()?;
    let report = receipts::verify_journal_with(
        &home,
        receipts::ExpectedHeads {
            receipts: parsed.value("--expected-head"),
            approvals: parsed.value("--expected-approval-head"),
        },
    )?;
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
        "checked: integrity hash, attester signature ({}), agent intent signature, authority signature against {} at decision time, praetore.mode binding, journal order (seq and hash link)",
        home.attester_pin().shown(),
        home.issuer_pins().shown()
    );
    match report.head {
        Some(head) => println!(
            "journal head: {} chained entries present, next seq {}, head {} ({} unchained earlier entries); keep it outside this machine and pass it as --expected-head to detect entries removed at the end",
            report.chained, head.seq, head.prev, report.unchained
        ),
        None => println!(
            "journal head: none ({} chained, {} unchained entries)",
            report.chained, report.unchained
        ),
    }
    println!("observe receipts record a decision that was NOT enforced.");
    match report.approval_head {
        Some(head) => println!(
            "approval journal: {} decision(s), {} execution(s), head {head}; keep it outside this machine and pass it as --expected-approval-head to detect records removed at the end",
            report.approval_decisions, report.approval_executions
        ),
        None => println!("approval journal: none"),
    }
    println!(
        "approval checks: approver signature, binding to the held call, expiry, one use per approval (an approval whose execution and forwarded receipt are both cut from the end of the journals can run again; pass both saved heads to detect it). An observe REQUIRE_APPROVAL receipt means enforce would ask; it is not a hold."
    );
    Ok(if report.failures.is_empty() { 0 } else { 1 })
}

fn cmd_dashboard(args: &[String]) -> Result<i32, String> {
    let parsed = parse(
        args,
        &[
            "--dir",
            "--port",
            "--expected-head",
            "--expected-approval-head",
        ],
        &[],
        false,
    )?;
    let port = match parsed.value("--port") {
        None => crate::dashboard::DEFAULT_PORT,
        Some(value) => value
            .parse::<u16>()
            .map_err(|_| format!("--port must be a number from 0 to 65535, got {value:?}"))?,
    };
    let expected_head = parsed.value("--expected-head");
    if let Some(head) = expected_head
        && praetore_core::journal_chain::ChainLink::from_hex(head).is_none()
    {
        return Err("--expected-head must be 64 lowercase hex characters".into());
    }
    let expected_approval_head = parsed.value("--expected-approval-head");
    if let Some(head) = expected_approval_head
        && !(head.len() == 64 && head.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    {
        return Err("--expected-approval-head must be 64 lowercase hex characters".into());
    }
    let home = parsed.home()?;
    let listener = crate::dashboard::bind(port)?;
    let address = listener
        .local_addr()
        .map_err(|e| format!("cannot read the listening address: {e}"))?;
    println!("praetore-mcp dashboard (read-only): http://{address}/");
    println!("home: {}", home.root.shown());
    println!("listening on 127.0.0.1 only; stop with Ctrl-C");
    let expected = receipts::ExpectedHeads {
        receipts: expected_head,
        approvals: expected_approval_head,
    };
    crate::dashboard::serve(&listener, &home, expected, None)?;
    Ok(0)
}

fn cmd_report(args: &[String]) -> Result<i32, String> {
    use crate::report::{self, Selector};
    let parsed = parse(args, &["--dir", "--session"], &["--last"], false)?;
    let selector = match (parsed.value("--session"), parsed.flag("--last")) {
        (Some(_), true) => return Err("--session and --last cannot be used together".into()),
        (Some(id), false) if report::valid_session_id(id) => Selector::Session(id.to_owned()),
        (Some(id), false) => {
            return Err(format!(
                "--session must be the 8 lowercase hex characters at the end of the report file name, got {id:?}"
            ));
        }
        (None, _) => Selector::Last,
    };
    let generated = report::regenerate(&parsed.home()?, &selector)?;
    println!("{}", generated.json.shown());
    println!("{}", generated.pdf.shown());
    if generated.verify_passed {
        println!("verify passed");
        Ok(0)
    } else {
        println!("verify FAILED: the report says so on its first page");
        Ok(1)
    }
}

fn cmd_approvals(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["--dir"], &[], false)?;
    let home = parsed.home()?;
    let pending = crate::approvals::pending_decisions(&home, time::OffsetDateTime::now_utc())?;
    if pending.is_empty() {
        println!("no pending approvals");
        return Ok(0);
    }
    for (item, decision) in pending {
        println!("id         {}", item.approval_id);
        println!("server     {}", crate::proxy::display_safe(&item.server));
        println!("tool       {}", crate::proxy::display_safe(&item.tool));
        println!("expires    {}", expiry_line(&item.expiry));
        println!("arguments  {}", item.arguments_preview);
        match decision {
            crate::approvals::PendingDecision::Open(commands) => {
                println!("approve    {}", commands.approve);
                println!("reject     {}", commands.reject);
            }
            crate::approvals::PendingDecision::Expired => {
                println!("{}", crate::approvals::EXPIRED_PENDING);
            }
            crate::approvals::PendingDecision::Decided(outcome) => {
                println!(
                    "decided: {outcome} already; {}",
                    crate::approvals::DECIDED_PENDING
                );
            }
        }
        println!();
    }
    Ok(0)
}

/// An RFC 3339 expiry as `approvals` and `approve` print it: local time,
/// UTC and what is left (see [`crate::when`]).
#[expect(clippy::disallowed_methods, reason = "display only")]
fn expiry_line(expiry: &crate::approvals::Expiry) -> String {
    expiry
        .at()
        .map_or_else(|| expiry.text().to_owned(), crate::when::expiry_now)
}

fn cmd_decide(args: &[String], outcome: crate::approvals::HumanOutcome) -> Result<i32, String> {
    let (id, dir) = parse_decision_args(args)?;
    let home = store::resolve_home(dir.as_deref()).map(Home::new)?;
    if !home.is_initialized() {
        return Err(format!(
            "{} is not initialized; run `{}`",
            home.root.shown(),
            crate::commands::command("init", &home.root)
        ));
    }
    if outcome == crate::approvals::HumanOutcome::Approve && !interactive_terminal() {
        return Err(
            "`approve` needs an interactive terminal (stdin and stderr are not both terminals). Nothing was signed. This check is cooperative: a process that can open a terminal as this user can still approve, and it is not a guarantee that a person reviewed the call."
                .into(),
        );
    }
    let shown = if outcome == crate::approvals::HumanOutcome::Approve {
        Some(confirm_approval(&home, &id)?)
    } else {
        None
    };
    let decided = crate::approvals::decide(&home, &id, outcome, shown.as_ref())?;
    println!(
        "{} {} (approver {})",
        decided.outcome, decided.approval_id, decided.approver_key_id
    );
    println!(
        "server {} tool {} expires {}",
        crate::proxy::display_safe(&decided.server),
        crate::proxy::display_safe(&decided.tool),
        decided.expiry.text()
    );
    println!("expires    {}", expiry_line(&decided.expiry));
    if outcome == crate::approvals::HumanOutcome::Approve {
        println!("The agent can retry this exact call once before it expires.");
        #[expect(clippy::disallowed_methods, reason = "display only")]
        let before = decided.expiry.at().map_or_else(
            || decided.expiry.text().to_owned(),
            crate::when::clock_local,
        );
        println!("Now run the agent again before {before} so the call runs once.");
    } else {
        println!("The call will not be forwarded. A new attempt asks for approval again.");
    }
    Ok(0)
}

fn interactive_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn confirm_approval(home: &Home, id: &str) -> Result<crate::approvals::PendingCall, String> {
    let pending = crate::approvals::pending_call(home, id)?;
    // An expired call cannot be approved: say so before asking for the code.
    // `decide` checks again, in case it expires while the code is typed.
    if pending
        .expiry
        .is_expired_at(time::OffsetDateTime::now_utc())
    {
        return Err(crate::approvals::expired_message(
            id,
            &pending.expiry,
            crate::approvals::HumanOutcome::Approve,
        ));
    }
    let show = praetore_core::display::escape_for_display;
    eprintln!("server     {}", show(&pending.server));
    eprintln!("tool       {}", show(&pending.tool));
    eprintln!("expires    {}", expiry_line(&pending.expiry));
    eprintln!("arguments  {}", show(&pending.arguments_canonical));
    let code = confirmation_code();
    eprintln!("Type {code} to approve {id}.");
    eprintln!(
        "This asks for a person at the terminal. It is cooperative: a process that can act as this user can still approve."
    );
    eprint!("confirmation: ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| format!("cannot read confirmation: {e}"))?;
    if answer.trim() != code {
        return Err("confirmation did not match; nothing was signed".into());
    }
    Ok(pending)
}

fn confirmation_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut raw = [0u8; 6];
    OsRng.fill_bytes(&mut raw);
    raw.iter()
        .map(|byte| ALPHABET[(*byte as usize) % ALPHABET.len()] as char)
        .collect()
}

/// `<id>` plus optional `--dir DIR`, in either order.
fn parse_decision_args(args: &[String]) -> Result<(String, Option<PathBuf>), String> {
    let mut id = None;
    let mut dir = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dir" => {
                let value = args.get(index + 1).ok_or("--dir needs a value")?.clone();
                if dir.replace(PathBuf::from(value)).is_some() {
                    return Err("--dir given twice".into());
                }
                index += 2;
            }
            "-h" | "--help" => return Err("pass --help before the approval id".into()),
            other if other.starts_with('-') => {
                return Err(format!("unexpected argument {other:?}"));
            }
            other => {
                if id.replace(other.to_owned()).is_some() {
                    return Err("approval id given twice".into());
                }
                index += 1;
            }
        }
    }
    let id = id.ok_or("approve/reject needs an approval id")?;
    Ok((id, dir))
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
                "another praetore-mcp policy command is running on this home (lock {}); if none is, remove that file",
                path.shown()
            )),
            Err(error) => Err(format!("cannot create lock {}: {error}", path.shown())),
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
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.shown()))?;
    let policy = praetore_core::Policy::from_json(&text).map_err(|e| {
        format!(
            "{} is invalid ({e}); fix it (see `{}`) or restore a backup",
            path.shown(),
            crate::commands::command("policy check", &home.root)
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
        home.policy().shown(),
        backup.shown()
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
                .map_err(|e| format!("cannot read {}: {e}", path.shown()))?;
            match praetore_core::Policy::from_json(&text).and_then(|p| p.digest().map(|d| (p, d))) {
                Err(error) => {
                    println!("INVALID {}: {error}", path.shown());
                    if matches!(
                        error,
                        praetore_core::PraetoreError::PolicyFormatUnsupported { found: 1, .. }
                    ) {
                        println!(
                            "hint: policy format 1 was written before G7, and until it is migrated every tool call is refused. Add \"format_version\": 2 and \"action_classes\": {{\"{}\": \"Mission\"}}, or run `praetore policy classify --policy {}` to propose the table (see docs/policy-language.md); the digest changes, so receipts already written keep verifying only against the old document.",
                            crate::store::ACTION_TYPE,
                            path.shown()
                        );
                    }
                    1
                }
                Ok((parsed_policy, digest)) => {
                    let warnings = policy::lint(
                        &parsed_policy,
                        &crate::commands::program(),
                        &dir_suffix(&home),
                    );
                    for warning in &warnings {
                        println!("warning: {warning}");
                    }
                    // Build the same engine `wrap` builds, so key/pin/policy
                    // problems surface here instead of as refused calls.
                    let engine = if home.is_initialized() {
                        crate::gate::Gate::load(&home, Mode::Observe).map(|_| ())
                    } else {
                        Err(format!("{} is not initialized", home.root.shown()))
                    };
                    match engine {
                        Ok(()) => {
                            println!(
                                "OK {} policy {} v{}: {} rule(s), digest {digest}, {} warning(s); HighAssurance engine starts",
                                path.shown(),
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
        "coverage" => {
            let parsed = parse(rest, &["--dir", "--server"], &[], true)?;
            let Some((command, command_args)) = parsed.rest.split_first() else {
                return Err("policy coverage needs `-- <command> [args...]`".into());
            };
            let server = parsed
                .value("--server")
                .map_or_else(|| default_server_name(command), str::to_owned);
            if !valid_server_name(&server) {
                return Err(format!(
                    "invalid server name {server:?} (1-128 printable characters, not starting with '-')"
                ));
            }
            let home = parsed.home()?;
            let (_, policy) = read_policy(&home)?;
            let tools = crate::coverage::list_tools(command, command_args)?;
            let report = policy::coverage(&policy, &server, &tools);
            print!(
                "{}",
                policy::render_coverage(
                    &policy,
                    &server,
                    &report,
                    &crate::commands::program(),
                    &dir_suffix(&home)
                )
            );
            // Read only: no restart reminder.
            return Ok(if report.iter().any(|item| item.only_allow_all) {
                1
            } else {
                0
            });
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
                    "unknown policy subcommand {effect_name:?} (list, check, coverage, deny, require-approval, allow, remove)"
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
                let program = crate::commands::program();
                let dir = dir_suffix(&home);
                for warning in policy::lint(&saved, &program, &dir) {
                    if warning.starts_with(&rule_tag) {
                        println!("warning: {warning}");
                    }
                }
                if let Some(warning) = policy::allow_all_warning(&saved, &program, &dir) {
                    println!("warning: {warning}");
                }
            }
            0
        }
    };
    println!("{}", policy::RESTART_REMINDER);
    Ok(code)
}
