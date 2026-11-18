# praetore-mcp: guide for external developers

This guide is for someone trying `praetore-mcp` for the first time on their
own machine. It says what the tool does today, what it does not do, how to
check each claim yourself, and what to do when something goes wrong. The
full reference is the [README](README.md).

## What it does

`praetore-mcp` sits between an MCP client (Claude Desktop, Cursor, VS Code)
and a stdio MCP server. For every `tools/call` that goes **through a wrapped
MCP server**, it evaluates your policy with the PRÆTORE engine and writes an
Ed25519-signed receipt. In `enforce` mode, DENY and REQUIRE_APPROVAL calls
are not forwarded. A DENY is an MCP tool error whose text is
`Denied by PRÆTORE. Evidence id: ...`. The rule id is not in that text. It
is on stderr and in `praetore-mcp receipts`. A REQUIRE_APPROVAL call is not
forwarded until a person approves that exact call from a terminal
(`praetore-mcp approve`).

What was run end to end (macOS arm64, 2026-10-30): `cargo install --git`,
`init`, a `deny` rule for `write_file`, `install --mode enforce` into the real
Claude Desktop and Cursor apps, in front of
`@modelcontextprotocol/server-filesystem@2.1.0`. Reads were allowed,
`write_file` was refused in both apps with the evidence id shown in the chat,
the file was not created, and `praetore-mcp verify` checked every receipt.
Not run: Windows, Linux desktop apps, VS Code, other MCP servers. That
macOS arm64 run on 2026-10-30 did not include local approval.

## Ten-minute walkthrough

### Without Rust

Download one archive and `SHA256SUMS` from the published
[v0.3.6 release](https://github.com/Mavericksantander/praetore/releases/tag/v0.3.6)
(commit `27ceddbbd295162ca351ea5dfa47fe8bb37315a3`). That release is not a
build of the current `main` branch. You do not clone the repository.

| Machine | Archive |
| --- | --- |
| macOS Apple silicon | `praetore-mcp-v0.3.6-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `praetore-mcp-v0.3.6-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `praetore-mcp-v0.3.6-x86_64-unknown-linux-gnu.tar.gz` |

v0.3.6 has no Windows binary and no Linux ARM binary, and there is no brew
installer. Check the archive before you open it. On macOS:
`shasum -a 256 -c SHA256SUMS --ignore-missing`. On Linux:
`sha256sum -c SHA256SUMS --ignore-missing`. The published digests are in
[Install from the v0.3.6 release](../../docs/install-prebuilt.md). If
`SHA256SUMS` does not match that list, stop. Then `tar -xzf` the archive.
It contains a directory of the same name with `praetore-mcp`, `LICENSE` and
`NOTICE`.

Put `praetore-mcp` on your `PATH` before you run `install`. We recommend
`~/.local/bin`. From the directory the archive was extracted to, with
`<dir>` that directory's absolute path:

```sh
mkdir -p ~/.local/bin && ln -sf <dir>/praetore-mcp ~/.local/bin/praetore-mcp && hash -r
```

If `~/.local/bin` is not on your `PATH` yet, add it in your shell profile.
`install` records the absolute path of the binary that is running, with
symlinks resolved. With the link above that is the file in the extracted
directory, `<dir>/praetore-mcp`, not `~/.local/bin/praetore-mcp`. Keep
that directory: if you delete it, the client config and the commands
praetore-mcp printed point at a file that no longer exists. Moving or
replacing that file later leaves the client config pointing at the old
path. Run `install` again after you move it.

Commands that praetore-mcp prints for you to copy (`approve` and `reject`
for a held call, in the tool error, in `approvals` and in the dashboard;
`init` and the `policy` suggestions) start with the real absolute path of
the running binary (symlinks resolved, so `<dir>/praetore-mcp` with the
link above) and pass `--dir` as an absolute path, both in single quotes
for a POSIX shell. They run as printed even when the binary is not on your
`PATH`. If the binary's path cannot be read, they start with
`praetore-mcp`, which needs it on `PATH`. On Windows they are written as
before.

A path or a name that holds a control character (an escape sequence,
`\r`, `\n`) or a zero-width or bidi character is never printed as is. In
messages, in the dashboard and in the PDF report it is written as
`\u{..}`: a home named `a<ESC>[2Kb` shows as `a\u{1b}[2Kb`. In a
command to copy, such a path is written as `$'...'` with `\xHH` escapes,
which bash and zsh read back as the exact path.

Checking the Sigstore signature of `SHA256SUMS` is optional. It needs
`cosign`. For v0.3.6, pass
`--certificate-github-workflow-sha 27ceddbbd295162ca351ea5dfa47fe8bb37315a3`
so the check does not need a clone. See
[Release artifact integrity](../../docs/operations.md#release-artifact-integrity).
The required check is the digest command above.

The commands below are the from-source path. They need Rust. Skip them if
you installed the release binary.

```sh
cargo install --git https://github.com/Mavericksantander/praetore praetore-mcp --locked
```

`cargo install` puts the binary in `~/.cargo/bin` (or `--root`). `install`
records that absolute path too.

### First server, observe, then enforce

```sh
praetore-mcp init
```

Add one stdio server before `install`, on a test folder that holds no real
data. Use the absolute path of that folder (`cd` there and `pwd -P`). Do
not point `@modelcontextprotocol/server-filesystem` at your home directory
or at a project folder, and do not write `~` in the JSON. Use the absolute
path from `command -v npx` as `command`. If that prints nothing, Node is
missing. This guide does not install Node. npm may print `EBADENGINE`
because `@modelcontextprotocol/server-filesystem@2.3.0` declares
`node >= 24`. That warning is from npm. If the server still answers the
tool call, continue. If it does not start, stop. Do not install or
upgrade Node.

Cursor, `~/.cursor/mcp.json` (Claude Desktop uses the same `mcpServers`
shape in `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/absolute/path/to/npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2.3.0", "/absolute/path/to/test-dir"]
    }
  }
}
```

VS Code's user `mcp.json` (`~/Library/Application Support/Code/User/mcp.json`
on macOS; on Linux, `$XDG_CONFIG_HOME/Code/User/mcp.json` when
`XDG_CONFIG_HOME` is set, otherwise `~/.config/Code/User/mcp.json`) uses
`servers` and `"type": "stdio"`:

```json
{
  "servers": {
    "filesystem": {
      "type": "stdio",
      "command": "/absolute/path/to/npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2.3.0", "/absolute/path/to/test-dir"]
    }
  }
}
```

`install` and `uninstall` ask `Apply these changes to <file>? [y/N]` only
when stdin is a terminal. Without a terminal they exit 1 and print
`not modifying <file> without confirmation; re-run with --yes`, and they
change nothing. Read the dry-run, then apply observe mode. Substitute
`claude-desktop` or `vscode` for `cursor` if that is your client.

```sh
praetore-mcp install --client cursor --mode observe --dry-run
praetore-mcp install --client cursor --mode observe --yes
```

Run the dry-run again. It should say
`skipped: already wrapped by praetore-mcp` and `nothing to change`
(exit 0). The config entry's `command` is the absolute path of the binary,
and its args start with `wrap`. Quit the client completely and open it
again. A running client keeps the old config and the old policy.

In a **chat** (see "Limits" below for why it matters), ask the model to
list the test directory with the wrapped server. Then:

```sh
praetore-mcp receipts --tail 5
praetore-mcp verify
```

`OK 0 receipts` means the journal is empty. It does not mean a server was
wrapped.

**From 0.3.5, the policy `init` writes is default deny.** It has no rules
and no `allow-all-mcp-tool-calls` rule. In enforce mode every `tools/call`
that no rule allows is denied, including tools you have not looked at and
tools a server adds later. Observe mode forwards a DENY instead of blocking
it, so the observe step above works with no rules: the receipts show `DENY`
with no rule id. Observe still refuses what both modes refuse (see
"Limits", item 6). `init` needs no rule for the client to start the server or list
its tools: only `tools/call` is evaluated. `init` in v0.3.4 and earlier
wrote an allow-all rule instead (`allow-all-mcp-tool-calls`); see "A home
from v0.3.4" below.

Allow the tools you want, one rule per tool, and add one deny rule for the
server named `filesystem`. The deny rule is not needed for default deny; it
puts a rule id on the `write_file` receipt. A policy change is loaded when
`wrap` starts, so restart the client after this. The `policy` command
prints that reminder. The published v0.3.4 release can hold a
REQUIRE_APPROVAL call. That optional step is after the switch to enforce,
below. Do not add it with these rules. In observe the call is not held.

```sh
praetore-mcp policy allow --id allow-list --server filesystem --tool list_directory
praetore-mcp policy allow --id allow-read --server filesystem --tool read_text_file
praetore-mcp policy deny --id first-rule --server filesystem --tool write_file
praetore-mcp policy check
```

See what the policy decides for every tool the server lists. `policy
coverage` starts the server with the command after `--`, sends
`initialize` and `tools/list`, closes it, and writes nothing under the
home. Use the same command and test folder as in the client config. It is
in 0.3.5. It is not in v0.3.4.

```sh
praetore-mcp policy coverage --server filesystem -- /absolute/path/to/npx -y @modelcontextprotocol/server-filesystem@2.3.0 /absolute/path/to/test-dir
```

On `@modelcontextprotocol/server-filesystem@2.3.0` it lists 16 tools:
`list_directory` and `read_text_file` are `ALLOW`, `write_file` is `DENY`
by `first-rule`, and the other 13 (`append_file`, `copy_file`, `edit_file`,
`move_file` and the rest) are `DENY` by `default deny`. Below the table,
each of those 13 has its `policy allow` line. Run only the lines for tools
you want to allow: each one allows every call to that tool in enforce
mode.

Restart the client, then ask for `write_file` on the test folder. In
observe the file is still written, and `praetore-mcp receipts --tail 5`
shows `DENY` and `first-rule`.

To switch that observe install to enforce, uninstall and install again.
`install --mode enforce` on an entry that is already wrapped prints
`nothing to change` and exits 0. The mode already in the config stays.

```sh
praetore-mcp uninstall --client cursor --yes
praetore-mcp install --client cursor --mode enforce --dry-run
praetore-mcp install --client cursor --mode enforce --yes
```

Read the dry-run before `--yes`. It must show `wrap` with `--mode enforce`.
Restart the client. In enforce, `list_directory` and `read_text_file` are
forwarded, every other tool is refused, and `write_file` is refused and the
file is not written. The client text is `Denied by PRÆTORE. Evidence id: ...`. The rule
id is in `praetore-mcp receipts`, in the `DENY` / `first-rule` row, with
mode `enforce`. You can instead edit `--mode` in the client config and
restart. `install` does not rewrite `--mode` while the entry is already
wrapped.

```sh
praetore-mcp receipts --tail 5
praetore-mcp verify    # OK N receipts: N verified, 0 failed; prints the journal head
```

The v0.3.3 `praetore-mcp verify` does not read 0.3.4 receipts. A 0.3.4
journal line is `{"seq","prev","evidence"}`. v0.3.3 reads each line as a
bare evidence document. This release's `praetore-mcp verify` still reads a
v0.3.3 journal: those lines are unchained and may only come before the
first chained entry.

### A home from v0.3.4

A home created by `init` in v0.3.4 or earlier has the rule
`allow-all-mcp-tool-calls`. It allows every `tools/call` that no other rule
matches. DENY rules for some tools then leave every other tool allowed: in
a real run with that rule and DENY rules per tool, `copy_file` and
`append_file` of `@modelcontextprotocol/server-filesystem@2.3.0` were
allowed because no rule named them.

With the v0.3.4 binary nothing warns about it. Running `init` again prints
"already initialized; nothing was changed" and no warning. `policy check`
does not warn about the allow-all rule. `policy coverage` does not exist
(exit code 2). To move to default deny with v0.3.4, add an ALLOW rule for
each tool you need, remove the allow-all rule, then restart the client:

```sh
praetore-mcp policy allow --id ID --server NAME --tool NAME
praetore-mcp policy remove --id allow-all-mcp-tool-calls
```

From 0.3.5 there are warnings, none of them in v0.3.4:

- `init` run again on such a home prints a warning with the `policy remove`
  command (not in v0.3.4);
- `policy check` warns when an allow-all rule sits next to DENY rules for
  specific tools (not in v0.3.4);
- `policy coverage` lists the tools that only the allow-all rule allows,
  with exit code 1 (not in v0.3.4).

### Optional: local approval

Optional, after the install is in enforce, and only for the test server
named `filesystem`. In observe a REQUIRE_APPROVAL call is not held. Add
the rule, restart the client, and ask to create a directory in the test
folder (`~/praetore-test` when that is the folder you created) with the
`create_directory` tool of `filesystem`. The call is held.

```sh
praetore-mcp policy require-approval --id approve-mkdir --server filesystem --tool create_directory
praetore-mcp approvals
```

`approvals` lists the pending call. Run `approve` yourself in a terminal.
An assistant must not run it. `approve` needs an interactive terminal
(stdin and stderr are both terminals) and the confirmation code you type.
Without a terminal it signs nothing.

```sh
praetore-mcp approvals
praetore-mcp approve <id>
```

After you approve, ask for the same call again. It is forwarded once.
`approve` ends with the time to retry before, for example
`Now run the agent again before 20:34 (local time) / 23:34 UTC so the call
runs once.` `approvals`, `approve` and the dashboard show the expiry in
local time with UTC beside it and the time left
(`2026-11-15 20:34:40 local time (UTC-03:00) / 2026-11-15 23:34:40 UTC (in
9 min 40 s)`). `approve` on an expired call signs nothing and says so
before it asks for the code: `this approval expired at 20:34 (local time)
/ 23:34 UTC; run the agent again so the call is held again, then approve
the new id.` Its exit code is 2, as for every refused `approve`. In the
dashboard, a call that was approved but not retried before the approval
expired is marked expired, apart from one that was approved and executed.
A held call nobody decided before it expired reads Expired (Vencida) in
every view, and is no longer listed to decide: `approvals` prints
`expired: run the agent again so the call is held again` for it in place
of the `approve` and `reject` commands. If an `approve` or `reject` stopped
after it signed the decision and before it removed the pending file,
`approvals` prints `decided: <outcome> already; ...` for that id and no
commands; holding the same call again removes the file.
`praetore-mcp reject <id>` records a rejection, and that call is not
forwarded. A pending call expires after 10 minutes by default. The
terminal check is cooperative: a process that can act as this user can
open a terminal and approve. It is not a guarantee that a person reviewed
the call. Cutting or deleting `approvals/journal.jsonl` alone does not
let a used approval run again; cutting the end of the receipts journal as
well does, and only a saved head finds it (point 3 below). A DENY rule on the same tool wins: the call is
refused and approval is not asked. Limits of that flow are in point 3
below. The evidence id in the chat matches the `EVIDENCE ID`
column. To undo:
`praetore-mcp uninstall --client cursor --yes`, or restore the
`.praetore-backup-*` file next to the config, then restart the client.

If `wrap` writes the receipt of an approved call and then cannot write
its execution record (a crash, a full disk, `approvals/journal.jsonl` not
writable), the call is not forwarded. From then on `verify` reports that
receipt, every time, with `has no execution of it for that receipt` and
exit code 1. The approval is spent: the same call is held again under a
new pending id. Fix the disk or the file mode, ask for the call again,
and approve the new id. The old failure stays in `verify`; write down why
it happened next to the heads you keep.

### Looking at the receipts in a browser

```sh
praetore-mcp dashboard            # http://127.0.0.1:8787/
praetore-mcp dashboard --port 0   # a free port, printed at startup
```

`dashboard` serves a read-only page over `receipts/*.jsonl` on 127.0.0.1
only. It is in 0.3.5. It is not in v0.3.4. There is no option to listen on
another address. Stop it with Ctrl-C. The page has five views. Each mark
it draws stands for a value in a receipt, in a pending approval file or
in the result of `verify`; nothing is drawn that PRÆTORE does not record.

- **Home**: the agent id and the servers from the 40 latest receipts, the mode
  (enforce, observe, or both with their counts), the verification result
  (OK with the number of receipts, or the first failure, or the error when
  the journal cannot be read) and three counts: ALLOW, DENY and pending
  calls.
- **Live**: the 8 newest receipts as a drawing. The agent is a line on the
  left; each call is a box with its tool, server, local time and UTC. A
  call that was allowed reaches its box. A denied call stops at a red bar
  with what decided it: the rule id, `default deny: no rule allows it`, or
  the engine check. In observe mode the bar is only outlined, since the
  call went through. A call waiting for approval stops at an amber dashed
  bar marked "pending, notice not signed, not checked by verify", with the
  `approve` and `reject` commands to run in a terminal, as the server
  writes them (absolute binary path and `--dir`); the copy button copies
  the `approve` line exactly as shown. A
  receipt that `verify` rejects is marked, with the reason `verify` gives,
  over up to three lines in the drawing and in the list; a longer one
  continues in the receipt detail. A call that arrives while the page is
  open is scanned in; nothing moves when a read of the journal finds
  nothing new.
- **Chain**: the receipts in seq order, joined by the `prev` hash link,
  with the decision of each in the same colors. Where `verify` fails, the
  link is drawn cut and the reason is written next to it. The filters
  (decision, tool, time range, text) run over the whole journal on the
  server, 100 receipts per page, newest first; the receipts outside the
  page are drawn as one node each side that opens the next page, and only
  the rows on screen are drawn.
- **Sessions** (from 0.3.6): the session reports in `DIR/reports/` (see
  [A report of each session](#a-report-of-each-session)), newest first.
  Each report written at close is one entry: session id, agent, server,
  mode, open and close time (local and UTC), the decisions of the session
  and, apart, the status of its approvals, the result of `verify` in the
  report, and the buttons **Download PDF** and **Download JSON**, with the
  SHA-256 of the JSON next to them. The pairs `praetore-mcp report` wrote
  later (`.regen-`) are listed under the report they came from, each with
  its own buttons, never mixed with it. `#/sessions/<id>` opens the view on
  that session. When a session ends while the page is open, the next
  refresh shows it with a short "Report ready" notice and its download
  button.
- **Information**: approvals, the policy rules, the verification detail
  and statistics (counts per decision, activity per hour or day, the most
  used tools). A summary of the policy (id, version, digest) and a warning
  when the policy has an allow-all rule and the journal has enforce
  receipts. The mode is a `wrap` option, so the page takes it from the
  receipts. An allow-all rule is an ALLOW rule with no tool and no
  condition, for every server or for one, like the
  `allow-all-mcp-tool-calls` that `init` wrote before default deny; it is
  the same rule `policy check` warns about.

Live and Chain each have a list view with the same content as text: rows
reached with Tab and opened with Enter, read by a screen reader, with no
animation. The drawings have a text label for screen readers. With
"reduce motion" set in the system, nothing moves.

Opening a receipt shows its tool, its arguments as text, what decided it,
the mode, local time and UTC, the evidence id, seq, the `prev` hash link
and the result of `verify` for that receipt. What decided it comes from the
`decided_by` signed in the receipt (a rule, a rule that matched but could
not apply, default deny or an engine check), with the rule text when the
current policy is the one the receipt names. Other tabs show the full JSON
line, `path_check` (lexical, resolved, status), and the agent, attester
and authority signatures with their key ids. Each signature shows OK or
FAIL.

The verification status, per receipt and for the whole journal, comes from
the same code as `praetore-mcp verify` and is also shown in the sidebar. It
covers the receipts only. It includes the journal order (seq/prev) and the
journal head. Keep the head outside this machine. `--expected-head HEX`
and `--expected-approval-head HEX` work as they do for `verify`. The result is kept in memory and computed
again when any file `verify` reads (the journal files, the attester and
issuer pins, the approver pin, the approval journal) changes length,
modification time, change time or inode. On a platform without change times
it is computed again on every request. With a large journal the first
request after a change takes as long as `verify`. A line that is not a
receipt (a write cut short, for example) is listed as unreadable; a journal
that cannot be read at all shows the error instead of the table.

The page reads three things from the home: the receipts, which `verify`
checks; the calls waiting for approval, read from `approvals/pending/*.json`,
which are not signed and which `verify` does not check (the page labels them
"not signed"); and the rules of the current policy. It is read-only:
approving or rejecting is done with `praetore-mcp approve` and
`praetore-mcp reject` in a terminal.

The page is embedded in the binary and loads nothing from the network.
`dashboard` writes nothing under the home: it does not write, regenerate
or sign a report. It answers only GET requests (anything else gets 405)
whose `Host` is `127.0.0.1:PORT` or `localhost:PORT`; a request with an
`Origin` header other than `http://127.0.0.1:PORT` or
`http://localhost:PORT` is refused (403).

`GET /reports/<file>` serves one report file as a download
(`Content-Disposition: attachment`, `application/pdf` or
`application/json`, `X-Content-Type-Options: nosniff`, not cached). Only a
name that is exactly a report file name is served:
`session-<UTC>-<id>.json` or `.pdf`, or the same with `.regen-<UTC>` before
the extension. The file is opened without following a symlink, and the
open file must be a regular file with a single link (no hard link to
another file), owned by the user the dashboard runs as, whose real path,
with every symlink on the way resolved, is in the real `DIR/reports/`. Its
content must be a report: a `.json` must parse as a report with the schema
`praetore-mcp.session-report/1`; a `.pdf` must start with `%PDF` and its
`.json` next to it must pass the same checks. Any other name, `..`, a
separator (also percent-encoded, such as `%2e%2e` or `%2f`), a symlink, a
hard link, a file of another user, a file outside `DIR/reports/`, content
that is not a report or a file that does not exist gets 404. A file larger
than 64 MiB gets 413 and is not read. The Sessions view lists a file only
when this same check accepts it, so every file it lists downloads. Any local process
can still open the page and read what it shows, tool arguments included,
so run it only while you are using it. Texts are in Spanish, English and
Portuguese.

### A report of each session

From 0.3.6, when a `wrap` session ends (the client or the server closes,
or SIGINT/SIGTERM on macOS and Linux) and it recorded at least one receipt,
two files are written to `DIR/reports/`:

```
session-<start UTC>-<id>.json   header + the session's receipts
session-<start UTC>-<id>.pdf    the same session, for a person to read
```

The JSON header has the praetore-mcp version, agent, server, mode, seq
range, the heads of the receipts and approval journals when the session
closed, and the result of `verify`. Each receipt is the journal line
itself, on a line of its own, copied byte for byte. The session's approval
records are the lines of `approvals/journal.jsonl` copied byte for byte
too; if that journal cannot be read, the header says why in
`approval_journal_error` and the PDF says so in its approvals table. The PDF has the
summary (ALLOW, DENY, held, approved, expired), the calls, the approvals
with the approver key id and time, the result of `verify`, both heads and
the SHA-256 of the JSON file. Times are local with UTC next to them. If
`verify` fails, the first page says `VERIFY FAILED` and both files are
still written.

The JSON header and the PDF name the build that wrote them: the version
for a release build (`0.3.6`), or the version with `-dev+<short commit>`
for any other build (`0.3.6-dev+1a2b3c4`), or `-dev` alone (`0.3.6-dev`).
A release build is one whose checked out commit of this repository carries
the exact tag `v<crate version>` (another `v*` tag does not count), or one
built with `PRAETORE_MCP_RELEASE=1`. The commit is read from git only when
the repository git finds is this one (its top level holds
`crates/praetore-mcp/build.rs`); a build with no `.git`, inside some other
repository or with no `git` on `PATH` takes it from
`PRAETORE_MCP_BUILD_COMMIT` (7 to 40 hex characters) or has none.
`praetore-mcp --version` prints the same build version. In CI, the job
that builds the release archives fails on a tag that is not
`v<crate version>`, on a tag build whose `--version` is not exactly
`praetore-mcp <crate version>`, on any other build whose `--version` is
not exactly `praetore-mcp <crate version>-dev+<commit>`, and when the
binary cannot run on the runner (x86_64 on Apple silicon runs under
Rosetta 2). The version is read only from what the binary prints.

When the report is written, `wrap` prints where to see it, after its path:

```
praetore-mcp: session report: /home/user/.praetore/mcp/reports/session-20261116T030240Z-560f69f7.pdf
praetore-mcp: to see and download it, run '<dir>/praetore-mcp' dashboard --dir '/home/user/.praetore/mcp' --port 8787 and open http://127.0.0.1:8787/#/sessions/560f69f7 (a dashboard on another port: #/sessions/560f69f7 there)
```

The dashboard writes nothing under the home, so `wrap` cannot tell whether
one is running, or on which port, without connecting to a local port. It
does not try: it prints the command (absolute binary path and `--dir`,
quoted for a POSIX shell) with `--port 8787`, the default port, and the
link to the page of the session on that port. If a dashboard on that port
is already open, the link works as it is; for a dashboard on another port,
open `#/sessions/<id>` on that one.

The Sessions view of the dashboard lists the reports and downloads them;
like the report itself, it is a view. It signs nothing and does not prove
that a person reviewed a session. A report is tamper-evident only against
a copy of the heads kept somewhere else.

```sh
praetore-mcp report                    # a new report of the last session
praetore-mcp report --session a41f9c2e # the id after the start time
praetore-mcp wrap --no-report -- ...   # this session writes no report
```

`report` writes a new pair next to the original; the report written at
close is never replaced. The new files are
`session-<start UTC>-<id>.regen-<now UTC>.json` and `.pdf`, and the new
header names the close report in `regenerated_from`. They read the journal
as it is now and run `verify` again, so after a change to the journal the
close report and the new one can disagree, and both stay. `--last` and
`--session` only look at reports written at close.

SIGINT and SIGTERM on macOS and Linux: with reports on, `wrap` waits up to
300 ms for the server to end, forwards the signal to it, waits up to 2 s
more, kills it if it is still running, writes the report, and then ends by
that same signal, as before reports existed. A second signal ends `wrap`
at once without the report. With `--no-report` or `report = false`, `wrap`
installs no handler: the signal ends it at once, as in 0.3.5.

`report = false` in `DIR/config.toml` turns reports off for every session
of that home. `praetore-mcp install` does not add `--no-report`.

### Approval TTL

A pending approval stays open 10 minutes by default. To change it for a
home, add this line to `DIR/config.toml`:

```toml
approval_ttl_seconds = 1800
```

`wrap` reads and checks every source that is set, then uses the first
one in this order:

1. `PRAETORE_MCP_APPROVAL_TTL_SECONDS` in the environment of `wrap`;
2. `approval_ttl_seconds` in `DIR/config.toml`;
3. the integer in `DIR/approvals/ttl-seconds` (older setting, still read);
4. 600 seconds.

Use the config line when an MCP client starts `wrap`. Many clients pass
only a few variables to the servers they start (the MCP Python SDK's
`stdio_client` passes HOME, PATH and a few more), so an exported
`PRAETORE_MCP_APPROVAL_TTL_SECONDS` may never reach `wrap`. The config
file is read from the home, whatever the environment.

`wrap` checks the TTL before it starts the server. A value outside 1 to
86400 or not an integer in any of the three sources, a malformed or
repeated `approval_ttl_seconds` line (`approval_ttl_seconds: 1800` with a
colon included), a `config.toml` that starts with a byte order mark, or a
`config.toml` or `ttl-seconds` that cannot be read stops `wrap` with exit code 2 and the cause, naming
the source, on stderr. That holds even when a source of higher priority
is valid: with `PRAETORE_MCP_APPROVAL_TTL_SECONDS=120` set,
`approval_ttl_seconds = 90000` still stops `wrap`:

```
praetore-mcp: approval TTL: config.toml approval_ttl_seconds must be from 1 to 86400 seconds, got 90000; wrap did not start
```

A bad value is never skipped in favour of another source. Other problems in `config.toml`
(a bad `report` value, an unknown key) stay warnings.

The report is a view of the journal: it signs nothing, changes no journal
and takes no part in a decision. If it cannot be written, the reason goes
to stderr and the session ends with the same exit code. It is
tamper-evident on this machine; verify against an external copy of the
heads. Someone who can write the home can rewrite a report as well as the
journal, so keep the heads (or the PDF) somewhere the wrapped servers
cannot write. `verify` at close reads the whole journal, so the report
takes longer as the journal grows. Reports contain tool names and
arguments; they are created with mode 0600, and `DIR/reports/` is set to
0700 each time a report is written (also when it already existed). They
are never deleted or replaced by `praetore-mcp`. A session can be regenerated only if it
wrote a report. On Windows a session ended with Ctrl-C writes none.

## Limits

Read these before relying on anything above.

1. **Only MCP `tools/call` through a wrapped server is governed.** Tools the
   client runs itself never reach `praetore-mcp`: the Read/Write/Bash tools
   of Claude Code (including Code sessions inside Claude Desktop), Cursor's
   built-in edit and terminal tools, and computer use. In the macOS check, a
   Code session wrote the file that the policy denies, and
   `praetore-mcp receipts` showed no receipt at all, because no `tools/call`
   was sent. If the agent has another route to the same resource, a `deny`
   rule does not close it. How to check: if an action happened and there is
   no receipt for it, it did not go through `praetore-mcp`, or (observe only)
   `praetore-mcp` could not parse the line and forwarded it with a stderr
   warning that names its SHA-256.
2. **The keys are LOCAL/DEV keys for one machine.** `init` creates four
   Ed25519 keys under `~/.praetore/mcp/keys/` (0600): issuer, agent,
   attester and approver. There is no PKI, no key rotation, no hardware
   key storage and no revocation. Anyone who can read that directory can
   sign receipts and approvals as this installation. A receipt shows what
   this installation recorded; it does not prove anything about who
   controls the machine. An older home gets the approver key from a second
   `praetore-mcp init`. That run does not replace the other keys or the
   receipts.
3. **Local approval is cooperative.** In enforce mode a REQUIRE_APPROVAL
   call is not forwarded. The tool error names an approval id and the
   command to run, for example `'<dir>/praetore-mcp' approve <id> --dir '/home/user/.praetore/mcp'`
   (the real paths of the running binary, `<dir>` being the directory the
   archive was extracted to, and of the home).
   `praetore-mcp approvals` lists pending calls (server, tool, a short form
   of the arguments, expiry). `approve` works only in an interactive
   terminal. Before it asks for a short code, it prints the server, the
   tool, the expiry (local time, UTC and the time left), and the full
   arguments. It continues only if that
   code is typed back. `reject <id>` records a rejection and the call is not
   forwarded. The approval matches one server, one tool and the canonical
   arguments, expires after 10 minutes unless the approval TTL says
   otherwise (1 to 86400 seconds, see "Approval TTL" below), and is
   consumed by one later call; see
   [the evasion matrix](../../docs/security/evasion-matrix.md). A
   second identical call asks again. Different arguments do not match.
   A process that can act as this user can open a terminal and approve.
   That is not a guarantee that a person reviewed the call. The terminal
   check is cooperative. The forwarded call's receipt names the approval
   id, so cutting or deleting `approvals/journal.jsonl` alone does not let
   a used approval run again, and `verify` fails on that receipt. Cutting
   the end of the receipts journal as well lets it run again; `verify`
   detects that only with `--expected-head HEX` or
   `--expected-approval-head HEX`, a head printed earlier and kept off this
   machine; the command is in the README, Local approval. The v0.3.3 `praetore-mcp verify` does
   not read 0.3.4 receipts. Observe mode
   does not hold the call; `praetore-mcp receipts` shows
   `enforce would ask` on that receipt.
4. **Path arguments must resolve to themselves.** For an argument that a
   `--arg-path-prefix` rule covers, `wrap` resolves symlinks first. If the
   path goes through a symlink, has `.`/`..`, or its parent does not exist,
   restrictive path rules match it and ALLOW path rules do not. On macOS,
   `/tmp/...` is such a path (`/tmp` → `/private/tmp`): use the resolved
   path in rules and arguments. On a filesystem that ignores case or Unicode
   normalization (APFS by default), a path that differs from a rule's prefix
   only in case or normalization (`/x/SECRET` or `/x/ẞECRET` against
   `/x/secret`, NFD against NFC) is also treated that way (`ambiguous`), even
   when it does not exist yet, and so is another spelling of the same
   directory, such as the macOS firmlink `/System/Volumes/Data/Users/...`
   for `/Users/...`. The receipt shows what was checked in
   `context["praetore.path_check"]`. **This is defense in depth for local
   servers on the same host and mount namespace, not a guarantee**; the
   structural fix is confining the server (T-013B, PR #61). Not covered:
   hard links, TOCTOU (point 5), Linux bind mounts of a subdirectory, and
   decoding the server applies to the path. **Not supported:** servers in
   another namespace or on another host (`docker`, `podman`, `ssh`,
   `chroot`; `wrap` warns at startup when it sees one) and network or FUSE
   mounts that loop back to the same disk. See the README for details.
5. **Time of check to time of use (TOCTOU).** The decision is made on the
   arguments when the call passes through the proxy. The MCP server opens
   the file afterwards. Anything that changes the filesystem in between (for
   example replacing a directory with a symlink) is not seen by the
   decision.
6. **Observe mode does not block DENY.** It records what enforce would
   have decided, labeled `praetore.mode: observe` in the signed receipt, and
   forwards the call. Use it to try a policy, not to stop calls. It still
   refuses, as enforce does: a `tools/call` the policy does not classify, a
   client line it cannot parse that may name a `safety*` tool, a client
   line over 32 MiB, a whole batch when a `tools/call` in it is refused, and
   a `tools/call` whose receipt line would not verify (nothing is written).
   When the home cannot be loaded, every `tools/call` and every client line
   that cannot be parsed is refused. In enforce, a tool that no rule allows
   is denied by default.
7. **The proxy is cooperative.** Whoever can edit the client config can
   remove the wrapper. The proxy does not see actions the server takes on its
   own initiative.
8. **Policy changes need a restart.** Each `wrap` process loads
   `policy.json` when it starts. After `policy deny|allow|remove`, restart
   the client.
9. **`policy coverage` shows one `tools/list`.** It reports what the rules
   decide for the tools the server listed in that run, for a call where no
   argument condition matches. A call's arguments, the mode and path
   resolution can still change the outcome on the receipt. A tool the
   server did not list is not in the report; in enforce, default deny
   applies to it unless a rule allows it.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| An action the policy denies happened, and `praetore-mcp receipts` has no receipt for it | The client used its own tool (Claude Code / Code session, Cursor's built-in tools, computer use), not the MCP server | Use a chat that calls the MCP tool, or ask for it by name ("use the `write_file` tool of `filesystem`"). See Limit 1. |
| `receipts` says `no receipts yet` but the server is listed in the client | No `tools/call` reached the proxy yet, or the client was not restarted after `install` | Quit the client completely and reopen it; ask for an MCP tool by name. |
| `wrap` prints `... is not initialized` and every tool call fails with `praetore-mcp is not ready` | `init` was not run for that `--dir` | `praetore-mcp init` (or `--dir` matching the one in the client config), then restart the client. Both modes refuse every `tools/call` until then. Builds up to `9735974` forwarded calls **without receipts** in observe in this state ([#48](https://github.com/Mavericksantander/praetore/pull/48)). |
| macOS says the downloaded `praetore-mcp` "cannot be opened" or is from an unidentified developer | CI-built macOS binaries are not signed or notarized | After checking it against `SHA256SUMS` (or the artifact's `.sha256`), run `xattr -d com.apple.quarantine praetore-mcp`, or build it yourself with `cargo install --git`. |
| `bad CPU type in executable` | An `x86_64-apple-darwin` binary on Apple silicon without Rosetta 2 | Use the `aarch64-apple-darwin` archive. |
| A call on a `/tmp/...` (or other symlinked) path is refused, or never allowed, by a path rule | The argument does not resolve to itself (`/tmp` → `/private/tmp` on macOS) | Use the resolved path (`realpath /tmp/x`). `praetore-mcp receipts` and the receipt's `praetore.path_check` show `differs` and the resolved value. |
| `policy deny ... --arg-path-prefix` prints `warning: ... resolves to ...` | The prefix itself goes through a symlink | Remove the rule and add it again with the resolved prefix; otherwise a DENY rule does not cover the resolved path. |
| A new rule has no effect | The running `wrap` loaded the old policy | Restart the client. `praetore-mcp policy check` shows the digest it will load. |
| In enforce a tool is refused and its receipt shows `DENY` with no rule id | Default deny: no rule allows that tool | `praetore-mcp policy allow --id ID --server NAME --tool NAME`, then restart the client. `praetore-mcp policy coverage --server NAME -- <server command>` lists the decision for every tool. |
| `init` or `policy check` prints a warning about `allow-all-mcp-tool-calls` | The home was created by `init` in v0.3.4 or earlier | See "A home from v0.3.4". Add the ALLOW rules you need, then `praetore-mcp policy remove --id allow-all-mcp-tool-calls`. |
| The server does not start; `wrap` exits with 127 | The client could not find the server command (for example `npx`) with the PATH apps get from the desktop | Put the absolute path in the config, e.g. `/opt/homebrew/bin/npx` (check with `which npx`), then `install` again. In the macOS check, both apps found Homebrew's `npx` without this. |
| `install` says the config `is not strict JSON` | The file has comments or trailing commas (JSONC) | Remove them, or wrap the server by hand with `praetore-mcp wrap ... -- <command>`. The file is never rewritten in this case. |
| `install --mode enforce` says `nothing to change` / `already wrapped` and exits 0 | The entry is already wrapped. `install` does not change `--mode` on a wrapped entry. Exit 0 leaves the mode already in the config | `praetore-mcp uninstall --client <client> --yes`, then `praetore-mcp install --client <client> --mode enforce --yes`, then restart the client. Or edit `--mode` in the config and restart. |
| `install` or `uninstall` prints `not modifying ... without confirmation; re-run with --yes` and exits 1 | stdin is not a terminal, and `--yes` was not passed. The file was not changed | Read the dry-run, then re-run with `--yes`. A later `verify` that prints `OK 0 receipts` means the journal is empty. |
| The same Cursor file is listed twice when running `install` from `~` | A build up to `9735974`: `~/.cursor/mcp.json` and `./.cursor/mcp.json` are the same file | Harmless (the second pass is skipped). Current builds list it once ([#52](https://github.com/Mavericksantander/praetore/pull/52)). |
| `praetore-mcp wrap --help` fails with `unexpected argument "--help"` | A build up to `9735974`, before per-command help ([#49](https://github.com/Mavericksantander/praetore/pull/49)) | Reinstall (see the README's Install section), or use `praetore-mcp --help`, which lists every option. |
| `another praetore-mcp policy command is running (lock …)` | A previous `policy` command was interrupted | If no other `policy` command is running, delete `~/.praetore/mcp/policy.json.lock`. |
| `verify` prints `FAIL` | A journal line was edited, or the trust files do not match the keys that signed it | Do not trust that receipt. Check that `--dir` is the home that wrote it. Re-labeling observe as enforce is detected on purpose. |
| `verify` prints `FAIL ... journal order` | An entry was removed, duplicated or reordered, or a daily file is missing | Do not trust the journal as complete. Compare with a copy or a head kept elsewhere (`verify --expected-head HEX`). |
| Tool calls hang with no reply and no stderr message, in both modes | Another process of the same user holds `receipts/.journal.lock`. Each receipt is appended under an exclusive `flock` that waits without a timeout, and the call is decided only after its receipt is written | Nothing is forwarded while it waits (fail closed). Find the holder (`lsof receipts/.journal.lock` or `fuser` on Linux) and stop it; the wrapper continues once the lock is released. Do not delete the lock file while a wrapper may be appending. |
| Every call is refused in enforce with `does not end with a newline` | The last journal line is incomplete (an interrupted write, a full disk) | Run `praetore-mcp verify`, keep a copy of the journal, and remove the incomplete last line by hand. |
| About a year after `init`, every call is refused in enforce mode | The authority from `init` is valid for 364 days | Run `init` in a new `--dir` and `install` again. |

Where to look:

* Claude Desktop (macOS): `~/Library/Logs/Claude/mcp-server-<name>.log`
  has the wrapped server's stderr (seen in the macOS check). `praetore-mcp`
  writes its own `praetore-mcp:` warnings and errors to the same stream; a
  run without warnings or errors writes none.
* Cursor: the server status and errors are in its MCP settings.
* Any client: `praetore-mcp receipts` and `praetore-mcp verify` read the
  journal under `~/.praetore/mcp/receipts/`.

## Reporting a problem

Include `praetore-mcp --version`, the OS, the client and its version, the
`praetore-mcp:` lines from the log, and the output of `praetore-mcp policy
check` and `praetore-mcp verify`. Do not include the files under `keys/`.
