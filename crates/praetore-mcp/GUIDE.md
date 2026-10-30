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
are not forwarded; the client gets an MCP tool error with the rule and the
evidence id.

What was run end to end (macOS arm64, 2026-10-30): `cargo install --git`,
`init`, a `deny` rule for `write_file`, `install --mode enforce` into the real
Claude Desktop and Cursor apps, in front of
`@modelcontextprotocol/server-filesystem@2.1.0`. Reads were allowed,
`write_file` was refused in both apps with the evidence id shown in the chat,
the file was not created, and `praetore-mcp verify` checked every receipt.
Not run: Windows, Linux desktop apps, VS Code, other MCP servers.

## Ten-minute walkthrough

```sh
cargo install --git https://github.com/Mavericksantander/praetore praetore-mcp --locked
praetore-mcp init
praetore-mcp policy deny --id deny-write --server filesystem --tool write_file
praetore-mcp policy check

# Add a filesystem server to your client first, e.g. in Claude Desktop's
# claude_desktop_config.json:
#   "mcpServers": {"filesystem": {"command": "npx",
#     "args": ["-y", "@modelcontextprotocol/server-filesystem@2.1.0", "/path/to/test-dir"]}}

praetore-mcp install --mode enforce --dry-run
praetore-mcp install --client claude-desktop --mode enforce   # backup written first
# Quit the client completely (⌘Q on macOS) and open it again.
```

In a **chat** (see "Limits" below for why it matters), ask the model to read
a file in the test directory and then to write one with the `write_file`
tool of `filesystem`. Then:

```sh
praetore-mcp receipts --tail 5   # one ALLOW, one DENY deny-write
praetore-mcp verify              # OK N receipts: N verified, 0 failed
```

The evidence id in the chat matches the `EVIDENCE ID` column. To undo:
`praetore-mcp uninstall --client claude-desktop`, or restore the
`.praetore-backup-*` file next to the config.

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
   no receipt for it, it did not go through `praetore-mcp`.
2. **The keys are LOCAL/DEV keys for one machine.** `init` creates three
   Ed25519 keys under `~/.praetore/mcp/keys/` (0600). There is no PKI, no key
   rotation, no hardware key storage and no revocation. Anyone who can read
   that directory can sign receipts as this installation. A receipt shows
   what this installation recorded; it does not prove anything about who
   controls the machine.
3. **REQUIRE_APPROVAL has no approval flow.** A matching call is blocked in
   enforce mode, with the text "requires human approval (not supported by
   praetore-mcp yet)". There is no way to approve it and let it run.
4. **Path arguments must resolve to themselves.** For an argument that a
   `--arg-path-prefix` rule covers, `wrap` resolves symlinks first. If the
   path goes through a symlink, has `.`/`..`, or its parent does not exist,
   restrictive path rules match it and ALLOW path rules do not. On macOS,
   `/tmp/...` is such a path (`/tmp` → `/private/tmp`): use the resolved
   path in rules and arguments. The receipt shows what was checked in
   `context["praetore.path_check"]`.
5. **Time of check to time of use (TOCTOU).** The decision is made on the
   arguments when the call passes through the proxy. The MCP server opens
   the file afterwards. Anything that changes the filesystem in between (for
   example replacing a directory with a symlink) is not seen by the
   decision.
6. **Observe mode does not block anything.** It records what enforce would
   have decided, labeled `praetore.mode: observe` in the signed receipt. Use
   it to try a policy, not to stop calls.
7. **The proxy is cooperative.** Whoever can edit the client config can
   remove the wrapper. The proxy does not see actions the server takes on its
   own initiative.
8. **Policy changes need a restart.** Each `wrap` process loads
   `policy.json` when it starts. After `policy deny|allow|remove`, restart
   the client.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| An action the policy denies happened, and `praetore-mcp receipts` has no receipt for it | The client used its own tool (Claude Code / Code session, Cursor's built-in tools, computer use), not the MCP server | Use a chat that calls the MCP tool, or ask for it by name ("use the `write_file` tool of `filesystem`"). See Limit 1. |
| `receipts` says `no receipts yet` but the server is listed in the client | No `tools/call` reached the proxy yet, or the client was not restarted after `install` | Quit the client completely and reopen it; ask for an MCP tool by name. |
| `wrap` prints `... is not initialized` and every tool call fails with `praetore-mcp is not ready` | `init` was not run for that `--dir` | `praetore-mcp init` (or `--dir` matching the one in the client config), then restart the client. Both modes refuse every `tools/call` until then. Builds up to `9735974` forwarded calls **without receipts** in observe in this state ([#48](https://github.com/Mavericksantander/praetore/pull/48)). |
| A call on a `/tmp/...` (or other symlinked) path is refused, or never allowed, by a path rule | The argument does not resolve to itself (`/tmp` → `/private/tmp` on macOS) | Use the resolved path (`realpath /tmp/x`). `praetore-mcp receipts` and the receipt's `praetore.path_check` show `differs` and the resolved value. |
| `policy deny ... --arg-path-prefix` prints `warning: ... resolves to ...` | The prefix itself goes through a symlink | Remove the rule and add it again with the resolved prefix; otherwise a DENY rule does not cover the resolved path. |
| A new rule has no effect | The running `wrap` loaded the old policy | Restart the client. `praetore-mcp policy check` shows the digest it will load. |
| The server does not start; `wrap` exits with 127 | The client could not find the server command (for example `npx`) with the PATH apps get from the desktop | Put the absolute path in the config, e.g. `/opt/homebrew/bin/npx` (check with `which npx`), then `install` again. In the macOS check, both apps found Homebrew's `npx` without this. |
| `install` says the config `is not strict JSON` | The file has comments or trailing commas (JSONC) | Remove them, or wrap the server by hand with `praetore-mcp wrap ... -- <command>`. The file is never rewritten in this case. |
| `install` says `nothing to change` / `already wrapped` | The entry already runs through `praetore-mcp` | To change the mode, `uninstall` first, then `install --mode ...`. |
| The same Cursor file is listed twice when running `install` from `~` | A build up to `9735974`: `~/.cursor/mcp.json` and `./.cursor/mcp.json` are the same file | Harmless (the second pass is skipped). Current builds list it once ([#52](https://github.com/Mavericksantander/praetore/pull/52)). |
| `praetore-mcp wrap --help` fails with `unexpected argument "--help"` | A build up to `9735974`, before per-command help ([#49](https://github.com/Mavericksantander/praetore/pull/49)) | Reinstall (see the README's Install section), or use `praetore-mcp --help`, which lists every option. |
| `another praetore-mcp policy command is running (lock …)` | A previous `policy` command was interrupted | If no other `policy` command is running, delete `~/.praetore/mcp/policy.json.lock`. |
| `verify` prints `FAIL` | A journal line was edited, or the trust files do not match the keys that signed it | Do not trust that receipt. Check that `--dir` is the home that wrote it. Re-labeling observe as enforce is detected on purpose. |
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
