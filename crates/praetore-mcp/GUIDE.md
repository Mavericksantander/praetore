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
[v0.3.3 release](https://github.com/Mavericksantander/praetore/releases/tag/v0.3.3)
(commit `0ce6334ff33d7e76a2e2a2bdd3cde69dcd416a0c`). That release is not a
build of the current `main` branch. You do not clone the repository.

| Machine | Archive |
| --- | --- |
| macOS Apple silicon | `praetore-mcp-v0.3.3-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `praetore-mcp-v0.3.3-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `praetore-mcp-v0.3.3-x86_64-unknown-linux-gnu.tar.gz` |

v0.3.3 has no Windows binary and no Linux ARM binary, and there is no brew
installer. Check the archive before you open it. On macOS:
`shasum -a 256 -c SHA256SUMS --ignore-missing`. On Linux:
`sha256sum -c SHA256SUMS --ignore-missing`. The published digests are in
[Install from the v0.3.3 release](../../docs/install-prebuilt.md). If
`SHA256SUMS` does not match that list, stop. Then `tar -xzf` the archive.
It contains a directory of the same name with `praetore-mcp`, `LICENSE` and
`NOTICE`.

Move `praetore-mcp` to a directory on your `PATH` that you will keep, for
example `~/.local/bin`, before you run `install`. `install` records the
absolute path of the binary that is running. Moving or replacing that file
later leaves the client config pointing at the old path. Run `install`
again after you move it.

Checking the Sigstore signature of `SHA256SUMS` is optional. It needs
`cosign`. For v0.3.3, pass
`--certificate-github-workflow-sha 0ce6334ff33d7e76a2e2a2bdd3cde69dcd416a0c`
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

Add one deny rule for the server named `filesystem`. A policy change is
loaded when `wrap` starts, so restart the client after this. The `policy`
command prints that reminder. The published v0.3.3 release has no
approval. In enforce, REQUIRE_APPROVAL is treated like DENY, with the text
"requires human approval (not supported by praetore-mcp yet)". From 0.3.4,
which today is installed only from source, the flow is "Local approval"
below.

```sh
praetore-mcp policy deny --id first-rule --server filesystem --tool write_file
praetore-mcp policy check
```

Restart the client, then ask for `write_file` on the test folder. In
observe the file is still written, and `praetore-mcp receipts --tail 5`
shows `DENY` and `first-rule`. The rule blocks that one tool. On
`@modelcontextprotocol/server-filesystem@2.3.0` it does not make the server
read-only: `append_file`, `edit_file`, `create_directory`, `move_file` and
`copy_file` still write.

To switch that observe install to enforce, uninstall and install again.
`install --mode enforce` on an entry that is already wrapped prints
`nothing to change` and exits 0. The mode already in the config stays.

```sh
praetore-mcp uninstall --client cursor --yes
praetore-mcp install --client cursor --mode enforce --dry-run
praetore-mcp install --client cursor --mode enforce --yes
```

Read the dry-run before `--yes`. It must show `wrap` with `--mode enforce`.
Restart the client. In enforce, `write_file` is refused and the file is not
written. The client text is `Denied by PRÆTORE. Evidence id: ...`. The rule
id is in `praetore-mcp receipts`, in the `DENY` / `first-rule` row, with
mode `enforce`. You can instead edit `--mode` in the client config and
restart. `install` does not rewrite `--mode` while the entry is already
wrapped.

```sh
praetore-mcp receipts --tail 5
praetore-mcp verify    # OK N receipts: N verified, 0 failed; prints the journal head
```

From 0.3.4, to hold a call until someone at the machine approves it:

```sh
praetore-mcp policy require-approval --id approve-mkdir --server filesystem --tool create_directory
# restart the client, attempt create_directory, then:
praetore-mcp approvals
praetore-mcp approve <id>    # interactive terminal; type the code it prints
```

A DENY rule on the same tool wins: the call is refused and approval is not
asked. The agent retries the same call. It is forwarded once. Limits of
that flow are in point 3 below. The evidence id in the chat matches the `EVIDENCE ID`
column. To undo:
`praetore-mcp uninstall --client cursor --yes`, or restore the
`.praetore-backup-*` file next to the config, then restart the client.

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
   command to run, for example `praetore-mcp approve <id> --dir <home>`.
   `praetore-mcp approvals` lists pending calls (server, tool, a short form
   of the arguments, expiry). `approve` works only in an interactive
   terminal. Before it asks for a short code, it prints the server, the
   tool, the UTC expiry, and the full arguments. It continues only if that
   code is typed back. `reject <id>` records a rejection and the call is not
   forwarded. The approval matches one server, one tool and the canonical
   arguments, expires after 10 minutes unless
   `PRAETORE_MCP_APPROVAL_TTL_SECONDS` or `approvals/ttl-seconds` says
   otherwise (1 to 86400 seconds), and is consumed by one later call. A
   second identical call asks again. Different arguments do not match.
   A process that can act as this user can open a terminal and approve.
   That is not a guarantee that a person reviewed the call. Deleting or
   truncating `approvals/journal.jsonl` lets an approval be used again.
   `verify` does not detect that unless you compare, by hand, the approval
   head it prints. There is no flag for that head. Observe mode
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
| macOS says the downloaded `praetore-mcp` "cannot be opened" or is from an unidentified developer | CI-built macOS binaries are not signed or notarized | After checking it against `SHA256SUMS` (or the artifact's `.sha256`), run `xattr -d com.apple.quarantine praetore-mcp`, or build it yourself with `cargo install --git`. |
| `bad CPU type in executable` | An `x86_64-apple-darwin` binary on Apple silicon without Rosetta 2 | Use the `aarch64-apple-darwin` archive. |
| A call on a `/tmp/...` (or other symlinked) path is refused, or never allowed, by a path rule | The argument does not resolve to itself (`/tmp` → `/private/tmp` on macOS) | Use the resolved path (`realpath /tmp/x`). `praetore-mcp receipts` and the receipt's `praetore.path_check` show `differs` and the resolved value. |
| `policy deny ... --arg-path-prefix` prints `warning: ... resolves to ...` | The prefix itself goes through a symlink | Remove the rule and add it again with the resolved prefix; otherwise a DENY rule does not cover the resolved path. |
| A new rule has no effect | The running `wrap` loaded the old policy | Restart the client. `praetore-mcp policy check` shows the digest it will load. |
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
