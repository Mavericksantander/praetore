# praetore-mcp

`praetore-mcp` is a local **stdio MCP proxy**. It sits between an MCP client
(Claude Desktop, Cursor, VS Code) and any existing stdio MCP server. Every
`tools/call` the client sends is evaluated by the PRÆTORE HighAssurance engine,
and the result is written as a signed evidence receipt that a third party can
check offline with `praetore-verify`. It needs no PostgreSQL, no server and no
Rust code.

* **observe** (default): every call is forwarded. The decision is only
  recorded. If the home cannot be loaded at startup (not initialized, or
  invalid keys, pins or policy), no receipt can be written, so every
  `tools/call` is refused in observe as well (see Limitations).
* **enforce**: ALLOW is forwarded. DENY and REQUIRE_APPROVAL are not
  forwarded; the client gets an MCP tool error instead.

New to praetore-mcp? [GUIDE.md](GUIDE.md) walks through a first run, lists
what it does not cover, and has a troubleshooting table.

## Install

`praetore-mcp` is not published on crates.io. Install it with Cargo, without
cloning the repository (below), or use a CI-built binary (see "Prebuilt
binaries"). The
workspace declares `rust-version = "1.88"` (checked with Rust 1.94); building
praetore-mcp needs no PostgreSQL, Node or Python.

```sh
cargo install --git https://github.com/Mavericksantander/praetore praetore-mcp --locked
praetore-mcp --version
```

`--locked` builds with the repository's `Cargo.lock`. To pin an exact
revision, add `--rev <commit>` (or `--tag <tag>` once releases are tagged).
The binary goes to `~/.cargo/bin` (or `--root DIR`); `cargo uninstall
praetore-mcp` removes it. `praetore-mcp install` writes the absolute path of
the running binary into client configs, so run `install` again after moving
or reinstalling it to a different location.

From a clone of the repository: `cargo install --locked --path
crates/praetore-mcp`, or `cargo build --release -p praetore-mcp`.

### Prebuilt binaries

The `Assurance gates` workflow builds `praetore-mcp` with `--release
--locked` for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` and
`x86_64-apple-darwin` (cross-built on Apple silicon). Before packaging, each
binary runs `scripts/mcp-smoke.py`: one allowed `read_text_file` and one
denied `write_file` through `npx @modelcontextprotocol/server-filesystem@2.1.0`,
then `verify`. Each run uploads
`praetore-mcp-<version>-<target>.tar.gz` (the binary, `LICENSE`, `NOTICE`)
and its `.sha256` as workflow artifacts. `Release checksums` then re-checks
them and writes one `SHA256SUMS` covering the three archives and
`praetore-verify` (`scripts/release-checksums.sh`); on a `v*` tag it is kept
as the `release-assets-<tag>` artifact.

These are workflow artifacts, not a GitHub Release, and downloading them
needs a GitHub login. The macOS binaries are **not signed or notarized**:
Gatekeeper blocks a downloaded copy until you remove the quarantine
attribute (`xattr -d com.apple.quarantine praetore-mcp`). Check the archive
first:

```sh
shasum -a 256 -c praetore-mcp-<version>-<target>.tar.gz.sha256
# or, with the release-assets set:
shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf praetore-mcp-<version>-<target>.tar.gz
```

To run the same smoke test on your own build: `python3 -I
scripts/mcp-smoke.py target/release/praetore-mcp` (needs Node with `npx`).

## 5-minute quickstart

```sh

# 1. Create LOCAL/DEV keys, a signed authority, trust pins and a default policy
praetore-mcp init                     # ~/.praetore/mcp, or $PRAETORE_MCP_HOME, or --dir DIR

# 2. See what would change in your MCP client configs (nothing is written)
praetore-mcp install --dry-run        # all detected clients
praetore-mcp install --client claude-desktop --dry-run

# 3. Apply it. A timestamped backup is written next to each file first.
praetore-mcp install --client claude-desktop          # asks for confirmation
praetore-mcp install --client claude-desktop --yes    # non-interactive

# 4. Restart Claude Desktop and use your tools as usual.

# 5. Look at the receipts
praetore-mcp receipts --tail 20

# 6. Verify every receipt (integrity, attester signature, intent, authority, mode)
praetore-mcp verify

# 7. Add rules (no JSON editing), check them, then restart the client
praetore-mcp policy deny --id deny-delete --server filesystem --tool delete_file
praetore-mcp policy require-approval --id approve-ssh --tool read_file --arg-path-prefix path=/Users/me/.ssh
praetore-mcp policy list
praetore-mcp policy check

# 8. Switch to enforce (install skips entries that are already wrapped, so uninstall first)
praetore-mcp uninstall --client claude-desktop --yes
praetore-mcp install --client claude-desktop --mode enforce --yes
```

`install` turns each stdio entry such as

```json
"filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me"], "env": {"X": "1"} }
```

into

```json
"filesystem": { "command": "/abs/path/praetore-mcp",
  "args": ["wrap", "--dir", "/Users/me/.praetore/mcp", "--name", "filesystem", "--mode", "observe",
           "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me"],
  "env": {"X": "1"} }
```

`env` and any other fields stay as they are, and so does the key order.
`praetore-mcp uninstall [--client ...] [--yes]` restores the original
entries exactly. Use `install --mode enforce` to wrap in enforce mode. To
change the mode later, edit `--mode` in the client config, or uninstall and
install again.

You can also wrap a server by hand:

```sh
praetore-mcp wrap --name my-server --mode observe -- node server.js --flag
```

## Command-line help and exit codes

`praetore-mcp --help` lists every command; `praetore-mcp <command> --help`
(or `-h`) prints that command's options, for example `praetore-mcp wrap
--help` or `praetore-mcp policy deny --help`. For `wrap`, anything after
`--` belongs to the MCP server, so `wrap -- server --help` starts the server
with `--help`. `praetore-mcp --version` prints the version.

| Exit code | Meaning |
|---|---|
| 0 | Success, including `--help` and `--version`. |
| 1 | The command ran and found a problem: `verify` found a failed receipt, `policy check` found an invalid policy or engine, or `install`/`uninstall` could not read, parse or write a config, or the change was not confirmed. |
| 2 | Usage error, or the command could not run (the reason is on stderr). |
| `wrap` | The MCP server's own exit code; 127 if the server cannot be started; 1 if it was killed by a signal. |

These codes are checked by `crates/praetore-mcp/tests/cli.rs`.

## Supported clients

| Client | File | Format |
| --- | --- | --- |
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%\Claude\claude_desktop_config.json`; Linux `~/.config/Claude/claude_desktop_config.json` | `{"mcpServers": {name: {command, args, env}}}` |
| Cursor | `~/.cursor/mcp.json`, and `.cursor/mcp.json` in the current directory | `{"mcpServers": {...}}`. Stdio entries may have `"type": "stdio"` and `envFile`; remote entries have `url` |
| VS Code | user profile `mcp.json` (macOS `~/Library/Application Support/Code/User/mcp.json`, Windows `%APPDATA%\Code\User\mcp.json`, Linux `~/.config/Code/User/mcp.json`), and `.vscode/mcp.json` in the current directory | `{"servers": {...}, "inputs": [...]}`. Entries have `"type": "stdio" \| "http" \| "sse"` |

Use `--client NAME --config FILE` to point at any other file in one of these
formats. Remote entries (`url`, or `type` other than `stdio`) and entries that
are already wrapped are skipped. Files that are not strict JSON, such as JSONC
with comments or trailing commas, are refused and never rewritten. The VS Code
`"mcp"` key inside `settings.json` is not supported.

Where these formats come from: the Cursor and VS Code formats were checked
against their current documentation. The Claude Desktop format and its macOS
and Windows paths are the documented ones. The Linux Claude Desktop path and
the VS Code user-profile paths follow each app's standard config directory;
they are assumptions.

Checked with the real apps on macOS (arm64): Claude Desktop
(`~/Library/Application Support/Claude/claude_desktop_config.json`) and
Cursor (`~/.cursor/mcp.json`), each with `install --mode enforce` in front of
`@modelcontextprotocol/server-filesystem@2.1.0` launched with `npx`, and a
`deny` rule for `write_file`: reads were ALLOWed, `write_file` was refused
with the rule and evidence id shown in the chat, the file was not created,
and `verify` checked every receipt. Not checked: Windows, Linux, VS Code.

A config file that two default paths resolve to (for example Cursor's
`~/.cursor/mcp.json` and `./.cursor/mcp.json` when run from `~`, or a
symlink) is processed once.

## What a receipt is

Each `tools/call` produces one JSON line in
`DIR/receipts/<UTC date>.jsonl`. The journal is append-only and is fsynced
after every line. Each line is a complete PRÆTORE HighAssurance (`v2`)
`Evidence` document:

* `action`: `action_type` `mcp.tools/call`, `target` = server name,
  `capability` `mcp:tools/call`, and `parameters`
  `{"server", "tool", "arguments", "arguments.<key>"...}`;
* `decision`: ALLOW / DENY / REQUIRE_APPROVAL, the matching rule ids and the
  reason;
* `context["praetore.mode"]`: `"observe"` or `"enforce"`, and
  `context["praetore.proxy"]`: `"praetore-mcp/<version>"`;
* `policy_digest`, signed v2 intent (`audience` `praetore-mcp-local`),
  `decided_at`, authority digest, and the attester signature.

The mode is part of the request context. That context is covered by the agent's
v2 intent signature, the evidence integrity hash and the attester signature.
An observe receipt therefore cannot be relabeled as enforce without breaking
`verify`. Observe receipts record a decision that was **not** enforced.

When `arguments` is larger than 8 KiB, or cannot be represented within core
limits (for example, nesting that is too deep or integers above 2^53), it is
replaced by `arguments_sha256`, `arguments_bytes` and `arguments_omitted: true`.
This keeps every receipt under the 64 KiB evidence limit. Rules keyed on
missing argument fields then behave as described below: they fail safe.

### Verifying one receipt with `praetore-verify`

`init` writes `issuer-pins.jsonl` and `attester-public-key.hex` in exactly the
formats `praetore-verify` reads:

```sh
D=~/.praetore/mcp
sed -n 1p "$D"/receipts/2026-10-30.jsonl > /tmp/receipt.json
praetore-verify evidence \
  --evidence /tmp/receipt.json \
  --attester-pin "$D"/attester-public-key.hex \
  --issuer-pins "$D"/issuer-pins.jsonl \
  --require-intent
# OK evidence OK authority_verified=true ... intent_verified=true ...
praetore-verify policy-digest --policy "$D"/policy.json   # compare with the receipt's policy_digest
```

`praetore-verify` checks the authority against the current time.
`praetore-mcp verify` checks it at the receipt's `decided_at`, so historical
receipts still verify after the local authority expires.

## Writing policy

`DIR/policy.json` is a PRÆTORE v2 policy (see
[`docs/policy-language.md`](../../docs/policy-language.md)). The default policy
has one rule, `allow-all-mcp-tool-calls`, which allows every `tools/call`.
Manage rules with `praetore-mcp policy` instead of editing JSON by hand:

```sh
praetore-mcp policy list                     # id, effect, server, tool, other conditions
praetore-mcp policy check                    # validate, print digest, lint; exit 1 if invalid
praetore-mcp policy deny             --id ID [--server NAME] [--tool NAME] [conditions...]
praetore-mcp policy require-approval --id ID [--server NAME] [--tool NAME] [conditions...]
praetore-mcp policy allow            --id ID [--server NAME] [--tool NAME] [conditions...]
praetore-mcp policy remove --id ID

# conditions (repeatable, all ANDed; KEY is a top-level tool argument):
#   --arg-exact KEY=VALUE          VALUE is JSON if it parses (5, true, "5", [1]), else a string
#   --arg-path-prefix KEY=/abs/dir segment-aware path prefix (rejects .., %, NUL)
#   --arg-prefix KEY=VALUE         plain string prefix
#   --any-tool                     allow a rule with no --server/--tool (see below)
```

`--server` matches the name given to `wrap --name` (the receipt's `target`).
`--tool` matches `params.name`. Argument conditions apply to
`arguments.<KEY>`.

Every generated rule is complete: action `mcp.tools/call`,
`required_capability` `mcp:tools/call`, and every field present. The local
authority grants that capability and the proxy always sets the server as the
target, so generated rules are always *bound*. In current core, a restrictive
match that is unbound (the authority lacks the rule's capability, or the action
has no target) always contributes DENY. A hand-written REQUIRE_APPROVAL rule
without `required_capability` would therefore never produce approval.

Each command validates the whole resulting policy with `Policy::from_json`
before writing. It then writes the file atomically, keeps a timestamped backup
next to it, bumps the policy `version`, and prints the new digest. Invalid
input (a duplicate id, a malformed `KEY=VALUE`, a relative path prefix, an
unknown flag) never writes anything. `policy check` also starts the same
HighAssurance engine `wrap` uses, and warns about rules that will behave in
surprising ways.

**Running wrappers do not reload the policy.** Each `wrap` process reads
`policy.json` once, when it starts. Every `policy` command prints a reminder to
restart the MCP client (or the wrapped servers). In enforce mode, an invalid
policy makes every `tools/call` fail closed. Run `policy check` before
restarting.

Things to know:

* **v2 treats a missing or mistyped field as unknown, and unknown matches DENY
  and REQUIRE_APPROVAL rules.** A rule on `arguments.path` with no tool
  selector also matches every call that has no `path` argument. For this
  reason `policy deny|require-approval|allow` refuses `--arg-*` without
  `--tool` or `--server`, and refuses rules with no selector at all, unless
  you pass `--any-tool`. Even with `--tool read_file`, a `read_file` call that
  omits `path` matches the rule; that is the fail-safe direction.
* The outcome folds as DENY > REQUIRE_APPROVAL > ALLOW. If no rule matches, the
  result is DENY. `policy allow` rules only matter after you
  `policy remove --id allow-all-mcp-tool-calls`.
* A hand-written rule can also match on the mode through
  `context_conditions` on `praetore.mode`.
* Every receipt records the policy digest. Compare it with
  `praetore-mcp policy check` or `praetore-verify policy-digest`.

## Message handling

* Messages are newline-delimited JSON-RPC 2.0 (the MCP stdio transport). All
  traffic is forwarded **byte-for-byte** except client→server `tools/call`.
  Server→client output is never parsed or delayed. The server's stderr passes
  through.
* A `tools/call` is identified by `"method": "tools/call"` in a single message
  or inside a JSON-RPC batch (array). Requests with string, numeric or `null`
  ids get replies with the same id. Notifications (no `id`) that are blocked
  get no reply.
* Batches are all or nothing in enforce. If any `tools/call` in a batch is
  blocked, **nothing in the batch is forwarded**. The client gets one reply
  array: blocked tool calls get their `isError` reason, other tool calls get
  `isError` "not executed", and other requests get JSON-RPC error `-32600`.
  Allowed calls in a refused batch still have ALLOW receipts, because a
  receipt records the decision, not execution. A batch with nothing blocked is
  forwarded byte-for-byte; elements are never re-serialized. Nested arrays
  inside a batch are treated as ambiguous (see below).
* Blocked reply: `{"jsonrpc":"2.0","id":ID,"result":{"content":[{"type":"text","text":"Denied by PRÆTORE policy. Rule: ... Evidence id: ..."}],"isError":true}}`.
* Client lines are parsed strictly. **Duplicate object keys** (for example two
  `method` members), invalid UTF-8 and invalid JSON are unparseable. Such a
  line could hide a `tools/call` from the proxy while the server still reads
  it as one. **Enforce does not forward unparseable lines** and answers with
  JSON-RPC error `-32700` (`id: null`). Observe forwards them unchanged.
* **Ambiguous lines** are lines that this proxy and the server could split or
  read differently. Enforce refuses them with `-32700` (`id: null`). Observe
  forwards them unchanged, warns, and evaluates and records **every**
  `tools/call` reading it can find. Two kinds are detected:
  * **Bare carriage returns.** The proxy frames on `\n`, and JSON treats
    `\r` as whitespace. Universal-newline readers end a line at `\r`, `\n`
    or `\r\n`: the MCP Python SDK (`TextIOWrapper`, `newline=None`) and
    Node `readline`. Any `\r` except one trailing `\r\n` therefore makes a
    line ambiguous. In observe, each `\r`-separated segment is classified on
    its own. Other separators that `str.splitlines` knows (`\v`, `\f`,
    `\x1c`-`\x1e`, U+0085, U+2028, U+2029) are not line breaks for those
    readers. They are also not JSON whitespace, so a raw one outside a string
    makes the line unparseable; inside a string it is harmless.
  * **Case-insensitive keys.** Go `encoding/json` (used by mcp-go) matches
    struct fields case-insensitively, and the last match wins. A line is
    ambiguous if two keys fold to the same string under simple case folding.
    This is checked at the message level, in `params`, and anywhere inside
    `params.arguments`. It covers Go's orbits such as `s`/`S`/`ſ`,
    `k`/`K`/`K` (Kelvin), `ß`/`ẞ` and `σ`/`ς`/`Σ`. A line is also ambiguous
    if a message-level or `params` key is a case variant of `method`,
    `params`, `id`, `jsonrpc`, `name` or `arguments`. In observe, both the
    exact-key and the Go (case-folded, last-wins) readings are recorded.
* Client lines over 32 MiB are refused in enforce. In observe they are
  forwarded unchecked, with a warning.
* If the home cannot be loaded when `wrap` starts (not initialized, or
  missing or invalid keys, pins, authority or policy), **both modes refuse
  every `tools/call` (fail closed)** and gate the remaining traffic as
  enforce does; other MCP messages still reach the server. Fix the home
  (`praetore-mcp init`, `praetore-mcp policy check`) and restart the client.
* Errors while evaluating one call after a successful start (clock, replay
  guard): **enforce refuses the call (fail closed); observe forwards it with
  a loud stderr warning and no receipt.** If a receipt cannot be written,
  enforce refuses the call; observe forwards it and warns.

## Trust model

* **The proxy's own LOCAL/DEV agent key signs each request.** A receipt
  attests that *this praetore-mcp installation observed (observe) or
  authorized (enforce) this tool call under this policy*. It does **not** show
  that the upstream agent, LLM or user signed or intended the call. The
  client is not authenticated.
* `init` creates three LOCAL/DEV Ed25519 keys under `DIR/keys/` (mode 0600,
  never printed): an issuer, which signs the authority; an agent, which signs
  intents; and an evidence attester, which signs receipts. All three live on
  the same machine, so anyone who can read `DIR/keys` can mint receipts that
  verify. Use them for local adoption and demos, not as a production trust
  anchor.
* The replay guard is in-memory per wrapper process. Request ids are fresh
  UUIDv4s minted by the proxy, and the guard refuses rather than evicts when
  full. It is not durable across restarts.
* Freshness is local: there is no revocation source, so each check grants a
  one-minute lease. The authority is valid for 364 days from `init` (the
  HighAssurance maximum is 365). After that, every call fails closed in
  enforce. Run `init` again in a new `--dir` and reinstall.
* The host clock is trusted (`SystemClock`).

## Limitations

* stdio transport only. HTTP / SSE / Streamable HTTP MCP servers are not
  proxied yet; `install` skips them.
* REQUIRE_APPROVAL is not supported. In enforce mode it is treated like DENY,
  with the text "requires human approval (not supported by praetore-mcp yet)".
* The keys are LOCAL/DEV keys. See the trust model.
* Observe is not enforcement. Observe receipts are labeled with the signed
  `praetore.mode: observe`.
* The proxy is cooperative. Anyone who can edit the client config can remove
  the wrapper (`uninstall`, or a manual edit) and bypass it. The proxy also
  cannot see tools the server runs on its own initiative.
* Only top-level argument fields can be matched individually
  (`arguments.<key>`). `policy` commands refuse keys containing `.`,
  because `arguments.opts.path` would match a literal top-level key
  `"opts.path"` that the caller controls, not the nested field. `policy
  check` warns about such hand-written rules. Nested fields can only be
  matched through an `Exact`
  match on a whole value.
* Several wrappers (one per server) append to the same daily journal file
  with single `O_APPEND` writes. This is safe on local filesystems; network
  filesystems are not supported.
* `install` follows a symlinked config (for example one managed by a dotfile
  manager): it rewrites the real target atomically and leaves the link in
  place. Backups are created 0600 and are never overwritten. The temp file has
  a random name, is created exclusively, and gets the original file's mode.
* `init` creates missing directories as 0700 and never changes the
  permissions of an existing `--dir` / `PRAETORE_MCP_HOME`. Symlinked `keys/`
  and `receipts/` directories and symlinked journal files are refused.
* On Windows, `wrap` resolves a bare command through `PATH` and `PATHEXT`
  (so `npx` finds `npx.cmd`). `install` writes paths without the `\\?\`
  verbatim prefix. This Windows-specific code is unit-tested but has not been
  run on Windows.
* File permissions are enforced on Unix only. On Windows, protect `DIR/keys`
  yourself.
* JSONC client configs and the VS Code `settings.json` `"mcp"` key are not
  rewritten.

## Files

| Path | Content |
| --- | --- |
| `keys/{issuer,agent,attester}.local-dev.key` | LOCAL/DEV Ed25519 secrets (0600) |
| `agent.json`, `authority.json` | agent identity and its signed authority (`mcp:tools/call`) |
| `issuer-pins.jsonl` | issuer pin (`praetore-verify --issuer-pins`) |
| `attester-public-key.hex` | attester public key (`praetore-verify --attester-pin`) |
| `policy.json` | v2 policy |
| `receipts/YYYY-MM-DD.jsonl` | append-only evidence journal |
