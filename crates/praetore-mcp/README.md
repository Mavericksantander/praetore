# praetore-mcp

`praetore-mcp` is a local **stdio MCP proxy**. It sits between an MCP client
(Claude Desktop, Cursor, VS Code) and any existing stdio MCP server. Every
`tools/call` the client sends is evaluated by the PRÆTORE HighAssurance engine,
and the result is written as a signed evidence receipt that a third party can
check offline with `praetore-verify`. It needs no PostgreSQL, no server and no
Rust code.

* **observe** (default): every call is forwarded. The decision is only
  recorded.
* **enforce**: ALLOW is forwarded. DENY and REQUIRE_APPROVAL are not
  forwarded; the client gets an MCP tool error instead.

## 5-minute quickstart

```sh
cargo install --locked --path crates/praetore-mcp   # or: cargo build --release -p praetore-mcp

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
[`docs/policy-language.md`](../../docs/policy-language.md)). The default has one
rule:

```json
{"id": "allow-all-mcp-tool-calls", "action_type": "mcp.tools/call", "effect": "Allow",
 "required_capability": "mcp:tools/call", "target": null,
 "parameter_conditions": [], "context_conditions": []}
```

Add DENY or REQUIRE_APPROVAL rules keyed on `server`, `tool`, `arguments` (the
whole object, `Exact` only) or `arguments.<key>` (top-level argument fields):

```json
{"id": "deny-delete", "action_type": "mcp.tools/call", "effect": "Deny",
 "required_capability": null, "target": "filesystem",
 "parameter_conditions": [{"key": "tool", "operator": "Exact", "expected": "delete_file"}],
 "context_conditions": []},
{"id": "approve-secrets", "action_type": "mcp.tools/call", "effect": "RequireApproval",
 "required_capability": "mcp:tools/call", "target": null,
 "parameter_conditions": [
   {"key": "tool", "operator": "Exact", "expected": "read_file"},
   {"key": "arguments.path", "operator": "PathPrefix", "expected": "/Users/me/.ssh"}],
 "context_conditions": []}
```

Things to know:

* **v2 treats a missing or mistyped field as unknown, and unknown matches DENY
  and REQUIRE_APPROVAL rules.** A rule on `arguments.path` with no `tool`
  condition also matches every call that has no `path` argument. Pair argument
  conditions with a `tool` (or `target`) condition.
* The outcome folds as DENY > REQUIRE_APPROVAL > ALLOW. If no rule matches, the
  result is DENY.
* REQUIRE_APPROVAL rules must set `required_capability` in HighAssurance.
* A policy can also match on the mode, for example with
  `context_conditions: [{"key": "praetore.mode", ...}]`.
* Every receipt records the policy digest. Running wrappers load the policy
  when they start, so restart the MCP client after you edit it. In enforce
  mode, an invalid policy makes every `tools/call` fail closed.

## Message handling

* Messages are newline-delimited JSON-RPC 2.0 (the MCP stdio transport). All
  traffic is forwarded **byte-for-byte** except client→server `tools/call`.
  Server→client output is never parsed or delayed. The server's stderr passes
  through.
* A `tools/call` is identified by `"method": "tools/call"` in a single message
  or inside a JSON-RPC batch (array). Requests with string, numeric or `null`
  ids get replies with the same id. Notifications (no `id`) that are blocked
  get no reply.
* In a batch, blocked elements are removed. The remaining elements are
  re-serialized and forwarded, and the blocked replies are returned to the
  client as one batch. A batch with nothing blocked is forwarded unchanged.
* Blocked reply: `{"jsonrpc":"2.0","id":ID,"result":{"content":[{"type":"text","text":"Denied by PRÆTORE policy. Rule: ... Evidence id: ..."}],"isError":true}}`.
* Client lines are parsed strictly. **Duplicate object keys** (for example two
  `method` members), invalid UTF-8 and invalid JSON are unparseable. Such a
  line could hide a `tools/call` from the proxy while the server still reads
  it as one. **Enforce does not forward unparseable lines** and answers with
  JSON-RPC error `-32700` (`id: null`). Observe forwards them unchanged.
* Client lines over 32 MiB are refused in enforce. In observe they are
  forwarded unchecked, with a warning.
* Errors (missing or invalid keys, policy, clock, replay guard): **enforce
  refuses the call (fail closed); observe forwards it with a loud stderr
  warning and no receipt.** If a receipt cannot be written, enforce refuses
  the call; observe forwards it and warns.

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
  (`arguments.<key>`). Nested fields can only be matched through an `Exact`
  match on a whole value.
* Several wrappers (one per server) append to the same daily journal file
  with single `O_APPEND` writes. This is safe on local filesystems; network
  filesystems are not supported.
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
