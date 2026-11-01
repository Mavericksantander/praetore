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

For a `v*` tag, CI also signs `SHA256SUMS` with Sigstore keyless signing
(`SHA256SUMS.sigstore.json`) and publishes everything as a GitHub Release;
the steps to verify a download are in
[`docs/operations.md`](../../docs/operations.md#release-artifact-integrity).
Builds from other runs are workflow artifacts, and downloading them needs a
GitHub login. The macOS binaries are **not signed or notarized**:
Gatekeeper blocks a downloaded copy until you remove the quarantine
attribute (`xattr -d com.apple.quarantine praetore-mcp`). Check the archive
first, against `SHA256SUMS` from a release (after verifying its signature as
in `docs/operations.md`) or the `.sha256` next to a workflow artifact:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing          # release
shasum -a 256 -c praetore-mcp-<version>-<target>.tar.gz.sha256  # workflow artifact
tar -xzf praetore-mcp-<version>-<target>.tar.gz
```

The Linux binary is built on GitHub's `ubuntu-latest` runner and needs a
glibc at least as new as that image's; build it yourself on older systems.

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

Both `praetore-verify evidence --issuer-pins` and `praetore-mcp verify` check
the authority at the receipt's signed `decided_at`, so historical receipts
still verify after the local authority expires. This shows the authority was
valid when the decision was recorded, not that it is valid now; the decision
time is only as trustworthy as the attester key that signed it.

## Writing policy

`DIR/policy.json` is a PRÆTORE policy, format 2 with semantics v2 (see
[`docs/policy-language.md`](../../docs/policy-language.md)). The default policy
has one rule, `allow-all-mcp-tool-calls`, which allows every `tools/call`,
and declares the action type `mcp.tools/call` as `Mission` in
`action_classes`. A home created before G7 has a format 1 policy, which no
longer loads: add `"format_version": 2` and
`"action_classes": {"mcp.tools/call": "Mission"}` (`policy check` prints this
hint). Receipts written before keep verifying against the old document with
`praetore-verify --policy`.

**Safety actions (G7).** A `tools/call` whose tool name starts with `safety:`
has that name as its action type. If the policy declares it `Safety`, the
gate answers `SAFETY_ACTION_NOT_GOVERNED` before path resolution, signing,
the engine or the receipts journal, and the proxy forwards the call to the
wrapped server unchanged and without a receipt, in enforce and in observe
mode: PRÆTORE decides and signs nothing about it. An undeclared `safety:*`
tool is refused as `UNCLASSIFIED_ACTION` in both modes and is not forwarded.
If `policy.json` cannot be read, every call is refused, `safety:*` included
(see `docs/threat-model.md`).

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

**Path arguments are resolved before evaluation (T-014).** This is
**defense in depth for local servers on the same host and in the same mount
namespace as `wrap`, not a guarantee.** The proxy can only check a path
string against its own view of the filesystem; the server opens it later,
in its own process, and every filesystem has its own rules for which names
are the same entry. The structural fix is to confine the server itself
(T-013B, PR #61: open inside a confined root, component by component, and
check the opened descriptor). Known limits, all documented below: hard
links, TOCTOU, Linux bind mounts of a subdirectory, servers in another
namespace or on another host (**not supported**), network and FUSE mounts
that loop back to the same disk (**not supported**), and any decoding the
server applies to the path (`%2F`, `file://`, `~`, trimming). Core's
`PathPrefix` is lexical by design. For every argument that some rule matches
with `--arg-path-prefix` (any rule, any effect), `wrap` first resolves an
absolute value through the filesystem (`canonicalize`; for a file that does
not exist yet, its parent). Unless the value resolves to itself, the engine
sees the placeholder `praetore-mcp:path-check-failed` instead, which core
treats as an unsafe path: every DENY / REQUIRE_APPROVAL `PathPrefix` rule
matches it and no ALLOW `PathPrefix` rule does. "Does not resolve to itself"
means a symlink anywhere in the path, a `.`/`..` segment, a dangling symlink,
or a parent that does not exist. The receipt records
`context["praetore.path_check"][KEY] = {"lexical", "resolved", "status"}`
(`same`, `differs`, `unresolved` or `ambiguous`), and the bytes forwarded to
the server are never changed. Consequences:

* Write rules and arguments with resolved paths. On macOS `/tmp` and `/var`
  are symlinks to `/private/tmp` and `/private/var`, so `/tmp/x` is refused by
  a restrictive rule on that key and never allowed by an ALLOW rule.
  `policy deny|allow|require-approval` and `policy check` warn when a rule's
  prefix exists and resolves to another path (a DENY rule on `/tmp/secret`
  refuses `/private/tmp/secret/x` only as `ambiguous`, and an ALLOW rule
  never matches it), and when it is `/System`, `/System/Volumes`, or at or
  under `/System/Volumes/Data` (it is, or contains, a firmlink target, so
  arguments in the usual spelling such as `/Users/...` are `ambiguous`
  against it).
* Case and Unicode normalization. For an existing entry `realpath` returns
  the stored spelling, so on APFS `/x/SECRET/f` (stored `secret`) or an NFD
  `cafe\u{301}` (stored NFC `café`) is `differs`. A name that does not exist
  yet cannot be checked that way, so a path that resolves to itself is also
  compared with every `--arg-path-prefix` value of the policy: if it is at
  or under one only once names are compared the way the filesystem compares
  them (case folding and/or NFC), and not byte for byte, it is `ambiguous`
  and the engine sees the placeholder. Case folding is Unicode full case
  folding (CaseFolding.txt C+F, crate `caseless`) followed by upper- and
  lower-casing, repeated to a fixed point, so `ẞ`, `ß`, `ss` and `SS` are one
  name; it is broader than APFS (`ı`/`I` and `İ`/`i` are also refused as
  `ambiguous` although APFS keeps them apart). Each differing segment uses the
  sensitivity of its directory: on macOS `pathconf(_PC_CASE_SENSITIVE)`
  decides case, normalization is always ignored (APFS, HFS+); on Linux only
  ext4/f2fs/tmpfs directories without the casefold flag, and btrfs, count
  as byte for byte; anything else (XFS too, which may be `ascii-ci`), or a
  failed probe, folds both (fail closed). When case is folded, trailing `.`
  and ` ` are ignored as well (Linux vfat/exfat drop them; macOS FAT keeps
  them, so there it only costs a few extra refusals). On a case-sensitive filesystem `/x/SECRET` is an ordinary path and
  is not refused by a rule on `/x/secret`.
* Other spellings of the same directory. `realpath` does not cross macOS
  firmlinks: `/System/Volumes/Data/Users/u/.ssh` resolves to itself and is
  the same directory as `/Users/u/.ssh`. So the deepest existing ancestor of
  each policy prefix is also compared by `(st_dev, st_ino)` with every
  existing ancestor of the argument; on a match, the rest of the argument
  must start with the prefix's missing tail (names folded as above). Such a
  path is `ambiguous`. This also covers a bind mount of the prefix itself
  (or of one of its ancestors), a prefix written through a symlink, and a
  hard link to a file that is itself a prefix. On macOS the argument's other
  spelling (`/System/Volumes/Data` added or removed, when its deepest
  existing ancestor is the same `(st_dev, st_ino)` both ways) is also
  compared with every prefix, so DENY `/System/Volumes/Data` covers
  `/Users/u/.ssh/x` and DENY `/usr` covers `/System/Volumes/Data/usr/local/x`.
  Not covered: a Linux bind mount of a *subdirectory* of a prefix mounted
  elsewhere (DENY `/home/u` with `/srv/x` bound from `/home/u/project`:
  `/proc/self/mountinfo` is not read).
* **Hard links are not covered.** A hard link to a file inside a prefix
  (`ln <prefix>/secret /elsewhere/f`) is the same file under an unrelated
  name, and there is no way to find the other names of a file: the gate
  sees `/elsewhere/f` as an ordinary path. An agent needs a tool that
  creates hard links to exploit this; whoever created an existing link
  already had access to the data. Only a hard link to a file that is itself
  a prefix is caught (same `(st_dev, st_ino)`).
* Per-process and system roots are `unresolved` on every OS: anything under
  `/dev` or `/proc` (`/dev/fd/N`, `/dev/stdin`, `/proc/self/fd/N`,
  `/proc/<pid>/root`, `/proc/<pid>/cwd`), compared with folding (so
  `/DEV/fd/4` on a case-insensitive root), before and after resolution. The
  gate would resolve `/dev/fd/N` with its own descriptors; the server opens
  it with its own, where N may be a file inside a DENY prefix. Accepted
  over-rejection: a tool that writes to `/dev/null` (or reads `/dev/stdin`)
  through an argument a `PathPrefix` rule covers is refused by restrictive
  rules and never allowed by ALLOW ones. On macOS the same holds for
  `/System/Volumes/<X>` with X other than `Data` (`Update/mnt1` is the live
  system volume under another `st_dev`; `Preboot`, `VM`, `Recovery`, ...
  hold no user files).
* macOS path-resolution aliases. `realpath` leaves `/.nofollow/<path>` (the
  same entry, without following symlinks) as it is, and `/.resolve/...` and
  `/.vol/<dev>/<ino>` are aliases too. On macOS every absolute argument whose
  first segment starts with `.` is `unresolved` (fail closed, also for
  unknown magic directories and for `/.NOFOLLOW`). A stock Mac has nothing
  else there (`/.file` is an empty mode-000 file, `/.VolumeIcon.icns` a
  symlink).
* Cost: per covered argument and call, a few `stat`s per ancestor of the
  argument and per distinct ancestor of the policy prefixes (memoized for
  the call, stopping at the first missing one), plus the name comparisons.
  Measured on a debug build: about 20-30 ms with 1000 prefixes, about 3 ms
  with 60 prefixes of 1000 bytes. The policy is trusted; keep it small.
* **Not supported: a server in another mount namespace or on another host**
  (`wrap -- docker run -v ...`, `podman`, `ssh`, a chroot). The check runs
  in the proxy's view of the filesystem, and the server may resolve the same
  string to a different file. Example: with DENY `/usr/bin`, `/bin/curl`
  is `same` on a Mac (where `/bin` is a real directory) but is
  `/usr/bin/curl` inside a merged-usr Debian image. `wrap` prints a
  warning at startup when the command looks like `docker`, `podman`,
  `nerdctl`, `ssh`, `chroot`, `kubectl`, `bwrap`, ... (also behind
  `env`/`sudo`) and the policy has path rules; the heuristic does not see
  wrapper scripts.
* **Not supported: network and FUSE mounts that expose the same files**
  under another `st_dev` (SMB/NFS to `localhost`, `bindfs`/`sshfs` with
  macFUSE or FSKit, Linux `/run/user/<uid>/doc` or `gvfs`). They are the same
  family as a bind mount of a subdirectory.
* Server-side decoding (`%2F`, `file://`, `~`/`$HOME` expansion, trimming)
  happens after the decision and is invisible to the gate. Non-absolute
  forms are already unsafe for core; an absolute path the server decodes
  further is not covered.
* Ignorable characters: when a filesystem folds names, every Unicode 16
  `Default_Ignorable_Code_Point` and the SFM private-use range U+F000-F0FF
  are dropped from the fold key (HFS+ ignores U+200C-200F, U+202A-202E,
  U+206A-206F and U+FEFF anywhere in a name; macOS ExFAT a leading U+FEFF
  and trailing U+F000-range characters), and a segment made only of them is
  `unresolved`. Checked on a real HFS+ image against the 48 HFS+ aliases a
  reviewer found.
* Relative values are not resolved; core already treats them as unsafe.
* The check happens when the proxy decides. The server opens the path later,
  so a symlink created or swapped in between is not seen (TOCTOU, see
  Limitations).

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
* Path checks are point-in-time (TOCTOU). Arguments covered by a
  `PathPrefix` rule are resolved when the proxy decides; the MCP server opens
  the path afterwards. Replacing a directory with a symlink between the two
  is not detected, nor is a filesystem mounted, or a policy prefix created,
  in between (filesystem sensitivity and identities are read at decision
  time too). Arguments no `PathPrefix` rule covers are never resolved.
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
