# Install praetore-mcp from the published v0.3.4 release

This page installs the `praetore-mcp` binary from the published
[v0.3.4 release](https://github.com/Mavericksantander/praetore/releases/tag/v0.3.4).
That release was built from commit
`a606c111d788bfb927a8c5b953e30bf1d8c37421`. It is not a build of the
current `main` branch. You do not clone the repository, and you do not
install Rust.

`praetore-mcp` is a local stdio MCP proxy for AI-enabled systems. This
is pre-release software, not independently audited, with no security
guarantees. It is not a network service; it runs on the person's computer.

The arrival mode is observe. The steps below stop at `praetore-mcp verify`.
On macOS, that command is the whole verification. The release asset named
`praetore-verify` is a Linux ELF x86_64 binary. Do not download or run it
on macOS.

## Which archive

Download one archive from the release. v0.3.4 has no Windows binary, no
Linux ARM binary, and no brew installer.

| Machine | Archive |
| --- | --- |
| macOS Apple silicon | `praetore-mcp-v0.3.4-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `praetore-mcp-v0.3.4-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `praetore-mcp-v0.3.4-x86_64-unknown-linux-gnu.tar.gz` |

The Linux archive is the `x86_64-unknown-linux-gnu` build from that release.
It was built on GitHub's `ubuntu-latest` runner and needs a glibc at least
as new as that image's. macOS binaries are not signed or notarized.

Each archive unpacks to a directory of the same name containing
`praetore-mcp`, `LICENSE`, and `NOTICE`.

## Checksums

Download `SHA256SUMS` from the same release and check the archive before
you unpack it. These are the published digests. If the downloaded
`SHA256SUMS` does not match this list, stop.

```text
1e29d46c47dbec7289d9b8291dfd79f13f4ac516c0319a474fbdad03899fafe0  praetore-mcp-v0.3.4-aarch64-apple-darwin.tar.gz
d8e539e96217238318643f3bdf283c68b5b2492b62facf5d8fbf273c928195bb  praetore-mcp-v0.3.4-x86_64-apple-darwin.tar.gz
7a7ae8c683f5aff6de204d03675f3bf5622b6fd733cf9c28eb992a6c222839ad  praetore-mcp-v0.3.4-x86_64-unknown-linux-gnu.tar.gz
31114a527f3d221c66abe0acf29ea4eafb2158aeb1978707c42a3d395d634916  praetore-verify
```

The `praetore-verify` line is part of the published file. This install does
not use that binary. Do not download or run it on macOS.

The release also includes `SHA256SUMS.sigstore.json`. Checking that
signature is optional for this install. It needs `cosign`. For v0.3.4,
pass `--certificate-github-workflow-sha a606c111d788bfb927a8c5b953e30bf1d8c37421`
so the check does not need a clone (`git rev-parse` does). What the
signature proves is described in
[Release artifact integrity](operations.md#release-artifact-integrity).
The check this page requires is the digest list above.

## Steps

Replace the archive name in the example with the one for your machine.
The example uses the Apple silicon archive. Do not use `sudo`.

```sh
mkdir -p "$HOME/praetore-v0.3.4"
cd "$HOME/praetore-v0.3.4"
base=https://github.com/Mavericksantander/praetore/releases/download/v0.3.4
curl -fsSL -O "$base/SHA256SUMS"
curl -fsSL -O "$base/praetore-mcp-v0.3.4-aarch64-apple-darwin.tar.gz"
```

On macOS:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
```

On Linux:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

The line for your archive must say `OK`. If it does not, stop. Do not clear
a quarantine attribute, and do not copy the binary.

```sh
tar -xzf praetore-mcp-v0.3.4-aarch64-apple-darwin.tar.gz
cd praetore-mcp-v0.3.4-aarch64-apple-darwin
```

On macOS, after the checksum matches, clear the quarantine attribute on the
extracted binary. Skip both `xattr` commands on Linux. Gatekeeper can refuse
a downloaded program that is not signed or notarized and report that it
cannot be opened or is from an unidentified developer. Do not turn
Gatekeeper off.

```sh
xattr -d com.apple.quarantine praetore-mcp
```

If `xattr` reports that the attribute is already absent, continue. Put the
binary on `PATH` in your user account:

```sh
mkdir -p "$HOME/.local/bin"
cp praetore-mcp "$HOME/.local/bin/praetore-mcp"
```

macOS can copy the quarantine attribute with the file. From the directory
that holds the copy, run the same command on that copy:

```sh
cd "$HOME/.local/bin"
xattr -d com.apple.quarantine praetore-mcp
```

If `~/.local/bin` is not on `PATH`, add it in your own shell startup file:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Open a new shell, then confirm you are running that copy. `praetore-mcp
install` records the absolute path of the binary you run. Move the binary
to `~/.local/bin` before `install`. Moving or replacing that file later
leaves the client config pointing at the old path. Run `install` again
after you move it.

```sh
command -v praetore-mcp
praetore-mcp --version
```

`command -v` should print `$HOME/.local/bin/praetore-mcp`. The version line
should be `praetore-mcp 0.3.4`. If either check fails, stop.

```sh
praetore-mcp init
praetore-mcp install --client <client> --mode observe --dry-run
```

`<client>` is `claude-desktop`, `cursor`, or `vscode`. Read the dry-run diff
before you apply it. `install` and `uninstall` ask
`Apply these changes to <file>? [y/N]` only when stdin is a terminal.
Without a terminal they exit 1 and print
`not modifying <file> without confirmation; re-run with --yes`, and they
do not change the file. After you accept the dry-run, apply it with
`--yes`:

```sh
praetore-mcp install --client <client> --mode observe --yes
```

Run the dry-run again. A wrapped entry is reported as
`skipped: already wrapped by praetore-mcp` and `nothing to change`
(exit 0). Open the config and check that the entry's `command` is the
absolute path of `~/.local/bin/praetore-mcp` and that its args start with
`wrap`. If `command` is still the original server program, the install did
not apply. `praetore-mcp verify` can then print `OK 0 receipts`, which
means the journal is empty.

Restart the client after `install`. A running client keeps the old config.
`init` writes local keys, policy, and receipts under `~/.praetore/mcp` (or
`$PRAETORE_MCP_HOME`). The private keys are under `~/.praetore/mcp/keys/`.
Do not print them or paste them anywhere.

If the dry-run prints `no MCP client configuration found` or
`(no MCP servers found)`, there is no stdio server to wrap. You can add
one test server on a new folder that holds no real data. Stop if
`~/praetore-test` already exists. Create it, put a file `hello.txt` in it,
and take the absolute path with `cd "$HOME/praetore-test" && pwd -P`. Run
`command -v npx`. If that does not print one absolute path, Node is
missing: stop, and do not install Node. Point the server at that test
folder, never at your home directory and never at a project folder. Use
the absolute path of `npx` as `command`. Do not write `~` in the JSON.

Cursor (`~/.cursor/mcp.json`) and Claude Desktop use `mcpServers`. Claude
Desktop's file is `~/Library/Application Support/Claude/claude_desktop_config.json`
on macOS. On Linux it is `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json`
when `XDG_CONFIG_HOME` is set, and `~/.config/Claude/claude_desktop_config.json`
otherwise. VS Code's user `mcp.json` is
`~/Library/Application Support/Code/User/mcp.json` on macOS. On Linux it is
`$XDG_CONFIG_HOME/Code/User/mcp.json` when `XDG_CONFIG_HOME` is set, and
`~/.config/Code/User/mcp.json` otherwise. It uses `servers` and
`"type": "stdio"`. Write the user file, not a project `.cursor/mcp.json`
or `.vscode/mcp.json`.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/absolute/path/to/npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2.3.0", "/absolute/path/to/praetore-test"]
    }
  }
}
```

Then run the observe dry-run and `install --mode observe --yes` again, and
restart the client.

Make one harmless `tools/call` through the wrapped MCP server, for example
listing the test directory. The client's own built-in tools do not produce
a receipt. Then:

```sh
praetore-mcp receipts --tail 5
praetore-mcp verify
```

`praetore-mcp verify` checks this installation's receipt journal
(integrity, signatures, mode binding). In observe, a receipt records a
decision that was not enforced. The v0.3.3 `praetore-mcp verify` does not
read 0.3.4 receipts. A 0.3.4 journal line is `{"seq","prev","evidence"}`.
v0.3.3 reads each line as a bare evidence document. This release's
`praetore-mcp verify` still reads a v0.3.3 journal: those lines are
unchained and may only come before the first chained entry.

A policy change is loaded when `wrap` starts. Restart the client after
`policy deny`, `policy allow`, `policy require-approval`, or
`policy remove`. The `policy` command prints that reminder. To add a first
deny rule, only when a wrapped server is named `filesystem`:

```sh
praetore-mcp policy deny --id first-rule --server filesystem --tool write_file
praetore-mcp policy check
```

Restart the client. In observe, a `write_file` call on the test folder
still writes the file, and `praetore-mcp receipts --tail 5` shows `DENY`
and `first-rule`. The rule blocks that one tool. On
`@modelcontextprotocol/server-filesystem@2.3.0` it does not make the server
read-only: `append_file`, `edit_file`, `create_directory`, `move_file` and
`copy_file` still write. Local approval is the optional step after
enforce, below. Do not add that rule here.

Observe is the arrival mode. To switch to enforce, do not run
`install --mode enforce` on the wrapped entry. That prints
`nothing to change` and exits 0, and the mode already in the config stays.
Uninstall, install again, and restart the client:

```sh
praetore-mcp uninstall --client <client> --dry-run
praetore-mcp uninstall --client <client> --yes
praetore-mcp install --client <client> --mode enforce --dry-run
praetore-mcp install --client <client> --mode enforce --yes
```

Read the enforce dry-run before `--yes`. It must show `wrap` with
`--mode enforce`. In enforce, the same `write_file` call is refused and
the file is not written. The receipt shows `DENY` and `first-rule` with
mode `enforce`. You can instead edit `--mode` in the client config and
restart the client. `install` does not rewrite `--mode` while the entry is
already wrapped.

Optional, after the install is in enforce, and only for the test server
named `filesystem` on `~/praetore-test`. In observe a REQUIRE_APPROVAL
call is not held. Add one rule, restart the client, and ask to create a
directory in `~/praetore-test` with the `create_directory` tool of
`filesystem`. The call is held.

```sh
praetore-mcp policy require-approval --id approve-mkdir --server filesystem --tool create_directory
praetore-mcp approvals
```

`approvals` lists the pending call. An assistant must not run
`praetore-mcp approve`. `approve` needs an interactive terminal (stdin and
stderr are both terminals) and the confirmation code the person types.
Without a terminal it signs nothing. The person runs these in their own
terminal:

```sh
praetore-mcp approvals
praetore-mcp approve <id>
```

After that approval, the same call goes through once. `praetore-mcp reject
<id>` records a rejection, and that call is not forwarded. A pending call
expires after 10 minutes by default. The terminal check is cooperative: a
process that can act as this user can open a terminal and approve. It is
not a guarantee that a person reviewed the call. Deleting or truncating
`approvals/journal.jsonl` lets an approval be used again.

To remove the wrapper, run `praetore-mcp uninstall --client <client> --yes`
or restore the backup file next to the client config, then restart the
client. Remove `~/.local/bin/praetore-mcp` only if you want the program
gone. Delete `~/.praetore/mcp` only when you mean to delete the keys and
receipts.

If a Mac reports `bad CPU type in executable`, the archive does not match
the machine. Use `aarch64-apple-darwin` on Apple silicon and
`x86_64-apple-darwin` on an Intel Mac, and check the checksum again.

## Node and `npx`

A wrapped server that was configured as `npx` can fail when a desktop
client starts it: `praetore-mcp wrap` exits 127 because the client's `PATH`
does not include `npx`. Put the absolute path in the client config, for
example `/opt/homebrew/bin/npx` on Apple silicon Homebrew. `which npx`
prints the path. Show yourself the config change, run `install` again, and
restart the client. This page does not install Node. npm may print
`EBADENGINE` because `@modelcontextprotocol/server-filesystem@2.3.0`
declares `node >= 24`. That warning is from npm. If the server still
answers the tool call, continue. If it does not start, stop. Do not
install or upgrade Node.

## Limits

- Only `tools/call` requests that go through a wrapped MCP server are
  governed. The client's own built-in tools are not.
- Observe mode (the arrival mode) does not block: a DENY receipt records
  what enforce would have blocked, but the call still runs.
- This is pre-release software, not independently audited, with no security
  guarantees. It is not a network service; it runs on the person's computer.
- macOS binaries are not signed or notarized.
- v0.3.4 has no Windows binary, no Linux ARM binary, and no brew installer.
- Enforcement is still cooperative (someone who can edit the client config
  can remove the wrapper).
- `praetore-mcp verify` checks this installation's receipt journal
  (integrity, signatures, mode binding). In observe, a receipt records a
  decision that was not enforced. `OK 0 receipts` means the journal is empty.
  The v0.3.3 `praetore-mcp verify` does not read 0.3.4 receipts.
- A `write_file` deny rule blocks that tool only. On
  `@modelcontextprotocol/server-filesystem@2.3.0`, `append_file`,
  `edit_file`, `create_directory`, `move_file` and `copy_file` still write.
- Policy changes need a client restart. In enforce, a REQUIRE_APPROVAL
  call is held until a person runs `praetore-mcp approve <id>` in an
  interactive terminal. The terminal check is cooperative. Deleting or
  truncating `approvals/journal.jsonl` lets an approval be used again.
  `praetore-mcp reject <id>` records a rejection and the call is not
  forwarded. A pending call expires after 10 minutes by default.

PRÆTORE provides deterministic authorization and governance primitives for
AI-enabled systems. A receipt shows what this installation recorded. It does
not show that the call was enforced.

Building the library examples from source is a different path. It needs Rust
and a clone, and it stays in the repository [Quickstart](../README.md#quickstart).
