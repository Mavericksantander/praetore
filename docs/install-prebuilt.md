# Install praetore-mcp from the published v0.3.3 release

This page installs the `praetore-mcp` binary from the published
[v0.3.3 release](https://github.com/Mavericksantander/praetore/releases/tag/v0.3.3).
That release was built from commit
`0ce6334ff33d7e76a2e2a2bdd3cde69dcd416a0c`. It is not a build of the
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

Download one archive from the release. There is no public Linux ARM binary
and no brew installer.

| Machine | Archive |
| --- | --- |
| macOS Apple silicon | `praetore-mcp-v0.3.3-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `praetore-mcp-v0.3.3-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `praetore-mcp-v0.3.3-x86_64-unknown-linux-gnu.tar.gz` |

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
6535454b0eb692c29e7410d4856ebc72ba41c03be6d7e413d2097fc8320c8adf  praetore-mcp-v0.3.3-aarch64-apple-darwin.tar.gz
48aa92ff82de317a7630e9d9483c3a7700b79959d018dd1e8edd3360196432f9  praetore-mcp-v0.3.3-x86_64-apple-darwin.tar.gz
944f18c5985676cfd3c7d9969ba205e6efe3eedbcb3f3d51dfe1c6b3db5b9515  praetore-mcp-v0.3.3-x86_64-unknown-linux-gnu.tar.gz
30573a3cb85346ddba77aecc823998b2c983d201c9c4fcdf5c75843eb5935dde  praetore-verify
```

The `praetore-verify` line is part of the published file. This install does
not use that binary. Do not download or run it on macOS.

The release also includes `SHA256SUMS.sigstore.json`. Checking that
signature is a separate step, described in
[Release artifact integrity](operations.md#release-artifact-integrity).
The check on this page is the digest list above.

## Steps

Replace the archive name in the example with the one for your machine.
The example uses the Apple silicon archive. Do not use `sudo`.

```sh
mkdir -p "$HOME/praetore-v0.3.3"
cd "$HOME/praetore-v0.3.3"
base=https://github.com/Mavericksantander/praetore/releases/download/v0.3.3
curl -fsSL -O "$base/SHA256SUMS"
curl -fsSL -O "$base/praetore-mcp-v0.3.3-aarch64-apple-darwin.tar.gz"
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
tar -xzf praetore-mcp-v0.3.3-aarch64-apple-darwin.tar.gz
cd praetore-mcp-v0.3.3-aarch64-apple-darwin
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
install` records the absolute path of the binary you run.

```sh
command -v praetore-mcp
praetore-mcp --version
```

`command -v` should print `$HOME/.local/bin/praetore-mcp`. The version line
should be `praetore-mcp 0.3.3`. If either check fails, stop.

```sh
praetore-mcp init
praetore-mcp install --client <client> --mode observe --dry-run
praetore-mcp install --client <client> --mode observe
```

`<client>` is `claude-desktop`, `cursor`, or `vscode`. Read the dry-run diff
before you apply it. Restart the client after `install`. `init` writes
local keys, policy, and receipts under `~/.praetore/mcp` (or
`$PRAETORE_MCP_HOME`). The private keys are under `~/.praetore/mcp/keys/`.
Do not print them or paste them anywhere.

Make one harmless `tools/call` through a wrapped MCP server, for example
listing a directory on a server you already configured. Then:

```sh
praetore-mcp receipts --tail 5
praetore-mcp verify
```

`praetore-mcp verify` checks this installation's receipt journal
(integrity, signatures, mode binding). In observe, a receipt records a
decision that was not enforced.

To remove the wrapper, run `praetore-mcp uninstall --client <client>` or
restore the backup file next to the client config, then restart the client.
Remove `~/.local/bin/praetore-mcp` only if you want the program gone.
Delete `~/.praetore/mcp` only when you mean to delete the keys and receipts.
This page does not switch the install to enforce mode.

If a Mac reports `bad CPU type in executable`, the archive does not match
the machine. Use `aarch64-apple-darwin` on Apple silicon and
`x86_64-apple-darwin` on an Intel Mac, and check the checksum again.

## Node and `npx`

A wrapped server that was configured as `npx` can fail when a desktop
client starts it: `praetore-mcp wrap` exits 127 because the client's `PATH`
does not include `npx`. Put the absolute path in the client config, for
example `/opt/homebrew/bin/npx` on Apple silicon Homebrew. `which npx`
prints the path. Show yourself the config change, run `install` again, and
restart the client. This page does not install Node.

## Limits

- Only `tools/call` requests that go through a wrapped MCP server are
  governed. The client's own built-in tools are not.
- Observe mode (the arrival mode) does not block: a DENY receipt records
  what enforce would have blocked, but the call still runs.
- This is pre-release software, not independently audited, with no security
  guarantees. It is not a network service; it runs on the person's computer.
- macOS binaries are not signed or notarized.
- There is no public Linux ARM binary and no brew installer.
- Enforcement is still cooperative (someone who can edit the client config
  can remove the wrapper).
- `praetore-mcp verify` checks this installation's receipt journal
  (integrity, signatures, mode binding). In observe, a receipt records a
  decision that was not enforced.

PRÆTORE provides deterministic authorization and governance primitives for
AI-enabled systems. A receipt shows what this installation recorded. It does
not show that the call was enforced.

Building the library examples from source is a different path. It needs Rust
and a clone, and it stays in the repository [Quickstart](../README.md#quickstart).
