#!/usr/bin/env bash
# Fails unless serde_json's float_roundtrip feature is active for every crate
# that parses JSON from the client or from a journal.
#
# `cargo tree -e features -i serde_json` prints the feature edges of that
# crate. float_roundtrip is the correctly rounded binary64 parser. Without it,
# a number can be evaluated as one value and executed as another.
#
# Usage: scripts/check-serde-json-float-roundtrip.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

fail=0
check() {
  local label="$1"
  shift
  echo "::group::${label}"
  local tree
  if ! tree="$("$@" 2>&1)"; then
    echo "$tree"
    echo "error: cargo tree failed for ${label}" >&2
    echo "::endgroup::"
    fail=1
    return
  fi
  printf '%s\n' "$tree"
  echo "::endgroup::"
  if ! grep -F 'float_roundtrip' <<<"$tree" >/dev/null; then
    echo "error: ${label} does not activate serde_json feature float_roundtrip" >&2
    fail=1
  fi
}

# Workspace crates whose production code parses client JSON or journal JSON.
packages=(
  praetore-mcp
  praetore-core
  praetore-verify
  praetore-receipt
  praetore-cli
  praetore-replay-postgres
  praetore-gateway
  praetore-gateway-service
  praetore-console
  praetore-observe
)
for package in "${packages[@]}"; do
  check "$package" cargo tree --locked -p "$package" -e features -i serde_json
done

# Standalone example: it parses hook input and receipt journal lines, and it
# has its own lockfile.
check "examples/claude-code-hook" \
  cargo tree --locked --manifest-path examples/claude-code-hook/Cargo.toml -e features -i serde_json

exit "$fail"
