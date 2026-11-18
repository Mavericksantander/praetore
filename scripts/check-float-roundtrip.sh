#!/usr/bin/env bash
# Every workspace package that ships serde_json must build it with
# `float_roundtrip`.
#
# Without that feature serde_json rounds some decimal literals to the wrong
# f64 (49.9999999999999965 reads as 49.99999999999999 instead of 50.0). A
# policy gate, a verifier or a receipt writer built that way reads a number
# other than the one an MCP server reads from the same bytes, and a receipt
# can be written that verify cannot read back.
#
# Each package is resolved on its own, over its shipped (normal + build)
# dependency graph: a workspace-wide command unifies features and would hide
# a package that loses the feature when installed alone.
set -euo pipefail

packages="$(cargo metadata --locked --no-deps --format-version 1 |
  python3 -c 'import json,sys; print("\n".join(p["name"] for p in json.load(sys.stdin)["packages"]))')"

failed=0
for package in $packages; do
  if ! tree="$(cargo tree --locked -p "$package" --edges normal,build,features -i serde_json 2>/dev/null)"; then
    echo "skip $package (serde_json is not in its shipped graph)"
    continue
  fi
  if grep -qF 'serde_json feature "float_roundtrip"' <<<"$tree"; then
    echo "ok   $package"
  else
    echo "::error::$package ships serde_json without float_roundtrip. Root cause: the feature is not enabled by $package or by any of its dependencies, so its JSON numbers are rounded differently from the MCP server's. Fix: in crates/$package/Cargo.toml set serde_json = { version = \"1.0\", features = [\"float_roundtrip\"] }."
    failed=1
  fi
done
exit "$failed"
