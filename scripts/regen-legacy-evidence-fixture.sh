#!/usr/bin/env bash
# Regenerates crates/praetore-verify/tests/fixtures/legacy-evidence-no-policy-digest.json:
# a receipt signed by praetore-core at commit 3db7b5e (origin/main before
# #17), which has no policy_digest. Uses only test keys (secret bytes [1;32],
# [2;32], [3;32]); no real secrets.
#
# Output is equivalent but not byte-identical between runs: at 3db7b5e
# evidence_id is a random UUIDv4 and the intent nonce/timestamps are fresh.
# The test only relies on: no policy_digest, valid signature by attester [3;32].
set -euo pipefail
LEGACY_COMMIT=3db7b5e
repo=$(git rev-parse --show-toplevel)
out="$repo/crates/praetore-verify/tests/fixtures/legacy-evidence-no-policy-digest.json"
tmp=$(mktemp -d)
cleanup() { git -C "$repo" worktree remove --force "$tmp/wt" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
git -C "$repo" worktree add --detach "$tmp/wt" "$LEGACY_COMMIT" >/dev/null
mkdir -p "$tmp/wt/crates/praetore-core/examples"
cp "$repo/scripts/legacy-fixture/gen_legacy.rs" "$tmp/wt/crates/praetore-core/examples/gen_legacy.rs"
(cd "$tmp/wt" && CARGO_TARGET_DIR="$tmp/target" cargo run --quiet -p praetore-core --example gen_legacy) > "$out.tmp"
mv "$out.tmp" "$out"
echo "wrote $out (from $LEGACY_COMMIT)"
