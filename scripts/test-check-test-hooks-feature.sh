#!/usr/bin/env bash
# Self-test for scripts/check-test-hooks-feature.sh: the tree as it is
# passes; each way of shipping the feature fails. Works on copies of the
# tracked files, offline (run after the dependencies are fetched).
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
script="$here/scripts/check-test-hooks-feature.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

copy() {
  local dir="$work/$1"
  mkdir -p "$dir"
  (cd "$here" && git ls-files -z | xargs -0 tar -cf - --no-recursion) | tar -xf - -C "$dir"
  echo "$dir"
}

# check LABEL WANT DIR [REASON]: WANT 0 must pass; otherwise the script
# must fail and say REASON (so a failure for another cause does not count).
check() {
  local label=$1 want=$2 dir=$3 reason=${4:-} got=0
  CHECK_TEST_HOOKS_OFFLINE=1 "$script" "$dir" >"$work/out" 2>"$work/err" || got=$?
  if { [ "$want" = 0 ] && [ "$got" != 0 ]; } || { [ "$want" != 0 ] && [ "$got" = 0 ]; } \
    || { [ -n "$reason" ] && ! grep -qF -- "$reason" "$work/out" "$work/err"; }; then
    echo "FAIL: $label: exit $got, want $([ "$want" = 0 ] && echo 0 || echo 'non-zero')"
    sed 's/^/    /' "$work/out" "$work/err"
    failures=$((failures + 1))
  else
    echo "ok: $label (exit $got)"
  fi
}

edit() {
  python3 - "$@" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
assert text.count(old) == 1, (path, old)
open(path, "w").write(text.replace(old, new))
PY
}

dir=$(copy pristine)
check "the tree as it is" 0 "$dir"

dir=$(copy default)
edit "$dir/crates/praetore-replay-postgres/Cargo.toml" 'test-hooks = []' $'test-hooks = []\ndefault = ["test-hooks"]'
check "default enables test-hooks" 1 "$dir" 'enables test-hooks by default'

dir=$(copy default-indirect)
edit "$dir/crates/praetore-replay-postgres/Cargo.toml" 'test-hooks = []' $'test-hooks = []\nextras = ["test-hooks"]\ndefault = ["extras"]'
check "default enables test-hooks through another feature" 1 "$dir" 'enables test-hooks by default'

dir=$(copy normal-dependency)
edit "$dir/crates/praetore-cli/Cargo.toml" 'praetore-replay-postgres = { path = "../praetore-replay-postgres" }' 'praetore-replay-postgres = { path = "../praetore-replay-postgres", features = ["test-hooks"] }'
check "a shipping crate's normal dependency enables test-hooks" 1 "$dir" 'praetore-cli enables praetore-replay-postgres/test-hooks from a normal dependency'

dir=$(copy crate-feature)
edit "$dir/crates/praetore-gateway-service/Cargo.toml" '[dependencies]' $'[features]\nhooks = ["praetore-replay-postgres/test-hooks"]\n\n[dependencies]'
check "a shipping crate's feature enables test-hooks" 1 "$dir" 'praetore-gateway-service feature hooks enables praetore-replay-postgres/test-hooks'

dir=$(copy release-features)
edit "$dir/.github/workflows/assurance.yml" 'cargo build --release --locked --package praetore-verify' 'cargo build --release --locked --package praetore-verify --features praetore-replay-postgres/test-hooks'
check "a release build enables test-hooks" 1 "$dir" 'release build enables test hooks or all features'

dir=$(copy release-all-features)
edit "$dir/.github/workflows/assurance.yml" 'cargo build --release --locked --package praetore-verify' 'cargo build --release --locked --package praetore-verify --all-features'
check "a release build uses --all-features" 1 "$dir" 'release build enables test hooks or all features'

[ "$failures" = 0 ] || { echo "$failures case(s) failed"; exit 1; }
echo "all cases passed"
