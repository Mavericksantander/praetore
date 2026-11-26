#!/usr/bin/env bash
# Self-test of scripts/test-check-test-hooks-feature.sh: its release-build
# cases must follow whole workflow lines, not a piece of text. Each variant
# below is a valid workflow that a match by text broke (#253, #257): the
# self-test must still pass on it and must cover the changed line.
#   reformatted: the praetore-verify release line with --target before
#                --package.
#   prefixed:    a second release line that starts like the first one.
# Works on copies of the tracked files, offline, like the self-test.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
workflow=.github/workflows/assurance.yml
original='      - run: cargo build --release --locked --package praetore-verify'
failures=0

# variant NAME NEW-LINES... : a git copy of the tree where the whole line
# $original is replaced by NEW-LINES; prints its directory.
variant() {
  local name=$1
  shift
  local dir="$work/$name"
  mkdir -p "$dir"
  (cd "$here" && git ls-files -z | xargs -0 tar -cf - --no-recursion) | tar -xf - -C "$dir"
  python3 - "$dir/$workflow" "$original" "$@" <<'PY'
import sys
path, original, new = sys.argv[1], sys.argv[2], sys.argv[3:]
lines = open(path).read().split("\n")
assert lines.count(original) == 1, (path, original)
at = lines.index(original)
lines[at:at + 1] = new
open(path, "w").write("\n".join(lines))
PY
  git -C "$dir" init -q
  git -C "$dir" add -A
  echo "$dir"
}

# expect NAME DIR LINE...: the copy's self-test passes and has a case for
# each LINE (trimmed), for both forbidden additions.
expect() {
  local name=$1 dir=$2 got=0
  shift 2
  CHECK_TEST_HOOKS_OFFLINE=1 "$dir/scripts/test-check-test-hooks-feature.sh" >"$work/out" 2>&1 || got=$?
  local ok=1
  [ "$got" = 0 ] || ok=0
  for line in "$@"; do
    local trimmed="${line#"${line%%[![:space:]]*}"}"
    for case in "enables test-hooks" "uses --all-features"; do
      grep -F -- "ok: a release build $case ($workflow:" "$work/out" | grep -qF -- ": $trimmed) " || ok=0
    done
  done
  if [ "$ok" = 1 ]; then
    echo "ok: $name (self-test exit $got, changed lines covered)"
  else
    echo "FAIL: $name: self-test exit $got or a changed line has no case"
    sed 's/^/    /' "$work/out"
    failures=$((failures + 1))
  fi
}

reformatted='      - run: cargo build --release --locked --target x86_64-unknown-linux-gnu --package praetore-verify'
dir=$(variant reformatted "$reformatted")
expect reformatted "$dir" "$reformatted"

prefixed='      - run: cargo build --release --locked --package praetore-verify --target aarch64-apple-darwin'
dir=$(variant prefixed "$original" "$prefixed")
expect prefixed "$dir" "$original" "$prefixed"

[ "$failures" = 0 ] || { echo "$failures variant(s) failed"; exit 1; }
echo "all variants passed"
