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

# Release builds: every whole line of the workflow that is a
# `cargo build ... --release ...` command, whatever the order of its flags,
# gets each forbidden addition in its own copy, and the check must refuse
# it. Lines are picked and replaced by number, never by a piece of text, so
# a reformatted line or a second line that starts the same way is covered
# too. No such line at all is a failure: the case would test nothing.
release_lines() {
  python3 - "$1" <<'PY'
import sys
for number, line in enumerate(open(sys.argv[1]).read().split("\n"), 1):
    tokens = line.split()
    if "cargo" in tokens:
        rest = tokens[tokens.index("cargo") + 1:]
        if rest[:1] == ["build"] and "--release" in rest:
            print(number)
PY
}

# edit_line PATH NUMBER ADDITION: appends ADDITION to that whole line
# (before a trailing backslash continuation).
edit_line() {
  python3 - "$@" <<'PY'
import sys
path, number, addition = sys.argv[1], int(sys.argv[2]), sys.argv[3]
lines = open(path).read().split("\n")
line = lines[number - 1]
if line.endswith("\\"):
    lines[number - 1] = line[:-1].rstrip() + " " + addition + " \\"
else:
    lines[number - 1] = line + " " + addition
open(path, "w").write("\n".join(lines))
PY
}

workflow=.github/workflows/assurance.yml
mapfile -t numbers < <(release_lines "$here/$workflow")
if [ "${#numbers[@]}" = 0 ]; then
  echo "FAIL: no cargo build --release line in $workflow"
  failures=$((failures + 1))
fi
for number in "${numbers[@]}"; do
  line=$(sed -n "${number}p" "$here/$workflow" | sed 's/^ *//')
  dir=$(copy "release-features-$number")
  edit_line "$dir/$workflow" "$number" '--features praetore-replay-postgres/test-hooks'
  check "a release build enables test-hooks ($workflow:$number: $line)" 1 "$dir" 'release build enables test hooks or all features'
  dir=$(copy "release-all-features-$number")
  edit_line "$dir/$workflow" "$number" '--all-features'
  check "a release build uses --all-features ($workflow:$number: $line)" 1 "$dir" 'release build enables test hooks or all features'
done

[ "$failures" = 0 ] || { echo "$failures case(s) failed"; exit 1; }
echo "all cases passed"
