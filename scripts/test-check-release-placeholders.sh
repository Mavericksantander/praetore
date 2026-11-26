#!/usr/bin/env bash
# Self-test for scripts/check-release-placeholders.sh.
# Fixtures are built at run time ("${del}" stands for DEL) so that neither
# this file nor the checker holds a placeholder the checker would find.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script=${CHECK_RELEASE_PLACEHOLDERS:-"$here/check-release-placeholders.sh"}
del=DEL
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failures=0
expect() {
  local label=$1 want=$2 root=$3 got=0
  "$script" "$root" >"$work/out" 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: expected exit $want, got $got"
    sed 's/^/  /' "$work/out"
    failures=$((failures + 1))
  else
    echo "PASS: $label (exit $got)"
  fi
}

# A fresh repository with one tracked file holding $1 at path $2.
repo_with() {
  local dir
  dir=$(mktemp -d "$work/repo.XXXXXX")
  git -C "$dir" init -q
  mkdir -p "$dir/$(dirname "$2")"
  printf 'Release notes\n%s\n' "$1" >"$dir/$2"
  git -C "$dir" add -A
  echo "$dir"
}

expect "no placeholder" 0 "$(repo_with 'sha256 0123abcd, tag v0.3.7' README.md)"
expect "word -${del}- outside brackets is not a placeholder" 0 \
  "$(repo_with "SHA256-${del}-ARTEFACTO and <SHA256 ${del}>" README.md)"
expect "artifact SHA-256 placeholder in README" 1 \
  "$(repo_with "<SHA256-${del}-ARTEFACTO-v0.3.7>  praetore-mcp" README.md)"
expect "tag commit placeholder in docs" 1 \
  "$(repo_with "commit <SHA-${del}-COMMIT-${del}-TAG-v0.3.7>" docs/operations.md)"
expect "tag date placeholder outside Markdown" 1 \
  "$(repo_with "date: <FECHA-${del}-TAG-v0.3.7>" .github/workflows/x.yml)"

ignored=$(repo_with 'clean' README.md)
printf 'target/\n' >"$ignored/.gitignore"
mkdir -p "$ignored/target"
printf '<SHA-%s-COMMIT-%s-TAG-v0.3.7>\n' "$del" "$del" >"$ignored/target/notes.md"
git -C "$ignored" add -A
expect "placeholder only in an ignored file" 0 "$ignored"

expect "not a git work tree" 2 "$work/nowhere"

# The checker and this self-test sit in the real tree: it must not find
# itself.
expect "this repository (checker and self-test included)" 0 "$(cd "$here/.." && pwd)"

if (( failures > 0 )); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
