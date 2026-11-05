#!/usr/bin/env bash
# Tests scripts/check-actions-pinned.sh with one workflow line per case.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/check-actions-pinned.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sha=11d5960a326750d5838078e36cf38b85af677262
upper=$(tr a-f A-F <<<"$sha")

check() { # <expected: pass|fail> <workflow line>
  printf 'jobs:\n  a:\n    steps:\n%s\n' "$2" > "$work/w.yml"
  local result=pass
  "$script" "$work" > /dev/null 2>&1 || result=fail
  if [[ "$result" != "$1" ]]; then
    echo "FAIL: expected $1, got ${result}: $2"
    exit 1
  fi
  echo "ok: $1: $2"
}

check pass "      - uses: actions/checkout@${sha}"
check pass "      - uses: actions/checkout@${sha} # v4.4.0"
check pass "        uses: actions/cache/restore@${sha}"
check pass "      - uses: actions/checkout@${sha}
      - run: echo the word uses in a command"
check fail "      - uses: actions/checkout@v4"
check fail "        uses: actions/checkout@v4"
check fail "      - uses: dtolnay/rust-toolchain@stable"
check fail "      - uses: actions/checkout"
check fail "      - uses: actions/checkout@${sha:0:39}"
check fail "      - uses: actions/checkout@${sha}0"
check fail "      - uses: actions/checkout@${upper}"
check fail "      - uses: actions/checkout@v4 # ${sha}"
check fail "      - uses: \"actions/checkout@v4\""
check fail "      - \"uses\": actions/checkout@v4"
check fail "      - {uses: actions/checkout@v4}"
check fail "      - uses: ./.github/actions/local"
check fail "      - uses: docker://alpine:3"
check fail "      - run: echo no action here"

# A pinned line does not hide an unpinned one elsewhere, in another file.
printf '    - uses: actions/checkout@%s\n' "$sha" > "$work/w.yml"
printf '    - uses: actions/checkout@v4\n' > "$work/other.yaml"
if "$script" "$work" > /dev/null 2>&1; then
  echo "FAIL: an unpinned uses: in a .yaml file passed"
  exit 1
fi
echo "ok: fail: an unpinned uses: in another file"
rm "$work"/*
if "$script" "$work" > /dev/null 2>&1; then
  echo "FAIL: an empty directory passed"
  exit 1
fi
echo "ok: fail: no workflows"
