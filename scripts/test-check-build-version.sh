#!/usr/bin/env bash
# Self-test for scripts/check-build-version.sh with stand-in binaries that
# print a fixed --version line.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/check-build-version.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
prints() {
  printf '#!/bin/sh\necho "%s"\n' "$2" > "$work/$1"
  chmod +x "$work/$1"
}
prints release "praetore-mcp 0.3.6"
prints dev "praetore-mcp 0.3.6-dev+abc1234"
prints dev40 "praetore-mcp 0.3.6-dev+$(printf 'a%.0s' $(seq 40))"
prints dev_plain "praetore-mcp 0.3.6-dev"
prints dev_short "praetore-mcp 0.3.6-dev+abc12"
prints dev_upper "praetore-mcp 0.3.6-dev+ABC1234"
prints dev_other "praetore-mcp 0.3.5-dev+abc1234"
prints dev_dots "praetore-mcp 0x3x6-dev+abc1234"
prints dev_suffix "praetore-mcp 0.3.6-dev+abc1234 extra"
prints rc "praetore-mcp 0.3.7-rc.1"
prints rc_dev "praetore-mcp 0.3.7-rc.1-dev+abc1234"
printf 'not a program' > "$work/norun"

failures=0
check() {
  local label=$1 want=$2 bin=$3 crate=$4 ref=$5 ref_name=$6 got=0
  "$script" "$work/$bin" "$crate" "$ref" "$ref_name" > "$work/out" 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: exit $got, want $want"
    sed 's/^/    /' "$work/out"
    failures=$((failures + 1))
  fi
}
branch=refs/heads/main
check "dev build off a tag" 0 dev 0.3.6 "$branch" main
check "dev build, 40 hex" 0 dev40 0.3.6 "$branch" main
check "release build off a tag" 1 release 0.3.6 "$branch" main
check "-dev without commit" 1 dev_plain 0.3.6 "$branch" main
check "commit shorter than 7" 1 dev_short 0.3.6 "$branch" main
check "uppercase commit" 1 dev_upper 0.3.6 "$branch" main
check "another crate version" 1 dev_other 0.3.6 "$branch" main
check "dots are not wildcards" 1 dev_dots 0.3.6 "$branch" main
check "text after the commit" 1 dev_suffix 0.3.6 "$branch" main
check "tag, release build" 0 release 0.3.6 refs/tags/v0.3.6 v0.3.6
check "tag, dev build" 1 dev 0.3.6 refs/tags/v0.3.6 v0.3.6
check "tag is not the crate version" 1 release 0.3.6 refs/tags/v0.3.7 v0.3.7
check "rc tag, rc build" 0 rc 0.3.7-rc.1 refs/tags/v0.3.7-rc.1 v0.3.7-rc.1
check "rc dev build off a tag" 0 rc_dev 0.3.7-rc.1 "$branch" main
check "binary that does not run" 1 norun 0.3.6 "$branch" main
check "binary that does not run, tag" 1 norun 0.3.6 refs/tags/v0.3.6 v0.3.6
got=0
"$script" "$work/dev" 0.3.6 "$branch" > /dev/null 2>&1 || got=$?
if [[ "$got" != 2 ]]; then
  echo "FAIL: three arguments: exit $got, want 2"
  failures=$((failures + 1))
fi
if [[ "$failures" -ne 0 ]]; then
  echo "$failures check-build-version case(s) failed"
  exit 1
fi
echo "check-build-version: all cases pass"
