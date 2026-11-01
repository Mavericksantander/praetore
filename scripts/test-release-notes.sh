#!/usr/bin/env bash
# Self-test for scripts/release-notes.sh against a fixed CHANGELOG.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/release-notes.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/CHANGELOG.md" <<'MD'
# Changelog

## Unreleased

- next

## 1.2.0 - 2026-11-01

- one
- two

## 1.1.0

## 1.0.0 (not yet tagged or published)

- old
MD

failures=0
check() {
  local label=$1 want=$2 tag=$3 expected=${4:-}
  local out got
  if out=$("$script" "$tag" "$work/CHANGELOG.md" 2>/dev/null); then got=pass; else got=fail; fi
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: expected $want, got $got"
    failures=$((failures + 1))
  elif [[ "$want" == pass && "$out" != "$expected" ]]; then
    echo "FAIL: $label: unexpected notes:"
    echo "$out"
    failures=$((failures + 1))
  else
    echo "PASS: $label ($got)"
  fi
}

check "dated section" pass v1.2.0 $'- one\n- two'
check "empty section" fail v1.1.0
check "untagged heading is not a release" fail v1.0.0
check "missing section" fail v9.9.9
check "tag without v" fail 1.2.0
check "not a semver tag" fail v1.2
check "Unreleased is never released" fail vUnreleased

if [[ $failures -ne 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
