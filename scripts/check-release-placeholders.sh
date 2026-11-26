#!/usr/bin/env bash
# Fails if a release placeholder reaches a tracked file.
#
# Docs prepared before a tag carry values that only exist after it (the
# commit SHA of the tag, the SHA-256 of each release artifact, the tag
# date). They are written as an upper-case word, "-DEL-", more words, all
# between angle brackets, for example SHA-DEL-COMMIT-DEL-TAG-v0.3.7 or
# SHA256-DEL-ARTEFACTO-v0.3.7 in brackets. Any of them in a tracked file
# means the real value was never filled in.
#
#   scripts/check-release-placeholders.sh [ROOT]
#
# ROOT defaults to the repository of this script. Only files tracked by git
# are read, as the commit that reaches main has them; binary files are
# skipped. This file and its self-test hold no placeholder: the pattern
# below starts with "<[" and the self-test builds its fixtures at run time.
#
# Exit codes: 0 none found, 1 placeholders found (listed as file:line:text),
# 2 ROOT is not a git work tree.
set -euo pipefail

pattern='<[A-Za-z0-9._-]*-DEL-[A-Za-z0-9._-]*>'

root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
if ! git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "check-release-placeholders: $root is not a git work tree" >&2
  exit 2
fi

if hits=$(cd "$root" && git grep -nIE -e "$pattern"); then
  echo "check-release-placeholders: release placeholders in tracked files:" >&2
  echo "$hits" >&2
  echo "Fill in the real values of the release (see docs/operations.md) before this reaches main." >&2
  exit 1
fi
echo "check-release-placeholders: no release placeholders in tracked files"
