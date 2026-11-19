#!/usr/bin/env bash
# Proves the HighAssurance inventory check does not use the fragile grep.
#
# The old CI step counted `^running 1 test$`. A listing that contains that
# line and a split `test <name> ... ok`, and no `<name>: test` line, was
# counted as one run. This script requires that fixture to be rejected, and
# requires the same noise on a complete `--list` to be accepted.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/check-hook-high-assurance-tests.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat >"$work/grep-shaped" <<'EOF'
running 1 test
test tests_high_assurance::every_receipt_records_a_signed_decision_time ... child stdout
ok
EOF

grep_count=$(grep -c '^running 1 test$' "$work/grep-shaped" || true)
if [ "$grep_count" -ne 1 ]; then
  echo "fixture must be one the old grep counted as a single run (got $grep_count)"
  exit 1
fi
if "$script" --expect-names <"$work/grep-shaped"; then
  echo "inventory check accepted a listing that only looks like a run"
  exit 1
fi

"$script" --print-expected >"$work/names"
sed 's/$/: test/' "$work/names" >"$work/lines"
{
  cat "$work/lines"
  cat "$work/grep-shaped"
} >"$work/complete"
"$script" --expect-names <"$work/complete"

{
  cat "$work/complete"
  echo "tests_high_assurance::not_in_the_inventory: test"
} >"$work/extra"
if "$script" --expect-names <"$work/extra"; then
  echo "an unlisted HighAssurance test was accepted"
  exit 1
fi

{
  sed '1d; s/$/: test/' "$work/names"
  echo "running 1 test"
} >"$work/dropped"
if "$script" --expect-names <"$work/dropped"; then
  echo "a dropped HighAssurance test was accepted"
  exit 1
fi

sed -n '1s/$/: test/p' "$work/names" >"$work/ignored"
if "$script" --reject-if-ignored <"$work/ignored"; then
  echo "an ignored HighAssurance test was accepted"
  exit 1
fi
printf '0 tests, 0 benchmarks\n' | "$script" --reject-if-ignored

echo "high assurance inventory check: grep-shaped miss rejected, exact list accepted"
