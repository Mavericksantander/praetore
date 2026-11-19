#!/usr/bin/env bash
# Runs the HighAssurance tests of examples/claude-code-hook and checks that
# the set of tests in that module is exactly the list below.
#
# The check does not search the test output. A child process of a test writes
# on the same stream as libtest, so a search for `test <name> ... ok` or for
# `running 1 test` accepts a run that did not execute the named test, and
# rejects a run that did. `cargo test -- --format json` is nightly-only.
#
# Stable libtest lists each test as one line `<name>: test` from
# `cargo test -- --list`, before any test runs. This script:
#
# 1. Requires those lines for `tests_high_assurance::` to be exactly the
#    names below, each once. A renamed, removed or added test fails here.
# 2. Requires none of those names in `cargo test -- --list --ignored`.
# 3. Runs the module once, for the log. Its exit code must be 0.
# 4. Runs each name with `--exact`. Its exit code must be 0.
#
# `--exact` on a missing name runs 0 tests and exits 0. Step 1 is what
# catches that. The inventory is what Linux CI lists: a test compiled only
# on another OS is not in this list, and running the script there fails
# until the list matches that OS.
#
#   scripts/check-hook-high-assurance-tests.sh
#   scripts/check-hook-high-assurance-tests.sh --print-expected
#   scripts/check-hook-high-assurance-tests.sh --expect-names       # list on stdin
#   scripts/check-hook-high-assurance-tests.sh --reject-if-ignored  # ignored list on stdin
set -euo pipefail

manifest=examples/claude-code-hook/Cargo.toml
module=tests_high_assurance
tests=(
  every_receipt_records_a_signed_decision_time
  declared_safety_tool_gets_no_receipt_and_no_claim
  state_without_a_replay_store_is_refused_with_a_pointer_to_init
  unavailable_replay_store_fails_closed
  unwritable_receipts_journal_denies_and_leaves_an_orphan_claim
  tool_use_id_is_signed_and_tampering_fails
  unsigned_tool_use_id_copy_only_when_signed
  tool_use_id_of_any_json_type_is_handled
  same_tool_use_id_twice_is_allowed_and_reported
  missing_tool_use_id_is_recorded_as_absent
  tool_use_id_is_bounded_and_escaped
  guard::replaying_the_same_request_is_refused
  guard::guard_reports_unavailable_when_the_store_is
  guard::concurrent_claims_of_one_request_succeed_exactly_once
  guard::concurrent_hook_calls_each_claim_their_own_request
  guard::directory_owned_by_another_user_is_refused
  guard::acl_entry_status_fails_closed
)

expected_names() {
  local test
  for test in "${tests[@]}"; do
    printf '%s::%s\n' "$module" "$test"
  done
}

# stdin is `cargo test -- --list` output. mode is `expect` or `ignored`.
# The program is an argument, so stdin stays the listing.
check_list() {
  local mode=$1
  local expected_file
  expected_file=$(mktemp)
  expected_names >"$expected_file"
  set +e
  python3 -c '
import sys
mode, module, expected_path = sys.argv[1], sys.argv[2], sys.argv[3]
expected = open(expected_path, encoding="utf-8").read().split()
suffix = ": test"
prefix = module + "::"
listed = []
for raw in sys.stdin:
    line = raw.rstrip("\n")
    if not (line.startswith(prefix) and line.endswith(suffix)):
        continue
    name = line[: -len(suffix)]
    if " " in name:
        sys.stderr.write("error: malformed list line: %s\n" % line)
        sys.exit(1)
    listed.append(name)
dupes = sorted({name for name in listed if listed.count(name) > 1})
if dupes:
    sys.stderr.write("duplicate tests_high_assurance names: %s\n" % ", ".join(dupes))
    sys.exit(1)
got, exp = set(listed), set(expected)
if mode == "expect":
    missing = sorted(exp - got)
    extra = sorted(got - exp)
    if missing or extra:
        if missing:
            sys.stderr.write("missing from cargo test --list: %s\n" % ", ".join(missing))
        if extra:
            sys.stderr.write("not in the HighAssurance inventory: %s\n" % ", ".join(extra))
        sys.exit(1)
    sys.exit(0)
if mode == "ignored":
    hit = sorted(got & exp)
    if hit:
        sys.stderr.write("HighAssurance test is ignored: %s\n" % ", ".join(hit))
        sys.exit(1)
    sys.exit(0)
sys.stderr.write("error: unknown mode %s\n" % mode)
sys.exit(2)
' "$mode" "$module" "$expected_file"
  local rc=$?
  set -e
  rm -f "$expected_file"
  return "$rc"
}

case "${1:-}" in
  --print-expected)
    expected_names
    exit 0
    ;;
  --expect-names)
    check_list expect
    exit 0
    ;;
  --reject-if-ignored)
    check_list ignored
    exit 0
    ;;
  "")
    ;;
  *)
    echo "error: unknown argument: $1" >&2
    exit 2
    ;;
esac

cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

set +e
cargo test --manifest-path "$manifest" --locked -- --list >"$tmp/list" 2>"$tmp/list.err"
list_rc=$?
set -e
if [ "$list_rc" -ne 0 ]; then
  cat "$tmp/list.err" >&2
  echo "::error::cargo test --list failed (exit $list_rc)"
  exit 1
fi
check_list expect <"$tmp/list"

set +e
cargo test --manifest-path "$manifest" --locked -- --list --ignored >"$tmp/ignored" 2>"$tmp/ignored.err"
ignored_rc=$?
set -e
if [ "$ignored_rc" -ne 0 ]; then
  cat "$tmp/ignored.err" >&2
  echo "::error::cargo test --list --ignored failed (exit $ignored_rc)"
  exit 1
fi
check_list ignored <"$tmp/ignored"

set +e
cargo test --manifest-path "$manifest" --locked "$module" -- --nocapture --test-threads=1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  echo "::error::the HighAssurance hook tests failed (cargo test exit $rc)"
  exit 1
fi

for test in "${tests[@]}"; do
  name="$module::$test"
  set +e
  cargo test --manifest-path "$manifest" --locked -- --exact "$name" --test-threads=1 >"$tmp/one" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    cat "$tmp/one"
    echo "::error::$test failed (cargo test exit $rc)"
    exit 1
  fi
  echo "ok: $name"
done
echo "all ${#tests[@]} named HighAssurance hook tests ran and passed"
