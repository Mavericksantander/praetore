#!/usr/bin/env bash
# Runs the HighAssurance tests of examples/claude-code-hook and checks that
# each named test ran and passed.
#
# The check reads exit codes, not test output. The old CI step searched the
# output for `^test tests_high_assurance::<name> ... ok$`. A test that starts a
# child process (the hook binary) gets the child's stdout on the same line,
# between `... ` and `ok`, and the search failed although the test passed.
#
# 1. The whole module once, one thread, output shown, for the log. Its exit
#    code must be 0.
# 2. Each named test alone: `cargo test -- --exact <path> --test-threads=1`.
#    Its exit code must be 0, and exactly one target must report
#    `running 1 test`. That line is printed before the test starts, so
#    nothing the test prints can split it. With `--exact`, a name that
#    matches no test runs 0 tests and exits 0, so the count is what catches
#    a renamed or removed test.
#
# Usage: scripts/check-hook-high-assurance-tests.sh   (from the repo root)
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
  same_tool_use_id_twice_is_allowed_and_reported
  missing_tool_use_id_is_recorded_as_absent
  tool_use_id_is_bounded_and_escaped
  guard::replaying_the_same_request_is_refused
  guard::guard_reports_unavailable_when_the_store_is
  guard::concurrent_claims_of_one_request_succeed_exactly_once
  guard::concurrent_hook_calls_each_claim_their_own_request
  guard::directory_owned_by_another_user_is_refused
)

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
  out="$(cargo test --manifest-path "$manifest" --locked -- --exact "$name" --test-threads=1 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "$out"
    echo "::error::$test failed (cargo test exit $rc)"
    exit 1
  fi
  ran="$(grep -c '^running 1 test$' <<<"$out" || true)"
  if [ "$ran" -ne 1 ]; then
    echo "$out"
    echo "::error::$test did not run: no test is named $name"
    exit 1
  fi
  echo "ok: $name"
done
echo "all ${#tests[@]} named HighAssurance hook tests ran and passed"
