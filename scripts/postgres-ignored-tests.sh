#!/usr/bin/env bash
# Runs every #[ignore] test of `praetore-replay-postgres --test postgres`
# (PostgreSQL integration, migrations 0001 to the latest, G1 safety records),
# one at a time with --exact, except the ones listed below, which need a
# dedicated CI step. A new ignored test runs here without editing the
# workflow. Needs PRAETORE_TEST_DATABASE_URL.
#
# Each test must report "1 passed": a test that is renamed, filtered out or
# skipped fails the run instead of passing silently.
set -euo pipefail

: "${PRAETORE_TEST_DATABASE_URL:?PRAETORE_TEST_DATABASE_URL is required}"

# Run by their own steps in .github/workflows/assurance.yml:
EXCLUDED=(
  # Must run before any test creates praetore_runtime.
  postgres_migrations_refuse_a_missing_runtime_group_up_front
  # Logs in as the `postgres` superuser.
  postgres_runtime_role_must_not_own_or_bypass_the_schema
  # Two phases around a server restart.
  replay_claim_survives_server_restart
  postgres_journal_survives_server_restart_without_automatic_dispatch
  postgres_apd_and_migrations_survive_restart
  # Child processes of postgres_apd_crash_between_approve_and_claim_closes_as_crash_recovered.
  crash_helper_approve_then_hang
  crash_helper_reconcile
)

listed="$(cargo test -q -p praetore-replay-postgres --locked --test postgres -- --ignored --list 2>/dev/null | sed -n 's/: test$//p')"
total=0
for test in $listed; do
  for excluded in "${EXCLUDED[@]}"; do
    [ "$test" = "$excluded" ] && continue 2
  done
  total=$((total + 1))
  echo "::group::$test"
  output="$(cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored --exact "$test" 2>&1)" || { echo "$output"; echo "::error::$test failed"; exit 1; }
  echo "$output"
  echo "::endgroup::"
  grep -q "test result: ok. 1 passed" <<<"$output" || { echo "::error::$test did not run"; exit 1; }
done
# Every excluded test must still exist (a rename would drop it silently).
for excluded in "${EXCLUDED[@]}"; do
  grep -qxF "$excluded" <<<"$listed" || { echo "::error::excluded test $excluded does not exist"; exit 1; }
done
g1="$(grep -c '^g1_safety::' <<<"$listed" || true)"
[ "$g1" -ge 1 ] || { echo "::error::no G1 safety test was listed"; exit 1; }
echo "ran $total ignored tests ($g1 G1 safety tests); ${#EXCLUDED[@]} run by dedicated steps"
