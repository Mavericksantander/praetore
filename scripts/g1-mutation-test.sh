#!/usr/bin/env bash
# G1 mutation test: shows that the safety ingestion tests depend on the gap
# check (in the ingester and in the verifier) and on the rejected-record
# path.
#
# For each mutant it:
#   1. runs the G1 tests on the unmodified tree (they must pass);
#   2. applies scripts/g1-mutants/<mutant>.patch:
#      * ingest-gap: the ingester no longer writes a loss record for a
#        source_seq gap;
#      * verify-gap: the verifier no longer requires source_seq continuity;
#      * rejected: input that does not verify is dropped silently instead of
#        stored as a signed `rejected` record;
#   3. checks that the mutant compiles and that the same tests now FAIL;
#   4. reverts the patch.
# Exits 0 only if every mutant is killed. A patch that no longer applies or
# a mutant that does not compile fails the script: update the patch.
# Run from anywhere inside the repository. Uses debug builds.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

applied=""
revert() {
  if [ -n "$applied" ]; then
    git apply -R "scripts/g1-mutants/$applied.patch"
    applied=""
  fi
}
trap revert EXIT

# One test command per line. A mutant counts as killed only when every
# listed command fails on it.
tests_for() {
  case "$1" in
    ingest-gap)
      echo "cargo test --locked -p praetore-core --lib safety_ingest::tests::a_source_seq_gap_is_recorded_as_a_signed_loss_record"
      echo "cargo test --locked -p praetore-verify --test safety_journal_cli"
      ;;
    verify-gap)
      echo "cargo test --locked -p praetore-core --lib safety_ingest::tests::a_gap_without_a_loss_record_fails_even_when_signed"
      ;;
    rejected)
      echo "cargo test --locked -p praetore-core --lib safety_ingest::tests::input_that_does_not_verify_is_recorded_as_rejected_never_dropped"
      echo "cargo test --locked -p praetore-verify --test safety_journal_cli"
      ;;
  esac
}

survivors=0
for mutant in ingest-gap verify-gap rejected; do
  commands=()
  while IFS= read -r line; do commands+=("$line"); done < <(tests_for "$mutant")
  for command in "${commands[@]}"; do
    printf '\n== %s: baseline (%s)\n' "$mutant" "$command"
    $command 2>&1 | grep -E '^test |test result' || true
    if ! $command > /dev/null 2>&1; then
      echo "FAIL: the $mutant G1 tests do not pass on the unmodified tree"
      exit 1
    fi
  done

  printf '\n== %s: mutant applied (scripts/g1-mutants/%s.patch)\n' "$mutant" "$mutant"
  git apply --check "scripts/g1-mutants/$mutant.patch"
  git apply "scripts/g1-mutants/$mutant.patch"
  applied="$mutant"
  passing=0
  for command in "${commands[@]}"; do
    if ! $command --no-run > /dev/null 2>&1; then
      echo "FAIL: the $mutant mutant does not compile; update scripts/g1-mutants/$mutant.patch"
      exit 1
    fi
    set +e
    output="$($command 2>&1)"
    status=$?
    set -e
    printf -- '-- %s\n' "$command"
    grep -E '^test |test result|panicked at|assertion|left:|right:' <<<"$output" | head -40 || true
    if [ "$status" -eq 0 ]; then
      echo "still passes: $command"
      passing=$((passing + 1))
    else
      echo "fails on the mutant (exit $status): $command"
    fi
  done
  revert
  if [ "$passing" -ne 0 ]; then
    echo "SURVIVED: $passing of the $mutant test commands still pass with the mutant"
    survivors=$((survivors + 1))
  else
    echo "KILLED: the $mutant tests fail on the mutant"
  fi
done

if [ "$survivors" -ne 0 ]; then
  echo "RESULT: $survivors mutant(s) survived"
  exit 1
fi
echo
echo "RESULT: every mutant was killed"
