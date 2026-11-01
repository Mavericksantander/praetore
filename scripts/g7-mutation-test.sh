#!/usr/bin/env bash
# G7 mutation test: shows that the runtime tests for `safety:*` actions
# depend on the `classify` call at each entry point.
#
# For each entry point (gateway HTTP API, praetore-mcp gate, Claude Code
# hook), for the gateway's reserved-prefix gate alone, for the engine's own
# class re-check, and for the unclassified refusal deciding before the
# request is verified, it:
#   1. runs the G7 runtime tests on the unmodified tree (they must pass);
#   2. applies scripts/g7-mutants/<entry>.patch, which removes the classify
#      call and wraps the action unclassified, as the code did before G7
#      (the patch adds `MissionAction::mutant_unclassified`, which exists
#      only in the mutant);
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
    git apply -R "scripts/g7-mutants/$applied.patch"
    applied=""
  fi
}
trap revert EXIT

# One test command per line. A mutant counts as killed only when every
# listed command fails on it.
tests_for() {
  case "$1" in
    gateway) echo "cargo test --locked -p praetore-gateway --test safety_actions" ;;
    mcp) echo "cargo test --locked -p praetore-mcp --lib g7_" ;;
    hook) echo "cargo test --locked --manifest-path examples/claude-code-hook/Cargo.toml tests_g7" ;;
    gateway-prefix) echo "cargo test --locked -p praetore-gateway --test safety_actions reserved_safety_prefix_answers_the_same_declared_or_not" ;;
    engine) echo "cargo test --locked -p praetore-core --test action_classes" ;;
    unclassified)
      echo "cargo test --locked -p praetore-core --test action_classes"
      echo "cargo test --locked -p praetore-gateway --test enforcement g7_forged_or_unauthenticated_unclassified_request_leaves_no_receipt"
      ;;
  esac
}

survivors=0
for mutant in gateway gateway-prefix mcp hook engine unclassified; do
  commands=()
  while IFS= read -r line; do commands+=("$line"); done < <(tests_for "$mutant")
  for command in "${commands[@]}"; do
    printf '\n== %s: baseline (%s)\n' "$mutant" "$command"
    $command 2>&1 | grep -E '^test |test result' || true
    if ! $command > /dev/null 2>&1; then
      echo "FAIL: the $mutant G7 tests do not pass on the unmodified tree"
      exit 1
    fi
  done

  printf '\n== %s: mutant applied (scripts/g7-mutants/%s.patch)\n' "$mutant" "$mutant"
  git apply --check "scripts/g7-mutants/$mutant.patch"
  git apply "scripts/g7-mutants/$mutant.patch"
  applied="$mutant"
  passing=0
  for command in "${commands[@]}"; do
    if ! $command --no-run > /dev/null 2>&1; then
      echo "FAIL: the $mutant mutant does not compile; update scripts/g7-mutants/$mutant.patch"
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
