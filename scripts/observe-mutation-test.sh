#!/usr/bin/env bash
# Observe fails closed: shows that the end-to-end test of an evaluation
# error depends on the refusal in `decide` (praetore-mcp/src/proxy.rs).
#
#   1. runs the test on the unmodified tree (it must pass);
#   2. applies scripts/observe-mutants/m2-evaluation-error-forwarded.patch,
#      which makes observe forward a call it could not evaluate, as before;
#   3. requires the mutant to compile and the same test to fail by a panic
#      (cargo test exit 101), not by a build error;
#   4. reverts the patch.
# Exits 0 only if the mutant is killed. A patch that no longer applies fails
# the script: update the patch. Run from anywhere inside the repository.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

patch=scripts/observe-mutants/m2-evaluation-error-forwarded.patch
test=a_call_that_cannot_be_evaluated_is_refused_in_observe
command=(cargo test --locked -p praetore-mcp --test observe_fails_closed -- --exact "$test")

applied=0
revert() {
  if [ "$applied" -eq 1 ]; then
    git apply -R "$patch"
    applied=0
  fi
}
trap revert EXIT

# `cargo test --test` alone does not build the examples; the test runs
# examples/fake_server as the wrapped server.
cargo build --locked -p praetore-mcp --example fake_server

printf '== baseline: %s\n' "${command[*]}"
"${command[@]}"

printf '\n== mutant applied (%s)\n' "$patch"
git apply --check "$patch"
git apply "$patch"
applied=1
if ! cargo test --locked -p praetore-mcp --test observe_fails_closed --no-run > /dev/null 2>&1; then
  echo "FAIL: the mutant does not compile; update $patch"
  exit 1
fi
set +e
output="$("${command[@]}" 2>&1)"
status=$?
set -e
grep -E '^test |test result|panicked at' <<<"$output" | head -20 || true
revert
echo "exit $status on the mutant"
if [ "$status" -ne 101 ] || ! grep -q 'panicked at' <<<"$output"; then
  echo "SURVIVED: $test does not fail by a panic on the mutant"
  exit 1
fi
echo "KILLED: $test fails on the mutant (exit 101, panicked)"
