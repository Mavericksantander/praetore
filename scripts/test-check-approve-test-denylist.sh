#!/usr/bin/env bash
# Self-test for scripts/check-approve-test-denylist.sh using isolated temporary
# copies (never modifies the working tree and never compiles/runs approve).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/scripts/check-approve-test-denylist.sh"
denylist_src="$repo_root/scripts/approve-test-denylist.txt"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Build a lightweight copy of crates/ (only .rs files) so mutations do not touch
# the working tree.
mkdir -p "$work/scripts"
cp "$denylist_src" "$work/scripts/approve-test-denylist.txt"
(cd "$repo_root" && find crates -name '*.rs' -print0 | xargs -0 cp --parents -t "$work")

# 1. Clean copy must pass (exit 0).
"$checker" --root "$work" --denylist "$work/scripts/approve-test-denylist.txt" >/dev/null

# 2. Mutant 1: new decide(Approve) call outside the denylist must fail != 0.
cat <<'RS' >> "$work/crates/praetore-mcp/tests/approvals.rs"

#[test]
fn mutant_unlisted_approve_call_must_fail() {
    let (_temp, home) = init_home();
    let _ = praetore_mcp::approvals::decide(&home, "id", praetore_mcp::approvals::HumanOutcome::Approve, None);
}
RS

set +e
out_unlisted="$("$checker" --root "$work" --denylist "$work/scripts/approve-test-denylist.txt" 2>&1)"
rc_unlisted=$?
set -e
if [[ "$rc_unlisted" -eq 0 ]]; then
  echo "FAIL: mutant 1 (unlisted approve call) exited 0; expected non-zero" >&2
  exit 1
fi
grep -Fq "mutant_unlisted_approve_call_must_fail" <<<"$out_unlisted" || {
  echo "FAIL: mutant 1 output did not name mutant_unlisted_approve_call_must_fail:" >&2
  echo "$out_unlisted" >&2
  exit 1
}
grep -Fq "Root cause:" <<<"$out_unlisted" || {
  echo "FAIL: mutant 1 output missing Root cause explanation:" >&2
  echo "$out_unlisted" >&2
  exit 1
}

# Revert Mutant 1
cp "$repo_root/crates/praetore-mcp/tests/approvals.rs" "$work/crates/praetore-mcp/tests/approvals.rs"

# 3. Mutant 2: stale entry in denylist must fail != 0.
echo "praetore-gateway | --test enforcement | runnable | nonexistent_stale_approve_test" >> "$work/scripts/approve-test-denylist.txt"

set +e
out_stale="$("$checker" --root "$work" --denylist "$work/scripts/approve-test-denylist.txt" 2>&1)"
rc_stale=$?
set -e
if [[ "$rc_stale" -eq 0 ]]; then
  echo "FAIL: mutant 2 (stale denylist entry) exited 0; expected non-zero" >&2
  exit 1
fi
grep -Fq "nonexistent_stale_approve_test" <<<"$out_stale" || {
  echo "FAIL: mutant 2 output did not name nonexistent_stale_approve_test:" >&2
  echo "$out_stale" >&2
  exit 1
}
grep -Fq "Root cause:" <<<"$out_stale" || {
  echo "FAIL: mutant 2 output missing Root cause explanation:" >&2
  echo "$out_stale" >&2
  exit 1
}

echo "OK: test-check-approve-test-denylist passed (clean=0, unlisted_mutant=$rc_unlisted, stale_mutant=$rc_stale)"
