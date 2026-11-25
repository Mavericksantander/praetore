#!/usr/bin/env bash
# Self-test for scripts/check-approve-test-denylist.sh using isolated temporary
# copies (never modifies the working tree and never compiles/runs approve).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/scripts/check-approve-test-denylist.sh"
denylist_src="$repo_root/scripts/approve-test-denylist.txt"
verbose="${VERBOSE:-0}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/scripts"
cp "$denylist_src" "$work/scripts/approve-test-denylist.txt"
(cd "$repo_root" && find crates -name '*.rs' -print0 | xargs -0 cp --parents -t "$work")

run_mutant() {
  local label="$1"
  local expected_needle="$2"
  shift 2

  set +e
  local out
  out="$("$checker" --root "$work" --denylist "$work/scripts/approve-test-denylist.txt" 2>&1)"
  local rc=$?
  set -e

  if [[ "$rc" -ne 1 ]]; then
    echo "FAIL: mutant '$label' exited $rc; expected 1" >&2
    echo "$out" >&2
    exit 1
  fi
  if ! grep -Fq "$expected_needle" <<<"$out"; then
    echo "FAIL: mutant '$label' output did not mention '$expected_needle':" >&2
    echo "$out" >&2
    exit 1
  fi
  if ! grep -Fq "Root cause:" <<<"$out"; then
    echo "FAIL: mutant '$label' output missing Root cause explanation:" >&2
    echo "$out" >&2
    exit 1
  fi
  if [[ "$verbose" -eq 1 ]]; then
    echo "=== mutant $label (rc=$rc) ==="
    echo "$out"
  fi
}

# 1. Clean copy must pass (exit 0).
clean_out="$("$checker" --root "$work" --denylist "$work/scripts/approve-test-denylist.txt" 2>&1)"
if [[ "$verbose" -eq 1 ]]; then
  echo "=== clean (rc=0) ==="
  echo "$clean_out"
fi

# 2. Mutant 1: direct decide(Approve) call outside the denylist.
cat <<'RS' >> "$work/crates/praetore-mcp/tests/approvals.rs"

#[test]
fn mutant_unlisted_approve_call_must_fail() {
    let (_temp, home) = init_home();
    let _ = praetore_mcp::approvals::decide(&home, "id", praetore_mcp::approvals::HumanOutcome::Approve, None);
}
RS
run_mutant "direct_decide" "mutant_unlisted_approve_call_must_fail"
cp "$repo_root/crates/praetore-mcp/tests/approvals.rs" "$work/crates/praetore-mcp/tests/approvals.rs"

# 3. Mutant B2: cross-file pub fn in crates/praetore-mcp/src/approvals.rs calling decide, used from tests/cli.rs.
cat <<'RS' >> "$work/crates/praetore-mcp/src/approvals.rs"

pub fn mutant_b2_cross_file_decide(home: &std::path::Path) {
    let _ = decide(home, "id", HumanOutcome::Approve, None);
}
RS
cat <<'RS' >> "$work/crates/praetore-mcp/tests/cli.rs"

#[test]
fn mutant_b2_cross_file_cli_calls_pub_approvals_helper() {
    let temp = tempfile::tempdir().unwrap();
    praetore_mcp::approvals::mutant_b2_cross_file_decide(temp.path());
}
RS
run_mutant "B2_cross_file_pub_fn" "mutant_b2_cross_file_cli_calls_pub_approvals_helper"
cp "$repo_root/crates/praetore-mcp/src/approvals.rs" "$work/crates/praetore-mcp/src/approvals.rs"
cp "$repo_root/crates/praetore-mcp/tests/cli.rs" "$work/crates/praetore-mcp/tests/cli.rs"

# 4. Mutant shared tests/ helper (mod common).
cat <<'RS' >> "$work/crates/praetore-sandbox-fs/tests/common/mod.rs"

pub fn mutant_shared_common_approve(home: &std::path::Path) {
    let _ = praetore_mcp::approvals::decide(home, "id", praetore_mcp::approvals::HumanOutcome::Reject, None);
}
RS
cat <<'RS' >> "$work/crates/praetore-sandbox-fs/tests/confinement.rs"

#[test]
fn mutant_shared_common_helper_used_in_test() {
    common::mutant_shared_common_approve(std::path::Path::new("/tmp/h"));
}
RS
run_mutant "shared_tests_common_helper" "mutant_shared_common_helper_used_in_test"
cp "$repo_root/crates/praetore-sandbox-fs/tests/common/mod.rs" "$work/crates/praetore-sandbox-fs/tests/common/mod.rs"
cp "$repo_root/crates/praetore-sandbox-fs/tests/confinement.rs" "$work/crates/praetore-sandbox-fs/tests/confinement.rs"

# 5. CLI mutants (every required form).
# 5a. "approve" in non-first position of run(&[...])
cat <<'RS' >> "$work/crates/praetore-mcp/tests/cli.rs"

#[test]
fn mutant_cli_run_nonfirst_pos() {
    let _ = run(&["--dir", "/tmp/h", "approve"]);
}
RS
run_mutant "cli_run_nonfirst" "mutant_cli_run_nonfirst_pos"
cp "$repo_root/crates/praetore-mcp/tests/cli.rs" "$work/crates/praetore-mcp/tests/cli.rs"

# 5b. "reject" in non-first position of .args([...])
cat <<'RS' >> "$work/crates/praetore-mcp/tests/cli.rs"

#[test]
fn mutant_cli_args_nonfirst_pos() {
    let _ = Command::new("praetore-mcp").args(["--dir", "/tmp/h", "reject"]).output();
}
RS
run_mutant "cli_args_nonfirst" "mutant_cli_args_nonfirst_pos"
cp "$repo_root/crates/praetore-mcp/tests/cli.rs" "$work/crates/praetore-mcp/tests/cli.rs"

# 5c. variable passed to .arg(var)
cat <<'RS' >> "$work/crates/praetore-mcp/tests/cli.rs"

#[test]
fn mutant_cli_arg_variable() {
    let sub = "approve";
    let _ = Command::new("praetore-mcp").arg("--dir").arg("/tmp/h").arg(sub).output();
}
RS
run_mutant "cli_arg_var" "mutant_cli_arg_variable"
cp "$repo_root/crates/praetore-mcp/tests/cli.rs" "$work/crates/praetore-mcp/tests/cli.rs"

# 5d. constant in run(&[..., CONST])
cat <<'RS' >> "$work/crates/praetore-mcp/tests/cli.rs"

const MUTANT_CLI_CONST_SUB: &str = "reject";

#[test]
fn mutant_cli_const_in_run() {
    let _ = run(&["--dir", "/tmp/h", MUTANT_CLI_CONST_SUB]);
}
RS
run_mutant "cli_const_in_run" "mutant_cli_const_in_run"
cp "$repo_root/crates/praetore-mcp/tests/cli.rs" "$work/crates/praetore-mcp/tests/cli.rs"

# 5e. local array/slice variable passed to run(&args) / .args(&args)
cat <<'RS' >> "$work/crates/praetore-mcp/tests/cli.rs"

#[test]
fn mutant_cli_slice_var_in_args() {
    let argv = ["--dir", "/tmp/h", "approve"];
    let _ = Command::new("praetore-mcp").args(&argv).output();
}
RS
run_mutant "cli_slice_var" "mutant_cli_slice_var_in_args"
cp "$repo_root/crates/praetore-mcp/tests/cli.rs" "$work/crates/praetore-mcp/tests/cli.rs"

# 6. Stale entry in denylist must exit 1.
echo "praetore-gateway | --test enforcement | runnable | nonexistent_stale_approve_test" >> "$work/scripts/approve-test-denylist.txt"
run_mutant "stale_denylist_entry" "nonexistent_stale_approve_test"

echo "OK: test-check-approve-test-denylist passed (clean=0, 9 mutants all rc=1)"
