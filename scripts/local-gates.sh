#!/usr/bin/env bash
# Local verification gates without executing any approve/reject tests.
#
# Never runs `cargo test --workspace`, never runs `--ignored`, and never runs
# `scripts/postgres-ignored-tests.sh`. Instead:
#   1. Runs source-only approve denylist verification and its self-test.
#   2. Runs cargo fmt (workspace + fuzz) and cargo clippy.
#   3. Verifies via `cargo test -- --list` / `--ignored --list` that EVERY
#      entry in scripts/approve-test-denylist.txt still exists (fails if stale)
#      and that `--skip` removes every runnable denylisted test.
#   4. Runs non-ignored local tests target-by-target with exact `--skip`
#      filters for denylisted tests.
#
#   scripts/local-gates.sh
#   scripts/local-gates.sh --validate-denylist-only
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

denylist="$repo_root/scripts/approve-test-denylist.txt"
validate_only=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --validate-denylist-only)
      validate_only=1
      shift
      ;;
    --denylist)
      denylist="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [--validate-denylist-only] [--denylist <path>]" >&2
      exit 2
      ;;
  esac
done

echo "==> [1/4] Source-only approve test denylist check"
"$repo_root/scripts/test-check-approve-test-denylist.sh"
"$repo_root/scripts/check-approve-test-denylist.sh" --root "$repo_root" --denylist "$denylist"

if [[ "$validate_only" -eq 0 ]]; then
  echo "==> [2/4] Format and clippy"
  cargo fmt --all -- --check
  cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
fi

echo "==> [3/4] Verify denylist entries against cargo test --list"
python3 - "$denylist" <<'PY'
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

denylist_path = Path(sys.argv[1])
groups = defaultdict(list)

for lineno, raw in enumerate(denylist_path.read_text(encoding="utf-8").splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    parts = [p.strip() for p in line.split("|")]
    if len(parts) != 4 or parts[2] not in ("runnable", "ignored"):
        sys.stderr.write(f"ERROR: malformed denylist line {denylist_path}:{lineno}: {raw!r}\n")
        sys.exit(1)
    pkg, tgt, mode, name = parts
    groups[(pkg, tgt, mode)].append(name)

for (pkg, tgt, mode), names in sorted(groups.items()):
    extra_flag = ["--ignored"] if mode == "ignored" else []
    cmd = ["cargo", "test", "-q", "--locked", "-p", pkg] + tgt.split() + ["--"] + extra_flag + ["--list"]
    out = subprocess.check_output(cmd, text=True)
    listed = {l[:-6] for l in out.splitlines() if l.endswith(": test")}
    missing = sorted(set(names) - listed)
    if missing:
        sys.stderr.write(
            f"ERROR: stale entry in {denylist_path} for {pkg} {tgt} ({mode}): "
            f"not listed by cargo test --list:\n"
        )
        for m in missing:
            sys.stderr.write(f"  - {m}\n")
        sys.exit(1)
    if mode == "runnable":
        skip_args = []
        for n in names:
            skip_args.extend(["--skip", n])
        filt_out = subprocess.check_output(cmd + skip_args, text=True)
        filt_listed = {l[:-6] for l in filt_out.splitlines() if l.endswith(": test")}
        leaked = sorted(set(names) & filt_listed)
        if leaked:
            sys.stderr.write(
                f"ERROR: --skip failed to exclude denylisted test(s) in {pkg} {tgt}:\n"
            )
            for l in leaked:
                sys.stderr.write(f"  - {l}\n")
            sys.exit(1)
    print(f"verified {pkg} {tgt} ({mode}): {len(names)} denylisted tests present")
PY

if [[ "$validate_only" -eq 1 ]]; then
  echo "OK: denylist validation passed"
  exit 0
fi

echo "==> [4/4] Run local non-approve tests"

# Clean crates (verified zero approve/reject tests)
clean_packages=(
  praetore-core
  praetore-receipt
  praetore-verify
  praetore-python
  praetore-sandbox-fs
  praetore-observe
  praetore-safety-client
  praetore-gateway-service
  praetore-console
)
for pkg in "${clean_packages[@]}"; do
  echo "--- cargo test --locked -p $pkg"
  cargo test --locked -p "$pkg"
done

# Helper to load exact --skip flags for a (pkg, target) pair
skip_flags_for() {
  local pkg="$1"
  local tgt="$2"
  python3 - "$denylist" "$pkg" "$tgt" <<'PY'
import sys
from pathlib import Path

denylist_path, pkg, tgt = sys.argv[1], sys.argv[2], sys.argv[3]
for raw in Path(denylist_path).read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    p, t, mode, name = [x.strip() for x in line.split("|")]
    if p == pkg and t == tgt and mode == "runnable":
        print("--skip")
        print(name)
PY
}

run_with_denylist() {
  local pkg="$1"
  shift
  local tgt="$*"
  local skips=()
  while IFS= read -r arg; do
    skips+=("$arg")
  done < <(skip_flags_for "$pkg" "$tgt")
  echo "--- cargo test --locked -p $pkg $tgt (${#skips[@]} skip args)"
  if [[ ${#skips[@]} -gt 0 ]]; then
    cargo test --locked -p "$pkg" $tgt -- "${skips[@]}"
  else
    cargo test --locked -p "$pkg" $tgt
  fi
}

# praetore-replay-postgres: --lib and --doc only (never --test postgres or --ignored)
echo "--- cargo test --locked -p praetore-replay-postgres --lib --doc"
cargo test --locked -p praetore-replay-postgres --lib
cargo test --locked -p praetore-replay-postgres --doc

# praetore-cli: safe targets + --bin praetore with --skip (never postgres ignored tests)
echo "--- cargo test --locked -p praetore-cli (non-approve targets)"
cargo test --locked -p praetore-cli --bin praetore-safety-ingest
cargo test --locked -p praetore-cli --test safety_manifest_cli
run_with_denylist praetore-cli --bin praetore

# praetore-gateway: --lib, --doc, --test safety_actions, and --test enforcement with --skip
echo "--- cargo test --locked -p praetore-gateway"
cargo test --locked -p praetore-gateway --lib
cargo test --locked -p praetore-gateway --doc
cargo test --locked -p praetore-gateway --test safety_actions
run_with_denylist praetore-gateway --test enforcement

# praetore-mcp: build binary for approvals::tests::run_verify, then --doc, --lib with --skip, and every --test target with --skip
echo "--- cargo test --locked -p praetore-mcp"
cargo build --locked -p praetore-mcp --bin praetore-mcp
cargo test --locked -p praetore-mcp --doc
run_with_denylist praetore-mcp --lib
mcp_tests="$(cargo metadata --no-deps --format-version 1 --locked | python3 -c '
import sys, json
meta = json.load(sys.stdin)
for p in meta["packages"]:
    if p["name"] == "praetore-mcp":
        for t in sorted(p["targets"], key=lambda x: x["name"]):
            if "test" in t["kind"]:
                print(t["name"])
')"
for t in $mcp_tests; do
  run_with_denylist praetore-mcp --test "$t"
done

echo "OK: all local gates passed without running any approve/reject test"
