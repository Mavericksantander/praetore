#!/usr/bin/env bash
# Self-test for exact `--skip` filtering using ONLY `cargo test -- --list`
# (never executes any tests). Verifies:
#   1. On every runnable target in scripts/approve-test-denylist.txt, `--exact`
#      with `--skip` skips exactly the denylist count (over_skipped == [],
#      leaked == []).
#   2. Substring mutant (synthetic prefix `action::tests::creates_valid` in
#      `praetore-core --lib`): without `--exact`, over_skipped is non-empty
#      (exit 1); with `--exact` and exact name `action::tests::creates_valid_action`,
#      over_skipped is [] and skipped == denylist (exit 0).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
denylist="${1:-$repo_root/scripts/approve-test-denylist.txt}"
cd "$repo_root"

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
    if mode == "runnable":
        groups[(pkg, tgt)].append(name)

def check_skip_list(pkg, tgt, names, use_exact):
    base_cmd = ["cargo", "test", "-q", "--locked", "-p", pkg] + tgt.split() + ["--"]
    all_out = subprocess.check_output(base_cmd + ["--list"], text=True)
    listed = {l[:-6] for l in all_out.splitlines() if l.endswith(": test")}

    skip_args = ["--exact"] if use_exact else []
    for n in names:
        skip_args.extend(["--skip", n])
    filt_out = subprocess.check_output(base_cmd + skip_args + ["--list"], text=True)
    filt_listed = {l[:-6] for l in filt_out.splitlines() if l.endswith(": test")}

    deny_set = set(names)
    leaked = sorted(deny_set & filt_listed)
    over_skipped = sorted((listed - deny_set) - filt_listed)
    skipped_count = len(listed) - len(filt_listed)
    return {
        "total": len(listed),
        "denylist": len(deny_set),
        "skipped": skipped_count,
        "leaked": leaked,
        "over_skipped": over_skipped,
    }

# 1. Real denylist targets with --exact
for (pkg, tgt), names in sorted(groups.items()):
    res = check_skip_list(pkg, tgt, names, use_exact=True)
    print(
        f"real {pkg} {tgt}: total={res['total']} denylist={res['denylist']} "
        f"skipped={res['skipped']} leaked={res['leaked']} over_skipped={res['over_skipped']}"
    )
    if res["leaked"] or res["over_skipped"] or res["skipped"] != res["denylist"]:
        sys.stderr.write(
            f"FAIL: skip count mismatch or over_skipped on {pkg} {tgt}: {res}\n"
        )
        sys.exit(1)

# 2. Substring mutant (via --list only, zero tests run):
#    Prefix 'action::tests::creates_valid' matches 'action::tests::creates_valid_action'
#    by substring if --exact is omitted.
sub_res = check_skip_list(
    "praetore-core", "--lib", ["action::tests::creates_valid"], use_exact=False
)
print(
    f"mutant_no_exact praetore-core --lib: total={sub_res['total']} "
    f"denylist={sub_res['denylist']} skipped={sub_res['skipped']} "
    f"over_skipped={sub_res['over_skipped']}"
)
if not sub_res["over_skipped"]:
    sys.stderr.write("FAIL: expected non-empty over_skipped without --exact\n")
    sys.exit(1)

exact_prefix_res = check_skip_list(
    "praetore-core", "--lib", ["action::tests::creates_valid"], use_exact=True
)
print(
    f"mutant_exact_nonexistent_prefix praetore-core --lib: total={exact_prefix_res['total']} "
    f"denylist={exact_prefix_res['denylist']} skipped={exact_prefix_res['skipped']} "
    f"over_skipped={exact_prefix_res['over_skipped']}"
)
if exact_prefix_res["over_skipped"] or exact_prefix_res["skipped"] != 0:
    sys.stderr.write("FAIL: expected 0 skipped and empty over_skipped with --exact on partial prefix\n")
    sys.exit(1)

exact_full_res = check_skip_list(
    "praetore-core", "--lib", ["action::tests::creates_valid_action"], use_exact=True
)
print(
    f"green_exact_full praetore-core --lib: total={exact_full_res['total']} "
    f"denylist={exact_full_res['denylist']} skipped={exact_full_res['skipped']} "
    f"over_skipped={exact_full_res['over_skipped']}"
)
if exact_full_res["over_skipped"] or exact_full_res["leaked"] or exact_full_res["skipped"] != 1:
    sys.stderr.write("FAIL: expected exact full match to skip 1 test with over_skipped=[]\n")
    sys.exit(1)

print("OK: skip --exact self-test passed (all over_skipped=[])")
PY
