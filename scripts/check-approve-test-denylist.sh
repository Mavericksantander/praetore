#!/usr/bin/env bash
# Source-only check for the approve/reject test denylist.
# Scans Rust source files under crates/ without compiling or executing any
# tests or approve/reject paths. Fails with a root-cause message if:
#   1. Any test calls (directly or via helpers) approvals::decide, CLI
#      approve/reject, Gateway::resolve_human_approval,
#      ExecutionJournal::record_human_approval, or HTTP POST /v1/approvals/
#      outside scripts/approve-test-denylist.txt.
#   2. Any entry in scripts/approve-test-denylist.txt no longer exists in
#      the corresponding crate/target source.
#
#   scripts/check-approve-test-denylist.sh
#   scripts/check-approve-test-denylist.sh --root <repo_dir> --denylist <path>
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
denylist=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      repo_root="$2"
      shift 2
      ;;
    --denylist)
      denylist="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [--root <dir>] [--denylist <path>]" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$denylist" ]]; then
  denylist="$repo_root/scripts/approve-test-denylist.txt"
fi

if [[ ! -f "$denylist" ]]; then
  echo "ERROR: denylist file not found: $denylist" >&2
  exit 1
fi

python3 - "$repo_root" "$denylist" <<'PY'
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
denylist_path = Path(sys.argv[2]).resolve()
crates_dir = repo_root / "crates"

if not crates_dir.is_dir():
    sys.stderr.write(f"ERROR: crates directory not found under {repo_root}\n")
    sys.exit(1)


def is_test_attr(attrs):
    for a in attrs:
        s = re.sub(r"\s+", "", a)
        if re.match(r"^#\[(?:[A-Za-z0-9_]+::)*test(?:\(.*\))?\]$", s):
            return True
    return False


def strip_comments_and_strings(src):
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            out.append(" ")
            out.append(" ")
            i += 2
            depth = 1
            while i < n and depth > 0:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    out.append(" ")
                    out.append(" ")
                    i += 2
                elif src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    out.append(" ")
                    out.append(" ")
                    i += 2
                else:
                    out.append("\n" if src[i] == "\n" else " ")
                    i += 1
        elif c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                out.append("'")
                i += 1
                while i < n:
                    ch = src[i]
                    if ch == "\\" and i + 1 < n:
                        out.append(" ")
                        out.append("\n" if src[i + 1] == "\n" else " ")
                        i += 2
                    elif ch == "'":
                        out.append("'")
                        i += 1
                        break
                    else:
                        out.append("\n" if ch == "\n" else " ")
                        i += 1
            elif i + 2 < n and src[i + 2] == "'" and src[i + 1] != "\n":
                out.extend(["'", " ", "'"])
                i += 3
            else:
                out.append(c)
                i += 1
        elif c == '"':
            out.append('"')
            i += 1
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    out.append(" ")
                    out.append("\n" if src[i + 1] == "\n" else " ")
                    i += 2
                elif src[i] == '"':
                    out.append('"')
                    i += 1
                    break
                else:
                    out.append("\n" if src[i] == "\n" else " ")
                    i += 1
        elif (
            c == "r" or (c in ("b", "c") and i + 1 < n and src[i + 1] == "r")
        ) and not (i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_")):
            r_idx = i if c == "r" else i + 1
            j = r_idx + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                prefix_len = (r_idx - i) + 1 + hashes
                out.extend([" "] * prefix_len + ['"'])
                i = j + 1
                end_seq = '"' + "#" * hashes
                idx = src.find(end_seq, i)
                if idx == -1:
                    idx = n
                for ch in src[i:idx]:
                    out.append("\n" if ch == "\n" else " ")
                if idx < n:
                    out.extend(['"'] + [" "] * hashes)
                    i = idx + len(end_seq)
                else:
                    i = n
                continue
            out.append(c)
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def map_file_to_target(rel_path):
    parts = rel_path.parts
    if len(parts) < 3 or parts[0] != "crates":
        return None
    pkg = parts[1]
    if parts[2] == "src":
        if pkg == "praetore-cli":
            if rel_path.name == "safety_ingest_main.rs":
                return (pkg, "--bin praetore-safety-ingest", [])
            if rel_path.name == "main.rs":
                return (pkg, "--bin praetore", [])
            return (pkg, "--bin praetore", [rel_path.stem])
        if pkg in ("praetore-verify", "praetore-observe"):
            return (pkg, f"--bin {pkg}", [] if rel_path.name == "main.rs" else [rel_path.stem])
        if rel_path.name in ("lib.rs", "main.rs"):
            return (pkg, "--lib", [])
        mod_parts = list(parts[3:-1]) + ([rel_path.stem] if rel_path.stem != "mod" else [])
        return (pkg, "--lib", mod_parts)
    if parts[2] == "tests":
        if len(parts) == 4 and rel_path.suffix == ".rs":
            return (pkg, f"--test {rel_path.stem}", [])
        if len(parts) > 4:
            return (pkg, f"--test {parts[3]}", list(parts[4:-1]) + ([rel_path.stem] if rel_path.stem != "mod" else []))
    return None


def sinks_for_file(rel_str, pkg):
    sinks = [
        ("approvals::decide", r"(?:crate::approvals::|praetore_mcp::approvals::|approvals::)decide\s*\(", None),
        ("approvals::seed_one_decision", r"seed_one_decision\s*\(", None),
        (
            "CLI approve/reject",
            r'(?:run|args)\s*\(\s*&?\s*\[\s*"(?:approve|reject)"',
            lambda b: '"--help"' not in b and '"-h"' not in b,
        ),
        (
            "CLI arg approve/reject",
            r'\.arg\s*\(\s*"(?:approve|reject)"\s*\)',
            lambda b: '"--help"' not in b and '"-h"' not in b,
        ),
        ("sh -c $reject", r'Command::new\("/bin/sh"\)', lambda b: "reject" in b),
        ("Gateway::resolve_human_approval", r"\.resolve_human_approval\s*\(", None),
        ("ExecutionJournal::record_human_approval", r"\.record_human_approval\s*\(", None),
        (
            "HTTP POST /v1/approvals/",
            r"/v1/approvals/",
            lambda b: bool(re.search(r'"POST"|\.post\(', b, re.I)) and not ("Router::new()" in b and "http_api::router" not in b),
        ),
    ]
    if rel_str == "crates/praetore-mcp/src/approvals.rs":
        sinks.append(("approvals::decide (local)", r"(?<![A-Za-z0-9_:.])decide\s*\(", None))
    if pkg == "praetore-replay-postgres":
        sinks.extend([
            ("SQL insert_human_approval", r"insert_human_approval\s*\(", None),
            ("helper spawn crash_helper_approve_then_hang", r"crash_helper_approve_then_hang", None),
        ])
    if pkg == "praetore-cli":
        sinks.extend([
            ("CLI resolve_approval", r"(?<![A-Za-z0-9_:.])resolve_approval\s*\(", None),
            ("HTTP POST /v1/approvals/ via approval_path", r"\.approval_path\s*\(", None),
            ("HTTP /api/bandeja/.../aprobar|rechazar", r"/api/bandeja/.*?(?:aprobar|rechazar)", None),
        ])
    return sinks


def scan_rust_file(path, rel_path, file_mod_prefix, sinks):
    raw = path.read_text(encoding="utf-8")
    clean = strip_comments_and_strings(raw)
    if len(raw) != len(clean):
        raise AssertionError(f"internal lexer length mismatch on {rel_path}")
    items = []

    def scan_block(start_idx, end_idx, mod_path):
        i = start_idx
        pending_attrs = []
        while i < end_idx:
            while i < end_idx and clean[i].isspace():
                i += 1
            if i >= end_idx:
                break
            if clean[i] == "#":
                j = i + 1
                is_inner = j < end_idx and clean[j] == "!"
                if is_inner:
                    j += 1
                if j < end_idx and clean[j] == "[":
                    d = 0
                    while j < end_idx:
                        if clean[j] == "[":
                            d += 1
                        elif clean[j] == "]":
                            d -= 1
                            if d == 0:
                                j += 1
                                break
                        j += 1
                    if not is_inner:
                        pending_attrs.append(raw[i:j])
                    i = j
                    continue
            m_prop = re.match(r"proptest!\s*\{", clean[i:end_idx])
            if m_prop:
                bstart = i + m_prop.end() - 1
                d = 0
                j = bstart
                while j < end_idx:
                    if clean[j] == "{":
                        d += 1
                    elif clean[j] == "}":
                        d -= 1
                        if d == 0:
                            break
                    j += 1
                scan_block(bstart + 1, min(j, end_idx), mod_path)
                pending_attrs.clear()
                i = j + 1
                continue
            m_mod = re.match(
                r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*([;{])",
                clean[i:end_idx],
            )
            if m_mod:
                name = m_mod.group(1)
                if m_mod.group(2) == ";":
                    pending_attrs.clear()
                    i += m_mod.end()
                    continue
                bstart = i + m_mod.end() - 1
                d = 0
                j = bstart
                while j < end_idx:
                    if clean[j] == "{":
                        d += 1
                    elif clean[j] == "}":
                        d -= 1
                        if d == 0:
                            break
                    j += 1
                scan_block(bstart + 1, min(j, end_idx), mod_path + [name])
                pending_attrs.clear()
                i = j + 1
                continue
            m_impl = re.match(
                r"impl(?:<[^>]*>)?\s+(?:[A-Za-z0-9_:<>]+\s+for\s+)?([A-Za-z0-9_:]+)(?:<[^>]*>)?(?:\s+where\b[^{]*)?\s*\{",
                clean[i:end_idx],
            )
            if m_impl:
                bstart = i + m_impl.end() - 1
                d = 0
                j = bstart
                while j < end_idx:
                    if clean[j] == "{":
                        d += 1
                    elif clean[j] == "}":
                        d -= 1
                        if d == 0:
                            break
                    j += 1
                cls = m_impl.group(1).split("::")[-1]
                scan_block(bstart + 1, min(j, end_idx), mod_path + ["__impl__" + cls])
                pending_attrs.clear()
                i = j + 1
                continue
            m_fn = re.match(
                r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)\b",
                clean[i:end_idx],
            )
            if m_fn:
                name = m_fn.group(1)
                fn_line = raw[:i].count("\n") + 1
                j = i + m_fn.end()
                angle = 0
                paren = 0
                while j < end_idx:
                    ch = clean[j]
                    if ch == "<":
                        angle += 1
                    elif ch == ">" and angle > 0:
                        angle -= 1
                    elif ch == "(":
                        paren += 1
                    elif ch == ")" and paren > 0:
                        paren -= 1
                    elif ch == "{" and paren == 0:
                        break
                    elif ch == ";" and paren == 0:
                        break
                    j += 1
                if j < end_idx and clean[j] == "{":
                    bstart = j
                    d = 0
                    while j < end_idx:
                        if clean[j] == "{":
                            d += 1
                        elif clean[j] == "}":
                            d -= 1
                            if d == 0:
                                break
                        j += 1
                    end_line = raw[: min(j, end_idx)].count("\n") + 1
                    items.append(
                        (
                            name,
                            list(mod_path),
                            fn_line,
                            end_line,
                            bstart,
                            min(j + 1, end_idx),
                            list(pending_attrs),
                        )
                    )
                    pending_attrs.clear()
                    i = j + 1
                    continue
                else:
                    pending_attrs.clear()
                    i = j + 1
                    continue
            pending_attrs.clear()
            while i < end_idx:
                if clean[i] == ";":
                    i += 1
                    break
                elif clean[i] == "{":
                    d = 0
                    while i < end_idx:
                        if clean[i] == "{":
                            d += 1
                        elif clean[i] == "}":
                            d -= 1
                            if d == 0:
                                i += 1
                                break
                        i += 1
                    break
                i += 1

    scan_block(0, len(raw), [])

    taint = {}
    for idx, it in enumerate(items):
        name, mpath, sline, eline, bstart, bend, attrs = it
        body_raw = raw[bstart:bend]
        for sname, spat, cond in sinks:
            m = re.search(spat, body_raw)
            if m and (cond is None or cond(body_raw)):
                hit_line = raw[: bstart + m.start()].count("\n") + 1
                taint[idx] = (sname, hit_line, [])
                break

    changed = True
    while changed:
        changed = False
        for idx, it in enumerate(items):
            if idx in taint:
                continue
            name, mpath, sline, eline, bstart, bend, attrs = it
            body_clean = clean[bstart:bend]
            real_mpath = [x for x in mpath if not x.startswith("__impl__")]
            for h_idx, h_it in enumerate(items):
                if h_idx not in taint:
                    continue
                hname, hmpath, hsline, _, _, _, hattrs = h_it
                if is_test_attr(hattrs):
                    continue
                h_is_impl = any(x.startswith("__impl__") for x in hmpath)
                h_real_mpath = [x for x in hmpath if not x.startswith("__impl__")]
                pats = []
                if h_is_impl:
                    pats.append(rf"\.{re.escape(hname)}\s*\(")
                    cls = [x[8:] for x in hmpath if x.startswith("__impl__")][-1]
                    pats.append(rf"(?<![A-Za-z0-9_]){re.escape(cls)}::{re.escape(hname)}\s*\(")
                else:
                    if h_real_mpath == real_mpath:
                        pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(hname)}\s*\(")
                    if len(h_real_mpath) > len(real_mpath) and h_real_mpath[: len(real_mpath)] == real_mpath:
                        rel = "::".join(h_real_mpath[len(real_mpath) :] + [hname])
                        pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(rel)}\s*\(")
                    if len(real_mpath) > len(h_real_mpath) and real_mpath[: len(h_real_mpath)] == h_real_mpath:
                        pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(hname)}\s*\(")
                    if h_real_mpath == []:
                        pats.append(rf"(?<![A-Za-z0-9_:.])(?:super::)+{re.escape(hname)}\s*\(")
                    full = "::".join(h_real_mpath + [hname])
                    pats.append(rf"(?:crate::)?{re.escape(full)}\s*\(")
                matched = None
                for p in pats:
                    m = re.search(p, body_clean)
                    if m:
                        matched = raw[: bstart + m.start()].count("\n") + 1
                        break
                if matched:
                    h_reason, h_line, h_chain = taint[h_idx]
                    h_disp = "::".join(h_real_mpath + [hname])
                    taint[idx] = (h_reason, h_line, [(h_disp, matched)] + h_chain)
                    changed = True
                    break

    all_tests_in_file = []
    tainted_tests_in_file = []
    for idx, it in enumerate(items):
        name, mpath, sline, eline, bstart, bend, attrs = it
        if not is_test_attr(attrs):
            continue
        real_mpath = file_mod_prefix + [x for x in mpath if not x.startswith("__impl__")]
        fq = "::".join(real_mpath + [name])
        ign = any("ignore" in a for a in attrs)
        all_tests_in_file.append((fq, sline, ign))
        if idx in taint:
            sname, sink_line, chain = taint[idx]
            tainted_tests_in_file.append((fq, sline, ign, sname, sink_line, chain))
    return all_tests_in_file, tainted_tests_in_file


# Parse denylist
deny_entries = {}
for lineno, raw_line in enumerate(denylist_path.read_text(encoding="utf-8").splitlines(), 1):
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    parts = [p.strip() for p in line.split("|")]
    if len(parts) != 4 or parts[2] not in ("runnable", "ignored"):
        sys.stderr.write(
            f"ERROR: malformed denylist line {denylist_path}:{lineno}: {raw_line!r}\n"
        )
        sys.exit(1)
    key = (parts[0], parts[1], parts[3])
    if key in deny_entries:
        sys.stderr.write(
            f"ERROR: duplicate denylist entry {key} at {denylist_path}:{lineno}\n"
        )
        sys.exit(1)
    deny_entries[key] = (parts[2], lineno)

discovered_tests = {}
tainted_tests = {}

for rs_path in sorted(crates_dir.rglob("*.rs")):
    rel_path = rs_path.relative_to(repo_root)
    mapped = map_file_to_target(rel_path)
    if mapped is None:
        continue
    pkg, tgt, prefix = mapped
    sinks = sinks_for_file(rel_path.as_posix(), pkg)
    all_t, tainted_t = scan_rust_file(rs_path, rel_path, prefix, sinks)
    for fq, sline, ign in all_t:
        discovered_tests[(pkg, tgt, fq)] = (rel_path.as_posix(), sline, ign)
    for fq, sline, ign, sname, sink_line, chain in tainted_t:
        tainted_tests[(pkg, tgt, fq)] = (rel_path.as_posix(), sline, ign, sname, sink_line, chain)

unlisted = sorted(k for k in tainted_tests if k not in deny_entries)
stale = sorted(k for k in deny_entries if k not in discovered_tests)

errors = 0
if unlisted:
    errors += 1
    sys.stderr.write(
        "ERROR: found test(s) reaching approve/reject outside scripts/approve-test-denylist.txt.\n"
        "Root cause: running approve/reject locally (including in disposable homes) violates the "
        "repository's approve gate policy. Any test that calls approvals::decide(Approve|Reject), "
        "CLI approve/reject, Gateway::resolve_human_approval, ExecutionJournal::record_human_approval, "
        "or HTTP POST /v1/approvals/ must be explicitly listed in scripts/approve-test-denylist.txt "
        "(so scripts/local-gates.sh skips it) or must not invoke approve/reject.\n"
    )
    for pkg, tgt, fq in unlisted:
        rel_s, sline, ign, sname, sink_line, chain = tainted_tests[(pkg, tgt, fq)]
        via = (
            " via " + " -> ".join(f"{fn}@{ln}" for fn, ln in chain)
            if chain
            else ""
        )
        sys.stderr.write(
            f"  - {pkg} | {tgt} | {fq} ({rel_s}:{sline}): {sname} at {rel_s}:{sink_line}{via}\n"
        )

if stale:
    errors += 1
    sys.stderr.write(
        "ERROR: stale entry in scripts/approve-test-denylist.txt references test(s) not found in source.\n"
        "Root cause: a denylisted test was renamed, moved, or removed without updating "
        "scripts/approve-test-denylist.txt, which would leave local-gates.sh skipping a nonexistent test.\n"
    )
    for pkg, tgt, fq in stale:
        mode, lineno = deny_entries[(pkg, tgt, fq)]
        sys.stderr.write(
            f"  - {denylist_path}:{lineno}: {pkg} | {tgt} | {mode} | {fq}\n"
        )

if errors:
    sys.exit(1)

print(
    f"OK: {len(deny_entries)} denylisted approve/reject tests verified against source "
    f"({len(discovered_tests)} total tests scanned; 0 unlisted calls, 0 stale entries)"
)
PY
