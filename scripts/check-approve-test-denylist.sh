#!/usr/bin/env bash
# Source-only check for the approve/reject test denylist.
# Scans Rust source files under crates/ without compiling or executing any
# tests or approve/reject paths. Fails with a root-cause message if:
#   1. Any test calls (directly or via intra-file/cross-file helpers across the
#      workspace, including pub fn in src/ and shared tests/ helpers)
#      approvals::decide, CLI approve/reject, Gateway::resolve_human_approval,
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
from collections import defaultdict
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


def extract_string_literals(src):
    lits = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            depth = 1
            while i < n and depth > 0:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    i += 2
                elif src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
        elif c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                i += 2
                while i < n:
                    if src[i] == "\\" and i + 1 < n:
                        i += 2
                    elif src[i] == "'":
                        i += 1
                        break
                    else:
                        i += 1
            elif i + 2 < n and src[i + 2] == "'" and src[i + 1] != "\n":
                i += 3
            else:
                i += 1
        elif c == '"':
            s0 = i
            i += 1
            buf = []
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    buf.append(src[i + 1])
                    i += 2
                elif src[i] == '"':
                    i += 1
                    break
                else:
                    buf.append(src[i])
                    i += 1
            lits.append((s0, i, "".join(buf)))
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
                s0 = i
                i = j + 1
                end_seq = '"' + "#" * hashes
                idx = src.find(end_seq, i)
                if idx == -1:
                    lits.append((s0, n, src[i:n]))
                    i = n
                else:
                    lits.append((s0, idx + len(end_seq), src[i:idx]))
                    i = idx + len(end_seq)
                continue
            i += 1
        else:
            i += 1
    return lits


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


def parse_use_tree(expr):
    expr = expr.strip()
    out = []

    def parse_node(prefix, text):
        text = text.strip()
        if not text:
            return
        if text.startswith("{") and text.endswith("}"):
            inner = text[1:-1]
            depth = 0
            start = 0
            for idx, ch in enumerate(inner):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                elif ch == "," and depth == 0:
                    parse_node(prefix, inner[start:idx])
                    start = idx + 1
            parse_node(prefix, inner[start:])
            return
        brace_pos = text.find("{")
        if brace_pos != -1:
            head = text[:brace_pos].strip()
            if head.endswith("::"):
                head = head[:-2].strip()
            tail = text[brace_pos:].strip()
            new_prefix = prefix + [p.strip() for p in head.split("::") if p.strip()]
            parse_node(new_prefix, tail)
            return
        m_as = re.match(r"^(.*?)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)$", text, re.S)
        if m_as:
            path_str = m_as.group(1).strip()
            alias = m_as.group(2).strip()
        else:
            path_str = text
            alias = None
        segs = [p.strip() for p in path_str.split("::") if p.strip()]
        if segs == ["self"]:
            if prefix:
                out.append((list(prefix), alias or prefix[-1]))
            return
        if segs == ["*"]:
            out.append((list(prefix), "*"))
            return
        full = prefix + segs
        if full:
            out.append((full, alias or full[-1]))

    parse_node([], expr)
    return out


def sinks_for_file(rel_str, pkg):
    sinks = [
        ("approvals::decide", r"(?:crate::approvals::|praetore_mcp::approvals::|approvals::)decide\s*\(", None),
        ("approvals::seed_one_decision", r"seed_one_decision\s*\(", None),
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


def extract_path_from_attrs(attrs):
    for a in attrs:
        m = re.search(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]', a)
        if m:
            return m.group(1)
    return None


def parse_file(rs_path, rel_path, pkg, tgt, file_mod_prefix):
    raw = rs_path.read_text(encoding="utf-8")
    clean = strip_comments_and_strings(raw)
    if len(raw) != len(clean):
        raise AssertionError(f"internal lexer length mismatch on {rel_path}")
    lits = extract_string_literals(raw)

    items = []
    file_uses = []
    file_mods = []
    file_consts = defaultdict(set)

    def lits_in_range(a, b):
        return [val for s, e, val in lits if s >= a and e <= b]

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
            m_use = re.match(r"(pub(?:\([^)]*\))?\s+)?use\s+", clean[i:end_idx])
            if m_use:
                is_pub_use = bool(m_use.group(1))
                j = i + m_use.end()
                while j < end_idx and clean[j] != ";":
                    j += 1
                expr = clean[i + m_use.end():j]
                for parts_u, alias in parse_use_tree(expr):
                    file_uses.append((tuple(mod_path), is_pub_use, parts_u, alias))
                pending_attrs.clear()
                i = min(j + 1, end_idx)
                continue
            m_const = re.match(
                r"(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+([A-Za-z_][A-Za-z0-9_]*)\b",
                clean[i:end_idx],
            )
            if m_const:
                cname = m_const.group(1)
                j = i + m_const.end()
                depth = 0
                while j < end_idx:
                    ch = clean[j]
                    if ch in "{([":
                        depth += 1
                    elif ch in "})]" and depth > 0:
                        depth -= 1
                    elif ch == ";" and depth == 0:
                        break
                    j += 1
                if any(v in ("approve", "reject") for v in lits_in_range(i + m_const.end(), j)):
                    file_consts[tuple(mod_path)].add(cname)
                pending_attrs.clear()
                i = min(j + 1, end_idx)
                continue
            m_mod = re.match(
                r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*([;{])",
                clean[i:end_idx],
            )
            if m_mod:
                name = m_mod.group(1)
                if m_mod.group(2) == ";":
                    attr_path = extract_path_from_attrs(pending_attrs)
                    target_rel = None
                    if attr_path:
                        cand = (rs_path.parent / attr_path).resolve()
                        if cand.exists():
                            try:
                                target_rel = cand.relative_to(repo_root).as_posix()
                            except ValueError:
                                target_rel = None
                    else:
                        base_dir = rs_path.parent
                        is_crate_root = rs_path.name in ("lib.rs", "main.rs", "mod.rs") or (len(rel_path.parts) == 4 and rel_path.parts[2] == "tests")
                        if not is_crate_root:
                            c1 = base_dir / rs_path.stem / f"{name}.rs"
                            c2 = base_dir / rs_path.stem / name / "mod.rs"
                        else:
                            c1 = base_dir / f"{name}.rs"
                            c2 = base_dir / name / "mod.rs"
                        for c in (c1, c2):
                            if c.exists():
                                target_rel = c.resolve().relative_to(repo_root).as_posix()
                                break
                    file_mods.append((tuple(mod_path), name, target_rel))
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
                r"(pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)\b",
                clean[i:end_idx],
            )
            if m_fn:
                vis_str = (m_fn.group(1) or "").strip()
                if not vis_str:
                    vis = "private"
                elif vis_str == "pub":
                    vis = "pub"
                else:
                    vis = "crate"
                name = m_fn.group(2)
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
                        {
                            "name": name,
                            "mpath": list(mod_path),
                            "sline": fn_line,
                            "eline": end_line,
                            "bstart": bstart,
                            "bend": min(j + 1, end_idx),
                            "attrs": list(pending_attrs),
                            "vis": vis,
                            "is_test": is_test_attr(pending_attrs),
                        }
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
    renamed_targets = {parts_u[-1] for _, _, parts_u, alias in file_uses if alias != "*" and parts_u and alias != parts_u[-1]}
    return {
        "rel_path": rel_path.as_posix(),
        "pkg": pkg,
        "crate_ident": pkg.replace("-", "_"),
        "tgt": tgt,
        "file_mod_prefix": file_mod_prefix,
        "is_src": rel_path.parts[2] == "src",
        "raw": raw,
        "clean": clean,
        "lits": lits,
        "items": items,
        "uses": file_uses,
        "mods": file_mods,
        "consts": file_consts,
        "renamed_targets": renamed_targets,
    }


def check_cli_sink_in_fn(finfo, it):
    raw = finfo["raw"]
    clean = finfo["clean"]
    lits = finfo["lits"]
    bstart = it["bstart"]
    bend = it["bend"]
    body_clean = clean[bstart:bend]
    real_mpath = [x for x in it["mpath"] if not x.startswith("__impl__")]

    def lits_in(a, b):
        return [val for s, e, val in lits if s >= a and e <= b]

    cli_vars = set()
    for k in range(len(real_mpath) + 1):
        cli_vars |= finfo["consts"].get(tuple(real_mpath[:k]), set())

    for m in re.finditer(r"\b(?:let\s+(?:mut\s+)?|const\s+|static\s+)([A-Za-z_][A-Za-z0-9_]*)\b[^=;]*=", body_clean):
        vname = m.group(1)
        j = m.end()
        depth = 0
        while j < len(body_clean):
            ch = body_clean[j]
            if ch in "{([":
                depth += 1
            elif ch in "})]" and depth > 0:
                depth -= 1
            elif ch == ";" and depth == 0:
                break
            j += 1
        rhs_clean = body_clean[m.end():j]
        rhs_ids = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", rhs_clean))
        if any(v in ("approve", "reject") for v in lits_in(bstart + m.end(), bstart + j)) or (rhs_ids & cli_vars):
            cli_vars.add(vname)

    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:push|extend)\s*\(", body_clean):
        vname = m.group(1)
        j = m.end() - 1
        d = 0
        while j < len(body_clean):
            if body_clean[j] == "(":
                d += 1
            elif body_clean[j] == ")":
                d -= 1
                if d == 0:
                    break
            j += 1
        rhs_clean = body_clean[m.end():j]
        rhs_ids = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", rhs_clean))
        if any(v in ("approve", "reject") for v in lits_in(bstart + m.end(), bstart + j)) or (rhs_ids & cli_vars):
            cli_vars.add(vname)

    loop_cli_vars = set()
    help_flag_vars = set()
    for m in re.finditer(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+", body_clean):
        vname = m.group(1)
        j = m.end()
        while j < len(body_clean) and body_clean[j] != "{":
            j += 1
        iter_lits = lits_in(bstart + m.end(), bstart + j)
        if any(v in ("approve", "reject") for v in iter_lits):
            loop_cli_vars.add(vname)
        if iter_lits and all(v in ("--help", "-h") for v in iter_lits):
            help_flag_vars.add(vname)

    all_vars = cli_vars | loop_cli_vars

    for m in re.finditer(r"(?:(?<![A-Za-z0-9_.])(?:run|praetore)|\.args|\.arg)\s*\(", body_clean):
        open_p = body_clean.find("(", m.start())
        d = 0
        j = open_p
        while j < len(body_clean):
            if body_clean[j] == "(":
                d += 1
            elif body_clean[j] == ")":
                d -= 1
                if d == 0:
                    break
            j += 1
        arg_a = bstart + open_p + 1
        arg_b = bstart + j
        arg_lits = lits_in(arg_a, arg_b)
        arg_clean = clean[arg_a:arg_b]
        arg_ids = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", arg_clean))

        stmt_start = max(body_clean.rfind(";", 0, m.start()), body_clean.rfind("{", 0, m.start())) + 1
        stmt_end = body_clean.find(";", j)
        if stmt_end == -1:
            stmt_end = len(body_clean)
        stmt_lits = lits_in(bstart + stmt_start, bstart + stmt_end)

        is_direct = any(v in ("approve", "reject") for v in arg_lits)
        used_vars = arg_ids & all_vars

        if is_direct:
            if any(v in ("--help", "-h") for v in arg_lits):
                continue
            if body_clean[m.start():open_p].strip().startswith(".arg") and any(v in ("--help", "-h") for v in stmt_lits):
                continue
            return raw[: bstart + m.start()].count("\n") + 1
        if used_vars:
            if any(v in ("--help", "-h") for v in arg_lits):
                continue
            if body_clean[m.start():open_p].strip().startswith(".arg") and any(v in ("--help", "-h") for v in stmt_lits):
                continue
            if used_vars <= loop_cli_vars and (arg_ids & help_flag_vars):
                continue
            return raw[: bstart + m.start()].count("\n") + 1
    return None


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

# Parse all Rust files across workspace
files = []
for rs_path in sorted(crates_dir.rglob("*.rs")):
    rel_path = rs_path.relative_to(repo_root)
    mapped = map_file_to_target(rel_path)
    if mapped is None:
        continue
    pkg, tgt, prefix = mapped
    files.append(parse_file(rs_path, rel_path, pkg, tgt, prefix))

all_fns = []
for finfo in files:
    finfo["local_non_impl_names"] = set()
    for it in finfo["items"]:
        g_idx = len(all_fns)
        rec = dict(it)
        rec["finfo"] = finfo
        rec["g_idx"] = g_idx
        rec["real_mpath"] = [x for x in it["mpath"] if not x.startswith("__impl__")]
        rec["is_impl"] = any(x.startswith("__impl__") for x in it["mpath"])
        rec["cls"] = [x[8:] for x in it["mpath"] if x.startswith("__impl__")][-1] if rec["is_impl"] else None
        rec["body_clean"] = finfo["clean"][rec["bstart"]:rec["bend"]]
        rec["id_set"] = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", rec["body_clean"]))
        all_fns.append(rec)
        if not rec["is_impl"]:
            finfo["local_non_impl_names"].add(rec["name"])

# Direct sinks
taint = {}
for g_idx, fn in enumerate(all_fns):
    finfo = fn["finfo"]
    raw = finfo["raw"]
    body_raw = raw[fn["bstart"]:fn["bend"]]
    sinks = sinks_for_file(finfo["rel_path"], finfo["pkg"])
    for sname, spat, cond in sinks:
        m = re.search(spat, body_raw)
        if m and (cond is None or cond(body_raw)):
            hit_line = raw[: fn["bstart"] + m.start()].count("\n") + 1
            taint[g_idx] = (sname, finfo["rel_path"], hit_line, [])
            break
    if g_idx not in taint:
        cli_line = check_cli_sink_in_fn(finfo, fn)
        if cli_line is not None:
            taint[g_idx] = ("CLI approve/reject", finfo["rel_path"], cli_line, [])

# Build pub use re-exports per crate
pub_reexports = defaultdict(list)
for finfo in files:
    if not finfo["is_src"]:
        continue
    for mpath, is_pub_use, parts_u, alias in finfo["uses"]:
        if not is_pub_use:
            continue
        if parts_u[0] == "crate":
            resolved = [finfo["crate_ident"]] + parts_u[1:]
        elif parts_u[0] == "self":
            resolved = [finfo["crate_ident"]] + finfo["file_mod_prefix"] + list(mpath) + parts_u[1:]
        elif parts_u[0] == finfo["crate_ident"]:
            resolved = parts_u
        else:
            resolved = [finfo["crate_ident"]] + finfo["file_mod_prefix"] + list(mpath) + parts_u
        pub_reexports[finfo["crate_ident"]].append((
            tuple([finfo["crate_ident"]] + finfo["file_mod_prefix"] + list(mpath)),
            tuple(resolved),
            alias,
        ))


def canonical_paths_for_fn(fn):
    finfo = fn["finfo"]
    base = [finfo["crate_ident"]] + finfo["file_mod_prefix"] + fn["real_mpath"] + [fn["name"]]
    bt = tuple(base)
    paths = [bt]
    for mod_pfx, target, alias in pub_reexports.get(finfo["crate_ident"], []):
        if target == bt and alias != "*":
            paths.append(mod_pfx + (alias,))
        elif alias == "*" and bt[:-1] == target:
            paths.append(mod_pfx + (fn["name"],))
    return paths


imported_by_mod = defaultdict(list)
for finfo in files:
    for mpath, mod_name, target_rel in finfo["mods"]:
        if target_rel:
            imported_by_mod[target_rel].append((finfo["rel_path"], mod_name, mpath))


def caller_patterns_for_fn(h_fn, caller_finfo, caller_fn):
    h_finfo = h_fn["finfo"]
    hname = h_fn["name"]
    pats = []

    if caller_finfo["rel_path"] == h_finfo["rel_path"]:
        real_mpath = caller_fn["real_mpath"]
        h_real_mpath = h_fn["real_mpath"]
        if h_fn["is_impl"]:
            pats.append(rf"\.{re.escape(hname)}\s*\(")
            pats.append(rf"(?<![A-Za-z0-9_]){re.escape(h_fn['cls'])}::{re.escape(hname)}\s*\(")
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
        return pats

    same_pkg = (caller_finfo["pkg"] == h_finfo["pkg"])
    if h_fn["vis"] == "private":
        return []
    if h_fn["vis"] == "crate" and not same_pkg:
        return []

    if h_finfo["is_src"]:
        if h_fn["is_impl"]:
            cls = h_fn["cls"]
            pats.append(rf"(?<![A-Za-z0-9_]){re.escape(cls)}::{re.escape(hname)}\s*\(")
            if re.search(rf"\b{re.escape(cls)}\b", caller_finfo["clean"]):
                pats.append(rf"\.{re.escape(hname)}\s*\(")
        else:
            c_mpath = tuple(caller_fn["real_mpath"])
            for cpath in canonical_paths_for_fn(h_fn):
                full_q = "::".join(cpath)
                pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(full_q)}\s*\(")
                if same_pkg and caller_finfo["is_src"]:
                    crate_q = "::".join(("crate",) + cpath[1:])
                    pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(crate_q)}\s*\(")
                for u_mpath, _, u_parts, u_alias in caller_finfo["uses"]:
                    if u_mpath and not c_mpath[:len(u_mpath)] == u_mpath:
                        continue
                    if u_parts[0] == "crate" and same_pkg:
                        norm = (h_finfo["crate_ident"],) + tuple(u_parts[1:])
                    elif u_parts[0] == "self" and same_pkg:
                        norm = (h_finfo["crate_ident"],) + tuple(caller_finfo["file_mod_prefix"]) + u_mpath + tuple(u_parts[1:])
                    else:
                        norm = tuple(u_parts)
                    if norm == cpath and u_alias != "*":
                        if u_alias not in caller_finfo["local_non_impl_names"] or u_alias != hname:
                            pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(u_alias)}\s*\(")
                    elif u_alias == "*" and norm == cpath[:-1]:
                        if hname not in caller_finfo["local_non_impl_names"]:
                            pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(hname)}\s*\(")
                    elif u_alias != "*" and len(norm) < len(cpath) and cpath[:len(norm)] == norm:
                        tail = "::".join((u_alias,) + cpath[len(norm):])
                        pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(tail)}\s*\(")

    for imp_rel, mod_name, imp_mpath in imported_by_mod.get(h_finfo["rel_path"], []):
        if imp_rel != caller_finfo["rel_path"]:
            continue
        c_mpath = tuple(caller_fn["real_mpath"])
        if imp_mpath and not c_mpath[:len(imp_mpath)] == imp_mpath:
            continue
        if h_fn["is_impl"]:
            cls = h_fn["cls"]
            pats.append(rf"(?<![A-Za-z0-9_]){re.escape(cls)}::{re.escape(hname)}\s*\(")
            if re.search(rf"\b{re.escape(cls)}\b", caller_finfo["clean"]):
                pats.append(rf"\.{re.escape(hname)}\s*\(")
        else:
            rel_after_imp = (mod_name,) + tuple(h_fn["real_mpath"]) + (hname,)
            pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape('::'.join(rel_after_imp))}\s*\(")
            for u_mpath, _, u_parts, u_alias in caller_finfo["uses"]:
                if u_mpath and not c_mpath[:len(u_mpath)] == u_mpath:
                    continue
                norm = tuple(u_parts[1:]) if u_parts[0] in ("self", "crate") else tuple(u_parts)
                if norm == rel_after_imp and u_alias != "*":
                    if u_alias not in caller_finfo["local_non_impl_names"] or u_alias != hname:
                        pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(u_alias)}\s*\(")
                elif u_alias == "*" and norm == rel_after_imp[:-1]:
                    if hname not in caller_finfo["local_non_impl_names"]:
                        pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(hname)}\s*\(")
                elif u_alias != "*" and len(norm) < len(rel_after_imp) and rel_after_imp[:len(norm)] == norm:
                    tail = "::".join((u_alias,) + rel_after_imp[len(norm):])
                    pats.append(rf"(?<![A-Za-z0-9_:.]){re.escape(tail)}\s*\(")
    return pats


# Global workspace fixpoint taint propagation
changed = True
while changed:
    changed = False
    tainted_helpers = [idx for idx in list(taint.keys()) if not all_fns[idx]["is_test"]]
    for caller_idx, caller_fn in enumerate(all_fns):
        if caller_idx in taint:
            continue
        caller_finfo = caller_fn["finfo"]
        body_clean = caller_fn["body_clean"]
        raw = caller_finfo["raw"]
        for h_idx in tainted_helpers:
            h_fn = all_fns[h_idx]
            hname = h_fn["name"]
            if hname not in caller_fn["id_set"] and hname not in caller_finfo["renamed_targets"]:
                continue
            pats = caller_patterns_for_fn(h_fn, caller_finfo, caller_fn)
            if not pats:
                continue
            matched_line = None
            for p in pats:
                m = re.search(p, body_clean)
                if m:
                    matched_line = raw[: caller_fn["bstart"] + m.start()].count("\n") + 1
                    break
            if matched_line is not None:
                h_reason, h_file, h_line, h_chain = taint[h_idx]
                h_finfo = h_fn["finfo"]
                h_disp = "::".join(
                    ([h_finfo["crate_ident"]] if h_finfo != caller_finfo else [])
                    + h_finfo["file_mod_prefix"]
                    + h_fn["real_mpath"]
                    + [h_fn["name"]]
                )
                taint[caller_idx] = (
                    h_reason,
                    h_file,
                    h_line,
                    [(h_disp, f"{caller_finfo['rel_path']}:{matched_line}")] + h_chain,
                )
                changed = True
                break

discovered_tests = {}
tainted_tests = {}
for idx, fn in enumerate(all_fns):
    if not fn["is_test"]:
        continue
    finfo = fn["finfo"]
    fq = "::".join(finfo["file_mod_prefix"] + fn["real_mpath"] + [fn["name"]])
    ign = any("ignore" in a for a in fn["attrs"])
    key = (finfo["pkg"], finfo["tgt"], fq)
    discovered_tests[key] = (finfo["rel_path"], fn["sline"], ign)
    if idx in taint:
        sname, sfile, sink_line, chain = taint[idx]
        tainted_tests[key] = (finfo["rel_path"], fn["sline"], ign, sname, sfile, sink_line, chain)

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
        rel_s, sline, ign, sname, sfile, sink_line, chain = tainted_tests[(pkg, tgt, fq)]
        via = (
            " via " + " -> ".join(f"{fn}@{loc}" for fn, loc in chain)
            if chain
            else ""
        )
        sys.stderr.write(
            f"  - {pkg} | {tgt} | {fq} ({rel_s}:{sline}): {sname} at {sfile}:{sink_line}{via}\n"
        )

if stale:
    errors += 1
    sys.stderr.write(
        "ERROR: stale entry/entries in scripts/approve-test-denylist.txt.\n"
        "Root cause: a denylist entry no longer matches any test in the source tree; keeping "
        "stale entries hides renames or deletions and can silently weaken the skip filter.\n"
    )
    for pkg, tgt, fq in stale:
        mode, lineno = deny_entries[(pkg, tgt, fq)]
        sys.stderr.write(f"  - line {lineno}: {pkg} | {tgt} | {mode} | {fq}\n")

if errors:
    sys.exit(1)

print(
    f"OK: {len(tainted_tests)} approve/reject tests accounted for in {denylist_path.name} "
    f"({len(discovered_tests)} total tests scanned across crates/)"
)
PY
