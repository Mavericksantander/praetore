#!/usr/bin/env bash
# Fails when a Cargo.toml in this tree does not declare the same rust-version
# as the root workspace. The expected value is
# [workspace.package].rust-version in the root Cargo.toml.
#
# A package that sets rust-version.workspace = true is accepted when the
# workspace Cargo.toml that owns it (the nearest ancestor that has a
# [workspace] table, including the file itself) declares that same value.
# Any other package must set rust-version to the same string. A missing
# field fails. Cargo.toml files under target/ are ignored.
#
#   scripts/check-rust-version.sh [ROOT]
set -euo pipefail

root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
if [[ ! -f "${root}/Cargo.toml" ]]; then
  echo "error: ${root}/Cargo.toml does not exist" >&2
  exit 2
fi

python3 - "${root}" <<'PY'
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1]).resolve()
failures = []

def load(path: pathlib.Path):
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        failures.append(f"{path}: cannot parse TOML: {error}")
        return None

root_doc = load(root / "Cargo.toml")
if root_doc is None:
    for line in failures:
        print(f"error: {line}", file=sys.stderr)
    sys.exit(1)

expected = (
    root_doc.get("workspace", {})
    .get("package", {})
    .get("rust-version")
)
if not isinstance(expected, str) or not expected:
    print(
        "error: root Cargo.toml has no [workspace.package] rust-version string",
        file=sys.stderr,
    )
    sys.exit(1)

def workspace_rust_version(package_file: pathlib.Path):
    """rust-version of the workspace that owns this package file."""
    current = package_file.parent
    while True:
        manifest = current / "Cargo.toml"
        if manifest.is_file():
            doc = load(manifest)
            if doc is not None and "workspace" in doc:
                value = doc.get("workspace", {}).get("package", {}).get("rust-version")
                return value if isinstance(value, str) else None
        if current == root or current.parent == current:
            return None
        current = current.parent

manifests = sorted(root.rglob("Cargo.toml"))
seen_package = False
for path in manifests:
    if "target" in path.relative_to(root).parts:
        continue
    doc = load(path)
    if doc is None or "package" not in doc:
        continue
    seen_package = True
    rust_version = doc["package"].get("rust-version")
    rel = path.relative_to(root)
    if isinstance(rust_version, str):
        if rust_version != expected:
            failures.append(
                f"{rel}: rust-version is {rust_version!r}, workspace requires {expected!r}"
            )
        continue
    if isinstance(rust_version, dict) and rust_version.get("workspace") is True and len(rust_version) == 1:
        inherited = workspace_rust_version(path)
        if inherited != expected:
            failures.append(
                f"{rel}: rust-version.workspace = true, but its workspace declares {inherited!r}, not {expected!r}"
            )
        continue
    if rust_version is None:
        failures.append(f"{rel}: package does not declare rust-version")
        continue
    failures.append(f"{rel}: rust-version has an unsupported form {rust_version!r}")

if not seen_package and not failures:
    failures.append("no [package] table found")

if failures:
    print(
        f"error: rust-version must be {expected!r} on every package (or rust-version.workspace = true under a workspace that declares it)",
        file=sys.stderr,
    )
    for line in failures:
        print(f"error: {line}", file=sys.stderr)
    sys.exit(1)

print(f"rust-version {expected} on every package Cargo.toml under {root}")
PY
