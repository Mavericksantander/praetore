#!/usr/bin/env python3
"""Refresh repository-derived dashboard facts and its file://-safe data bundle."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TEST_ATTRIBUTE = re.compile(r"#\[(?:tokio::)?test(?:\s*\([^]]*\))?\]")


def git_value(root: Path, *args: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def cargo_metadata(manifest_path: Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(manifest_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cargo metadata failed for {manifest_path}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def rust_package_facts(root: Path, package: dict[str, Any], known_names: set[str]) -> dict[str, Any]:
    manifest_path = Path(package["manifest_path"])
    package_root = manifest_path.parent
    dependency_names = {dependency["name"] for dependency in package.get("dependencies", [])}
    local_dependencies = dependency_names & known_names
    sources = sorted(package_root.glob("src/**/*.rs"))
    test_files = sorted(package_root.glob("tests/**/*.rs"))
    rust_files = sources + test_files
    test_attributes = sum(
        len(TEST_ATTRIBUTE.findall(path.read_text(encoding="utf-8")))
        for path in rust_files
    )
    test_paths = [path.relative_to(root).as_posix() for path in test_files]
    return {
        "id": package["name"],
        "name": package["name"],
        "path": package_root.relative_to(root).as_posix(),
        "manifest": manifest_path.relative_to(root).as_posix(),
        "description": package.get("description") or "",
        "dependencies": sorted(dependency_names),
        "localDependencies": sorted(local_dependencies),
        "externalDependencyCount": len(dependency_names - known_names),
        "testFiles": test_paths,
        "rustTestAttributes": test_attributes,
    }


def discover(root: Path) -> dict[str, Any]:
    workspace_path = root / "Cargo.toml"
    workspace_metadata = cargo_metadata(workspace_path)
    workspace_members = workspace_metadata.get("workspace_members", [])
    workspace_packages = {
        package["id"]: package for package in workspace_metadata.get("packages", [])
    }
    packages_by_name = {
        workspace_packages[package_id]["name"]: workspace_packages[package_id]
        for package_id in workspace_members
    }
    known_names = set(packages_by_name)
    packages = [
        rust_package_facts(root, workspace_packages[package_id], known_names)
        for package_id in workspace_members
    ]

    fuzz_manifest = root / "fuzz" / "Cargo.toml"
    if fuzz_manifest.exists():
        fuzz_metadata = cargo_metadata(fuzz_manifest)
        packages.extend(
            rust_package_facts(root, package, known_names)
            for package in fuzz_metadata.get("packages", [])
            if package["manifest_path"] == str(fuzz_manifest)
        )

    python_manifest = root / "packages" / "praetore-python" / "pyproject.toml"
    if python_manifest.exists():
        packages.append(
            {
                "id": "python-package",
                "name": "praetore-python distribution",
                "path": python_manifest.parent.relative_to(root).as_posix(),
                "manifest": python_manifest.relative_to(root).as_posix(),
                "description": "Python package and verifier client.",
                "dependencies": [],
                "localDependencies": ["praetore-python"],
                "externalDependencyCount": 0,
                "testFiles": sorted(
                    path.relative_to(root).as_posix()
                    for path in (python_manifest.parent / "tests").glob("test_*.py")
                ),
                "rustTestAttributes": 0,
            }
        )

    deployment_root = root / "deploy" / "kubernetes"
    if deployment_root.exists():
        packages.append(
            {
                "id": "kubernetes-deployment",
                "name": "Kubernetes deployment",
                "path": deployment_root.relative_to(root).as_posix(),
                "manifest": None,
                "description": "Kubernetes templates and deployment policies.",
                "dependencies": [],
                "localDependencies": [],
                "externalDependencyCount": 0,
                "testFiles": [],
                "rustTestAttributes": 0,
                "manifestCount": len(list(deployment_root.glob("*.yaml"))),
            }
        )

    status_text = git_value(root, "status", "--short", "--untracked-files=all")
    revision = git_value(root, "rev-parse", "--short", "HEAD")
    branch = git_value(root, "branch", "--show-current")
    if status_text is None:
        worktree = {"available": False, "changedFiles": None, "clean": None}
    else:
        changed_files = len([line for line in status_text.splitlines() if line.strip()])
        worktree = {
            "available": True,
            "changedFiles": changed_files,
            "clean": changed_files == 0,
        }

    return {
        "lastRefreshed": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "revision": revision or "unknown",
        "branch": branch or "unknown",
        "worktree": worktree,
        "workspacePackageCount": len(workspace_members),
        "packages": sorted(packages, key=lambda item: item["id"]),
        "ciWorkflows": sorted(
            path.relative_to(root).as_posix()
            for path in (root / ".github" / "workflows").glob("*.yml")
        )
        + sorted(
            path.relative_to(root).as_posix()
            for path in (root / ".github" / "workflows").glob("*.yaml")
        ),
    }


def write_bundle(data: dict[str, Any], data_path: Path, bundle_path: Path) -> None:
    serialized = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    bundle = "window.PRAETORE_DASHBOARD_DATA = " + json.dumps(
        data, ensure_ascii=False, separators=(",", ":")
    )
    bundle = bundle.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    bundle += ";\n"
    data_path.write_text(serialized, encoding="utf-8")
    bundle_path.write_text(bundle, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root (defaults to the parent of this script's directory).",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    data_path = Path(__file__).resolve().parent / "dashboard-data.json"
    bundle_path = Path(__file__).resolve().parent / "dashboard-data.js"

    data = json.loads(data_path.read_text(encoding="utf-8"))
    data["discovered"] = discover(root)
    for assessment in data.get("assessments", []):
        if assessment.get("lastVerifiedRevision") == "discovered.revision":
            assessment["lastVerifiedRevision"] = data["discovered"]["revision"]
    write_bundle(data, data_path, bundle_path)
    print(
        "Refreshed repository facts for "
        f"{data['discovered']['revision']} "
        f"({len(data['discovered']['packages'])} inventory entries)."
    )


if __name__ == "__main__":
    main()
