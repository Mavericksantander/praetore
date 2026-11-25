#!/usr/bin/env bash
# The development feature `test-hooks` of praetore-replay-postgres (a hook
# inside store() for the permutation test) must never reach a shipped
# build. Fails when:
#   1. the feature is missing, or `default` enables it, directly or
#      through another of the package's features;
#   2. a workspace crate enables it from a normal or build dependency, or
#      from one of its own features;
#   3. the resolved normal + build graph of any workspace crate that ships
#      the package, with default features, has it enabled;
#   4. a release build command in the workflows, scripts or examples
#      enables it or builds with --all-features.
# Usage: check-test-hooks-feature.sh [workspace-root]
set -euo pipefail

root="${1:-.}"
cd "$root"
crate=praetore-replay-postgres
feature=test-hooks
offline=()
[ "${CHECK_TEST_HOOKS_OFFLINE:-0}" = 1 ] && offline=(--offline)

metadata="$(cargo metadata --locked "${offline[@]}" --no-deps --format-version 1)"

# 1 and 2: the manifests.
users="$(CRATE="$crate" FEATURE="$feature" python3 -c '
import json, os, sys
crate, feature = os.environ["CRATE"], os.environ["FEATURE"]
meta = json.load(sys.stdin)
errors, users = [], []
packages = {p["name"]: p for p in meta["packages"]}
own = packages.get(crate)
if own is None or feature not in own["features"]:
    errors.append(f"{crate} does not declare the feature {feature}")
else:
    seen, todo = set(), list(own["features"].get("default", []))
    while todo:
        item = todo.pop()
        if item in seen:
            continue
        seen.add(item)
        todo.extend(own["features"].get(item, []))
    if feature in seen:
        errors.append(f"{crate} enables {feature} by default")
for package in meta["packages"]:
    name = package["name"]
    for dep in package["dependencies"]:
        if dep["name"] != crate:
            continue
        if dep["kind"] != "dev":
            users.append(name)
            if feature in dep["features"]:
                kind = dep["kind"] or "normal"
                errors.append(f"{name} enables {crate}/{feature} from a {kind} dependency")
    for key, values in package["features"].items():
        for value in values:
            if value.split("/")[-1] == feature and value.split("/")[0].rstrip("?") in (crate, "dep:" + crate):
                errors.append(f"{name} feature {key} enables {value}")
for error in errors:
    print(f"::error::{error}", file=sys.stderr)
if errors:
    sys.exit(1)
print(" ".join(sorted(set(users)) + [crate]))
' <<<"$metadata")"

# 3: the resolved graph each shipping crate builds with.
for package in $users; do
  tree="$(cargo tree --locked "${offline[@]}" -p "$package" --edges normal,build,features -i "$crate")"
  if grep -F "$crate feature \"$feature\"" <<<"$tree" >/dev/null; then
    echo "::error::$package resolves $crate with $feature in its shipped graph"
    exit 1
  fi
done

# 4: release build commands.
found=0
while IFS= read -r line; do
  echo "::error::release build enables test hooks or all features: $line"
  found=1
done < <(grep -rnE -- '--release' .github/workflows scripts examples deploy Dockerfile* 2>/dev/null \
  | grep -v '^scripts/check-test-hooks-feature.sh:' \
  | grep -v '^scripts/test-check-test-hooks-feature.sh:' \
  | grep -E -- "$feature|--all-features" || true)
[ "$found" = 0 ] || exit 1

echo "$crate/$feature: absent from default features, from every shipping crate ($users) and from release builds"
