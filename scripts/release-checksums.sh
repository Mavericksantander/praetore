#!/usr/bin/env bash
# Assemble checksummed release assets from the CI-built archives.
#
# Usage: scripts/release-checksums.sh <version> <mcp-assets-dir> <praetore-verify-binary> <out-dir>
#
# <mcp-assets-dir> holds praetore-mcp-<version>-<target>.tar.gz and the
# .sha256 written by the runner that built it. For each expected target the
# script checks that the archive and its .sha256 exist, that the .sha256
# matches, and that the archive holds exactly <name>/praetore-mcp, LICENSE
# and NOTICE. It then copies the archives and praetore-verify (built on the
# Linux x86_64 runner) into <out-dir>, writes SHA256SUMS there and checks it.
# Any missing, extra or mismatching file fails the run; <out-dir> must not
# exist yet.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <version> <mcp-assets-dir> <praetore-verify-binary> <out-dir>" >&2
  exit 2
fi
version=$1 assets=$2 verify_bin=$3 out=$4
targets=(x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-apple-darwin)

if command -v sha256sum >/dev/null; then sha=(sha256sum); else sha=(shasum -a 256); fi

if [[ -e "$out" ]]; then
  echo "error: $out already exists" >&2
  exit 1
fi
mkdir -p "$out"

expected=()
for target in "${targets[@]}"; do
  name="praetore-mcp-${version}-${target}"
  archive="${name}.tar.gz"
  for file in "$archive" "${archive}.sha256"; do
    [[ -f "$assets/$file" ]] || { echo "error: missing $assets/$file" >&2; exit 1; }
  done
  (cd "$assets" && "${sha[@]}" -c "${archive}.sha256")
  listing=$(tar -tzf "$assets/$archive" | sed 's#/$##' | LC_ALL=C sort)
  want=$(printf '%s\n' "$name" "$name/LICENSE" "$name/NOTICE" "$name/praetore-mcp" | LC_ALL=C sort)
  if [[ "$listing" != "$want" ]]; then
    echo "error: unexpected contents in $archive:" >&2
    echo "$listing" >&2
    exit 1
  fi
  expected+=("$archive" "${archive}.sha256")
  cp "$assets/$archive" "$out/"
done

# Nothing else may ride along into the release.
extra=$(cd "$assets" && ls -1 | LC_ALL=C sort | comm -23 - <(printf '%s\n' "${expected[@]}" | LC_ALL=C sort))
if [[ -n "$extra" ]]; then
  echo "error: unexpected files in $assets:" >&2
  echo "$extra" >&2
  exit 1
fi

cp "$verify_bin" "$out/praetore-verify"
cd "$out"
# List first: the redirect would otherwise create SHA256SUMS inside the list.
files=$(LC_ALL=C ls -1 | LC_ALL=C sort)
echo "$files" | xargs "${sha[@]}" > SHA256SUMS
"${sha[@]}" -c SHA256SUMS
cat SHA256SUMS
