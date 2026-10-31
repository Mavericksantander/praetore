#!/usr/bin/env bash
# Self-test for scripts/release-checksums.sh: one good set of archives, then
# one broken copy per failure the script must catch.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/release-checksums.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
version=v0.0.0-test
targets=(x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-apple-darwin)
if command -v sha256sum >/dev/null; then sha=(sha256sum); else sha=(shasum -a 256); fi

make_assets() {
  local dir=$1
  mkdir -p "$dir"
  for target in "${targets[@]}"; do
    local name="praetore-mcp-${version}-${target}"
    mkdir -p "$work/src/$name"
    echo "binary for $target" > "$work/src/$name/praetore-mcp"
    echo license > "$work/src/$name/LICENSE"
    echo notice > "$work/src/$name/NOTICE"
    tar -C "$work/src" -czf "$dir/${name}.tar.gz" "$name"
    (cd "$dir" && "${sha[@]}" "${name}.tar.gz" > "${name}.tar.gz.sha256")
    rm -rf "$work/src/$name"
  done
}

echo verify > "$work/praetore-verify"
failures=0

expect() {
  local want=$1 label=$2 assets=$3
  local out="$work/out-$RANDOM"
  if "$script" "$version" "$assets" "$work/praetore-verify" "$out" >"$work/log" 2>&1; then
    got=pass
  else
    got=fail
  fi
  if [[ "$got" == "$want" ]]; then
    echo "PASS: $label ($got)"
  else
    echo "FAIL: $label: expected $want, got $got"
    cat "$work/log"
    failures=$((failures + 1))
  fi
  if [[ "$got" == pass ]]; then
    (cd "$out" && "${sha[@]}" -c SHA256SUMS >/dev/null)
    local count
    count=$(wc -l < "$out/SHA256SUMS" | tr -d ' ')
    if [[ "$count" != 4 ]]; then
      echo "FAIL: $label: SHA256SUMS has $count lines, expected 4"
      failures=$((failures + 1))
    fi
  fi
}

make_assets "$work/good"
expect pass "three archives and praetore-verify" "$work/good"

cp -R "$work/good" "$work/missing"
rm "$work/missing/praetore-mcp-${version}-x86_64-apple-darwin.tar.gz"
expect fail "missing archive" "$work/missing"

cp -R "$work/good" "$work/nosum"
rm "$work/nosum/praetore-mcp-${version}-aarch64-apple-darwin.tar.gz.sha256"
expect fail "missing per-runner .sha256" "$work/nosum"

cp -R "$work/good" "$work/tampered"
echo x >> "$work/tampered/praetore-mcp-${version}-x86_64-unknown-linux-gnu.tar.gz"
expect fail "archive changed after the runner checksummed it" "$work/tampered"

cp -R "$work/good" "$work/extra"
touch "$work/extra/praetore-mcp-${version}-riscv64gc-unknown-linux-gnu.tar.gz"
expect fail "unexpected extra file" "$work/extra"

mkdir -p "$work/contents"
make_assets "$work/contents"
name="praetore-mcp-${version}-aarch64-apple-darwin"
mkdir -p "$work/src/$name"
for f in praetore-mcp LICENSE NOTICE stray; do echo "$f" > "$work/src/$name/$f"; done
tar -C "$work/src" -czf "$work/contents/${name}.tar.gz" "$name"
(cd "$work/contents" && "${sha[@]}" "${name}.tar.gz" > "${name}.tar.gz.sha256")
expect fail "archive with an extra file inside" "$work/contents"

mkdir "$work/exists"
if "$script" "$version" "$work/good" "$work/praetore-verify" "$work/exists" >/dev/null 2>&1; then
  echo "FAIL: existing output directory was reused"
  failures=$((failures + 1))
else
  echo "PASS: existing output directory is refused (fail)"
fi

if [[ $failures -ne 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
