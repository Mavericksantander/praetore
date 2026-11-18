#!/usr/bin/env bash
# Self-test for scripts/check-rust-version.sh. Builds tiny workspaces and
# checks that a diverging, missing or differently inherited rust-version
# fails, and that a uniform tree passes.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/check-rust-version.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

write() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat > "$path"
}

check() {
  local label=$1 want=$2 dir=$3 got=0
  "$script" "$dir" >"$work/out" 2>"$work/err" || got=$?
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: exit $got, want $want"
    sed 's/^/    /' "$work/out" "$work/err"
    failures=$((failures + 1))
  fi
}

base="$work/ok"
write "$base/Cargo.toml" <<'EOF'
[workspace]
members = ["crates/one"]
resolver = "2"

[workspace.package]
rust-version = "1.88"
EOF
write "$base/crates/one/Cargo.toml" <<'EOF'
[package]
name = "one"
version = "0.0.0"
edition = "2021"
rust-version.workspace = true
EOF
write "$base/fuzz/Cargo.toml" <<'EOF'
[package]
name = "fuzz-one"
version = "0.0.0"
edition = "2021"
rust-version = "1.88"
EOF
write "$base/examples/hook/Cargo.toml" <<'EOF'
[package]
name = "hook"
version = "0.0.0"
edition = "2021"
rust-version = "1.88"

[workspace]
EOF
check "uniform workspace, literal and inherited" 0 "$base"

diverge="$work/diverge"
cp -a "$base" "$diverge"
write "$diverge/crates/one/Cargo.toml" <<'EOF'
[package]
name = "one"
version = "0.0.0"
edition = "2021"
rust-version = "1.70"
EOF
check "member rust-version differs" 1 "$diverge"

missing="$work/missing"
cp -a "$base" "$missing"
write "$missing/fuzz/Cargo.toml" <<'EOF'
[package]
name = "fuzz-one"
version = "0.0.0"
edition = "2021"
EOF
check "package omits rust-version" 1 "$missing"

other="$work/other"
cp -a "$base" "$other"
write "$other/examples/hook/Cargo.toml" <<'EOF'
[package]
name = "hook"
version = "0.0.0"
edition = "2021"
rust-version = "1.89"

[workspace]
EOF
check "standalone package differs" 1 "$other"

inherit_gap="$work/inherit-gap"
cp -a "$base" "$inherit_gap"
write "$inherit_gap/examples/hook/Cargo.toml" <<'EOF'
[package]
name = "hook"
version = "0.0.0"
edition = "2021"
rust-version.workspace = true

[workspace]
EOF
check "workspace = true where the workspace omits rust-version" 1 "$inherit_gap"

no_root="$work/no-root"
mkdir -p "$no_root"
write "$no_root/Cargo.toml" <<'EOF'
[workspace]
members = ["one"]
EOF
write "$no_root/one/Cargo.toml" <<'EOF'
[package]
name = "one"
version = "0.0.0"
edition = "2021"
rust-version = "1.88"
EOF
check "root workspace omits rust-version" 1 "$no_root"

if [[ "$failures" -ne 0 ]]; then
  echo "$failures check-rust-version case(s) failed"
  exit 1
fi
echo "check-rust-version: all cases pass"
