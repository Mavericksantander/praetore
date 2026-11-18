#!/usr/bin/env bash
# Canary for the clippy rule that keeps praetore_mcp::approvals::Expiry::at
# for display only (crates/praetore-mcp/clippy.toml). It adds a module that
# calls Expiry::at() with no #[expect], runs clippy on the crate with
# -D warnings in this same environment, and requires that clippy fails with
# "disallowed method". tests/lint_guard.rs reads the sources and the config
# files; this canary also sees what only the build sees (RUSTFLAGS and
# friends, a .cargo/config.toml anywhere Cargo looks, lint levels from the
# workspace). The module and lib.rs are restored on exit.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
crate="${root}/crates/praetore-mcp"
lib="${crate}/src/lib.rs"
canary="${crate}/src/zz_lint_canary.rs"
backup=$(mktemp)
log=$(mktemp)
cp "${lib}" "${backup}"
restore() {
  cp "${backup}" "${lib}"
  rm -f "${canary}" "${backup}" "${log}"
}
trap restore EXIT

cat > "${canary}" <<'EOF'
//! Written by scripts/clippy-canary.sh and removed when it ends.
pub fn canary(expiry: &crate::approvals::Expiry) -> bool {
    expiry.at().is_some()
}
EOF
printf '\npub mod zz_lint_canary;\n' >> "${lib}"

status=0
(cd "${root}" && cargo clippy -p praetore-mcp --lib --locked -- -D warnings) >"${log}" 2>&1 || status=$?

if [[ ${status} -ne 0 ]] && grep -q "disallowed method" "${log}"; then
  echo "clippy canary: Expiry::at() without #[expect] is refused (disallowed method), as it must be."
  exit 0
fi
cat "${log}"
if [[ ${status} -eq 0 ]]; then
  echo "::error::clippy canary: a new Expiry::at() call without #[expect] passed clippy -D warnings. Something turned clippy::disallowed_methods off for this build: RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS or CARGO_BUILD_RUSTFLAGS with -A or --cap-lints; rustflags in a .cargo/config.toml; #![allow(warnings)] or an allow of clippy::disallowed_methods (or clippy::style, clippy::all) on the crate; a [lints] table in Cargo.toml or the workspace; or clippy.toml no longer lists praetore_mcp::approvals::Expiry::at. Remove it: expiry must only be compared with Expiry::is_expired_at."
else
  echo "::error::clippy canary: clippy failed, but not with \"disallowed method\" (exit ${status}); the canary could not check the rule. See the output above."
fi
exit 1
