#!/usr/bin/env bash
# Checks the build version a praetore-mcp binary prints against the ref it
# was built for. The version comes from crates/praetore-mcp/build_version.rs
# and is read only from what the binary prints.
#
#   scripts/check-build-version.sh BINARY CRATE_VERSION REF REF_NAME
#
# On a tag (REF refs/tags/v*), REF_NAME must be v<CRATE_VERSION> and
# `BINARY --version` exactly `praetore-mcp <CRATE_VERSION>`. On any other
# ref, exactly `praetore-mcp <CRATE_VERSION>-dev+<7 to 40 hex>`. A binary
# that does not run fails the check.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 BINARY CRATE_VERSION REF REF_NAME" >&2
  exit 2
fi
bin=$1 crate=$2 ref=$3 ref_name=$4

if [[ "${ref}" == refs/tags/v* && "${ref_name}" != "v${crate}" ]]; then
  echo "error: tag ${ref_name} is not v${crate}, the version in crates/praetore-mcp/Cargo.toml. Tag the commit v${crate} or set the crate version to ${ref_name#v}."
  exit 1
fi
if ! printed=$("${bin}" --version); then
  echo "error: ${bin} --version did not run on this runner, so its build version cannot be checked. For x86_64-apple-darwin on Apple silicon, install Rosetta 2 first."
  exit 1
fi
echo "printed: ${printed}"
if [[ "${ref}" == refs/tags/v* ]]; then
  want="praetore-mcp ${crate}"
  if [[ "${printed}" != "${want}" ]]; then
    echo "error: on tag ${ref_name} --version printed '${printed}', not '${want}'. build_version.rs makes a release build only when git finds this repository with the tag on HEAD: check that the checkout has the tag and .git."
    exit 1
  fi
else
  # The crate version is quoted: matched as literal text, not a pattern.
  if ! [[ "${printed}" =~ ^praetore-mcp\ "${crate}"-dev\+[0-9a-f]{7,40}$ ]]; then
    echo "error: off a tag --version printed '${printed}', not 'praetore-mcp ${crate}-dev+<commit>'. build_version.rs reads the commit from this repository's git: check that the checkout has .git."
    exit 1
  fi
fi
