#!/usr/bin/env bash
# Verify a published GitHub Release as a third party would: download its
# assets, check SHA256SUMS.sigstore.json with cosign verify-blob against the
# GitHub Actions OIDC issuer and the identity of the workflow that signs
# releases for that tag, at the tag's commit, and then check the checksums.
# Also requires that a changed SHA256SUMS, another identity and another issuer
# are refused, so a verification that accepts anything fails the run.
#
# Usage: scripts/verify-release-signature.sh <tag>
# Needs cosign and an authenticated gh. GITHUB_REPOSITORY selects the repository.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 2
fi
tag=$1
repo="${GITHUB_REPOSITORY:-Mavericksantander/praetore}"
workflow="https://github.com/${repo}/.github/workflows/assurance.yml"
identity="${workflow}@refs/tags/${tag}"
issuer=https://token.actions.githubusercontent.com

# The commit of the tag, not of the tag object: this is GITHUB_SHA in the run
# that signed, and what `git rev-parse 'vX.Y.Z^{commit}'` prints.
commit=$(gh api "repos/${repo}/commits/${tag}" --jq .sha)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh release download "$tag" --repo "$repo" --dir "$work"
cd "$work"

verify() { # <blob> <identity> <issuer>
  cosign verify-blob --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "$2" \
    --certificate-oidc-issuer "$3" \
    --certificate-github-workflow-repository "$repo" \
    --certificate-github-workflow-sha "$commit" \
    "$1"
}

verify SHA256SUMS "$identity" "$issuer"

cp SHA256SUMS tampered
echo "0000  extra" >> tampered
if verify tampered "$identity" "$issuer" 2> /dev/null; then
  echo "error: a changed SHA256SUMS verified" >&2
  exit 1
fi
if verify SHA256SUMS "${workflow}@refs/heads/main" "$issuer" 2> /dev/null; then
  echo "error: the signature verified against another workflow identity" >&2
  exit 1
fi
if verify SHA256SUMS "$identity" https://accounts.google.com 2> /dev/null; then
  echo "error: the signature verified against another OIDC issuer" >&2
  exit 1
fi
rm tampered

if command -v sha256sum > /dev/null; then
  sha256sum -c SHA256SUMS
else
  shasum -a 256 -c SHA256SUMS
fi
echo "release ${tag}: signature and checksums verified (commit ${commit})"
