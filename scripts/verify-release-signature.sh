#!/usr/bin/env bash
# Verify a published GitHub Release as a third party would: download its
# assets, check SHA256SUMS.sigstore.json with cosign verify-blob against the
# GitHub Actions OIDC issuer and the identity of the workflow that signs
# releases for that tag, at the tag's commit, and then check the checksums.
#
# Also requires that a changed SHA256SUMS, another identity, another issuer,
# another repository and another commit are refused. A refusal only counts when
# cosign gives the reason expected for that case, so a network failure is never
# taken for a refusal.
#
# Usage: scripts/verify-release-signature.sh <tag|--latest>
# Needs cosign and an authenticated gh. GITHUB_REPOSITORY selects the repository.
#
# Exit status:
#   0  verified
#   1  verification failed: a signature or checksum was refused, or something
#      that must be refused was accepted
#   2  usage
#   3  inconclusive: nothing was refused, but the check could not be completed
#      (network failure after retries, or a refusal for an unexpected reason)
set -uo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag|--latest>" >&2
  exit 2
fi
repo="${GITHUB_REPOSITORY:-Mavericksantander/praetore}"
attempts="${VERIFY_ATTEMPTS:-4}"
delay="${VERIFY_RETRY_DELAY:-5}"
issuer=https://token.actions.githubusercontent.com
workflow="https://github.com/${repo}/.github/workflows/assurance.yml"

refused() { echo "error: $*" >&2; exit 1; }
inconclusive() { echo "inconclusive: $*" >&2; exit 3; }

looks_like_network_failure() {
  grep -qiE 'dial tcp|timeout|timed out|connection (refused|reset)|no such host|TLS handshake|EOF|temporary failure|network is unreachable|HTTP (429|5[0-9][0-9])|status code (429|5[0-9][0-9])|updating local metadata|fetching (target|metadata)' <<<"$1"
}

# Runs a command that only reads from the network, with retries.
fetch() {
  local try output
  for ((try = 1; try <= attempts; try++)); do
    if output=$("$@" 2>&1); then
      printf '%s\n' "$output"
      return 0
    fi
    echo "attempt ${try}/${attempts} failed: ${*:1:3}: ${output}" >&2
    ((try < attempts)) && sleep "$((delay * try))"
  done
  return 1
}

cosign_verify() { # <blob> <identity> <issuer> <repository> <commit>
  cosign verify-blob --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "$2" \
    --certificate-oidc-issuer "$3" \
    --certificate-github-workflow-repository "$4" \
    --certificate-github-workflow-sha "$5" \
    "$1" 2>&1
}

must_verify() {
  local try output
  for ((try = 1; try <= attempts; try++)); do
    if output=$(cosign_verify "$@"); then
      printf '%s\n' "$output"
      return 0
    fi
    if ! looks_like_network_failure "$output"; then
      printf '%s\n' "$output" >&2
      refused "cosign refused the signature of the published release"
    fi
    echo "attempt ${try}/${attempts}: network failure: ${output}" >&2
    ((try < attempts)) && sleep "$((delay * try))"
  done
  inconclusive "cosign could not reach the network: ${output}"
}

must_refuse() { # <case> <expected refusal> <cosign_verify arguments...>
  local name=$1 expected=$2 try output
  shift 2
  for ((try = 1; try <= attempts; try++)); do
    if output=$(cosign_verify "$@"); then
      refused "${name}: verified, and must be refused"
    fi
    if grep -qF "$expected" <<<"$output"; then
      echo "refused as expected: ${name}"
      return 0
    fi
    looks_like_network_failure "$output" || break
    echo "attempt ${try}/${attempts}: ${name}: network failure: ${output}" >&2
    ((try < attempts)) && sleep "$((delay * try))"
  done
  inconclusive "${name}: failed without the expected refusal: ${output}"
}

tag=$1
if [[ "$tag" == --latest ]]; then
  tag=$(fetch gh release view --repo "$repo" --json tagName --jq .tagName) \
    || inconclusive "could not find the latest release"
fi
identity="${workflow}@refs/tags/${tag}"

# The commit of the tag, not of the tag object: this is GITHUB_SHA in the run
# that signed, and what `git rev-parse 'vX.Y.Z^{commit}'` prints. The full ref,
# so a branch with the same name cannot be taken for it.
commit=$(fetch gh api "repos/${repo}/commits/refs/tags/${tag}" --jq .sha) \
  || inconclusive "could not resolve the commit of ${tag}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch gh release download "$tag" --repo "$repo" --dir "$work" --clobber > /dev/null \
  || inconclusive "could not download the assets of ${tag}"
cd "$work" || exit 3

must_verify SHA256SUMS "$identity" "$issuer" "$repo" "$commit"

cp SHA256SUMS tampered
echo "0000  extra" >> tampered
must_refuse "changed SHA256SUMS" "matching bundle to payload" \
  tampered "$identity" "$issuer" "$repo" "$commit"
must_refuse "another identity" "none of the expected identities matched" \
  SHA256SUMS "${workflow}@refs/heads/main" "$issuer" "$repo" "$commit"
must_refuse "another issuer" "none of the expected identities matched" \
  SHA256SUMS "$identity" https://accounts.google.com "$repo" "$commit"
must_refuse "another repository" "expected GitHub Workflow Repository not found" \
  SHA256SUMS "$identity" "$issuer" "${repo}-other" "$commit"
must_refuse "another commit" "expected GitHub Workflow SHA not found" \
  SHA256SUMS "$identity" "$issuer" "$repo" 0000000000000000000000000000000000000000
rm tampered

if command -v sha256sum > /dev/null; then
  checksums=(sha256sum -c SHA256SUMS)
else
  checksums=(shasum -a 256 -c SHA256SUMS)
fi
"${checksums[@]}" || refused "a release asset does not match SHA256SUMS"
echo "release ${tag}: signature and checksums verified (commit ${commit})"
