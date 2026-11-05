#!/usr/bin/env bash
# Tests how scripts/verify-release-signature.sh classifies outcomes, with stubs
# of gh and cosign: above all, that a network failure is never taken for a
# refusal by cosign. The real cosign run is the CI job release-signature.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/verify-release-signature.sh"
stubs=$(mktemp -d)
trap 'rm -rf "$stubs"' EXIT

cat > "$stubs/gh" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  "release view"*)
    [[ "${STUB_GH:-}" == down ]] && { echo "HTTP 503" >&2; exit 1; }
    echo v9.9.9 ;;
  api*)
    [[ "${STUB_GH:-}" == down ]] && { echo "HTTP 503" >&2; exit 1; }
    [[ "$*" == *commits/refs/tags/v9.9.9* ]] || { echo "bad ref: $*" >&2; exit 1; }
    echo 1111111111111111111111111111111111111111 ;;
  "release download"*)
    args="$*"; dir=${args##*--dir }; dir=${dir%% *}
    echo asset > "$dir/asset"
    (cd "$dir" && { sha256sum asset 2>/dev/null || shasum -a 256 asset; } > SHA256SUMS)
    [[ "${STUB_GH:-}" == bad_checksum ]] && echo changed > "$dir/asset"
    echo bundle > "$dir/SHA256SUMS.sigstore.json" ;;
esac
STUB

# A correct verifier: accepts only the real blob, identity, issuer, repository
# and commit, with cosign's messages. STUB_COSIGN changes that.
cat > "$stubs/cosign" <<'STUB'
#!/usr/bin/env bash
while [[ $# -gt 1 ]]; do
  case "$1" in
    --certificate-identity) identity=$2 ;;
    --certificate-oidc-issuer) issuer=$2 ;;
    --certificate-github-workflow-repository) repo=$2 ;;
    --certificate-github-workflow-sha) sha=$2 ;;
  esac
  shift
done
blob=$1
case "${STUB_COSIGN:-}" in
  accept_all) exit 0 ;;
  network) echo "Error: dial tcp 1.2.3.4:443: i/o timeout" >&2; exit 1 ;;
  network_once)
    if [[ ! -e "$STUB_STATE" ]]; then
      touch "$STUB_STATE"
      echo "Error: updating local metadata and targets: HTTP 503" >&2; exit 1
    fi ;;
  # The real signature verifies, then every refusal fails on the network.
  network_on_negatives)
    if [[ "$blob" != SHA256SUMS || "$identity" != *refs/tags/* || "$issuer" != *githubusercontent* ||
          "$repo" == *-other || "$sha" == 0* ]]; then
      echo "Error: connection reset by peer" >&2; exit 1
    fi
    exit 0 ;;
  unexpected_refusal)
    if [[ "$blob" != SHA256SUMS ]]; then echo "Error: some other failure" >&2; exit 1; fi
    exit 0 ;;
  refuses) echo "Error: invalid signature when validating ASN.1 encoded signature" >&2; exit 1 ;;
esac
if [[ "$blob" != SHA256SUMS ]]; then
  echo "Error: error verifying bundle: matching bundle to payload: bundle=x payload=y" >&2; exit 1
fi
if [[ "$identity" != *refs/tags/* || "$issuer" != *githubusercontent* ]]; then
  echo "Error: none of the expected identities matched what was in the certificate" >&2; exit 1
fi
[[ "$repo" != *-other ]] || { echo "Error: expected GitHub Workflow Repository not found in certificate" >&2; exit 1; }
[[ "$sha" != 0* ]] || { echo "Error: expected GitHub Workflow SHA not found in certificate" >&2; exit 1; }
STUB
chmod +x "$stubs/gh" "$stubs/cosign"

check() { # <name> <expected status> [VAR=value...]
  local name=$1 expected=$2 status=0
  shift 2
  rm -f "$stubs/state"
  env PATH="$stubs:$PATH" VERIFY_ATTEMPTS=2 VERIFY_RETRY_DELAY=0 STUB_STATE="$stubs/state" \
    GITHUB_REPOSITORY=example/repo "$@" "$script" "${TAG:-v9.9.9}" > "$stubs/out" 2>&1 || status=$?
  if [[ "$status" != "$expected" ]]; then
    echo "FAIL: ${name}: exit ${status}, expected ${expected}"
    cat "$stubs/out"
    exit 1
  fi
  echo "ok: ${name} (exit ${status})"
}

check "a good release verifies" 0
TAG=--latest check "--latest resolves the release" 0
check "one network failure is retried" 0 STUB_COSIGN=network_once
check "cosign cannot reach the network" 3 STUB_COSIGN=network
check "refusals fail on the network: not a refusal" 3 STUB_COSIGN=network_on_negatives
check "a refusal for an unexpected reason" 3 STUB_COSIGN=unexpected_refusal
check "GitHub is down" 3 STUB_GH=down
check "the real signature is refused" 1 STUB_COSIGN=refuses
check "a verifier that accepts anything" 1 STUB_COSIGN=accept_all
check "an asset does not match SHA256SUMS" 1 STUB_GH=bad_checksum
