#!/usr/bin/env bash
# PRAETORE receipt verification demo (DEMO/TEST ONLY: fixed public seeds,
# fictitious data). Exit 0 only if the valid receipt verifies and every
# tampered copy is rejected with the expected error.
set -euo pipefail
cd "$(dirname "$0")/.."
exec cargo run --quiet --locked -p praetore-receipt --features signing --example demo_receipt_verify
