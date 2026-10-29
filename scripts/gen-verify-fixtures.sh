#!/usr/bin/env bash
# Regenerates examples/verify/ (README fixtures for praetore-verify) from
# fixed TEST-ONLY keys. No real secrets. Run from anywhere inside the repo.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
cargo run --quiet -p praetore-core --example verify_fixtures -- examples/verify
echo "wrote examples/verify/"
