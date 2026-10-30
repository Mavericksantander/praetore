#!/usr/bin/env bash
# Regenera examples/third-party-verification/bundle/ con claves DEMO fijas
# (públicas, sin valor). La salida es determinista: correrlo dos veces da
# los mismos bytes. Se puede correr desde cualquier carpeta del repo.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
cargo run --quiet --locked -p praetore-core --example third_party_bundle -- \
  examples/third-party-verification/bundle
echo "escrito: examples/third-party-verification/bundle/"
