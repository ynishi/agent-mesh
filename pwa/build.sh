#!/bin/bash
# Build the WASM package and symlink into pwa/pkg for local dev.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Building agent-mesh-wasm..."
cd crates/agent-mesh-wasm
wasm-pack build --target web --release
cd ../..

# Symlink pkg into pwa/
rm -f pwa/pkg
ln -sf ../crates/agent-mesh-wasm/pkg pwa/pkg

echo "Done. Serve with: python3 -m http.server -d pwa 8000"
