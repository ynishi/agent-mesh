#!/bin/bash
# Build WASM + PWA (Vite + React).
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Building agent-mesh-wasm..."
cd crates/agent-mesh-wasm
wasm-pack build --target web --release
cd ../..

echo "Building PWA..."
cd pwa
npm ci --legacy-peer-deps
npx tsc --noEmit
npx vite build
cd ..

echo "Done. Output: pwa/dist/"
echo "Serve with: agent-mesh-server --pwa-dir pwa/dist"
