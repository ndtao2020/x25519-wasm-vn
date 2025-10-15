#!/bin/bash

set -e

echo "Building X25519-WASM..."

cargo build --target wasm32-unknown-unknown --release

wasm-bindgen --target web --out-dir ./pkg ./target/wasm32-unknown-unknown/release/x25519_wasm_vn.wasm
wasm-bindgen --target deno --out-dir ./pkg/deno ./target/wasm32-unknown-unknown/release/x25519_wasm_vn.wasm
wasm-bindgen --target nodejs --out-dir ./pkg/nodejs ./target/wasm32-unknown-unknown/release/x25519_wasm_vn.wasm
wasm-bindgen --target bundler --out-dir ./pkg/bundler ./target/wasm32-unknown-unknown/release/x25519_wasm_vn.wasm

cp package.json pkg/package.json
cp README.md pkg/README.md
cp LICENSE pkg/LICENSE

echo "*" > ./pkg/.gitignore

# Optimize WASM
echo "⚡ Optimizing WASM..."

if command -v wasm-opt &> /dev/null; then

    wasm-opt -Oz pkg-web/x25519_wasm_vn_bg.wasm -o pkg-web/x25519_wasm_vn_bg.wasm
    wasm-opt -Oz pkg-deno/x25519_wasm_vn_bg.wasm -o pkg-deno/x25519_wasm_vn_bg.wasm
    wasm-opt -Oz pkg-nodejs/x25519_wasm_vn_bg.wasm -o pkg-nodejs/x25519_wasm_vn_bg.wasm
    wasm-opt -Oz pkg-bundler/x25519_wasm_vn_bg.wasm -o pkg-bundler/x25519_wasm_vn_bg.wasm

    echo "✅ WASM optimized"
else
    echo "⚠️  wasm-opt not found, skipping optimization"
fi
