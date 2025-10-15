#!/bin/bash

set -e

echo "Building X25519-WASM..."

cargo build --target wasm32-unknown-unknown --release

wasm-bindgen --target web --out-dir ./pkg-web --omit-imports --reference-types ./target/wasm32-unknown-unknown/release/x25519_wasm_vn.wasm

wasm-bindgen --target deno --out-dir ./pkg-deno --omit-imports --reference-types ./target/wasm32-unknown-unknown/release/x25519_wasm_vn.wasm

wasm-bindgen --target nodejs --out-dir ./pkg-nodejs --omit-imports --reference-types ./target/wasm32-unknown-unknown/release/x25519_wasm_vn.wasm

wasm-bindgen --target bundler --out-dir ./pkg-bundler --omit-imports --reference-types ./target/wasm32-unknown-unknown/release/x25519_wasm_vn.wasm

cp package.json pkg-bundler/package.json
cp README.md pkg-bundler/README.md
cp LICENSE pkg-bundler/LICENSE

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
