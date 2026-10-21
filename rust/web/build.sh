#!/bin/sh
# build floss-rs for the browser: web/floss_web.wasm, next to index.html, worker.js and floss.js.
# needs: rustup target add wasm32-wasip1, and clang (for zydis, in lancelot).
# serve this directory with any static web server, like: python3 -m http.server -d web
set -e
cd "$(dirname "$0")"
LANCELOT=$(cargo metadata --format-version 1 --manifest-path ../Cargo.toml \
  | python3 -c 'import json, sys; print(next(p["manifest_path"] for p in json.load(sys.stdin)["packages"] if p["name"] == "lancelot"))')
# lancelot's CMake toolchain file builds zydis for WebAssembly with clang.
CMAKE_TOOLCHAIN_FILE="$(dirname "$(dirname "$LANCELOT")")/wasm32-toolchain.cmake" cargo build --release
cp target/wasm32-wasip1/release/floss_web.wasm .
ls -l floss_web.wasm
