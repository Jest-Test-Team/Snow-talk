#!/usr/bin/env bash
# Generate Swift + Kotlin bindings for snow-core via UniFFI.
set -euo pipefail
cd "$(dirname "$0")/.."
# Unstripped profile: UniFFI reads its metadata from the library's symbols.
cargo build -p snow-core --profile bindings
LIB=target/bindings/libsnow_core.dylib
[[ -f $LIB ]] || LIB=target/bindings/libsnow_core.so
cargo run -q -p snow-core --features bindgen --bin uniffi-bindgen -- \
  generate --library "$LIB" --language swift --out-dir bindings/swift
cargo run -q -p snow-core --features bindgen --bin uniffi-bindgen -- \
  generate --library "$LIB" --language kotlin --out-dir bindings/kotlin
echo "bindings written to bindings/"
