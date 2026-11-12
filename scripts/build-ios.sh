#!/usr/bin/env bash
# Build SnowCore.xcframework (device + simulator) for apps/ios. Requires full Xcode.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v xcodebuild >/dev/null && xcodebuild -version >/dev/null 2>&1 \
  || { echo "error: full Xcode is required (xcode-select -s /Applications/Xcode.app)"; exit 1; }
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
rustup target add "${TARGETS[@]}"
for t in "${TARGETS[@]}"; do
  IPHONEOS_DEPLOYMENT_TARGET=15.0 cargo build -p snow-core --release --target "$t"
done
mkdir -p target/ios-sim
lipo -create target/aarch64-apple-ios-sim/release/libsnow_core.a \
             target/x86_64-apple-ios/release/libsnow_core.a \
     -output target/ios-sim/libsnow_core.a
./scripts/gen-bindings.sh
HDRS=target/ios-headers; rm -rf "$HDRS"; mkdir -p "$HDRS"
cp bindings/swift/*.h "$HDRS"/
cat bindings/swift/*.modulemap > "$HDRS/module.modulemap"
OUT=apps/ios/SnowCore.xcframework; rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libsnow_core.a -headers "$HDRS" \
  -library target/ios-sim/libsnow_core.a -headers "$HDRS" \
  -output "$OUT"
mkdir -p apps/ios/SnowTalk/Generated && cp bindings/swift/*.swift apps/ios/SnowTalk/Generated/
echo "built $OUT"
