#!/usr/bin/env bash
# Build libsnow_core.so for apps/android. Requires Android NDK + cargo-ndk.
# Android/sideload builds include adult tags (SNOW_FEATURES="" to leave them out).
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME (Android Studio > SDK Manager > NDK)}"
command -v cargo-ndk >/dev/null || cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -P 28 \
  -o apps/android/app/src/main/jniLibs build -p snow-core --release --features "${SNOW_FEATURES-adult_tags}"
./scripts/gen-bindings.sh
mkdir -p apps/android/app/src/main/java && cp -R bindings/kotlin/* apps/android/app/src/main/java/
echo "built jniLibs"
