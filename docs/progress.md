# Progress & plan-alignment log

The plan these entries are checked against is summarized in `docs/threat-model.md`
and the phase list below.

## Phase 0 — Scaffolding (2026-11-12)

| Plan item | Status |
|---|---|
| Cargo workspace (`crates/*`, `server/` excluded, wasm-built separately) | ✅ |
| CI: fmt, clippy `-D warnings`, test, wasm build, cargo-deny | ✅ `.github/workflows/ci.yml`, `deny.toml` (no copyleft; libsignal banned) |
| UniFFI binding generation script | ✅ `scripts/gen-bindings.sh` — verified locally, produces Swift + Kotlin |
| iOS xcframework / Android cargo-ndk scripts | ✅ written, ⚠️ **unverified**: this machine has no Xcode or Android SDK/NDK |
| Empty iOS/Android shells calling `snow_core::version()` | ⏭️ **Deferred to start of Phase 3**: can't be built or verified without Xcode / Android Studio |
| Licenses (Apache-2.0 root; proprietary `server/LICENSE`) | ✅ |

**Deviation:** the native shell apps move from Phase 0 to Phase 3. Nothing else in
Phase 1–2 depends on them, so the order of the remaining work doesn't change.

**Action for the user:** install Xcode (then run `sudo xcode-select -s /Applications/Xcode.app`)
and Android Studio with the SDK, NDK, and cmdline-tools before Phase 3.
