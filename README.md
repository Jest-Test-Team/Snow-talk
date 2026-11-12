# Snow-talk

Anonymous 1:1 pairing chat for iOS and Android with end-to-end encryption over a
zero-trust blind relay.

```
Client (keys + plaintext in RAM) ⇄ Cloudflare Workers (matchmaker + blind relay) ⇄ Client
```

| Path | Contents | License |
|---|---|---|
| `crates/` | Rust protocol, crypto, and client core (exposed to apps via UniFFI) | Apache-2.0 |
| `apps/ios`, `apps/android` | Native SwiftUI / Jetpack Compose shells | Apache-2.0 |
| `server/` | Cloudflare Workers (workers-rs) matchmaker + relay | Proprietary |

See `docs/threat-model.md` and `docs/progress.md`.

## Build

```sh
cargo test --workspace        # Rust core
cd server && npx wrangler dev # local relay
cargo run -p snow-cli -- --help
```

Mobile builds: `scripts/build-ios.sh`, `scripts/build-android.sh`
(require Xcode and the Android SDK + NDK respectively).
