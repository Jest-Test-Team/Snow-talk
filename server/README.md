# snow-server (proprietary — see LICENSE)

Cloudflare Workers relay written with workers-rs.

```sh
npm install
cp .dev.vars.example .dev.vars
npx wrangler dev            # http://localhost:8787
cargo test                  # native unit tests (ticket logic)
cargo clippy --target wasm32-unknown-unknown -- -D warnings
```

Production secrets: `npx wrangler secret put POW_KEY` and `TICKET_KEY` (32+ random bytes each).

Logging policy: request/invocation logs are disabled in `wrangler.toml`.
Code may only call `util::event(name)` with a static lifecycle name — never
payloads, IPs, tickets or room IDs.
