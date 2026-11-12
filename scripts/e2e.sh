#!/usr/bin/env bash
# Start the relay locally, pair two bots, and check the relay never saw plaintext.
set -euo pipefail
cd "$(dirname "$0")/.."
MARKER="E2E-MARKER-$RANDOM$RANDOM"
LOG=$(mktemp)
[[ -f server/.dev.vars ]] || cp server/.dev.vars.example server/.dev.vars
(cd server && npm install --silent && npx wrangler dev --port 8787 >"$LOG" 2>&1) &
WRANGLER=$!
trap 'kill $WRANGLER 2>/dev/null; pkill -f "wrangler dev --port 8787" 2>/dev/null || true' EXIT
for _ in $(seq 1 90); do grep -q "Ready on" "$LOG" && break; sleep 2; done
cargo run -q -p snow-cli -- pair-test --messages "${MESSAGES:-5}" --marker "$MARKER"
if grep -q "$MARKER" "$LOG" || grep -rq "$MARKER" server/.wrangler/state 2>/dev/null; then
  echo "FAIL: plaintext marker reached the relay's logs or storage"; exit 1
fi
if grep -q "GET /room/" "$LOG"; then echo "FAIL: ticket appeared in a URL"; exit 1; fi
echo "blind-relay checks passed"
