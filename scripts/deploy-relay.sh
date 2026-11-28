#!/usr/bin/env bash
# Deploy the relay to the Cloudflare account wrangler is logged in to.
#
#   scripts/deploy-relay.sh        # first run: creates the R2 bucket and secrets
#
# Secrets (TICKET_KEY, POW_KEY, TOKEN_MASTER) are generated once into
# server/.secrets.prod.json (gitignored, mode 600). Back it up: TOKEN_MASTER is
# needed to sign remote configs that pin the token keys, and Cloudflare never
# shows secret values again. Rotating TICKET_KEY / POW_KEY only drops live
# chats; rotating TOKEN_MASTER invalidates everyone's tokens.
set -euo pipefail
cd "$(dirname "$0")/../server"
npx wrangler whoami >/dev/null 2>&1 || { echo "not logged in: run 'npx wrangler login' in server/"; exit 1; }
unset SNOW_BUILD_ARGS  # never ship the e2e test root

if ! npx wrangler r2 bucket list 2>/dev/null | grep -q "snow-talk-public"; then
  npx wrangler r2 bucket create snow-talk-public
fi

SECRETS=.secrets.prod.json
if [[ ! -f $SECRETS ]]; then
  umask 077
  printf '{"TICKET_KEY":"%s","POW_KEY":"%s","TOKEN_MASTER":"%s"}\n' \
    "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > "$SECRETS"
  echo "generated $SECRETS — back it up somewhere safe"
fi

OUT=$(npx wrangler deploy 2>&1) || { echo "$OUT"; exit 1; }
echo "$OUT" | grep -vE "^\s*$" | tail -n 12
npx wrangler secret bulk "$SECRETS" >/dev/null
URL=$(echo "$OUT" | grep -oE 'https://[a-z0-9.-]+\.workers\.dev' | head -n1)
echo "relay: $URL"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'x-snow-bucket: 255' "$URL/pow")
echo "GET /pow → $code"
[[ $code == 200 ]]
