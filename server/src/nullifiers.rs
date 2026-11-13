//! Spent-token registry: the only place a token's nullifier is recorded, so a
//! token can be spent once across every matchmaker shard.
//!
//! Sharded by `nf:{epoch}:{nullifier[0] % SHARDS}`. Each shard wipes itself once
//! its epoch's tokens can no longer be spent. A nullifier is a hash of the token
//! input; it says nothing about who spent it or what they did.
use crate::util::now_ms;
use worker::*;

pub const SHARDS: u8 = 8;

#[durable_object]
pub struct Nullifiers {
    state: State,
}

impl DurableObject for Nullifiers {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    /// `POST` postcard `Vec<[u8; 32]>` with `x-snow-epoch`. 200 = all were new
    /// and are now spent; 409 = at least one was already spent (none recorded).
    /// Durable Object input gates make the check-then-write atomic.
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let epoch: u64 = req
            .headers()
            .get("x-snow-epoch")?
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| Error::RustError("missing epoch".into()))?;
        let body = req.bytes().await?;
        let Ok(nfs) = postcard::from_bytes::<Vec<[u8; 32]>>(&body) else {
            return Response::error("bad request", 400);
        };
        let storage = self.state.storage();
        let keys: Vec<String> = nfs
            .iter()
            .map(|n| format!("n:{}", hex::encode(n)))
            .collect();
        for k in &keys {
            if storage.get::<u8>(k).await?.is_some() {
                return Response::error("spent", 409);
            }
        }
        for k in &keys {
            storage.put(k, 1u8).await?;
        }
        if storage.get_alarm().await?.is_none() {
            // Tokens of `epoch` are spendable through epoch + 1.
            let expires_ms = (epoch + 2) * snow_tokens::EPOCH_SECS * 1000;
            let delay = expires_ms.saturating_sub(now_ms()).max(60_000) as i64;
            storage.set_alarm(delay).await?;
        }
        Response::ok("ok")
    }

    async fn alarm(&self) -> Result<Response> {
        self.state.storage().delete_all().await?;
        Response::empty()
    }
}
