//! Spent-token registry: the only place a token's nullifier is recorded, so a
//! token can be spent once across every matchmaker shard.
//!
//! Sharded by `nf:{epoch}:{nullifier[0] % SHARDS}`. Each shard wipes itself once
//! its epoch's tokens can no longer be spent. A nullifier is a hash of the token
//! input; it says nothing about who spent it or what they did.
use crate::util::{event, now_ms, now_secs, secret};
use snow_tokens::{Issuer, Kind, Token};
use std::collections::BTreeMap;
use worker::*;

pub const SHARDS: u8 = 8;

/// Verify `need` tokens of `kind` among `spend` and burn their nullifiers.
/// `false` if there aren't enough genuine, current, unspent ones. Tokens are
/// unlinkable, so this learns only "holds N tokens", never whose.
pub async fn redeem(env: &Env, spend: &[Vec<u8>], kind: Kind, need: usize) -> Result<bool> {
    let now_epoch = snow_tokens::epoch(now_secs());
    let mut toks: Vec<Token> = spend
        .iter()
        .filter_map(|b| postcard::from_bytes::<Token>(b).ok())
        .filter(|t| t.kind == kind)
        .collect();
    toks.dedup_by_key(|t| t.nullifier());
    if need == 0 || toks.len() < need {
        return Ok(false);
    }
    toks.truncate(need);
    let master = secret(env, "TOKEN_MASTER")?;
    let mut groups: BTreeMap<(u32, u8), Vec<[u8; 32]>> = BTreeMap::new();
    for t in &toks {
        let ok = snow_tokens::is_current(t.epoch, now_epoch)
            && Issuer::new(&master, kind, t.epoch).is_ok_and(|i| i.verify(t));
        if !ok {
            return Ok(false);
        }
        let nf = t.nullifier();
        let g = groups.entry((t.epoch, nf[0] % SHARDS)).or_default();
        if g.contains(&nf) {
            return Ok(false);
        }
        g.push(nf);
    }
    // Rare partial failure (a double-spend attempt) leaves earlier groups
    // spent; that only hurts the cheater.
    let ns = env.durable_object("NULLIFIERS")?;
    for ((epoch, shard), nfs) in groups {
        let stub = ns
            .id_from_name(&format!("nf:{epoch}:{shard}"))?
            .get_stub()?;
        let headers = Headers::new();
        headers.set("x-snow-epoch", &epoch.to_string())?;
        let body = postcard::to_allocvec(&nfs).map_err(|e| Error::RustError(e.to_string()))?;
        let req = Request::new_with_init(
            "https://nullifiers/",
            RequestInit::new()
                .with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(js_sys::Uint8Array::from(&body[..]).into())),
        )?;
        if stub.fetch_with_request(req).await?.status_code() != 200 {
            return Ok(false);
        }
    }
    event("tokens_redeemed");
    Ok(true)
}

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
