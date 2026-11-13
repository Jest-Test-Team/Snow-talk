//! `POST /tokens/vip`: exchange one store purchase for blind VIP tokens.
//!
//! The purchase proof is verified (see `iap`), the tokens are evaluated blind
//! (VOPRF), and the purchase is recorded in the `Redemptions` registry under a
//! hash of its transaction ID together with a hash of the blinded elements, so
//! a lost response can be retried with the same request but a second, different
//! request for the same purchase is refused.
use crate::iap::{self, Policy};
use crate::util::*;
use sha2::{Digest, Sha256};
use snow_proto::{Store, VipRefusal, VipRequest, VipResponse};
use snow_tokens::{Issuer, Kind, MAX_BATCH};
use worker::*;

const MAX_BODY: usize = 32 * 1024;

pub async fn handle(mut req: Request, env: &Env) -> Result<Response> {
    let body = req.bytes().await?;
    if body.len() > MAX_BODY {
        return Response::error("too large", 413);
    }
    let Ok(r) = postcard::from_bytes::<VipRequest>(&body) else {
        return Response::error("bad request", 400);
    };
    let resp = decide(&r, env).await?;
    let headers = Headers::new();
    headers.set("content-type", "application/octet-stream")?;
    headers.set("cache-control", "no-store")?;
    let bytes = postcard::to_allocvec(&resp).map_err(|e| Error::RustError(e.to_string()))?;
    Ok(Response::from_bytes(bytes)?.with_headers(headers))
}

fn var(env: &Env, name: &str) -> String {
    env.var(name).map(|v| v.to_string()).unwrap_or_default()
}

fn verify(proof: &str, env: &Env) -> std::result::Result<iap::Transaction, iap::IapError> {
    // Test builds only (`--features e2e-test-root`): a test root from the
    // environment. Release builds can only ever trust Apple's root.
    #[cfg(feature = "e2e-test-root")]
    if let Ok(root) = env.var("APPLE_TEST_ROOT") {
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD
            .decode(root.to_string())
            .map_err(|_| iap::IapError::Malformed)?;
        return iap::verify_apple(proof, &der);
    }
    let _ = env;
    iap::verify_apple(proof, iap::APPLE_ROOT_G3)
}

async fn decide(r: &VipRequest, env: &Env) -> Result<VipResponse> {
    use VipResponse::Refused;
    if r.store != Store::Apple {
        return Ok(Refused(VipRefusal::Unsupported));
    }
    let now_epoch = snow_tokens::epoch(now_secs());
    if !(r.epoch == now_epoch || r.epoch + 1 == now_epoch) {
        return Ok(Refused(VipRefusal::Invalid));
    }
    let Ok(tx) = verify(&r.proof, env) else {
        return Ok(Refused(VipRefusal::Invalid));
    };
    let bundle = var(env, "APPLE_BUNDLE_ID");
    let products = var(env, "APPLE_PRODUCTS");
    let policy = Policy {
        bundle_id: &bundle,
        products: Policy::parse_products(&products),
        allow_sandbox: var(env, "APPLE_SANDBOX") == "true",
    };
    let n = match policy.grant(&tx) {
        Ok(n) if n as usize <= MAX_BATCH && n as usize <= r.blinded.len() => n as usize,
        _ => return Ok(Refused(VipRefusal::NotEligible)),
    };
    let blinded = &r.blinded[..n];
    let issuer = Issuer::new(&secret(env, "TOKEN_MASTER")?, Kind::Vip, r.epoch)
        .map_err(|e| Error::RustError(e.to_string()))?;
    let Ok((evaluated, proof)) = issuer.issue(blinded, random_bytes()) else {
        return Ok(Refused(VipRefusal::Invalid));
    };
    // Record the redemption only once everything else has succeeded.
    let key = iap::redemption_key("apple", &tx.transaction_id);
    let mut h = Sha256::new();
    for b in blinded {
        h.update(b);
    }
    let req_hash: [u8; 32] = h.finalize().into();
    let stub = env
        .durable_object("REDEMPTIONS")?
        .id_from_name(&format!("iap:{}", &key[..2]))?
        .get_stub()?;
    let headers = Headers::new();
    headers.set("x-snow-key", &key)?;
    let req = Request::new_with_init(
        "https://redemptions/",
        RequestInit::new()
            .with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(js_sys::Uint8Array::from(&req_hash[..]).into())),
    )?;
    if stub.fetch_with_request(req).await?.status_code() != 200 {
        return Ok(Refused(VipRefusal::AlreadyRedeemed));
    }
    event("vip_issued");
    Ok(VipResponse::Tokens {
        epoch: r.epoch,
        public_key: issuer.public_key(),
        evaluated,
        proof: [
            proof[..32].try_into().expect("64"),
            proof[32..].try_into().expect("64"),
        ],
    })
}

/// Purchases already exchanged for tokens: `hash(transaction id) → hash(blinded)`.
/// Kept forever (a store proof never expires); holds no IDs or tokens.
#[durable_object]
pub struct Redemptions {
    state: State,
}

impl DurableObject for Redemptions {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    /// 200 = new (now recorded) or the same request again; 409 = redeemed
    /// before with different blinded elements.
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let key = req
            .headers()
            .get("x-snow-key")?
            .filter(|k| k.len() == 64)
            .ok_or_else(|| Error::RustError("missing key".into()))?;
        let hash = req.bytes().await?;
        let st = self.state.storage();
        match st.get::<Vec<u8>>(&key).await? {
            None => {
                st.put(&key, hash).await?;
                Response::empty()
            }
            Some(h) if h == hash => Response::empty(),
            Some(_) => Response::error("already redeemed", 409),
        }
    }
}
