//! In-app purchase proofs → VIP token grants. Pure logic (no Workers APIs), so
//! it is unit-testable natively.
//!
//! **App Store** (StoreKit 2): the app sends the transaction's
//! `jwsRepresentation`. It is verified offline, the way Apple's own server
//! library does it: the `x5c` chain must end in the pinned Apple Root CA - G3,
//! carry Apple's leaf / intermediate marker OIDs and be valid at the
//! transaction's `signedDate`; the leaf key must verify the ES256 signature.
//! No App Store Server API credentials are needed for this.
//!
//! **Google Play** needs the Play Developer API (service-account credentials)
//! and is not implemented yet.
//!
//! Privacy: the server sees one transaction (Apple can link that to an Apple
//! ID). It stores only a hash of the transaction ID, to refuse a second
//! redemption. The VIP tokens it signs are blind, so spending them later can't
//! be linked back to the purchase.
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

/// Apple Root CA - G3, from https://www.apple.com/certificateauthority/.
/// SHA-256 63343abf b89a6a03 ebb57e9b 3f5fa7be 7c4f5c75 6f3017b3 a8c488c3 653e9179.
pub const APPLE_ROOT_G3: &[u8] = include_bytes!("../certs/AppleRootCA-G3.cer");

/// Marks a leaf certificate as an App Store receipt-signing certificate.
const OID_APPLE_LEAF: &str = "1.2.840.113635.100.6.11.1";
/// Marks the Apple Worldwide Developer Relations intermediate.
const OID_APPLE_INTERMEDIATE: &str = "1.2.840.113635.100.6.2.1";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";

#[derive(Debug, PartialEq, Eq)]
pub enum IapError {
    Malformed,
    UntrustedChain,
    BadSignature,
    /// Wrong app, unknown product, wrong environment, not a consumable, or refunded.
    NotEligible,
}

/// The fields of Apple's `JWSTransactionDecodedPayload` we use.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub transaction_id: String,
    pub bundle_id: String,
    pub product_id: String,
    #[serde(default = "one")]
    pub quantity: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub environment: String,
    pub signed_date: u64,
    #[serde(default)]
    pub revocation_date: Option<u64>,
}
fn one() -> u32 {
    1
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    x5c: Vec<String>,
}

/// Verify a StoreKit 2 signed transaction against `root_der`.
pub fn verify_apple(jws: &str, root_der: &[u8]) -> Result<Transaction, IapError> {
    let mut parts = jws.split('.');
    let (Some(h64), Some(p64), Some(s64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(IapError::Malformed);
    };
    let b64 = |s: &str| URL_SAFE_NO_PAD.decode(s).map_err(|_| IapError::Malformed);
    let header: Header = serde_json::from_slice(&b64(h64)?).map_err(|_| IapError::Malformed)?;
    let tx: Transaction = serde_json::from_slice(&b64(p64)?).map_err(|_| IapError::Malformed)?;
    if header.alg != "ES256" || header.x5c.len() != 3 {
        return Err(IapError::Malformed);
    }
    let ders = header
        .x5c
        .iter()
        .map(|c| STANDARD.decode(c).map_err(|_| IapError::Malformed))
        .collect::<Result<Vec<_>, _>>()?;
    if ders[2] != root_der {
        return Err(IapError::UntrustedChain);
    }
    let certs = ders
        .iter()
        .map(|d| Certificate::from_der(d).map_err(|_| IapError::Malformed))
        .collect::<Result<Vec<_>, _>>()?;
    let (leaf, inter, root) = (&certs[0], &certs[1], &certs[2]);
    // Apple's library checks the chain as of the signing date, so receipts stay
    // verifiable after the leaf certificate expires.
    let at = tx.signed_date / 1000;
    for c in &certs {
        if !valid_at(c, at) {
            return Err(IapError::UntrustedChain);
        }
    }
    if !has_ext(leaf, OID_APPLE_LEAF) || !has_ext(inter, OID_APPLE_INTERMEDIATE) {
        return Err(IapError::UntrustedChain);
    }
    verify_cert(inter, root)?;
    verify_cert(leaf, inter)?;

    use p256::ecdsa::signature::Verifier;
    let leaf_key = spki_key(leaf)?;
    let SpkiKey::P256(key) = leaf_key else {
        return Err(IapError::UntrustedChain);
    };
    let sig = p256::ecdsa::Signature::from_slice(&b64(s64)?).map_err(|_| IapError::Malformed)?;
    let signed = &jws[..h64.len() + 1 + p64.len()];
    key.verify(signed.as_bytes(), &sig)
        .map_err(|_| IapError::BadSignature)?;
    Ok(tx)
}

/// What the operator sells: `APPLE_PRODUCTS = "vip_5:5,vip_15:15"`.
pub struct Policy<'a> {
    pub bundle_id: &'a str,
    /// `(product id, VIP tokens per unit)`.
    pub products: Vec<(&'a str, u32)>,
    /// Accept sandbox purchases (TestFlight / development).
    pub allow_sandbox: bool,
}

impl<'a> Policy<'a> {
    pub fn parse_products(spec: &'a str) -> Vec<(&'a str, u32)> {
        spec.split(',')
            .filter_map(|p| {
                let (id, n) = p.trim().split_once(':')?;
                Some((id, n.parse().ok()?))
            })
            .collect()
    }

    /// VIP tokens this transaction buys.
    pub fn grant(&self, tx: &Transaction) -> Result<u32, IapError> {
        let env_ok =
            tx.environment == "Production" || (self.allow_sandbox && tx.environment == "Sandbox");
        let per = self
            .products
            .iter()
            .find(|(id, _)| *id == tx.product_id)
            .map(|(_, n)| *n);
        match per {
            Some(n)
                if tx.bundle_id == self.bundle_id
                    && env_ok
                    && tx.kind == "Consumable"
                    && tx.revocation_date.is_none() =>
            {
                Ok(n.saturating_mul(tx.quantity.max(1)))
            }
            _ => Err(IapError::NotEligible),
        }
    }
}

/// Key under which a redeemed transaction is remembered (no raw IDs stored).
pub fn redemption_key(store: &str, transaction_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"snowtalk-iap-v1\0");
    h.update(store.as_bytes());
    h.update([0]);
    h.update(transaction_id.as_bytes());
    hex::encode(h.finalize())
}

fn valid_at(c: &Certificate, unix: u64) -> bool {
    let v = &c.tbs_certificate.validity;
    let nb = v.not_before.to_unix_duration().as_secs();
    let na = v.not_after.to_unix_duration().as_secs();
    nb <= unix && unix <= na
}

fn has_ext(c: &Certificate, oid: &str) -> bool {
    c.tbs_certificate
        .extensions
        .as_ref()
        .is_some_and(|exts| exts.iter().any(|e| e.extn_id.to_string() == oid))
}

enum SpkiKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

fn spki_key(c: &Certificate) -> Result<SpkiKey, IapError> {
    let spki = &c.tbs_certificate.subject_public_key_info;
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<x509_cert::der::asn1::ObjectIdentifier>().ok())
        .map(|o| o.to_string())
        .ok_or(IapError::Malformed)?;
    let point = spki.subject_public_key.raw_bytes();
    match curve.as_str() {
        OID_P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map(SpkiKey::P256)
            .map_err(|_| IapError::Malformed),
        OID_P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map(SpkiKey::P384)
            .map_err(|_| IapError::Malformed),
        _ => Err(IapError::UntrustedChain),
    }
}

/// `cert` must be signed by `issuer`'s key (and name `issuer` as its issuer).
fn verify_cert(cert: &Certificate, issuer: &Certificate) -> Result<(), IapError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(IapError::UntrustedChain);
    }
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|_| IapError::Malformed)?;
    let digest = match cert.signature_algorithm.oid.to_string().as_str() {
        OID_ECDSA_SHA256 => Sha256::digest(&tbs).to_vec(),
        OID_ECDSA_SHA384 => Sha384::digest(&tbs).to_vec(),
        _ => return Err(IapError::UntrustedChain),
    };
    let sig = cert.signature.raw_bytes();
    let ok = match spki_key(issuer)? {
        SpkiKey::P256(k) => p256::ecdsa::Signature::from_der(sig)
            .is_ok_and(|s| k.verify_prehash(&digest, &s).is_ok()),
        SpkiKey::P384(k) => p384::ecdsa::Signature::from_der(sig)
            .is_ok_and(|s| k.verify_prehash(&digest, &s).is_ok()),
    };
    ok.then_some(()).ok_or(IapError::UntrustedChain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, IsCa, Issuer, KeyPair,
        PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
    };

    struct Chain {
        root: Vec<u8>,
        x5c: Vec<String>,
        leaf_key: KeyPair,
    }

    fn ca(name: &str, ext: Option<&[u64]>) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, name);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        if let Some(oid) = ext {
            p.custom_extensions
                .push(CustomExtension::from_oid_content(oid, vec![5, 0]));
        }
        p
    }

    /// A chain shaped like Apple's: P-384 root and intermediate, P-256 leaf.
    fn chain(leaf_oid: bool) -> Chain {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let root_params = ca("Test Root", None);
        let root = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::from_params(&root_params, &root_key);
        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let inter_params = ca("Test WWDR", Some(&[1, 2, 840, 113635, 100, 6, 2, 1]));
        let inter = inter_params.signed_by(&inter_key, &root_issuer).unwrap();
        let inter_issuer = Issuer::from_params(&inter_params, &inter_key);
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut lp = ca(
            "Test Leaf",
            leaf_oid.then_some(&[1, 2, 840, 113635, 100, 6, 11, 1][..]),
        );
        lp.is_ca = IsCa::NoCa;
        let leaf = lp.signed_by(&leaf_key, &inter_issuer).unwrap();
        Chain {
            root: root.der().to_vec(),
            x5c: [leaf.der(), inter.der(), root.der()]
                .iter()
                .map(|d| STANDARD.encode(d))
                .collect(),
            leaf_key,
        }
    }

    fn payload(env: &str, revoked: bool) -> String {
        let now = 1_794_000_000_000u64;
        let rev = if revoked {
            format!(",\"revocationDate\":{now}")
        } else {
            String::new()
        };
        format!(
            r#"{{"transactionId":"2000000123","originalTransactionId":"2000000123","bundleId":"app.snowtalk.ios","productId":"vip_5","purchaseDate":{now},"quantity":2,"type":"Consumable","environment":"{env}","signedDate":{now}{rev}}}"#
        )
    }

    fn sign(c: &Chain, payload: &str) -> String {
        use p256::ecdsa::signature::Signer;
        use p256::pkcs8::DecodePrivateKey;
        let header = serde_json::json!({ "alg": "ES256", "x5c": c.x5c }).to_string();
        let msg = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let sk = p256::ecdsa::SigningKey::from_pkcs8_der(&c.leaf_key.serialize_der()).unwrap();
        let sig: p256::ecdsa::Signature = sk.sign(msg.as_bytes());
        format!("{msg}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn policy() -> Policy<'static> {
        Policy {
            bundle_id: "app.snowtalk.ios",
            products: Policy::parse_products("vip_5:5, vip_15:15"),
            allow_sandbox: false,
        }
    }

    #[test]
    fn genuine_transaction_grants_tokens() {
        let c = chain(true);
        let tx = verify_apple(&sign(&c, &payload("Production", false)), &c.root).unwrap();
        assert_eq!(tx.transaction_id, "2000000123");
        assert_eq!(policy().grant(&tx), Ok(10), "5 per unit × quantity 2");
    }

    #[test]
    fn forgeries_are_refused() {
        let c = chain(true);
        let jws = sign(&c, &payload("Production", false));
        // Someone else's root (e.g. the real Apple root vs. a self-made chain).
        assert_eq!(
            verify_apple(&jws, APPLE_ROOT_G3),
            Err(IapError::UntrustedChain)
        );
        // Payload swapped after signing.
        let mut parts: Vec<&str> = jws.split('.').collect();
        let forged =
            URL_SAFE_NO_PAD.encode(payload("Production", false).replace("vip_5", "vip_15"));
        parts[1] = &forged;
        assert_eq!(
            verify_apple(&parts.join("."), &c.root),
            Err(IapError::BadSignature)
        );
        // A leaf without Apple's receipt-signing marker.
        let c2 = chain(false);
        assert_eq!(
            verify_apple(&sign(&c2, &payload("Production", false)), &c2.root),
            Err(IapError::UntrustedChain)
        );
        // Leaf from a different chain spliced onto ours.
        let mut spliced = chain(true);
        spliced.x5c[1] = c.x5c[1].clone();
        spliced.x5c[2] = c.x5c[2].clone();
        assert_eq!(
            verify_apple(&sign(&spliced, &payload("Production", false)), &c.root),
            Err(IapError::UntrustedChain)
        );
        assert_eq!(verify_apple("a.b", &c.root), Err(IapError::Malformed));
    }

    #[test]
    fn policy_checks() {
        let c = chain(true);
        let sandbox = verify_apple(&sign(&c, &payload("Sandbox", false)), &c.root).unwrap();
        assert_eq!(policy().grant(&sandbox), Err(IapError::NotEligible));
        let mut p = policy();
        p.allow_sandbox = true;
        assert_eq!(p.grant(&sandbox), Ok(10));
        let refunded = verify_apple(&sign(&c, &payload("Production", true)), &c.root).unwrap();
        assert_eq!(policy().grant(&refunded), Err(IapError::NotEligible));
        let mut other = refunded.clone();
        other.revocation_date = None;
        other.bundle_id = "com.example.other".into();
        assert_eq!(policy().grant(&other), Err(IapError::NotEligible));
        other.bundle_id = "app.snowtalk.ios".into();
        other.product_id = "unknown".into();
        assert_eq!(policy().grant(&other), Err(IapError::NotEligible));
        assert_ne!(redemption_key("apple", "1"), redemption_key("google", "1"));
    }

    #[test]
    fn pinned_root_is_apple_g3() {
        let h = Sha256::digest(APPLE_ROOT_G3);
        assert_eq!(
            hex::encode(h),
            "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"
        );
        let root = Certificate::from_der(APPLE_ROOT_G3).unwrap();
        assert!(matches!(spki_key(&root), Ok(SpkiKey::P384(_))));
    }
}
