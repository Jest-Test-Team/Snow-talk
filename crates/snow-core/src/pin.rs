//! Certificate pinning on top of normal WebPKI validation.
//!
//! Pins are base64 SHA-256 hashes of a certificate's SubjectPublicKeyInfo (the
//! HPKP format: `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der |
//! openssl dgst -sha256 -binary | base64`). The chain must validate normally, and
//! at least one certificate in it (leaf or intermediate) must match a pin. Pin
//! the issuing CA keys plus a backup so routine leaf rotation doesn't brick the app.
use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub fn parse_pins(pins: &[String]) -> Vec<[u8; 32]> {
    pins.iter()
        .filter_map(|p| {
            base64::engine::general_purpose::STANDARD
                .decode(p.trim())
                .ok()
        })
        .filter_map(|v| <[u8; 32]>::try_from(v).ok())
        .collect()
}

pub fn spki_sha256(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let parsed = webpki::EndEntityCert::try_from(cert).ok()?;
    Some(Sha256::digest(parsed.subject_public_key_info().as_ref()).into())
}

pub fn chain_matches(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    pins: &[[u8; 32]],
) -> bool {
    std::iter::once(end_entity)
        .chain(intermediates)
        .filter_map(spki_sha256)
        .any(|h| pins.contains(&h))
}

#[derive(Debug)]
pub struct PinnedVerifier {
    pub inner: Arc<WebPkiServerVerifier>,
    pub pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        if chain_matches(end_entity, intermediates, &self.pins) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert() -> (CertificateDer<'static>, [u8; 32]) {
        let c = rcgen::generate_simple_self_signed(vec!["relay.test".into()]).unwrap();
        let spki = Sha256::digest(rcgen::PublicKeyData::subject_public_key_info(
            &c.signing_key,
        ))
        .into();
        (c.cert.der().clone(), spki)
    }

    #[test]
    fn matches_leaf_or_intermediate_only_when_pinned() {
        let (leaf, leaf_pin) = cert();
        let (ca, ca_pin) = cert();
        assert!(chain_matches(&leaf, &[], &[leaf_pin]));
        assert!(chain_matches(&leaf, std::slice::from_ref(&ca), &[ca_pin]));
        assert!(!chain_matches(&leaf, &[ca], &[[0; 32]]));
    }

    #[test]
    fn pin_parsing_ignores_garbage() {
        let good = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let pins = parse_pins(&[good, "not base64!".into(), "AAAA".into()]);
        assert_eq!(pins, vec![[7u8; 32]]);
    }
}
