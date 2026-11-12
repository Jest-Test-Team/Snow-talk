use snow_crypto::*;
use snow_proto::{Handshake, Inner, PeerEnvelope, Role};

/// Run the full handshake in memory, optionally letting `tamper` rewrite the
/// responder's reveal on its way to the initiator.
fn pair() -> (ChatSession, ChatSession) {
    let (mut a, ca) = Handshaker::new(Role::Initiator);
    let (mut b, cb) = Handshaker::new(Role::Responder);
    let Step::Send(ra) = a.on_message(cb).unwrap() else {
        panic!()
    };
    let Step::Send(rb) = b.on_message(ca).unwrap() else {
        panic!()
    };
    assert!(matches!(b.on_message(ra).unwrap(), Step::AwaitPreKey));
    let Step::Established { session: sa, first } = a.on_message(rb).unwrap() else {
        panic!()
    };
    let (sb, inner) = b.accept(&first).unwrap();
    assert_eq!(inner, Inner::Ready);
    (*sa, sb)
}

fn text(id: u64, s: &str) -> Inner {
    Inner::Text {
        id,
        body: s.into(),
        ttl_secs: 0,
    }
}

#[test]
fn handshake_then_bidirectional_chat_with_matching_sas() {
    let (mut a, mut b) = pair();
    assert_eq!(a.sas(), b.sas());
    for i in 0..5 {
        let e = a.encrypt(&text(i, "哈囉")).unwrap();
        assert_eq!(b.decrypt(&e).unwrap(), text(i, "哈囉"));
        let e = b.encrypt(&text(i, "hi")).unwrap();
        assert_eq!(a.decrypt(&e).unwrap(), text(i, "hi"));
    }
}

#[test]
fn out_of_order_and_replay() {
    let (mut a, mut b) = pair();
    let e: Vec<_> = (0..3).map(|i| a.encrypt(&text(i, "x")).unwrap()).collect();
    assert_eq!(b.decrypt(&e[2]).unwrap(), text(2, "x"));
    assert_eq!(b.decrypt(&e[0]).unwrap(), text(0, "x"));
    assert_eq!(b.decrypt(&e[1]).unwrap(), text(1, "x"));
    assert_eq!(
        b.decrypt(&e[1]),
        Err(CryptoError::Decrypt),
        "replay must fail"
    );
}

#[test]
fn chaff_and_text_ciphertexts_have_equal_length() {
    let (mut a, mut b) = pair();
    // Get past the pre-key phase.
    let r = b.encrypt(&Inner::Chaff).unwrap();
    a.decrypt(&r).unwrap();
    let len = |e: &PeerEnvelope| match e {
        PeerEnvelope::Olm { body, .. } => body.len(),
        _ => unreachable!(),
    };
    let c = a.encrypt(&Inner::Chaff).unwrap();
    let t = a.encrypt(&text(1, &"長".repeat(900))).unwrap();
    assert_eq!(len(&c), len(&t));
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let (mut a, mut b) = pair();
    let PeerEnvelope::Olm { kind, mut body } = a.encrypt(&text(1, "x")).unwrap() else {
        panic!()
    };
    let n = body.len();
    body[n - 20] ^= 1;
    assert_eq!(
        b.decrypt(&PeerEnvelope::Olm { kind, body }),
        Err(CryptoError::Decrypt)
    );
}

#[test]
fn reveal_not_matching_commit_is_rejected() {
    let (mut a, ca) = Handshaker::new(Role::Initiator);
    let (mut b, cb) = Handshaker::new(Role::Responder);
    let Step::Send(_) = a.on_message(cb).unwrap() else {
        panic!()
    };
    let Step::Send(Handshake::Reveal {
        identity_key,
        one_time_key,
        ..
    }) = b.on_message(ca).unwrap()
    else {
        panic!()
    };
    // A MITM swaps in its own nonce/keys after the commit was fixed.
    let forged = Handshake::Reveal {
        identity_key,
        one_time_key,
        nonce: [0; 32],
    };
    assert!(matches!(
        a.on_message(forged),
        Err(CryptoError::CommitMismatch)
    ));
}

#[test]
fn out_of_order_handshake_is_rejected() {
    let (mut a, _) = Handshaker::new(Role::Initiator);
    let bogus = Handshake::Reveal {
        identity_key: [1; 32],
        one_time_key: Some([2; 32]),
        nonce: [3; 32],
    };
    assert!(matches!(
        a.on_message(bogus),
        Err(CryptoError::UnexpectedMessage)
    ));
}

#[test]
fn mitm_with_own_keys_yields_different_sas() {
    // The relay runs two separate handshakes: A↔M and M↔B.
    let (sa, _sm1) = pair();
    let (_sm2, sb) = pair();
    assert_ne!(sa.sas(), sb.sas());
}

#[test]
fn largest_prekey_ciphertext_fits_in_a_frame() {
    use snow_proto::{encode_frame, ClientMsg, MAX_TEXT_LEN};
    let (mut a, _b) = pair();
    // Still in the pre-key phase (b never replied), so this is the largest message type.
    let env = a
        .encrypt(&text(u64::MAX, &"a".repeat(MAX_TEXT_LEN)))
        .unwrap();
    assert!(matches!(env, PeerEnvelope::Olm { kind: 0, .. }));
    let relay = postcard::to_allocvec(&env).unwrap();
    let frame = encode_frame(&ClientMsg::Relay(relay), &mut rand::rngs::OsRng).unwrap();
    assert_eq!(frame.len(), snow_proto::FRAME_LEN);
}
