use snow_proto::*;

fn rng() -> rand::rngs::OsRng {
    rand::rngs::OsRng
}

#[test]
fn every_frame_is_fixed_length_and_roundtrips() {
    let msgs = [
        ClientMsg::Leave,
        ClientMsg::Relay(vec![7; 10]),
        ClientMsg::Relay(vec![7; 3900]),
        ClientMsg::Join {
            pow: PowSolution {
                challenge: vec![1; 64],
                nonce: 42,
            },
            bucket: Some(3),
        },
    ];
    for m in msgs {
        let f = encode_frame(&m, &mut rng()).unwrap();
        assert_eq!(f.len(), FRAME_LEN);
        assert_eq!(decode_frame::<ClientMsg>(&f).unwrap(), m);
    }
}

#[test]
fn rejects_wrong_length_version_and_oversize() {
    assert_eq!(
        decode_frame::<ClientMsg>(&[1; 10]),
        Err(FrameError::BadLength(10))
    );
    let mut f = encode_frame(&ClientMsg::Leave, &mut rng()).unwrap();
    f[0] = 9;
    assert_eq!(
        decode_frame::<ClientMsg>(&f),
        Err(FrameError::BadVersion(9))
    );
    let big = ClientMsg::Relay(vec![0; FRAME_LEN]);
    assert!(matches!(
        encode_frame(&big, &mut rng()),
        Err(FrameError::TooLarge(_))
    ));
}

#[test]
fn inner_is_fixed_length_for_chaff_and_max_text() {
    let chaff = encode_inner(&Inner::Chaff).unwrap();
    let text = Inner::Text {
        id: u64::MAX,
        body: "字".repeat(MAX_TEXT_LEN / 3),
        ttl_secs: 30,
    };
    let t = encode_inner(&text).unwrap();
    assert_eq!(chaff.len(), INNER_LEN);
    assert_eq!(t.len(), INNER_LEN);
    assert_eq!(decode_inner(&t).unwrap(), text);
    assert_eq!(decode_inner(&chaff).unwrap(), Inner::Chaff);
    let too_long = Inner::Text {
        id: 1,
        body: "a".repeat(MAX_TEXT_LEN + 1),
        ttl_secs: 0,
    };
    assert_eq!(encode_inner(&too_long), Err(InnerError::TooLarge));
}
