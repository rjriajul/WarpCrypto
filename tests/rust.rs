// Known answers below were generated independently with Python's `cryptography` and `hashlib`.
use sha2::{Digest, Sha256};
use warpcrypto::{Error, Message};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn range<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start + i as u8)
}

fn auth_key() -> [u8; 256] {
    std::array::from_fn(|i| (i * 7 % 256) as u8)
}

const AKID: [u8; 8] = [0x60, 0xdd, 0x29, 0x72, 0x97, 0x02, 0x71, 0x2e];

#[test]
fn ige_known_answer() {
    let (key, iv) = (range::<32>(0), range::<32>(32));
    let mut data = range::<64>(0);
    warpcrypto::ige256_encrypt(&mut data, &key, &iv).unwrap();
    assert_eq!(data.to_vec(), hex("42e66e1a756cccf5b27acc47523ad074ee39bf54e3db37bbdf415df6b400fca977f708327c9e9341cc3dc8efd31e76463daa65b1f0d0252f790d77f1824a662c"));
    warpcrypto::ige256_decrypt(&mut data, &key, &iv).unwrap();
    assert_eq!(data, range::<64>(0));
}

#[test]
fn ige_rejects_partial_block() {
    for len in [1, 15, 17, 31] {
        let mut data = vec![0u8; len];
        assert_eq!(warpcrypto::ige256_encrypt(&mut data, &[0; 32], &[0; 32]), Err(Error::NotBlockAligned));
        assert_eq!(warpcrypto::ige256_decrypt(&mut data, &[0; 32], &[0; 32]), Err(Error::NotBlockAligned));
    }
    warpcrypto::ige256_encrypt(&mut [], &[0; 32], &[0; 32]).unwrap();
}

#[test]
fn ctr_known_answer() {
    let expected = hex("5a6f06540cfe7791f8275f360ecea89d70e202c6d7904e4a4d0fe14a6ef83ed03c4455781ee0ea8393c8218ec93ce9bda6fa");
    let key = range::<32>(0);
    let mut data = range::<50>(0);
    let (mut iv, mut state) = (range::<16>(0), 0);
    warpcrypto::ctr256(&mut data, &key, &mut iv, &mut state);
    assert_eq!(data.to_vec(), expected);
    // 50 bytes = 3 full blocks + 2 bytes into the 4th
    assert_eq!((u128::from_be_bytes(iv), state), (u128::from_be_bytes(range::<16>(0)) + 3, 2));
}

#[test]
fn ctr_split_matches_one_shot() {
    let key = range::<32>(9);
    let plain: Vec<u8> = (0..5000u32).map(|i| (i * 31) as u8).collect();
    let mut whole = plain.clone();
    let (mut iv, mut state) = (range::<16>(3), 0);
    warpcrypto::ctr256(&mut whole, &key, &mut iv, &mut state);

    let mut parts = plain.clone();
    let (mut iv, mut state) = (range::<16>(3), 0);
    let mut at = 0;
    for step in [7, 1, 16, 33, 2500, 9, 0, 2434] {
        warpcrypto::ctr256(&mut parts[at..at + step], &key, &mut iv, &mut state);
        at += step;
    }
    assert_eq!(at, plain.len());
    assert_eq!(parts, whole);
}

#[test]
fn ctr_bad_state_is_treated_as_zero() {
    let key = range::<32>(0);
    let (mut a, mut b) = ([1u8; 40], [1u8; 40]);
    warpcrypto::ctr256(&mut a, &key, &mut range::<16>(0), &mut 0);
    warpcrypto::ctr256(&mut b, &key, &mut range::<16>(0), &mut 200);
    assert_eq!(a, b);
}

#[test]
fn kdf_known_answer() {
    let (ak, mk) = (auth_key(), range::<16>(0));
    let (k, iv) = warpcrypto::kdf(&ak, &mk, true);
    assert_eq!(k.to_vec(), hex("3a9d065301d7eddf6ed875fe8c309d9c686b81216cd601efeb4092ff95c856d2"));
    assert_eq!(iv.to_vec(), hex("c7f9766b463380b6625a23a8027b4a6da6584fb8332635d6d9f4f8b2f4bc5b9d"));
    let (k, iv) = warpcrypto::kdf(&ak, &mk, false);
    assert_eq!(k.to_vec(), hex("f32d73632ba87eebd076729540ffdee2c53208afeae558ca741781e1ac3431ff"));
    assert_eq!(iv.to_vec(), hex("0d04f2c1a632120c06f6d5bc0625c70f3d51d58845470bfb0365352dbacfc486"));
}

#[test]
fn unpack_known_server_message() {
    let packet = hex("60dd29729702712e58576321064f59638fbd04ec085d34c0947be68b2f595378e90e1fdcfa8f44db065a25c3525455d81577a7e83b8b322a8be0218049257a33de0a90a628e83baa80d9fab6af5fe620de56b16422dc1e30");
    let msg = warpcrypto::unpack_message(&packet, &auth_key(), &AKID, &range::<8>(100), true).unwrap();
    assert_eq!(msg, Message { msg_id: 0x1234567801, seq_no: 5, body: b"hello, server!!!".to_vec() });
}

#[test]
fn pack_unpack_roundtrip() {
    let (ak, sid) = (auth_key(), range::<8>(100));
    for len in [0, 4, 16, 100, 1000, 70000] {
        let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let packed = warpcrypto::pack_message(&ak, &AKID, &sid, 77, 1 << 40, 9, &body);
        assert_eq!(&packed[..8], &AKID);
        assert_eq!((packed.len() - 24) % 16, 0);
        let msg = warpcrypto::unpack_message(&packed, &ak, &AKID, &sid, false).unwrap();
        assert_eq!(msg, Message { msg_id: 1 << 40, seq_no: 9, body });
        // client messages use x=0, so reading them as server messages must fail
        assert_eq!(warpcrypto::unpack_message(&packed, &ak, &AKID, &sid, true), Err(Error::MsgKeyMismatch));
    }
}

#[test]
fn pack_padding_is_random() {
    let (ak, sid) = (auth_key(), range::<8>(100));
    let a = warpcrypto::pack_message(&ak, &AKID, &sid, 1, 2, 3, b"same");
    let b = warpcrypto::pack_message(&ak, &AKID, &sid, 1, 2, 3, b"same");
    assert_ne!(a, b);
}

/// Builds a server→client message with a valid msg_key, so only the later checks can reject it.
fn server_packet(sid: &[u8; 8], declared_len: i32, body: &[u8], pad: usize) -> Vec<u8> {
    let ak = auth_key();
    let mut plain = Vec::new();
    plain.extend_from_slice(&1i64.to_le_bytes());
    plain.extend_from_slice(sid);
    plain.extend_from_slice(&99i64.to_le_bytes());
    plain.extend_from_slice(&3i32.to_le_bytes());
    plain.extend_from_slice(&declared_len.to_le_bytes());
    plain.extend_from_slice(body);
    plain.extend(std::iter::repeat_n(0xab, pad));
    assert_eq!(plain.len() % 16, 0);
    let msg_key: [u8; 16] = Sha256::new().chain_update(&ak[96..128]).chain_update(&plain).finalize()[8..24].try_into().unwrap();
    let (key, iv) = warpcrypto::kdf(&ak, &msg_key, false);
    warpcrypto::ige256_encrypt(&mut plain, &key, &iv).unwrap();
    [&AKID[..], &msg_key, &plain].concat()
}

fn unpack(packet: &[u8]) -> Result<Message, Error> {
    warpcrypto::unpack_message(packet, &auth_key(), &AKID, &range::<8>(100), true)
}

#[test]
fn unpack_checks() {
    let sid = range::<8>(100);
    assert_eq!(unpack(&server_packet(&sid, 4, b"abcd", 12)).unwrap().body, b"abcd");
    assert_eq!(unpack(&server_packet(&sid, 0, b"", 1024)).unwrap().body, b"");

    let cases: [(Vec<u8>, Error); 10] = [
        (vec![0; 23], Error::TooShort),
        ([&[0u8; 8][..], &[0; 40]].concat(), Error::AuthKeyIdMismatch),
        ([&AKID[..], &[0; 16]].concat(), Error::MsgKeyMismatch),
        (server_packet(&[0; 8], 4, b"abcd", 12), Error::SessionIdMismatch),
        (server_packet(&sid, -4, b"abcd", 12), Error::NegativeLength),
        (server_packet(&sid, 400, b"abcd", 12), Error::LengthExceedsData),
        (server_packet(&sid, 2, b"ab", 14), Error::LengthNotAligned),
        (server_packet(&sid, 8, b"abcdefgh", 8), Error::PaddingOutOfRange),
        (server_packet(&sid, 0, b"", 1040), Error::PaddingOutOfRange),
        (server_packet(&sid, 28, &[0; 16], 16), Error::PaddingOutOfRange),
    ];
    for (packet, err) in cases {
        assert_eq!(unpack(&packet), Err(err));
    }

    let mut tampered = server_packet(&sid, 4, b"abcd", 12);
    tampered[30] ^= 1;
    assert_eq!(unpack(&tampered), Err(Error::MsgKeyMismatch));
}
