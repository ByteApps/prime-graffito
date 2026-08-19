//! Published-vector tests: BIP340 signing/verification and the BIP341
//! taproot tweak, plus address encoding cross-checked against rust-bitcoin.

use notes_core::sign::{schnorr_sign, schnorr_verify};
use notes_core::taproot::taproot_tweak_pubkey;
use notes_core::{address, Network};

fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).unwrap();
    out
}

// From the official BIP340 test vector CSV (index 0, 1, 2).
#[test]
fn bip340_sign_vectors() {
    let cases = [
        (
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        ),
        (
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        ),
        (
            "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
            "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        ),
    ];
    for (seckey, aux, msg, want_sig) in cases {
        let sig = schnorr_sign(&h32(seckey), &h32(msg), &h32(aux)).unwrap();
        assert_eq!(hex::encode_upper(sig), want_sig, "seckey {seckey}");
    }
}

#[test]
fn bip340_verify_rejects_tampered() {
    let seckey = h32("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let msg = h32("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    let aux = h32("0000000000000000000000000000000000000000000000000000000000000001");
    let pubkey = h32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    let sig = schnorr_sign(&seckey, &msg, &aux).unwrap();
    assert!(schnorr_verify(&pubkey, &msg, &sig));
    let mut bad = sig;
    bad[7] ^= 1;
    assert!(!schnorr_verify(&pubkey, &msg, &bad));
    let mut wrong_msg = msg;
    wrong_msg[0] ^= 1;
    assert!(!schnorr_verify(&pubkey, &wrong_msg, &sig));
}

// BIP341 scriptPubKey test vector #1: key-path-only (no script tree).
#[test]
fn bip341_tweak_vector() {
    let internal = h32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
    let (output_x, _) = taproot_tweak_pubkey(&internal, None).unwrap();
    assert_eq!(
        hex::encode(output_x),
        "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    );
}

#[test]
fn address_matches_rust_bitcoin() {
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::secp256k1::Secp256k1;

    let secp = Secp256k1::verification_only();
    let internal = h32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
    let (output_x, _) = taproot_tweak_pubkey(&internal, None).unwrap();

    for (network, btc_network) in [
        (Network::Mainnet, bitcoin::Network::Bitcoin),
        // rust-bitcoin's Testnet(3) shares the tb HRP with testnet4.
        (Network::Testnet4, bitcoin::Network::Testnet),
        (Network::Signet, bitcoin::Network::Signet),
        (Network::Regtest, bitcoin::Network::Regtest),
    ] {
        let ours = address::taproot_address(network, &output_x);
        let theirs = bitcoin::Address::p2tr(
            &secp,
            UntweakedPublicKey::from_slice(&internal).unwrap(),
            None,
            btc_network,
        );
        assert_eq!(ours, theirs.to_string(), "{network:?}");
    }
}

/// FROZEN directed-note derivation vector (dm.rs): pins the static-static
/// x-only ECDH shared secret and the HKDF'd dm key between the two fixed
/// test identities, in BOTH directions. Originally computed 2026-07-05;
/// REGENERATED 2026-08-18 for the Graffito crypto epoch (KEY_SALT/DM_SALT
/// rebound to `prime-graffito/...` — see keys.rs/dm.rs module docs) and
/// frozen again — any further change to KEY_SALT, DM_SALT/DM_INFO, lift_x,
/// or the tweak pipeline breaks every directed note on-chain.
#[test]
fn dm_derivation_vector() {
    use notes_core::bundle::Identity;
    use notes_core::dm;
    let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
    let b = Identity::from_app_seed(&[9u8; 32]).unwrap();
    assert_eq!(
        hex::encode(a.output_x),
        "771861d417e02e44450bb0a2b5e47dffa654c41cd2613603fad848069d89b85b"
    );
    assert_eq!(
        hex::encode(b.output_x),
        "e1f4ac96b1295464846cc0fa3b51607308ffbbfa5befd959dd1f2e871daa5c20"
    );
    let shared_ab = dm::ecdh_shared_x(&a.tweaked_seckey, &b.output_x).unwrap();
    let shared_ba = dm::ecdh_shared_x(&b.tweaked_seckey, &a.output_x).unwrap();
    assert_eq!(
        hex::encode(shared_ab),
        "6b6ba4a75214913146c342de860749c81f050bd1ca4fef466d8b7e816404b7ce"
    );
    assert_eq!(shared_ab, shared_ba);
    assert_eq!(
        hex::encode(dm::dm_key(&shared_ab)),
        "73759dfb6bce71d7796a6f8c2189d1d980bfbe81faa6f8273e9e639f15e34ea1"
    );
}

/// FROZEN directed-note AAD layout (dm.rs, PLAN-pnte-redesign.md 2026-08-11
/// rebinding): `dm_aad` = sender_x(32) || recipient_x(32) || outpoint(36),
/// 100 bytes — pinned so a byte-layout regression is caught even though
/// `seal_aad` uses a random nonce internally (see
/// `directed_aad_seal_open_vector` below for a full round-trip pin, and
/// `roundtrip.rs::directed_aad_binds_direction_and_sender` for the
/// composed-tx-level proof).
#[test]
fn dm_aad_layout_vector() {
    use notes_core::dm::dm_aad;
    let sender_x = [0x11u8; 32];
    let recipient_x = [0x22u8; 32];
    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&[0xAAu8; 32]);
    outpoint[32..].copy_from_slice(&7u32.to_le_bytes());
    let aad = dm_aad(&sender_x, &recipient_x, &outpoint);
    assert_eq!(aad.len(), 100);
    assert_eq!(&aad[..32], &sender_x);
    assert_eq!(&aad[32..64], &recipient_x);
    assert_eq!(&aad[64..], &outpoint);
}

/// FROZEN single-recipient directed-note seal/open round-trip with a fixed
/// outpoint: pins that `seal_directed`/`open_received`/`open_sent` all
/// agree, and that authentication fails under a different outpoint (the
/// AEAD-level proof that the AAD rebinding actually took — a wrong
/// outpoint is now exactly as fatal to decryption as the old wrong
/// note_id was).
#[test]
fn directed_aad_seal_open_vector() {
    use notes_core::bundle::Identity;
    use notes_core::dm;

    let a = Identity::from_app_seed(&[7u8; 32]).unwrap(); // sender
    let b = Identity::from_app_seed(&[9u8; 32]).unwrap(); // recipient
    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&[0x77u8; 32]);
    outpoint[32..].copy_from_slice(&3u32.to_le_bytes());
    let plaintext = b"frozen outpoint-bound vector";

    let blob =
        dm::seal_directed(&a.tweaked_seckey, &a.output_x, &b.output_x, &outpoint, plaintext)
            .unwrap();
    assert_eq!(
        dm::open_received(&b.tweaked_seckey, &b.output_x, &a.output_x, &outpoint, &blob).unwrap(),
        plaintext
    );
    // Sender re-read (wipe recovery): symmetric with open_received.
    assert_eq!(
        dm::open_sent(&a.tweaked_seckey, &a.output_x, &b.output_x, &outpoint, &blob).unwrap(),
        plaintext
    );

    // A different outpoint (a different funding spend) fails the AAD.
    let mut wrong_outpoint = outpoint;
    wrong_outpoint[32..].copy_from_slice(&4u32.to_le_bytes());
    assert!(dm::open_received(&b.tweaked_seckey, &b.output_x, &a.output_x, &wrong_outpoint, &blob)
        .is_err());
}

/// Full `seal_multi`/open round-trip with FIXED identities and a fixed
/// FROZEN multi-recipient AAD layout (dm.rs): `multi_body_aad` =
/// sender_x(32) || outpoint(36), 68 bytes — pinned so a byte-layout
/// regression is caught even though `seal_multi`/`seal_aad` use a random
/// nonce internally (see `multi_seal_open_vector` below for a full
/// round-trip pin). Rebound from the old `sender_x(32) || note_id(4)`,
/// 36 bytes, by PLAN-pnte-redesign.md (2026-08-11) alongside the singular
/// `dm_aad` above — restored here per orchestrator review: a layout vector
/// deleted at exactly the moment the layout changes proves nothing.
#[test]
fn multi_body_aad_layout_vector() {
    use notes_core::dm::multi_body_aad;
    let sender_x = [0x11u8; 32];
    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&[0xBBu8; 32]);
    outpoint[32..].copy_from_slice(&5u32.to_le_bytes());
    let aad = multi_body_aad(&sender_x, &outpoint);
    assert_eq!(aad.len(), 68);
    assert_eq!(&aad[..32], &sender_x);
    assert_eq!(&aad[32..], &outpoint);
}

/// outpoint: pins the wrap length (`dm::WRAP_LEN` == 72 bytes, always), that
/// the recipient side (`open_received_multi`, own-index-first and
/// fallback-to-any-wrap) and the sender side (`open_sent_multi`,
/// index-0-first) both recover the SAME plaintext via the shared content
/// key, and that authentication fails for a stranger, under a wrong
/// outpoint, and against a tampered wrap or a tampered sealed body (the
/// AEAD-level protection that actually secures the content — a tampered
/// *count* byte is no longer even part of the body at all, since the
/// recipient count now lives in the envelope header — see the
/// decode-liberal tests in `multi_recipient.rs`).
#[test]
fn multi_seal_open_vector() {
    use notes_core::bundle::Identity;
    use notes_core::dm;

    let a = Identity::from_app_seed(&[7u8; 32]).unwrap(); // sender
    let b = Identity::from_app_seed(&[9u8; 32]).unwrap(); // recipient 0
    let c = Identity::from_app_seed(&[11u8; 32]).unwrap(); // recipient 1
    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&[0x33u8; 32]);
    outpoint[32..].copy_from_slice(&1u32.to_le_bytes());
    let content_key = [0x55u8; 32];
    let plaintext = b"shared secret for B and C";

    let (wraps, sealed_body) = dm::seal_multi(
        &a.tweaked_seckey,
        &a.output_x,
        &[b.output_x, c.output_x],
        &outpoint,
        &content_key,
        plaintext,
    )
    .unwrap();
    assert_eq!(wraps.len(), 2);
    assert_eq!(dm::WRAP_LEN, 72);
    for w in &wraps {
        assert_eq!(w.len(), dm::WRAP_LEN);
    }

    // Recipient B: own index (0) first.
    let opened_b = dm::open_received_multi(
        &b.tweaked_seckey,
        &b.output_x,
        &a.output_x,
        &outpoint,
        &wraps,
        &sealed_body,
        Some(0),
    )
    .unwrap();
    assert_eq!(opened_b, plaintext);

    // Recipient C: own index (1) first.
    let opened_c = dm::open_received_multi(
        &c.tweaked_seckey,
        &c.output_x,
        &a.output_x,
        &outpoint,
        &wraps,
        &sealed_body,
        Some(1),
    )
    .unwrap();
    assert_eq!(opened_c, plaintext);

    // Recipient B WITHOUT knowing its own index: fallback tries every wrap.
    let opened_b_fallback = dm::open_received_multi(
        &b.tweaked_seckey,
        &b.output_x,
        &a.output_x,
        &outpoint,
        &wraps,
        &sealed_body,
        None,
    )
    .unwrap();
    assert_eq!(opened_b_fallback, plaintext);

    // Sender re-read: recovers K via recipient index 0 (B) and opens the body.
    let opened_a = dm::open_sent_multi(
        &a.tweaked_seckey,
        &a.output_x,
        &[b.output_x, c.output_x],
        &outpoint,
        &wraps,
        &sealed_body,
    )
    .unwrap();
    assert_eq!(opened_a, plaintext);

    // Wrong recipient (not a wrap holder) cannot open any wrap.
    let stranger = Identity::from_app_seed(&[13u8; 32]).unwrap();
    assert!(dm::open_received_multi(
        &stranger.tweaked_seckey,
        &stranger.output_x,
        &a.output_x,
        &outpoint,
        &wraps,
        &sealed_body,
        None,
    )
    .is_err());

    // Wrong outpoint: the wrap's AAD no longer matches.
    let mut wrong_outpoint = outpoint;
    wrong_outpoint[32..].copy_from_slice(&9u32.to_le_bytes());
    assert!(dm::open_received_multi(
        &b.tweaked_seckey,
        &b.output_x,
        &a.output_x,
        &wrong_outpoint,
        &wraps,
        &sealed_body,
        Some(0),
    )
    .is_err());

    // Tampered wrap byte -> AEAD auth failure.
    let mut tampered_wraps = wraps.clone();
    tampered_wraps[0][10] ^= 1;
    assert!(dm::open_received_multi(
        &b.tweaked_seckey,
        &b.output_x,
        &a.output_x,
        &outpoint,
        &tampered_wraps,
        &sealed_body,
        Some(0),
    )
    .is_err());

    // Tampered sealed-body byte -> AEAD auth failure even with a valid wrap.
    let mut tampered_body = sealed_body.clone();
    let last = tampered_body.len() - 1;
    tampered_body[last] ^= 1;
    assert!(dm::open_received_multi(
        &b.tweaked_seckey,
        &b.output_x,
        &a.output_x,
        &outpoint,
        &wraps,
        &tampered_body,
        Some(0),
    )
    .is_err());
}

