//! Anti-fee-sniping `nLockTime`: the policy type, and proof that the
//! locktime we build with is actually committed to by the BIP-341 sighash
//! (cross-checked against rust-bitcoin/libsecp256k1, the same way the rest
//! of our transaction construction is).

use notes_core::bundle::{compose_note, compose_note_exact, Identity};
use notes_core::tx::{estimate_vsize, LockTimePolicy, Utxo};

const APP_SEED: [u8; 32] = [7u8; 32];
const AUX: [u8; 32] = [0x42; 32];

fn identity() -> Identity {
    Identity::from_app_seed(&APP_SEED).unwrap()
}

fn utxos() -> Vec<Utxo> {
    vec![
        Utxo { txid: [1u8; 32], vout: 0, value: 60_000 },
        Utxo { txid: [2u8; 32], vout: 1, value: 25_000 },
    ]
}

#[test]
fn policy_resolves() {
    // Anti-fee-sniping: the last height we know about.
    assert_eq!(LockTimePolicy::Tip.resolve(Some(912_744)), 912_744);
    // No tip yet (nothing ever synced) must fall back to 0, NOT to a
    // guess: a locktime in the future would make the tx non-final and get
    // it rejected from the mempool.
    assert_eq!(LockTimePolicy::Tip.resolve(None), 0);
    // The explicit opt-out ignores the tip entirely.
    assert_eq!(LockTimePolicy::Zero.resolve(Some(912_744)), 0);
    // A caller-chosen height ignores the tip too.
    assert_eq!(LockTimePolicy::Custom { height: 42 }.resolve(Some(912_744)), 42);
    assert_eq!(LockTimePolicy::Custom { height: 42 }.resolve(None), 42);
}

#[test]
fn policy_default_is_anti_fee_sniping() {
    // The default must match Core/BDK, not this crate's old behavior —
    // a wallet that has to opt IN to anti-fee-sniping mostly won't.
    assert_eq!(LockTimePolicy::default(), LockTimePolicy::Tip);
}

#[test]
fn policy_serde_roundtrip() {
    // Both apps persist this in their config files, so the wire form has
    // to survive a round-trip (and stay readable in a hand-edited JSON).
    for policy in [
        LockTimePolicy::Tip,
        LockTimePolicy::Zero,
        LockTimePolicy::Custom { height: 912_744 },
    ] {
        let json = serde_json::to_string(&policy).unwrap();
        let back: LockTimePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back, "{json}");
    }
    assert_eq!(serde_json::to_string(&LockTimePolicy::Tip).unwrap(), r#"{"mode":"tip"}"#);
    assert_eq!(
        serde_json::to_string(&LockTimePolicy::Custom { height: 7 }).unwrap(),
        r#"{"mode":"custom","height":7}"#
    );
}

#[test]
fn locktime_reaches_the_wire_and_moves_the_txid() {
    let id = identity();
    let build = |lock_time: u32| {
        compose_note(&id, &utxos(), "anti fee sniping", false, 80, 2.0, lock_time, || {
            Ok(AUX)
        })
        .unwrap()
    };

    let zero = build(0);
    let tip = build(912_744);

    assert_eq!(zero.tx.lock_time, 0);
    assert_eq!(tip.tx.lock_time, 912_744);

    // Last 4 bytes of the serialization are nLockTime, little-endian.
    let raw = hex::decode(&tip.raw_hex).unwrap();
    assert_eq!(&raw[raw.len() - 4..], &912_744u32.to_le_bytes());

    // Different locktime => different txid. If these matched, the field
    // would not be committed to and the whole change would be cosmetic.
    assert_ne!(zero.txid_hex, tip.txid_hex);
}

#[test]
fn locktime_does_not_change_vsize_or_fee() {
    // nLockTime is a fixed 4 bytes that `estimate_vsize` already counts,
    // so the byte-exact cost estimator must be completely unaffected —
    // this is what keeps `cost_estimator_is_exact` honest across the
    // change.
    let id = identity();
    let build = |lock_time: u32| {
        compose_note(&id, &utxos(), "same size either way", false, 80, 3.0, lock_time,
            || Ok(AUX))
        .unwrap()
    };
    let zero = build(0);
    let tip = build(912_744);

    assert_eq!(zero.vsize, tip.vsize);
    assert_eq!(zero.fee, tip.fee);
    assert_eq!(zero.change, tip.change);
    assert_eq!(zero.tx.inputs.len(), tip.tx.inputs.len());
    // And the prediction still matches the real thing.
    let payload_lens: Vec<usize> =
        tip.tx.outputs.iter().filter(|o| o.value == 0).map(|o| o.script_pubkey.len() - 2).collect();
    assert_eq!(estimate_vsize(tip.tx.inputs.len(), &payload_lens, None, true), tip.vsize);
}

/// The load-bearing one: rust-bitcoin must parse a non-zero-locktime note
/// tx, agree on txid and vsize, recompute the BIP-341 key-spend sighash
/// from the parsed transaction, and have libsecp256k1 accept our Schnorr
/// signature over it. That can only hold if our sighash implementation
/// commits to nLockTime exactly the way the spec says.
#[test]
fn nonzero_locktime_cross_checks_against_rust_bitcoin() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let id = identity();
    let inputs = utxos();
    let note = compose_note_exact(
        &id,
        &inputs,
        "locktime is covered by the sighash",
        true,
        None,
        80,
        3.0,
        912_744,
        || Ok(AUX),
    )
    .unwrap();

    let raw = hex::decode(&note.raw_hex).unwrap();
    let btx: bitcoin::Transaction = deserialize(&raw).unwrap();

    // rust-bitcoin's own view of the locktime must be the height we asked
    // for, parsed as a HEIGHT (not a timestamp).
    assert_eq!(btx.lock_time.to_consensus_u32(), 912_744);
    assert!(btx.lock_time.is_block_height());
    assert_eq!(btx.compute_txid().to_string(), note.txid_hex);
    assert_eq!(btx.vsize(), note.vsize);

    // Every input must still signal RBF, which is what makes nLockTime
    // enforced in the first place.
    assert!(btx.input.iter().all(|i| i.sequence.to_consensus_u32() == 0xffff_fffd));
    assert!(btx.input.iter().all(|i| i.sequence.enables_absolute_lock_time()));

    let spk = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&id.output_x));
    let prevouts: Vec<TxOut> = note
        .tx
        .inputs
        .iter()
        .map(|i| TxOut { value: Amount::from_sat(i.value), script_pubkey: spk.clone() })
        .collect();

    let secp = Secp256k1::verification_only();
    let output_key = XOnlyPublicKey::from_slice(&id.output_x).unwrap();
    let mut cache = SighashCache::new(&btx);
    for (index, witness) in note.tx.witnesses.iter().enumerate() {
        let sighash = cache
            .taproot_key_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = Signature::from_slice(&witness[0]).unwrap();
        secp.verify_schnorr(&sig, &msg, &output_key)
            .expect("libsecp256k1 must accept our signature over rust-bitcoin's sighash");
    }
}

/// Negative control for the test above: tampering with nLockTime after
/// signing must invalidate the signature. Without this, the cross-check
/// could pass for a sighash that simply ignored the field.
#[test]
fn tampering_with_locktime_breaks_the_signature() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let id = identity();
    let mut note = compose_note(
        &id,
        &utxos(),
        "tamper me",
        false,
        80,
        2.0,
        912_744,
        || Ok(AUX),
    )
    .unwrap();

    // Flip the locktime on the SIGNED transaction and re-serialize.
    note.tx.lock_time = 912_745;
    let raw = note.tx.serialize_segwit();
    let btx: bitcoin::Transaction = deserialize(&raw).unwrap();

    let spk = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&id.output_x));
    let prevouts: Vec<TxOut> = note
        .tx
        .inputs
        .iter()
        .map(|i| TxOut { value: Amount::from_sat(i.value), script_pubkey: spk.clone() })
        .collect();

    let secp = Secp256k1::verification_only();
    let output_key = XOnlyPublicKey::from_slice(&id.output_x).unwrap();
    let mut cache = SighashCache::new(&btx);
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = Signature::from_slice(&note.tx.witnesses[0][0]).unwrap();
    assert!(
        secp.verify_schnorr(&sig, &msg, &output_key).is_err(),
        "nLockTime must be committed to by the sighash"
    );
}
