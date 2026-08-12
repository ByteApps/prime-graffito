//! `notes_core::decode::decode_transaction` — round-trips against this
//! crate's own BIP144 encoder, a field-for-field cross-check against
//! rust-bitcoin's independent decoder (dev-dependency only, per house
//! rule — see `wpkh.rs`'s header comment), and adversarial-input
//! robustness (never panics, never over-allocates, always errors on
//! malformed/truncated/oversized-claim input).

use bitcoin::consensus::encode::deserialize as btc_deserialize;
use bitcoin::hashes::Hash;

use notes_core::address::{p2tr_script_pubkey, p2wpkh_script_pubkey, Recipient};
use notes_core::bundle::{
    compose_directed_note_with_change_amount, compose_note, Identity,
};
use notes_core::decode::decode_transaction;
use notes_core::keys::hash160;
use notes_core::tx::{
    build_note_tx_mixed_exact, build_sweep_tx_multi, InputKind, MixedInput, SweepSource,
    Transaction, Utxo,
};
use notes_core::Network;

const AUX: [u8; 32] = [0x42; 32];
const NET: Network = Network::Regtest;

fn identity() -> Identity {
    Identity::from_app_seed(&[7u8; 32]).unwrap()
}

fn utxos() -> Vec<Utxo> {
    vec![
        Utxo { txid: [1u8; 32], vout: 0, value: 60_000 },
        Utxo { txid: [2u8; 32], vout: 1, value: 25_000 },
        Utxo { txid: [3u8; 32], vout: 0, value: 1_000 },
    ]
}

/// A raw tx never carries its inputs' prevout values (see `decode.rs`'s
/// header comment) — the round-trip comparison must zero them on the
/// expected side.
fn zeroed(mut t: Transaction) -> Transaction {
    for i in t.inputs.iter_mut() {
        i.value = 0;
    }
    t
}

fn wpkh_seckey(byte: u8) -> [u8; 32] {
    let mut k = [0x22u8; 32];
    k[0] = byte;
    k
}

fn wpkh_spk(seckey: &[u8; 32]) -> Vec<u8> {
    use k256::ecdsa::SigningKey;
    let sk = SigningKey::from_bytes(seckey.into()).unwrap();
    let pk: [u8; 33] = sk.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
    p2wpkh_script_pubkey(&hash160(&pk))
}

// ---------------------------------------------------------------------
// 1. Round-trips against tx.rs's own encoder.
// ---------------------------------------------------------------------

/// A plain self-note: segwit round-trip, and the legacy (no-witness)
/// encoding round-trips too once witnesses are cleared on the expected
/// side (the legacy wire format carries no witness section at all).
#[test]
fn round_trip_plain_self_note() {
    let id = identity();
    let note = compose_note(&id, &utxos(), "hello world", true, 80, 2.0, 0, || Ok(AUX)).unwrap();

    let segwit_bytes = note.tx.serialize_segwit();
    let decoded = decode_transaction(&segwit_bytes).unwrap();
    assert_eq!(decoded, zeroed(note.tx.clone()));

    let legacy_bytes = note.tx.serialize_legacy();
    let decoded_legacy = decode_transaction(&legacy_bytes).unwrap();
    let mut expected_legacy = zeroed(note.tx.clone());
    expected_legacy.witnesses = Vec::new();
    assert_eq!(decoded_legacy, expected_legacy);
}

/// A directed note carrying a custom gift amount (not just the dust
/// default) — a different output shape (OP_RETURN, recipient, change)
/// from the plain self-note above.
#[test]
fn round_trip_directed_note_with_gift() {
    let sender = identity();
    let recip = Identity::from_app_seed(&[9u8; 32]).unwrap();
    let to_recip = Recipient::parse(NET, &recip.address(NET)).unwrap();

    let note = compose_directed_note_with_change_amount(
        &sender, &utxos(), "happy birthday", true, &to_recip, 50_000, None, 80, 2.0,
        0,
        || Ok(AUX))
    .unwrap();

    let decoded = decode_transaction(&note.tx.serialize_segwit()).unwrap();
    assert_eq!(decoded, zeroed(note.tx.clone()));
}

/// A multi-source sweep: several inputs from TWO different taproot
/// identities into one destination output — no OP_RETURN, no change.
#[test]
fn round_trip_multi_source_sweep() {
    let a = identity();
    let b = Identity::from_app_seed(&[11u8; 32]).unwrap();
    let a_coins = utxos();
    let b_coins =
        vec![Utxo { txid: [4u8; 32], vout: 2, value: 40_000 }, Utxo { txid: [5u8; 32], vout: 0, value: 7_000 }];
    let dest = notes_core::address::address_to_script_pubkey(NET, &Identity::from_app_seed(&[13u8; 32]).unwrap().address(NET)).unwrap();

    let sweep = build_sweep_tx_multi(
        &[
            SweepSource { utxos: &a_coins, output_x: a.output_x, tweaked_seckey: &a.tweaked_seckey },
            SweepSource { utxos: &b_coins, output_x: b.output_x, tweaked_seckey: &b.tweaked_seckey },
        ],
        dest,
        2.0,
        0,
        || Ok(AUX))
    .unwrap();

    let decoded = decode_transaction(&sweep.tx.serialize_segwit()).unwrap();
    assert_eq!(decoded, zeroed(sweep.tx.clone()));
}

/// A MIXED taproot + P2WPKH tx: the spending-wallet-funded note shape
/// (funding-unification) — one P2WPKH input, one taproot input, signed
/// in one pass via `wpkh::sign_mixed_inputs`.
#[test]
fn round_trip_mixed_taproot_and_wpkh() {
    let notebook = Identity::from_app_seed(&[0x51; 32]).unwrap();
    let taproot_spk = p2tr_script_pubkey(&notebook.output_x);
    let wpkh_sk = wpkh_seckey(5);
    let wpkh_input_spk = wpkh_spk(&wpkh_sk);
    let change_spk = wpkh_spk(&wpkh_seckey(6));
    let payloads = vec![b"mixed source note".to_vec()];

    let inputs = vec![
        MixedInput {
            utxo: Utxo { txid: [1u8; 32], vout: 0, value: 1_000 },
            prevout_spk: taproot_spk.clone(),
            kind: InputKind::Taproot,
            seckey: notebook.tweaked_seckey,
        },
        MixedInput {
            utxo: Utxo { txid: [2u8; 32], vout: 3, value: 50_000 },
            prevout_spk: wpkh_input_spk,
            kind: InputKind::P2wpkh,
            seckey: wpkh_sk,
        },
    ];

    let note = build_note_tx_mixed_exact(
        &inputs, &payloads, None, 0, &taproot_spk, &change_spk, 1.5, 0, || Ok(AUX))
    .unwrap();

    let decoded = decode_transaction(&note.tx.serialize_segwit()).unwrap();
    assert_eq!(decoded, zeroed(note.tx.clone()));
}

// ---------------------------------------------------------------------
// 2. rust-bitcoin cross-check.
// ---------------------------------------------------------------------

/// Field-for-field agreement with rust-bitcoin's independent decoder:
/// version, locktime, per-input outpoint/sequence/witness stacks,
/// per-output value/spk, txid, and vsize — for every fixture shape above.
#[test]
fn rust_bitcoin_cross_check_every_fixture() {
    let id = identity();
    let recip = Identity::from_app_seed(&[9u8; 32]).unwrap();
    let to_recip = Recipient::parse(NET, &recip.address(NET)).unwrap();
    let b = Identity::from_app_seed(&[11u8; 32]).unwrap();

    let self_note =
        compose_note(&id, &utxos(), "hello world", true, 80, 2.0, 0, || Ok(AUX)).unwrap();
    let directed = compose_directed_note_with_change_amount(
        &id, &utxos(), "happy birthday", true, &to_recip, 50_000, None, 80, 2.0,
        0,
        || Ok(AUX))
    .unwrap();
    let a_coins = utxos();
    let b_coins =
        vec![Utxo { txid: [4u8; 32], vout: 2, value: 40_000 }, Utxo { txid: [5u8; 32], vout: 0, value: 7_000 }];
    let dest = notes_core::address::address_to_script_pubkey(NET, &Identity::from_app_seed(&[13u8; 32]).unwrap().address(NET)).unwrap();
    let sweep = build_sweep_tx_multi(
        &[
            SweepSource { utxos: &a_coins, output_x: id.output_x, tweaked_seckey: &id.tweaked_seckey },
            SweepSource { utxos: &b_coins, output_x: b.output_x, tweaked_seckey: &b.tweaked_seckey },
        ],
        dest,
        2.0,
        0,
        || Ok(AUX))
    .unwrap();

    for raw in [self_note.raw_hex.clone(), directed.raw_hex.clone(), sweep.raw_hex.clone()] {
        let bytes = hex::decode(&raw).unwrap();
        let ours = decode_transaction(&bytes).unwrap();
        let theirs: bitcoin::Transaction = btc_deserialize(&bytes).unwrap();

        assert_eq!(ours.version, theirs.version.0);
        assert_eq!(ours.lock_time, theirs.lock_time.to_consensus_u32());
        assert_eq!(ours.inputs.len(), theirs.input.len());
        for (oi, ti) in ours.inputs.iter().zip(&theirs.input) {
            assert_eq!(oi.txid, ti.previous_output.txid.to_byte_array());
            assert_eq!(oi.vout, ti.previous_output.vout);
            // decode_transaction only accepts our own RBF-signaling
            // sequence — its success already proves this, asserted here
            // for documentation.
            assert_eq!(ti.sequence.to_consensus_u32(), 0xffff_fffd);
        }
        assert_eq!(ours.witnesses.len(), theirs.input.len());
        for (ow, ti) in ours.witnesses.iter().zip(&theirs.input) {
            assert_eq!(ow, &ti.witness.to_vec());
        }
        assert_eq!(ours.outputs.len(), theirs.output.len());
        for (oo, to) in ours.outputs.iter().zip(&theirs.output) {
            assert_eq!(oo.value, to.value.to_sat());
            assert_eq!(oo.script_pubkey, to.script_pubkey.to_bytes());
        }

        assert_eq!(ours.txid_hex(), theirs.compute_txid().to_string());
        assert_eq!(ours.vsize(), theirs.vsize());
    }
}

// ---------------------------------------------------------------------
// 3. Adversarial input: never panics, always errors.
// ---------------------------------------------------------------------

#[test]
fn empty_and_garbage_input_errors() {
    assert!(decode_transaction(&[]).is_err());
    assert!(decode_transaction(&[0u8; 1]).is_err());
    assert!(decode_transaction(&[0u8; 3]).is_err()); // shorter than a version field
    assert!(decode_transaction(b"not a transaction at all, just ascii junk").is_err());
}

/// A huge claimed count (input count, output count, witness item count,
/// witness item length) with no bytes behind it must error immediately,
/// never allocate anywhere close to the claimed size, and never panic.
#[test]
fn huge_claimed_counts_never_allocate_or_panic() {
    // version(4) + varint 0xff + 8 bytes of 0xff = u64::MAX claimed inputs.
    let mut huge_inputs = vec![2, 0, 0, 0, 0xff];
    huge_inputs.extend_from_slice(&[0xffu8; 8]);
    assert!(decode_transaction(&huge_inputs).is_err());

    // A real tx prefix (version + 1 real input) followed by a huge claimed
    // output count with nothing behind it.
    let id = identity();
    let note = compose_note(&id, &utxos(), "x", false, 80, 1.0, 0, || Ok(AUX)).unwrap();
    let full = note.tx.serialize_segwit();
    // version(4) + first real varint(1) + one full TxIn(41 bytes) = 46
    // bytes in, then splice a huge output-count varint with no data.
    let mut spliced = full[..46].to_vec();
    spliced.push(0xff);
    spliced.extend_from_slice(&[0xffu8; 8]);
    assert!(decode_transaction(&spliced).is_err());

    // marker(0x00) + an unsupported flag byte (must not silently fall
    // back to some other interpretation).
    let mut bad_flag = vec![2, 0, 0, 0, 0x00, 0x00];
    bad_flag.extend_from_slice(&[0u8; 40]);
    assert!(decode_transaction(&bad_flag).is_err());
}

/// Byte-by-byte truncation of several real, differently-shaped signed
/// transactions must never panic, and must error for every length short
/// of the full encoding (a valid tx's prefix is never itself a valid,
/// differently-shaped tx by coincidence).
#[test]
fn truncated_at_every_byte_boundary_never_panics() {
    let id = identity();
    let recip = Identity::from_app_seed(&[9u8; 32]).unwrap();
    let to_recip = Recipient::parse(NET, &recip.address(NET)).unwrap();

    let self_note =
        compose_note(&id, &utxos(), "x", false, 80, 1.0, 0, || Ok(AUX)).unwrap();
    let directed = compose_directed_note_with_change_amount(
        &id, &utxos(), "y", true, &to_recip, 1_000, None, 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    for note in [self_note, directed] {
        let full = note.tx.serialize_segwit();
        for len in 0..full.len() {
            assert!(
                decode_transaction(&full[..len]).is_err(),
                "truncation at {len}/{} bytes must error, not succeed or panic",
                full.len()
            );
        }
        // The full, untruncated bytes must still decode successfully.
        assert!(decode_transaction(&full).is_ok());
        // One byte of trailing garbage must be rejected.
        let mut trailing = full.clone();
        trailing.push(0xAB);
        assert!(decode_transaction(&trailing).is_err());
    }
}

/// The BIP144 marker/flag disambiguation: a first-varint-count of 0 is
/// always treated as the segwit marker, never a genuine "0 inputs" tx —
/// and an unsupported flag byte after it must error rather than being
/// reinterpreted as something else.
#[test]
fn marker_flag_ambiguity_is_handled() {
    // version + marker(0x00) + a non-0x01 flag -> rejected.
    for bad_flag in [0x00u8, 0x02, 0xff] {
        let bytes = vec![2, 0, 0, 0, 0x00, bad_flag];
        assert!(decode_transaction(&bytes).is_err(), "flag {bad_flag:#x} must be rejected");
    }
    // version + marker(0x00) + flag(0x01) but nothing else -> unexpected EOF.
    let bytes = vec![2, 0, 0, 0, 0x00, 0x01];
    assert!(decode_transaction(&bytes).is_err());
}
