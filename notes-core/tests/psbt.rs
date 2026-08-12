//! PSBT codec: self round-trip, signing that reproduces the direct-signed
//! note tx byte-for-byte, and two-direction interop with rust-bitcoin.

use notes_core::address::p2tr_script_pubkey;
use notes_core::bundle::{compose_note_exact, Identity};
use notes_core::psbt::Psbt;
use notes_core::tx::{TxOut, Utxo};

const APP_SEED: [u8; 32] = [7u8; 32];
const AUX: [u8; 32] = [0x42; 32];

fn id() -> Identity {
    Identity::from_app_seed(&APP_SEED).unwrap()
}

/// Two inputs so the PSBT exercises multi-input maps + sighashing.
fn utxos() -> Vec<Utxo> {
    vec![Utxo { txid: [1u8; 32], vout: 0, value: 60_000 }, Utxo { txid: [2u8; 32], vout: 1, value: 25_000 }]
}

/// Build the unsigned PSBT for a note tx spending exactly our two UTXOs.
fn unsigned_psbt(id: &Identity) -> (Psbt, notes_core::tx::NoteTx, Vec<u8>) {
    let note = compose_note_exact(id, &utxos(), "psbt me maybe", false, None, 80, 2.0, 0, || {
        Ok(AUX)
    })
    .unwrap();
    let our_spk = p2tr_script_pubkey(&id.output_x);
    let witness_utxos: Vec<TxOut> = note
        .tx
        .inputs
        .iter()
        .map(|i| TxOut { value: i.value, script_pubkey: our_spk.clone() })
        .collect();
    let internal_keys = vec![Some(id.internal_x); note.tx.inputs.len()];
    let mut unsigned = note.tx.clone();
    unsigned.witnesses.clear();
    let psbt = Psbt::from_unsigned(unsigned, witness_utxos, internal_keys).unwrap();
    (psbt, note, our_spk)
}

#[test]
fn serialize_deserialize_roundtrip() {
    let id = id();
    let (psbt, note, our_spk) = unsigned_psbt(&id);
    let bytes = psbt.serialize();
    let re = Psbt::deserialize(&bytes).unwrap();
    assert_eq!(re.serialize(), bytes, "round-trip must be byte-stable");
    assert_eq!(re.unsigned_tx.txid_hex(), note.txid_hex);
    assert_eq!(re.inputs.len(), 2);
    for inp in &re.inputs {
        assert_eq!(inp.witness_utxo.as_ref().unwrap().script_pubkey, our_spk);
        assert_eq!(inp.tap_internal_key, Some(id.internal_x));
        assert!(inp.tap_key_sig.is_none());
    }
    // Garbage / truncation rejected, not panicked.
    assert!(Psbt::deserialize(b"nope").is_err());
    assert!(Psbt::deserialize(&bytes[..bytes.len() - 1]).is_err());
}

/// Signing every input via the PSBT (same tweaked key + same aux) reproduces
/// the note tx that `compose_note_exact` signed directly — byte-for-byte.
#[test]
fn psbt_signing_reproduces_direct_signed_tx() {
    let id = id();
    let (mut psbt, note, _) = unsigned_psbt(&id);
    for i in 0..psbt.inputs.len() {
        psbt.sign_taproot_key_path(i, &id.tweaked_seckey, &AUX).unwrap();
    }
    let final_tx = psbt.extract_final_tx().unwrap();
    assert_eq!(hex::encode(final_tx.serialize_segwit()), note.raw_hex);
    assert_eq!(final_tx.txid_hex(), note.txid_hex);
}

/// Our serialized (signed) PSBT parses in rust-bitcoin, agrees on the tx, and
/// every `tap_key_sig` verifies against rust-bitcoin's own BIP341 sighash.
#[test]
fn our_psbt_interops_with_rust_bitcoin() {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut as BTxOut};

    let id = id();
    let (mut psbt, note, our_spk) = unsigned_psbt(&id);
    for i in 0..psbt.inputs.len() {
        psbt.sign_taproot_key_path(i, &id.tweaked_seckey, &AUX).unwrap();
    }
    let bytes = psbt.serialize();

    let bpsbt = bitcoin::Psbt::deserialize(&bytes).expect("rust-bitcoin parses our PSBT");
    assert_eq!(bpsbt.unsigned_tx.compute_txid().to_string(), note.txid_hex);
    assert!(bpsbt.inputs.iter().all(|i| i.witness_utxo.is_some()));

    let prevouts: Vec<BTxOut> = note
        .tx
        .inputs
        .iter()
        .map(|i| BTxOut {
            value: Amount::from_sat(i.value),
            script_pubkey: ScriptBuf::from_bytes(our_spk.clone()),
        })
        .collect();
    let secp = Secp256k1::verification_only();
    let output_key = XOnlyPublicKey::from_slice(&id.output_x).unwrap();
    let mut cache = SighashCache::new(&bpsbt.unsigned_tx);
    for (i, inp) in psbt.inputs.iter().enumerate() {
        let sig = inp.tap_key_sig.as_ref().unwrap();
        let sighash = cache
            .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        secp.verify_schnorr(
            &Signature::from_slice(&sig[..64]).unwrap(),
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .expect("PSBT tap_key_sig must verify under rust-bitcoin's sighash");
    }
}

/// The external-signer entry point: sign only inputs that pay OUR address,
/// leave foreign inputs untouched, and stay idempotent.
#[test]
fn sign_own_taproot_signs_only_our_inputs() {
    let id = id();
    let (mut psbt, _note, _) = unsigned_psbt(&id); // 2 inputs, both ours
    // Make the 2nd input foreign (a different taproot address).
    let other = Identity::from_app_seed(&[0x22u8; 32]).unwrap();
    psbt.inputs[1].witness_utxo.as_mut().unwrap().script_pubkey =
        notes_core::address::p2tr_script_pubkey(&other.output_x);

    let (ours, signed) = psbt.sign_own_taproot(&id.output_x, &id.tweaked_seckey, || Ok(AUX)).unwrap();
    assert_eq!((ours, signed), (1, 1));
    assert!(psbt.inputs[0].tap_key_sig.is_some());
    assert!(psbt.inputs[1].tap_key_sig.is_none(), "foreign input must stay unsigned");

    // Idempotent: a second pass signs nothing new.
    let (ours2, signed2) = psbt.sign_own_taproot(&id.output_x, &id.tweaked_seckey, || Ok(AUX)).unwrap();
    assert_eq!((ours2, signed2), (1, 0));
}

/// A PSBT built by rust-bitcoin (unsigned tx + witness_utxos) parses in our
/// codec and agrees on the tx and every input's spent output.
#[test]
fn rust_bitcoin_psbt_parses_in_our_codec() {
    use bitcoin::consensus::encode::deserialize as btc_deser;
    use bitcoin::{Amount, ScriptBuf, TxOut as BTxOut};

    let id = id();
    let (_psbt, note, our_spk) = unsigned_psbt(&id);

    // Unsigned (legacy) tx bytes → rust-bitcoin tx → its Psbt builder.
    let mut unsigned = note.tx.clone();
    unsigned.witnesses.clear();
    let unsigned_btx: bitcoin::Transaction = btc_deser(&unsigned.serialize_legacy()).unwrap();
    let mut bpsbt = bitcoin::Psbt::from_unsigned_tx(unsigned_btx).unwrap();
    for (i, inp) in bpsbt.inputs.iter_mut().enumerate() {
        inp.witness_utxo = Some(BTxOut {
            value: Amount::from_sat(note.tx.inputs[i].value),
            script_pubkey: ScriptBuf::from_bytes(our_spk.clone()),
        });
    }

    let ours = Psbt::deserialize(&bpsbt.serialize()).expect("we parse rust-bitcoin's PSBT");
    assert_eq!(ours.unsigned_tx.txid_hex(), note.txid_hex);
    assert_eq!(ours.inputs.len(), note.tx.inputs.len());
    for (i, inp) in ours.inputs.iter().enumerate() {
        let wu = inp.witness_utxo.as_ref().unwrap();
        assert_eq!(wu.value, note.tx.inputs[i].value);
        assert_eq!(wu.script_pubkey, our_spk);
    }

    // And our codec can then sign + finalize that rust-bitcoin-built PSBT.
    let mut ours = ours;
    for i in 0..ours.inputs.len() {
        ours.sign_taproot_key_path(i, &id.tweaked_seckey, &AUX).unwrap();
    }
    assert_eq!(hex::encode(ours.extract_final_tx().unwrap().serialize_segwit()), note.raw_hex);
}

/// Port B (network-display fix, 2026-07-19): `input_derivation_coin_type`
/// reads a real BIP-371 `tap_key_origins` entry the way an external tool
/// (Sparrow, a funding-wallet manager, anything that imported our
/// `export.rs` account descriptor) would actually attach it — built here
/// with rust-bitcoin itself, exactly like `rust_bitcoin_psbt_parses_in_our_codec`
/// exercises real interop rather than a hand-rolled byte string.
#[test]
fn input_derivation_coin_type_reads_real_tap_key_origin() {
    use bitcoin::bip32::{ChildNumber, Fingerprint, KeySource};
    use bitcoin::secp256k1::XOnlyPublicKey;
    use bitcoin::TapLeafHash;

    let id = id();
    let (psbt, _note, _) = unsigned_psbt(&id);
    let bytes = psbt.serialize();
    let mut bpsbt = bitcoin::Psbt::deserialize(&bytes).unwrap();

    let internal = XOnlyPublicKey::from_slice(&id.internal_x).unwrap();
    let fp = Fingerprint::from([0xaa, 0xbb, 0xcc, 0xdd]);
    // m/86'/1'/0'/0/0 — coin_type' = 1 (every non-mainnet network in this
    // ecosystem's own `seeds::coin_type`).
    let path: Vec<ChildNumber> = vec![
        ChildNumber::from_hardened_idx(86).unwrap(),
        ChildNumber::from_hardened_idx(1).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
        ChildNumber::from_normal_idx(0).unwrap(),
        ChildNumber::from_normal_idx(0).unwrap(),
    ];
    let source: KeySource = (fp, path.into());
    bpsbt.inputs[0].tap_key_origins.insert(internal, (Vec::<TapLeafHash>::new(), source));

    let reserialized = bpsbt.serialize();
    let ours = Psbt::deserialize(&reserialized).unwrap();
    assert_eq!(ours.input_derivation_coin_type(0), Some(1));
    // Input 1 never got an origin attached — no signal, not a crash.
    assert_eq!(ours.input_derivation_coin_type(1), None);

    // Round-trip through OUR serializer preserves the unknown field
    // byte-for-byte (lossless fidelity, psbt.rs's own doc promise), so the
    // signal survives us re-emitting the PSBT too.
    let ours_bytes = ours.serialize();
    let ours_again = Psbt::deserialize(&ours_bytes).unwrap();
    assert_eq!(ours_again.input_derivation_coin_type(0), Some(1));
}

/// Absence and malformed data must both yield `None`, never panic or
/// misread — this function backs a display-only confirm-screen decision,
/// never signing/validation.
#[test]
fn input_derivation_coin_type_is_none_when_absent_or_malformed() {
    let id = id();
    let (psbt, _note, _) = unsigned_psbt(&id);
    // No BIP32 fields attached at all (unsigned_psbt never sets any).
    assert_eq!(psbt.input_derivation_coin_type(0), None);
    assert_eq!(psbt.input_derivation_coin_type(99), None); // out of range

    // A same-type-byte field that's too short to contain a coin-type level
    // must not panic and must not fabricate a value.
    let mut broken = psbt.clone();
    broken.inputs[0].unknown.push((vec![0x16], vec![0x00, 0x01, 0x02])); // n=0 hashes, 3 leftover bytes only
    assert_eq!(broken.input_derivation_coin_type(0), None);
}
