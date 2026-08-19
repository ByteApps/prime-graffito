//! P2WPKH (BIP143) signing for the spending wallet's native-segwit inputs
//! (PLAN-graffito-funding-unification.md, "New signing surface: P2WPKH
//! in notes-core"). Unlike the hand-rolled BIP340 Schnorr in `sign.rs`
//! (hand-rolled per spec so `aux_rand` stays a parameter for reproducible
//! vectors), ECDSA's RFC6979 deterministic nonce and low-S/DER
//! canonicalization are exactly the kind of rule a vetted crate exists to
//! get right, so this module signs via k256's `ecdsa` feature (still pure
//! Rust, no C — see Cargo.toml) instead of hand-rolling them. Cross-checked
//! byte-for-byte against rust-bitcoin in `tests/wpkh_vectors.rs` (house
//! rule for crypto surface — same treatment `export.rs`/`psbt.rs` got; an
//! integration test rather than an inline `#[cfg(test)]` module so the
//! `bitcoin` dev-dependency never enters the same compilation unit as the
//! rest of `src/`, see that file's header comment).

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};

use crate::keys::{double_sha256, hash160};
use crate::sighash::taproot_key_spend_sighash;
use crate::sign::schnorr_sign;
use crate::tx::{write_varint, Transaction};
use crate::Error;

/// SIGHASH_ALL — the only sighash type the spending wallet ever produces
/// (same "sign everything, every time" convention as the taproot signer's
/// SIGHASH_DEFAULT).
pub const SIGHASH_ALL: u8 = 0x01;

/// The BIP143 `scriptCode` for a P2WPKH input: the equivalent P2PKH script
/// `OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2wpkh_script_code(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76); // OP_DUP
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20
    s.extend_from_slice(pubkey_hash);
    s.push(0x88); // OP_EQUALVERIFY
    s.push(0xac); // OP_CHECKSIG
    s
}

/// BIP143 sighash (SIGHASH_ALL, no ANYONECANPAY) for P2WPKH input `index`.
/// `script_code` is that input's [`p2wpkh_script_code`]; the spent value
/// comes from `tx.inputs[index].value` (same convention
/// `sighash::taproot_key_spend_sighash` uses). Only `index`'s own value and
/// script_code are consulted — BIP143's `hashPrevouts`/`hashSequence`
/// commit every input's outpoint and (fixed RBF) sequence, never their
/// amounts or scripts, so unlike BIP341 this needs no per-input scriptPubKey
/// array.
pub fn bip143_sighash(tx: &Transaction, index: usize, script_code: &[u8]) -> [u8; 32] {
    let mut prevouts = Vec::new();
    let mut sequences = Vec::new();
    for input in &tx.inputs {
        prevouts.extend_from_slice(&input.txid);
        prevouts.extend_from_slice(&input.vout.to_le_bytes());
        sequences.extend_from_slice(&0xffff_fffdu32.to_le_bytes()); // RBF, matches tx.rs
    }
    let mut outputs = Vec::new();
    for output in &tx.outputs {
        outputs.extend_from_slice(&output.value.to_le_bytes());
        write_varint(&mut outputs, output.script_pubkey.len() as u64);
        outputs.extend_from_slice(&output.script_pubkey);
    }
    let hash_prevouts = double_sha256(&prevouts);
    let hash_sequence = double_sha256(&sequences);
    let hash_outputs = double_sha256(&outputs);

    let input = &tx.inputs[index];
    let mut msg = Vec::with_capacity(156 + script_code.len());
    msg.extend_from_slice(&tx.version.to_le_bytes());
    msg.extend_from_slice(&hash_prevouts);
    msg.extend_from_slice(&hash_sequence);
    msg.extend_from_slice(&input.txid);
    msg.extend_from_slice(&input.vout.to_le_bytes());
    write_varint(&mut msg, script_code.len() as u64);
    msg.extend_from_slice(script_code);
    msg.extend_from_slice(&input.value.to_le_bytes());
    msg.extend_from_slice(&0xffff_fffdu32.to_le_bytes()); // this input's sequence
    msg.extend_from_slice(&hash_outputs);
    msg.extend_from_slice(&tx.lock_time.to_le_bytes());
    msg.extend_from_slice(&(SIGHASH_ALL as u32).to_le_bytes());

    double_sha256(&msg)
}

/// Sign input `index` as a P2WPKH spend (BIP143, SIGHASH_ALL): RFC6979
/// deterministic ECDSA, normalized to low-S, DER-encoded. `seckey` is the
/// RAW private key owning the P2WPKH address — unlike taproot, P2WPKH has
/// no output-key tweak. Returns the witness stack `[sig || 0x01, pubkey]`.
pub fn sign_p2wpkh_input(
    tx: &Transaction,
    index: usize,
    seckey: &[u8; 32],
) -> Result<Vec<Vec<u8>>, Error> {
    let signing_key =
        SigningKey::from_bytes(seckey.into()).map_err(|_| Error::InvalidPrivateKey)?;
    let pubkey: [u8; 33] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed SEC1 point is always 33 bytes");
    let pubkey_hash = hash160(&pubkey);
    let script_code = p2wpkh_script_code(&pubkey_hash);
    let sighash = bip143_sighash(tx, index, &script_code);

    let sig: Signature = signing_key
        .sign_prehash(&sighash)
        .map_err(|_| Error::Signing("ecdsa sign_prehash failed"))?;
    let sig = sig.normalize_s().unwrap_or(sig); // Bitcoin requires low-S

    let mut sig_bytes = sig.to_der().as_bytes().to_vec();
    sig_bytes.push(SIGHASH_ALL);
    Ok(vec![sig_bytes, pubkey.to_vec()])
}

/// One transaction input's signing key: taproot key-path (schnorr, already
/// tweaked) or P2WPKH (ECDSA, raw). The mixed shape a spending-wallet
/// funded note or sweep can produce (PLAN: a P2WPKH funding input is the
/// common case; a taproot input rides along when sweeping notebook dust
/// together with spending-wallet fee inputs).
pub enum InputKey<'a> {
    Taproot { tweaked_seckey: &'a [u8; 32] },
    P2wpkh { seckey: &'a [u8; 32] },
}

/// Sign EVERY input of `tx` per `keys[i]`, one pass: taproot inputs sign
/// schnorr against the BIP341 sighash (same as `tx.rs`'s builders), P2WPKH
/// inputs sign ECDSA against BIP143 above — the "sign-all-P2WPKH-inputs"
/// helper, generalized to mix with the existing taproot signing. `aux`
/// supplies BIP340 randomness for taproot inputs only.
///
/// `prevout_spks[i]` must be input `i`'s spent scriptPubKey for EVERY
/// input, taproot or not: BIP341 commits every input's scriptPubKey and
/// amount when signing ANY taproot input (`tx.inputs[i].value` supplies the
/// amounts), so a P2WPKH input's entry still has to be its real spk even
/// though that input's OWN BIP143 signature never reads this array.
pub fn sign_mixed_inputs(
    tx: &mut Transaction,
    prevout_spks: &[Vec<u8>],
    keys: &[InputKey],
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<(), Error> {
    if keys.len() != tx.inputs.len() || prevout_spks.len() != tx.inputs.len() {
        return Err(Error::Signing("keys/prevout_spks length != input count"));
    }
    let mut witnesses = Vec::with_capacity(tx.inputs.len());
    for (i, key) in keys.iter().enumerate() {
        let witness = match key {
            InputKey::Taproot { tweaked_seckey } => {
                let sighash = taproot_key_spend_sighash(tx, prevout_spks, i);
                let sig = schnorr_sign(tweaked_seckey, &sighash, &aux()?)?;
                vec![sig.to_vec()]
            }
            InputKey::P2wpkh { seckey } => sign_p2wpkh_input(tx, i, seckey)?,
        };
        witnesses.push(witness);
    }
    tx.witnesses = witnesses;
    Ok(())
}

