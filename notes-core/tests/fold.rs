//! Pin tests for `notes_core::fold` (honest-fee-label prediction, ported
//! from the graffito desktop app's `app-core/src/mixed.rs`, 2026-07-19): every
//! predictor here must match what this crate's OWN builders actually do,
//! for the three shapes the device confirm gate and compose cost line
//! care about — a real WITH-CHANGE build, a real NO-CHANGE/FOLDED build,
//! and a real ANCHORED (notebook-input-present, dust-to-self skipped)
//! mixed build. See `mixed_tx.rs` for the sibling cross-checks of the
//! builders themselves.

use notes_core::address::{p2tr_script_pubkey, p2wpkh_script_pubkey};
use notes_core::fold::{notebook_vsize_no_change, predict_fold, predict_mixed_fold, predict_notebook_fold};
use notes_core::keys::hash160;
use notes_core::tx::{
    build_note_tx_exact, build_note_tx_mixed_exact_anchored, build_note_tx_with_change,
    estimate_vsize, estimate_vsize_mixed, InputKind, MixedInput, Utxo,
};
use notes_core::DUST_LIMIT;

use k256::ecdsa::SigningKey;

const AUX: [u8; 32] = [0x77; 32];
const NOTEBOOK_X: [u8; 32] = [0x11; 32];
const TAPROOT_SECKEY: [u8; 32] = [0x44; 32];

fn wpkh_seckey(byte: u8) -> [u8; 32] {
    let mut k = [0x22u8; 32];
    k[0] = byte;
    k
}

fn wpkh_spk(seckey: &[u8; 32]) -> Vec<u8> {
    let sk = SigningKey::from_bytes(seckey.into()).unwrap();
    let pk: [u8; 33] = sk.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
    p2wpkh_script_pubkey(&hash160(&pk))
}

/// WITH-CHANGE shape: a selection large enough to afford a discretionary
/// change output must predict `None` (no fold), matching a real build
/// that actually returns `change > 0`.
#[test]
fn predict_notebook_fold_none_when_change_affordable() {
    let payload_lens = vec![2usize]; // a tiny "hi" note, one chunk
    let change_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let rate = 1.0;
    let utxo = Utxo { txid: [9u8; 32], vout: 0, value: 100_000 };

    let built = build_note_tx_with_change(
        &[utxo],
        &NOTEBOOK_X,
        &[b"hi".to_vec()],
        None,
        0,
        None,
        rate,
        0,
        &TAPROOT_SECKEY,
        || Ok(AUX))
    .unwrap();
    assert!(built.change > 0, "a 100,000-sat coin must afford a change output");

    let vsize_wc = estimate_vsize(1, &payload_lens, None, true);
    let fold = predict_notebook_fold(100_000, 0, vsize_wc, change_spk.len(), rate);
    assert_eq!(fold, None, "an affordable change output must never predict a fold");
}

/// NO-CHANGE/FOLDED shape: a single 330-sat coin can't afford change AND
/// forces its entire remaining value into the fee (Sal's concrete
/// testnet4 example) — `predict_notebook_fold` must reproduce the exact
/// (nominal, folded) split the real build pays.
#[test]
fn predict_notebook_fold_matches_build_note_tx_exact() {
    let rate = 1.0;
    let change_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let payloads = vec![b"x".repeat(12)];
    let payload_lens = vec![12usize];
    let utxo = Utxo { txid: [3u8; 32], vout: 0, value: DUST_LIMIT };

    let built = build_note_tx_exact(
        &[utxo],
        &NOTEBOOK_X,
        &payloads,
        None,
        0,
        None,
        rate,
        0,
        &TAPROOT_SECKEY,
        || Ok(AUX))
    .unwrap();
    assert_eq!(built.change, 0, "the whole 330-sat coin must force the no-change fold shape");
    assert_eq!(built.fee, DUST_LIMIT, "the whole coin goes to the fee");

    let vsize_wc = estimate_vsize(1, &payload_lens, None, true);
    // Independent oracle: call estimate_vsize's own no-change branch
    // directly, proving notebook_vsize_no_change's Δ-shortcut is EXACT,
    // not an approximation.
    let vsize_nc_direct = estimate_vsize(1, &payload_lens, None, false);
    assert_eq!(notebook_vsize_no_change(vsize_wc, change_spk.len()), vsize_nc_direct);

    let (nominal, folded) =
        predict_notebook_fold(DUST_LIMIT, 0, vsize_wc, change_spk.len(), rate).expect("fold predicted");
    let fee_nc_direct = (vsize_nc_direct as f64 * rate).ceil() as u64;
    assert_eq!(nominal, fee_nc_direct);
    assert_eq!(nominal + folded, built.fee, "predicted split must equal the real built tx's fee");
}

/// ANCHORED (skip-dust) mixed shape: a notebook coin rides alongside a
/// spending-wallet coin, so `build_note_tx_mixed_exact_anchored` skips the
/// notebook dust-to-self output — and a selection too small to afford
/// change folds the leftover into the fee. `predict_mixed_fold` (called
/// the same way the device's coin-control cost line would: no dust in
/// `fixed_extra_lens`/`fixed_out`, matching the anchored condition) must
/// match the real build exactly.
#[test]
fn predict_mixed_fold_matches_anchored_build() {
    let rate = 3.0;
    let wpkh_sk = wpkh_seckey(5);
    let spending_spk = wpkh_spk(&wpkh_sk);
    let notebook_dust_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let change_spk = wpkh_spk(&wpkh_seckey(6));
    let payloads = vec![b"anchored fold pin".to_vec()];
    let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();

    // Deliberately small: a notebook coin (anchors the tx, dust skipped)
    // plus a tiny spending coin, too little left over for a P2WPKH change
    // output once the fee is paid.
    let inputs = vec![
        MixedInput {
            utxo: Utxo { txid: [1u8; 32], vout: 0, value: 200 },
            prevout_spk: notebook_dust_spk.clone(),
            kind: InputKind::Taproot,
            seckey: TAPROOT_SECKEY,
        },
        MixedInput {
            utxo: Utxo { txid: [2u8; 32], vout: 0, value: 400 },
            prevout_spk: spending_spk,
            kind: InputKind::P2wpkh,
            seckey: wpkh_sk,
        },
    ];
    let in_value: u64 = inputs.iter().map(|i| i.utxo.value).sum();

    let built = build_note_tx_mixed_exact_anchored(
        &inputs,
        &payloads,
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        rate,
        0,
        || Ok(AUX))
    .unwrap();
    assert_eq!(built.change, 0, "this tiny selection must fold, not leave a change output");
    // Anchored: no notebook-dust output at all, matching the input-anchored
    // skip condition (a notebook coin is among the inputs).
    assert!(
        built.tx.outputs.iter().all(|o| !(o.script_pubkey == notebook_dust_spk && o.value == DUST_LIMIT)),
        "an input-anchored build must skip the dust-to-self output"
    );

    let kinds = vec![InputKind::Taproot, InputKind::P2wpkh];
    let fixed_extra_lens: Vec<usize> = Vec::new(); // no recipient, no dust (anchored)
    let fold = predict_mixed_fold(&kinds, &payload_lens, &fixed_extra_lens, change_spk.len(), in_value, 0, rate)
        .expect("fold predicted");
    assert_eq!(fold.0 + fold.1, built.fee, "predicted split must equal the real anchored build's fee");

    // Cross-check against the raw estimator pair too, proving
    // `predict_mixed_fold` is just those two calls plus `predict_fold`.
    let vsize_wc = estimate_vsize_mixed(&kinds, &payload_lens, &[change_spk.len()]);
    let vsize_nc = estimate_vsize_mixed(&kinds, &payload_lens, &fixed_extra_lens);
    let fee_wc = (vsize_wc as f64 * rate).ceil() as u64;
    let fee_nc = (vsize_nc as f64 * rate).ceil() as u64;
    assert_eq!(predict_fold(in_value, 0, fee_wc, fee_nc, true), Some(fold));
}

/// The un-anchored mixed shape (pure spending-wallet funding, no notebook
/// input) DOES carry the notebook dust-to-self output — `predict_mixed_fold`
/// must include it in both `fixed_extra_lens` (vsize) and `fixed_out`
/// (value) to match, exactly like the device's coin-control preview does
/// (`dust_applies = sp_participates && n_notebook == 0`).
#[test]
fn predict_mixed_fold_matches_unanchored_dust_build() {
    let rate = 2.0;
    let wpkh_sk = wpkh_seckey(7);
    let spending_spk = wpkh_spk(&wpkh_sk);
    let notebook_dust_spk = p2tr_script_pubkey(&NOTEBOOK_X);
    let change_spk = wpkh_spk(&wpkh_seckey(8));
    let payloads = vec![b"unanchored".to_vec()];
    let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();

    let inputs = vec![MixedInput {
        utxo: Utxo { txid: [4u8; 32], vout: 0, value: 700 },
        prevout_spk: spending_spk,
        kind: InputKind::P2wpkh,
        seckey: wpkh_sk,
    }];
    let in_value = 700u64;

    let built = build_note_tx_mixed_exact_anchored(
        &inputs,
        &payloads,
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        rate,
        0,
        || Ok(AUX))
    .unwrap();
    assert_eq!(built.change, 0, "700 sats must be too little for change once dust+fee are paid");
    assert!(
        built.tx.outputs.iter().any(|o| o.script_pubkey == notebook_dust_spk && o.value == DUST_LIMIT),
        "no notebook input means the dust-to-self anchor must still be emitted"
    );

    let kinds = vec![InputKind::P2wpkh];
    let fixed_extra_lens = vec![notebook_dust_spk.len()];
    let fold =
        predict_mixed_fold(&kinds, &payload_lens, &fixed_extra_lens, change_spk.len(), in_value, DUST_LIMIT, rate)
            .expect("fold predicted");
    assert_eq!(fold.0 + fold.1, built.fee, "predicted split must equal the real build's fee");
}

/// Exact fit (leftover == 0) must never read as a "fold" — there's no
/// honest leftover to explain, the nominal fee simply consumes the whole
/// remainder.
#[test]
fn predict_fold_none_on_exact_fit() {
    // in_value covers fixed_out + fee_no_change with nothing left over.
    assert_eq!(predict_fold(1_000, 100, 2_000, 900, true), None);
}
