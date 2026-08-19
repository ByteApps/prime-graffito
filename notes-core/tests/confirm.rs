//! `notes_core::confirm::summarize_signed_tx` — the device's universal
//! "Confirm & sign" screen's byte-truth summarizer. Ported scenario-for-
//! scenario from the graffito desktop app's `app-core/src/confirm.rs` test module
//! (six classification scenarios) plus an `address_from_spk` round-trip
//! check, adapted to this crate's own decoder/address rendering instead of
//! `rust-bitcoin`. Integration test (not an inline `#[cfg(test)]` module)
//! mirroring the rest of this crate's convention (`roundtrip.rs`,
//! `mixed_tx.rs`, `wpkh_vectors.rs`, ...).

use std::collections::BTreeMap;

use notes_core::address::{address_from_spk, p2tr_script_pubkey, p2wpkh_script_pubkey, Recipient};
use notes_core::bundle::Identity;
use notes_core::confirm::{summarize_signed_tx, ConfirmCtx, PrevoutInfo};
use notes_core::envelope;
use notes_core::tx::{op_return_script, Transaction, TxOut, Utxo};
use notes_core::Network;

const NET: Network = Network::Mainnet;
const NOTEBOOK_SEED: [u8; 32] = [7u8; 32];
const BOB_SEED: [u8; 32] = [9u8; 32];
const STRANGER_SEED: [u8; 32] = [42u8; 32];

fn notebook_spk(seed: [u8; 32]) -> Vec<u8> {
    let id = Identity::from_app_seed(&seed).unwrap();
    p2tr_script_pubkey(&id.output_x)
}

fn addr_of(spk: &[u8]) -> String {
    address_from_spk(spk, NET).unwrap()
}

fn pnte_op_return(text: &str) -> Vec<u8> {
    let payload = envelope::encode_outputs(0, None, text.as_bytes(), 100_000).unwrap();
    op_return_script(&payload[0])
}

fn spending_spk(fill: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[fill; 20]);
    s
}

fn txout(value: u64, spk: Vec<u8>) -> TxOut {
    TxOut { value, script_pubkey: spk }
}

fn raw_hex(tx: &Transaction) -> String {
    hex::encode(tx.serialize_segwit())
}

fn prevout_key(txid_byte: u8, vout: u32) -> String {
    format!("{}:{vout}", hex::encode([txid_byte; 32]))
}

fn signed_txin(txid_byte: u8, vout: u32) -> Utxo {
    Utxo { txid: [txid_byte; 32], vout, value: 0 }
}

/// Build a syntactically-decodable segwit tx by hand (mirrors what a real
/// signer produces): our own RBF sequence (implied by `serialize_segwit`),
/// one dummy 64-byte witness item per input (decode doesn't verify
/// signatures — this module exists to label facts, not authenticate them).
fn make_tx(inputs: Vec<Utxo>, outputs: Vec<TxOut>) -> Transaction {
    let n = inputs.len();
    Transaction {
        version: 2,
        lock_time: 0,
        inputs,
        outputs,
        witnesses: (0..n).map(|_| vec![vec![0x11; 64]]).collect(),
    }
}

fn base_ctx(self_spks: Vec<Vec<u8>>, spending_spks: Vec<Vec<u8>>) -> ConfirmCtx {
    ConfirmCtx {
        network: NET,
        prevouts: BTreeMap::new(),
        self_spks,
        spending_spks,
        expected_change: None,
        recipient: None,
        recipient_name: None,
        recipients: Vec::new(),
        note_preview: None,
    }
}

/// 1 taproot input (known prevout) · OP_RETURN PNTE · self-dust 330 ·
/// change back to the same notebook → full classification, exact fee and
/// fee_line asserted.
#[test]
fn typical_note_tx_full_classification() {
    let spk_a = notebook_spk(NOTEBOOK_SEED);
    let tx = make_tx(
        vec![signed_txin(1, 0)],
        vec![
            txout(0, pnte_op_return("hello world")),
            txout(330, spk_a.clone()),
            txout(99_000, spk_a.clone()),
        ],
    );
    let vsize = tx.vsize() as u64;
    let hex_str = raw_hex(&tx);

    let mut ctx = base_ctx(vec![spk_a.clone()], vec![]);
    ctx.prevouts.insert(
        prevout_key(1, 0),
        PrevoutInfo { value: 100_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
    );

    let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
    assert_eq!(sum.txid, tx.txid_hex());
    assert_eq!(sum.vsize, vsize);

    assert_eq!(sum.inputs.len(), 1);
    assert_eq!(sum.inputs[0].title, addr_of(&spk_a));
    assert_eq!(sum.inputs[0].subtitle, "Notebook · Alice");
    assert_eq!(sum.inputs[0].amount, "100,000");
    assert_eq!(sum.inputs[0].kind, "input");

    assert_eq!(sum.outputs.len(), 3);
    assert_eq!(sum.outputs[0].kind, "note");
    assert_eq!(sum.outputs[0].title, "");
    assert_eq!(sum.outputs[0].subtitle, "OP_RETURN · PNTE note");
    assert_eq!(sum.outputs[0].amount, "");

    assert_eq!(sum.outputs[1].kind, "self");
    assert_eq!(sum.outputs[1].subtitle, "your notebook (keeps the note yours)");
    assert_eq!(sum.outputs[1].amount, "330");

    assert_eq!(sum.outputs[2].kind, "change");
    assert_eq!(sum.outputs[2].subtitle, "change · your notebook");
    assert_eq!(sum.outputs[2].amount, "99,000");

    assert_eq!(sum.total_in, Some(100_000));
    assert_eq!(sum.total_out, 99_330);
    let expected_fee = 100_000 - 99_330; // 670 -- no thousands separator needed
    assert_eq!(sum.fee, Some(expected_fee));
    let expected_rate = expected_fee as f64 / vsize as f64;
    assert_eq!(sum.fee_line, format!("{expected_fee} sats · {expected_rate:.1} sat/vB"));
    assert!(sum.warn.is_none());
}

/// Two input sources with different labels + change to the spending
/// wallet → both input subtitles surface and the change output is
/// classified "change · Spending wallet".
#[test]
fn mixed_inputs_and_spending_change() {
    let spk_a = notebook_spk(NOTEBOOK_SEED);
    let spend_spk = spending_spk(0xab);
    let tx = make_tx(
        vec![signed_txin(1, 0), signed_txin(2, 1)],
        vec![txout(0, pnte_op_return("mixed sources")), txout(90_000, spend_spk.clone())],
    );
    let hex_str = raw_hex(&tx);

    let mut ctx = base_ctx(vec![spk_a.clone(), spend_spk.clone()], vec![spend_spk.clone()]);
    ctx.prevouts.insert(
        prevout_key(1, 0),
        PrevoutInfo { value: 40_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
    );
    ctx.prevouts.insert(
        prevout_key(2, 1),
        PrevoutInfo { value: 60_000, address: None, source: "ColdBox".into() },
    );

    let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
    assert_eq!(sum.inputs.len(), 2);
    assert_eq!(sum.inputs[0].subtitle, "Notebook · Alice");
    assert_eq!(sum.inputs[1].subtitle, "ColdBox");
    // Unknown address on the ColdBox prevout falls back to the outpoint string.
    assert_eq!(sum.inputs[1].title, prevout_key(2, 1));

    let change_row = sum.outputs.iter().find(|o| o.kind == "change").expect("change output");
    assert_eq!(change_row.subtitle, "change · Spending wallet");
    assert_eq!(change_row.amount, "90,000");

    assert_eq!(sum.total_in, Some(100_000));
    assert_eq!(sum.fee, Some(10_000));
    assert!(sum.warn.is_none());
}

/// Directed note with a recipient + a gift amount → the recipient row
/// carries the contact name, not the generic label.
#[test]
fn directed_note_with_named_recipient() {
    let spk_a = notebook_spk(NOTEBOOK_SEED);
    let spk_bob = notebook_spk(BOB_SEED);
    let bob_addr = addr_of(&spk_bob);
    let tx = make_tx(
        vec![signed_txin(1, 0)],
        vec![
            txout(0, pnte_op_return("gift for bob")),
            txout(5_000, spk_bob.clone()),
            txout(94_500, spk_a.clone()),
        ],
    );
    let hex_str = raw_hex(&tx);

    let mut ctx = base_ctx(vec![spk_a.clone()], vec![]);
    ctx.recipient = Some(bob_addr.clone());
    ctx.recipient_name = Some("Bob".to_string());
    ctx.prevouts.insert(
        prevout_key(1, 0),
        PrevoutInfo { value: 100_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
    );

    let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
    let recipient_row = sum.outputs.iter().find(|o| o.kind == "recipient").expect("recipient output");
    assert_eq!(recipient_row.title, bob_addr);
    assert_eq!(recipient_row.subtitle, "Bob");
    assert_eq!(recipient_row.amount, "5,000");
    assert!(sum.warn.is_none());
}

/// Missing one input's prevout data → fee unknown, warn set.
#[test]
fn missing_prevout_makes_fee_unknown() {
    let spk_a = notebook_spk(NOTEBOOK_SEED);
    let tx = make_tx(
        vec![signed_txin(1, 0), signed_txin(2, 1)],
        vec![txout(0, pnte_op_return("partial data")), txout(50_000, spk_a.clone())],
    );
    let hex_str = raw_hex(&tx);

    let mut ctx = base_ctx(vec![spk_a.clone()], vec![]);
    ctx.prevouts.insert(
        prevout_key(1, 0),
        PrevoutInfo { value: 40_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
    );
    // input (2,1) intentionally left out of ctx.prevouts.

    let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
    assert_eq!(sum.total_in, None);
    assert_eq!(sum.fee, None);
    assert_eq!(sum.fee_line, "fee unknown - missing input data");
    assert!(sum.warn.is_some());
    assert_eq!(sum.inputs[1].amount, "?");
    assert_eq!(sum.inputs[1].subtitle, "outpoint · amount unknown");
}

/// An output paying an address we don't recognize is flagged, not
/// silently swallowed — the paranoid tripwire.
#[test]
fn foreign_output_flags_a_warning() {
    let spk_a = notebook_spk(NOTEBOOK_SEED);
    let spk_stranger = notebook_spk(STRANGER_SEED);
    let tx = make_tx(
        vec![signed_txin(1, 0)],
        vec![txout(0, pnte_op_return("uh oh")), txout(60_000, spk_stranger.clone())],
    );
    let hex_str = raw_hex(&tx);

    let mut ctx = base_ctx(vec![spk_a.clone()], vec![]);
    ctx.prevouts.insert(
        prevout_key(1, 0),
        PrevoutInfo { value: 100_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
    );

    let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
    let foreign_row = sum.outputs.iter().find(|o| o.kind == "other").expect("foreign output");
    assert_eq!(foreign_row.title, addr_of(&spk_stranger));
    assert_eq!(foreign_row.subtitle, "not one of your addresses");
    assert!(sum.warn.is_some());
    assert!(sum.warn.as_ref().unwrap().contains("doesn't recognize"));
}

/// Adversarial input never panics — it just errors.
#[test]
fn garbage_and_truncated_input_errs_without_panicking() {
    let ctx = base_ctx(vec![], vec![]);
    assert!(summarize_signed_tx("", &ctx).is_err());
    assert!(summarize_signed_tx("not hex at all", &ctx).is_err());
    assert!(summarize_signed_tx("deadbeef", &ctx).is_err());
    // Odd-length hex.
    assert!(summarize_signed_tx("abc", &ctx).is_err());
    // A varint claiming a huge input count with no bytes behind it — must
    // error, not allocate/panic.
    assert!(summarize_signed_tx("0200000001ff", &ctx).is_err());
    // A truncated, otherwise-valid-looking real tx.
    let spk_a = notebook_spk(NOTEBOOK_SEED);
    let tx = make_tx(vec![signed_txin(1, 0)], vec![txout(50_000, spk_a)]);
    let full = raw_hex(&tx);
    let truncated = &full[..full.len() / 2];
    assert!(summarize_signed_tx(truncated, &ctx).is_err());
}

/// `address_from_spk` renders P2TR + P2WPKH byte-identically to what
/// `Recipient::parse` accepts round-trip, on every network HRP.
#[test]
fn address_from_spk_round_trips_every_network() {
    for net in [Network::Mainnet, Network::Testnet4, Network::Signet, Network::Regtest] {
        let p2tr_spk = notebook_spk(NOTEBOOK_SEED);
        let addr = address_from_spk(&p2tr_spk, net).expect("p2tr renders");
        let parsed = Recipient::parse(net, &addr).unwrap();
        assert_eq!(parsed.spk, p2tr_spk, "p2tr round-trip on {net:?}");

        let p2wpkh_spk = p2wpkh_script_pubkey(&[0x5au8; 20]);
        let addr = address_from_spk(&p2wpkh_spk, net).expect("p2wpkh renders");
        let parsed = Recipient::parse(net, &addr).unwrap();
        assert_eq!(parsed.spk, p2wpkh_spk, "p2wpkh round-trip on {net:?}");
    }

    // Anything else (e.g. a bare OP_RETURN payload) renders to nothing.
    assert!(address_from_spk(&pnte_op_return("x"), NET).is_none());
}

/// Decode/confirm round-trip of a REAL anchored mixed build
/// (`build_note_tx_mixed_exact_anchored`, funding-unification's
/// dust-skip rule): notebook input present ⇒ no dust-to-self output ⇒
/// `summarize_signed_tx` shows no "self" row, only the notebook's "input"
/// row and a spending-wallet "change" row — proving the classifier needs
/// no special-casing for the anchored shape (it just decodes what's
/// actually on the wire).
#[test]
fn anchored_mixed_tx_round_trip_has_no_self_row() {
    use notes_core::address::p2wpkh_script_pubkey;
    use notes_core::keys::hash160;
    use notes_core::tx::{build_note_tx_mixed_exact_anchored, InputKind, MixedInput};
    use k256::ecdsa::SigningKey;

    fn wpkh_spk_of(seckey: &[u8; 32]) -> Vec<u8> {
        let sk = SigningKey::from_bytes(seckey.into()).unwrap();
        let pk: [u8; 33] = sk.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
        p2wpkh_script_pubkey(&hash160(&pk))
    }

    let notebook = Identity::from_app_seed(&NOTEBOOK_SEED).unwrap();
    let notebook_dust_spk = p2tr_script_pubkey(&notebook.output_x);
    let wpkh_sk = [0x51u8; 32];
    let wpkh_input_spk = wpkh_spk_of(&wpkh_sk);
    let change_sk = [0x52u8; 32];
    let change_spk = wpkh_spk_of(&change_sk);

    let inputs = vec![
        MixedInput {
            utxo: Utxo { txid: [1u8; 32], vout: 0, value: 1_000 },
            prevout_spk: notebook_dust_spk.clone(), // anchors the tx
            kind: InputKind::Taproot,
            seckey: notebook.tweaked_seckey,
        },
        MixedInput {
            utxo: Utxo { txid: [2u8; 32], vout: 1, value: 50_000 },
            prevout_spk: wpkh_input_spk.clone(),
            kind: InputKind::P2wpkh,
            seckey: wpkh_sk,
        },
    ];

    let note = build_note_tx_mixed_exact_anchored(
        &inputs,
        &[b"anchored confirm round-trip".to_vec()],
        None,
        0,
        &notebook_dust_spk,
        &change_spk,
        1.0,
        0,
        || Ok([0x77u8; 32]))
    .unwrap();

    let mut ctx = base_ctx(
        vec![notebook_dust_spk.clone(), wpkh_input_spk.clone(), change_spk.clone()],
        vec![wpkh_input_spk.clone(), change_spk.clone()],
    );
    ctx.prevouts.insert(
        prevout_key(1, 0),
        PrevoutInfo { value: 1_000, address: Some(addr_of(&notebook_dust_spk)), source: "Notebook · Alice".into() },
    );
    ctx.prevouts.insert(
        prevout_key(2, 1),
        PrevoutInfo { value: 50_000, address: Some(addr_of(&wpkh_input_spk)), source: "Spending wallet".into() },
    );

    let sum = summarize_signed_tx(&note.raw_hex, &ctx).unwrap();
    assert_eq!(sum.txid, note.txid_hex);

    // Notebook input row present.
    assert_eq!(sum.inputs.len(), 2);
    assert_eq!(sum.inputs[0].subtitle, "Notebook · Alice");
    assert_eq!(sum.inputs[0].title, addr_of(&notebook_dust_spk));

    // No dust-to-self output on the wire at all, so no "self" row.
    assert!(sum.outputs.iter().all(|o| o.kind != "self"), "anchored tx must have no self row");
    assert!(
        sum.outputs.iter().all(|o| o.title != addr_of(&notebook_dust_spk)),
        "no output should pay the notebook address when anchored"
    );

    // The change goes to the spending wallet, classified accordingly.
    let change_row = sum.outputs.iter().find(|o| o.kind == "change").expect("change output");
    assert_eq!(change_row.subtitle, "change · Spending wallet");
    assert_eq!(change_row.title, addr_of(&change_spk));

    assert_eq!(sum.total_in, Some(51_000));
    assert_eq!(sum.fee, Some(note.fee));
    assert!(sum.warn.is_none());
}
