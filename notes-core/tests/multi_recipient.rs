//! Multi-recipient directed notes (envelope `FLAG_MULTI`, 2..=255
//! recipients): tx assembly (tx.rs), the content-key hybrid compose path
//! (bundle.rs), the scanner's multi-recipient decode (including liberal
//! decoding of malformed/truncated payloads), `reply_set`, and a
//! rust-bitcoin cross-check of a signed multi-recipient tx.

use notes_core::address::{p2tr_script_pubkey, Recipient};
use notes_core::bundle::{
    compose_directed_note_multi_exact, compose_directed_note_multi_with_change,
    compose_directed_note_with_change_amount, extract_notes, extract_notes_watch, reply_set,
    Identity, OnchainTx, RecoveredNote, SyncBundle,
};
use notes_core::envelope::{self, FLAG_DIRECTED, FLAG_MULTI, FLAG_PRIVATE};
use notes_core::tx::{
    build_note_tx_multi_exact, build_note_tx_multi_with_change, build_note_tx_with_change,
    estimate_vsize_multi, op_return_payload, Utxo,
};
use notes_core::Network;

const AUX: [u8; 32] = [0x42; 32];
const NET: Network = Network::Regtest;
const CONTENT_KEY: [u8; 32] = [0x66; 32];

fn identity(byte: u8) -> Identity {
    Identity::from_app_seed(&[byte; 32]).unwrap()
}

fn utxos() -> Vec<Utxo> {
    vec![
        Utxo { txid: [1u8; 32], vout: 0, value: 200_000 },
        Utxo { txid: [2u8; 32], vout: 1, value: 25_000 },
    ]
}

fn recipient_of(id: &Identity) -> Recipient {
    Recipient::parse(NET, &id.address(NET)).unwrap()
}

// ---------------------------------------------------------------------
// 1. tx.rs: build_note_tx_multi_with_change / _exact.
// ---------------------------------------------------------------------

#[test]
fn multi_tx_output_order_and_single_entry_delegation() {
    let sender = identity(7);
    let b = identity(9);
    let c = identity(11);
    let payloads = vec![b"multi note".to_vec()];

    // 1-entry DELEGATES to build_note_tx_with_change (byte-identical, not
    // just coincidentally equal bytes).
    let single_via_multi = build_note_tx_multi_with_change(
        &utxos(),
        &sender.output_x,
        &payloads,
        &[(p2tr_script_pubkey(&b.output_x), 500)],
        None,
        2.0,
        0,
        &sender.tweaked_seckey,
        || Ok(AUX))
    .unwrap();
    let single_direct = build_note_tx_with_change(
        &utxos(),
        &sender.output_x,
        &payloads,
        Some(&p2tr_script_pubkey(&b.output_x)),
        500,
        None,
        2.0,
        0,
        &sender.tweaked_seckey,
        || Ok(AUX))
    .unwrap();
    assert_eq!(single_via_multi.raw_hex, single_direct.raw_hex);
    assert_eq!(single_via_multi.tx, single_direct.tx);

    // 2-recipient: OP_RETURN, then recipients in slice order, then change.
    let recipients =
        vec![(p2tr_script_pubkey(&b.output_x), 400u64), (p2tr_script_pubkey(&c.output_x), 600u64)];
    let note = build_note_tx_multi_with_change(
        &utxos(),
        &sender.output_x,
        &payloads,
        &recipients,
        None,
        2.0,
        0,
        &sender.tweaked_seckey,
        || Ok(AUX))
    .unwrap();
    assert_eq!(note.tx.outputs.len(), 4); // OP_RETURN, b, c, change
    assert_eq!(note.tx.outputs[0].script_pubkey[0], 0x6a);
    assert_eq!(note.tx.outputs[1].script_pubkey, recipients[0].0);
    assert_eq!(note.tx.outputs[1].value, 400);
    assert_eq!(note.tx.outputs[2].script_pubkey, recipients[1].0);
    assert_eq!(note.tx.outputs[2].value, 600);
    assert_eq!(note.sent, 1000);

    // Estimator matches the real built tx.
    let op_return_lens: Vec<usize> = note
        .tx
        .outputs
        .iter()
        .filter_map(|o| op_return_payload(&o.script_pubkey))
        .map(<[u8]>::len)
        .collect();
    let recipient_lens: Vec<usize> = recipients.iter().map(|(spk, _)| spk.len()).collect();
    let est = estimate_vsize_multi(note.tx.inputs.len(), &op_return_lens, &recipient_lens, true);
    assert_eq!(est, note.vsize);
}

#[test]
fn multi_tx_below_dust_amount_rejected() {
    let sender = identity(7);
    let b = identity(9);
    let c = identity(11);
    let recipients = vec![
        (p2tr_script_pubkey(&b.output_x), 329u64), // below DUST_LIMIT
        (p2tr_script_pubkey(&c.output_x), 500u64),
    ];
    let err = build_note_tx_multi_with_change(
        &utxos(),
        &sender.output_x,
        &[b"x".to_vec()],
        &recipients,
        None,
        2.0,
        0,
        &sender.tweaked_seckey,
        || Ok(AUX))
    .unwrap_err();
    assert!(matches!(err, notes_core::Error::Envelope(_)));
}

#[test]
fn multi_tx_recipient_count_bounds() {
    let sender = identity(7);
    // Zero recipients: rejected.
    let err = build_note_tx_multi_with_change(
        &utxos(),
        &sender.output_x,
        &[b"x".to_vec()],
        &[],
        None,
        2.0,
        0,
        &sender.tweaked_seckey,
        || Ok(AUX))
    .unwrap_err();
    assert!(matches!(err, notes_core::Error::Envelope(_)));
}

#[test]
fn multi_tx_exact_coin_control() {
    let sender = identity(7);
    let b = identity(9);
    let c = identity(11);
    let coins = utxos();
    let recipients =
        vec![(p2tr_script_pubkey(&b.output_x), 400u64), (p2tr_script_pubkey(&c.output_x), 500u64)];
    let exact = build_note_tx_multi_exact(
        &coins,
        &sender.output_x,
        &[b"x".to_vec()],
        &recipients,
        None,
        2.0,
        0,
        &sender.tweaked_seckey,
        || Ok(AUX))
    .unwrap();
    assert_eq!(exact.tx.inputs.len(), 2, "coin control spends every provided coin");
}

// ---------------------------------------------------------------------
// 2. rust-bitcoin cross-check of a signed multi-recipient tx.
// ---------------------------------------------------------------------

#[test]
fn multi_tx_rust_bitcoin_cross_check() {
    use bitcoin::consensus::encode::deserialize as btc_deser;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut as BtcTxOut};

    let sender = identity(7);
    let b = identity(9);
    let c = identity(11);
    let d = identity(13);
    let recipients = vec![
        (p2tr_script_pubkey(&b.output_x), 400u64),
        (p2tr_script_pubkey(&c.output_x), 500u64),
        (p2tr_script_pubkey(&d.output_x), 600u64),
    ];
    let coins = utxos();
    let note = build_note_tx_multi_with_change(
        &coins,
        &sender.output_x,
        &[b"cross-check".to_vec()],
        &recipients,
        None,
        2.0,
        0,
        &sender.tweaked_seckey,
        || Ok(AUX))
    .unwrap();

    let raw = hex::decode(&note.raw_hex).unwrap();
    let btx: bitcoin::Transaction = btc_deser(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), note.txid_hex);
    assert_eq!(btx.vsize(), note.vsize);
    assert_eq!(btx.output.len(), note.tx.outputs.len());
    for (bo, oo) in btx.output.iter().zip(&note.tx.outputs) {
        assert_eq!(bo.value.to_sat(), oo.value);
        assert_eq!(bo.script_pubkey.to_bytes(), oo.script_pubkey);
    }

    let spk = ScriptBuf::from_bytes(p2tr_script_pubkey(&sender.output_x));
    // Reconstruct the prevouts from the tx's ACTUAL (auto-selected) inputs,
    // not the full candidate coin list — the builder may not have needed
    // every offered coin.
    let prevouts: Vec<BtcTxOut> = note
        .tx
        .inputs
        .iter()
        .map(|i| BtcTxOut { value: Amount::from_sat(i.value), script_pubkey: spk.clone() })
        .collect();
    let secp = Secp256k1::verification_only();
    let output_key = XOnlyPublicKey::from_slice(&sender.output_x).unwrap();
    let mut cache = SighashCache::new(&btx);
    for index in 0..btx.input.len() {
        let sighash = cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        secp.verify_schnorr(
            &Signature::from_slice(&note.tx.witnesses[index][0]).unwrap(),
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .expect("multi-recipient note input must verify under BIP340/341");
    }
}

// ---------------------------------------------------------------------
// 3. bundle.rs: compose_directed_note_multi_* + scanner extraction.
// ---------------------------------------------------------------------

fn sender_bundle(note: &notes_core::tx::NoteTx, output_addrs: &[String]) -> SyncBundle {
    SyncBundle {
        network: "regtest".into(),
        notes_onchain: vec![OnchainTx {
            txid: note.txid_hex.clone(),
            height: Some(100),
            blocktime: Some(1_700_000_000),
            spends_from_self: true,
            payloads: note
                .tx
                .outputs
                .iter()
                .filter_map(|o| op_return_payload(&o.script_pubkey))
                .map(hex::encode)
                .collect(),
            pays_self: false,
            sender: None,
            author_candidates: Vec::new(),
            recipient: None,
            input_prevout_spks: Vec::new(),
            output_addrs: output_addrs.to_vec(),
            first_input_outpoint: note.spent_outpoints.first().map(|(txid, vout)| {
                notes_core::bundle::format_outpoint(txid, *vout)
            }),
        }],
        ..Default::default()
    }
}

fn recipient_bundle(
    note: &notes_core::tx::NoteTx,
    output_addrs: &[String],
    sender_addr: &str,
) -> SyncBundle {
    SyncBundle {
        network: "regtest".into(),
        notes_onchain: vec![OnchainTx {
            txid: note.txid_hex.clone(),
            height: Some(100),
            blocktime: Some(1_700_000_000),
            spends_from_self: false,
            payloads: note
                .tx
                .outputs
                .iter()
                .filter_map(|o| op_return_payload(&o.script_pubkey))
                .map(hex::encode)
                .collect(),
            pays_self: true,
            sender: Some(sender_addr.to_string()),
            author_candidates: Vec::new(),
            recipient: None,
            input_prevout_spks: Vec::new(),
            output_addrs: output_addrs.to_vec(),
            first_input_outpoint: note.spent_outpoints.first().map(|(txid, vout)| {
                notes_core::bundle::format_outpoint(txid, *vout)
            }),
        }],
        ..Default::default()
    }
}

#[test]
fn compose_scan_roundtrip_private_multi() {
    let a = identity(7);
    let b = identity(9);
    let c = identity(11);
    let recipients = vec![(recipient_of(&b), 400u64), (recipient_of(&c), 500u64)];
    let note = compose_directed_note_multi_with_change(
        &a,
        &utxos(),
        "sealed for B and C",
        true,
        &recipients,
        CONTENT_KEY,
        None,
        80,
        2.0,
        0,
        || Ok(AUX))
    .unwrap();

    // Wire check: FLAG_MULTI + FLAG_DIRECTED + FLAG_PRIVATE, count=2 in the header.
    let op_return =
        note.tx.outputs.iter().find_map(|o| op_return_payload(&o.script_pubkey)).unwrap();
    let (flags, multi_count, _offset) = envelope::parse_header(op_return).unwrap();
    assert_eq!(flags, FLAG_DIRECTED | FLAG_MULTI | FLAG_PRIVATE);
    assert_eq!(multi_count, Some(2));

    let output_addrs = vec![b.address(NET), c.address(NET)];

    // Sender A re-reads its own note.
    let a_notes = extract_notes(&sender_bundle(&note, &output_addrs), &a, NET);
    assert_eq!(a_notes.len(), 1);
    assert_eq!(a_notes[0].text.as_deref(), Some("sealed for B and C"));
    assert_eq!(a_notes[0].recipients, output_addrs);
    assert!(!a_notes[0].received);
    // Legacy singular field stays populated (first recipient) for
    // single-recipient-callers compatibility, own notes only.
    assert_eq!(a_notes[0].recipient, Some(output_addrs[0].clone()));

    // B decrypts via its own pairwise key.
    let b_notes = extract_notes(&recipient_bundle(&note, &output_addrs, &a.address(NET)), &b, NET);
    assert_eq!(b_notes.len(), 1);
    assert_eq!(b_notes[0].text.as_deref(), Some("sealed for B and C"));
    assert!(b_notes[0].received);
    assert_eq!(b_notes[0].sender.as_deref(), Some(a.address(NET).as_str()));
    assert_eq!(b_notes[0].recipients, output_addrs);
    // Legacy singular field stays None for a RECEIVED note (same rule as
    // the single-recipient path) — only `recipients` (plural) is populated.
    assert_eq!(b_notes[0].recipient, None);

    // C decrypts too.
    let c_notes = extract_notes(&recipient_bundle(&note, &output_addrs, &a.address(NET)), &c, NET);
    assert_eq!(c_notes[0].text.as_deref(), Some("sealed for B and C"));

    // A foreign identity cannot decrypt.
    let stranger = identity(99);
    let stranger_notes =
        extract_notes(&recipient_bundle(&note, &output_addrs, &a.address(NET)), &stranger, NET);
    assert_eq!(stranger_notes[0].text, None);

    // Watch-only: structure visible, body stays sealed.
    let watch_notes = extract_notes_watch(&recipient_bundle(&note, &output_addrs, &a.address(NET)), NET);
    assert_eq!(watch_notes[0].text, None);
    assert_eq!(watch_notes[0].recipients, output_addrs);
}

#[test]
fn compose_scan_roundtrip_public_multi() {
    let a = identity(7);
    let b = identity(9);
    let c = identity(11);
    let d = identity(13);
    let recipients =
        vec![(recipient_of(&b), 330u64), (recipient_of(&c), 330u64), (recipient_of(&d), 330u64)];
    let note = compose_directed_note_multi_with_change(
        &a,
        &utxos(),
        "postcard to three",
        false,
        &recipients,
        CONTENT_KEY,
        None,
        80,
        2.0,
        0,
        || Ok(AUX))
    .unwrap();
    let output_addrs = vec![b.address(NET), c.address(NET), d.address(NET)];

    for id in [&b, &c, &d] {
        let notes = extract_notes(&recipient_bundle(&note, &output_addrs, &a.address(NET)), id, NET);
        assert_eq!(notes[0].text.as_deref(), Some("postcard to three"));
        assert_eq!(notes[0].recipients, output_addrs);
    }

    // Public text needs no keys — watch-only sees it too.
    let watch_notes = extract_notes_watch(&recipient_bundle(&note, &output_addrs, &a.address(NET)), NET);
    assert_eq!(watch_notes[0].text.as_deref(), Some("postcard to three"));
}

/// Public (no AEAD, so no random-nonce ciphertext variance) single-entry
/// call: exact hex-for-hex delegation check, including the dedup path
/// (two entries for the same address collapse to one before delegation).
#[test]
fn single_recipient_via_multi_api_is_byte_identical_public() {
    let a = identity(7);
    let b = identity(9);
    let via_multi = compose_directed_note_multi_with_change(
        &a,
        &utxos(),
        "hi",
        false,
        &[(recipient_of(&b), 500)],
        CONTENT_KEY,
        None,
        80,
        2.0,
        0,
        || Ok(AUX))
    .unwrap();
    let direct = compose_directed_note_with_change_amount(
        &a, &utxos(), "hi", false, &recipient_of(&b), 500, None, 80, 2.0, 0, || Ok(AUX))
    .unwrap();
    assert_eq!(via_multi.raw_hex, direct.raw_hex);
    assert_eq!(via_multi.tx, direct.tx);

    // Two entries for the SAME address dedupe down to one and match too.
    let deduped = compose_directed_note_multi_with_change(
        &a,
        &utxos(),
        "hi",
        false,
        &[(recipient_of(&b), 500), (recipient_of(&b), 500)],
        CONTENT_KEY,
        None,
        80,
        2.0,
        0,
        || Ok(AUX))
    .unwrap();
    assert_eq!(deduped.raw_hex, direct.raw_hex);
}

/// Private single-entry call: `crypt::seal_aad` draws its nonce from the
/// OS RNG (not the `aux` BIP340 closure), so two independent private
/// composes can never be byte-for-byte identical even when they delegate
/// to the exact same function — this checks the delegation happened
/// (no FLAG_MULTI bit; same output shape/order/scripts/values) instead of
/// raw-hex equality.
#[test]
fn single_recipient_via_multi_api_delegates_for_private_too() {
    let a = identity(7);
    let b = identity(9);
    let via_multi = compose_directed_note_multi_with_change(
        &a,
        &utxos(),
        "hi",
        true,
        &[(recipient_of(&b), 500)],
        CONTENT_KEY,
        None,
        80,
        2.0,
        0,
        || Ok(AUX))
    .unwrap();
    let direct = compose_directed_note_with_change_amount(
        &a, &utxos(), "hi", true, &recipient_of(&b), 500, None, 80, 2.0, 0, || Ok(AUX))
    .unwrap();

    let op_return =
        via_multi.tx.outputs.iter().find_map(|o| op_return_payload(&o.script_pubkey)).unwrap();
    let (_flags, multi_count, _offset) = envelope::parse_header(op_return).unwrap();
    assert_eq!(multi_count, None, "1-entry compose must never set FLAG_MULTI");
    assert_eq!(via_multi.tx.outputs.len(), direct.tx.outputs.len());
    assert_eq!(via_multi.sent, direct.sent);
    assert_eq!(via_multi.change, direct.change);
    // Recipient + change scripts/values line up (only the sealed OP_RETURN
    // ciphertext differs, by nonce).
    for (a_out, b_out) in via_multi.tx.outputs[1..].iter().zip(&direct.tx.outputs[1..]) {
        assert_eq!(a_out.script_pubkey, b_out.script_pubkey);
        assert_eq!(a_out.value, b_out.value);
    }
}

#[test]
fn compose_directed_note_multi_exact_spends_all_given_coins() {
    let a = identity(7);
    let b = identity(9);
    let c = identity(11);
    let coins = utxos();
    let recipients = vec![(recipient_of(&b), 400u64), (recipient_of(&c), 500u64)];
    let note = compose_directed_note_multi_exact(
        &a,
        &coins,
        "coin control",
        false,
        &recipients,
        CONTENT_KEY,
        None,
        80,
        2.0,
        0,
        || Ok(AUX))
    .unwrap();
    assert_eq!(note.tx.inputs.len(), 2);
}

fn non_taproot_recipient() -> Recipient {
    Recipient { address: String::new(), spk: [0x00, 0x14].iter().chain([0x11; 20].iter()).copied().collect(), p2tr_x: None }
}

#[test]
fn multi_private_requires_taproot_recipients() {
    let a = identity(7);
    let b = identity(9);
    let recipients = vec![(recipient_of(&b), 400u64), (non_taproot_recipient(), 500u64)];
    let err = compose_directed_note_multi_with_change(
        &a, &utxos(), "hi", true, &recipients, CONTENT_KEY, None, 80, 2.0, 0, || Ok(AUX))
    .unwrap_err();
    assert!(matches!(err, notes_core::Error::RecipientNotTaproot));
}

#[test]
fn multi_public_allows_non_taproot_recipients() {
    let a = identity(7);
    let b = identity(9);
    let recipients = vec![(recipient_of(&b), 400u64), (non_taproot_recipient(), 500u64)];
    let note = compose_directed_note_multi_with_change(
        &a, &utxos(), "hi", false, &recipients, CONTENT_KEY, None, 80, 2.0, 0, || Ok(AUX))
    .unwrap();
    assert_eq!(note.sent, 900);
}

// ---------------------------------------------------------------------
// 4. Decode-liberal: count=1 accepted, count=0 rejected, truncated wraps
//    rejected — hand-crafted payloads (never produced by the composer,
//    which only ever emits FLAG_MULTI for count >= 2) exercising the
//    scanner directly.
// ---------------------------------------------------------------------

fn hand_crafted_bundle(
    flags: u8,
    multi_count: Option<u8>,
    body: &[u8],
    output_addrs: Vec<String>,
    sender_addr: &str,
) -> SyncBundle {
    let payload = envelope::encode_outputs(flags, multi_count, body, 100_000).unwrap();
    hand_crafted_bundle_raw(payload, output_addrs, sender_addr)
}

/// Like [`hand_crafted_bundle`], but takes already-assembled raw OP_RETURN
/// payload bytes — for shapes `envelope::encode_outputs` refuses to build
/// at all (validated on construction, e.g. a zero multi-count), which must
/// therefore be hand-assembled to prove the DECODER'S liberal rejection
/// rather than the encoder's refusal.
fn hand_crafted_bundle_raw(
    payloads: Vec<Vec<u8>>,
    output_addrs: Vec<String>,
    sender_addr: &str,
) -> SyncBundle {
    SyncBundle {
        network: "regtest".into(),
        notes_onchain: vec![OnchainTx {
            txid: "aa".repeat(32),
            height: Some(1),
            blocktime: Some(1_700_000_000),
            spends_from_self: false,
            payloads: payloads.iter().map(hex::encode).collect(),
            pays_self: true,
            sender: Some(sender_addr.to_string()),
            author_candidates: Vec::new(),
            recipient: None,
            input_prevout_spks: Vec::new(),
            output_addrs,
            first_input_outpoint: None,
        }],
        ..Default::default()
    }
}

#[test]
fn decode_liberal_count_one_accepted() {
    let a = identity(7);
    let b = identity(9);
    let body = b"solo via multi flag".to_vec();
    let flags = FLAG_DIRECTED | FLAG_MULTI;
    let bundle =
        hand_crafted_bundle(flags, Some(1), &body, vec![b.address(NET)], &a.address(NET));
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].text.as_deref(), Some("solo via multi flag"));
    assert_eq!(notes[0].recipients, vec![b.address(NET)]);
}

#[test]
fn decode_liberal_count_zero_rejected() {
    let a = identity(7);
    let b = identity(9);
    // envelope::encode_outputs refuses to build a zero multi-count header
    // at all, so it's hand-assembled byte-for-byte: PNTE + '1' + flags(2
    // hex) + count "00" + ' ' + body.
    let flags = FLAG_DIRECTED | FLAG_MULTI;
    let mut payload = b"PNTE1".to_vec();
    payload.extend_from_slice(format!("{flags:02x}00 ").as_bytes());
    payload.extend_from_slice(b"nobody");
    let bundle = hand_crafted_bundle_raw(vec![payload], vec![b.address(NET)], &a.address(NET));
    let notes = extract_notes(&bundle, &b, NET);
    assert!(
        notes.is_empty(),
        "a count=0 header is undecodable at the envelope level — the tx never registers as a note at all"
    );
}

#[test]
fn decode_liberal_truncated_wraps_rejected() {
    let a = identity(7);
    let b = identity(9);
    let c = identity(11);
    // Header claims 2 recipients (2*72 = 144 wrap bytes expected) but the
    // body only has room for a fraction of one wrap.
    let body = vec![0u8; 10];
    let flags = FLAG_DIRECTED | FLAG_MULTI | FLAG_PRIVATE;
    let bundle = hand_crafted_bundle(
        flags,
        Some(2),
        &body,
        vec![b.address(NET), c.address(NET)],
        &a.address(NET),
    );
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].text, None, "truncated wraps must be undecodable, not panic");
}

// ---------------------------------------------------------------------
// 5. reply_set
// ---------------------------------------------------------------------

#[test]
fn reply_set_unit() {
    let a = identity(7);
    let b = identity(9);
    let c = identity(11);
    let note = RecoveredNote {
        id: "aa".repeat(32),
        height: Some(1),
        blocktime: Some(1),
        private: true,
        directed: true,
        received: true,
        sender: Some(a.address(NET)),
        recipient: Some(b.address(NET)),
        recipients: vec![b.address(NET), c.address(NET)],
        text: Some("hi".into()),
        pq_flags: 0,
        locked: None,
    };
    // I'm B: sender A plus the OTHER recipient C, not myself.
    let set = reply_set(&note, &b.address(NET));
    assert_eq!(set, vec![a.address(NET), c.address(NET)]);

    // Legacy single-recipient note (recipients empty, recipient set):
    // falls back to the singular field.
    let legacy = RecoveredNote { recipients: Vec::new(), ..note.clone() };
    let set_legacy = reply_set(&legacy, &a.address(NET)); // I'm the sender A
    assert_eq!(set_legacy, vec![b.address(NET)]);

    // Self-note: no sender, no recipients -> empty.
    let self_note = RecoveredNote {
        sender: None,
        recipient: None,
        recipients: Vec::new(),
        received: false,
        directed: false,
        ..note
    };
    assert!(reply_set(&self_note, &a.address(NET)).is_empty());
}

/// `sealed_note_payloads_multi` (the PSBT/mixed-path payload primitive)
/// emits byte-identical payloads to the canonical self-contained composer
/// for the same inputs — public compared byte-for-byte (deterministic);
/// private proven by both recipients decrypting the payload bodies via the
/// scanner. One unique address must delegate to `sealed_note_payloads`
/// byte-identically (public), and dedupe collapses duplicates.
#[test]
fn sealed_payloads_multi_matches_composer_and_delegates() {
    use notes_core::bundle::{sealed_note_payloads, sealed_note_payloads_multi};
    let a = identity(7);
    let b = identity(9);
    let c = identity(11);
    let rb = Recipient::parse(NET, &b.address(NET)).unwrap();
    let rc = Recipient::parse(NET, &c.address(NET)).unwrap();
    // Arbitrary fixed outpoint — this test seals and opens by hand (not
    // through a real signed tx), so any 36 bytes work as long as the seal
    // and open sides agree, matching how a real PSBT-path caller would
    // thread its own chosen inputs' first outpoint.
    let outpoint = [0x24u8; 36];
    let key = [0x42u8; 32];

    // Public 2-recipient: byte-identical to the composer's OP_RETURNs.
    let (payloads, spks) = sealed_note_payloads_multi(
        &a, "psbt-path multi", false,
        &[Recipient::parse(NET, &b.address(NET)).unwrap(), Recipient::parse(NET, &c.address(NET)).unwrap()],
        outpoint, key, 100_000,
    ).unwrap();
    assert_eq!(spks, vec![rb.spk.clone(), rc.spk.clone()]);
    let utxos = vec![notes_core::tx::Utxo { txid: [3u8; 32], vout: 0, value: 1_000_000 }];
    let recipients = vec![
        (Recipient::parse(NET, &b.address(NET)).unwrap(), notes_core::DUST_LIMIT),
        (Recipient::parse(NET, &c.address(NET)).unwrap(), notes_core::DUST_LIMIT),
    ];
    let note = compose_directed_note_multi_with_change(
        &a, &utxos, "psbt-path multi", false, &recipients, key, None, 100_000, 1.0,
        0,
        || Ok([0u8; 32])).unwrap();
    let composer_payloads: Vec<Vec<u8>> = note
        .tx.outputs.iter()
        .filter_map(|o| notes_core::tx::op_return_payload(&o.script_pubkey))
        .map(<[u8]>::to_vec)
        .collect();
    assert_eq!(payloads, composer_payloads, "PSBT-path payloads must match the composer byte-for-byte");

    // Private 2-recipient: FLAG_MULTI|PRIVATE framing, both recipients decrypt.
    let (ppayloads, pspks) = sealed_note_payloads_multi(
        &a, "sealed for both", true,
        &[Recipient::parse(NET, &b.address(NET)).unwrap(), Recipient::parse(NET, &c.address(NET)).unwrap()],
        outpoint, key, 100_000,
    ).unwrap();
    assert_eq!(pspks.len(), 2);
    let (flags, multi_count, _offset) = envelope::parse_header(&ppayloads[0]).unwrap();
    assert_eq!(flags, FLAG_DIRECTED | FLAG_MULTI | FLAG_PRIVATE);
    assert_eq!(multi_count, Some(2));
    let decoded = envelope::decode_note(&ppayloads).unwrap();
    let wraps: Vec<Vec<u8>> = decoded.body[..2 * notes_core::dm::WRAP_LEN]
        .chunks(notes_core::dm::WRAP_LEN).map(<[u8]>::to_vec).collect();
    let sealed = &decoded.body[2 * notes_core::dm::WRAP_LEN..];
    for (i, reader) in [(0usize, &b), (1usize, &c)] {
        let pt = notes_core::dm::open_received_multi(
            &reader.tweaked_seckey, &reader.output_x, &a.output_x, &outpoint, &wraps, sealed, Some(i),
        ).unwrap();
        assert_eq!(pt, b"sealed for both");
    }

    // One unique address (incl. via dupes) delegates byte-identically (public).
    let (single, sspks) = sealed_note_payloads_multi(
        &a, "solo", false,
        &[Recipient::parse(NET, &b.address(NET)).unwrap(), Recipient::parse(NET, &b.address(NET)).unwrap()],
        outpoint, key, 100_000,
    ).unwrap();
    let (legacy, lspk) = sealed_note_payloads(&a, "solo", false, Some(&rb), outpoint, 100_000).unwrap();
    assert_eq!(single, legacy);
    assert_eq!(sspks, vec![lspk.unwrap()]);
}
