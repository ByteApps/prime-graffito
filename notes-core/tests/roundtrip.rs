//! Envelope/AEAD round-trips, fee-estimator exactness, full compose→scan
//! round-trips, and the rust-bitcoin cross-check of our transaction
//! serialization, sighash and signatures.

use notes_core::address::Recipient;
use notes_core::bundle::{
    compose_directed_note, compose_directed_note_multi_with_change, compose_note,
    compose_note_exact, compose_note_with_change, estimate_note_cost,
    extract_notes, extract_notes_multi, extract_notes_multi_deduped, extract_notes_watch,
    Identity, OnchainTx, SyncBundle,
};
use notes_core::crypt::{self, SEAL_OVERHEAD};
use notes_core::envelope;
use notes_core::tx::{estimate_vsize_multi, op_return_payload, Utxo};
use notes_core::Network;

const APP_SEED: [u8; 32] = [7u8; 32];
const AUX: [u8; 32] = [0x42; 32];
const NET: Network = Network::Regtest;

fn identity() -> Identity {
    Identity::from_app_seed(&APP_SEED).unwrap()
}

/// Second party for directed-note tests.
fn identity_b() -> Identity {
    Identity::from_app_seed(&[9u8; 32]).unwrap()
}

fn utxos() -> Vec<Utxo> {
    vec![
        Utxo { txid: [1u8; 32], vout: 0, value: 60_000 },
        Utxo { txid: [2u8; 32], vout: 1, value: 25_000 },
        Utxo { txid: [3u8; 32], vout: 0, value: 1_000 },
    ]
}

#[test]
fn envelope_roundtrip_boundaries() {
    // 80-byte policy → 8-byte header on the first output, 72 raw bytes on
    // every later one. Exercise exact-fit, ±1.
    for len in [1usize, 67, 68, 69, 72, 73, 136, 137, 200] {
        let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let payloads = envelope::encode_outputs(0, None, &body, 80).unwrap();
        assert!(payloads.iter().all(|c| c.len() <= 80), "len {len}");
        let decoded = envelope::decode_note(&payloads).unwrap();
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.multi_count, None);
        assert_eq!(decoded.body, body, "len {len}");
    }
}

#[test]
fn envelope_rejects_bad_shapes() {
    assert!(envelope::encode_outputs(0, None, b"", 80).is_err());
    assert!(envelope::encode_outputs(0, None, b"x", 7).is_err()); // smaller than the 8-byte header
    // > 255 outputs
    let big = vec![0u8; 80 * 256];
    assert!(envelope::encode_outputs(0, None, &big, 80).is_err());
    // foreign payloads: wrong magic, too short, wrong version, bad hex flags,
    // missing separator.
    assert!(envelope::decode_note(&[b"nonsense-not-pnte".to_vec()]).is_none());
    assert!(envelope::decode_note(&[b"PNTE".to_vec()]).is_none());
    assert!(envelope::decode_note(&[b"PNTE2 hi".to_vec()]).is_none(), "wrong version");
    assert!(envelope::decode_note(&[b"PNTE1zz hi".to_vec()]).is_none(), "non-hex flags");
    assert!(envelope::decode_note(&[b"PNTE100hi".to_vec()]).is_none(), "missing separator");
    // Reserved FLAG_CONT bit set (0x08) -> undecodable today.
    assert!(envelope::decode_note(&[b"PNTE108 1/1 hi".to_vec()]).is_none());
    // 0x10 is FLAG_PW (pq.rs, additive 2026) without the FLAG_PRIVATE|
    // FLAG_DIRECTED it requires -> still undecodable, same as before FLAG_PW
    // existed (this exact input used to test an unassigned bit; it now
    // exercises FLAG_PW's own validity rule instead — see envelope.rs's
    // pq bits tests for coverage of an actually-unassigned bit).
    assert!(envelope::decode_note(&[b"PNTE110 hi".to_vec()]).is_none());
    // FLAG_MULTI without FLAG_DIRECTED -> undecodable.
    assert!(envelope::decode_note(&[b"PNTE0401 hi".to_vec()]).is_none());
    // Empty payload list.
    assert!(envelope::decode_note(&[]).is_none());
}

#[test]
fn seal_open_roundtrip_and_auth() {
    let key = [3u8; 32];
    let outpoint = [0x11u8; 36];
    let blob = crypt::seal(&key, &outpoint, "hola ₿".as_bytes()).unwrap();
    assert_eq!(blob.len(), "hola ₿".len() + SEAL_OVERHEAD);
    assert_eq!(crypt::open(&key, &outpoint, &blob).unwrap(), "hola ₿".as_bytes());
    // wrong key / wrong outpoint (AAD) / tampered byte all fail
    assert!(crypt::open(&[4u8; 32], &outpoint, &blob).is_err());
    assert!(crypt::open(&key, &[9u8; 36], &blob).is_err());
    let mut bad = blob.clone();
    bad[30] ^= 1;
    assert!(crypt::open(&key, &outpoint, &bad).is_err());
}

#[test]
fn identity_is_deterministic() {
    let a = identity();
    let b = identity();
    assert_eq!(a.output_x, b.output_x);
    assert_eq!(a.enc_key, b.enc_key);
    assert!(a.address(notes_core::Network::Regtest).starts_with("bcrt1p"));
    // different seed → different everything
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    assert_ne!(a.output_x, c.output_x);
    assert_ne!(a.enc_key, c.enc_key);
}

/// The keystroke estimator must match reality exactly: predicted vsize ==
/// actual vsize of the built+signed tx (change present).
#[test]
fn cost_estimator_is_exact() {
    let id = identity();
    for (text_len, private, max_or) in
        [(5usize, false, 80usize), (5, true, 80), (200, true, 80), (200, false, 10_000), (2_000, true, 10_000)]
    {
        let text: String = "x".repeat(text_len);
        let note = compose_note(
            &id,
            &utxos(),
            &text,
            private,
            max_or,
            2.0,
            0,
            || Ok(AUX))
        .unwrap();
        assert!(note.change > 0, "fixture should produce change");
        let n_inputs = note.tx.inputs.len();
        let (_chunks, est_vsize) =
            estimate_note_cost(text_len, private, max_or, n_inputs, None).unwrap();
        assert_eq!(est_vsize, note.vsize, "text_len={text_len} private={private} max={max_or}");
    }

    // Directed notes: the recipient dust output (34-byte P2TR / 22-byte
    // P2WPKH spk) must be modeled byte-exactly too.
    let b = identity_b();
    let p2tr = Recipient::parse(NET, &b.address(NET)).unwrap();
    let p2wpkh = Recipient { address: String::new(), spk: vec![0x00, 0x14].into_iter().chain([0x11; 20]).collect(), p2tr_x: None };
    for (text_len, private, recipient) in
        [(5usize, true, &p2tr), (200, true, &p2tr), (40, false, &p2wpkh)]
    {
        let text: String = "y".repeat(text_len);
        let note = compose_directed_note(
            &id, &utxos(), &text, private, recipient, 80, 2.0, 0, || Ok(AUX))
        .unwrap();
        assert!(note.change > 0, "fixture should produce change");
        assert_eq!(note.sent, 330);
        let chunks = note
            .tx
            .outputs
            .iter()
            .filter(|o| o.script_pubkey.first() == Some(&0x6a))
            .count();
        // Output order: OP_RETURNs, dust to recipient, change.
        assert_eq!(note.tx.outputs[chunks].value, 330);
        assert_eq!(note.tx.outputs[chunks].script_pubkey, recipient.spk);
        assert_eq!(note.tx.outputs.len(), chunks + 2);
        let (_c, est_vsize) = estimate_note_cost(
            text_len,
            private,
            80,
            note.tx.inputs.len(),
            Some(recipient.spk.len()),
        )
        .unwrap();
        assert_eq!(est_vsize, note.vsize, "directed text_len={text_len} private={private}");
    }

    // Multi-recipient directed notes (FLAG_MULTI, 2..=255 recipients):
    // `estimate_vsize_multi` generalizes to N recipient output lengths.
    // Lengths are pulled from the ACTUALLY built tx (not hand-computed)
    // so this stays byte-exact regardless of chunking/wrap-length details.
    let big_utxos = vec![Utxo { txid: [9u8; 32], vout: 0, value: 20_000_000 }];
    for n in [2usize, 3, 255] {
        for private in [false, true] {
            let recipients: Vec<(Recipient, u64)> = (0..n)
                .map(|i| {
                    let peer = Identity::from_app_seed(&[(i as u8).wrapping_add(100); 32]).unwrap();
                    (Recipient::parse(NET, &peer.address(NET)).unwrap(), notes_core::DUST_LIMIT)
                })
                .collect();
            let note = compose_directed_note_multi_with_change(
                &id,
                &big_utxos,
                "multi shape check",
                private,
                &recipients,
                [0x66; 32],
                None,
                100_000, // single OP_RETURN, avoids chunk-count limits at n=255
                2.0,
                0,
                || Ok(AUX))
            .unwrap();
            assert!(note.change > 0, "fixture should produce change for n={n} private={private}");
            let op_return_lens: Vec<usize> = note
                .tx
                .outputs
                .iter()
                .filter_map(|o| op_return_payload(&o.script_pubkey))
                .map(<[u8]>::len)
                .collect();
            let recipient_lens: Vec<usize> = recipients.iter().map(|(r, _)| r.spk.len()).collect();
            let est_vsize = estimate_vsize_multi(
                note.tx.inputs.len(),
                &op_return_lens,
                &recipient_lens,
                true,
            );
            assert_eq!(est_vsize, note.vsize, "multi n={n} private={private}");
        }
    }
}

#[test]
fn insufficient_funds_is_reported() {
    let id = identity();
    let poor = vec![Utxo { txid: [1; 32], vout: 0, value: 50 }];
    let err = compose_note(&id, &poor, "hello", false, 80, 2.0, 0, || Ok(AUX));
    assert!(err.is_err());
    // 200 sats CAN fund a minimal no-change note at 2 sat/vB (residue
    // below dust folds into the fee) — that's intended behavior.
    let tight = vec![Utxo { txid: [1; 32], vout: 0, value: 200 }];
    let note = compose_note(&id, &tight, "hello", false, 80, 2.0, 0, || Ok(AUX)).unwrap();
    assert_eq!(note.change, 0);
    assert_eq!(note.fee, 200);
}

/// Build a bundle the way the companion would: one OnchainTx per note tx,
/// payloads pulled from the OP_RETURN outputs.
fn bundle_from_txs(txs: &[(&notes_core::tx::NoteTx, bool, Option<u64>)]) -> SyncBundle {
    SyncBundle {
        network: "regtest".into(),
        notes_onchain: txs
            .iter()
            .map(|(note, self_spend, height)| OnchainTx {
                txid: note.txid_hex.clone(),
                height: *height,
                blocktime: height.map(|h| 1_700_000_000 + h),
                spends_from_self: *self_spend,
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
                output_addrs: Vec::new(),
                first_input_outpoint: note.spent_outpoints.first().map(|(txid, vout)| {
                    notes_core::bundle::format_outpoint(txid, *vout)
                }),
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn compose_scan_roundtrip_public_private_chunked() {
    let id = identity();
    let long_text = "multi-chunk note ".repeat(20); // 340 bytes → 6 chunks at 80
    let pub_note =
        compose_note(&id, &utxos(), "public hello ₿", false, 80, 1.0, 0, || Ok(AUX))
            .unwrap();
    let priv_note =
        compose_note(&id, &utxos(), "secret plans", true, 80, 1.0, 0, || Ok(AUX))
            .unwrap();
    let chunked =
        compose_note(&id, &utxos(), &long_text, true, 80, 1.0, 0, || Ok(AUX)).unwrap();
    assert!(
        chunked.tx.outputs.iter().filter(|o| o.script_pubkey.first() == Some(&0x6a)).count() > 1
    );

    let bundle = bundle_from_txs(&[
        (&pub_note, true, Some(100)),
        (&priv_note, true, Some(101)),
        (&chunked, true, Some(102)),
    ]);
    let notes = extract_notes(&bundle, &id, NET);
    assert_eq!(notes.len(), 3);
    assert_eq!(notes[0].text.as_deref(), Some("public hello ₿"));
    assert!(!notes[0].private);
    assert!(!notes[0].received && !notes[0].directed);
    assert_eq!(notes[1].text.as_deref(), Some("secret plans"));
    assert!(notes[1].private);
    assert_eq!(notes[2].text.as_deref(), Some(long_text.as_str()));
}

#[test]
fn scan_ignores_foreign_and_spoofed() {
    let id = identity();
    let note =
        compose_note(&id, &utxos(), "mine", true, 80, 1.0, 0, || Ok(AUX)).unwrap();
    // Same payloads, neither spending from nor paying us → pure spoof,
    // ignored entirely (the acceptance rule stays additive).
    let spoofed = bundle_from_txs(&[(&note, false, Some(50))]);
    assert!(extract_notes(&spoofed, &id, NET).is_empty());

    // A private note sealed under a DIFFERENT seed: envelope parses but
    // text must be None (foreign ciphertext).
    let other = identity_b();
    let foreign =
        compose_note(&other, &utxos(), "not yours", true, 80, 1.0, 0, || Ok(AUX))
            .unwrap();
    let bundle = bundle_from_txs(&[(&foreign, true, Some(60))]);
    let notes = extract_notes(&bundle, &id, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].text.is_none());
}

/// The exact spoof crypt.rs's uniform AAD rule (2026-08-11 orchestrator
/// review) exists to close: an attacker copies the sealed OP_RETURN bytes
/// of my own private self-note — verbatim, same key would still open it —
/// out of the original tx into a NEW tx that merely PAYS my address, hoping
/// my secret text surfaces attributed to them as a "received" note. Since
/// the AAD binds the ORIGINAL tx's first-input outpoint, a copy riding on
/// a different tx (therefore a different first input) must fail to
/// authenticate — never decrypt, never misattribute.
#[test]
fn self_note_replay_into_a_pays_me_tx_does_not_spoof() {
    let id = identity();
    let attacker = identity_b();
    let mine = compose_note(&id, &utxos(), "my private secret", true, 80, 1.0, 0, || Ok(AUX))
        .unwrap();

    // The legitimate scan: own note, decrypts under its real outpoint.
    let legit = bundle_from_txs(&[(&mine, true, Some(100))]);
    let legit_notes = extract_notes(&legit, &id, NET);
    assert_eq!(legit_notes.len(), 1);
    assert_eq!(legit_notes[0].text.as_deref(), Some("my private secret"));

    // The attack: the SAME sealed payload bytes, riding a DIFFERENT tx that
    // pays my address (a different first-input outpoint — different funder,
    // different coin). Same key, same ciphertext; only the outpoint differs.
    let copied_payloads: Vec<String> = mine
        .tx
        .outputs
        .iter()
        .filter_map(|o| op_return_payload(&o.script_pubkey))
        .map(hex::encode)
        .collect();
    let spoof_tx = OnchainTx {
        txid: "bb".repeat(32),
        height: Some(101),
        blocktime: Some(1_700_000_101),
        spends_from_self: false,
        payloads: copied_payloads,
        pays_self: true,
        sender: Some(attacker.address(NET)),
        author_candidates: Vec::new(),
        recipient: None,
        input_prevout_spks: Vec::new(),
        output_addrs: Vec::new(),
        first_input_outpoint: Some(notes_core::bundle::format_outpoint(&[0x99u8; 32], 7)),
    };
    let spoofed = SyncBundle {
        network: "regtest".into(),
        notes_onchain: vec![spoof_tx],
        ..Default::default()
    };
    let notes = extract_notes(&spoofed, &id, NET);
    assert_eq!(notes.len(), 1, "still registers as SOME note (structurally valid PNTE header)");
    assert!(
        notes[0].text.is_none(),
        "the copied ciphertext must NOT decrypt under the new tx's different outpoint"
    );
}

#[test]
fn dm_shared_key_is_symmetric() {
    use notes_core::dm;
    let a = identity();
    let b = identity_b();
    let ab = dm::ecdh_shared_x(&a.tweaked_seckey, &b.output_x).unwrap();
    let ba = dm::ecdh_shared_x(&b.tweaked_seckey, &a.output_x).unwrap();
    // The tweaked scalars may be negated relative to their lifted points —
    // x-only must erase all four parity combinations.
    assert_eq!(ab, ba, "static-static ECDH must be symmetric over real tweaked keys");
    assert_eq!(dm::dm_key(&ab), dm::dm_key(&ba));

    // A third party derives something else entirely.
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    assert_ne!(dm::ecdh_shared_x(&c.tweaked_seckey, &b.output_x).unwrap(), ab);

    // AAD binds the outpoint at the dm layer (PLAN-pnte-redesign.md).
    let outpoint = [0xAAu8; 36];
    let wrong_outpoint = [0xBBu8; 36];
    let blob =
        dm::seal_directed(&a.tweaked_seckey, &a.output_x, &b.output_x, &outpoint, b"psst")
            .unwrap();
    assert_eq!(
        dm::open_received(&b.tweaked_seckey, &b.output_x, &a.output_x, &outpoint, &blob)
            .unwrap(),
        b"psst"
    );
    assert!(dm::open_received(&b.tweaked_seckey, &b.output_x, &a.output_x, &wrong_outpoint, &blob)
        .is_err());
}

/// A → B, public: B sees a received note with text and sender; A's own
/// scan shows the same note as sent-to-B.
#[test]
fn compose_directed_public_roundtrip() {
    let a = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "hello bob, love alice", false, &to_b, 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    // B's bundle view: tx pays B but does not spend from B.
    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(a.address(NET));
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    let n = &notes[0];
    assert!(n.received && n.directed && !n.private);
    assert_eq!(n.text.as_deref(), Some("hello bob, love alice"));
    assert_eq!(n.sender.as_deref(), Some(a.address(NET).as_str()));

    // A's own view: spends from self, recipient recorded from the vout.
    let mut own = bundle_from_txs(&[(&note, true, Some(100))]);
    own.notes_onchain[0].recipient = Some(b.address(NET));
    let notes = extract_notes(&own, &a, NET);
    assert_eq!(notes.len(), 1);
    assert!(!notes[0].received && notes[0].directed);
    assert_eq!(notes[0].recipient.as_deref(), Some(b.address(NET).as_str()));
    assert_eq!(notes[0].text.as_deref(), Some("hello bob, love alice"));
}

/// Watch-only scan: identical structure to the keyed scan — same notes,
/// origins, senders/recipients, public text — but every private body stays
/// sealed (text: None), including own self-notes.
#[test]
fn watch_scan_matches_keyed_scan_minus_private_text() {
    let a = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();

    let pub_note =
        compose_note(&a, &utxos(), "public hello", false, 80, 1.0, 0, || Ok(AUX))
            .unwrap();
    let priv_note =
        compose_note(&a, &utxos(), "secret plans", true, 80, 1.0, 0, || Ok(AUX))
            .unwrap();
    let sent_priv = compose_directed_note(
        &a, &utxos(), "for bob only", true, &to_b, 80, 1.0, 0, || Ok(AUX))
    .unwrap();
    let from_b = compose_directed_note(
        &b, &utxos(), "hi alice", false, &Recipient::parse(NET, &a.address(NET)).unwrap(), 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    // A's address history as the companion would bundle it.
    let mut bundle = bundle_from_txs(&[
        (&pub_note, true, Some(100)),
        (&priv_note, true, Some(101)),
        (&sent_priv, true, Some(102)),
        (&from_b, false, Some(103)),
    ]);
    bundle.notes_onchain[2].recipient = Some(b.address(NET));
    bundle.notes_onchain[3].pays_self = true;
    bundle.notes_onchain[3].sender = Some(b.address(NET));

    let keyed = extract_notes(&bundle, &a, NET);
    let watch = extract_notes_watch(&bundle, NET);
    assert_eq!(keyed.len(), 4);
    assert_eq!(watch.len(), keyed.len());
    for (w, k) in watch.iter().zip(&keyed) {
        assert_eq!(w.id, k.id);
        assert_eq!(w.height, k.height);
        assert_eq!(w.private, k.private);
        assert_eq!(w.directed, k.directed);
        assert_eq!(w.received, k.received);
        assert_eq!(w.sender, k.sender);
        assert_eq!(w.recipient, k.recipient);
        // The one permitted difference: private bodies never decrypt.
        if k.private {
            assert!(w.text.is_none(), "watch scan must not decrypt {}", w.id);
        } else {
            assert_eq!(w.text, k.text);
        }
    }
    // The keyed scan DID read the private ones — the comparison is real.
    assert_eq!(keyed[1].text.as_deref(), Some("secret plans"));
    assert_eq!(keyed[2].text.as_deref(), Some("for bob only"));
}

/// A → B, private: B decrypts via reciprocal ECDH; A re-derives the key
/// from the dust-output address (post-wipe recovery); a third identity
/// cannot read it.
#[test]
fn compose_directed_private_roundtrip() {
    let a = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "for bob's eyes only", true, &to_b, 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(a.address(NET));
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].received && notes[0].directed && notes[0].private);
    assert_eq!(notes[0].text.as_deref(), Some("for bob's eyes only"));

    // Sender wipe-recovery: A reads its own sent note from bare chain data.
    let mut own = bundle_from_txs(&[(&note, true, Some(100))]);
    own.notes_onchain[0].recipient = Some(b.address(NET));
    let notes = extract_notes(&own, &a, NET);
    assert_eq!(notes[0].text.as_deref(), Some("for bob's eyes only"));

    // A third identity presented with the same tx gets ciphertext only.
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    let mut leaked = bundle_from_txs(&[(&note, false, Some(100))]);
    leaked.notes_onchain[0].pays_self = true;
    leaked.notes_onchain[0].sender = Some(a.address(NET));
    let notes = extract_notes(&leaked, &c, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].text.is_none(), "not addressed to C — must stay sealed");
}

/// Externally-funded directed-private note: the tx is funded and signed by a
/// third-party wallet (F), so the first taproot input is F, not the author A.
/// A's key rides along only as a dust-to-self output surfaced in
/// `author_candidates`. B must still decrypt by trying the candidate keys and
/// attribute the note to A — never to the funder F. A wrong candidate never
/// spuriously authenticates.
#[test]
fn externally_funded_directed_private_decodes_via_candidate() {
    let a = identity(); // author
    let b = identity_b(); // recipient
    let f = Identity::from_app_seed(&[0x11u8; 32]).unwrap(); // external funder
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "paid by cold storage", true, &to_b, 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    // B's view of an EXTERNALLY funded tx: pays B, does NOT spend from B, and
    // the first-input sender is the funder F. A's key is present only as a
    // candidate (the dust-to-self output the composer adds for discoverability).
    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(f.address(NET));
    bundle.notes_onchain[0].author_candidates =
        vec![f.address(NET), a.address(NET), b.address(NET)];
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].received && notes[0].directed && notes[0].private);
    assert_eq!(notes[0].text.as_deref(), Some("paid by cold storage"));
    // Attributed to the real author A, not the funder F.
    assert_eq!(notes[0].sender.as_deref(), Some(a.address(NET).as_str()));

    // Legacy bundle (only the funder as sender, no candidates) must NOT decrypt
    // — proving the candidate set is precisely what enables external funding.
    let mut legacy = bundle_from_txs(&[(&note, false, Some(100))]);
    legacy.notes_onchain[0].pays_self = true;
    legacy.notes_onchain[0].sender = Some(f.address(NET));
    let notes = extract_notes(&legacy, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].text.is_none(), "no candidate → funder key cannot decrypt");

    // Wrong-but-taproot candidates never spuriously authenticate (AAD/AEAD).
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    let mut wrong = bundle_from_txs(&[(&note, false, Some(100))]);
    wrong.notes_onchain[0].pays_self = true;
    wrong.notes_onchain[0].sender = Some(f.address(NET));
    wrong.notes_onchain[0].author_candidates = vec![f.address(NET), c.address(NET)];
    let notes = extract_notes(&wrong, &b, NET);
    assert!(notes[0].text.is_none(), "wrong candidates must fail the AAD");
}

/// Author-side recovery of an EXTERNALLY-FUNDED directed-private note. The
/// author's tx does not spend from them (a funder paid), so a rescan sees it as
/// "received" — but open_sent with the recipient candidate (the note's dust
/// output) restores it to the author's own notebook: not received, recipient set.
#[test]
fn externally_funded_author_recovers_own_directed_private() {
    let a = identity(); // author
    let b = identity_b(); // recipient
    let f = Identity::from_app_seed(&[0x11u8; 32]).unwrap(); // funder
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "my own words, externally paid", true, &to_b, 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    // A's rescan of the externally-funded tx: it pays A (dust-to-self) but does
    // NOT spend from A; the input sender is the funder; candidates include B.
    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(f.address(NET));
    bundle.notes_onchain[0].author_candidates = vec![f.address(NET), b.address(NET)];
    let notes = extract_notes(&bundle, &a, NET);
    assert_eq!(notes.len(), 1);
    assert!(!notes[0].received, "author's own note must not read as received");
    assert_eq!(notes[0].recipient.as_deref(), Some(b.address(NET).as_str()));
    assert_eq!(notes[0].text.as_deref(), Some("my own words, externally paid"));
}

/// The 68-byte AAD binds the sender: attributing the same sealed body to a
/// different sender address must fail decryption, not yield wrong text.
#[test]
fn directed_aad_binds_direction_and_sender() {
    let a = identity();
    let b = identity_b();
    let c = Identity::from_app_seed(&[8u8; 32]).unwrap();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "authentic", true, &to_b, 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    let mut spoofed = bundle_from_txs(&[(&note, false, Some(100))]);
    spoofed.notes_onchain[0].pays_self = true;
    spoofed.notes_onchain[0].sender = Some(c.address(NET)); // lie about the author
    let notes = extract_notes(&spoofed, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].text.is_none(), "spoofed sender must fail the AAD, not decrypt");
}

/// Received acceptance is additive: pays-me PNTE surfaces as received
/// (never own); neither-from-nor-paying stays ignored (covered again here
/// with a directed note for completeness).
#[test]
fn received_acceptance_is_additive() {
    let a = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &a, &utxos(), "delivered", false, &to_b, 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    // pays_self missing (old bundle) → tx contributes nothing at B.
    let old_style = bundle_from_txs(&[(&note, false, Some(100))]);
    assert!(extract_notes(&old_style, &b, NET).is_empty());

    // pays_self set → received, and never classified as own.
    let mut bundle = bundle_from_txs(&[(&note, false, Some(100))]);
    bundle.notes_onchain[0].pays_self = true;
    bundle.notes_onchain[0].sender = Some(a.address(NET));
    let notes = extract_notes(&bundle, &b, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].received);
}

/// Two unrelated txs — one own, one received — scanned in the same bundle
/// must stay two separate notes. PLAN-pnte-redesign.md retires the old
/// note_id×origin bucketing this used to stress (a note's id IS its txid,
/// unique by construction, so no two distinct notes could ever collide
/// into one bucket anymore); kept as basic own/received separation
/// coverage.
#[test]
fn own_and_received_notes_stay_separate_entries() {
    let a = identity();
    let b = identity_b();
    let mine =
        compose_note(&a, &utxos(), "my own words", false, 80, 1.0, 0, || Ok(AUX)).unwrap();
    let to_a = Recipient::parse(NET, &a.address(NET)).unwrap();
    let attack = compose_directed_note(
        &b, &utxos(), "gotcha?", false, &to_a, 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    let mut bundle = bundle_from_txs(&[(&mine, true, Some(100)), (&attack, false, Some(101))]);
    bundle.notes_onchain[1].pays_self = true;
    bundle.notes_onchain[1].sender = Some(b.address(NET));
    let notes = extract_notes(&bundle, &a, NET);
    assert_eq!(notes.len(), 2, "own and received notes must stay separate");
    let own = notes.iter().find(|n| !n.received).unwrap();
    assert_eq!(own.text.as_deref(), Some("my own words"), "own note must survive intact");
    let recv = notes.iter().find(|n| n.received).unwrap();
    assert_eq!(recv.text.as_deref(), Some("gotcha?"));
}

#[test]
fn private_directed_requires_p2tr_recipient() {
    let a = identity();
    let v0 = Recipient {
        address: "fake".into(),
        spk: {
            let mut s = vec![0x00, 0x14];
            s.extend_from_slice(&[0x11; 20]);
            s
        },
        p2tr_x: None,
    };
    let err = compose_directed_note(
        &a, &utxos(), "secret", true, &v0, 80, 1.0, 0, || Ok(AUX));
    assert!(matches!(err, Err(notes_core::Error::RecipientNotTaproot)));
    // Public to a v0 address is fine.
    compose_directed_note(&a, &utxos(), "postcard", false, &v0, 80, 1.0, 0, || Ok(AUX))
        .unwrap();
}

#[test]
fn decode_scanned_roundtrip() {
    use notes_core::bundle::{decode_scanned, SCAN_MAGIC};
    let json = r#"{"network":"regtest","tip_height":7}"#;
    // CNB1 + deflate-raw (what the companion's CompressionStream emits).
    let mut blob = SCAN_MAGIC.to_vec();
    blob.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(json.as_bytes(), 6));
    assert_eq!(decode_scanned(&blob).unwrap(), json);
    // Plain JSON QR tolerated.
    assert_eq!(decode_scanned(json.as_bytes()).unwrap(), json);
    // Garbage rejected.
    assert!(decode_scanned(b"CNB1notdeflate").is_err());
    assert!(decode_scanned(b"hello world").is_err());
    assert!(decode_scanned(b"").is_err());
}

/// Idempotency: importing overlapping bundles converges (dedupe by chunk).
#[test]
fn scan_import_is_idempotent() {
    let id = identity();
    let note =
        compose_note(&id, &utxos(), "once only", true, 80, 1.0, 0, || Ok(AUX)).unwrap();
    let mut bundle = bundle_from_txs(&[(&note, true, Some(10))]);
    let dup = bundle.notes_onchain[0].clone();
    bundle.notes_onchain.push(dup); // overlapping incremental import
    let notes = extract_notes(&bundle, &id, NET);
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].text.as_deref(), Some("once only"));

    // Same for a RECEIVED directed note duplicated across bundles.
    let b = identity_b();
    let to_me = Recipient::parse(NET, &id.address(NET)).unwrap();
    let sent = compose_directed_note(
        &b, &utxos(), "dm once", true, &to_me, 80, 1.0, 0, || Ok(AUX))
    .unwrap();
    let mut rb = bundle_from_txs(&[(&sent, false, Some(11))]);
    rb.notes_onchain[0].pays_self = true;
    rb.notes_onchain[0].sender = Some(b.address(NET));
    let dup = rb.notes_onchain[0].clone();
    rb.notes_onchain.push(dup);
    let received = extract_notes(&rb, &id, NET);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].text.as_deref(), Some("dm once"));
}

#[test]
fn directed_note_custom_gift_amount() {
    use notes_core::bundle::compose_directed_note_with_change_amount;
    use notes_core::DUST_LIMIT;

    let sender = identity_b();
    let recip = identity();
    let to_recip = Recipient::parse(NET, &recip.address(NET)).unwrap();

    // Default directed note sends exactly dust to the recipient.
    let dust_note = compose_directed_note(
        &sender, &utxos(), "hi", false, &to_recip, 80, 1.0, 0, || Ok(AUX))
    .unwrap();
    assert_eq!(dust_note.sent, DUST_LIMIT, "default gift is dust");

    // A custom gift amount lands verbatim in the recipient output, and the fee
    // math balances: inputs = fee + gift + change.
    let gift = 50_000u64;
    let gift_note = compose_directed_note_with_change_amount(
        &sender, &utxos(), "happy birthday", false, &to_recip, gift, None, 80, 1.0,
        0,
        || Ok(AUX))
    .unwrap();
    assert_eq!(gift_note.sent, gift, "gift amount reaches the recipient output");
    let inputs_total: u64 = gift_note.tx.inputs.iter().map(|i| i.value).sum();
    assert_eq!(inputs_total, gift_note.fee + gift_note.sent + gift_note.change);

    // The recipient can still read the note (delivery/index unaffected).
    let mut rb = bundle_from_txs(&[(&gift_note, false, Some(20))]);
    rb.notes_onchain[0].pays_self = true;
    rb.notes_onchain[0].sender = Some(sender.address(NET));
    let received = extract_notes(&rb, &recip, NET);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].text.as_deref(), Some("happy birthday"));

    // Below dust is rejected.
    let err = compose_directed_note_with_change_amount(
        &sender, &utxos(), "too small", false, &to_recip, DUST_LIMIT - 1, None, 80,
        1.0, 0, || Ok(AUX));
    assert!(err.is_err(), "gift below dust must be rejected");
}

#[test]
fn address_decode_matches_rust_bitcoin() {
    use std::str::FromStr;
    // Any-network v0 + v1 decodes must equal rust-bitcoin's scriptPubKey.
    for (net, btc_net, addr) in [
        (
            notes_core::Network::Signet,
            bitcoin::Network::Signet,
            "tb1q2ylq48ne37ng9clds23xjcrxp8hmn707j5vpyk", // P2WPKH (testnet HRP)
        ),
        (
            notes_core::Network::Mainnet,
            bitcoin::Network::Bitcoin,
            "bc1p548gt356p9jrhr6p5hfvd83km5zus936hlcfyzl0xhmtg5av2arqtvrpme", // P2TR
        ),
    ] {
        let ours = notes_core::address::address_to_script_pubkey(net, addr).unwrap();
        let theirs = bitcoin::Address::from_str(addr)
            .unwrap()
            .require_network(btc_net)
            .unwrap()
            .script_pubkey();
        assert_eq!(ours, theirs.into_bytes(), "{addr}");
    }
    // Wrong network HRP must be rejected.
    assert!(notes_core::address::address_to_script_pubkey(
        notes_core::Network::Regtest,
        "bc1p548gt356p9jrhr6p5hfvd83km5zus936hlcfyzl0xhmtg5av2arqtvrpme"
    )
    .is_err());
}

/// Sweep: all inputs, one external output, rust-bitcoin cross-check.
#[test]
fn sweep_cross_check() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let id = identity();
    let dest = notes_core::address::address_to_script_pubkey(
        notes_core::Network::Regtest,
        &Identity::from_app_seed(&[9u8; 32]).unwrap().address(notes_core::Network::Regtest),
    )
    .unwrap();
    let sweep = notes_core::tx::build_sweep_tx(
        &utxos(),
        &id.output_x,
        dest.clone(),
        2.0,
        0,
        &id.tweaked_seckey,
        || Ok(AUX))
    .unwrap();
    assert_eq!(sweep.tx.inputs.len(), 3, "sweeps every utxo");
    assert_eq!(sweep.tx.outputs.len(), 1);
    assert_eq!(sweep.tx.outputs[0].value, 86_000 - sweep.fee);

    let raw = hex::decode(&sweep.raw_hex).unwrap();
    let btx: bitcoin::Transaction = deserialize(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), sweep.txid_hex);
    assert_eq!(btx.vsize(), sweep.vsize);

    let spk = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&id.output_x));
    let prevouts: Vec<TxOut> = sweep
        .tx
        .inputs
        .iter()
        .map(|i| TxOut { value: Amount::from_sat(i.value), script_pubkey: spk.clone() })
        .collect();
    let secp = Secp256k1::verification_only();
    let output_key = XOnlyPublicKey::from_slice(&id.output_x).unwrap();
    let mut cache = SighashCache::new(&btx);
    for (index, witness) in (0..btx.input.len()).zip(&sweep.tx.witnesses) {
        let sighash = cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        secp.verify_schnorr(
            &Signature::from_slice(&witness[0]).unwrap(),
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .expect("sweep signature must verify");
    }
}

/// The heavyweight cross-check: rust-bitcoin must (a) parse our raw tx,
/// (b) agree on txid and vsize, (c) recompute the identical BIP341 sighash
/// via its own implementation, and (d) accept our schnorr signature with
/// libsecp256k1 against the tweaked output key.
#[test]
fn rust_bitcoin_cross_check() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let id = identity();
    let note = compose_note(
        &id,
        &utxos(),
        "cross-checked against rust-bitcoin",
        true,
        80,
        3.0,
        0,
        || Ok(AUX))
    .unwrap();

    let raw = hex::decode(&note.raw_hex).unwrap();
    let btx: bitcoin::Transaction = deserialize(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), note.txid_hex);
    assert_eq!(btx.vsize(), note.vsize);

    // Reconstruct the prevouts (every input spends our own P2TR output).
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
    for (index, witness) in btx.input.iter().enumerate().map(|(i, _)| i).zip(&note.tx.witnesses) {
        let sighash = cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = Signature::from_slice(&witness[0]).unwrap();
        secp.verify_schnorr(&sig, &msg, &output_key)
            .expect("libsecp256k1 must accept our BIP340 signature over rust-bitcoin's sighash");
    }
}

/// Same cross-check for a DIRECTED tx (self inputs + dust to recipient +
/// OP_RETURNs + change): rust-bitcoin must parse it, agree on txid/vsize,
/// recompute the sighash and accept our signature.
#[test]
fn directed_rust_bitcoin_cross_check() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut};

    let id = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let note = compose_directed_note(
        &id,
        &utxos(),
        "directed, cross-checked against rust-bitcoin",
        true,
        &to_b,
        80,
        3.0,
        0,
        || Ok(AUX))
    .unwrap();

    let raw = hex::decode(&note.raw_hex).unwrap();
    let btx: bitcoin::Transaction = deserialize(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), note.txid_hex);
    assert_eq!(btx.vsize(), note.vsize);
    // The dust output must land at B's address per rust-bitcoin's decoder.
    let dust = btx.output.iter().find(|o| o.value.to_sat() == 330).unwrap();
    assert_eq!(dust.script_pubkey.as_bytes(), to_b.spk.as_slice());

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
    for (index, witness) in (0..btx.input.len()).zip(&note.tx.witnesses) {
        let sighash = cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        secp.verify_schnorr(
            &Signature::from_slice(&witness[0]).unwrap(),
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .expect("directed tx signature must verify");
    }
}

#[test]
fn change_can_go_to_a_custom_address() {
    let a = identity();
    let b = identity_b();
    // Custom change destination = identity B's own taproot spk.
    let b_spk = notes_core::address::address_to_script_pubkey(
        Network::Regtest,
        &b.address(Network::Regtest),
    )
    .unwrap();

    let default_tx =
        compose_note(&a, &utxos(), "hi", false, 80, 1.0, 0, || Ok([0u8; 32])).unwrap();
    let custom_tx = compose_note_with_change(
        &a, &utxos(), "hi", false, Some(&b_spk), 80, 1.0, 0, || Ok([0u8; 32]))
    .unwrap();

    // Same inputs, same note; only the change output's script differs.
    assert_eq!(default_tx.spent_outpoints, custom_tx.spent_outpoints);
    assert_eq!(default_tx.change, custom_tx.change);
    let default_change = default_tx.tx.outputs.last().unwrap();
    let custom_change = custom_tx.tx.outputs.last().unwrap();
    assert_eq!(default_change.value, custom_change.value);
    assert_ne!(default_change.script_pubkey, custom_change.script_pubkey);
    assert_eq!(custom_change.script_pubkey, b_spk);
    // And it's a valid, different tx.
    assert_ne!(default_tx.txid_hex, custom_tx.txid_hex);
}

#[test]
fn exact_inputs_spends_all_given_coins() {
    let a = identity();
    // Two coins; auto-select would use only the first (largest).
    let coins = vec![
        Utxo { txid: [1u8; 32], vout: 0, value: 60_000 },
        Utxo { txid: [2u8; 32], vout: 0, value: 40_000 },
    ];
    let auto = compose_note(&a, &coins, "hi", false, 80, 1.0, 0, || Ok([0u8; 32])).unwrap();
    // Auto used 1 input (60k covers it); exact-with-both spends both.
    assert_eq!(auto.spent_outpoints.len(), 1);
    let exact = compose_note_exact(&a, &coins, "hi", false, None, 80, 1.0, 0, || Ok([0u8; 32])).unwrap();
    assert_eq!(exact.spent_outpoints.len(), 2, "exact spends every provided coin");
    assert!(exact.change > auto.change, "spending both leaves more change");

    // Exact with just the first coin == auto (both use that one coin).
    let one = compose_note_exact(&a, &coins[..1], "hi", false, None, 80, 1.0, 0, || Ok([0u8; 32])).unwrap();
    assert_eq!(one.txid_hex, auto.txid_hex);

    // Not enough value → InsufficientFunds.
    let tiny = vec![Utxo { txid: [3u8; 32], vout: 0, value: 10 }];
    assert!(compose_note_exact(&a, &tiny, "hi", false, None, 80, 1.0, 0, || Ok([0u8; 32])).is_err());
}

/// Multi-source sweep (wallet-level consolidate): coins from TWO
/// identities in one tx, each input signed with its own key —
/// rust-bitcoin recomputes both sighashes and verifies each signature
/// against the matching owner's output key. Also pins the delegation:
/// build_sweep_tx must stay byte-identical to a one-source multi call.
#[test]
fn sweep_multi_source_cross_check() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{Amount, ScriptBuf, TxOut};
    use notes_core::tx::SweepSource;

    let a = identity();
    let b = Identity::from_app_seed(&[11u8; 32]).unwrap();
    let a_coins = utxos();
    let b_coins =
        vec![Utxo { txid: [4u8; 32], vout: 2, value: 40_000 }, Utxo { txid: [5u8; 32], vout: 0, value: 7_000 }];
    let dest = notes_core::address::address_to_script_pubkey(
        notes_core::Network::Regtest,
        &Identity::from_app_seed(&[9u8; 32]).unwrap().address(notes_core::Network::Regtest),
    )
    .unwrap();

    let sweep = notes_core::tx::build_sweep_tx_multi(
        &[
            SweepSource { utxos: &a_coins, output_x: a.output_x, tweaked_seckey: &a.tweaked_seckey },
            SweepSource { utxos: &b_coins, output_x: b.output_x, tweaked_seckey: &b.tweaked_seckey },
        ],
        dest.clone(),
        2.0,
        0,
        || Ok(AUX))
    .unwrap();
    assert_eq!(sweep.tx.inputs.len(), 5, "every source coin rides");
    assert_eq!(sweep.tx.outputs.len(), 1);
    assert_eq!(sweep.tx.outputs[0].value, 133_000 - sweep.fee);
    // The estimator stays byte-exact in the multi case.
    assert_eq!(sweep.vsize, notes_core::tx::estimate_sweep_vsize(5, dest.len()));

    let raw = hex::decode(&sweep.raw_hex).unwrap();
    let btx: bitcoin::Transaction = deserialize(&raw).unwrap();
    assert_eq!(btx.compute_txid().to_string(), sweep.txid_hex);
    assert_eq!(btx.vsize(), sweep.vsize);

    // Per-input owner: first 3 inputs are a's, last 2 are b's.
    let spk_a = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&a.output_x));
    let spk_b = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&b.output_x));
    let prevouts: Vec<TxOut> = sweep
        .tx
        .inputs
        .iter()
        .enumerate()
        .map(|(i, u)| TxOut {
            value: Amount::from_sat(u.value),
            script_pubkey: if i < 3 { spk_a.clone() } else { spk_b.clone() },
        })
        .collect();
    let secp = Secp256k1::verification_only();
    let key_a = XOnlyPublicKey::from_slice(&a.output_x).unwrap();
    let key_b = XOnlyPublicKey::from_slice(&b.output_x).unwrap();
    let mut cache = SighashCache::new(&btx);
    for (index, witness) in (0..btx.input.len()).zip(&sweep.tx.witnesses) {
        let sighash = cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        secp.verify_schnorr(
            &Signature::from_slice(&witness[0]).unwrap(),
            &Message::from_digest(sighash.to_byte_array()),
            if index < 3 { &key_a } else { &key_b },
        )
        .expect("each input verifies against its own source's key");
    }

    // Delegation pin: the single-source paths agree byte-for-byte.
    let single = notes_core::tx::build_sweep_tx(
        &a_coins,
        &a.output_x,
        dest.clone(),
        2.0,
        0,
        &a.tweaked_seckey,
        || Ok(AUX))
    .unwrap();
    let single_multi = notes_core::tx::build_sweep_tx_multi(
        &[SweepSource { utxos: &a_coins, output_x: a.output_x, tweaked_seckey: &a.tweaked_seckey }],
        dest,
        2.0,
        0,
        || Ok(AUX))
    .unwrap();
    assert_eq!(single.raw_hex, single_multi.raw_hex);
}

// ---------------------------------------------------------------------
// Self-spk-SET ownership rule (PLAN-graffito-funding-unification.md M0):
// `extract_notes_multi`/`_watch_multi` generalize OWN from "spends from the
// notebook address" to "spends from any of MY scriptPubKeys", via the new
// `OnchainTx::input_prevout_spks` field. `extract_notes`/`extract_notes_watch`
// delegate to the multi variant with a singleton set, so every test above
// (which never sets `input_prevout_spks`) is the byte-for-byte proof that
// delegation changes nothing.
// ---------------------------------------------------------------------

fn wpkh_spk(fill: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[fill; 20]);
    s
}

/// (a) A funded note: the input spends a P2WPKH scriptPubKey that IS in the
/// self-spk set (the spending wallet's own address) — outputs are the
/// OP_RETURN chunk(s) plus DUST_LIMIT to the notebook, same shape a real
/// funded self-note produces. Must scan OWN even though the legacy
/// `spends_from_self` bool (computed only against the notebook's own P2TR
/// address) says false.
#[test]
fn self_spk_set_marks_p2wpkh_funded_note_own() {
    let id = identity();
    let note = compose_note(
        &id, &utxos(), "funded from the spending wallet", false, 80, 1.0, 0, || Ok(AUX))
    .unwrap();
    let funding_spk = wpkh_spk(0xab);
    let onchain = OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(200),
        blocktime: Some(1_700_000_200),
        spends_from_self: false, // NOT the notebook's own P2TR address
        payloads: note
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey))
            .map(hex::encode)
            .collect(),
        pays_self: true, // DUST_LIMIT to the notebook, same as any self-funded note
        sender: None,
        author_candidates: Vec::new(),
        recipient: None,
        input_prevout_spks: vec![hex::encode(&funding_spk)],
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle =
        SyncBundle { network: "regtest".into(), notes_onchain: vec![onchain], ..Default::default() };

    let notes = extract_notes_multi(&bundle, &id, NET, &[funding_spk]);
    assert_eq!(notes.len(), 1);
    assert!(!notes[0].received, "spending-wallet-funded note must scan OWN");
    assert_eq!(notes[0].text.as_deref(), Some("funded from the spending wallet"));
}

/// (b) The identical tx shape from (a), scanned via the OLD single-address
/// entry point — whose implicit self-spk set is just the notebook's own
/// P2TR spk, never this funding P2WPKH spk. Unaffected by
/// `input_prevout_spks` being populated: falls through to the existing
/// pays-self + PNTE → RECEIVED rule, exactly as before this change (assert
/// the current behavior; don't change it).
#[test]
fn self_spk_set_leaves_non_matching_spk_scan_unchanged() {
    let id = identity();
    let sender_id = identity_b();
    let note = compose_note(
        &sender_id, &utxos(), "funded by someone else's wallet", false, 80, 1.0,
        0,
        || Ok(AUX))
    .unwrap();
    let funding_spk = wpkh_spk(0xcd);
    let onchain = OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(201),
        blocktime: Some(1_700_000_201),
        spends_from_self: false,
        payloads: note
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey))
            .map(hex::encode)
            .collect(),
        pays_self: true,
        sender: Some(sender_id.address(NET)),
        author_candidates: Vec::new(),
        recipient: None,
        input_prevout_spks: vec![hex::encode(&funding_spk)],
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle =
        SyncBundle { network: "regtest".into(), notes_onchain: vec![onchain], ..Default::default() };

    let notes = extract_notes(&bundle, &id, NET);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].received, "must scan received, exactly as before this change");
    assert_eq!(notes[0].sender.as_deref(), Some(sender_id.address(NET).as_str()));
}

/// (c) Own vs received stay separate notes under the self-spk-SET rule
/// too: an spk-matched OWN tx and an unrelated pays-self RECEIVED tx in
/// the same bundle must not merge (each tx is independently its own note
/// by construction — PLAN-pnte-redesign.md — but this is still useful
/// coverage of the self-spk-set path specifically).
#[test]
fn self_spk_set_own_received_notes_stay_separate() {
    let id = identity();
    let attacker = identity_b();
    let funding_spk = wpkh_spk(0xee);

    let mine =
        compose_note(&id, &utxos(), "my funded words", false, 80, 1.0, 0, || Ok(AUX))
            .unwrap();
    let attack = compose_note(
        &attacker, &utxos(), "gotcha via wpkh?", false, 80, 1.0, 0, || Ok(AUX))
    .unwrap();

    let own_tx = OnchainTx {
        txid: mine.txid_hex.clone(),
        height: Some(300),
        blocktime: Some(1_700_000_300),
        spends_from_self: false,
        payloads: mine
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey))
            .map(hex::encode)
            .collect(),
        pays_self: true,
        sender: None,
        author_candidates: Vec::new(),
        recipient: None,
        input_prevout_spks: vec![hex::encode(&funding_spk)],
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let received_tx = OnchainTx {
        txid: attack.txid_hex.clone(),
        height: Some(301),
        blocktime: Some(1_700_000_301),
        spends_from_self: false,
        payloads: attack
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey))
            .map(hex::encode)
            .collect(),
        pays_self: true,
        sender: Some(attacker.address(NET)),
        author_candidates: Vec::new(),
        recipient: None,
        input_prevout_spks: Vec::new(), // no raw spk data -> falls back to spends_from_self=false
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle = SyncBundle {
        network: "regtest".into(),
        notes_onchain: vec![own_tx, received_tx],
        ..Default::default()
    };

    let notes = extract_notes_multi(&bundle, &id, NET, &[funding_spk]);
    assert_eq!(notes.len(), 2, "own and received notes must stay separate");
    let own = notes.iter().find(|n| !n.received).unwrap();
    assert_eq!(own.text.as_deref(), Some("my funded words"));
    let recv = notes.iter().find(|n| n.received).unwrap();
    assert_eq!(recv.text.as_deref(), Some("gotcha via wpkh?"));
}

/// (d) Regression: the set rule EXTENDS `spends_from_self`, never replaces
/// it. A new-style bundle (populated `input_prevout_spks`) whose tx DOES
/// spend from the notebook must stay OWN for callers that pass no set
/// (`extract_notes_watch`'s empty set) or a non-matching set — i.e. the
/// producer's bool always still counts.
#[test]
fn self_spk_set_extends_spends_from_self_never_replaces() {
    let id = identity();
    let note =
        compose_note(&id, &utxos(), "plain self note", false, 80, 1.0, 0, || Ok(AUX))
            .unwrap();
    let onchain = OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(400),
        blocktime: Some(1_700_000_400),
        spends_from_self: true, // the producer's verdict: spends from the notebook
        payloads: note
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey))
            .map(hex::encode)
            .collect(),
        pays_self: true,
        sender: None,
        author_candidates: Vec::new(),
        recipient: None,
        // New-style bundle: raw prevout spks present (the notebook's P2TR).
        input_prevout_spks: vec![hex::encode(notes_core::address::p2tr_script_pubkey(
            &id.output_x,
        ))],
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle =
        SyncBundle { network: "regtest".into(), notes_onchain: vec![onchain], ..Default::default() };

    // Watch scan (empty self-spk set) on the NEW bundle format.
    let watch = extract_notes_watch(&bundle, NET);
    assert_eq!(watch.len(), 1);
    assert!(!watch[0].received, "watch scan must keep OWN detection on new-style bundles");

    // A caller whose set doesn't include the notebook spk (e.g. only a
    // spending-wallet spk): spends_from_self still wins via the OR.
    let notes = extract_notes_multi(&bundle, &id, NET, &[wpkh_spk(0x01)]);
    assert_eq!(notes.len(), 1);
    assert!(!notes[0].received, "spends_from_self must always still count");
}

/// (e) An OWN funded directed-private note recovers its text + recipient:
/// the tx spends the SPENDING wallet (spends_from_self=false, ownership
/// via the spk set), and the sender re-derives the DM key from the
/// bundle's `recipient` field — which must therefore be populated by the
/// producer regardless of the old spends-from-self test. Conversely a
/// funded SELF-note's `recipient` field (which a producer computing
/// "first non-self output" would fill with the change address) must NOT
/// surface — only directed notes have recipients.
#[test]
fn funded_directed_private_own_note_recovers_text_and_recipient() {
    let a = identity();
    let b = identity_b();
    let to_b = Recipient::parse(NET, &b.address(NET)).unwrap();
    let funding_spk = wpkh_spk(0x77);

    let sent = compose_directed_note(
        &a, &utxos(), "funded, for bob", true, &to_b, 80, 1.0, 0, || Ok(AUX))
    .unwrap();
    let self_note =
        compose_note(&a, &utxos(), "funded self", false, 80, 1.0, 0, || Ok(AUX))
            .unwrap();

    let mk = |note: &notes_core::tx::NoteTx, recipient: Option<String>, h: u64| OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(h),
        blocktime: Some(1_700_000_000 + h),
        spends_from_self: false, // funded: inputs are the spending wallet's
        payloads: note
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey))
            .map(hex::encode)
            .collect(),
        pays_self: true, // dust-to-self keeps it discoverable
        sender: None,
        author_candidates: Vec::new(),
        recipient,
        input_prevout_spks: vec![hex::encode(&funding_spk)],
        output_addrs: Vec::new(),
        first_input_outpoint: note.spent_outpoints.first().map(|(txid, vout)| {
            notes_core::bundle::format_outpoint(txid, *vout)
        }),
    };
    let bundle = SyncBundle {
        network: "regtest".into(),
        notes_onchain: vec![
            mk(&sent, Some(b.address(NET)), 500),
            // Producer naively fills "first non-self output" = the bc1q
            // change address; the directed gate must drop it.
            mk(&self_note, Some("bcrt1qchangechangechange".into()), 501),
        ],
        ..Default::default()
    };

    let notes = extract_notes_multi(&bundle, &a, NET, &[funding_spk]);
    assert_eq!(notes.len(), 2);
    let sent_n = notes.iter().find(|n| n.id == sent.txid_hex).unwrap();
    assert!(!sent_n.received, "funded directed note is OWN via the spk set");
    assert_eq!(sent_n.recipient.as_deref(), Some(b.address(NET).as_str()));
    assert_eq!(sent_n.text.as_deref(), Some("funded, for bob"), "sender re-reads own sent note");
    let self_n = notes.iter().find(|n| n.id == self_note.txid_hex).unwrap();
    assert!(!self_n.received);
    assert_eq!(self_n.recipient, None, "self-note must not surface the change address");
}

// ---------------------------------------------------------------------
// DISPLAY-OWNER dedup for multi-notebook own notes (2026-07-18 design
// decision, a protocol DISPLAY rule — NOT an ownership change): when a
// tx spends from MULTIPLE notebook addresses, every notebook scanning it
// independently would otherwise each keep a copy of the same own note.
// `extract_notes_multi_deduped`/`extract_notes_watch_multi_deduped` keep
// it only in the scan of the notebook whose spk is the FIRST notebook
// input in tx order (mirrors the frozen first-taproot-input sender
// rule). Unreachable from our own composers (which only ever spend from
// one notebook), but craftable by a foreign wallet. See bundle.rs's doc
// comments on `extract_notes_multi_deduped` for the full rule.
// ---------------------------------------------------------------------

fn notebook_spk_of(id: &Identity) -> Vec<u8> {
    notes_core::address::p2tr_script_pubkey(&id.output_x)
}

/// (a) A tx spending from TWO notebook addresses (A then B, in that input
/// order) is scanned independently as both notebooks. Deduped: exactly
/// one keeps it — the first-input notebook, A. Never-zero: A + B totals
/// to exactly 1 kept note across both scans.
#[test]
fn display_owner_dedup_first_notebook_input_wins() {
    let a = identity();
    let b = identity_b();
    let spk_a = notebook_spk_of(&a);
    let spk_b = notebook_spk_of(&b);
    let notebook_spks = vec![spk_a.clone(), spk_b.clone()];

    let note = compose_note(
        &a, &utxos(), "owned by two notebooks", false, 80, 1.0, 0, || Ok(AUX))
    .unwrap();
    let onchain = OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(600),
        blocktime: Some(1_700_000_600),
        spends_from_self: false,
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
        // Crafted: spends from BOTH notebooks, A's input first.
        input_prevout_spks: vec![hex::encode(&spk_a), hex::encode(&spk_b)],
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle =
        SyncBundle { network: "regtest".into(), notes_onchain: vec![onchain], ..Default::default() };

    let as_a = extract_notes_multi_deduped(&bundle, &a, NET, &[spk_a.clone()], &notebook_spks);
    let as_b = extract_notes_multi_deduped(&bundle, &b, NET, &[spk_b.clone()], &notebook_spks);

    assert_eq!(as_a.len(), 1, "first-notebook-input (A) keeps the note");
    assert_eq!(as_b.len(), 0, "second notebook (B) must not also display it");
    assert_eq!(
        as_a.len() + as_b.len(),
        1,
        "never-zero: across all scanned notebooks, exactly one keeps the note"
    );
}

/// (b) Same shape as (a) but the notebook inputs are reversed (B then A)
/// — the owner flips to B, proving the rule follows tx order, not
/// identity or notebook_spks list order.
#[test]
fn display_owner_dedup_flips_with_input_order() {
    let a = identity();
    let b = identity_b();
    let spk_a = notebook_spk_of(&a);
    let spk_b = notebook_spk_of(&b);
    let notebook_spks = vec![spk_a.clone(), spk_b.clone()];

    let note = compose_note(
        &a, &utxos(), "owned by two notebooks, reversed", false, 80, 1.0,
        0,
        || Ok(AUX))
    .unwrap();
    let onchain = OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(601),
        blocktime: Some(1_700_000_601),
        spends_from_self: false,
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
        // Reversed: B's input first this time.
        input_prevout_spks: vec![hex::encode(&spk_b), hex::encode(&spk_a)],
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle =
        SyncBundle { network: "regtest".into(), notes_onchain: vec![onchain], ..Default::default() };

    let as_a = extract_notes_multi_deduped(&bundle, &a, NET, &[spk_a.clone()], &notebook_spks);
    let as_b = extract_notes_multi_deduped(&bundle, &b, NET, &[spk_b.clone()], &notebook_spks);

    assert_eq!(as_a.len(), 0, "A is no longer the first notebook input");
    assert_eq!(as_b.len(), 1, "owner flips to B, the new first-notebook-input");
    assert_eq!(as_a.len() + as_b.len(), 1, "never-zero holds under reversal too");
}

/// (c) The refinement: a spending-wallet P2WPKH input sits at position 0,
/// a notebook (A) input comes later. The wpkh input must NOT steal the
/// anchor — A still owns the note, because the anchor search is scoped
/// to `notebook_spks` only, never the full self-spk set.
#[test]
fn display_owner_dedup_ignores_non_notebook_input_at_position_zero() {
    let a = identity();
    let b = identity_b();
    let spk_a = notebook_spk_of(&a);
    let spk_b = notebook_spk_of(&b);
    let funding_spk = wpkh_spk(0x55);
    let notebook_spks = vec![spk_a.clone(), spk_b.clone()]; // NOT the wpkh spk

    let note = compose_note(
        &a, &utxos(), "wallet-funded but notebook-anchored", false, 80, 1.0,
        0,
        || Ok(AUX))
    .unwrap();
    let onchain = OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(602),
        blocktime: Some(1_700_000_602),
        spends_from_self: false,
        payloads: note
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey))
            .map(hex::encode)
            .collect(),
        pays_self: true,
        sender: None,
        author_candidates: Vec::new(),
        recipient: None,
        // Spending-wallet input FIRST, notebook A's input SECOND.
        input_prevout_spks: vec![hex::encode(&funding_spk), hex::encode(&spk_a)],
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle =
        SyncBundle { network: "regtest".into(), notes_onchain: vec![onchain], ..Default::default() };

    // is_own via the spending-wallet spk being in self_spks (funded shape).
    let as_a = extract_notes_multi_deduped(
        &bundle, &a, NET, &[funding_spk.clone(), spk_a.clone()], &notebook_spks,
    );
    assert_eq!(
        as_a.len(),
        1,
        "notebook A still anchors the note even though a non-notebook input comes first"
    );
}

/// (d) A pure dust-anchored spending-wallet-funded note (no notebook
/// input at all) is unaffected — the anchor search finds nothing, so the
/// note is kept exactly as `extract_notes_multi` would keep it.
#[test]
fn display_owner_dedup_noop_when_no_notebook_input() {
    let a = identity();
    let funding_spk = wpkh_spk(0x66);
    let notebook_spks = vec![notebook_spk_of(&a)];

    let note = compose_note(
        &a, &utxos(), "pure spending-wallet funded, dust anchor only", false, 80,
        1.0, 0, || Ok(AUX))
    .unwrap();
    let onchain = OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(603),
        blocktime: Some(1_700_000_603),
        spends_from_self: false,
        payloads: note
            .tx
            .outputs
            .iter()
            .filter_map(|o| op_return_payload(&o.script_pubkey))
            .map(hex::encode)
            .collect(),
        pays_self: true,
        sender: None,
        author_candidates: Vec::new(),
        recipient: None,
        input_prevout_spks: vec![hex::encode(&funding_spk)], // no notebook input present
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle =
        SyncBundle { network: "regtest".into(), notes_onchain: vec![onchain], ..Default::default() };

    let notes =
        extract_notes_multi_deduped(&bundle, &a, NET, &[funding_spk], &notebook_spks);
    assert_eq!(notes.len(), 1, "dust-anchored / no notebook input: unchanged, always kept");
}

/// (e) The old, non-deduped `extract_notes_multi` is byte-identical to
/// `extract_notes_multi_deduped` called with an empty `notebook_spks` —
/// on the very fixture from (a) that WOULD be deduped with a populated
/// set, proving dedup is strictly opt-in.
#[test]
fn display_owner_dedup_empty_notebook_spks_matches_undeduped() {
    let a = identity();
    let b = identity_b();
    let spk_a = notebook_spk_of(&a);
    let spk_b = notebook_spk_of(&b);

    let note = compose_note(
        &a, &utxos(), "identical old vs deduped-noop", false, 80, 1.0, 0, || Ok(AUX))
    .unwrap();
    let onchain = OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(604),
        blocktime: Some(1_700_000_604),
        spends_from_self: false,
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
        input_prevout_spks: vec![hex::encode(&spk_a), hex::encode(&spk_b)],
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle =
        SyncBundle { network: "regtest".into(), notes_onchain: vec![onchain], ..Default::default() };

    let old = extract_notes_multi(&bundle, &a, NET, &[spk_a.clone()]);
    let deduped_noop = extract_notes_multi_deduped(&bundle, &a, NET, &[spk_a.clone()], &[]);
    assert_eq!(old, deduped_noop, "empty notebook_spks must be byte-identical to the old fn");
    assert_eq!(old.len(), 1, "sanity: the fixture is scanned OWN and kept by both");
}

/// (f) A legacy bundle whose `input_prevout_spks` is empty (old
/// producer, serde default) must be a dedup no-op regardless of how
/// `notebook_spks` is populated — the never-narrowing invariant.
#[test]
fn display_owner_dedup_noop_on_legacy_empty_input_prevout_spks() {
    let a = identity();
    let notebook_spks = vec![notebook_spk_of(&a)]; // populated, but can't match anything

    let note = compose_note(
        &a, &utxos(), "legacy bundle, no raw prevout spks", false, 80, 1.0,
        0,
        || Ok(AUX))
    .unwrap();
    let onchain = OnchainTx {
        txid: note.txid_hex.clone(),
        height: Some(605),
        blocktime: Some(1_700_000_605),
        spends_from_self: true, // legacy producer's own verdict
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
        input_prevout_spks: Vec::new(), // legacy: no raw spk data at all
        output_addrs: Vec::new(),
        first_input_outpoint: None,
    };
    let bundle =
        SyncBundle { network: "regtest".into(), notes_onchain: vec![onchain], ..Default::default() };

    let notes = extract_notes_multi_deduped(&bundle, &a, NET, &[], &notebook_spks);
    assert_eq!(notes.len(), 1, "legacy bundle with no input_prevout_spks: dedup is a no-op");
}
