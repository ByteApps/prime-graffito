//! Sync-bundle JSON (companion → device), note extraction (the scanner
//! side), and the high-level compose path (device → signed tx hex).

use serde::{Deserialize, Serialize};

use crate::address::{p2tr_script_pubkey, p2tr_x_of_address, taproot_address, Recipient};
use crate::crypt;
use crate::dm;
use crate::envelope::{self, Chunk, FLAG_DIRECTED, FLAG_MULTI, FLAG_PRIVATE};
use crate::keys::{derive_encryption_key, derive_identity_key, xonly_pubkey};
use crate::taproot::{taproot_tweak_pubkey, taproot_tweak_seckey};
use crate::tx::{
    build_note_tx_exact, build_note_tx_multi_exact, build_note_tx_multi_with_change,
    build_note_tx_with_change, NoteTx, Utxo,
};
use crate::{Error, Network};

/// Everything derived from the app seed that the app needs at runtime.
pub struct Identity {
    pub internal_x: [u8; 32],
    pub output_x: [u8; 32],
    pub tweaked_seckey: [u8; 32],
    pub enc_key: [u8; 32],
}

impl Identity {
    pub fn from_app_seed(app_seed: &[u8; 32]) -> Result<Self, Error> {
        let identity_key = derive_identity_key(app_seed);
        let (internal_x, _) = xonly_pubkey(&identity_key)?;
        let (output_x, _) = taproot_tweak_pubkey(&internal_x, None)?;
        let tweaked_seckey = taproot_tweak_seckey(&identity_key, None)?;
        Ok(Identity {
            internal_x,
            output_x,
            tweaked_seckey,
            enc_key: derive_encryption_key(app_seed),
        })
    }

    /// Identity from a BIP-86 leaf secret — the bip86 notebook scheme
    /// (PLAN-chain-notes-seed-rotation.md) and chain-notes-app's shipped
    /// derivation: BIP-341 tweak for the keys, the FROZEN
    /// `chain-notes-app/enc/v1` rule for the enc key. Byte-identical to
    /// what chain-notes-app derives after a plain BIP-39 import.
    pub fn from_leaf_secret(leaf_secret: &[u8; 32]) -> Result<Self, Error> {
        let (internal_x, _) = xonly_pubkey(leaf_secret)?;
        let (output_x, _) = taproot_tweak_pubkey(&internal_x, None)?;
        let tweaked_seckey = taproot_tweak_seckey(leaf_secret, None)?;
        Ok(Identity {
            internal_x,
            output_x,
            tweaked_seckey,
            enc_key: crate::keys::enc_key_from_leaf(leaf_secret),
        })
    }

    /// [`Self::from_leaf_secret`] for notebook `index` of `account` under
    /// rotation seed `seed_index` — the full recovery-seeds pipeline from
    /// the app seed (see `seeds.rs`).
    pub fn from_bip86(
        app_seed: &[u8; 32],
        seed_index: u32,
        network: Network,
        account: u32,
        index: u32,
    ) -> Result<Self, Error> {
        let leaf = crate::seeds::derive_leaf(app_seed, seed_index, network, account, index)?;
        Self::from_leaf_secret(&leaf)
    }

    pub fn address(&self, network: Network) -> String {
        taproot_address(network, &self.output_x)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FeeRates {
    #[serde(rename = "fastestFee")]
    pub fastest: f64,
    #[serde(rename = "halfHourFee")]
    pub half_hour: f64,
    #[serde(rename = "hourFee")]
    pub hour: f64,
    #[serde(rename = "economyFee")]
    pub economy: f64,
    #[serde(rename = "minimumFee")]
    pub minimum: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    #[serde(default)]
    pub height: Option<u64>,
    /// The address this coin actually belongs to, when it is NOT the bundle's
    /// scanned notebook address (funding-unification: a Prime device's
    /// spending-wallet coins). Empty/absent (serde default) = the scanned
    /// address, i.e. today's behavior for every existing bundle producer —
    /// additive, never a narrowing. A companion that also probes the
    /// spending wallet's known addresses (device-exported list; see
    /// companion/index.html) sets this so the device can route the coin into
    /// the right ledger instead of guessing from scriptPubKey shape alone.
    #[serde(default)]
    pub owner_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnchainTx {
    pub txid: String,
    #[serde(default)]
    pub height: Option<u64>,
    #[serde(default)]
    pub blocktime: Option<u64>,
    /// True when the tx spends an input belonging to the notes address —
    /// the sender-authentication rule for OWN notes; PNTE payloads in txs
    /// merely PAYING the address surface as RECEIVED notes instead.
    pub spends_from_self: bool,
    /// OP_RETURN payloads (hex), in output order.
    pub payloads: Vec<String>,
    /// True when any output pays the notes address (directed-note delivery).
    #[serde(default)]
    pub pays_self: bool,
    /// First taproot input prevout address — the (unforgeable) author of a
    /// received note under self-funding, and the default display sender.
    #[serde(default)]
    pub sender: Option<String>,
    /// Every taproot address appearing in the tx (input prevouts AND outputs).
    /// When a note is funded by an EXTERNAL wallet the author's key is not the
    /// spending input but a dust output back to their own address, so decode
    /// tries each of these as the directed-private ECDH sender until the AEAD
    /// authenticates. Optional/defaulted: legacy bundles fall back to `sender`.
    #[serde(default)]
    pub author_candidates: Vec<String>,
    /// First non-self, non-OP_RETURN output address — the recipient of an
    /// own directed note (lets the sender re-derive the DM key after a wipe).
    #[serde(default)]
    pub recipient: Option<String>,
    /// Raw scriptPubKeys (hex) of every input's prevout — enables the
    /// self-spk-SET ownership rule (`extract_notes_multi`/`_watch_multi`,
    /// PLAN-chain-notes-funding-unification.md). Empty (the serde default)
    /// falls back to `spends_from_self` for bundles that don't populate it
    /// — old callers and old bundles are unaffected.
    #[serde(default)]
    pub input_prevout_spks: Vec<String>,
    /// Addresses of every NON-OP_RETURN output, in ascending vout order
    /// (multi-recipient directed notes, FLAG_MULTI: recipients precede
    /// change by construction, so `output_addrs[0..count]` are the
    /// recipients). Empty (serde default) on old bundles/producers that
    /// don't fill it in — degrades gracefully: a FLAG_MULTI note simply
    /// can't recover its recipient list or decode (same as any other
    /// too-short-body case), never a crash.
    #[serde(default)]
    pub output_addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncBundle {
    pub network: String,
    pub full: bool,
    pub since_height: Option<u64>,
    pub tip_height: u64,
    pub bundle_time: u64,
    /// Legacy field, tolerated on parse but no longer emitted or consumed:
    /// chunk size is a device-side setting (app Settings screen).
    pub max_op_return_bytes: usize,
    pub fee_rates: FeeRates,
    pub btc_usd: Option<f64>,
    pub utxos: Vec<BundleUtxo>,
    pub notes_onchain: Vec<OnchainTx>,
    /// Companion gap-discovery, option (b) (PLAN-chain-notes-funding-
    /// unification.md, 2026-07-19): every spending-wallet watch-window
    /// address (the device's exported next-20-receive + next-20-change
    /// lookahead, NOT just the addresses that currently hold a coin) the
    /// companion found ANY on-chain history for — funded, spent, or both.
    /// A spent-then-emptied address never appears in `utxos` (no coin
    /// left to tag `owner_address`), but the device still needs to know
    /// it was used so its own next_receive/next_change bookkeeping
    /// converges past it instead of re-showing an already-spent address
    /// as "next receive" forever. Additive/`#[serde(default)]`: absent on
    /// every existing bundle producer and old bundle, so behavior is
    /// unchanged until a producer opts in.
    #[serde(default)]
    pub owner_used: Vec<String>,
}

impl Default for SyncBundle {
    fn default() -> Self {
        SyncBundle {
            network: String::new(),
            full: false,
            since_height: None,
            tip_height: 0,
            bundle_time: 0,
            max_op_return_bytes: 80,
            fee_rates: FeeRates::default(),
            btc_usd: None,
            utxos: Vec::new(),
            notes_onchain: Vec::new(),
            owner_used: Vec::new(),
        }
    }
}

impl SyncBundle {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn utxos(&self) -> Vec<Utxo> {
        self.utxos
            .iter()
            .filter_map(|u| {
                let mut txid = [0u8; 32];
                hex::decode_to_slice(&u.txid, &mut txid).ok()?;
                txid.reverse(); // display order → internal order
                Some(Utxo { txid, vout: u.vout, value: u.value })
            })
            .collect()
    }
}

/// Magic prefix of a scanned-bundle payload: `CNB1 || deflate-raw(json)`.
/// The same bytes travel as one binary QR (small bundles) or as the
/// reassembled payload of an animated `ur:bytes` sequence (the system
/// scanner hands back the whole message either way).
pub const SCAN_MAGIC: &[u8; 4] = b"CNB1";

/// Decode a payload returned by the system QR scanner into bundle JSON.
/// Tolerates a plain uncompressed JSON QR too (starts with `{`).
pub fn decode_scanned(data: &[u8]) -> Result<String, Error> {
    if data.len() > 4 && data[..4] == *SCAN_MAGIC {
        let inflated = miniz_oxide::inflate::decompress_to_vec(&data[4..])
            .map_err(|_| Error::Envelope("bad deflate stream"))?;
        String::from_utf8(inflated).map_err(|_| Error::Envelope("bundle not utf-8"))
    } else if data.first() == Some(&b'{') {
        String::from_utf8(data.to_vec()).map_err(|_| Error::Envelope("bundle not utf-8"))
    } else {
        Err(Error::Envelope("not a Chain Notes bundle QR"))
    }
}

/// A note recovered from chain data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredNote {
    pub note_id: [u8; 4],
    pub txids: Vec<String>,
    pub height: Option<u64>,
    pub blocktime: Option<u64>,
    pub private: bool,
    /// Directed note (dust output to a recipient; FLAG_DIRECTED set).
    pub directed: bool,
    /// True = someone else sent this note TO our address; false = our own.
    pub received: bool,
    /// Author address of a received note (first taproot input prevout).
    pub sender: Option<String>,
    /// Recipient address of our own directed note. Kept populated (first
    /// recipient) for compatibility with single-recipient callers even on
    /// a multi-recipient note — see `recipients` for the full list.
    pub recipient: Option<String>,
    /// Full recipient list of a multi-recipient directed note (FLAG_MULTI,
    /// `output_addrs[0..count]`), in output order. Empty for a
    /// single-recipient directed note (use `recipient` instead) or a
    /// self-note. Unlike `recipient` this is populated for BOTH own and
    /// received notes — "who else was on this note" is meaningful either
    /// way (see `reply_set`).
    pub recipients: Vec<String>,
    /// None = private note that did not decrypt under our key (foreign).
    pub text: Option<String>,
}

/// `{sender} ∪ recipients` minus `my_address`, deduped, sender first then
/// recipients in vout order — "who else was on this note", for a reply
/// picker. Falls back to the legacy singular `recipient` field when
/// `recipients` is empty (a single-recipient directed note, which never
/// populates the plural field). A self-note (no sender, no recipients)
/// returns an empty list.
pub fn reply_set(note: &RecoveredNote, my_address: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let push = |addr: &str, out: &mut Vec<String>| {
        if addr != my_address && !out.iter().any(|a| a == addr) {
            out.push(addr.to_string());
        }
    };
    if let Some(s) = &note.sender {
        push(s, &mut out);
    }
    if note.recipients.is_empty() {
        if let Some(r) = &note.recipient {
            push(r, &mut out);
        }
    } else {
        for r in &note.recipients {
            push(r, &mut out);
        }
    }
    out
}

/// Scan a bundle's on-chain txs into notes.
///
/// Acceptance: a tx that SPENDS FROM the notes address carries OWN notes
/// (the frozen spoof-resistance rule); a tx that only PAYS the address and
/// carries PNTE is a RECEIVED note, attributed to its (unforgeable) input
/// address; anything else is ignored. Chunks bucket by (note_id, origin) so
/// a pays-me tx reusing one of our note_ids can never contaminate our own
/// note. Import stays idempotent — output depends only on chain content.
pub fn extract_notes(
    bundle: &SyncBundle,
    identity: &Identity,
    network: Network,
) -> Vec<RecoveredNote> {
    let self_spk = p2tr_script_pubkey(&identity.output_x);
    extract_notes_multi(bundle, identity, network, &[self_spk])
}

/// [`extract_notes`] generalized to a SET of "my" scriptPubKeys — OWN iff a
/// tx's input prevout spk is in `self_spks` (funding-unification PLAN,
/// "Attribution & scanner changes"): the notebook spk alone today, plus the
/// spending wallet's P2WPKH spks once that ships. `extract_notes` delegates
/// here with a singleton `[notebook spk]`, so behavior is identical to
/// before for every existing caller. The set rule ORs with the producer's
/// `spends_from_self` bool, so it extends the old rule and never narrows
/// it (legacy bundles with an empty `input_prevout_spks` behave exactly
/// as before).
pub fn extract_notes_multi(
    bundle: &SyncBundle,
    identity: &Identity,
    network: Network,
    self_spks: &[Vec<u8>],
) -> Vec<RecoveredNote> {
    extract_notes_inner(bundle, Some(identity), network, self_spks, &[], &[])
}

/// [`extract_notes_multi`] plus the DISPLAY-OWNER dedup rule for multi-
/// notebook own notes (2026-07-18 design decision — a protocol DISPLAY
/// rule, not an ownership change; unreachable from our own composers
/// today, which only ever spend from one notebook, but craftable by a
/// foreign wallet spending from several of a wallet's notebook
/// addresses in one tx): without this, every notebook whose address the
/// tx spends from would independently scan the note as its own, showing
/// a duplicate in each. New rule: an OWN note is kept by THIS scan only
/// if the FIRST input (in tx order) whose prevout scriptPubKey is in
/// `notebook_spks` is either absent (no notebook input at all — the
/// dust-anchored spending/external-funded shape, unchanged) or equal to
/// `identity`'s own notebook scriptPubKey. This mirrors the FROZEN
/// first-taproot-input sender rule used for received notes. It is a
/// strict DISPLAY narrowing only — decryption/`text` is untouched, and
/// since the anchor (when one exists) is always some notebook's own
/// spk, exactly one notebook's scan of the same tx ever matches: never
/// zero, matching the never-narrowing OWN-detection invariant, and the
/// sealing-key alignment note below.
///
/// `notebook_spks` must be the SET of NOTEBOOK scriptPubKeys only — never
/// the full `self_spks` set, which may also contain spending-wallet
/// (P2WPKH) or other non-notebook spks. Passing the full set would let a
/// spending-wallet input at position 0 "steal" the anchor and hide the
/// note from every notebook, which would violate never-zero-display. An
/// EMPTY `notebook_spks` is a strict no-op (identical output to
/// [`extract_notes_multi`]) — used by that function's own delegation, so
/// dedup is opt-in. Because the anchor search reads
/// `OnchainTx::input_prevout_spks`, a bundle that leaves that field empty
/// (old producers, serde-default) can never match any notebook spk
/// either, so dedup is *also* a no-op there regardless of
/// `notebook_spks` — old bundles keep every own note, never dropped.
///
/// Sealing-key alignment: in every tx our own apps produce, the
/// composing notebook's input is the (and typically the only) notebook
/// input, so display-owner and decrypt-owner always coincide — this rule
/// only ever disambiguates foreign-crafted multi-notebook-input txs.
pub fn extract_notes_multi_deduped(
    bundle: &SyncBundle,
    identity: &Identity,
    network: Network,
    self_spks: &[Vec<u8>],
    notebook_spks: &[Vec<u8>],
) -> Vec<RecoveredNote> {
    let own_spk = p2tr_script_pubkey(&identity.output_x);
    extract_notes_inner(bundle, Some(identity), network, self_spks, notebook_spks, &own_spk)
}

/// Watch-only [`extract_notes`]: everything a public observer of the address
/// can recover — note structure, origins, senders/recipients, public text —
/// with no key material. Every private body stays sealed (`text: None`),
/// including own self-notes, and received directed-private notes keep their
/// display-default sender (no candidate-key authentication is possible).
pub fn extract_notes_watch(bundle: &SyncBundle, network: Network) -> Vec<RecoveredNote> {
    extract_notes_watch_multi(bundle, network, &[])
}

/// [`extract_notes_watch`] generalized to a self-spk SET — see
/// [`extract_notes_multi`]. Watch mode has no identity key, so (unlike
/// `extract_notes`) the caller supplies whatever spks it is observing (an
/// empty set adds nothing, leaving `spends_from_self` to decide alone —
/// today's watch-only behavior, even on bundles that populate
/// `input_prevout_spks`).
pub fn extract_notes_watch_multi(
    bundle: &SyncBundle,
    network: Network,
    self_spks: &[Vec<u8>],
) -> Vec<RecoveredNote> {
    extract_notes_inner(bundle, None, network, self_spks, &[], &[])
}

/// [`extract_notes_watch_multi`] plus the DISPLAY-OWNER dedup rule — see
/// [`extract_notes_multi_deduped`] for the full rule and the
/// never-zero/sealing-key-alignment reasoning, which applies identically
/// here. Watch mode has no `Identity` to read "this scan's own notebook
/// spk" from, so the caller supplies it explicitly as
/// `scanned_notebook_spk` (the scriptPubKey of the address being
/// watched). As with the keyed variant, an empty `notebook_spks` is a
/// strict no-op.
pub fn extract_notes_watch_multi_deduped(
    bundle: &SyncBundle,
    network: Network,
    self_spks: &[Vec<u8>],
    notebook_spks: &[Vec<u8>],
    scanned_notebook_spk: &[u8],
) -> Vec<RecoveredNote> {
    extract_notes_inner(bundle, None, network, self_spks, notebook_spks, scanned_notebook_spk)
}

/// First input (in tx order) whose prevout scriptPubKey is in
/// `notebook_spks`; `None` when no input matches (including the legacy
/// case where `input_prevout_spks` is empty) — the DISPLAY-OWNER anchor
/// for [`extract_notes_multi_deduped`]/[`extract_notes_watch_multi_deduped`].
fn tx_notebook_anchor(tx: &OnchainTx, notebook_spks: &[Vec<u8>]) -> Option<Vec<u8>> {
    if notebook_spks.is_empty() {
        return None;
    }
    tx.input_prevout_spks.iter().find_map(|spk_hex| {
        let spk = hex::decode(spk_hex).ok()?;
        if notebook_spks.iter().any(|s| *s == spk) {
            Some(spk)
        } else {
            None
        }
    })
}

fn extract_notes_inner(
    bundle: &SyncBundle,
    keys: Option<&Identity>,
    network: Network,
    self_spks: &[Vec<u8>],
    notebook_spks: &[Vec<u8>],
    own_notebook_spk: &[u8],
) -> Vec<RecoveredNote> {
    #[derive(PartialEq, Eq, Clone)]
    enum Origin {
        Own,
        Received(Option<String>), // sender address
    }
    struct Pending {
        origin: Origin,
        chunks: Vec<Chunk>,
        txids: Vec<String>,
        height: Option<u64>,
        blocktime: Option<u64>,
        recipient: Option<String>,
        /// Union of taproot addresses seen in the carrying tx(s) — candidate
        /// authors for a received directed-private note (external funding).
        author_candidates: Vec<String>,
        /// DISPLAY-OWNER anchor (own notes only): the first-notebook-input
        /// spk of the FIRST tx that introduced this note, per
        /// `tx_notebook_anchor`. `None` = no notebook input found (keep,
        /// dust-anchored shape) or not applicable (received notes, or
        /// `notebook_spks` empty — dedup disabled).
        notebook_anchor: Option<Vec<u8>>,
        /// Non-OP_RETURN output addresses of the FIRST tx that introduced
        /// this note, ascending vout order — multi-recipient decode
        /// (FLAG_MULTI) slices `output_addrs[0..count]` as the recipient
        /// list. Empty for old bundles (serde default) or non-multi notes,
        /// which never read this field.
        output_addrs: Vec<String>,
    }
    let mut by_id: Vec<([u8; 4], Pending)> = Vec::new();

    for tx in &bundle.notes_onchain {
        // Self-spk-SET ownership rule: the producer's `spends_from_self`
        // bool (spends from the notebook address) OR any input prevout spk
        // in `self_spks`. An OR, deliberately — a pure extension, never a
        // narrowing, of the old rule: a caller passing an empty set (e.g.
        // `extract_notes_watch`) keeps full OWN detection even on bundles
        // that populate `input_prevout_spks`, and spoof resistance is
        // unchanged (a stranger's tx matches neither side).
        let is_own = tx.spends_from_self
            || tx.input_prevout_spks.iter().any(|spk_hex| {
                hex::decode(spk_hex)
                    .map(|spk| self_spks.iter().any(|s| *s == spk))
                    .unwrap_or(false)
            });
        let origin = if is_own {
            Origin::Own
        } else if tx.pays_self {
            Origin::Received(tx.sender.clone())
        } else {
            continue; // neither from nor to us — pure spoof, ignored
        };
        for payload_hex in &tx.payloads {
            let Ok(payload) = hex::decode(payload_hex) else { continue };
            let Some(chunk) = envelope::decode(&payload) else { continue };
            let entry = match by_id
                .iter_mut()
                .find(|(id, p)| *id == chunk.note_id && p.origin == origin)
            {
                Some((_, p)) => p,
                None => {
                    // Computed once, from the FIRST tx that introduces this
                    // note — later txs carrying more chunks of the same
                    // note_id/origin don't move the anchor.
                    let notebook_anchor = if origin == Origin::Own {
                        tx_notebook_anchor(tx, notebook_spks)
                    } else {
                        None
                    };
                    by_id.push((
                        chunk.note_id,
                        Pending {
                            origin: origin.clone(),
                            chunks: Vec::new(),
                            txids: Vec::new(),
                            height: None,
                            blocktime: None,
                            recipient: None,
                            author_candidates: Vec::new(),
                            notebook_anchor,
                            output_addrs: tx.output_addrs.clone(),
                        },
                    ));
                    &mut by_id.last_mut().expect("just pushed").1
                }
            };
            // Drop exact duplicates (overlapping incremental bundles).
            if entry.chunks.iter().any(|c| c.seq == chunk.seq && c.data == chunk.data) {
                continue;
            }
            entry.chunks.push(chunk);
            if !entry.txids.contains(&tx.txid) {
                entry.txids.push(tx.txid.clone());
            }
            if entry.recipient.is_none() {
                entry.recipient = tx.recipient.clone();
            }
            for cand in &tx.author_candidates {
                if !entry.author_candidates.contains(cand) {
                    entry.author_candidates.push(cand.clone());
                }
            }
            // A note's height is its FIRST confirmation.
            if entry.height.is_none() || tx.height < entry.height {
                if tx.height.is_some() {
                    entry.height = tx.height;
                    entry.blocktime = tx.blocktime;
                }
            }
        }
    }

    let mut notes = Vec::new();
    for (note_id, pending) in by_id {
        // DISPLAY-OWNER dedup: an own note anchored to a DIFFERENT notebook's
        // input is displayed only by that notebook's scan, not this one. A
        // `None` anchor (no notebook input, or dedup disabled via an empty
        // `notebook_spks`) always keeps — never a narrowing of OWN-ness
        // itself, only of which single scan renders it.
        if pending.origin == Origin::Own {
            if let Some(anchor) = &pending.notebook_anchor {
                if anchor.as_slice() != own_notebook_spk {
                    continue;
                }
            }
        }
        let Ok(body) = envelope::reassemble(&pending.chunks) else { continue };
        let flags = pending.chunks[0].flags;
        let private = flags & FLAG_PRIVATE != 0;
        let directed = flags & FLAG_DIRECTED != 0;
        let multi = flags & FLAG_MULTI != 0;
        let mut received = matches!(pending.origin, Origin::Received(_));
        // `sender` starts as the first-input address (display default); it and
        // `recipient`/`received` are corrected below once a directed-private
        // note authenticates under a specific candidate key (external funding).
        let mut sender = match &pending.origin {
            Origin::Received(s) => s.clone(),
            Origin::Own => None,
        };
        // Only a DIRECTED note has a recipient (the envelope flag knows;
        // the bundle field is just "first non-self output", which for a
        // funded or custom-change SELF-note would be the change address).
        let mut recipient =
            if received || !directed { None } else { pending.recipient.clone() };

        // Multi-recipient (FLAG_MULTI): the body's first byte is `count`;
        // `output_addrs[0..count]` are the recipients (they precede change
        // by construction). Populated whenever `count` parses as non-zero,
        // for BOTH own and received notes (unlike the legacy singular
        // `recipient` above) — see `reply_set`. `count == 0` or a body too
        // short to even carry the count byte leaves this empty and
        // `plaintext` (below) None — liberal decoding, not a crash.
        let mut recipients: Vec<String> = Vec::new();
        let multi_count: Option<usize> =
            if multi { body.first().map(|&c| c as usize).filter(|&c| c > 0) } else { None };
        if let Some(count) = multi_count {
            recipients = pending.output_addrs.iter().take(count).cloned().collect();
        }

        let plaintext = if multi {
            match multi_count {
                // count == 0, or empty body: undecodable, not a crash.
                None => None,
                Some(count) => {
                    let rest = &body[1..];
                    if !private {
                        Some(rest.to_vec())
                    } else if keys.is_none() {
                        None // watch-only: no decryption key on this device
                    } else if !directed {
                        // FLAG_MULTI without FLAG_DIRECTED never comes from any
                        // composer (see envelope.rs) — no recipient keys to
                        // even attempt against; liberal decode = undecodable.
                        None
                    } else {
                        let identity = keys.expect("gated above");
                        let wrap_total = count * dm::WRAP_LEN;
                        if rest.len() < wrap_total {
                            None // truncated wraps: undecodable, not a crash
                        } else {
                            let wraps: Vec<Vec<u8>> =
                                rest[..wrap_total].chunks(dm::WRAP_LEN).map(<[u8]>::to_vec).collect();
                            let sealed_body = &rest[wrap_total..];
                            if received {
                                // Received multi-recipient-private. Same
                                // candidate search as the single-recipient
                                // case (author = first-input sender, or any
                                // taproot address seen in the tx), then the
                                // same externally-funded-own-note fallback.
                                let mut candidates: Vec<[u8; 32]> = Vec::new();
                                let push_cand = |addr: &str, out: &mut Vec<[u8; 32]>| {
                                    if let Some(x) = p2tr_x_of_address(network, addr) {
                                        if x != identity.output_x && !out.contains(&x) {
                                            out.push(x);
                                        }
                                    }
                                };
                                if let Some(s) = sender.as_deref() {
                                    push_cand(s, &mut candidates);
                                }
                                for addr in &pending.author_candidates {
                                    push_cand(addr, &mut candidates);
                                }
                                let my_index = recipients.iter().position(|a| {
                                    p2tr_x_of_address(network, a) == Some(identity.output_x)
                                });
                                let mut recovered = None;
                                for cand in &candidates {
                                    if let Ok(pt) = dm::open_received_multi(
                                        &identity.tweaked_seckey,
                                        &identity.output_x,
                                        cand,
                                        &note_id,
                                        &wraps,
                                        sealed_body,
                                        my_index,
                                    ) {
                                        sender = Some(taproot_address(network, cand));
                                        recovered = Some(pt);
                                        break;
                                    }
                                }
                                if recovered.is_none() {
                                    let recipients_x: Vec<[u8; 32]> = recipients
                                        .iter()
                                        .filter_map(|a| p2tr_x_of_address(network, a))
                                        .collect();
                                    if let Ok(pt) = dm::open_sent_multi(
                                        &identity.tweaked_seckey,
                                        &identity.output_x,
                                        &recipients_x,
                                        &note_id,
                                        &wraps,
                                        sealed_body,
                                    ) {
                                        // Our own externally-funded multi note.
                                        received = false;
                                        sender = None;
                                        recovered = Some(pt);
                                    }
                                }
                                recovered
                            } else {
                                // Own sent multi-recipient-private (self-funded):
                                // re-derive via any recipient's output key.
                                let recipients_x: Vec<[u8; 32]> = recipients
                                    .iter()
                                    .filter_map(|a| p2tr_x_of_address(network, a))
                                    .collect();
                                dm::open_sent_multi(
                                    &identity.tweaked_seckey,
                                    &identity.output_x,
                                    &recipients_x,
                                    &note_id,
                                    &wraps,
                                    sealed_body,
                                )
                                .ok()
                            }
                        }
                    }
                }
            }
        } else if !private {
            Some(body)
        } else if keys.is_none() {
            None // watch-only: no decryption key on this device
        } else if !directed {
            // Own self-note: the frozen enc_key path, byte-for-byte as v1.
            let identity = keys.expect("gated above");
            crypt::open(&identity.enc_key, &note_id, &body).ok()
        } else if received {
            let identity = keys.expect("gated above");
            // Received directed-private. The author is the first-input address
            // for self-funded notes, or a dust-to-self output for externally-
            // funded ones — so try the input sender, then every taproot address
            // in the tx, and accept whichever AEAD-authenticates (~2^-128 for a
            // wrong key). If none opens as RECEIVED, we may instead be the
            // AUTHOR who funded the note externally (our own tx doesn't spend
            // from us, so it looks "received"): retry each candidate as the
            // RECIPIENT via open_sent, restoring our note to our own notebook.
            let mut candidates: Vec<[u8; 32]> = Vec::new();
            let push_cand = |addr: &str, out: &mut Vec<[u8; 32]>| {
                if let Some(x) = p2tr_x_of_address(network, addr) {
                    if x != identity.output_x && !out.contains(&x) {
                        out.push(x);
                    }
                }
            };
            if let Some(s) = sender.as_deref() {
                push_cand(s, &mut candidates);
            }
            for addr in &pending.author_candidates {
                push_cand(addr, &mut candidates);
            }
            let mut recovered = None;
            for cand in &candidates {
                if let Ok(pt) = dm::open_received(
                    &identity.tweaked_seckey,
                    &identity.output_x,
                    cand,
                    &note_id,
                    &body,
                ) {
                    // Attribute the note to the authenticated author.
                    sender = Some(taproot_address(network, cand));
                    recovered = Some(pt);
                    break;
                }
            }
            if recovered.is_none() {
                for cand in &candidates {
                    if let Ok(pt) = dm::open_sent(
                        &identity.tweaked_seckey,
                        &identity.output_x,
                        cand,
                        &note_id,
                        &body,
                    ) {
                        // Our own externally-funded note — not received.
                        received = false;
                        sender = None;
                        recipient = Some(taproot_address(network, cand));
                        recovered = Some(pt);
                        break;
                    }
                }
            }
            recovered
        } else {
            // Own sent directed-private (self-funded): re-derive via the
            // dust-output recipient key.
            let identity = keys.expect("gated above");
            recipient
                .as_deref()
                .and_then(|r| p2tr_x_of_address(network, r))
                .and_then(|recipient_x| {
                    dm::open_sent(
                        &identity.tweaked_seckey,
                        &identity.output_x,
                        &recipient_x,
                        &note_id,
                        &body,
                    )
                    .ok()
                })
        };
        // Legacy singular `recipient` field, kept populated with the FIRST
        // recipient for compatibility with single-recipient callers — same
        // own-only gating as the single-recipient path above (`received` is
        // now settled to its final value, including the externally-funded
        // fallback that can flip it inside the match above).
        if multi && !received && directed {
            recipient = recipients.first().cloned();
        }
        let text = plaintext.and_then(|pt| String::from_utf8(pt).ok());

        notes.push(RecoveredNote {
            note_id,
            txids: pending.txids,
            height: pending.height,
            blocktime: pending.blocktime,
            private,
            directed,
            received,
            sender,
            recipient,
            recipients,
            text,
        });
    }
    // Confirmed first, oldest first; unconfirmed last.
    notes.sort_by_key(|n| n.height.unwrap_or(u64::MAX));
    notes
}

/// Seal (if private) and envelope a note body into its OP_RETURN payloads,
/// plus the recipient scriptPubKey for a directed note. This is the exact
/// body/flags/envelope logic the on-device compose path uses, factored out so
/// an EXTERNAL (PSBT) funder can produce byte-identical on-chain note bytes
/// without holding the funding key. Directed-private notes stay decryptable
/// under external funding because the author key rides on a dust-to-self
/// output (see `extract_notes`' candidate-key search).
pub fn sealed_note_payloads(
    identity: &Identity,
    text: &str,
    private: bool,
    recipient: Option<&Recipient>,
    note_id: [u8; 4],
    max_op_return_bytes: usize,
) -> Result<(Vec<Vec<u8>>, Option<Vec<u8>>), Error> {
    let body = if private {
        if let Some(r) = recipient {
            let recipient_x = r.p2tr_x.ok_or(Error::RecipientNotTaproot)?;
            dm::seal_directed(
                &identity.tweaked_seckey,
                &identity.output_x,
                &recipient_x,
                &note_id,
                text.as_bytes(),
            )?
        } else {
            crypt::seal(&identity.enc_key, &note_id, text.as_bytes())?
        }
    } else {
        text.as_bytes().to_vec()
    };
    let flags = recipient.map_or(0, |_| FLAG_DIRECTED) | if private { FLAG_PRIVATE } else { 0 };
    let payloads = envelope::encode_chunks(note_id, flags, &body, max_op_return_bytes)?;
    Ok((payloads, recipient.map(|r| r.spk.clone())))
}

/// Multi-recipient analog of [`sealed_note_payloads`] — the payload-side
/// primitive for externally-assembled (PSBT / mixed-source) multi-recipient
/// notes, exposing the SAME FROZEN `FLAG_MULTI` body framing the
/// self-contained `compose_directed_note_multi_*` builders emit (count(u8)
/// || utf8 text, or count || wraps || sealed body — see envelope.rs/dm.rs).
///
/// `recipients` are deduped by address (first occurrence wins, order
/// preserved); exactly ONE unique address delegates to
/// [`sealed_note_payloads`] and is byte-identical to it (`content_key`
/// unused there, same convention as the compose delegation). Private
/// requires every recipient taproot. Returns the enveloped payloads plus
/// each recipient's scriptPubKey in output order — the caller MUST place
/// the recipient outputs in exactly that order (wrap order = output order).
pub fn sealed_note_payloads_multi(
    identity: &Identity,
    text: &str,
    private: bool,
    recipients: &[Recipient],
    note_id: [u8; 4],
    content_key: [u8; 32],
    max_op_return_bytes: usize,
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), Error> {
    let mut deduped: Vec<&Recipient> = Vec::new();
    for r in recipients {
        if !deduped.iter().any(|existing| existing.address == r.address) {
            deduped.push(r);
        }
    }
    if deduped.is_empty() || deduped.len() > 255 {
        return Err(Error::Envelope("recipients: 1..=255"));
    }
    if deduped.len() == 1 {
        let (payloads, spk) =
            sealed_note_payloads(identity, text, private, Some(deduped[0]), note_id, max_op_return_bytes)?;
        return Ok((payloads, vec![spk.expect("recipient was given")]));
    }
    let body = multi_body(identity, text, private, note_id, &deduped, content_key)?;
    let flags = FLAG_DIRECTED | FLAG_MULTI | if private { FLAG_PRIVATE } else { 0 };
    let payloads = envelope::encode_chunks(note_id, flags, &body, max_op_return_bytes)?;
    Ok((payloads, deduped.iter().map(|r| r.spk.clone()).collect()))
}

/// Shared tail of both compose paths: body → enveloped payloads → signed tx.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn compose_inner(
    identity: &Identity,
    utxos: &[Utxo],
    note_id: [u8; 4],
    flags: u8,
    body: &[u8],
    recipient_spk: Option<&[u8]>,
    recipient_amount: u64,
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let payloads = envelope::encode_chunks(note_id, flags, body, max_op_return_bytes)?;
    build_note_tx_with_change(
        utxos,
        &identity.output_x,
        &payloads,
        recipient_spk,
        recipient_amount,
        change_spk,
        fee_rate,
        lock_time,
        &identity.tweaked_seckey,
        aux,
    )
}

/// Compose path: text → (sealed) body → enveloped payloads → signed tx.
#[allow(clippy::too_many_arguments)]
pub fn compose_note(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    compose_note_with_change(
        identity, utxos, text, private, note_id, None, max_op_return_bytes, fee_rate, lock_time, aux,
    )
}

/// Like `compose_note`, but change goes to `change_spk` when Some.
#[allow(clippy::too_many_arguments)]
pub fn compose_note_with_change(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let body = if private {
        crypt::seal(&identity.enc_key, &note_id, text.as_bytes())?
    } else {
        text.as_bytes().to_vec()
    };
    let flags = if private { FLAG_PRIVATE } else { 0 };
    compose_inner(
        identity, utxos, note_id, flags, &body, None, crate::DUST_LIMIT, change_spk,
        max_op_return_bytes, fee_rate, lock_time, aux,
    )
}

/// Directed compose: like `compose_note` but the note is addressed TO
/// `recipient` — a DUST_LIMIT output delivers/indexes it at their address.
/// Private bodies are sealed under the static-static ECDH key (dm.rs), so
/// only the recipient (and the sender, reciprocally) can read them; private
/// therefore requires a taproot recipient. Public directed notes go to any
/// segwit address.
#[allow(clippy::too_many_arguments)]
pub fn compose_directed_note(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    recipient: &Recipient,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    compose_directed_note_with_change(
        identity, utxos, text, private, note_id, recipient, None, max_op_return_bytes,
        fee_rate, lock_time,
        aux,
    )
}

/// Like `compose_directed_note`, but change goes to `change_spk` when Some.
#[allow(clippy::too_many_arguments)]
pub fn compose_directed_note_with_change(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    recipient: &Recipient,
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    compose_directed_note_with_change_amount(
        identity, utxos, text, private, note_id, recipient, crate::DUST_LIMIT, change_spk,
        max_op_return_bytes, fee_rate, lock_time, aux,
    )
}

/// Like `compose_directed_note_with_change`, but the recipient (gift) output
/// carries `recipient_amount` sats (must be >= DUST_LIMIT) instead of the
/// default dust — lets a directed note double as a gift.
#[allow(clippy::too_many_arguments)]
pub fn compose_directed_note_with_change_amount(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    recipient: &Recipient,
    recipient_amount: u64,
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let body = if private {
        let recipient_x = recipient.p2tr_x.ok_or(Error::RecipientNotTaproot)?;
        dm::seal_directed(
            &identity.tweaked_seckey,
            &identity.output_x,
            &recipient_x,
            &note_id,
            text.as_bytes(),
        )?
    } else {
        text.as_bytes().to_vec()
    };
    let flags = FLAG_DIRECTED | if private { FLAG_PRIVATE } else { 0 };
    compose_inner(
        identity,
        utxos,
        note_id,
        flags,
        &body,
        Some(&recipient.spk),
        recipient_amount,
        change_spk,
        max_op_return_bytes,
        fee_rate,
        lock_time,
        aux,
    )
}

/// Coin-control compose: spend EXACTLY `inputs` (no auto-selection).
/// Change (self unless `change_spk`) is the leftover.
#[allow(clippy::too_many_arguments)]
pub fn compose_note_exact(
    identity: &Identity,
    inputs: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let body = if private {
        crypt::seal(&identity.enc_key, &note_id, text.as_bytes())?
    } else {
        text.as_bytes().to_vec()
    };
    let flags = if private { FLAG_PRIVATE } else { 0 };
    let payloads = envelope::encode_chunks(note_id, flags, &body, max_op_return_bytes)?;
    build_note_tx_exact(
        inputs,
        &identity.output_x,
        &payloads,
        None,
        crate::DUST_LIMIT,
        change_spk,
        fee_rate,
        lock_time,
        &identity.tweaked_seckey,
        aux,
    )
}

/// Coin-control directed compose: spend EXACTLY `inputs`.
#[allow(clippy::too_many_arguments)]
pub fn compose_directed_note_exact(
    identity: &Identity,
    inputs: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    recipient: &Recipient,
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    compose_directed_note_exact_amount(
        identity, inputs, text, private, note_id, recipient, crate::DUST_LIMIT, change_spk,
        max_op_return_bytes, fee_rate, lock_time, aux,
    )
}

/// Like `compose_directed_note_exact`, but the recipient (gift) output carries
/// `recipient_amount` sats (must be >= DUST_LIMIT).
#[allow(clippy::too_many_arguments)]
pub fn compose_directed_note_exact_amount(
    identity: &Identity,
    inputs: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    recipient: &Recipient,
    recipient_amount: u64,
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let body = if private {
        let recipient_x = recipient.p2tr_x.ok_or(Error::RecipientNotTaproot)?;
        dm::seal_directed(
            &identity.tweaked_seckey,
            &identity.output_x,
            &recipient_x,
            &note_id,
            text.as_bytes(),
        )?
    } else {
        text.as_bytes().to_vec()
    };
    let flags = FLAG_DIRECTED | if private { FLAG_PRIVATE } else { 0 };
    let payloads = envelope::encode_chunks(note_id, flags, &body, max_op_return_bytes)?;
    build_note_tx_exact(
        inputs,
        &identity.output_x,
        &payloads,
        Some(&recipient.spk),
        recipient_amount,
        change_spk,
        fee_rate,
        lock_time,
        &identity.tweaked_seckey,
        aux,
    )
}

// ---------------------------------------------------------------------
// Multi-recipient directed compose (FLAG_MULTI, 2..=255 recipients) — the
// content-key hybrid scheme (dm.rs). Additive: none of the single-
// recipient compose functions above are touched.
// ---------------------------------------------------------------------

/// Dedupe `recipients` by address (first occurrence wins, order otherwise
/// preserved) and validate the resulting count is 1..=255 — shared by both
/// multi-recipient compose entry points below.
fn dedupe_recipients(recipients: &[(Recipient, u64)]) -> Result<Vec<&(Recipient, u64)>, Error> {
    let mut deduped: Vec<&(Recipient, u64)> = Vec::new();
    for r in recipients {
        if !deduped.iter().any(|(existing, _)| existing.address == r.0.address) {
            deduped.push(r);
        }
    }
    if deduped.is_empty() || deduped.len() > 255 {
        return Err(Error::Envelope("recipients: 1..=255"));
    }
    Ok(deduped)
}

/// Build the FLAG_MULTI body: `count(u8) || utf8 text` (public) or
/// `count(u8) || count × wrap(72B) || sealed_body` (private, via
/// `dm::seal_multi`). Shared by both compose entry points below.
fn multi_body(
    identity: &Identity,
    text: &str,
    private: bool,
    note_id: [u8; 4],
    deduped: &[&Recipient],
    content_key: [u8; 32],
) -> Result<Vec<u8>, Error> {
    if private {
        let recipients_x: Vec<[u8; 32]> = deduped
            .iter()
            .map(|r| r.p2tr_x.ok_or(Error::RecipientNotTaproot))
            .collect::<Result<_, _>>()?;
        let (wraps, sealed_body) = dm::seal_multi(
            &identity.tweaked_seckey,
            &identity.output_x,
            &recipients_x,
            &note_id,
            &content_key,
            text.as_bytes(),
        )?;
        let mut body = Vec::with_capacity(1 + wraps.len() * dm::WRAP_LEN + sealed_body.len());
        body.push(deduped.len() as u8);
        for w in &wraps {
            body.extend_from_slice(w);
        }
        body.extend_from_slice(&sealed_body);
        Ok(body)
    } else {
        let mut body = Vec::with_capacity(1 + text.len());
        body.push(deduped.len() as u8);
        body.extend_from_slice(text.as_bytes());
        Ok(body)
    }
}

/// Multi-recipient directed compose: like `compose_directed_note_with_change_amount`
/// but for MANY recipients, each with its own gift amount (>= DUST_LIMIT).
/// Private bodies are sealed ONCE under a caller-supplied `content_key`
/// (never stored — same convention as `note_id`; TRNG'd by the app) and
/// wrapped once per recipient under the usual pairwise ECDH key — see
/// dm.rs's module docs for the full scheme. Private therefore requires
/// every recipient to be taproot (`RecipientNotTaproot` otherwise); public
/// allows any segwit address, same policy as the single-recipient path.
///
/// `recipients` is deduped by address (first occurrence wins) BEFORE
/// anything else, so a call that collapses to exactly one UNIQUE address —
/// whether it started with one entry or several duplicates of the same
/// address — delegates to `compose_directed_note_with_change_amount` and
/// is therefore byte-identical to today's single-recipient wire format (no
/// FLAG_MULTI, no count byte, no wraps, `content_key` unused).
#[allow(clippy::too_many_arguments)]
pub fn compose_directed_note_multi_with_change(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    recipients: &[(Recipient, u64)],
    content_key: [u8; 32],
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let deduped = dedupe_recipients(recipients)?;
    if deduped.len() == 1 {
        let (recipient, amount) = deduped[0];
        return compose_directed_note_with_change_amount(
            identity,
            utxos,
            text,
            private,
            note_id,
            recipient,
            *amount,
            change_spk,
            max_op_return_bytes,
            fee_rate,
            lock_time,
            aux,
        );
    }
    let recips: Vec<&Recipient> = deduped.iter().map(|(r, _)| r).collect();
    let body = multi_body(identity, text, private, note_id, &recips, content_key)?;
    let flags = FLAG_DIRECTED | FLAG_MULTI | if private { FLAG_PRIVATE } else { 0 };
    let payloads = envelope::encode_chunks(note_id, flags, &body, max_op_return_bytes)?;
    let recipient_pairs: Vec<(Vec<u8>, u64)> =
        deduped.iter().map(|(r, amount)| (r.spk.clone(), *amount)).collect();
    build_note_tx_multi_with_change(
        utxos,
        &identity.output_x,
        &payloads,
        &recipient_pairs,
        change_spk,
        fee_rate,
        lock_time,
        &identity.tweaked_seckey,
        aux,
    )
}

/// Coin-control (`_exact`) analog of [`compose_directed_note_multi_with_change`]:
/// spend EXACTLY `inputs`. Same dedup/1-entry-delegation rule (delegates to
/// `compose_directed_note_exact_amount`, byte-identical for a single
/// unique address).
#[allow(clippy::too_many_arguments)]
pub fn compose_directed_note_multi_exact(
    identity: &Identity,
    inputs: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    recipients: &[(Recipient, u64)],
    content_key: [u8; 32],
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let deduped = dedupe_recipients(recipients)?;
    if deduped.len() == 1 {
        let (recipient, amount) = deduped[0];
        return compose_directed_note_exact_amount(
            identity,
            inputs,
            text,
            private,
            note_id,
            recipient,
            *amount,
            change_spk,
            max_op_return_bytes,
            fee_rate,
            lock_time,
            aux,
        );
    }
    let recips: Vec<&Recipient> = deduped.iter().map(|(r, _)| r).collect();
    let body = multi_body(identity, text, private, note_id, &recips, content_key)?;
    let flags = FLAG_DIRECTED | FLAG_MULTI | if private { FLAG_PRIVATE } else { 0 };
    let payloads = envelope::encode_chunks(note_id, flags, &body, max_op_return_bytes)?;
    let recipient_pairs: Vec<(Vec<u8>, u64)> =
        deduped.iter().map(|(r, amount)| (r.spk.clone(), *amount)).collect();
    build_note_tx_multi_exact(
        inputs,
        &identity.output_x,
        &payloads,
        &recipient_pairs,
        change_spk,
        fee_rate,
        lock_time,
        &identity.tweaked_seckey,
        aux,
    )
}

/// Cost preview for the compose screen: (payload_lens, est_vsize) for the
/// current text. Pure arithmetic — no crypto runs (see crypt::SEAL_OVERHEAD).
pub fn estimate_note_cost(
    text_len: usize,
    private: bool,
    max_op_return_bytes: usize,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
) -> Result<(usize, usize), Error> {
    let body_len = if private { text_len + crypt::SEAL_OVERHEAD } else { text_len };
    if body_len == 0 {
        return Err(Error::Envelope("empty body"));
    }
    if max_op_return_bytes <= envelope::HEADER_LEN {
        return Err(Error::Envelope("max_payload smaller than header"));
    }
    let chunk_size = max_op_return_bytes - envelope::HEADER_LEN;
    let total = body_len.div_ceil(chunk_size);
    if total > u8::MAX as usize {
        return Err(Error::PayloadTooLarge);
    }
    let mut payload_lens = vec![max_op_return_bytes; total - 1];
    let tail = body_len - (total - 1) * chunk_size;
    payload_lens.push(envelope::HEADER_LEN + tail);
    let vsize = crate::tx::estimate_vsize(n_inputs.max(1), &payload_lens, recipient_spk_len, true);
    Ok((total, vsize))
}
