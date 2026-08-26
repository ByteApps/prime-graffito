mod notebooks;
mod passphrase;
mod spending;
mod theme;

use std::cell::{OnceCell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use notes_core::address::Recipient;
use notes_core::bundle::{
    compose_directed_note_multi_exact, compose_directed_note_multi_with_change,
    compose_directed_note_pq_exact_amount, compose_directed_note_pq_with_change_amount,
    compose_note_exact, compose_note_pq_exact, compose_note_pq_with_change, decode_scanned,
    estimate_note_cost, estimate_note_cost_pq, extract_notes_pq, sealed_note_payloads,
    sealed_note_payloads_multi, Identity, SyncBundle,
};
use notes_core::address::p2tr_script_pubkey;
use notes_core::keys::generate_aux_rand;
use notes_core::pq;
use notes_core::tx::{
    build_note_tx_mixed_exact_anchored_multi, build_sweep_tx_multi, estimate_sweep_vsize,
    estimate_vsize_mixed, InputKind, LockTimePolicy, MixedInput, NoteTx, SweepSource, Utxo,
};
use notes_core::Network;
use serde::{Deserialize, Serialize};
use spending::SpendingIndex;
use slint_keyos_platform::app_ui2;
use slint_keyos_platform::fs::{self, Location, OpenFlags};
use slint_keyos_platform::gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult};
use slint_keyos_platform::navigation::open_qr_scanner;
use slint_keyos_platform::qrcode;
use slint_keyos_platform::slint::{
    Color, ComponentHandle, Image, Model, SharedString, Timer, VecModel,
};

security::use_api!();

app_ui2!("Graffito");

type Fs = fs::FileSystem<fs_permissions::FileSystemPermissions>;

/// Below this the 12-byte envelope header dominates and a 255-chunk note
/// holds almost nothing.
const MIN_CHUNK: usize = 20;
/// Default chunk ceiling: Bitcoin Core v30's relay default (verified live
/// on mempool.space). Chunk size is a pure DEVICE setting — bundles carry
/// no relay policy; if an endpoint rejects, pick "80 compat" in Settings
/// and recompose.
const DEFAULT_CHUNK: usize = 100_000;
/// Bitcoin standardness ceiling on a single transaction: `MAX_STANDARD_TX_WEIGHT`
/// (400_000 WU) / 4 = 100_000 vB. Nodes won't relay a bigger tx, so this — NOT
/// the per-output chunk size — is the hard wall on one note (a note is one tx of
/// ≤255 OP_RETURN chunks). At a small chunk size the 255-chunk cap binds first,
/// so raising the size to DEFAULT_CHUNK can rescue a note that overflows.
const MAX_STANDARD_TX_VSIZE: usize = 100_000;

/// Whether the composed note fits in one standard tx, and if not, whether
/// raising the chunk size to Standard (DEFAULT_CHUNK) would rescue it.
enum FitCheck {
    Ok,
    /// Over now, but fits at Standard — the user is on a smaller setting whose
    /// 255-chunk cap binds first. Offer to switch.
    FitsAtStandard,
    /// Over even at Standard: the ~100 kB per-tx network wall. No setting helps.
    HardWall,
}

// `pq_extra` = `pq::pq_overhead(pq_flags, alg)` bytes (0 when the compose
// Security section is inactive) — folded into the same `estimate_note_cost`
// arithmetic `estimate_note_cost_pq` uses internally, so a pq-layered
// note's ceiling/chunk-size checks see its real (larger) body.
fn note_fits(
    text_len: usize,
    private: bool,
    chunk: usize,
    recipient_spk_len: Option<usize>,
    pq_extra: usize,
) -> bool {
    estimate_note_cost(text_len + pq_extra, private, chunk, 1, recipient_spk_len)
        .map(|(_, vsize)| vsize <= MAX_STANDARD_TX_VSIZE)
        .unwrap_or(false) // Err = >255 chunks → over-limit
}

fn fit_check(
    effective_chunk: usize,
    text_len: usize,
    private: bool,
    recipient_spk_len: Option<usize>,
    pq_extra: usize,
) -> FitCheck {
    if note_fits(text_len, private, effective_chunk, recipient_spk_len, pq_extra) {
        FitCheck::Ok
    } else if effective_chunk < DEFAULT_CHUNK
        && note_fits(text_len, private, DEFAULT_CHUNK, recipient_spk_len, pq_extra)
    {
        FitCheck::FitsAtStandard
    } else {
        FitCheck::HardWall
    }
}

const STATE_DIR: &str = "/.graffito";
const NOTEBOOKS_PATH: &str = "/.graffito/notebooks.json";
const CONFIG_PATH: &str = "/.graffito/config.json"; // device-level {network, chunk}
const INBOX_DIR: &str = "/graffito/inbox";
const OUTBOX_DIR: &str = "/graffito/outbox";

// ---------------------------------------------------------------- state

#[derive(Serialize, Deserialize, Clone)]
struct NoteRec {
    /// The note's id IS its txid (lowercase hex) — PLAN-pnte-redesign.md,
    /// one note = one tx. `txid` below is now always equal to this; kept
    /// as a separate field for back-compat with call sites/UI bindings
    /// that read it distinctly.
    id: String,
    text: String,
    private: bool,
    txid: String,
    raw_hex: String, // "" for notes recovered from chain (already broadcast)
    fee: u64,
    vsize: u64,
    chunks: u64,
    height: Option<u64>,
    blocktime: Option<u64>,
    status: String, // "pending" | "confirmed"
    // Directed notes (all default so pre-existing state.json loads as-is).
    #[serde(default)]
    directed: bool,
    /// Recipient address of a note we sent to someone else.
    #[serde(default)]
    to: Option<String>,
    /// Sender address of a note someone sent to us.
    #[serde(default)]
    from: Option<String>,
    /// Every recipient of a multi-recipient directed note (own or received),
    /// in output/wrap order. Empty for self-notes and pre-multi-recipient
    /// state.json entries. `to` stays the primary (first) recipient for
    /// back-compat single-recipient display/log parity.
    #[serde(default)]
    recipients: Vec<String>,
    /// Post-quantum sealing flags (`notes_core::envelope::FLAG_PW`/
    /// `FLAG_MLKEM`) — 0 for an ordinary note. Structural, set once at
    /// scan/compose time from `RecoveredNote.pq_flags`/`SealLayers::flags`
    /// and never recomputed.
    #[serde(default)]
    pq_flags: u8,
    /// Present for a RECEIVED pq note this device couldn't auto-decrypt at
    /// scan time (a password layer, or a combined password+ML-KEM note —
    /// `extract_notes_pq` only auto-tries ML-KEM alone). `text` holds a
    /// placeholder until a manual `unlock-note` succeeds, at which point
    /// this is cleared and `text` becomes the real plaintext — mirrors the
    /// Mac app's `NoteRecord.locked`/`unlock_note`. Never populated for a
    /// note this device composed itself (plaintext is already known then).
    #[serde(default)]
    locked: Option<pq::LockedBody>,
}

#[derive(Serialize, Deserialize, Clone)]
struct UtxoRec {
    txid: String, // display hex
    vout: u32,
    value: u64,
}

/// A send-to contact. Order in `State.contacts` IS the recency (front =
/// most recently used — there is no clock on-device). Device-side
/// convenience only: state.json, NOT recoverable from chain after a wipe.
#[derive(Serialize, Deserialize, Clone)]
struct ContactRec {
    name: String, // "" = unnamed
    address: String,
    /// This contact's ML-KEM public key, armored (`notes_core::pq::export_public`
    /// format — the same armor a Quantum-keys screen "Show public key" QR
    /// carries). Only the public half is ever stored. `None` = no key
    /// scanned yet.
    #[serde(default)]
    mlkem_ek: Option<String>,
}

const MAX_CONTACTS: usize = 20;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct State {
    /// Which notebook (indexed identity) this state belongs to. NOT
    /// persisted — the file path (`state-<account>.json`) implies it; set
    /// on load. Lets `save_state` route without threading the account
    /// through every call site.
    #[serde(skip)]
    account: u32,
    network: String,
    notes: Vec<NoteRec>,
    utxos: Vec<UtxoRec>,
    contacts: Vec<ContactRec>,
    tip_height: Option<u64>,
    bundle_time: Option<u64>,
    /// User-picked chunk size; None = DEFAULT_CHUNK. Purely device-side.
    chunk_override: Option<usize>,
    /// Sender filter: sender keys (addresses, or "self") hidden from this
    /// notebook's notes list. The EXCLUSION set persists — anything not
    /// listed shows, so a new sender is visible by default.
    #[serde(default)]
    excluded_senders: Vec<String>,
    fee_economy: f64,
    fee_normal: f64,
    fee_fast: f64,
    btc_usd: Option<f64>,
}

impl Default for State {
    fn default() -> Self {
        State {
            account: 0,
            network: "mainnet".into(),
            notes: Vec::new(),
            utxos: Vec::new(),
            contacts: Vec::new(),
            tip_height: None,
            bundle_time: None,
            chunk_override: None,
            excluded_senders: Vec::new(),
            fee_economy: 1.0,
            fee_normal: 2.0,
            fee_fast: 5.0,
            btc_usd: None,
        }
    }
}

impl State {
    fn network(&self) -> Network {
        Network::from_str_opt(&self.network).unwrap_or(Network::Mainnet)
    }

    fn balance(&self) -> u64 {
        self.utxos.iter().map(|u| u.value).sum()
    }

    fn core_utxos(&self) -> Vec<Utxo> {
        self.utxos
            .iter()
            .filter_map(|u| {
                let mut txid = [0u8; 32];
                hex::decode_to_slice(&u.txid, &mut txid).ok()?;
                txid.reverse();
                Some(Utxo { txid, vout: u.vout, value: u.value })
            })
            .collect()
    }

    /// Chunk size actually used for composing: the override clamped into
    /// [MIN_CHUNK, DEFAULT_CHUNK], or DEFAULT_CHUNK.
    fn effective_chunk(&self) -> usize {
        self.chunk_override
            .map(|c| c.clamp(MIN_CHUNK, DEFAULT_CHUNK))
            .unwrap_or(DEFAULT_CHUNK)
    }

    /// The sender-filter key of a note: the counterparty for received
    /// notes, else "self" (own notes — self and directed-from-us).
    fn sender_key(n: &NoteRec) -> String {
        match &n.from {
            Some(f) => f.clone(),
            None => "self".to_string(),
        }
    }

    /// Distinct sender keys with counts, newest activity first.
    fn senders(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = Vec::new();
        for n in self.notes.iter().rev() {
            let k = Self::sender_key(n);
            match out.iter_mut().find(|(x, _)| *x == k) {
                Some((_, c)) => *c += 1,
                None => out.push((k, 1)),
            }
        }
        out
    }

    fn is_excluded(&self, key: &str) -> bool {
        self.excluded_senders.iter().any(|s| s == key)
    }

    fn set_excluded(&mut self, key: &str, excluded: bool) {
        if excluded {
            if !self.is_excluded(key) {
                self.excluded_senders.push(key.to_string());
            }
        } else {
            self.excluded_senders.retain(|s| s != key);
        }
    }

    fn fee_rate(&self, tier: i32) -> f64 {
        let rate = match tier {
            0 => self.fee_economy,
            2 => self.fee_fast,
            _ => self.fee_normal,
        };
        if rate <= 0.0 {
            1.0
        } else {
            rate
        }
    }
}

/// A built-and-signed note waiting for user confirmation.
struct Plan {
    note: NoteTx,
    text: String,
    private: bool,
    chunks: u64,
    /// Every recipient of this directed note, in output/wrap order (empty
    /// for a self-note). `recipient` stays as the FIRST entry (or None) for
    /// back-compat call sites that only need the primary address.
    recipients: Vec<String>,
    /// Funding-unification: which spending-wallet coins this note spent
    /// (dropped from the ledger on sign) and, when change went to a fresh
    /// spending address, the address to mark used — both applied ONLY
    /// after a successful sign (see `resolve_change`'s doc comment).
    spending_spent: Vec<(String, u32)>,
    spending_change_addr: Option<spending::SpendingAddress>,
    /// True when change (if any) belongs in the NOTEBOOK ledger — false
    /// when it went to a fresh spending address (`spending_change_addr`
    /// is Some) or an external custom address (neither Some, untracked).
    change_is_notebook: bool,
    /// True when this tx carries the notebook-dust output (decision 4,
    /// refined by the anchored-variant skip rule 2026-07-18: present when
    /// the spending wallet funded part of the note AND no notebook coin
    /// was among the selected inputs — a notebook input already anchors
    /// the tx, making the dust redundant). When true it lands as a NEW
    /// notebook coin right after the OP_RETURN(s)/optional recipient,
    /// before change; when false, change immediately follows the
    /// OP_RETURN(s)/optional recipient — the ledger vout math below
    /// derives both positions from this flag, never a hardcoded offset.
    notebook_dust: bool,
    /// Post-quantum sealing flags (`notes_core::envelope::FLAG_PW`/
    /// `FLAG_MLKEM`) — 0 for an ordinary note. Carried straight into the
    /// persisted `NoteRec` on sign.
    pq_flags: u8,
}

/// A built-and-signed sweep/consolidate waiting for user confirmation.
struct SweepPlan {
    tx: NoteTx,
    kind: &'static str,      // "sweep" | "consolidate"
    dest: Option<String>,    // None = self (consolidate)
    // Wallet-level: which outpoints (display txid, vout) each source
    // notebook contributed, so signing can update every source's ledger;
    // and the destination notebook a consolidate's new coin lands in.
    spent_by_account: Vec<(u32, Vec<(String, u32)>)>,
    dest_account: u32,
}

// ------------------------------------------------------------- helpers

/// The app seed (`GetAppSeed`), fetched LAZILY on first read.
///
/// SDK 1.0.0 made `GetAppSeed` `grantOnFirstUse`: the security server presents
/// a consent prompt through the app's GUI connection and BLOCKS until it is
/// answered. Fetching during `app_main` setup therefore hangs the app forever
/// -- the event loop that would draw that prompt and deliver the answer has
/// not started yet -- with no panic and no log line to say so, which is
/// exactly how it presents: a dead app whose last line is "Starting anonymous
/// server". Under SDK 0.4.0 there was no prompt, so the eager fetch this
/// replaces was correct then and silently became a hang on the port.
///
/// So every read goes through here, and the FIRST read is deliberately made
/// from the boot timer at the end of `app_main`, once `ui.run()` is pumping.
/// Anything reading the seed before that would reintroduce the hang.
fn app_seed_get(cell: &OnceCell<Option<[u8; 32]>>) -> &Option<[u8; 32]> {
    cell.get_or_init(|| match Security::default().app_seed() {
        Ok(seed) => Some(seed),
        Err(_) => {
            log::warn!("identity unavailable: device locked or seed unavailable");
            None
        }
    })
}

/// Derive a notebook's identity from the app seed (None if locked).
/// Every notebook is a per-network BIP-86 leaf under its rotation seed
/// (PLAN-graffito-seed-rotation.md).
fn derive_identity(
    app_seed: &Option<[u8; 32]>,
    meta: &notebooks::NotebookMeta,
    net: &str,
) -> Option<Identity> {
    let seed = app_seed.as_ref()?;
    let network = Network::from_str_opt(net).unwrap_or(Network::Mainnet);
    Identity::from_bip86(seed, meta.seed, network, meta.bip_account, meta.index).ok()
}

/// A notebook's raw BIP-86 leaf secret — needed for post-quantum key
/// derivation (`pq::mlkem_seed_from_leaf`/`mlkem_keypair_from_leaf`), which
/// `Identity::from_bip86` folds away internally (it only exposes the
/// tweaked keys, not the leaf itself). Mirrors `export_leaf_formats`'s use
/// of the same `seeds::derive_leaf` call.
fn derive_leaf_secret(
    app_seed: &Option<[u8; 32]>,
    meta: &notebooks::NotebookMeta,
    net: &str,
) -> Option<[u8; 32]> {
    let seed = app_seed.as_ref()?;
    let network = Network::from_str_opt(net).unwrap_or(Network::Mainnet);
    notes_core::seeds::derive_leaf(seed, meta.seed, network, meta.bip_account, meta.index).ok()
}

/// `pq::MlKemAlg` from a persisted level id (`config.json`'s `mlkem_level`,
/// or an on-chain alg byte) — 0/unknown resolves to the recommended
/// default, ML-KEM-768 (never a hard error; this is a display/UI default,
/// not wire-format decoding).
fn mlkem_alg_from_u8(id: u8) -> pq::MlKemAlg {
    pq::MlKemAlg::from_id(id).unwrap_or(pq::MlKemAlg::MlKem768)
}

fn mlkem_alg_name(alg: pq::MlKemAlg) -> &'static str {
    match alg {
        pq::MlKemAlg::MlKem512 => "ML-KEM-512",
        pq::MlKemAlg::MlKem768 => "ML-KEM-768",
        pq::MlKemAlg::MlKem1024 => "ML-KEM-1024",
    }
}

/// Verbatim-pinned description strings — same wording as the graffito
/// Mac app's `MlKemLevel::describe()`, so a contact importing a Prime
/// device's exported key sees identical copy on either platform.
fn mlkem_alg_describe(alg: pq::MlKemAlg) -> &'static str {
    match alg {
        pq::MlKemAlg::MlKem512 => {
            "Lowest parameter size; offers security roughly comparable to AES-128."
        }
        pq::MlKemAlg::MlKem768 => {
            "Standard recommendation for most general applications; provides security \
             comparable to AES-192."
        }
        pq::MlKemAlg::MlKem1024 => {
            "Highest parameter size; offers security comparable to AES-256 for maximum \
             long-term protection."
        }
    }
}

/// Every one of a notebook's three ML-KEM receive keypairs (512/768/1024),
/// derived from its leaf secret — for `extract_notes_pq`'s auto-unlock
/// candidate set and for the Quantum-keys screen's fingerprint/export.
/// Cheap: deterministic keygen from an HKDF-derived seed, no entropy draw
/// (`pq.rs`'s FROZEN per-notebook derivation, shared byte-for-byte with the
/// Mac app).
fn derive_mlkem_keypairs(leaf_secret: &[u8; 32]) -> Vec<pq::MlKemKeypair> {
    [pq::MlKemAlg::MlKem512, pq::MlKemAlg::MlKem768, pq::MlKemAlg::MlKem1024]
        .into_iter()
        .map(|alg| pq::mlkem_keypair_from_leaf(leaf_secret, alg))
        .collect()
}

/// Parse a contact's stored armored ML-KEM public key into `(level,
/// fingerprint)` for display (contact picker badge, naming-modal caption,
/// compose recipient caption) — `notes_core::pq::import_public` +
/// `pq::fingerprint`, same as the Quantum-keys screen and the Mac app's
/// `pqkeys::contact_pq_display`.
fn contact_pq_display(armor: &str) -> Result<(pq::MlKemAlg, String), String> {
    let (alg, ek) = pq::import_public(armor).map_err(|e| e.to_string())?;
    Ok((alg, pq::fingerprint(alg, &ek)))
}

/// "ML-KEM-768 · xxxx xxxx xxxx xxxx" — the one-line display format shared
/// by the contact picker's PQ badge/caption, the naming modal, and the
/// compose Security section's recipient-key caption.
fn contact_pq_caption(armor: &str) -> String {
    contact_pq_display(armor)
        .map(|(alg, fp)| format!("{} · {fp}", mlkem_alg_name(alg)))
        .unwrap_or_default()
}

/// Post-quantum status line for the compose Security section — mirrors the
/// Mac app's `passphrase::security_label` wording verbatim (ported for
/// cross-platform copy parity). Reachable from two shapes: a directed
/// private single-recipient draft (`directed == true`, both layers
/// possible) and a private SELF-note (`directed == false`,
/// PLAN-graffito-self-pw.md for the passphrase layer; PLAN-graffito-
/// quantum-key.md for `mlkem_level`, which is `Some` on a self-note ONLY
/// when the device's personal quantum key is active for this draft — a
/// self-note never offers a seed-derived KEM, so `Some` here always means
/// the non-seed device key). `passphrase_verified` = the typed text is
/// byte-identical to the last `passphrase::generate()` output (the ONLY
/// way a passphrase counts toward quantum resistance — an unverified
/// typed/pasted phrase never does, however long).
fn pq_security_label(
    private: bool,
    directed: bool,
    passphrase_active: bool,
    passphrase_verified: bool,
    mlkem_level: Option<pq::MlKemAlg>,
) -> String {
    if !private {
        return "Public note: anyone can read it on the blockchain, forever.".to_string();
    }
    let passphrase_counts = passphrase_active && passphrase_verified;
    if !directed {
        // Self-note: already sealed with a seed-derived key, so a
        // passphrase here guards a DIFFERENT threat than the directed
        // case's on-chain-ECDH harvest-now-decrypt-later — seed
        // compromise, or a quantum-recovered leaf secret from an exported
        // xpub/descriptor. Forgetting the password makes the note
        // unrecoverable, seed or no seed, which every password-mentioning
        // branch below says plainly. `mlkem_level` (PLAN-graffito-
        // quantum-key.md): the device's own non-seed quantum key — unlike
        // the password, losing THIS key (not just forgetting it) makes
        // the note unrecoverable, so the copy below says "readable only
        // where this quantum key is present" rather than reusing the
        // directed case's "hybrid encryption" framing.
        return match (mlkem_level, passphrase_active) {
            (None, false) => "Private note: sealed with a key derived from your seed. Already \
                 quantum-resistant — no public-key material ever touches the chain."
                .to_string(),
            (None, true) if passphrase_counts => format!(
                "Password-protected: not even your seed reads this back without it \
                 (~{:.0}-bit passphrase). Forget it and the note is gone forever, seed \
                 or no seed.",
                passphrase::GENERATED_BITS
            ),
            (None, true) => "Password added — strength unverifiable. Forget it and the note is \
                 gone forever, seed or no seed."
                .to_string(),
            (Some(level), false) => format!(
                "Quantum-resistant: readable only on this device — or another holding your \
                 {} personal quantum key. Losing that key loses the note, seed or no seed.",
                mlkem_alg_name(level)
            ),
            (Some(level), true) if passphrase_counts => format!(
                "Quantum-resistant: readable only where your {} personal quantum key is \
                 present, plus a strong passphrase (~{:.0} bits). Losing either loses the \
                 note.",
                mlkem_alg_name(level),
                passphrase::GENERATED_BITS
            ),
            (Some(level), true) => format!(
                "Quantum-resistant: readable only where your {} personal quantum key is \
                 present — passphrase layer added but unverified.",
                mlkem_alg_name(level)
            ),
        };
    }
    match (mlkem_level, passphrase_active) {
        (None, false) => {
            "Directed note: end-to-end encrypted (~128-bit ECDH), but NOT quantum-resistant."
                .to_string()
        }
        (None, true) if !passphrase_counts => {
            "Passphrase added — strength unverifiable, not counted as quantum-resistant."
                .to_string()
        }
        (None, true) => format!(
            "Quantum-resistant: protected by a strong passphrase (~{:.0} bits).",
            passphrase::GENERATED_BITS
        ),
        (Some(level), false) => format!(
            "Quantum-resistant: protected by {} hybrid encryption.",
            mlkem_alg_name(level)
        ),
        (Some(level), true) if passphrase_counts => format!(
            "Quantum-resistant: {} hybrid encryption plus a strong passphrase (~{:.0} bits).",
            mlkem_alg_name(level),
            passphrase::GENERATED_BITS
        ),
        (Some(level), true) => format!(
            "Quantum-resistant via {} hybrid encryption — passphrase layer added but unverified.",
            mlkem_alg_name(level)
        ),
    }
}

/// The active notebook's leaf key rendered as (raw hex, WIF) for the
/// Export-keys reveal — a single-address private-key export.
fn export_leaf_formats(
    seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
    index: u32,
) -> Result<(String, String), notes_core::Error> {
    Ok((
        notes_core::export::leaf_hex(seed, seed_index, network, account, index)?.as_str().to_string(),
        notes_core::export::leaf_wif(seed, seed_index, network, account, index)?.as_str().to_string(),
    ))
}

/// The reveal-screen title: master fingerprint · seed index · account.
/// The fingerprint (BIP-32 xfp, not a secret) identifies which seed/wallet
/// the exported keys belong to.
fn export_title(seed: &[u8; 32], seed_index: u32, account: u32) -> String {
    match notes_core::seeds::seed_fingerprint_hex(seed, seed_index) {
        Ok(fp) => format!("{fp} · Seed {seed_index} · account {account}"),
        Err(_) => format!("Seed {seed_index} · account {account}"),
    }
}

/// Every ACTIVE notebook with spendable coins, as
/// (account, output_x, tweaked_seckey, coins) — the inputs to a
/// wallet-level sweep/consolidate (`build_sweep_tx_multi`). Reads each
/// notebook's state from disk, so flush the active notebook first.
fn wallet_sources(
    fs: &Fs,
    ix: &notebooks::NotebookIndex,
    app_seed: &Option<[u8; 32]>,
    net: &str,
    ctx: (u32, u32),
) -> Vec<(u32, [u8; 32], [u8; 32], Vec<Utxo>)> {
    ix.visible(ctx.0, ctx.1)
        .filter_map(|m| {
            let st = load_state(fs, net, m.account);
            let coins = st.core_utxos();
            if coins.is_empty() {
                return None;
            }
            let id = derive_identity(app_seed, m, net)?;
            Some((m.account, id.output_x, id.tweaked_seckey, coins))
        })
        .collect()
}

/// Coin count + total across the wallet's visible notebooks ON `net`.
fn wallet_balance(
    fs: &Fs,
    ix: &notebooks::NotebookIndex,
    net: &str,
    ctx: (u32, u32),
) -> (usize, u64) {
    let mut n = 0;
    let mut total = 0;
    for m in ix.visible(ctx.0, ctx.1) {
        let st = load_state(fs, net, m.account);
        n += st.utxos.len();
        total += st.balance();
    }
    (n, total)
}

/// Device-level settings shared by every notebook (Sal 2026-07-11:
/// network is wallet-wide). Persisted at CONFIG_PATH.
#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct DeviceConfig {
    network: String,
    chunk_override: Option<usize>,
    /// Active rotation seed index (recovery-seeds; new bip86 notebooks
    /// derive under it).
    seed_index: u32,
    /// Active BIP-86 account — the wallet context (rev-3 parity).
    account: u32,
    /// What `nLockTime` composed/swept transactions carry. Default `Tip`
    /// (anti-fee-sniping, matching Core/BDK), resolved against the tip the
    /// last imported bundle reported — this device is offline, so that
    /// height can be stale, which is harmless: the tx is simply already
    /// final. `Zero` restores the pre-2026-07-27 behavior.
    lock_time: LockTimePolicy,
    /// Default ML-KEM level (`pq::MlKemAlg::id()`) the Quantum-keys screen
    /// shows/exports — 0 = unset, resolved to ML-KEM-768 (`mlkem_alg_from_u8`).
    /// Purely a display/export default: compose always seals to whichever
    /// level the resolved recipient's contact key actually advertises.
    #[serde(default)]
    mlkem_level: u8,
}
impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            network: "mainnet".into(),
            chunk_override: None,
            seed_index: 0,
            account: 0,
            lock_time: LockTimePolicy::default(),
            mlkem_level: 0,
        }
    }
}
/// The `nLockTime` to build with: the wallet's policy resolved against the
/// chain height the last imported bundle reported.
///
/// A height that does not fit in `u32` is treated as "unknown" rather than
/// wrapped — a wrapped value could land in the FUTURE, which would make the
/// transaction non-final and get it rejected from the mempool.
fn resolve_locktime(policy: LockTimePolicy, tip: Option<u64>) -> u32 {
    policy.resolve(tip.and_then(|h| u32::try_from(h).ok()))
}

/// The locktime section LABEL: names the height the current policy would
/// actually put on the wire, since "chain height" on an offline device
/// silently means "whatever the last bundle said". Deliberately ONE short
/// line — it is the label itself, and a taller block pushes the settings
/// rows below it past the bottom of the screen (which the simtap suites
/// tap at fixed offsets).
fn locktime_caption(policy: LockTimePolicy, tip: Option<u64>) -> String {
    match policy {
        LockTimePolicy::Tip => match tip {
            Some(h) => format!("Transaction locktime · {h} (last sync)"),
            None => "Transaction locktime · 0 until first sync".to_string(),
        },
        LockTimePolicy::Zero => "Transaction locktime · 0".to_string(),
        LockTimePolicy::Custom { height } => format!("Transaction locktime · {height}"),
    }
}

fn load_config(fs: &Fs) -> Option<DeviceConfig> {
    read_text(fs, CONFIG_PATH, Location::User)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
}

fn save_config(fs: &Fs, cfg: &DeviceConfig) {
    if let Ok(json) = serde_json::to_string(cfg) {
        let _ = ensure_dir(fs, STATE_DIR, Location::User)
            .and_then(|_| write_file(fs, CONFIG_PATH, Location::User, json.as_bytes()));
    }
}

/// Pre-2b per-notebook state path (had its own network field).
fn state_path_v1(account: u32) -> String {
    format!("/.graffito/state-{account}.json")
}

/// Per-(network, notebook) state file: each notebook has a separate ledger
/// on each network (network is device-level now).
fn state_path(net: &str, account: u32) -> String {
    format!("/.graffito/state-{net}-{account}.json")
}

/// Load a notebook's state for `net`, stamping network + account so
/// `save_state` routes back to the same file.
fn load_state(fs: &Fs, net: &str, account: u32) -> State {
    let mut st: State = read_text(fs, &state_path(net, account), Location::User)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();
    st.account = account;
    st.network = net.to_string();
    st
}

fn save_state(fs: &Fs, state: &State) {
    let json = serde_json::to_string(state).expect("state serializes");
    let path = state_path(&state.network, state.account);
    if let Err(e) = ensure_dir(fs, STATE_DIR, Location::User)
        .and_then(|_| write_file(fs, &path, Location::User, json.as_bytes()))
    {
        log::warn!("state save failed: {e}");
    }
}

fn load_notebooks(fs: &Fs) -> notebooks::NotebookIndex {
    read_text(fs, NOTEBOOKS_PATH, Location::User)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn save_notebooks(fs: &Fs, ix: &notebooks::NotebookIndex) {
    let json = serde_json::to_string(ix).expect("index serializes");
    if let Err(e) = ensure_dir(fs, STATE_DIR, Location::User)
        .and_then(|_| write_file(fs, NOTEBOOKS_PATH, Location::User, json.as_bytes()))
    {
        log::warn!("notebook index save failed: {e}");
    }
}

/// Load the notebook index, or an empty one on a fresh install — the
/// device has no onboarding, so first boot shows an empty notebook list
/// and the user creates their first (always bip86) notebook deliberately.
fn boot_notebooks(fs: &Fs) -> notebooks::NotebookIndex {
    if read_text(fs, NOTEBOOKS_PATH, Location::User).is_ok() {
        return load_notebooks(fs);
    }
    let ix = notebooks::NotebookIndex::default();
    save_notebooks(fs, &ix);
    ix
}

/// Device config, migrating pre-2b per-notebook state files
/// (`state-<account>.json`, each with its own network) into the
/// per-network layout (`state-<net>-<account>.json`) on first boot. The
/// device network becomes notebook 0's (else the lowest notebook's, else
/// mainnet); each notebook's ledger is preserved under its own network, so
/// switching the device network later reveals each notebook's chain data.
fn boot_config(fs: &Fs, ix: &notebooks::NotebookIndex) -> DeviceConfig {
    if let Some(cfg) = load_config(fs) {
        return cfg;
    }
    let mut dev: Option<(String, Option<usize>)> = None;
    for m in &ix.notebooks {
        let Ok(json) = read_text(fs, &state_path_v1(m.account), Location::User) else { continue };
        let st: State = serde_json::from_str(&json).unwrap_or_default();
        let net = st.network.clone();
        // Re-route to the per-network file.
        let _ = ensure_dir(fs, STATE_DIR, Location::User).and_then(|_| {
            write_file(fs, &state_path(&net, m.account), Location::User, json.as_bytes())
        });
        if m.account == 0 || dev.is_none() {
            dev = Some((net, st.chunk_override));
        }
    }
    let (network, chunk_override) = dev.unwrap_or_else(|| ("mainnet".into(), None));
    let cfg = DeviceConfig { network, chunk_override, ..Default::default() };
    save_config(fs, &cfg);
    log::info!("cb: config migrated network={} (per-network state files)", cfg.network);
    cfg
}

fn read_text(fs: &Fs, path: &str, loc: Location) -> Result<String, String> {
    use std::io::Read;
    let mut file = fs
        .open_file(path, loc, OpenFlags::READ_ONLY)
        .map_err(|e| format!("{e:?}"))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|_| "read failed".to_string())?;
    String::from_utf8(buf).map_err(|_| "not utf-8".to_string())
}

fn write_file(fs: &Fs, path: &str, loc: Location, bytes: &[u8]) -> Result<(), String> {
    fs.open_file(path, loc, OpenFlags::CREATE)
        .and_then(|mut f| f.overwrite(bytes))
        .map_err(|e| format!("{e:?}"))
}

/// create_dir for each path component (create_dir is single-level).
fn ensure_dir(fs: &Fs, path: &str, loc: Location) -> Result<(), String> {
    let mut so_far = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        so_far.push('/');
        so_far.push_str(part);
        if let Err(e) = fs.create_dir(so_far.as_str(), loc) {
            if !matches!(e, fs::Error::FileAlreadyExists) {
                return Err(format!("{e:?}"));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Personal device quantum key (PLAN-graffito-quantum-key.md) — a single,
// non-seed-derived ML-KEM keypair stored plain in app-sandboxed AppData.
// Unlike the per-notebook seed-derived keys (`derive_mlkem_keypairs`),
// this key has NO seed ancestry: it is NOT recovered by the 24 words, and
// it dies with app uninstall (KeyOS wipes AppData). One slot, v1 — see
// the plan for the replace/export/delete lifecycle. Loaded LAZILY only
// (never at boot): a screen open, a compose eligibility check, or an
// unlock attempt is what first touches this file.
// ---------------------------------------------------------------------

const QUANTUM_KEY_PATH: &str = "/.graffito/quantum-key.asc";

/// Read + parse the stored device quantum key, if any. `None` covers both
/// "no file" and "file present but undecodable" — either way there is no
/// usable key, and the caller falls back to the generate/import state.
fn load_device_quantum_key(fs: &Fs) -> Option<pq::MlKemKeypair> {
    let armor = read_text(fs, QUANTUM_KEY_PATH, Location::User).ok()?;
    let (alg, seed) = pq::import_private(&armor).ok()?;
    Some(pq::MlKemKeypair::from_seed(alg, &seed))
}

fn save_device_quantum_key(fs: &Fs, alg: pq::MlKemAlg, seed: &[u8; 64]) -> Result<(), String> {
    let armor = pq::export_private(alg, seed);
    ensure_dir(fs, STATE_DIR, Location::User)
        .and_then(|_| write_file(fs, QUANTUM_KEY_PATH, Location::User, armor.as_bytes()))
}

fn delete_device_quantum_key(fs: &Fs) -> Result<(), String> {
    fs.remove(QUANTUM_KEY_PATH, Location::User).map_err(|e| format!("{e:?}"))
}

/// Cached lookup: `None` = not checked yet, `Some(None)` = checked, no
/// file, `Some(Some(kp))` = loaded. Reads disk at most once per cache
/// lifetime; every mutating caller (generate/import/replace/delete)
/// writes the new value straight into the cache itself rather than
/// invalidating it, since each already has the fresh keypair (or its
/// absence) in hand.
fn device_quantum_key(
    fs: &Fs,
    cache: &Rc<RefCell<Option<Option<pq::MlKemKeypair>>>>,
) -> Option<pq::MlKemKeypair> {
    if let Some(cached) = cache.borrow().as_ref() {
        return cached.clone();
    }
    let kp = load_device_quantum_key(fs);
    *cache.borrow_mut() = Some(kp.clone());
    kp
}

/// A single QR (v40, EcLevel::M byte mode) holds up to 2331 bytes —
/// `slint_keyos_platform::qrcode::render` PANICS past that (`QrCode::new`
/// is `.expect`ed inside it), so anything landing in a QR must be checked
/// first. An armored ML-KEM PRIVATE key is always tiny (a fixed 64-byte
/// seed regardless of level) and never approaches this; the armored
/// PUBLIC key at ML-KEM-1024 (~2213 chars) is the one shape that gets
/// close, which is exactly why this guard exists — mirrors the
/// `MAX_QR_HEX_CHARS` pattern used for signed-tx QRs, sized for byte-mode
/// text (base64 armor) rather than uppercase-hex alphanumeric mode.
const MAX_QR_ARMOR_CHARS: usize = 2300;

fn qr_fits(text: &str) -> bool {
    text.len() <= MAX_QR_ARMOR_CHARS
}

/// Lazy Airlock mount with format-on-failed-mount recovery (nothing mounts
/// Airlock in the hosted simulator; see paper-wallet NOTES.md).
fn ensure_airlock_mounted(fs: &Fs) -> Result<(), String> {
    // SDK 1.0.0: MountAirlock/FormatAirlock/UnmountAirlock are
    // Foundation-only — a third-party app CALLING them gets AccessDenied,
    // and under the 1.0.0 permission model a denial PANICS inside the
    // generated SDK client (scalar.rs unwrap), killing the app. It is not
    // catchable app-side; `let _ = fs.mount_airlock()` still dies. Found
    // the hard way when the Sync screen's Import tap took the whole app
    // down in the hosted sim (2026-08-21).
    //
    // The app never needed to own the mount anyway: on HARDWARE the
    // SYSTEM mounts Airlock when USB attaches (and unmounts on detach) —
    // and in the hosted sim nothing mounts it at all. So: probe with a
    // GRANTED message (OpenDir on the volume root) whose failure is an
    // ordinary Err, and treat "can't open" as "Airlock not present".
    fs.open_dir("/", Location::Airlock)
        .map(|_| ())
        .map_err(|e| format!("airlock not present: {e:?}"))
}

fn unmount_airlock(_fs: &Fs) {
    // Deliberately nothing — see ensure_airlock_mounted: the system owns
    // the mount lifecycle, and the UnmountAirlock message would panic.
}

fn first_inbox_bundle(fs: &Fs) -> Option<(String, Location, &'static str)> {
    for (loc, label) in [(Location::User, "internal"), (Location::Airlock, "airlock")] {
        if loc == Location::Airlock && ensure_airlock_mounted(fs).is_err() {
            continue;
        }
        let mut names: Vec<String> = Vec::new();
        if let Ok(dir) = fs.open_dir(INBOX_DIR, loc) {
            while let Ok(Some(entry)) = dir.next_entry() {
                if entry.is_file && entry.name.ends_with(".json") {
                    names.push(entry.name);
                }
            }
        }
        names.sort();
        if let Some(name) = names.into_iter().next() {
            return Some((name, loc, label));
        }
    }
    None
}

/// Every `*.json` bundle in the inboxes (Internal first, then Airlock),
/// for the import picker. Airlock is mounted to enumerate, then unmounted
/// — the pick step re-mounts to read the chosen file.
fn list_inbox_bundles(fs: &Fs) -> Vec<(String, Location, &'static str)> {
    let mut out = Vec::new();
    for (loc, label) in [(Location::User, "internal"), (Location::Airlock, "airlock")] {
        if loc == Location::Airlock && ensure_airlock_mounted(fs).is_err() {
            continue;
        }
        let mut names: Vec<String> = Vec::new();
        if let Ok(dir) = fs.open_dir(INBOX_DIR, loc) {
            while let Ok(Some(entry)) = dir.next_entry() {
                if entry.is_file && entry.name.ends_with(".json") {
                    names.push(entry.name);
                }
            }
        }
        if loc == Location::Airlock {
            unmount_airlock(fs);
        }
        names.sort();
        for name in names {
            out.push((name, loc, label));
        }
    }
    out
}

/// Honest-fee-label (2026-07-19, ported from the graffito desktop app): the
/// sub-dust leftover a real signed [`notes_core::tx::NoteTx`] folded into
/// its own fee, decomposed from numbers the build already reports —
/// unlike the compose cost line's PRE-build prediction (`notes-core`'s
/// `fold` module, used before a real tx exists), this is a plain
/// decomposition of an ALREADY-BUILT tx: `note.change == 0` is the exact
/// signal a no-change shape was taken (`tx.rs`'s builders set `change: 0`
/// in that branch, never a `Some(0)` vs `None` ambiguity), so the nominal
/// byte-cost is `ceil(vsize * rate)` and anything the real fee pays ABOVE
/// that must be the folded leftover — zero when nothing folded (an exact
/// fit, or a with-change build).
fn note_fold_amount(fee: u64, vsize: usize, change: u64, rate: f64) -> u64 {
    if change != 0 {
        return 0;
    }
    let nominal = (vsize as f64 * rate).ceil().max(0.0) as u64;
    fee.saturating_sub(nominal)
}

fn sats_line(sats: u64, usd: Option<f64>) -> String {
    match usd {
        Some(price) => format!("{sats} sats (~${:.2})", sats as f64 / 1e8 * price),
        None => format!("{sats} sats"),
    }
}

/// sat/vB for the current tier selection: tiers 0–2 come from the last
/// bundle; tier 3 (custom) parses the user-edited rate field.
fn resolve_rate(tier: i32, rate_text: &str, st: &State) -> Result<f64, String> {
    if tier == 3 {
        match rate_text.trim().parse::<f64>() {
            Ok(r) if r.is_finite() && r > 0.0 && r <= 100_000.0 => Ok(r),
            _ => Err("Enter a valid custom fee rate (sat/vB).".into()),
        }
    } else {
        Ok(st.fee_rate(tier))
    }
}

/// Fresh TRNG content key for a multi-recipient directed note — notes-core
/// never generates this (dm.rs's module docs); caller-supplied, one-shot,
/// NEVER persisted or logged. Independent draw from any signing aux.
fn generate_content_key() -> Result<[u8; 32], String> {
    generate_aux_rand().map_err(|e| e.to_string())
}

/// Sats the recipient (gift) output of a directed note carries. The gift
/// field parsed, floored at DUST_LIMIT — empty/garbage falls back to dust,
/// and a sub-dust value is bumped up (the tx builder rejects below-dust).
/// Self-notes have no recipient output, so this returns 0 and is unused.
fn resolve_gift(directed: bool, gift_text: &str) -> u64 {
    if !directed {
        return 0;
    }
    gift_text
        .trim()
        .parse::<u64>()
        .unwrap_or(notes_core::DUST_LIMIT)
        .max(notes_core::DUST_LIMIT)
}

fn preview_of(text: &str) -> String {
    let one_line: String = text.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    let mut p: String = one_line.chars().take(40).collect();
    if one_line.chars().count() > 40 {
        p.push('…');
    }
    p
}

/// Compact address form for list rows: first 8 + last 6 chars.
fn short_addr(addr: &str) -> String {
    if addr.len() > 17 {
        format!("{}…{}", &addr[..8], &addr[addr.len() - 6..])
    } else {
        addr.to_string()
    }
}

/// Move-to-front recency (no clock on-device): reinsert the address at
/// index 0 preserving any existing name AND quantum key; cap the list at
/// MAX_CONTACTS.
fn upsert_contact(st: &mut State, address: &str) {
    let (name, mlkem_ek) = st
        .contacts
        .iter()
        .position(|c| c.address == address)
        .map(|i| {
            let c = st.contacts.remove(i);
            (c.name, c.mlkem_ek)
        })
        .unwrap_or_default();
    st.contacts.insert(0, ContactRec { name, address: address.to_string(), mlkem_ek });
    st.contacts.truncate(MAX_CONTACTS);
}

/// The compose header line for a picked recipient.
fn to_label_for(st: &State, address: &str) -> String {
    if address.is_empty() {
        return "to: self — my notebook".into();
    }
    match st.contacts.iter().find(|c| c.address == address && !c.name.is_empty()) {
        Some(c) => format!("to: {} ({})", c.name, short_addr(address)),
        None => format!("to: {}", short_addr(address)),
    }
}

// ----------------------------------------------------- spending wallet
// (PLAN-graffito-funding-unification.md, "Prime device" + M2/M3.)

/// Per-chunk OP_RETURN payload lengths for `text_len` bytes — the same
/// arithmetic `notes_core::bundle::estimate_note_cost` uses internally,
/// exposed locally because the funding-unification cost preview needs the
/// actual per-chunk lengths (for `tx::estimate_vsize_mixed`), not just the
/// single-taproot-input vsize that helper returns.
fn payload_lens_for(
    text_len: usize,
    private: bool,
    pq_extra: usize,
    max_op_return_bytes: usize,
) -> Result<Vec<usize>, String> {
    let body_len =
        if private { text_len + notes_core::crypt::SEAL_OVERHEAD + pq_extra } else { text_len };
    notes_core::envelope::payload_lens_for(0, None, body_len, max_op_return_bytes)
        .map_err(|e| e.to_string())
}

/// The active notebook's (rotation seed, BIP-86 account) context — the same
/// key a spending wallet is scoped at (`spending::SpendingIndex`).
fn notebook_ctx(ix: &notebooks::NotebookIndex, account: Option<u32>) -> Option<(u32, u32)> {
    let m = ix.get(account?)?;
    Some((m.seed, m.bip_account))
}

/// A Slint `FundingCoinRow.key` for one coin: "notebook:<txid>:<vout>" or
/// "spending:<txid>:<vout>" — stable, round-trips through `parse_funding_key`.
fn funding_key(spending: bool, txid: &str, vout: u32) -> String {
    format!("{}:{txid}:{vout}", if spending { "spending" } else { "notebook" })
}

fn parse_funding_key(key: &str) -> Option<(bool, String, u32)> {
    let mut parts = key.splitn(3, ':');
    let source = parts.next()?;
    let txid = parts.next()?.to_string();
    let vout: u32 = parts.next()?.parse().ok()?;
    Some((source == "spending", txid, vout))
}

/// Which coins currently fund the compose in progress. `touched` becomes
/// true the first time the user taps a coin on the Pay-from screen — until
/// then, an empty `spending` selection means "use today's byte-identical
/// auto-select over every notebook coin" (`compose_note`/
/// `compose_directed_note_with_change_amount`); once touched (or whenever
/// ANY spending coin is selected, touched or not — the default-source
/// rule), Continue spends EXACTLY the selected set.
#[derive(Default, Clone)]
struct FundingPick {
    notebook: Vec<(String, u32)>,
    spending: Vec<(String, u32)>,
    touched: bool,
}

impl FundingPick {
    fn is_selected(&self, spending: bool, txid: &str, vout: u32) -> bool {
        let set = if spending { &self.spending } else { &self.notebook };
        set.iter().any(|(t, v)| t == txid && *v == vout)
    }

    fn toggle(&mut self, spending: bool, txid: String, vout: u32) {
        let set = if spending { &mut self.spending } else { &mut self.notebook };
        if let Some(i) = set.iter().position(|(t, v)| *t == txid && *v == vout) {
            set.remove(i);
        } else {
            set.push((txid, vout));
        }
        self.touched = true;
    }

    /// "notebook" | "spending" | "mixed" | "none" — display + log label.
    fn mode_label(&self) -> &'static str {
        match (!self.notebook.is_empty(), !self.spending.is_empty()) {
            (true, true) => "mixed",
            (false, true) => "spending",
            (true, false) => "notebook",
            (false, false) => "none",
        }
    }
}

/// Default selection for a freshly-opened compose: spending ONLY when the
/// wallet is enabled AND has a balance (funding-unification's default-
/// source rule) — otherwise every notebook coin, exactly like compose
/// behaved before this feature existed.
fn default_funding_pick(st: &State, spending_section: Option<&spending::SpendingSection>) -> FundingPick {
    let spending_balance = spending_section.map(|s| s.balance()).unwrap_or(0);
    let use_spending =
        spending_section.map(|s| s.enabled).unwrap_or(false) && spending_balance > 0;
    if use_spending {
        FundingPick {
            notebook: Vec::new(),
            spending: spending_section
                .map(|s| s.utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect())
                .unwrap_or_default(),
            touched: false,
        }
    } else {
        FundingPick {
            notebook: st.utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect(),
            spending: Vec::new(),
            touched: false,
        }
    }
}

/// Change destination pick for the compose in progress.
#[derive(Clone)]
struct ChangePickState {
    choice: String, // "auto" | "notebook" | "custom"
    custom_address: String,
}

impl Default for ChangePickState {
    fn default() -> Self {
        ChangePickState { choice: "auto".into(), custom_address: String::new() }
    }
}

/// Resolve the change destination: "custom" parses the typed address;
/// "notebook" is always the notebook's own P2TR spk; "auto" is the notebook
/// UNLESS the current pick spends a spending-wallet coin, in which case it's
/// a fresh spending-wallet change address (protecting funds is the whole
/// point of the feature) — returned alongside the `SpendingAddress` to mark
/// used, which the caller persists ONLY after a successful sign (an aborted
/// compose must never burn a change index).
#[allow(clippy::too_many_arguments)]
fn resolve_change(
    choice: &str,
    custom_address: &str,
    network: Network,
    output_x: &[u8; 32],
    spending_participates: bool,
    app_seed: &[u8; 32],
    seed_index: u32,
    bip_account: u32,
    next_change_index: u32,
) -> Result<(Vec<u8>, Option<spending::SpendingAddress>), String> {
    match choice {
        "custom" => {
            let r = Recipient::parse(network, custom_address).map_err(|e| e.to_string())?;
            Ok((r.spk, None))
        }
        "notebook" => Ok((p2tr_script_pubkey(output_x), None)),
        _ => {
            if spending_participates {
                let key = notes_core::seeds::derive_spending_key(
                    app_seed,
                    seed_index,
                    network,
                    bip_account,
                    1,
                    next_change_index,
                )
                .map_err(|e| e.to_string())?;
                let addr = spending::SpendingAddress {
                    chain: 1,
                    index: next_change_index,
                    address: key.address,
                    spk_hex: hex::encode(&key.script_pubkey),
                };
                Ok((key.script_pubkey, Some(addr)))
            } else {
                Ok((p2tr_script_pubkey(output_x), None))
            }
        }
    }
}

/// Just the change spk's LENGTH, for the keystroke cost preview (no
/// derivation needed — P2WPKH/P2TR spk lengths are fixed regardless of the
/// specific address; only "custom" needs an actual parse).
fn change_spk_len_preview(
    choice: &str,
    custom_address: &str,
    network: Network,
    spending_participates: bool,
) -> Result<usize, String> {
    match choice {
        "custom" => {
            Recipient::parse(network, custom_address).map(|r| r.spk.len()).map_err(|e| e.to_string())
        }
        "notebook" => Ok(34),
        _ => Ok(if spending_participates { 22 } else { 34 }),
    }
}

// ------------------------------------------------ universal confirm gate
// (funding-unification's structured "Confirm & sign" screen, screen 4 —
// every fact shown there is decoded from the actual tx bytes by
// notes-core's `confirm::summarize_signed_tx`; these helpers only gather
// the LOOKUPS `ConfirmCtx` needs, never a verdict.)

/// Every VISIBLE (non-archived) notebook's own P2TR scriptPubKey in
/// wallet context (`seed`, `bip_account`), in notebook index order
/// (`NotebookIndex::visible` iterates `notebooks` sorted by `account`,
/// filtered to `!archived`). This is the `notebook_spks` anchor set for
/// `extract_notes_multi_deduped`'s DISPLAY-OWNER dedup (device
/// CLAUDE.md) — an archived notebook is excluded so its input can never
/// suppress a note display in an active one. Derives one identity per
/// visible notebook, so callers should compute this ONCE per bundle
/// import (or confirm-screen build), never per tx/chunk.
fn wallet_notebook_spks(
    ix: &notebooks::NotebookIndex,
    app_seed: &Option<[u8; 32]>,
    net: &str,
    ctx: (u32, u32),
) -> Vec<Vec<u8>> {
    ix.visible(ctx.0, ctx.1)
        .filter_map(|m| derive_identity(app_seed, m, net))
        .map(|id| p2tr_script_pubkey(&id.output_x))
        .collect()
}

/// Every scriptPubKey this wallet controls in context (`seed`, `bip_account`)
/// — every VISIBLE notebook's own P2TR spk (so consolidate-to-self and
/// cross-notebook outputs classify correctly) plus the spending wallet's
/// already-issued addresses. Returns (every self spk, the spending-only
/// subset), matching `ConfirmCtx`'s `self_spks`/`spending_spks` fields.
fn confirm_self_spks(
    ix: &notebooks::NotebookIndex,
    app_seed: &Option<[u8; 32]>,
    net: &str,
    ctx: (u32, u32),
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let notebook_spks = wallet_notebook_spks(ix, app_seed, net, ctx);
    let spending_spks: Vec<Vec<u8>> =
        ix.spending(net, ctx.0, ctx.1).map(|s| s.self_spks()).unwrap_or_default();
    let mut self_spks = notebook_spks;
    self_spks.extend(spending_spks.iter().cloned());
    (self_spks, spending_spks)
}

/// A short public-note preview decoded from a tx's OP_RETURN output(s) —
/// used only where the caller doesn't already hold the plaintext (the
/// external-PSBT flow; compose already has `text` in hand and sweeps carry
/// no note). Private notes read back as a fixed caption (the ciphertext
/// isn't readable here either way); no PNTE output at all returns `None`
/// (hides the confirm screen's NOTE block).
fn confirm_note_preview(outputs: &[notes_core::tx::TxOut]) -> Option<String> {
    let payloads: Vec<Vec<u8>> = outputs
        .iter()
        .filter_map(|o| notes_core::tx::op_return_payload(&o.script_pubkey))
        .map(<[u8]>::to_vec)
        .collect();
    let decoded = notes_core::envelope::decode_note(&payloads)?;
    if decoded.is_private() {
        return Some("Private note (encrypted)".to_string());
    }
    Some(String::from_utf8(decoded.body).unwrap_or_else(|_| "(unreadable note)".to_string()))
}

/// Self-pw note (PLAN-graffito-self-pw.md): the `pq::LockedBody` to
/// persist for a just-signed self-note (`p.recipients.is_empty()`) that
/// carries a pq layer — a self-pw note is stored LOCKED from the moment
/// it's signed, never with a plaintext cache. Re-decodes the tx's own
/// OP_RETURN payloads (byte-truth, same technique as
/// `confirm_note_preview`) rather than re-deriving anything, and binds
/// the outpoint to the tx's FIRST input exactly like
/// `compose_note_pq_with_change`/`compose_note_pq_exact` did when sealing
/// it. `None` when the tx carries no pq layer (nothing to lock — an
/// ordinary self-note keeps its existing plaintext-cached behavior
/// byte-identically) or its header doesn't decode (unreachable for a tx
/// this device just built and signed itself).
fn self_pw_locked_body(note: &NoteTx) -> Option<pq::LockedBody> {
    let payloads: Vec<Vec<u8>> = note
        .tx
        .outputs
        .iter()
        .filter_map(|o| notes_core::tx::op_return_payload(&o.script_pubkey))
        .map(<[u8]>::to_vec)
        .collect();
    let decoded = notes_core::envelope::decode_note(&payloads)?;
    let pq_bits =
        decoded.flags & (notes_core::envelope::FLAG_PW | notes_core::envelope::FLAG_MLKEM);
    if pq_bits == 0 {
        return None;
    }
    let outpoint = notes_core::tx::outpoint_bytes(note.tx.inputs.first()?);
    Some(pq::LockedBody::new_self(pq_bits, decoded.body, outpoint))
}

/// Populate `ConfirmSign` from notes-core's byte-truth decode of `raw_hex`
/// and show screen 4 — the shared tail for all three confirm-gate
/// producers (compose/sweep/psbt). On `Err`, the caller shows the message
/// on its own origin screen and must NOT navigate.
fn show_confirm_screen(
    ui: &AppWindow,
    kind: &str,
    raw_hex: &str,
    ctx: &notes_core::confirm::ConfirmCtx,
    context_line: String,
    sign_label: &str,
) -> Result<(), String> {
    let summary =
        notes_core::confirm::summarize_signed_tx(raw_hex, ctx).map_err(|e| e.to_string())?;
    let to_row = |r: &notes_core::confirm::SummaryRow| ConfirmRow {
        title: r.title.clone().into(),
        subtitle: r.subtitle.clone().into(),
        amount: r.amount.clone().into(),
        kind: r.kind.clone().into(),
    };
    let cs = ui.global::<ConfirmSign>();
    cs.set_inputs(Rc::new(VecModel::from(summary.inputs.iter().map(to_row).collect::<Vec<_>>())).into());
    cs.set_outputs(Rc::new(VecModel::from(summary.outputs.iter().map(to_row).collect::<Vec<_>>())).into());
    cs.set_context(context_line.into());
    cs.set_txid(summary.txid.clone().into());
    // Display-only pass-through — `summarize_signed_tx` never reads this
    // field itself (see `ConfirmCtx::note_preview`'s doc comment).
    cs.set_note(ctx.note_preview.clone().unwrap_or_default().into());
    cs.set_fee_line(summary.fee_line.clone().into());
    cs.set_warn(summary.warn.clone().unwrap_or_default().into());
    // Cleared unconditionally here (every kind) so a fold row from a
    // previous compose confirm can never leak into a later sweep/psbt
    // confirm that has no fold of its own — callers that DO have a fold
    // to show (compose only; see `on_compose_continue`) set it themselves
    // right after this call returns `Ok`.
    cs.set_fold("".into());
    cs.set_kind(kind.into());
    cs.set_sign_label(sign_label.into());
    log::info!(
        "cb: confirm show kind={kind} txid={} fee={} vsize={} inputs={} outputs={} warn={}",
        summary.txid,
        summary.fee.map(|f| f.to_string()).unwrap_or_else(|| "?".to_string()),
        summary.vsize,
        summary.inputs.len(),
        summary.outputs.len(),
        u8::from(summary.warn.is_some()),
    );
    ui.global::<Ui>().set_screen(4);
    Ok(())
}

// ---------------------------------------------------------------- main

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);

    let fs = cx.fs.clone();
    let ui_weak = ui.as_weak();

    let plan: Rc<RefCell<Option<Plan>>> = Rc::new(RefCell::new(None));
    let sweep_plan: Rc<RefCell<Option<SweepPlan>>> = Rc::new(RefCell::new(None));
    // External PSBT signing (funding-unification): the deserialized-but-
    // UNSIGNED Psbt scanned in stage A (`on_sign_psbt`), stashed until the
    // universal confirm screen's Sign tap actually signs it in stage B —
    // nothing about it is persisted before then.
    let psbt_pending: Rc<RefCell<Option<notes_core::psbt::Psbt>>> = Rc::new(RefCell::new(None));

    // The app seed (GetAppSeed, PIN-gated on hardware) — kept so each
    // notebook's identity can be derived on demand (`Identity::from_bip86`
    // over the notebook's rotation seed + BIP-86 account/index).
    //
    // EMPTY here on purpose: the fetch prompts the user on SDK 1.0.0 and so
    // cannot happen before the event loop runs (see `app_seed_get`). The boot
    // timer at the end of `app_main` primes it.
    let app_seed: Rc<OnceCell<Option<[u8; 32]>>> = Rc::new(OnceCell::new());

    // Notebooks: the index (account -> name/archived) + the ACTIVE notebook.
    // A notebook = an indexed identity; boot lands on the notebook LIST and
    // the active notebook is set when the user taps a row (empty on a fresh
    // install — the device has no onboarding).
    let notebooks: Rc<RefCell<notebooks::NotebookIndex>> =
        Rc::new(RefCell::new(boot_notebooks(&fs)));
    // Device-level network (wallet-wide): one setting shared by every
    // notebook; each notebook's ledger is per-network on disk.
    let device_cfg = boot_config(&fs, &notebooks.borrow());
    let net: Rc<RefCell<String>> = Rc::new(RefCell::new(device_cfg.network.clone()));
    let device_chunk: Rc<RefCell<Option<usize>>> =
        Rc::new(RefCell::new(device_cfg.chunk_override));
    // Active wallet context (recovery-seeds): rotation seed index + BIP-86
    // account. New notebooks derive under it; the list + wallet features
    // scope to it (legacy notebooks are context-free).
    let seed_idx: Rc<RefCell<u32>> = Rc::new(RefCell::new(device_cfg.seed_index));
    let bip_account: Rc<RefCell<u32>> = Rc::new(RefCell::new(device_cfg.account));
    // Anti-fee-sniping policy (wallet-level, like network and chunk).
    let lock_policy: Rc<RefCell<LockTimePolicy>> = Rc::new(RefCell::new(device_cfg.lock_time));
    // Default ML-KEM level for the Quantum-keys screen (wallet-level).
    let mlkem_level: Rc<RefCell<u8>> = Rc::new(RefCell::new(device_cfg.mlkem_level));
    // Quantum-keys screen (27): which notebook's ML-KEM key is shown —
    // `None` until the picker is touched, meaning "active-or-first-visible"
    // (the screen's original single-notebook default); `Some(index)` once
    // the user picks a specific notebook from the picker.
    let quantum_nb: Rc<RefCell<Option<u32>>> = Rc::new(RefCell::new(None));
    let active: Rc<RefCell<Option<u32>>> = Rc::new(RefCell::new(None));
    // Personal device quantum key (PLAN-graffito-quantum-key.md, screen
    // 28): lazily-loaded/cached — see `device_quantum_key`. NOT read here
    // at boot; the first touch is a screen open, a compose eligibility
    // check, or an unlock attempt.
    let device_pq_key: Rc<RefCell<Option<Option<pq::MlKemKeypair>>>> = Rc::new(RefCell::new(None));

    // Persist the device config from the current cells (single source of
    // truth — inline DeviceConfig constructions drift as fields grow).
    let persist_config = {
        let fs = fs.clone();
        let net = net.clone();
        let device_chunk = device_chunk.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let lock_policy = lock_policy.clone();
        let mlkem_level = mlkem_level.clone();
        Rc::new(move || {
            save_config(
                &fs,
                &DeviceConfig {
                    network: net.borrow().clone(),
                    chunk_override: *device_chunk.borrow(),
                    seed_index: *seed_idx.borrow(),
                    account: *bip_account.borrow(),
                    lock_time: *lock_policy.borrow(),
                    mlkem_level: *mlkem_level.borrow(),
                },
            );
        })
    };
    // The ACTIVE notebook's state + identity (both swap on notebook switch);
    // an empty placeholder until a notebook is opened.
    let state = Rc::new(RefCell::new(State::default()));
    let identity: Rc<RefCell<Option<Identity>>> = Rc::new(RefCell::new(None));


    let refresh_home = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let net = net.clone();
        let device_chunk = device_chunk.clone();
        let lock_policy = lock_policy.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let home = ui.global::<Home>();
            home.set_network(net.borrow().clone().into()); // device-level network
            if let Some(id) = identity.borrow().as_ref() {
                let addr = id.address(st.network());
                home.set_qr(qr_image(&addr.to_uppercase()));
                home.set_address(addr.into());
            }
            home.set_balance_line(sats_line(st.balance(), st.btc_usd).into());
            let sync_line = match st.tip_height {
                Some(h) => format!("synced to height {h}"),
                None => "never synced".to_string(),
            };
            home.set_sync_line(sync_line.into());
            let sync = ui.global::<Sync>();
            sync.set_status(
                format!(
                    "network: {}\nbalance: {} sats · {} utxos\nchain height: {}\nfees (sat/vB): {}/{}/{} · chunk: {} bytes",
                    st.network,
                    st.balance(),
                    st.utxos.len(),
                    st.tip_height.map(|h| h.to_string()).unwrap_or("—".into()),
                    st.fee_economy,
                    st.fee_normal,
                    st.fee_fast,
                    st.effective_chunk()
                )
                .into(),
            );
            let settings = ui.global::<Settings>();
            let dchunk = *device_chunk.borrow();
            settings.set_chunk_mode(match dchunk {
                None => 0,
                Some(80) => 1,
                Some(_) => 2,
            });
            let eff = dchunk.map(|c| c.clamp(MIN_CHUNK, DEFAULT_CHUNK)).unwrap_or(DEFAULT_CHUNK);
            settings.set_chunk_text(format!("{eff}").into());
            let policy = *lock_policy.borrow();
            settings.set_locktime_mode(match policy {
                LockTimePolicy::Tip => 0,
                LockTimePolicy::Zero => 1,
                LockTimePolicy::Custom { .. } => 2,
            });
            // Mirror the height the policy would actually use, so the
            // Custom field opens pre-filled with the current value.
            settings.set_locktime_text(format!("{}", resolve_locktime(policy, st.tip_height)).into());
            settings.set_locktime_effective(locktime_caption(policy, st.tip_height).into());
            log::info!(
                "cb: home balance={} utxos={} tip={}",
                st.balance(),
                st.utxos.len(),
                st.tip_height.map(|h| h.to_string()).unwrap_or("none".into())
            );
        }
    };

    let refresh_notes = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            // Sender filter: build the checklist + filter the list. A note
            // is hidden iff its sender key is in the persisted exclusion set.
            let senders: Vec<SenderRow> = st
                .senders()
                .into_iter()
                .map(|(key, count)| {
                    let label = if key == "self" {
                        "Self".to_string()
                    } else {
                        st.contacts
                            .iter()
                            .find(|c| c.address == key && !c.name.is_empty())
                            .map(|c| c.name.clone())
                            .unwrap_or_else(|| short_addr(&key))
                    };
                    SenderRow {
                        excluded: st.is_excluded(&key),
                        key: key.into(),
                        label: label.into(),
                        sub: format!("{count} note(s)").into(),
                    }
                })
                .collect();
            let hidden = senders.iter().filter(|s| s.excluded).count();
            let notes_g = ui.global::<Notes>();
            notes_g.set_senders(Rc::new(VecModel::from(senders)).into());
            notes_g.set_hidden_label(
                if hidden == 0 { "".to_string() } else { format!("{hidden} sender(s) hidden") }.into(),
            );
            let mut recs: Vec<&NoteRec> =
                st.notes.iter().filter(|n| !st.is_excluded(&State::sender_key(n))).collect();
            // Pending first, then newest confirmed first.
            recs.sort_by_key(|n| match n.height {
                None => (0u8, 0i64),
                Some(h) => (1u8, -(h as i64)),
            });
            let rows: Vec<NoteRow> = recs
                .iter()
                .map(|n| NoteRow {
                    id: n.id.clone().into(),
                    preview: preview_of(&n.text).into(),
                    meta: {
                        let base = match n.height {
                            Some(h) => format!("block {h} · {} chunk(s)", n.chunks.max(1)),
                            None => format!("pending · fee {} sats", n.fee),
                        };
                        match (&n.from, &n.to) {
                            (Some(from), _) => format!("{base} · from {}", short_addr(from)),
                            (None, Some(to)) => format!("{base} · to {}", short_addr(to)),
                            _ => base,
                        }
                    }
                    .into(),
                    badge: if n.private { "PRIVATE" } else { "PUBLIC" }.into(),
                    // Post-quantum (pq.rs): pq mirrors the contacts picker's
                    // "PQ" badge (a passphrase and/or ML-KEM layer was
                    // used); locked mirrors the note-view screen's lock
                    // state (a received pq note this device couldn't
                    // auto-decrypt at scan time — still visually distinct
                    // from an unlocked pq note in the list).
                    pq: n.pq_flags != 0,
                    locked: n.locked.is_some(),
                })
                .collect();
            log::info!("cb: refresh-notes n={} hidden={hidden}", rows.len());
            notes_g.set_rows(Rc::new(VecModel::from(rows)).into());
        }
    };

    let refresh_contacts = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            // State order IS recency (front = latest use) — no re-sort.
            let rows: Vec<ContactRow> = st
                .contacts
                .iter()
                .map(|c| ContactRow {
                    address: c.address.clone().into(),
                    name: c.name.clone().into(),
                    label: if c.name.is_empty() { short_addr(&c.address) } else { c.name.clone() }
                        .into(),
                    meta: short_addr(&c.address).into(),
                    pq_caption: c
                        .mlkem_ek
                        .as_deref()
                        .map(contact_pq_caption)
                        .unwrap_or_default()
                        .into(),
                })
                .collect();
            log::info!("cb: refresh-contacts n={}", rows.len());
            ui.global::<Contacts>().set_rows(Rc::new(VecModel::from(rows)).into());
        }
    };

    // Coins screen (9): the UTXO ledger as of the last sync bundle, biggest
    // first. Viewer-first — consolidate is the screen's single action.
    let refresh_coins = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let app_seed = app_seed.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            // Wallet-wide: every ACTIVE notebook's coins, each tagged with
            // its notebook. Flush the active notebook first so its file is
            // current, then read all from disk.
            save_state(&fs, &state.borrow());
            let ix = notebooks.borrow();
            let active_net = net.borrow().clone();
            let ctx = (*seed_idx.borrow(), *bip_account.borrow());
            let btc_usd = state.borrow().btc_usd;
            // (value, notebook name, txid, vout) across the wallet.
            let mut all: Vec<(u64, String, String, u32)> = Vec::new();
            let mut nb_with_coins = 0usize;
            for m in ix.visible(ctx.0, ctx.1) {
                let st2 = load_state(&fs, &active_net, m.account);
                if st2.utxos.is_empty() {
                    continue;
                }
                nb_with_coins += 1;
                let short = derive_identity(app_seed_get(&app_seed), m, &active_net)
                    .map(|id| short_addr(&id.address(st2.network())))
                    .unwrap_or_default();
                let name = notebook_name(&ix, m.account, &short);
                for u in &st2.utxos {
                    all.push((u.value, name.clone(), u.txid.clone(), u.vout));
                }
            }
            all.sort_by_key(|(v, ..)| std::cmp::Reverse(*v));
            let total: u64 = all.iter().map(|(v, ..)| v).sum();
            let rows: Vec<CoinRow> = all
                .iter()
                .map(|(v, name, txid, vout)| CoinRow {
                    label: format!("{v} sats · {name}").into(),
                    meta: format!("txid {} · output {}", short_addr(txid), vout).into(),
                })
                .collect();
            let coins = ui.global::<Coins>();
            coins.set_summary(
                format!(
                    "{} coin(s) · {} across {nb_with_coins} notebook(s)",
                    rows.len(),
                    sats_line(total, btc_usd)
                )
                .into(),
            );
            coins.set_can_consolidate(rows.len() >= 2);
            log::info!("cb: refresh-coins n={} total={total} notebooks={nb_with_coins}", rows.len());
            coins.set_rows(Rc::new(VecModel::from(rows)).into());
        }
    };

    // Sweep screen (10) repricing — every tier tap / rate keystroke. Pure
    // arithmetic (estimate_sweep_vsize is byte-exact vs build_sweep_tx).
    let update_sweep = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let sweep = ui.global::<Sweep>();
            let st = state.borrow();
            let tier = sweep.get_tier();
            if tier != 3 {
                sweep.set_rate_text(format!("{}", st.fee_rate(tier)).into());
            }
            // Wallet-level: inputs are EVERY notebook's coins (flush the
            // active one first so its file reflects the latest ledger).
            save_state(&fs, &st);
            let (n, total) = wallet_balance(
                &fs,
                &notebooks.borrow(),
                &st.network,
                (*seed_idx.borrow(), *bip_account.borrow()),
            );
            sweep.set_inputs_line(format!("Inputs · {n} coin(s) · {total} sats (all notebooks)").into());
            if n == 0 {
                sweep.set_cost_line("Nothing to sweep — no spendable coins.".into());
                sweep.set_can_continue(false);
                return;
            }
            let rate = match resolve_rate(tier, sweep.get_rate_text().as_str(), &st) {
                Ok(r) => r,
                Err(e) => {
                    sweep.set_cost_line(e.into());
                    sweep.set_can_continue(false);
                    return;
                }
            };
            let consolidate = sweep.get_kind() == "consolidate";
            let dest_spk_len = if consolidate {
                34 // our own P2TR
            } else {
                match Recipient::parse(st.network(), sweep.get_dest().as_str()) {
                    Ok(r) => r.spk.len(),
                    Err(_) => {
                        sweep.set_cost_line(
                            format!("Destination is not a valid {} address.", st.network).into(),
                        );
                        sweep.set_can_continue(false);
                        return;
                    }
                }
            };
            let vsize = estimate_sweep_vsize(n, dest_spk_len);
            let fee = (vsize as f64 * rate).ceil() as u64;
            if total <= fee || total - fee < notes_core::DUST_LIMIT {
                sweep.set_cost_line(
                    format!("Balance {total} sats can't cover the ~{fee} sat fee.").into(),
                );
                sweep.set_can_continue(false);
                return;
            }
            let recv = total - fee;
            sweep.set_cost_line(
                if consolidate {
                    format!(
                        "Consolidates {n} coins into one · ~{vsize} vB · fee ~{} @ {rate} sat/vB · keeps {recv} sats",
                        sats_line(fee, st.btc_usd)
                    )
                } else {
                    format!(
                        "Sweeps {total} sats · ~{vsize} vB · fee ~{} @ {rate} sat/vB · destination receives {recv} sats",
                        sats_line(fee, st.btc_usd)
                    )
                }
                .into(),
            );
            sweep.set_can_continue(true);
        }
    };

    // Funding-unification: current per-coin funding pick + change pick for
    // the compose in progress. Reset to the default rule whenever a fresh
    // compose is entered (see `pick_contact` below).
    let funding_pick: Rc<RefCell<FundingPick>> = Rc::new(RefCell::new(FundingPick::default()));
    let change_pick: Rc<RefCell<ChangePickState>> = Rc::new(RefCell::new(ChangePickState::default()));

    // Rebuild the Pay-from screen's rows/summaries, the compose nav row's
    // label, AND Settings' spending card (same underlying section) from
    // `state` + the active notebook's spending section + `funding_pick`.
    let refresh_funding = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let funding_pick = funding_pick.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let active_net = net.borrow().clone();
            let ix = notebooks.borrow();
            let ctx = notebook_ctx(&ix, *active.borrow())
                .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
            let section = ix.spending(&active_net, ctx.0, ctx.1).cloned();
            drop(ix);
            let pick = funding_pick.borrow();

            let nb_rows: Vec<FundingCoinRow> = st
                .utxos
                .iter()
                .map(|u| FundingCoinRow {
                    key: funding_key(false, &u.txid, u.vout).into(),
                    label: format!("{} sats", u.value).into(),
                    meta: format!("txid {} · output {}", short_addr(&u.txid), u.vout).into(),
                    selected: pick.is_selected(false, &u.txid, u.vout),
                })
                .collect();
            let nb_total: u64 = st.utxos.iter().map(|u| u.value).sum();
            let nb_selected_total: u64 = st
                .utxos
                .iter()
                .filter(|u| pick.is_selected(false, &u.txid, u.vout))
                .map(|u| u.value)
                .sum();

            let sp_rows: Vec<FundingCoinRow> = section
                .as_ref()
                .map(|s| {
                    s.utxos
                        .iter()
                        .map(|u| FundingCoinRow {
                            key: funding_key(true, &u.txid, u.vout).into(),
                            label: format!("{} sats", u.value).into(),
                            meta: format!(
                                "txid {} · output {} · idx {}",
                                short_addr(&u.txid),
                                u.vout,
                                u.index
                            )
                            .into(),
                            selected: pick.is_selected(true, &u.txid, u.vout),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let sp_total = section.as_ref().map(|s| s.balance()).unwrap_or(0);
            let sp_enabled = section.as_ref().map(|s| s.enabled).unwrap_or(false);
            let sp_selected_total: u64 = section
                .as_ref()
                .map(|s| {
                    s.utxos
                        .iter()
                        .filter(|u| pick.is_selected(true, &u.txid, u.vout))
                        .map(|u| u.value)
                        .sum()
                })
                .unwrap_or(0);

            let funding = ui.global::<Funding>();
            funding.set_notebook_coins(Rc::new(VecModel::from(nb_rows)).into());
            funding.set_spending_coins(Rc::new(VecModel::from(sp_rows)).into());
            funding.set_notebook_summary(
                format!("{} coin(s) · {} sats", st.utxos.len(), nb_total).into(),
            );
            funding.set_spending_summary(
                if !sp_enabled {
                    "Off".to_string()
                } else if sp_total == 0 {
                    "No coins".to_string()
                } else {
                    format!(
                        "{} coin(s) · {} sats",
                        section.as_ref().map(|s| s.utxos.len()).unwrap_or(0),
                        sp_total
                    )
                }
                .into(),
            );
            funding.set_spending_enabled(sp_enabled);
            let mode = pick.mode_label();
            let selected_total = nb_selected_total + sp_selected_total;
            let selected_n = pick.notebook.len() + pick.spending.len();
            funding.set_warning(
                if mode == "mixed" {
                    "This note spends from both the notebook and the spending wallet — their addresses become publicly linked on-chain.".to_string()
                } else {
                    String::new()
                }
                .into(),
            );

            let compose = ui.global::<Compose>();
            compose.set_pay_from_label(
                match mode {
                    "mixed" => "Mixed",
                    "spending" => "Spending wallet",
                    _ => "Notebook",
                }
                .into(),
            );
            compose
                .set_pay_from_balance(format!("{selected_total} sats · {selected_n} coin(s)").into());

            // Settings' spending card mirrors the SAME section — harmless to
            // refresh even when Settings isn't the visible screen.
            let settings = ui.global::<Settings>();
            settings.set_spending_enabled(sp_enabled);
            if let Some(s) = &section {
                settings.set_spending_balance_line(
                    format!("{} coin(s) · {} sats", s.utxos.len(), s.balance()).into(),
                );
                if let Some(seed) = app_seed_get(&app_seed).as_ref() {
                    let net_v = Network::from_str_opt(&active_net).unwrap_or(Network::Mainnet);
                    if let Ok(key) = notes_core::seeds::derive_spending_key(
                        seed, ctx.0, net_v, ctx.1, 0, s.next_receive,
                    ) {
                        settings.set_spending_address(key.address.clone().into());
                        settings.set_spending_qr(qr_image(&key.address.to_uppercase()));
                    }
                    // Companion watch window (funding-unification gap-
                    // discovery, option (b), 2026-07-19): the next
                    // SPENDING_WINDOW receive AND change addresses — a
                    // lookahead the companion can probe for coins/history the
                    // device hasn't revealed or spent yet, so a restore (or a
                    // funding-wallet-style external deposit straight to a
                    // not-yet-shown address) still gets found on the next
                    // sync. Plain address lines, receive block then change
                    // block, so the whole text pastes straight into the
                    // companion's "Spending wallet addresses" field — no
                    // chain/index prefix (unlike `spending-addresses-text`
                    // above, which is for human display of what's ALREADY
                    // used). Same derivation as everywhere else on this
                    // screen — no new crypto.
                    const SPENDING_WINDOW: u32 = 20;
                    let window_lines: Vec<String> = [0u32, 1u32]
                        .into_iter()
                        .flat_map(|chain| {
                            let base = if chain == 1 { s.next_change } else { s.next_receive };
                            (base..base.saturating_add(SPENDING_WINDOW)).filter_map(move |index| {
                                notes_core::seeds::derive_spending_key(
                                    seed, ctx.0, net_v, ctx.1, chain, index,
                                )
                                .ok()
                                .map(|k| k.address)
                            })
                        })
                        .collect();
                    let window_text = window_lines.join("\n");
                    settings.set_spending_window_text(window_text.clone().into());
                    settings.set_spending_window_qr(qr_image(&window_text.to_uppercase()));
                }
                let addr_lines: Vec<String> = s
                    .used
                    .iter()
                    .map(|a| {
                        format!(
                            "{}/{}  {}",
                            if a.chain == 1 { "change" } else { "receive" },
                            a.index,
                            a.address
                        )
                    })
                    .collect();
                settings.set_spending_addresses_text(addr_lines.join("\n").into());
            } else {
                settings.set_spending_balance_line("0 coin(s) · 0 sats".into());
                settings.set_spending_addresses_text("".into());
                settings.set_spending_window_text("".into());
            }
        }
    };

    // Rebuild the compose nav row's Change label + the Change screen's
    // "Auto" sub-line from `change_pick` + whether the CURRENT funding pick
    // spends any spending-wallet coin.
    let refresh_change = {
        let ui_weak = ui_weak.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let participates = !funding_pick.borrow().spending.is_empty();
            let cp = change_pick.borrow();
            let auto_label = if participates {
                "Fresh spending-wallet address — protects the change from address reuse."
            } else {
                "Notebook address — the same address it goes to today."
            };
            ui.global::<ChangePick>().set_auto_label(auto_label.into());
            let label = match cp.choice.as_str() {
                "custom" if !cp.custom_address.is_empty() => short_addr(&cp.custom_address),
                "custom" => "custom address".to_string(),
                "notebook" => "notebook".to_string(),
                _ if participates => "fresh spending address".to_string(),
                _ => "back to you".to_string(),
            };
            ui.global::<Compose>().set_change_label(label.into());
        }
    };

    // A notebook's display name: its local name, else the 1-based default
    // "Notebook <index+1>" (never empty — rows and the home title read
    // this). Every notebook is created named, so the default only covers
    // entries written before that rule; `addr_short` is the last resort
    // for an account with no index entry at all.
    fn notebook_name(ix: &notebooks::NotebookIndex, account: u32, addr_short: &str) -> String {
        match ix.get(account) {
            Some(m) if !m.name.trim().is_empty() => m.name.clone(),
            Some(m) => notebooks::default_name(m.index),
            None => addr_short.to_string(),
        }
    }

    // Rebuild the notebook list (screen 20) from the index + each
    // notebook's state file. Device has no live balance — the row meta is
    // address-short · note count.
    let refresh_notebooks = {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        Rc::new(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let ix = notebooks.borrow();
            let active_acct = *active.borrow();
            let dev_net = net.borrow().clone();
            let ctx = (*seed_idx.borrow(), *bip_account.borrow());
            let build = |m: &notebooks::NotebookMeta| -> NotebookRow {
                let st = load_state(&fs, &dev_net, m.account);
                let addr = derive_identity(app_seed_get(&app_seed), m, &dev_net)
                    .map(|id| id.address(Network::from_str_opt(&dev_net).unwrap_or(Network::Mainnet)))
                    .unwrap_or_default();
                let short = short_addr(&addr);
                let n = st.notes.len();
                NotebookRow {
                    account: m.account as i32,
                    name: notebook_name(&ix, m.account, &short).into(),
                    meta: format!(
                        "{short} · {n} note{}",
                        if n == 1 { "" } else { "s" }
                    )
                    .into(),
                    active: active_acct == Some(m.account),
                }
            };
            let rows: Vec<NotebookRow> = ix.visible(ctx.0, ctx.1).map(build).collect();
            let archived: Vec<NotebookRow> =
                ix.archived_in_context(ctx.0, ctx.1).map(build).collect();
            let nb = ui.global::<NotebooksUi>();
            nb.set_empty_line(
                if rows.is_empty() {
                    if !archived.is_empty() {
                        "All notebooks are archived.".into()
                    } else {
                        "No notebooks yet — create one to start writing.".into()
                    }
                } else {
                    "".into()
                },
            );
            nb.set_archived_label(
                if archived.is_empty() {
                    "".to_string()
                } else {
                    format!("Archived ({})", archived.len())
                }
                .into(),
            );
            log::info!("cb: notebooks list n={} archived={}", rows.len(), archived.len());
            nb.set_rows(Rc::new(VecModel::from(rows)).into());
            nb.set_archived_rows(Rc::new(VecModel::from(archived)).into());
        })
    };

    // Open a notebook: save the current one, swap identity + state to the
    // target account, refresh every per-notebook view, and show its home.
    let switch_notebook = {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let state = state.clone();
        let identity = identity.clone();
        let active = active.clone();
        let notebooks = notebooks.clone();
        let app_seed = app_seed.clone();
        let net = net.clone();
        let device_chunk = device_chunk.clone();
        let refresh_home = refresh_home.clone();
        let refresh_notes = refresh_notes.clone();
        let refresh_coins = refresh_coins.clone();
        let refresh_contacts = refresh_contacts.clone();
        let refresh_funding = refresh_funding.clone();
        Rc::new(move |account: u32| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if active.borrow().is_some() {
                save_state(&fs, &state.borrow());
            }
            *active.borrow_mut() = Some(account);
            *identity.borrow_mut() = notebooks
                .borrow()
                .get(account)
                .and_then(|m| derive_identity(app_seed_get(&app_seed), m, &net.borrow()));
            let mut loaded = load_state(&fs, &net.borrow(), account);
            loaded.chunk_override = *device_chunk.borrow(); // chunk is device-level
            *state.borrow_mut() = loaded;
            let short = identity
                .borrow()
                .as_ref()
                .map(|id| short_addr(&id.address(state.borrow().network())))
                .unwrap_or_default();
            let title = notebook_name(&notebooks.borrow(), account, &short);
            ui.global::<NotebooksUi>().set_title(title.into());
            log::info!("cb: open-notebook account={account}");
            refresh_home();
            refresh_notes();
            refresh_coins();
            refresh_contacts();
            refresh_funding();
            ui.global::<Ui>().set_screen(0);
        })
    };

    // The single pick funnel (self row / recent row / manual entry / scan):
    // validates, bumps recency, sets the compose recipient + label, and
    // navigates. Invalid manual input stays on the picker with an error.
    let pick_contact = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let update_sweep = update_sweep.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        let refresh_funding = refresh_funding.clone();
        let refresh_change = refresh_change.clone();
        move |addr_raw: &str| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let addr = addr_raw.trim().to_string();
            let contacts_g = ui.global::<Contacts>();
            let sweep_mode = contacts_g.get_pick_mode() == "sweep";
            let compose = ui.global::<Compose>();

            // Appending an EXTRA recipient to an in-progress directed draft
            // (Callbacks.add-recipient-open set this) — pushes onto
            // Compose.to-extra instead of replacing the primary, and does
            // NOT touch funding/change picks or navigate anywhere but back
            // to compose (this is editing a draft, not starting a fresh
            // one — unlike the replace path below, which intentionally
            // resets those for a brand-new compose target).
            if !sweep_mode && contacts_g.get_picking_extra() {
                if addr.is_empty() {
                    contacts_g
                        .set_input_error("Can't add yourself as an extra recipient.".into());
                    log::warn!("cb: pick-contact err=self extra=true");
                    return;
                }
                let mut st = state.borrow_mut();
                if Recipient::parse(st.network(), &addr).is_err() {
                    contacts_g
                        .set_input_error(format!("Not a valid {} address.", st.network).into());
                    log::warn!("cb: pick-contact err=invalid address extra=true");
                    return;
                }
                let primary = compose.get_to_address().to_string();
                let current_extra: Vec<ToRow> = compose.get_to_extra().iter().collect();
                if addr == primary || current_extra.iter().any(|r| r.address == addr) {
                    contacts_g.set_input_error("Already a recipient of this note.".into());
                    log::warn!("cb: pick-contact err=duplicate extra=true");
                    return;
                }
                if 1 + current_extra.len() + 1 > 255 {
                    contacts_g.set_input_error("Too many recipients (max 255).".into());
                    log::warn!("cb: pick-contact err=too-many extra=true");
                    return;
                }
                upsert_contact(&mut st, &addr);
                save_state(&fs, &st);
                let label = to_label_for(&st, &addr);
                drop(st);
                let mut new_extra = current_extra;
                new_extra.push(ToRow { address: addr.as_str().into(), label: label.into() });
                compose.set_to_extra(Rc::new(VecModel::from(new_extra)).into());
                contacts_g.set_picking_extra(false);
                contacts_g.set_input_text("".into());
                contacts_g.set_input_error("".into());
                contacts_g.set_naming_address("".into());
                log::info!("cb: pick-contact to={addr} extra=true");
                ui.global::<Ui>().set_screen(3);
                return;
            }

            if addr.is_empty() {
                // Self: compose only — the sweep picker hides the Self card
                // (sweep-to-self is the Coins screen's consolidate).
                if sweep_mode {
                    return;
                }
                compose.set_to_address("".into());
                compose.set_to_label("to: self — my notebook".into());
                compose.set_to_extra(Rc::new(VecModel::from(Vec::<ToRow>::new())).into());
                log::info!("cb: pick-contact to=self");
            } else {
                let mut st = state.borrow_mut();
                if Recipient::parse(st.network(), &addr).is_err() {
                    contacts_g
                        .set_input_error(format!("Not a valid {} address.", st.network).into());
                    log::warn!("cb: pick-contact err=invalid address");
                    return;
                }
                upsert_contact(&mut st, &addr);
                save_state(&fs, &st);
                if sweep_mode {
                    let sweep = ui.global::<Sweep>();
                    sweep.set_kind("sweep".into());
                    sweep.set_dest(addr.as_str().into());
                    sweep.set_dest_label(to_label_for(&st, &addr).into());
                    sweep.set_tier(1);
                    log::info!("cb: sweep-open kind=sweep to={addr}");
                } else {
                    compose.set_to_address(addr.as_str().into());
                    compose.set_to_label(to_label_for(&st, &addr).into());
                    compose.set_to_extra(Rc::new(VecModel::from(Vec::<ToRow>::new())).into());
                    log::info!("cb: pick-contact to={addr}");
                }
            }
            contacts_g.set_input_text("".into());
            contacts_g.set_input_error("".into());
            contacts_g.set_naming_address("".into());
            if sweep_mode {
                update_sweep();
                ui.global::<Ui>().set_screen(10);
            } else {
                // Fresh compose: reset the funding/change picks to their
                // default rule (spending only when enabled AND funded).
                let st = state.borrow();
                let ix = notebooks.borrow();
                let ctx = notebook_ctx(&ix, *active.borrow())
                    .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
                let section = ix.spending(&net.borrow(), ctx.0, ctx.1).cloned();
                drop(ix);
                *funding_pick.borrow_mut() = default_funding_pick(&st, section.as_ref());
                drop(st);
                *change_pick.borrow_mut() = ChangePickState::default();
                refresh_funding();
                refresh_change();
                ui.global::<Callbacks>().invoke_compose_changed();
                ui.global::<Ui>().set_screen(3);
            }
        }
    };

    {
        let pick_contact = pick_contact.clone();
        ui.global::<Callbacks>().on_pick_contact(move |addr| pick_contact(addr.as_str()));
    }

    // Compose's "+ Add recipient" row — opens the contacts picker in
    // append mode (Contacts.picking-extra), modeled on how the home
    // screen's "Compose note" button opens it in replace mode.
    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_add_recipient_open(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Contacts>().set_picking_extra(true);
            ui.global::<Contacts>().set_pick_mode("compose".into());
            ui.global::<Callbacks>().invoke_refresh_contacts();
            ui.global::<Ui>().set_screen(7);
        });
    }

    // Drop an address from Compose.to-extra — no navigation.
    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_remove_recipient(move |addr| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let compose = ui.global::<Compose>();
            let kept: Vec<ToRow> =
                compose.get_to_extra().iter().filter(|r| r.address != addr).collect();
            compose.set_to_extra(Rc::new(VecModel::from(kept)).into());
            log::info!("cb: remove-recipient addr={addr}");
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let pick_contact = pick_contact.clone();
        ui.global::<Callbacks>().on_scan_contact(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let opts = ScanQrOptions {
                header_title: "Scan recipient address".into(),
                message: "Point at an address QR (a companion page or another Prime's home screen)"
                    .into(),
                ..ScanQrOptions::default()
            };
            let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr { data, .. })) | Ok(Some(ScanQrResult::Ur2 { data, .. })) => data,
                Ok(_) => {
                    log::info!("cb: scan-contact cancelled");
                    return;
                }
                Err(e) => {
                    log::warn!("cb: scan-contact err=scanner {e:?}");
                    ui.global::<Contacts>()
                        .set_input_error(format!("QR scanner unavailable: {e:?}").into());
                    return;
                }
            };
            // Address QRs are plain text, possibly a BIP21 URI, and
            // legitimately ALL-UPPERCASE (our own home QR is) — normalize.
            let text = String::from_utf8(data).unwrap_or_default();
            let mut addr = text.trim();
            if addr.len() >= 8 && addr[..8].eq_ignore_ascii_case("bitcoin:") {
                addr = &addr[8..];
            }
            let addr = addr.split('?').next().unwrap_or("").trim().to_string();
            let st = state.borrow();
            let network = st.network();
            let network_name = st.network.clone();
            drop(st);
            let resolved = if Recipient::parse(network, &addr).is_ok() {
                Some(addr.clone())
            } else {
                let lower = addr.to_lowercase();
                Recipient::parse(network, &lower).is_ok().then_some(lower)
            };
            match resolved {
                Some(a) => {
                    log::info!("cb: scan-contact ok addr={a}");
                    pick_contact(&a);
                }
                None => {
                    log::warn!("cb: scan-contact err=not an address");
                    ui.global::<Contacts>().set_input_error(
                        format!("QR didn't contain a valid {network_name} address.").into(),
                    );
                }
            }
        });
    }

    // Quantum key scan (naming modal "Scan quantum key"): armored
    // ML-KEM public key only — `pq::import_public` rejects anything else
    // with a clear message (a private-key armor, a note, an address QR).
    // Scoped to `Contacts.naming-address` (set when the modal opened), so
    // scanning does NOT require re-saving the name field.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let refresh_contacts = refresh_contacts.clone();
        ui.global::<Callbacks>().on_scan_contact_pq(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let contacts_g = ui.global::<Contacts>();
            let addr = contacts_g.get_naming_address().to_string();
            if addr.is_empty() {
                return;
            }
            let opts = ScanQrOptions {
                header_title: "Scan quantum key".into(),
                message: "Point at a contact's ML-KEM public-key QR (their Settings → \
                          \"Quantum keys…\" screen)."
                    .into(),
                ..ScanQrOptions::default()
            };
            let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr { data, .. })) | Ok(Some(ScanQrResult::Ur2 { data, .. })) => {
                    data
                }
                Ok(_) => {
                    log::info!("cb: contact-pq-key cancelled");
                    return;
                }
                Err(e) => {
                    log::warn!("cb: contact-pq-key err=scanner {e:?}");
                    contacts_g.set_naming_pq_error(format!("QR scanner unavailable: {e:?}").into());
                    return;
                }
            };
            let armor = String::from_utf8(data).unwrap_or_default();
            match pq::import_public(&armor) {
                Ok((alg, ek)) => {
                    let fp = pq::fingerprint(alg, &ek);
                    let mut st = state.borrow_mut();
                    if let Some(c) = st.contacts.iter_mut().find(|c| c.address == addr) {
                        c.mlkem_ek = Some(armor);
                    }
                    save_state(&fs, &st);
                    drop(st);
                    log::info!("cb: contact-pq-key ok fp={fp}");
                    contacts_g
                        .set_naming_pq_caption(format!("{} · {fp}", mlkem_alg_name(alg)).into());
                    contacts_g.set_naming_pq_error("".into());
                    refresh_contacts();
                }
                Err(e) => {
                    log::warn!("cb: contact-pq-key err={e}");
                    contacts_g.set_naming_pq_error(format!("Not a quantum public key: {e}").into());
                }
            }
        });
    }

    // Quantum-keys screen (27): every visible notebook in the active
    // (seed, account) wallet context has its OWN ML-KEM receive identity
    // (derived from its own BIP-86 leaf secret, like the Export-keys
    // screen's hex/WIF), so the screen needs the same notebook picker —
    // `export_pick_notebook`'s row design + selection convention, reusing
    // the shared `ExportNbRow` struct. Default selection when the picker
    // hasn't been touched (`quantum_nb == None`): the ACTIVE notebook when
    // one is open, else the wallet context's first visible notebook — the
    // screen's original single-notebook behavior, preserved as the
    // default. Public-key only: device backup is the 24 recovery words,
    // which already reconstruct every notebook's key.
    let refresh_quantum_keys = {
        let ui_weak = ui_weak.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let mlkem_level = mlkem_level.clone();
        let quantum_nb = quantum_nb.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let qk = ui.global::<QuantumKeys>();
            let alg = mlkem_alg_from_u8(*mlkem_level.borrow());
            let level_idx = match alg {
                pq::MlKemAlg::MlKem512 => 0,
                pq::MlKemAlg::MlKem768 => 1,
                pq::MlKemAlg::MlKem1024 => 2,
            };
            qk.set_level(level_idx);
            qk.set_level_caption(mlkem_alg_describe(alg).into());

            let ix = notebooks.borrow();
            let net_s = net.borrow().clone();
            let network = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
            let ctx = (*seed_idx.borrow(), *bip_account.borrow());

            // Picker rows: every visible notebook in this wallet context,
            // same shape/derivation as `export_rows`.
            let mut rows: Vec<ExportNbRow> = Vec::new();
            for m in ix.visible(ctx.0, ctx.1) {
                let addr = derive_identity(app_seed_get(&app_seed), m, &net_s)
                    .map(|id| id.address(network))
                    .unwrap_or_default();
                let name = if m.name.trim().is_empty() {
                    notebooks::default_name(m.index)
                } else {
                    m.name.clone()
                };
                rows.push(ExportNbRow {
                    index: m.index as i32,
                    name: name.into(),
                    addr: short_addr(&addr).into(),
                });
            }

            // Selection: an explicit picker choice (if it's still visible),
            // else the active-or-first default described above.
            let default_meta = (*active.borrow())
                .and_then(|acc| ix.get(acc))
                .or_else(|| ix.visible(ctx.0, ctx.1).next())
                .cloned();
            let meta = quantum_nb
                .borrow()
                .and_then(|i| ix.visible(ctx.0, ctx.1).find(|m| m.index == i).cloned())
                .or(default_meta);
            drop(ix);

            let (nb_idx, nb_name) = meta
                .as_ref()
                .map(|m| {
                    let name = if m.name.trim().is_empty() {
                        notebooks::default_name(m.index)
                    } else {
                        m.name.clone()
                    };
                    (m.index as i32, name)
                })
                .unwrap_or((0, "".to_string()));
            qk.set_notebooks(Rc::new(VecModel::from(rows)).into());
            qk.set_nb_index(nb_idx);
            qk.set_nb_name(nb_name.into());

            let leaf =
                meta.as_ref().and_then(|m| derive_leaf_secret(app_seed_get(&app_seed), m, &net_s));
            match leaf {
                Some(leaf) => {
                    let kp = pq::mlkem_keypair_from_leaf(&leaf, alg);
                    qk.set_qr_zoom(false); // never re-enter the screen zoomed
                    qk.set_fingerprint(kp.fingerprint().into());
                    // The dense armor QR is optically unverifiable at
                    // device resolution (~1.2px/module), so the UI suite
                    // cross-checks THIS line against notes_cli
                    // pq-fingerprint's independent host derivation.
                    // Public info — safe to log.
                    log::info!("cb: pq-key fp={}", kp.fingerprint());
                    let armor = pq::export_public(alg, kp.ek());
                    qk.set_public_qr(qr_image(&armor));
                    qk.set_public_armor(armor.into());
                }
                None => {
                    qk.set_fingerprint("No notebook yet — create one first.".into());
                    qk.set_public_armor("".into());
                }
            }
        }
    };

    {
        let refresh_quantum_keys = refresh_quantum_keys.clone();
        let quantum_nb = quantum_nb.clone();
        ui.global::<Callbacks>().on_open_quantum_keys(move || {
            // Reopening the screen resets to the active-or-first default
            // rather than remembering the last-picked notebook from a
            // previous visit.
            *quantum_nb.borrow_mut() = None;
            refresh_quantum_keys();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let mlkem_level = mlkem_level.clone();
        let persist_config = persist_config.clone();
        let refresh_quantum_keys = refresh_quantum_keys.clone();
        ui.global::<Callbacks>().on_quantum_key_level(move |level_idx| {
            let Some(_ui) = ui_weak.upgrade() else { return };
            let alg = match level_idx {
                0 => pq::MlKemAlg::MlKem512,
                2 => pq::MlKemAlg::MlKem1024,
                _ => pq::MlKemAlg::MlKem768,
            };
            *mlkem_level.borrow_mut() = alg.id();
            persist_config();
            log::info!("cb: pq-key level={}", mlkem_alg_name(alg));
            refresh_quantum_keys();
        });
    }

    {
        let refresh_quantum_keys = refresh_quantum_keys.clone();
        let quantum_nb = quantum_nb.clone();
        ui.global::<Callbacks>().on_quantum_key_pick_notebook(move |index| {
            *quantum_nb.borrow_mut() = Some(index as u32);
            log::info!("cb: pq-key notebook={index}");
            refresh_quantum_keys();
        });
    }

    {
        ui.global::<Callbacks>().on_quantum_keys_close(move || {});
    }
    {
        let ui = ui_weak.upgrade().unwrap();
        ui.global::<Callbacks>().on_quantum_qr_zoom(move |open| {
            log::info!("cb: pq-key qr-zoom={}", if open { "open" } else { "closed" });
        });
    }

    // ---------------------------------------------------------------------
    // Personal device quantum key (PLAN-graffito-quantum-key.md, screen
    // 28) — Settings → "Quantum key…". A single, NON-seed-derived ML-KEM
    // keypair, generated on-device (fresh TRNG mixed with optional user
    // entropy — `pq::MlKemKeypair::generate_with_extra`) or imported,
    // stored plain in AppData (`QUANTUM_KEY_PATH`). Distinct from the
    // per-notebook seed-derived keys the "Quantum keys" screen above
    // shows: this key is NOT recovered by the 24 words and dies with app
    // uninstall — it is what makes the self-note ML-KEM compose pill
    // (compose-changed, earlier) meaningful at all (pq.rs's module doc:
    // encapsulating to a seed-derived receive key on a self-note is
    // security theater, since that key shares the enc key's root).
    // ---------------------------------------------------------------------
    let refresh_device_quantum_key = {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let device_pq_key = device_pq_key.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            match device_quantum_key(&fs, &device_pq_key) {
                Some(kp) => {
                    dq.set_has_key(true);
                    dq.set_fingerprint(kp.fingerprint().into());
                    dq.set_level_name(mlkem_alg_name(kp.alg()).into());
                    let armor = pq::export_public(kp.alg(), kp.ek());
                    dq.set_public_qr(qr_image(&armor));
                    dq.set_public_armor(armor.into());
                }
                None => {
                    dq.set_has_key(false);
                    dq.set_fingerprint("".into());
                    dq.set_level_name("".into());
                    dq.set_public_armor("".into());
                    dq.set_public_qr(Image::default());
                }
            }
        }
    };

    {
        let ui_weak = ui_weak.clone();
        let refresh_device_quantum_key = refresh_device_quantum_key.clone();
        ui.global::<Callbacks>().on_open_device_quantum_key(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            // Reopening always starts at the summary/generate-or-import
            // state, never wherever the last visit left off.
            dq.set_view("".into());
            dq.set_gen_level(1);
            dq.set_gen_level_caption(mlkem_alg_describe(pq::MlKemAlg::MlKem768).into());
            dq.set_gen_extra_text("".into());
            dq.set_gen_error("".into());
            dq.set_import_error("".into());
            dq.set_qr_zoom(false);
            dq.set_show_replace_confirm(false);
            dq.set_show_delete_confirm(false);
            refresh_device_quantum_key();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_device_quantum_key_close(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            // Wipe the sensitive private-key view (armor + QR) on the way
            // out — never lingers in a UI prop after the screen closes,
            // same hygiene as reveal-close/export-close.
            dq.set_private_armor("".into());
            dq.set_private_qr(Image::default());
            dq.set_view("".into());
            dq.set_qr_zoom(false);
        });
    }

    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_device_quantum_key_gen_level(move |level_idx| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            let alg = match level_idx {
                0 => pq::MlKemAlg::MlKem512,
                2 => pq::MlKemAlg::MlKem1024,
                _ => pq::MlKemAlg::MlKem768,
            };
            dq.set_gen_level(level_idx);
            dq.set_gen_level_caption(mlkem_alg_describe(alg).into());
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let device_pq_key = device_pq_key.clone();
        let refresh_device_quantum_key = refresh_device_quantum_key.clone();
        ui.global::<Callbacks>().on_device_quantum_key_generate(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            let alg = match dq.get_gen_level() {
                0 => pq::MlKemAlg::MlKem512,
                2 => pq::MlKemAlg::MlKem1024,
                _ => pq::MlKemAlg::MlKem768,
            };
            let extra = dq.get_gen_extra_text().to_string();
            let result = pq::MlKemKeypair::generate_with_extra(alg, extra.as_bytes())
                .map_err(|e| e.to_string())
                .and_then(|kp| save_device_quantum_key(&fs, kp.alg(), kp.seed()).map(|_| kp));
            match result {
                Ok(kp) => {
                    *device_pq_key.borrow_mut() = Some(Some(kp));
                    dq.set_gen_error("".into());
                    dq.set_gen_extra_text("".into());
                    log::info!("cb: quantum-key generate level={} ok", mlkem_alg_name(alg));
                    refresh_device_quantum_key();
                }
                Err(e) => {
                    log::warn!("cb: quantum-key generate level={} err={e}", mlkem_alg_name(alg));
                    dq.set_gen_error(format!("Couldn't generate a key: {e}").into());
                }
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let device_pq_key = device_pq_key.clone();
        let refresh_device_quantum_key = refresh_device_quantum_key.clone();
        ui.global::<Callbacks>().on_device_quantum_key_import(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            let opts = ScanQrOptions {
                header_title: "Import quantum key".into(),
                message: "Point at an armored GRAFFITO ML-KEM PRIVATE KEY QR — from a backup, \
                          this device's own export, or the graffito Mac app."
                    .into(),
                ..ScanQrOptions::default()
            };
            let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr { data, .. })) | Ok(Some(ScanQrResult::Ur2 { data, .. })) => {
                    data
                }
                Ok(_) => {
                    log::info!("cb: quantum-key import cancelled");
                    return;
                }
                Err(e) => {
                    log::warn!("cb: quantum-key import err=scanner {e:?}");
                    dq.set_import_error(format!("QR scanner unavailable: {e:?}").into());
                    return;
                }
            };
            let armor = String::from_utf8(data).unwrap_or_default();
            match pq::import_private(&armor) {
                Ok((alg, seed)) => match save_device_quantum_key(&fs, alg, &seed) {
                    Ok(()) => {
                        *device_pq_key.borrow_mut() =
                            Some(Some(pq::MlKemKeypair::from_seed(alg, &seed)));
                        dq.set_import_error("".into());
                        log::info!("cb: quantum-key import ok");
                        refresh_device_quantum_key();
                    }
                    Err(e) => {
                        log::warn!("cb: quantum-key import err={e}");
                        dq.set_import_error(format!("Couldn't save the key: {e}").into());
                    }
                },
                Err(e) => {
                    // A clearer message for the common mix-up: scanning a
                    // PUBLIC key armor (this screen's own "Share public
                    // key" QR, or a contact's) instead of a private one.
                    let msg = if pq::import_public(&armor).is_ok() {
                        "That's a PUBLIC quantum key — this needs the PRIVATE key armor \
                         instead (\"Export private key…\" on the device that holds it)."
                            .to_string()
                    } else {
                        format!("Not a private quantum key: {e}")
                    };
                    log::warn!("cb: quantum-key import err={e}");
                    dq.set_import_error(msg.into());
                }
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let device_pq_key = device_pq_key.clone();
        ui.global::<Callbacks>().on_device_quantum_key_reveal_private(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            let Some(kp) = device_quantum_key(&fs, &device_pq_key) else {
                // Shouldn't be reachable (the button only shows when
                // has-key is true) — fail safe back to the summary view.
                dq.set_view("".into());
                return;
            };
            let armor = pq::export_private(kp.alg(), kp.seed());
            dq.set_private_armor(armor.clone().into());
            if qr_fits(&armor) {
                dq.set_private_fits_qr(true);
                dq.set_private_qr(qr_image(&armor));
            } else {
                // Never reachable in practice — a private armor is always
                // a fixed 66-byte payload regardless of level — but this
                // is the same size guard `qr_image` needs everywhere else
                // (it panics past capacity), so it stays generic rather
                // than assuming the current sizes forever.
                dq.set_private_fits_qr(false);
                dq.set_private_qr(Image::default());
            }
            dq.set_view("private".into());
            log::info!("cb: quantum-key export-private ok fp={}", kp.fingerprint());
        });
    }

    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_device_quantum_key_hide_private(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            dq.set_private_armor("".into());
            dq.set_private_qr(Image::default());
            dq.set_view("".into());
            dq.set_qr_zoom(false);
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let device_pq_key = device_pq_key.clone();
        let refresh_device_quantum_key = refresh_device_quantum_key.clone();
        ui.global::<Callbacks>().on_device_quantum_key_replace_confirm(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            // "Replace…" = delete the current key, then land back on the
            // generate/import state — the confirm dialog is what named the
            // consequence (notes sealed to it become unreadable) before
            // this ran.
            if let Err(e) = delete_device_quantum_key(&fs) {
                log::warn!("cb: quantum-key replace err={e}");
            }
            *device_pq_key.borrow_mut() = Some(None);
            dq.set_show_replace_confirm(false);
            dq.set_view("".into());
            dq.set_private_armor("".into());
            dq.set_private_qr(Image::default());
            dq.set_gen_level(1);
            dq.set_gen_level_caption(mlkem_alg_describe(pq::MlKemAlg::MlKem768).into());
            dq.set_gen_extra_text("".into());
            log::info!("cb: quantum-key replace ok");
            refresh_device_quantum_key();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let device_pq_key = device_pq_key.clone();
        let refresh_device_quantum_key = refresh_device_quantum_key.clone();
        ui.global::<Callbacks>().on_device_quantum_key_delete_confirm(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let dq = ui.global::<DeviceQuantumKey>();
            if let Err(e) = delete_device_quantum_key(&fs) {
                log::warn!("cb: quantum-key delete err={e}");
            }
            *device_pq_key.borrow_mut() = Some(None);
            dq.set_show_delete_confirm(false);
            dq.set_view("".into());
            dq.set_private_armor("".into());
            dq.set_private_qr(Image::default());
            log::info!("cb: quantum-key delete ok");
            refresh_device_quantum_key();
        });
    }

    {
        ui.global::<Callbacks>().on_device_quantum_key_qr_zoom(move |open| {
            log::info!("cb: quantum-key qr-zoom={}", if open { "open" } else { "closed" });
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let refresh_contacts = refresh_contacts.clone();
        ui.global::<Callbacks>().on_save_contact_name(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let contacts_g = ui.global::<Contacts>();
            let addr = contacts_g.get_naming_address().to_string();
            if addr.is_empty() {
                return;
            }
            let name = contacts_g.get_name_text().trim().to_string();
            let mut st = state.borrow_mut();
            // Naming does NOT bump recency — only use does, so the row
            // being edited never jumps mid-interaction.
            if let Some(c) = st.contacts.iter_mut().find(|c| c.address == addr) {
                c.name = name.clone();
            }
            save_state(&fs, &st);
            drop(st);
            log::info!("cb: save-contact addr={addr} name-len={}", name.len());
            contacts_g.set_naming_address("".into());
            contacts_g.set_name_text("".into());
            refresh_contacts();
        });
    }

    {
        let refresh_coins = refresh_coins.clone();
        ui.global::<Callbacks>().on_refresh_coins(move || refresh_coins());
    }

    // Coins → the shared sweep screen with kind=consolidate, dest=self.
    {
        let ui_weak = ui_weak.clone();
        let update_sweep = update_sweep.clone();
        ui.global::<Callbacks>().on_consolidate_open(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let sweep = ui.global::<Sweep>();
            sweep.set_kind("consolidate".into());
            sweep.set_dest("".into());
            sweep.set_dest_label("to: self — one consolidated coin".into());
            sweep.set_tier(1);
            log::info!("cb: sweep-open kind=consolidate to=self");
            update_sweep();
            ui.global::<Ui>().set_screen(10);
        });
    }

    {
        let update_sweep = update_sweep.clone();
        ui.global::<Callbacks>().on_sweep_changed(move || update_sweep());
    }

    // Build + sign the sweep (ALL coins, key-path), then the confirm dialog.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let sweep_plan = sweep_plan.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let app_seed = app_seed.clone();
        let active = active.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let lock_policy = lock_policy.clone();
        ui.global::<Callbacks>().on_sweep_continue(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let identity = identity.clone();
            let sweep_plan = sweep_plan.clone();
            let fs = fs.clone();
            let notebooks = notebooks.clone();
            let app_seed = app_seed.clone();
            let active = active.clone();
            let seed_idx = seed_idx.clone();
            let bip_account = bip_account.clone();
            let lock_policy = lock_policy.clone();
            // Let the busy overlay paint one frame before the blocking work.
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let sweep = ui.global::<Sweep>();
                let consolidate = sweep.get_kind() == "consolidate";
                let kind = if consolidate { "consolidate" } else { "sweep" };
                let dest = sweep.get_dest().trim().to_string();
                let tier = sweep.get_tier();
                let rate_text = sweep.get_rate_text().to_string();
                let st = state.borrow();
                // Flush the active notebook, then gather EVERY notebook's
                // coins — a wallet-level sweep/consolidate, one multi-key tx.
                save_state(&fs, &st);
                let sources_raw = wallet_sources(
                    &fs,
                    &notebooks.borrow(),
                    app_seed_get(&app_seed),
                    &st.network,
                    (*seed_idx.borrow(), *bip_account.borrow()),
                );
                let dest_account = active.borrow().unwrap_or(0);
                let id_guard = identity.borrow();
                let result = id_guard
                    .as_ref()
                    .ok_or_else(|| "identity unavailable".to_string())
                    .and_then(|id| {
                        let rate = resolve_rate(tier, &rate_text, &st)?;
                        if sources_raw.is_empty() {
                            return Err("No spendable coins in the wallet.".to_string());
                        }
                        let dest_spk = if consolidate {
                            p2tr_script_pubkey(&id.output_x)
                        } else {
                            Recipient::parse(st.network(), &dest).map_err(|e| e.to_string())?.spk
                        };
                        let sources: Vec<SweepSource> = sources_raw
                            .iter()
                            .map(|(_, ox, sk, coins)| SweepSource {
                                utxos: coins,
                                output_x: *ox,
                                tweaked_seckey: sk,
                            })
                            .collect();
                        build_sweep_tx_multi(
                            &sources,
                            dest_spk,
                            rate,
                            resolve_locktime(*lock_policy.borrow(), st.tip_height),
                            generate_aux_rand,
                        )
                            .map_err(|e| e.to_string())
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok(tx) => {
                        let recv = tx.tx.outputs[0].value;
                        let n_notebooks = sources_raw.len();
                        // Spent outpoints per source notebook (display txid).
                        let spent_by_account: Vec<(u32, Vec<(String, u32)>)> = sources_raw
                            .iter()
                            .map(|(acct, _, _, coins)| {
                                let outs = coins
                                    .iter()
                                    .map(|u| {
                                        let mut t = u.txid;
                                        t.reverse();
                                        (hex::encode(t), u.vout)
                                    })
                                    .collect();
                                (*acct, outs)
                            })
                            .collect();
                        log::info!(
                            "cb: sweep kind={kind} to={} inputs={} notebooks={n_notebooks} amount={recv} fee={} vsize={} txid={} ok",
                            if consolidate { "self" } else { dest.as_str() },
                            tx.tx.inputs.len(),
                            tx.fee,
                            tx.vsize,
                            tx.txid_hex
                        );
                        // ConfirmCtx: byte-truth decode gate (screen 4).
                        // `sources_raw` already carries each contributing
                        // notebook's (account, output_x, coins), so the
                        // prevout labels come straight from it.
                        let ix = notebooks.borrow();
                        let (self_spks, spending_spks) =
                            confirm_self_spks(&ix, app_seed_get(&app_seed), &st.network, (*seed_idx.borrow(), *bip_account.borrow()));
                        let mut prevouts: BTreeMap<String, notes_core::confirm::PrevoutInfo> =
                            BTreeMap::new();
                        for (acct, ox, _, coins) in &sources_raw {
                            let addr = notes_core::address::taproot_address(st.network(), ox);
                            let name = notebook_name(&ix, *acct, &short_addr(&addr));
                            for u in coins.iter() {
                                let mut t = u.txid;
                                t.reverse();
                                prevouts.insert(
                                    format!("{}:{}", hex::encode(t), u.vout),
                                    notes_core::confirm::PrevoutInfo {
                                        value: u.value,
                                        address: Some(addr.clone()),
                                        source: format!("Notebook · {name}"),
                                    },
                                );
                            }
                        }
                        drop(ix);

                        let cctx = notes_core::confirm::ConfirmCtx {
                            network: st.network(),
                            prevouts,
                            self_spks,
                            spending_spks,
                            expected_change: None,
                            recipient: if consolidate { None } else { Some(dest.clone()) },
                            recipient_name: None,
                            recipients: Vec::new(),
                            note_preview: None,
                        };
                        let mut context_line = format!(
                            "{} · {}",
                            if consolidate { "Consolidate" } else { "Sweep" },
                            st.network
                        );
                        if n_notebooks > 1 {
                            context_line.push_str(&format!(
                                " - spends coins from {n_notebooks} notebooks, publicly linking their addresses on-chain."
                            ));
                        }

                        match show_confirm_screen(
                            &ui,
                            kind,
                            &tx.raw_hex,
                            &cctx,
                            context_line,
                            "Sign & export",
                        ) {
                            Ok(()) => {
                                *sweep_plan.borrow_mut() = Some(SweepPlan {
                                    tx,
                                    kind: if consolidate { "consolidate" } else { "sweep" },
                                    dest: (!consolidate).then(|| dest.clone()),
                                    spent_by_account,
                                    dest_account,
                                });
                            }
                            Err(e) => {
                                log::warn!("cb: confirm summarize err={e}");
                                sweep.set_cost_line(format!("Cannot show confirm: {e}").into());
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("cb: sweep kind={kind} err={e}");
                        sweep.set_cost_line(format!("Cannot build: {e}").into());
                    }
                }
            });
        });
    }

    // Spending wallet: Settings toggle.
    {
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let refresh_funding = refresh_funding.clone();
        ui.global::<Callbacks>().on_set_spending_enabled(move |on| {
            let mut ix = notebooks.borrow_mut();
            let ctx = notebook_ctx(&ix, *active.borrow())
                .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
            let net_s = net.borrow().clone();
            ix.spending_mut(&net_s, ctx.0, ctx.1).enabled = on;
            save_notebooks(&fs, &ix);
            drop(ix);
            log::info!("cb: set-spending enabled={on}");
            refresh_funding();
        });
    }

    // Pay-from screen (25): notebook / spending-wallet per-coin selection.
    {
        let refresh_funding = refresh_funding.clone();
        ui.global::<Callbacks>().on_funding_open(move || {
            log::info!("cb: funding-open");
            refresh_funding();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let funding_pick = funding_pick.clone();
        let refresh_funding = refresh_funding.clone();
        let refresh_change = refresh_change.clone();
        ui.global::<Callbacks>().on_funding_toggle_coin(move |key| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if let Some((spending_src, txid, vout)) = parse_funding_key(key.as_str()) {
                funding_pick.borrow_mut().toggle(spending_src, txid, vout);
            }
            refresh_funding();
            refresh_change();
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }
    {
        let funding_pick = funding_pick.clone();
        ui.global::<Callbacks>().on_funding_done(move || {
            let pick = funding_pick.borrow();
            log::info!(
                "cb: pay-from {} coins={}",
                pick.mode_label(),
                pick.notebook.len() + pick.spending.len()
            );
        });
    }

    // Change screen (26): compose destination for change.
    {
        let refresh_change = refresh_change.clone();
        ui.global::<Callbacks>().on_change_open(move || {
            refresh_change();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let change_pick = change_pick.clone();
        let refresh_change = refresh_change.clone();
        ui.global::<Callbacks>().on_change_pick(move |choice| {
            let Some(ui) = ui_weak.upgrade() else { return };
            change_pick.borrow_mut().choice = choice.to_string();
            ui.global::<ChangePick>().set_choice(choice.clone());
            ui.global::<ChangePick>().set_custom_error("".into());
            log::info!("cb: change-pick {choice}");
            refresh_change();
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let change_pick = change_pick.clone();
        ui.global::<Callbacks>().on_change_address_changed(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            change_pick.borrow_mut().custom_address =
                ui.global::<ChangePick>().get_custom_address().to_string();
            ui.global::<ChangePick>().set_custom_error("".into());
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_change_done(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }

    // Edge-tracks whether the compose draft is over the broadcast ceiling, so
    // the "too large" dialog pops once on crossing — not on every keystroke.
    let compose_oversize = Rc::new(std::cell::Cell::new(false));

    // Post-quantum Security section (pq.rs): the exact text the last
    // `passphrase::generate()` call produced — a typed passphrase counts
    // toward quantum resistance ONLY while it's still byte-identical to
    // this (any edit un-certifies it). `None` until Generate is tapped.
    let pq_generated: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));

    // Keystroke cost estimator — pure arithmetic, no crypto runs (see
    // notes-core crypt::SEAL_OVERHEAD), so per-keystroke recompute is free.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let compose_oversize = compose_oversize.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let pq_generated = pq_generated.clone();
        let fs = fs.clone();
        let device_pq_key = device_pq_key.clone();
        ui.global::<Callbacks>().on_compose_changed(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let compose = ui.global::<Compose>();
            let st = state.borrow();
            let to_address = compose.get_to_address().trim().to_string();
            let directed = !to_address.is_empty();
            let private = compose.get_private_note();
            // HOISTED to the handler TOP (2026-08-21): every early return below
            // (bad rate, empty text, "No funds", recipient-parse) must NOT skip
            // the pq section's visibility recompute — the "No funds"
            // and recipient-parse branches return before the cost math, and
            // the pq section's visibility must never depend on funding —
            // an unfunded notebook still shows (and toggles) the Security
            // section, exactly like the Mac app.
            //
            // Self-pw notes (PLAN-graffito-self-pw.md, 2026-08-22): the
            // passphrase layer is also available for a PRIVATE SELF-note
            // (no recipient) — `pq_eligible` gates the whole Security
            // section and the passphrase control for either shape.
            // ML-KEM on a DIRECTED note encapsulates to the contact's
            // seed-derived receive key; on a SELF-note (PLAN-graffito-
            // quantum-key.md) it instead encapsulates to THIS device's
            // personal, non-seed quantum key — a self-note's seed-derived
            // key would derive from the same leaf as its enc key (security
            // theater, pq.rs's module doc), so `pq_mlkem_eligible` for a
            // self-note additionally requires the device key file to
            // exist. Directed eligibility/computation stays byte-identical
            // to before this feature.
            let base_pq_eligible = private && compose.get_to_extra().row_count() == 0;
            let device_kp = if base_pq_eligible && !directed {
                device_quantum_key(&fs, &device_pq_key)
            } else {
                None
            };
            let pq_mlkem_eligible =
                base_pq_eligible && (directed || device_kp.is_some());
            let pq_eligible = base_pq_eligible;
            compose.set_pq_eligible(pq_eligible);
            compose.set_pq_mlkem_eligible(pq_mlkem_eligible);
            let mlkem_parsed: Option<(pq::MlKemAlg, Vec<u8>)> = if !pq_mlkem_eligible {
                None
            } else if directed {
                st.contacts
                    .iter()
                    .find(|c| c.address == to_address)
                    .and_then(|c| c.mlkem_ek.as_deref())
                    .and_then(|a| pq::import_public(a).ok())
            } else {
                device_kp.as_ref().map(|kp| (kp.alg(), kp.ek().to_vec()))
            };
            let mlkem_available = mlkem_parsed.is_some();
            compose.set_pq_mlkem_available(mlkem_available);
            if (!pq_mlkem_eligible || !mlkem_available) && compose.get_pq_mlkem_active() {
                compose.set_pq_mlkem_active(false);
            }
            compose.set_pq_mlkem_caption(
                if !pq_mlkem_eligible {
                    String::new()
                } else if let Some((alg, ek)) = &mlkem_parsed {
                    // Same "LEVEL · fingerprint" line either way — for a
                    // self-note this names the device's own quantum key
                    // (PLAN-graffito-quantum-key.md).
                    format!("{} · {}", mlkem_alg_name(*alg), pq::fingerprint(*alg, ek))
                } else {
                    "recipient has no quantum key — add one in Contacts".to_string()
                }
                .into(),
            );
            if !pq_eligible && compose.get_pq_passphrase_active() {
                compose.set_pq_passphrase_active(false);
            }
            let pq_passphrase_active = pq_eligible && compose.get_pq_passphrase_active();
            let pq_mlkem_active = pq_mlkem_eligible && mlkem_available && compose.get_pq_mlkem_active();
            let pq_passphrase_text = compose.get_pq_passphrase_text().to_string();
            let pq_passphrase_verified = pq_passphrase_active
                && !pq_passphrase_text.is_empty()
                && pq_generated.borrow().as_deref() == Some(pq_passphrase_text.as_str());
            let pq_passphrase_weak = pq_passphrase_active
                && !pq_passphrase_verified
                && !pq_passphrase_text.is_empty()
                && passphrase::typed_is_weak(&pq_passphrase_text);
            compose.set_pq_passphrase_weak(pq_passphrase_weak);
            compose.set_pq_passphrase_strength(
                if !pq_passphrase_active {
                    String::new()
                } else if pq_passphrase_verified {
                    format!("{:.0}-bit generated phrase", passphrase::GENERATED_BITS)
                } else if pq_passphrase_weak {
                    "weak — short passphrases are easy to brute-force; use Generate or add more words"
                        .to_string()
                } else {
                    "strength can't be verified — use Generate for a certified phrase".to_string()
                }
                .into(),
            );
            let pq_flags_guess: u8 = (if pq_passphrase_active { notes_core::envelope::FLAG_PW } else { 0 })
                | (if pq_mlkem_active { notes_core::envelope::FLAG_MLKEM } else { 0 });
            let pq_alg_guess = mlkem_parsed.as_ref().map(|(alg, _)| *alg);
            let pq_extra = pq::pq_overhead(pq_flags_guess, pq_alg_guess);
            compose.set_pq_security_label(
                if pq_flags_guess == 0 {
                    String::new()
                } else {
                    pq_security_label(
                        private,
                        directed,
                        pq_passphrase_active,
                        pq_passphrase_verified,
                        if pq_mlkem_active { pq_alg_guess } else { None },
                    )
                }
                .into(),
            );
            // Tier pills drive the rate field; a manual edit set tier=3
            // first, so we never overwrite the user's custom value.
            let tier = compose.get_tier();
            if tier != 3 {
                compose.set_rate_text(format!("{}", st.fee_rate(tier)).into());
            }
            let rate = match resolve_rate(tier, compose.get_rate_text().as_str(), &st) {
                Ok(r) => r,
                Err(e) => {
                    compose.set_cost_line(e.into());
                    compose.set_can_continue(false);
                    return;
                }
            };
            // Keyboard Done: the system keyboard's Done key has no distinct
            // signal — it sends a plain '\n' (gui-app-keyboard maps
            // KeyAction::Return to Key::Char('\n')). A note is composed as
            // one paragraph on-device, so ANY newline here means "done
            // typing": strip it and bump dismiss-nonce, which the editor
            // watches to drop focus (focus loss hides the keyboard).
            let raw = compose.get_text();
            if raw.as_str().contains('\n') {
                let stripped: String = raw.as_str().replace('\n', "");
                compose.set_text(stripped.into());
                compose.set_dismiss_nonce(compose.get_dismiss_nonce() + 1);
                log::info!("cb: compose keyboard-done");
            }
            let text = compose.get_text();
            let text_len = text.as_str().len();
            if text_len == 0 {
                compose.set_cost_line("Type to see the cost.".into());
                compose.set_can_continue(false);
                compose_oversize.set(false); // clearing the draft re-arms the dialog
                return;
            }
            let ix = notebooks.borrow();
            let ctx = notebook_ctx(&ix, *active.borrow())
                .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
            let net_s = net.borrow().clone();
            let section = ix.spending(&net_s, ctx.0, ctx.1).cloned();
            drop(ix);
            if st.utxos.is_empty() && section.as_ref().map(|s| s.balance()).unwrap_or(0) == 0 {
                compose
                    .set_cost_line("No funds — fund the address and import a sync bundle.".into());
                compose.set_can_continue(false);
                return;
            }
            // Directed = non-empty To field. Validate the recipient like
            // resolve_rate validates the rate — errors land in the cost
            // line, never a panic.
            let recipient_spk_len = if directed {
                match Recipient::parse(st.network(), &to_address) {
                    Ok(r) => {
                        if compose.get_private_note() && r.p2tr_x.is_none() {
                            compose.set_cost_line(
                                "Private directed notes need a taproot (…1p…) recipient — or switch to Public.".into(),
                            );
                            compose.set_can_continue(false);
                            return;
                        }
                        Some(r.spk.len())
                    }
                    Err(_) => {
                        compose.set_cost_line(
                            format!("Enter a valid {} recipient address.", st.network).into(),
                        );
                        compose.set_can_continue(false);
                        return;
                    }
                }
            } else {
                None
            };
            let gift = resolve_gift(directed, compose.get_gift_sats().as_str());
            // Recipient count for THIS draft (primary + every "+ Add
            // recipient" row); 0 for a self-note. Each recipient gets the
            // SAME gift amount, so the real sats leaving to recipients is
            // `gift * n_recipients`, not `gift` alone — the balance checks
            // and cost-line suffix below both need the total, not the
            // per-recipient amount.
            let n_recipients: usize =
                if directed { 1 + compose.get_to_extra().row_count() } else { 0 };
            let total_gift: u64 = gift * n_recipients as u64;

            // Post-quantum Security section (pq.rs) — directed private
            // single-recipient notes only (envelope validity rule: pq
            // layers are incompatible with FLAG_MULTI). Recomputed every
            // keystroke so the section reacts immediately to the Private
            // toggle, an extra recipient being added, or the recipient
            // changing underneath an already-open draft.

            let effective = st.effective_chunk();
            // `estimate_note_cost_pq` bakes `pq::pq_overhead` into the same
            // body_len arithmetic `estimate_note_cost` uses — byte-exact
            // for the compose cost line whenever a pq layer is active;
            // `(0, None)` (pq_flags_guess == 0) is never reached here.
            let est = if pq_flags_guess != 0 {
                estimate_note_cost_pq(
                    text_len, effective, 1, recipient_spk_len, pq_flags_guess, pq_alg_guess,
                )
            } else {
                estimate_note_cost(text_len, private, effective, 1, recipient_spk_len)
            };
            let fit = fit_check(effective, text_len, private, recipient_spk_len, pq_extra);

            // Over the per-tx broadcast ceiling (vsize > 100 kB, or > 255
            // chunks). Show it in the cost line, gate Continue, and pop the
            // "too large" dialog once — on the crossing, not every keystroke.
            if !matches!(fit, FitCheck::Ok) {
                match &est {
                    Ok((chunks, vsize)) => compose.set_cost_line(
                        format!("{chunks} chunk(s) · ~{vsize} vB — too large to broadcast").into(),
                    ),
                    Err(_) => {
                        compose.set_cost_line("Too large to broadcast (> 255 chunks).".into())
                    }
                }
                compose.set_can_continue(false);
                if !compose_oversize.replace(true) {
                    match fit {
                        FitCheck::FitsAtStandard => {
                            compose.set_oversize_offer_bump(true);
                            compose.set_oversize_message(
                                "This note doesn't fit at your current chunk size. \
                                 Switch to Standard (a single large chunk) to fit it in one transaction?"
                                    .into(),
                            );
                        }
                        _ => {
                            compose.set_oversize_offer_bump(false);
                            compose.set_oversize_message(
                                "This note is too large to broadcast. A single Bitcoin \
                                 transaction can't exceed ~100 kB (the network relay limit), \
                                 whatever the chunk size. Shorten the note, or split it across \
                                 several notes. Multi-transaction notes are planned for a \
                                 future release."
                                    .into(),
                            );
                        }
                    }
                    compose.set_show_oversize(true);
                }
                return;
            }
            compose_oversize.set(false);

            let pick = funding_pick.borrow();
            let sp_participates = !pick.spending.is_empty();
            let mode_auto = !pick.touched && !sp_participates;

            if mode_auto {
                // Byte-identical to pre-funding-unification behavior.
                match est {
                    Ok((chunks, vsize)) => {
                        let fee = (vsize as f64 * rate).ceil() as u64;
                        if fee + total_gift > st.balance() {
                            compose.set_cost_line(
                                format!(
                                    "Needs ~{} sats — balance is {}.",
                                    fee + total_gift,
                                    st.balance()
                                )
                                .into(),
                            );
                            compose.set_can_continue(false);
                        } else {
                            compose.set_cost_line(
                                format!(
                                    "{text_len} bytes · {chunks} chunk(s) · ~{vsize} vB · ~{} @ {rate} sat/vB{}",
                                    sats_line(fee, st.btc_usd),
                                    if !directed {
                                        String::new()
                                    } else if n_recipients <= 1 {
                                        format!(" + {gift} sats to recipient")
                                    } else {
                                        format!(
                                            " + {n_recipients} × {gift} = {total_gift} sats to {n_recipients} recipients"
                                        )
                                    }
                                )
                                .into(),
                            );
                            compose.set_can_continue(true);
                        }
                    }
                    Err(e) => {
                        compose.set_cost_line(format!("{e}").into());
                        compose.set_can_continue(false);
                    }
                }
                return;
            }

            // Exact-selected-coins preview (notebook subset, spending, or
            // mixed): real selected input kinds/count and real extra
            // outputs, unlike `estimate_note_cost`'s single-taproot-input
            // approximation above (used only for `fit_check`'s ceiling test).
            let payload_lens = match payload_lens_for(text_len, private, pq_extra, effective) {
                Ok(v) => v,
                Err(e) => {
                    compose.set_cost_line(e.into());
                    compose.set_can_continue(false);
                    return;
                }
            };
            let chunks = payload_lens.len();
            let n_notebook = pick.notebook.len();
            let n_spending = pick.spending.len();
            if n_notebook + n_spending == 0 {
                compose.set_cost_line("Select at least one coin — \"Pay from\" above.".into());
                compose.set_can_continue(false);
                return;
            }
            let kinds: Vec<InputKind> = std::iter::repeat(InputKind::Taproot)
                .take(n_notebook)
                .chain(std::iter::repeat(InputKind::P2wpkh).take(n_spending))
                .collect();
            let cp = change_pick.borrow();
            let change_len = match change_spk_len_preview(
                &cp.choice,
                &cp.custom_address,
                st.network(),
                sp_participates,
            ) {
                Ok(l) => l,
                Err(e) => {
                    compose.set_cost_line(e.into());
                    compose.set_can_continue(false);
                    return;
                }
            };
            drop(cp);
            let nb_total: u64 = st
                .utxos
                .iter()
                .filter(|u| pick.is_selected(false, &u.txid, u.vout))
                .map(|u| u.value)
                .sum();
            let sp_total: u64 = section
                .as_ref()
                .map(|s| {
                    s.utxos
                        .iter()
                        .filter(|u| pick.is_selected(true, &u.txid, u.vout))
                        .map(|u| u.value)
                        .sum()
                })
                .unwrap_or(0);
            let in_value = nb_total + sp_total;
            // Anchored condition (mirrors `build_note_tx_mixed_exact_anchored`):
            // the notebook dust-to-self output is skipped whenever a notebook
            // coin is among the selected inputs — that input already anchors
            // the tx to the notebook's address history, so the discoverability
            // dust would be pure waste. Only a pure-spending-wallet-funded
            // build (n_notebook == 0) still needs it.
            let dust_applies = sp_participates && n_notebook == 0;
            let dust_needed = if dust_applies { notes_core::DUST_LIMIT } else { 0 };

            // Both shapes' extra (non-OP_RETURN) output lengths, computed
            // unconditionally now (previously the no-change list was only
            // built inside the folded branch) so the honest-fee-label
            // fold prediction below can always compare the two, exactly
            // mirroring what `notes_core::fold::predict_fold` needs.
            let mut extra_no_change: Vec<usize> = Vec::new();
            if let Some(l) = recipient_spk_len {
                extra_no_change.push(l);
            }
            if dust_applies {
                extra_no_change.push(34); // notebook dust spk (P2TR, always 34 bytes)
            }
            let mut extra_with_change = extra_no_change.clone();
            extra_with_change.push(change_len);
            let vsize_with_change = estimate_vsize_mixed(&kinds, &payload_lens, &extra_with_change);
            let fee_with_change = (vsize_with_change as f64 * rate).ceil() as u64;
            let vsize_no_change = estimate_vsize_mixed(&kinds, &payload_lens, &extra_no_change);
            let fee_no_change = (vsize_no_change as f64 * rate).ceil() as u64;
            let leftover_with_change =
                in_value.checked_sub(fee_with_change + total_gift + dust_needed);

            // took_no_change tracks which shape `(vsize, fee, ok)` below
            // actually reflects — needed because `ok2`'s success range
            // (`<= DUST_LIMIT`, including exactly 0 — an exact fit, not a
            // fold) is intentionally broader than
            // `notes_core::fold::predict_fold`'s "something folded"
            // signal (which excludes a 0 leftover); keeping this boolean
            // means the fold suffix below can never fire on an exact-fit
            // no-change build that isn't actually folding anything.
            let (vsize, fee, ok, took_no_change) = match leftover_with_change {
                Some(v) if v >= notes_core::DUST_LIMIT => {
                    (vsize_with_change, fee_with_change, true, false)
                }
                _ => {
                    let ok2 = matches!(in_value.checked_sub(fee_no_change + total_gift + dust_needed), Some(v) if v <= notes_core::DUST_LIMIT);
                    (vsize_no_change, fee_no_change, ok2, true)
                }
            };
            // Honest-fee-label (2026-07-19, ported from the graffito desktop app):
            // when the no-change (dust-fold) shape is what a real build
            // would take, `fee` above is already the byte-true NOMINAL
            // fee — but the actual signed tx's fee also carries the
            // sub-dust leftover on top of it (it can't be its own output,
            // so the builder folds it into the fee instead).
            // `predict_fold` mirrors that builder decision exactly for
            // this fixed selection (pin-tested in notes-core's
            // `tests/fold.rs` against `build_note_tx_exact`/
            // `build_note_tx_mixed_exact_anchored`), so the cost line can
            // show the split honestly instead of a single number that
            // reads as an inflated fee.
            let fold = if ok && took_no_change {
                notes_core::fold::predict_fold(in_value, total_gift + dust_needed, fee_with_change, fee_no_change, true)
            } else {
                None
            };
            if !ok {
                compose.set_cost_line(
                    format!(
                        "Needs ~{} sats — selected coins total {}.",
                        fee + total_gift + dust_needed,
                        in_value
                    )
                    .into(),
                );
                compose.set_can_continue(false);
            } else {
                compose.set_cost_line(
                    format!(
                        "{text_len} bytes · {chunks} chunk(s) · ~{vsize} vB · ~{} @ {rate} sat/vB{}{}{}",
                        sats_line(fee, st.btc_usd),
                        if !directed {
                            String::new()
                        } else if n_recipients <= 1 {
                            format!(" + {gift} sats to recipient")
                        } else {
                            format!(
                                " + {n_recipients} × {gift} = {total_gift} sats to {n_recipients} recipients"
                            )
                        },
                        if dust_applies {
                            format!(" + {} sats dust to notebook", notes_core::DUST_LIMIT)
                        } else {
                            String::new()
                        },
                        if let Some((_, folded)) = fold {
                            format!(" + {folded} sats leftover (dust rule)")
                        } else {
                            String::new()
                        }
                    )
                    .into(),
                );
                compose.set_can_continue(true);
            }
        });
    }

    // Post-quantum Security section: a typed edit un-certifies the
    // passphrase (compose-changed recomputes `pq-passphrase-verified`
    // from `pq_generated` vs. the current text) — this callback is just
    // the "recompute now" trigger `edited` fires, same shape as every
    // other compose field's `edited => { Callbacks.compose-changed(); }`.
    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_pq_passphrase_changed(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let pq_generated = pq_generated.clone();
        ui.global::<Callbacks>().on_pq_generate_passphrase(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            match passphrase::generate() {
                Ok(phrase) => {
                    ui.global::<Compose>().set_pq_passphrase_text(phrase.clone().into());
                    *pq_generated.borrow_mut() = Some(phrase);
                    log::info!("cb: pq-generate bits={:.0}", passphrase::GENERATED_BITS);
                    ui.global::<Callbacks>().invoke_compose_changed();
                }
                Err(e) => {
                    log::warn!("cb: pq-generate err={e}");
                }
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let plan = plan.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        let lock_policy = lock_policy.clone();
        let fs = fs.clone();
        let device_pq_key = device_pq_key.clone();
        ui.global::<Callbacks>().on_compose_continue(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let identity = identity.clone();
            let plan = plan.clone();
            let notebooks = notebooks.clone();
            let net = net.clone();
            let seed_idx = seed_idx.clone();
            let bip_account = bip_account.clone();
            let active = active.clone();
            let app_seed = app_seed.clone();
            let funding_pick = funding_pick.clone();
            let change_pick = change_pick.clone();
            let lock_policy = lock_policy.clone();
            let fs = fs.clone();
            let device_pq_key = device_pq_key.clone();
            // Let the busy overlay paint one frame before the blocking work.
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let compose = ui.global::<Compose>();
                let text = compose.get_text().to_string();
                let private = compose.get_private_note();
                let to_address = compose.get_to_address().trim().to_string();
                let directed = !to_address.is_empty();
                let extra_addrs: Vec<String> =
                    compose.get_to_extra().iter().map(|r| r.address.to_string()).collect();
                let tier = compose.get_tier();
                let rate_text = compose.get_rate_text().to_string();
                let gift = resolve_gift(directed, compose.get_gift_sats().as_str());
                // Post-quantum Security section (pq.rs) — read once here;
                // `compose-changed` already clamps these false whenever
                // the section isn't eligible (not directed/private, an
                // extra recipient present, or no usable recipient key).
                let pq_passphrase_active = compose.get_pq_passphrase_active();
                let pq_mlkem_active = compose.get_pq_mlkem_active();
                let pq_passphrase_text = compose.get_pq_passphrase_text().to_string();
                let st = state.borrow();
                let id_guard = identity.borrow();
                let pick = funding_pick.borrow().clone();
                let change_choice = change_pick.borrow().clone();
                let ix = notebooks.borrow();
                let ctx = notebook_ctx(&ix, *active.borrow())
                    .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
                let net_s = net.borrow().clone();
                let section = ix.spending(&net_s, ctx.0, ctx.1).cloned();
                drop(ix);

                // (note, spending inputs spent, spending change addr to mark
                // used, change went to notebook?, mandatory notebook dust
                // output present?) — the note's id IS its txid
                // (`note.txid_hex`), known only once the tx is fully built
                // below (PLAN-pnte-redesign.md: one note = one tx).
                type ComposeOut = (
                    NoteTx,
                    Vec<(String, u32)>,
                    Option<spending::SpendingAddress>,
                    bool,
                    bool,
                    u8, // pq_flags: 0 = ordinary note, else FLAG_PW|FLAG_MLKEM
                );
                let result: Result<ComposeOut, String> = id_guard
                    .as_ref()
                    .ok_or_else(|| "identity unavailable".to_string())
                    .and_then(|id| {
                        let rate = resolve_rate(tier, &rate_text, &st)?;
                        // Full recipient list (primary + every "+ Add
                        // recipient" row), each carrying the same gift
                        // amount — order matches notes-core's own output
                        // wrap order (OP_RETURN(s), then recipients in list
                        // order), which the ledger vout math below depends
                        // on matching exactly. Empty for a self-note; the
                        // `_multi` notes-core functions error on an empty
                        // slice, so callers below only invoke them when
                        // `directed` is true (recipients_vec has >= 1
                        // entry in that case, always).
                        let recipients_vec: Vec<(Recipient, u64)> = if directed {
                            let mut v = Vec::with_capacity(1 + extra_addrs.len());
                            v.push((
                                Recipient::parse(st.network(), &to_address)
                                    .map_err(|e| e.to_string())?,
                                gift,
                            ));
                            for a in &extra_addrs {
                                v.push((
                                    Recipient::parse(st.network(), a).map_err(|e| e.to_string())?,
                                    gift,
                                ));
                            }
                            v
                        } else {
                            Vec::new()
                        };
                        // Fresh TRNG content key for a multi-recipient
                        // private body — one-shot, never persisted/logged.
                        // Drawn unconditionally (cheap) so every branch
                        // below can pass it to the `_multi` calls without
                        // re-deriving.
                        let content_key = generate_content_key()?;
                        let sp_participates = !pick.spending.is_empty();
                        let mode_auto = !pick.touched && !sp_participates;

                        // Post-quantum layers (pq.rs) — single-recipient
                        // directed-private notes AND private self-notes,
                        // notebook-funded only either way: the pq compose
                        // primitives seal against
                        // `id.tweaked_seckey`/`id.enc_key` directly and
                        // have no mixed/spending-wallet variant (unlike the
                        // ordinary/`_multi` builders). A self-note's
                        // ML-KEM layer (PLAN-graffito-quantum-key.md)
                        // encapsulates to THIS device's own personal
                        // quantum key instead of a contact's — compose-
                        // changed only lets the pill activate off
                        // `directed` when that device key exists, so the
                        // lookup below can only fail if the key was
                        // deleted between the pill lighting up and Sign.
                        let pq_wanted = pq_passphrase_active || pq_mlkem_active;
                        if pq_wanted && sp_participates {
                            return Err(
                                "Quantum-safe layers need notebook-only funding — clear the \
                                 spending-wallet coins from \"Pay from\"."
                                    .to_string(),
                            );
                        }
                        let pq_active = pq_wanted && private && extra_addrs.is_empty();
                        let pq_mlkem_pair: Option<(pq::MlKemAlg, Vec<u8>)> = if pq_active
                            && pq_mlkem_active
                        {
                            if directed {
                                let armor = st
                                    .contacts
                                    .iter()
                                    .find(|c| c.address == to_address)
                                    .and_then(|c| c.mlkem_ek.clone())
                                    .ok_or("recipient has no quantum key — add one in Contacts")?;
                                Some(pq::import_public(&armor).map_err(|e| e.to_string())?)
                            } else {
                                let kp = device_quantum_key(&fs, &device_pq_key).ok_or(
                                    "no quantum key on this device — create one in Settings",
                                )?;
                                Some((kp.alg(), kp.ek().to_vec()))
                            }
                        } else {
                            None
                        };
                        let pq_layers = pq::SealLayers {
                            mlkem_ek: pq_mlkem_pair.as_ref().map(|(alg, ek)| (*alg, ek.as_slice())),
                            password: (pq_active && pq_passphrase_active)
                                .then_some(pq_passphrase_text.as_str()),
                        };
                        let pq_flags_out = if pq_active { pq_layers.flags() } else { 0 };
                        if pq_flags_out != 0 {
                            log::info!("cb: pq-compose flags={pq_flags_out}");
                        }

                        if mode_auto {
                            // Byte-identical input selection to before this
                            // feature — change destination is still
                            // independently resolvable (the picker screen).
                            let (change_spk, _) = resolve_change(
                                &change_choice.choice,
                                &change_choice.custom_address,
                                st.network(),
                                &id.output_x,
                                false,
                                &*app_seed_get(&app_seed).as_ref().ok_or("identity unavailable")?,
                                ctx.0,
                                ctx.1,
                                0,
                            )?;
                            let change_is_notebook = change_choice.choice != "custom";
                            let note = if pq_active && directed {
                                let recipient = Recipient::parse(st.network(), &to_address)
                                    .map_err(|e| e.to_string())?;
                                compose_directed_note_pq_with_change_amount(
                                    id,
                                    &st.core_utxos(),
                                    &text,
                                    &recipient,
                                    gift,
                                    pq_layers,
                                    Some(change_spk.as_slice()),
                                    st.effective_chunk(),
                                    rate,
                                    resolve_locktime(*lock_policy.borrow(), st.tip_height),
                                    || generate_aux_rand(),
                                )
                            } else if pq_active {
                                // Self-pw note (PLAN-graffito-self-pw.md):
                                // sealed under the notebook's enc key, not
                                // a directed ECDH — `directed` is false
                                // here (no recipient), so `pq_layers` can
                                // only carry the password (ML-KEM is
                                // never active off a self-note).
                                compose_note_pq_with_change(
                                    id,
                                    &st.core_utxos(),
                                    &text,
                                    pq_layers,
                                    Some(change_spk.as_slice()),
                                    st.effective_chunk(),
                                    rate,
                                    resolve_locktime(*lock_policy.borrow(), st.tip_height),
                                    || generate_aux_rand(),
                                )
                            } else if !recipients_vec.is_empty() {
                                compose_directed_note_multi_with_change(
                                    id,
                                    &st.core_utxos(),
                                    &text,
                                    private,
                                    &recipients_vec,
                                    content_key,
                                    Some(change_spk.as_slice()),
                                    st.effective_chunk(),
                                    rate,
                                    resolve_locktime(*lock_policy.borrow(), st.tip_height),
                                    || generate_aux_rand(),
                                )
                            } else {
                                notes_core::bundle::compose_note_with_change(
                                    id,
                                    &st.core_utxos(),
                                    &text,
                                    private,
                                    Some(change_spk.as_slice()),
                                    st.effective_chunk(),
                                    rate,
                                    resolve_locktime(*lock_policy.borrow(), st.tip_height),
                                    || generate_aux_rand(),
                                )
                            }
                            .map_err(|e| e.to_string())?;
                            Ok((note, Vec::new(), None, change_is_notebook, false, pq_flags_out))
                        } else if !sp_participates {
                            // Notebook-only coin control (a subset was
                            // explicitly picked, or explicitly re-confirmed).
                            let inputs: Vec<Utxo> = st
                                .utxos
                                .iter()
                                .filter(|u| pick.is_selected(false, &u.txid, u.vout))
                                .filter_map(|u| {
                                    let mut txid = [0u8; 32];
                                    hex::decode_to_slice(&u.txid, &mut txid).ok()?;
                                    txid.reverse();
                                    Some(Utxo { txid, vout: u.vout, value: u.value })
                                })
                                .collect();
                            if inputs.is_empty() {
                                return Err("Select at least one coin to pay from.".into());
                            }
                            let (change_spk, _) = resolve_change(
                                &change_choice.choice,
                                &change_choice.custom_address,
                                st.network(),
                                &id.output_x,
                                false,
                                &*app_seed_get(&app_seed).as_ref().ok_or("identity unavailable")?,
                                ctx.0,
                                ctx.1,
                                0,
                            )?;
                            let change_is_notebook = change_choice.choice != "custom";
                            let note = if pq_active && directed {
                                let recipient = Recipient::parse(st.network(), &to_address)
                                    .map_err(|e| e.to_string())?;
                                compose_directed_note_pq_exact_amount(
                                    id,
                                    &inputs,
                                    &text,
                                    &recipient,
                                    gift,
                                    pq_layers,
                                    Some(change_spk.as_slice()),
                                    st.effective_chunk(),
                                    rate,
                                    resolve_locktime(*lock_policy.borrow(), st.tip_height),
                                    || generate_aux_rand(),
                                )
                            } else if pq_active {
                                // Self-pw note, coin-control funding — see
                                // the mode_auto branch's comment above.
                                compose_note_pq_exact(
                                    id,
                                    &inputs,
                                    &text,
                                    pq_layers,
                                    Some(change_spk.as_slice()),
                                    st.effective_chunk(),
                                    rate,
                                    resolve_locktime(*lock_policy.borrow(), st.tip_height),
                                    || generate_aux_rand(),
                                )
                            } else if !recipients_vec.is_empty() {
                                compose_directed_note_multi_exact(
                                    id,
                                    &inputs,
                                    &text,
                                    private,
                                    &recipients_vec,
                                    content_key,
                                    Some(change_spk.as_slice()),
                                    st.effective_chunk(),
                                    rate,
                                    resolve_locktime(*lock_policy.borrow(), st.tip_height),
                                    || generate_aux_rand(),
                                )
                            } else {
                                compose_note_exact(
                                    id,
                                    &inputs,
                                    &text,
                                    private,
                                    Some(change_spk.as_slice()),
                                    st.effective_chunk(),
                                    rate,
                                    resolve_locktime(*lock_policy.borrow(), st.tip_height),
                                    || generate_aux_rand(),
                                )
                            }
                            .map_err(|e| e.to_string())?;
                            Ok((note, Vec::new(), None, change_is_notebook, false, pq_flags_out))
                        } else {
                            // Spending-wallet participates (pure spending or
                            // mixed with notebook coins) — mixed builder. The
                            // notebook dust-to-self anchor is emitted ONLY
                            // when no notebook coin is among the selected
                            // inputs (`build_note_tx_mixed_exact_anchored`'s
                            // skip condition, funding-unification
                            // 2026-07-18) — a notebook input already anchors
                            // the tx to the notebook's address history.
                            let seed: &[u8; 32] =
                                &*app_seed_get(&app_seed).as_ref().ok_or("identity unavailable")?;
                            let notebook_dust_spk = p2tr_script_pubkey(&id.output_x);
                            let mut mixed_inputs: Vec<MixedInput> = Vec::new();
                            let mut has_notebook_input = false;
                            for u in
                                st.utxos.iter().filter(|u| pick.is_selected(false, &u.txid, u.vout))
                            {
                                let mut txid = [0u8; 32];
                                hex::decode_to_slice(&u.txid, &mut txid)
                                    .map_err(|_| "bad notebook txid".to_string())?;
                                txid.reverse();
                                mixed_inputs.push(MixedInput {
                                    utxo: Utxo { txid, vout: u.vout, value: u.value },
                                    prevout_spk: notebook_dust_spk.clone(),
                                    kind: InputKind::Taproot,
                                    seckey: id.tweaked_seckey,
                                });
                                has_notebook_input = true;
                            }
                            let sec =
                                section.as_ref().ok_or("spending wallet not set up".to_string())?;
                            let mut spent_spending: Vec<(String, u32)> = Vec::new();
                            for su in
                                sec.utxos.iter().filter(|u| pick.is_selected(true, &u.txid, u.vout))
                            {
                                let key = notes_core::seeds::derive_spending_key(
                                    seed,
                                    ctx.0,
                                    st.network(),
                                    ctx.1,
                                    su.chain,
                                    su.index,
                                )
                                .map_err(|e| e.to_string())?;
                                let mut txid = [0u8; 32];
                                hex::decode_to_slice(&su.txid, &mut txid)
                                    .map_err(|_| "bad spending txid".to_string())?;
                                txid.reverse();
                                mixed_inputs.push(MixedInput {
                                    utxo: Utxo { txid, vout: su.vout, value: su.value },
                                    prevout_spk: key.script_pubkey.clone(),
                                    kind: InputKind::P2wpkh,
                                    seckey: key.seckey,
                                });
                                spent_spending.push((su.txid.clone(), su.vout));
                            }
                            if mixed_inputs.is_empty() {
                                return Err("Select at least one coin to pay from.".into());
                            }
                            // The tx's FIRST input's outpoint — the mixed
                            // builder below keeps `mixed_inputs` order
                            // verbatim (notebook inputs first, then
                            // spending), so `mixed_inputs[0]` IS the tx's
                            // first input; every sealed body's AAD binds to
                            // it (crypt.rs/dm.rs's uniform outpoint rule,
                            // PLAN-pnte-redesign.md).
                            let outpoint = notes_core::tx::outpoint_bytes(&mixed_inputs[0].utxo);
                            // `sealed_note_payloads_multi` has no self-note
                            // case (errors on an empty recipients slice —
                            // notes-core bundle.rs:876), so a self-note
                            // (recipients_vec empty) keeps calling the old
                            // singular `sealed_note_payloads` with `None`;
                            // only a directed note switches to the `_multi`
                            // primitive.
                            let (payloads, recipients_amounts): (Vec<Vec<u8>>, Vec<(Vec<u8>, u64)>) =
                                if !recipients_vec.is_empty() {
                                    // `Recipient` isn't `Clone`; re-parsing
                                    // from the address string (already
                                    // validated once above) is cheap and
                                    // avoids touching notes-core for this.
                                    let recips: Vec<Recipient> = recipients_vec
                                        .iter()
                                        .map(|(r, _)| {
                                            Recipient::parse(st.network(), &r.address)
                                                .map_err(|e| e.to_string())
                                        })
                                        .collect::<Result<_, _>>()?;
                                    let (payloads, spks) = sealed_note_payloads_multi(
                                        id,
                                        &text,
                                        private,
                                        &recips,
                                        outpoint,
                                        content_key,
                                        st.effective_chunk(),
                                    )
                                    .map_err(|e| e.to_string())?;
                                    let amounts =
                                        spks.into_iter().map(|spk| (spk, gift)).collect();
                                    (payloads, amounts)
                                } else {
                                    let (payloads, _) = sealed_note_payloads(
                                        id,
                                        &text,
                                        private,
                                        None,
                                        outpoint,
                                        st.effective_chunk(),
                                    )
                                    .map_err(|e| e.to_string())?;
                                    (payloads, Vec::new())
                                };
                            let (change_spk, change_addr) = resolve_change(
                                &change_choice.choice,
                                &change_choice.custom_address,
                                st.network(),
                                &id.output_x,
                                true,
                                seed,
                                ctx.0,
                                ctx.1,
                                sec.next_change,
                            )?;
                            let change_is_notebook = change_choice.choice == "notebook";
                            // `build_note_tx_mixed_exact_anchored_multi` with
                            // <=1 recipient entries delegates byte-identically
                            // to `build_note_tx_mixed_exact_anchored` (tx.rs),
                            // so this single call covers self/single/multi
                            // recipient shapes without branching.
                            let note = build_note_tx_mixed_exact_anchored_multi(
                                &mixed_inputs,
                                &payloads,
                                &recipients_amounts,
                                &notebook_dust_spk,
                                &change_spk,
                                rate,
                                resolve_locktime(*lock_policy.borrow(), st.tip_height),
                                || generate_aux_rand(),
                            )
                            .map_err(|e| e.to_string())?;
                            // Dust is emitted iff no notebook input anchored
                            // the tx — mirrors the builder's own condition
                            // exactly (`inputs.iter().any(prevout_spk ==
                            // notebook_dust_spk)`), computed from the SAME
                            // `has_notebook_input` used to build `mixed_inputs`
                            // above, so this can never drift from the actual
                            // wire shape.
                            let notebook_dust = !has_notebook_input;
                            Ok((
                                note,
                                spent_spending,
                                change_addr,
                                change_is_notebook,
                                notebook_dust,
                                0, // pq layers require notebook-only funding — guarded above
                            ))
                        }
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok((note, spending_spent, spending_change_addr, change_is_notebook, notebook_dust, pq_flags_note)) => {
                        let chunks = note
                            .tx
                            .outputs
                            .iter()
                            .filter(|o| o.script_pubkey.first() == Some(&0x6a))
                            .count() as u64;
                        let funded_by = pick.mode_label();
                        // Full recipient list for THIS note (empty for a
                        // self-note; primary + every "+ Add recipient" row
                        // otherwise), in the same order as `recipients_vec`
                        // fed the builder above — matches notes-core's own
                        // output wrap order (OP_RETURN(s), recipients in
                        // list order), which the ledger vout math further
                        // below depends on matching exactly.
                        let recipients_display: Vec<String> = if directed {
                            let mut v = vec![to_address.clone()];
                            v.extend(extra_addrs.iter().cloned());
                            v
                        } else {
                            Vec::new()
                        };
                        log::info!(
                            "cb: compose len={} private={} to={} chunks={} fee={} vsize={} gift={} funded={funded_by} recipients={} txid={} ok",
                            text.len(),
                            private,
                            if directed { to_address.as_str() } else { "self" },
                            chunks,
                            note.fee,
                            note.vsize,
                            note.sent,
                            recipients_display.len(),
                            note.txid_hex
                        );
                        let recipient = if directed { Some(to_address.clone()) } else { None };
                        let recipient_name = if directed {
                            st.contacts
                                .iter()
                                .find(|c| c.address == to_address && !c.name.is_empty())
                                .map(|c| c.name.clone())
                        } else {
                            None
                        };

                        // ConfirmCtx: the universal byte-truth decode gate
                        // (screen 4) — every fact it shows comes from
                        // decoding `note.raw_hex` itself; this only gathers
                        // the LOOKUPS (source labels, self/change spks).
                        let active_acct = active.borrow().unwrap_or(0);
                        let ix = notebooks.borrow();
                        let active_name = {
                            let short = id_guard
                                .as_ref()
                                .map(|id| short_addr(&id.address(st.network())))
                                .unwrap_or_default();
                            notebook_name(&ix, active_acct, &short)
                        };
                        let (mut self_spks, mut spending_spks) =
                            confirm_self_spks(&ix, app_seed_get(&app_seed), &net_s, ctx);
                        drop(ix);
                        // A fresh spending-wallet change address this very
                        // tx pays isn't in `used` yet (marked only after a
                        // successful sign) — add it so the change output
                        // classifies as ours, not "other".
                        if let Some(addr) = &spending_change_addr {
                            if let Ok(spk) = hex::decode(&addr.spk_hex) {
                                if !spending_spks.iter().any(|s| s == &spk) {
                                    spending_spks.push(spk.clone());
                                }
                                if !self_spks.iter().any(|s| s == &spk) {
                                    self_spks.push(spk);
                                }
                            }
                        }

                        // Addresses of any spending-wallet coins this tx
                        // spent, for the input rows' title (best-effort —
                        // display only, never affects classification).
                        let spending_addrs: std::collections::HashMap<(String, u32), String> =
                            if spending_spent.is_empty() {
                                Default::default()
                            } else {
                                section
                                    .as_ref()
                                    .into_iter()
                                    .flat_map(|s| s.utxos.iter())
                                    .filter(|u| {
                                        spending_spent.iter().any(|(t, v)| *t == u.txid && *v == u.vout)
                                    })
                                    .filter_map(|u| {
                                        let seed_bytes = app_seed_get(&app_seed).as_ref()?;
                                        notes_core::seeds::derive_spending_key(
                                            seed_bytes,
                                            ctx.0,
                                            st.network(),
                                            ctx.1,
                                            u.chain,
                                            u.index,
                                        )
                                        .ok()
                                        .map(|k| ((u.txid.clone(), u.vout), k.address))
                                    })
                                    .collect()
                            };

                        let mut prevouts: BTreeMap<String, notes_core::confirm::PrevoutInfo> =
                            BTreeMap::new();
                        for u in &note.tx.inputs {
                            let mut t = u.txid;
                            t.reverse();
                            let txid_hex = hex::encode(t);
                            let is_spending =
                                spending_spent.iter().any(|(t2, v2)| *t2 == txid_hex && *v2 == u.vout);
                            let (source, address) = if is_spending {
                                (
                                    "Spending wallet".to_string(),
                                    spending_addrs.get(&(txid_hex.clone(), u.vout)).cloned(),
                                )
                            } else {
                                (
                                    format!("Notebook · {active_name}"),
                                    id_guard.as_ref().map(|id| id.address(st.network())),
                                )
                            };
                            prevouts.insert(
                                format!("{txid_hex}:{}", u.vout),
                                notes_core::confirm::PrevoutInfo { value: u.value, address, source },
                            );
                        }

                        let note_preview = Some(if private {
                            "Private note (encrypted)".to_string()
                        } else {
                            text.clone()
                        });
                        let cctx = notes_core::confirm::ConfirmCtx {
                            network: st.network(),
                            prevouts,
                            self_spks,
                            spending_spks,
                            expected_change: (change_choice.choice == "custom"
                                && !change_choice.custom_address.trim().is_empty())
                            .then(|| change_choice.custom_address.trim().to_string()),
                            recipient: recipient.clone(),
                            recipient_name,
                            recipients: recipients_display.clone(),
                            note_preview,
                        };
                        let context_line = format!(
                            "{} note · {}",
                            if directed {
                                "Directed"
                            } else if private {
                                "Private"
                            } else {
                                "Public"
                            },
                            st.network
                        );

                        match show_confirm_screen(
                            &ui,
                            "compose",
                            &note.raw_hex,
                            &cctx,
                            context_line,
                            "Sign & export",
                        ) {
                            Ok(()) => {
                                // Honest-fee-label: `note` is the REAL
                                // signed tx, so this is a decomposition of
                                // its own numbers (see `note_fold_amount`'s
                                // doc), not a prediction — `rate` resolves
                                // deterministically from the same
                                // `tier`/`rate_text`/`st` that already
                                // built `note` successfully, so this can't
                                // fail here.
                                if let Ok(rate) = resolve_rate(tier, &rate_text, &st) {
                                    let fold_amount =
                                        note_fold_amount(note.fee, note.vsize, note.change, rate);
                                    if fold_amount > 0 {
                                        ui.global::<ConfirmSign>()
                                            .set_fold(format!("{fold_amount} sats").into());
                                        log::info!("cb: confirm fold amount={fold_amount}");
                                    }
                                }
                                *plan.borrow_mut() = Some(Plan {
                                    note,
                                    text,
                                    private,
                                    chunks,
                                    recipients: recipients_display.clone(),
                                    spending_spent,
                                    spending_change_addr,
                                    change_is_notebook,
                                    notebook_dust,
                                    pq_flags: pq_flags_note,
                                });
                            }
                            Err(e) => {
                                log::warn!("cb: confirm summarize err={e}");
                                compose.set_cost_line(format!("Cannot show confirm: {e}").into());
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("cb: compose len={} private={} err={e}", text.len(), private);
                        compose.set_cost_line(format!("Cannot build: {e}").into());
                    }
                }
            });
        });
    }

    // Universal Confirm & sign gate (screen 4) — dispatches on
    // ConfirmSign.kind to the three sign bodies (each was its own
    // dedicated callback before the confirm-gate refactor; merged here so
    // Sign always fires through one place, no callback-from-callback
    // re-entrancy). Ledger/outbox mutations happen ONLY past this point.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let plan = plan.clone();
        let sweep_plan = sweep_plan.clone();
        let psbt_pending = psbt_pending.clone();
        let identity = identity.clone();
        let fs = fs.clone();
        let refresh_notes = refresh_notes.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let refresh_funding = refresh_funding.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_confirm_sign(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let kind = ui.global::<ConfirmSign>().get_kind().to_string();
            let txid = ui.global::<ConfirmSign>().get_txid().to_string();
            log::info!("cb: confirm sign kind={kind} txid={txid}");
            match kind.as_str() {
                "sweep" | "consolidate" => {
                    let Some(p) = sweep_plan.borrow_mut().take() else { return };
                    ui.global::<Ui>().set_busy(true);
                    let ui_weak = ui_weak.clone();
                    let state = state.clone();
                    let fs = fs.clone();
                    let active = active.clone();
                    let net = net.clone();
                    let refresh_home = refresh_home.clone();
                    Timer::single_shot(Duration::from_millis(150), move || {
                        let Some(ui) = ui_weak.upgrade() else { return };
                        let mut st = state.borrow_mut();
                        let active_acct = active.borrow().unwrap_or(p.dest_account);

                        // Wallet-level ledger: remove each notebook's spent
                        // inputs from its own state file (the active one via
                        // the live `st`); a consolidate's single output lands
                        // in the destination notebook as its new
                        // (unconfirmed) coin.
                        let inputs: usize = p.spent_by_account.iter().map(|(_, o)| o.len()).sum();
                        let recv = p.tx.tx.outputs[0].value;
                        for (acct, spent) in &p.spent_by_account {
                            if *acct == active_acct {
                                st.utxos.retain(|u| !spent.contains(&(u.txid.clone(), u.vout)));
                            } else {
                                let mut other = load_state(&fs, &net.borrow(), *acct);
                                other.utxos.retain(|u| !spent.contains(&(u.txid.clone(), u.vout)));
                                save_state(&fs, &other);
                            }
                        }
                        if p.kind == "consolidate" {
                            let coin = UtxoRec { txid: p.tx.txid_hex.clone(), vout: 0, value: recv };
                            if p.dest_account == active_acct {
                                st.utxos.push(coin);
                            } else {
                                let mut dest = load_state(&fs, &net.borrow(), p.dest_account);
                                dest.utxos.push(coin);
                                save_state(&fs, &dest);
                            }
                        }

                        let file = format!("{OUTBOX_DIR}/{}.hex", p.tx.txid_hex);
                        let internal = ensure_dir(&fs, OUTBOX_DIR, Location::User).and_then(|_| {
                            write_file(&fs, &file, Location::User, p.tx.raw_hex.as_bytes())
                        });
                        let airlock = ensure_airlock_mounted(&fs).and_then(|_| {
                            let r = ensure_dir(&fs, OUTBOX_DIR, Location::Airlock).and_then(|_| {
                                write_file(&fs, &file, Location::Airlock, p.tx.raw_hex.as_bytes())
                            });
                            unmount_airlock(&fs);
                            r
                        });
                        save_state(&fs, &st);
                        log::info!(
                            "cb: sign-sweep kind={} txid={} fee={} internal={} airlock={}",
                            p.kind,
                            p.tx.txid_hex,
                            p.tx.fee,
                            if internal.is_ok() { "ok" } else { "err" },
                            if airlock.is_ok() { "ok" } else { "err" },
                        );
                        drop(st);

                        let sp = ui.global::<SignPsbt>();
                        sp.set_summary(
                            format!(
                                "{}\nfee {} sats · {} vB\ntxid: {}",
                                match (p.kind, &p.dest) {
                                    ("consolidate", _) =>
                                        format!("Consolidated {inputs} coin(s) into one · {recv} sats"),
                                    (_, Some(d)) =>
                                        format!("Swept {inputs} coin(s) · {recv} sats to {}", short_addr(d)),
                                    _ => format!("Swept {inputs} coin(s) · {recv} sats"),
                                },
                                p.tx.fee,
                                p.tx.vsize,
                                p.tx.txid_hex
                            )
                            .into(),
                        );
                        if p.tx.raw_hex.len() <= MAX_QR_HEX_CHARS {
                            sp.set_qr(qr_image(&p.tx.raw_hex.to_uppercase()));
                            sp.set_has_qr(true);
                        } else {
                            sp.set_has_qr(false);
                        }
                        sp.set_back_screen(0);

                        // Reset the sweep flow so nothing leaks into the next run.
                        let sweep = ui.global::<Sweep>();
                        sweep.set_dest("".into());
                        sweep.set_dest_label("".into());
                        sweep.set_tier(1);
                        sweep.set_cost_line("".into());
                        sweep.set_can_continue(false);
                        ui.global::<Contacts>().set_pick_mode("compose".into());

                        ui.global::<Ui>().set_busy(false);
                        refresh_home();
                        ui.global::<Ui>().set_screen(8);
                    });
                }
                "psbt" => {
                    let Some(psbt) = psbt_pending.borrow_mut().take() else { return };
                    let id_guard = identity.borrow();
                    let Some(id) = id_guard.as_ref() else {
                        drop(id_guard);
                        ui.global::<Sync>().set_result("Device locked — no signing key.".into());
                        ui.global::<Ui>().set_screen(5);
                        return;
                    };
                    let output_x = id.output_x;
                    let tweaked_seckey = id.tweaked_seckey;
                    drop(id_guard);
                    ui.global::<Ui>().set_busy(true);
                    let ui_weak = ui_weak.clone();
                    let fs = fs.clone();
                    let mut psbt = psbt;
                    Timer::single_shot(Duration::from_millis(150), move || {
                        let Some(ui) = ui_weak.upgrade() else { return };
                        let (ours, signed) =
                            match psbt.sign_own_taproot(&output_x, &tweaked_seckey, generate_aux_rand) {
                                Ok(x) => x,
                                Err(e) => {
                                    ui.global::<Ui>().set_busy(false);
                                    ui.global::<Sync>().set_result(format!("Sign failed: {e}").into());
                                    ui.global::<Ui>().set_screen(5);
                                    return;
                                }
                            };
                        log::info!("cb: sign-psbt inputs={ours} signed={signed} ok");
                        let hex_str = hex::encode_upper(psbt.serialize());
                        let out_txid = psbt.unsigned_tx.txid_hex();
                        let file = format!("{OUTBOX_DIR}/{out_txid}.psbt.hex");
                        let _ = ensure_dir(&fs, OUTBOX_DIR, Location::User)
                            .and_then(|_| write_file(&fs, &file, Location::User, hex_str.as_bytes()));
                        let fee = psbt_fee(&psbt);
                        let note = psbt_note_summary(&psbt);
                        let sp = ui.global::<SignPsbt>();
                        sp.set_summary(
                            format!("Signed {signed} of {ours} input(s) · fee {fee} sats\n{note}")
                                .into(),
                        );
                        if hex_str.len() <= MAX_QR_HEX_CHARS {
                            sp.set_qr(qr_image(&hex_str));
                            sp.set_has_qr(true);
                        } else {
                            sp.set_has_qr(false);
                        }
                        ui.global::<Ui>().set_error("".into());
                        ui.global::<Ui>().set_busy(false);
                        ui.global::<Ui>().set_screen(8);
                    });
                }
                _ => {
                    // "compose" — the default arm.
                    let Some(p) = plan.borrow_mut().take() else { return };
                    ui.global::<Ui>().set_busy(true);
                    let ui_weak = ui_weak.clone();
                    let state = state.clone();
                    let fs = fs.clone();
                    let refresh_notes = refresh_notes.clone();
                    let notebooks = notebooks.clone();
                    let net = net.clone();
                    let seed_idx = seed_idx.clone();
                    let bip_account = bip_account.clone();
                    let active = active.clone();
                    let refresh_funding = refresh_funding.clone();
                    let funding_pick = funding_pick.clone();
                    let change_pick = change_pick.clone();
                    Timer::single_shot(Duration::from_millis(150), move || {
                        let Some(ui) = ui_weak.upgrade() else { return };
                        let mut st = state.borrow_mut();

                        // Notebook ledger: drop spent notebook inputs. Spending-wallet
                        // inputs (if any) are dropped from the SEPARATE spending
                        // ledger below via `p.spending_spent` — `p.note.spent_outpoints`
                        // covers both kinds, but only notebook outpoints ever match
                        // an entry in `st.utxos`, so this retain is safe either way.
                        let spent: Vec<(String, u32)> = p
                            .note
                            .spent_outpoints
                            .iter()
                            .map(|(txid, vout)| {
                                let mut t = *txid;
                                t.reverse();
                                (hex::encode(t), *vout)
                            })
                            .collect();
                        st.utxos.retain(|u| !spent.contains(&(u.txid.clone(), u.vout)));

                        // Output order: OP_RETURN(s), EVERY directed recipient (in
                        // list order — matches notes-core's own builders, and the
                        // order `recipients_vec` was fed to them in
                        // `on_compose_continue`), [notebook dust — present unless a
                        // notebook coin already anchors the tx, see
                        // `Plan.notebook_dust`'s doc], [change]. `p.chunks` +
                        // `p.recipients.len()` (0, 1, or N recipient outputs) place
                        // the dust slot; +1 more ONLY when `p.notebook_dust` is true
                        // places change — when dust is skipped, change lands in that
                        // same slot instead (computed from the flag, never a
                        // hardcoded position). Getting `p.recipients.len()` right
                        // here is safety-critical: a wrong offset would make the app
                        // track the WRONG utxo as its own dust/change coin.
                        let dust_vout = p.chunks as u32 + p.recipients.len() as u32;
                        if p.notebook_dust {
                            st.utxos.push(UtxoRec {
                                txid: p.note.txid_hex.clone(),
                                vout: dust_vout,
                                value: notes_core::DUST_LIMIT,
                            });
                        }
                        let change_vout = dust_vout + u32::from(p.notebook_dust);
                        if p.note.change > 0 && p.change_is_notebook {
                            st.utxos.push(UtxoRec {
                                txid: p.note.txid_hex.clone(),
                                vout: change_vout,
                                value: p.note.change,
                            });
                        }
                        // Custom/external change: not our coin, nothing to track
                        // (matches how a directed recipient's dust isn't tracked).

                        // Spending ledger: drop spent inputs + add change (if it
                        // went to a fresh spending address) in one pass — mirrors
                        // the notebook ledger's unconfirmed-chaining update above.
                        if !p.spending_spent.is_empty() || p.spending_change_addr.is_some() {
                            let mut ix = notebooks.borrow_mut();
                            let ctx = notebook_ctx(&ix, *active.borrow())
                                .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
                            let net_s = net.borrow().clone();
                            let sec = ix.spending_mut(&net_s, ctx.0, ctx.1);
                            let change_coin =
                                if p.note.change > 0 { p.spending_change_addr.as_ref() } else { None };
                            if let Some(addr) = change_coin {
                                sec.mark_used(addr.clone());
                            }
                            sec.apply_spend(
                                &p.spending_spent,
                                change_coin.map(|addr| spending::SpendingUtxo {
                                    txid: p.note.txid_hex.clone(),
                                    vout: change_vout,
                                    value: p.note.change,
                                    chain: addr.chain,
                                    index: addr.index,
                                }),
                            );
                            save_notebooks(&fs, &ix);
                        }

                        // Self-pw note (PLAN-graffito-self-pw.md): a
                        // self-note (no recipient) carrying a pq layer is
                        // stored LOCKED from the moment it's signed —
                        // never a plaintext cache, and re-derived here
                        // from the tx's own bytes rather than trusted from
                        // `p.pq_flags`/`p.text`, so a bug in the compose
                        // path can't accidentally leak plaintext into
                        // state.json. `None` for every other note (a
                        // directed note, or a self-note with no pq layer),
                        // which keeps their existing plaintext-cached
                        // behavior byte-identical.
                        let self_locked =
                            if p.recipients.is_empty() { self_pw_locked_body(&p.note) } else { None };
                        let rec = NoteRec {
                            id: p.note.txid_hex.clone(),
                            text: if self_locked.is_some() {
                                String::new()
                            } else {
                                p.text.clone()
                            },
                            private: p.private,
                            txid: p.note.txid_hex.clone(),
                            raw_hex: p.note.raw_hex.clone(),
                            fee: p.note.fee,
                            vsize: p.note.vsize as u64,
                            chunks: p.chunks,
                            height: None,
                            blocktime: None,
                            status: "pending".into(),
                            directed: !p.recipients.is_empty(),
                            to: p.recipients.first().cloned(),
                            from: None,
                            recipients: p.recipients.clone(),
                            pq_flags: p.pq_flags,
                            // A directed own composed note (or an ordinary
                            // self-note): plaintext is already known
                            // (`p.text` above) — never locked. A self-pw
                            // note: `self_locked` above, view-only unlock.
                            locked: self_locked,
                        };

                        // Export the signed tx for the companion to broadcast:
                        // always to internal outbox; Airlock too when available.
                        let file = format!("{OUTBOX_DIR}/{}.hex", p.note.txid_hex);
                        let internal = ensure_dir(&fs, OUTBOX_DIR, Location::User).and_then(|_| {
                            write_file(&fs, &file, Location::User, p.note.raw_hex.as_bytes())
                        });
                        let airlock = ensure_airlock_mounted(&fs).and_then(|_| {
                            let r = ensure_dir(&fs, OUTBOX_DIR, Location::Airlock).and_then(|_| {
                                write_file(&fs, &file, Location::Airlock, p.note.raw_hex.as_bytes())
                            });
                            // Full flush so the file survives unplug (paper-wallet
                            // pattern).
                            unmount_airlock(&fs);
                            r
                        });
                        log::info!(
                            "cb: sign-note id={} fee={} vsize={} internal={} airlock={}",
                            rec.id,
                            rec.fee,
                            rec.vsize,
                            if internal.is_ok() { "ok" } else { "err" },
                            if airlock.is_ok() { "ok" } else { "err" },
                        );

                        // Auto-save every recipient as a recent contact (usually a
                        // no-op re-front after the pick, but covers every path).
                        for to in &p.recipients {
                            upsert_contact(&mut st, to);
                        }
                        st.notes.push(rec.clone());
                        save_state(&fs, &st);
                        drop(st);
                        refresh_funding();

                        let view = ui.global::<View>();
                        view.set_id(rec.id.clone().into());
                        view.set_text(rec.text.clone().into());
                        view.set_badge(if rec.private { "PRIVATE" } else { "PUBLIC" }.into());
                        view.set_meta(
                            format!(
                                "pending — scan the QR with the companion, or broadcast {}.hex\nfee {} sats · {} vB",
                                rec.txid, rec.fee, rec.vsize
                            )
                            .into(),
                        );
                        // Straight to the QR after signing — that's the broadcast path.
                        set_view_qr(&view, &rec);
                        view.set_show_qr(view.get_has_qr());
                        ui.global::<Compose>().set_text("".into());
                        // A stale recipient must never silently direct the next note.
                        ui.global::<Compose>().set_to_address("".into());
                        ui.global::<Compose>().set_to_label("".into());
                        ui.global::<Compose>()
                            .set_to_extra(Rc::new(VecModel::from(Vec::<ToRow>::new())).into());
                        // Gift resets with the recipient so a large gift can't leak
                        // into the next note.
                        ui.global::<Compose>().set_gift_sats("330".into());
                        ui.global::<Compose>().set_gift_expanded(false);
                        // Funding/change picks reset too — a stale coin selection or
                        // custom change address must never leak into the next note.
                        *funding_pick.borrow_mut() = FundingPick::default();
                        *change_pick.borrow_mut() = ChangePickState::default();
                        ui.global::<ChangePick>().set_choice("auto".into());
                        ui.global::<ChangePick>().set_custom_address("".into());
                        ui.global::<Ui>().set_busy(false);
                        refresh_notes();
                        ui.global::<Ui>().set_screen(2);
                    });
                }
            }
        });
    }

    // Back from the universal Confirm & sign screen (4): discard whatever
    // was staged (Plan/SweepPlan/the stashed Psbt) and clear the shown
    // rows, then return to the kind's origin screen.
    {
        let ui_weak = ui_weak.clone();
        let plan = plan.clone();
        let sweep_plan = sweep_plan.clone();
        let psbt_pending = psbt_pending.clone();
        ui.global::<Callbacks>().on_confirm_cancel(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let kind = ui.global::<ConfirmSign>().get_kind().to_string();
            log::info!("cb: confirm cancel kind={kind}");
            *plan.borrow_mut() = None;
            *sweep_plan.borrow_mut() = None;
            *psbt_pending.borrow_mut() = None;
            let cs = ui.global::<ConfirmSign>();
            cs.set_inputs(Rc::new(VecModel::from(Vec::<ConfirmRow>::new())).into());
            cs.set_outputs(Rc::new(VecModel::from(Vec::<ConfirmRow>::new())).into());
            cs.set_context("".into());
            cs.set_txid("".into());
            cs.set_note("".into());
            cs.set_fee_line("".into());
            cs.set_warn("".into());
            cs.set_kind("".into());
            let back = match kind.as_str() {
                "sweep" | "consolidate" => 10,
                "psbt" => 5,
                _ => 3,
            };
            ui.global::<Ui>().set_screen(back);
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let fs = fs.clone();
        let device_pq_key = device_pq_key.clone();
        ui.global::<Callbacks>().on_open_note(move |id| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let Some(n) = st.notes.iter().find(|n| n.id == id.as_str()) else { return };
            let view = ui.global::<View>();
            view.set_id(n.id.clone().into());
            view.set_text(n.text.clone().into());
            view.set_badge(if n.private { "PRIVATE" } else { "PUBLIC" }.into());
            let where_line = match n.height {
                Some(h) => format!("confirmed at block {h}"),
                None => "pending — scan the tx QR with the companion to broadcast".to_string(),
            };
            let who_line = if n.recipients.len() > 1 {
                let mut line = format!("\nto ({}): {}", n.recipients.len(), n.recipients[0]);
                for addr in &n.recipients[1..] {
                    line.push_str(&format!("\n    {addr}"));
                }
                line
            } else {
                match (&n.from, &n.to) {
                    (Some(from), _) => format!("\nfrom: {from}"),
                    (None, Some(to)) => format!("\nto: {to}"),
                    _ => String::new(),
                }
            };
            view.set_meta(format!("{where_line}{who_line}\ntxid: {}", n.txid).into());
            set_view_qr(&view, n);
            view.set_show_qr(false);

            // Post-quantum lock state (pq.rs) — mirrors the Mac app's
            // `refresh_note_unlock_ui`: an own (sent) DIRECTED note
            // carrying FLAG_MLKEM can NEVER be re-opened (the ct was
            // encapsulated to the RECIPIENT only — checked first,
            // unconditionally, even if FLAG_PW is also set); a
            // received/unlockable note with FLAG_PW gets the password
            // field; anything else locked (a received ML-KEM-only note
            // this device somehow couldn't auto-decrypt at scan time)
            // gets an explanatory caption only.
            //
            // Self-notes have no sender OR recipient, so `n.from.is_none()`
            // alone can't disambiguate a self-locked body from an own
            // directed-sent one the way it used to — `is_self_locked`
            // (`LockedBody::is_self`) does. A self body sealed under
            // FLAG_MLKEM (PLAN-graffito-quantum-key.md) is now tried
            // against this device's own personal quantum key, if one is
            // stored: KEM-only unlocks automatically (view-only — nothing
            // persisted, matching every other self-pq unlock); KEM+FLAG_PW
            // still needs the typed password too, so it falls through to
            // the normal password field with the stored key supplied
            // alongside it at Unlock (`on_unlock_note`). No device key, or
            // a present key that doesn't decrypt (e.g. after a Replace),
            // falls back to an honest caption — never the directed
            // "sealed to the recipient's key" message (there IS no
            // recipient).
            let locked = n.locked.is_some();
            let is_self_locked = n.locked.as_ref().map(pq::LockedBody::is_self).unwrap_or(false);
            let sender_cannot_reopen = locked
                && !is_self_locked
                && n.from.is_none()
                && n.pq_flags & notes_core::envelope::FLAG_MLKEM != 0;
            let self_kem_locked =
                locked && is_self_locked && n.pq_flags & notes_core::envelope::FLAG_MLKEM != 0;
            let self_kem_also_pw =
                self_kem_locked && n.pq_flags & notes_core::envelope::FLAG_PW != 0;
            let mut kem_auto_text: Option<String> = None;
            let mut kem_key_present = false;
            let mut kem_key_wrong = false;
            if self_kem_locked {
                if let Some(kp) = device_quantum_key(&fs, &device_pq_key) {
                    kem_key_present = true;
                    if !self_kem_also_pw {
                        if let (Some(locked_body), Some(ident)) =
                            (n.locked.as_ref(), identity.borrow().as_ref())
                        {
                            match pq::unlock_self(
                                locked_body,
                                &ident.enc_key,
                                Some(&kp.secret()),
                                None,
                            ) {
                                Ok(bytes) => {
                                    // Log-contract line for the UI suite
                                    // (graffito-selfpq.sh): the auto-unlock
                                    // is otherwise invisible to log greps.
                                    log::info!("cb: unlock-note auto=kem ok");
                                    kem_auto_text = Some(String::from_utf8_lossy(&bytes).to_string())
                                }
                                Err(_) => {
                                    log::warn!("cb: unlock-note auto=kem err=mismatch");
                                    kem_key_wrong = true;
                                }
                            }
                        }
                    }
                }
            }
            let needs_password = (locked
                && !sender_cannot_reopen
                && !self_kem_locked
                && n.pq_flags & notes_core::envelope::FLAG_PW != 0)
                || (self_kem_also_pw && kem_key_present);
            view.set_locked(locked && kem_auto_text.is_none());
            view.set_needs_password(needs_password);
            view.set_lock_caption(
                if sender_cannot_reopen {
                    "Can't re-read this note — it's sealed to the recipient's key."
                } else if self_kem_locked && (kem_auto_text.is_some() || needs_password) {
                    ""
                } else if self_kem_locked && kem_key_wrong {
                    "This note's quantum key doesn't match the one stored on this device."
                } else if self_kem_locked {
                    "Locked with a quantum key this device doesn't hold."
                } else if locked && !needs_password {
                    "Sealed to a quantum key this device doesn't hold."
                } else {
                    ""
                }
                .into(),
            );
            if let Some(text) = &kem_auto_text {
                view.set_text(text.clone().into());
            }
            view.set_unlock_password("".into());
            view.set_unlock_error("".into());

            // Reply / Reply-all: a small local equivalent of notes-core's
            // `bundle::reply_set` operating on the persisted `NoteRec`
            // (plain display/UX logic, not a notes-core FROZEN invariant —
            // deliberately not routed through notes-core, which only has
            // the heavier `RecoveredNote` shape). `full_set` = {from} ∪
            // recipients minus my own address, deduped, sender-first.
            let my_address = identity.borrow().as_ref().map(|id| id.address(st.network()));
            let mut full_set: Vec<String> = Vec::new();
            let mut push_addr = |addr: &str, out: &mut Vec<String>| {
                if Some(addr) != my_address.as_deref() && !out.iter().any(|a| a == addr) {
                    out.push(addr.to_string());
                }
            };
            if let Some(from) = &n.from {
                push_addr(from, &mut full_set);
            }
            if !n.recipients.is_empty() {
                for r in &n.recipients {
                    push_addr(r, &mut full_set);
                }
            } else if let Some(to) = &n.to {
                push_addr(to, &mut full_set);
            }
            // Received note: Reply is ALWAYS addressed to the sender,
            // regardless of full_set's size. Own note: Reply is addressed
            // to the sole other party only when there is exactly one — 2+
            // hides Reply in favor of Reply-all (never both for an own
            // note). A pure self-note (full_set empty) shows neither.
            let reply_address = if let Some(from) = &n.from {
                from.clone()
            } else if full_set.len() == 1 {
                full_set[0].clone()
            } else {
                String::new()
            };
            view.set_reply_address(reply_address.into());
            let full_set_shared: Vec<SharedString> =
                full_set.iter().map(SharedString::from).collect();
            view.set_reply_set(Rc::new(VecModel::from(full_set_shared)).into());

            log::info!(
                "cb: open-note id={} status={}{} qr={}",
                n.id,
                n.status,
                n.from.as_deref().map(|f| format!(" from={f}")).unwrap_or_default(),
                view.get_has_qr()
            );
            ui.global::<Ui>().set_screen(2);
        });
    }

    // Manual unlock of a locked pq note (FLAG_PW) — the note view's
    // Unlock button. A self-locked body (`LockedBody::is_self`,
    // PLAN-graffito-self-pw.md) always goes through `unlock_self` — the
    // author holds the enc key it was sealed under, so there's no
    // received-vs-sent split the way a directed body has. Otherwise: a
    // received note tries every derived ML-KEM secret of the ACTIVE
    // notebook alongside the typed password (covers a combined
    // FLAG_MLKEM|FLAG_PW note, which `extract_notes_pq` never auto-tries);
    // an own (sent) DIRECTED note goes through `unlock_sent` instead —
    // already filtered to FLAG_PW-alone by `on_open_note`'s
    // `needs_password` gate, so `unlock_sent`'s `SenderCannotReopen` is
    // never actually reachable from here.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let identity = identity.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let device_pq_key = device_pq_key.clone();
        ui.global::<Callbacks>().on_unlock_note(move |password| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let id_str = ui.global::<View>().get_id().to_string();
            let mut st = state.borrow_mut();
            let Some(n) = st.notes.iter_mut().find(|n| n.id == id_str) else { return };
            let Some(locked) = n.locked.clone() else { return };
            let id_guard = identity.borrow();
            let Some(ident) = id_guard.as_ref() else {
                log::warn!("cb: unlock-note err=identity-unavailable");
                return;
            };
            let pw = password.to_string();
            let pw_opt = if pw.is_empty() { None } else { Some(pw.as_str()) };
            let is_self = locked.is_self();
            let result: Result<Vec<u8>, notes_core::Error> = if is_self {
                // PLAN-graffito-quantum-key.md: a self body carrying
                // FLAG_MLKEM only reaches here (needs_password set by
                // `on_open_note`) when it ALSO carries FLAG_PW and the
                // device key is present — KEM-only self bodies are tried
                // automatically on open and never show the Unlock button.
                let mlkem_secret = if locked.pq_flags & notes_core::envelope::FLAG_MLKEM != 0 {
                    device_quantum_key(&fs, &device_pq_key).map(|kp| kp.secret())
                } else {
                    None
                };
                pq::unlock_self(&locked, &ident.enc_key, mlkem_secret.as_ref(), pw_opt)
            } else {
                let received = n.from.is_some();
                if received {
                    if locked.pq_flags & notes_core::envelope::FLAG_MLKEM != 0 {
                        let ix = notebooks.borrow();
                        let net_s = net.borrow().clone();
                        let leaf = (*active.borrow())
                            .and_then(|acc| ix.get(acc))
                            .and_then(|meta| derive_leaf_secret(app_seed_get(&app_seed), meta, &net_s));
                        drop(ix);
                        let mut last = notes_core::Error::DecryptFailed;
                        let mut ok: Option<Vec<u8>> = None;
                        if let Some(leaf) = leaf {
                            for kp in derive_mlkem_keypairs(&leaf) {
                                let secret = kp.secret();
                                match pq::unlock_received(&locked, &ident.tweaked_seckey, Some(&secret), pw_opt)
                                {
                                    Ok(pt) => {
                                        ok = Some(pt);
                                        break;
                                    }
                                    Err(e) => last = e,
                                }
                            }
                        }
                        ok.ok_or(last)
                    } else {
                        pq::unlock_received(&locked, &ident.tweaked_seckey, None, pw_opt)
                    }
                } else {
                    pq::unlock_sent(&locked, &ident.tweaked_seckey, &ident.output_x, pw_opt)
                }
            };
            drop(id_guard);
            match result {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    // Self-pw unlock is VIEW-ONLY (PLAN-graffito-self-pw.md):
                    // the plaintext is shown for THIS viewing only —
                    // `n.text`/`n.locked` in the persisted store are left
                    // untouched, so re-opening the note (or a fresh boot)
                    // asks for the password again. A directed note's
                    // unlock keeps its existing fill-and-clear semantics.
                    if !is_self {
                        n.text = text.clone();
                        n.locked = None;
                        save_state(&fs, &st);
                    }
                    log::info!("cb: unlock-note ok");
                    drop(st);
                    let view = ui.global::<View>();
                    view.set_text(text.into());
                    view.set_locked(false);
                    view.set_needs_password(false);
                    view.set_lock_caption("".into());
                    view.set_unlock_error("".into());
                    view.set_unlock_password("".into());
                }
                Err(e) => {
                    log::warn!("cb: unlock-note err={e}");
                    ui.global::<View>().set_unlock_error(format!("{e}").into());
                }
            }
        });
    }

    // Reply: fresh compose draft addressed to View.reply-address. Routed
    // through the SAME `pick_contact` funnel a manual pick uses (contact
    // name resolution, recency bump, funding/change reset, → screen 3) —
    // it already clears Compose.to-extra on its replace path, so a stale
    // extra-recipient list from a previous draft can't leak in.
    {
        let ui_weak = ui_weak.clone();
        let pick_contact = pick_contact.clone();
        ui.global::<Callbacks>().on_reply_to_note(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let addr = ui.global::<View>().get_reply_address().to_string();
            if addr.is_empty() {
                return;
            }
            pick_contact(&addr);
        });
    }

    // Reply-all: primary = the first address in View.reply-set (via the
    // same `pick_contact` funnel, which also resets to-extra), every
    // remaining address pushed directly onto Compose.to-extra — NOT
    // re-run through `pick_contact` (that would re-reset funding/change
    // and re-navigate on every entry).
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let pick_contact = pick_contact.clone();
        ui.global::<Callbacks>().on_reply_all_to_note(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let set: Vec<String> =
                ui.global::<View>().get_reply_set().iter().map(|s| s.to_string()).collect();
            let Some((first, rest)) = set.split_first() else { return };
            pick_contact(first);
            let st = state.borrow();
            let extra: Vec<ToRow> = rest
                .iter()
                .map(|a| ToRow { address: a.as_str().into(), label: to_label_for(&st, a).into() })
                .collect();
            drop(st);
            ui.global::<Compose>().set_to_extra(Rc::new(VecModel::from(extra)).into());
        });
    }

    // Shared by file import AND camera scan: parse + merge a bundle,
    // logging `cb: import-bundle {src} … ok` (src keeps the file=/loc=
    // shape the UI tests grep).
    let apply_bundle: Rc<dyn Fn(&str, &str) -> Result<String, String>> = {
        let state = state.clone();
        let identity = identity.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        Rc::new(move |json: &str, src: &str| -> Result<String, String> {
            let id_guard = identity.borrow();
            let id = id_guard.as_ref().ok_or("identity unavailable")?;
            {
                let bundle =
                    SyncBundle::from_json(json).map_err(|e| format!("bad bundle: {e}"))?;
                let mut st = state.borrow_mut();
                if !bundle.network.is_empty() && bundle.network != st.network {
                    return Err(format!(
                        "bundle is for {}, app is on {} — switch network first",
                        bundle.network, st.network
                    ));
                }

                // Spending-unification: the self-spk SET is the notebook's
                // own spk plus every address the spending wallet has issued
                // (`SpendingSection.self_spks`) — extends OWN detection to
                // funded/mixed-source notes (extract_notes_multi_deduped ORs
                // with the producer's spends_from_self, never narrows).
                let ix = notebooks.borrow();
                let ctx = notebook_ctx(&ix, *active.borrow())
                    .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
                let net_s = net.borrow().clone();
                let section = ix.spending(&net_s, ctx.0, ctx.1).cloned();
                // DISPLAY-OWNER dedup anchor set (device CLAUDE.md): every
                // VISIBLE (non-archived) notebook's own spk in the active
                // wallet context, derived ONCE per import — never per tx —
                // by reusing the same per-notebook identity derivation
                // `confirm_self_spks` already does for the confirm screen.
                // Archived notebooks are excluded by `visible()`, so an
                // archived notebook's input can never suppress a note in an
                // active one.
                let notebook_spks = wallet_notebook_spks(&ix, app_seed_get(&app_seed), &net_s, ctx);
                // Post-quantum auto-unlock candidates: the ACTIVE notebook's
                // three derived ML-KEM receive secrets (512/768/1024) — the
                // only notebook whose received notes this scan could ever
                // be decrypting (the scan itself is already scoped to `id`,
                // this notebook's Identity). Empty when the leaf secret
                // isn't derivable (device locked) — `extract_notes_pq` with
                // no candidates behaves exactly like the pre-pq extraction,
                // just leaving every pq note `locked`.
                let mlkem_secrets: Vec<pq::MlKemSecret> =
                    (*active.borrow()).and_then(|acc| ix.get(acc)).and_then(|meta| {
                        derive_leaf_secret(app_seed_get(&app_seed), meta, &net_s)
                    }).map(|leaf| {
                        derive_mlkem_keypairs(&leaf).into_iter().map(|kp| kp.secret()).collect()
                    }).unwrap_or_default();
                drop(ix);
                let notebook_addr = id.address(st.network());
                let self_spks: Vec<Vec<u8>> = {
                    let mut v = vec![p2tr_script_pubkey(&id.output_x)];
                    if let Some(s) = &section {
                        v.extend(s.self_spks());
                    }
                    v
                };

                let recovered = extract_notes_pq(
                    &bundle,
                    id,
                    st.network(),
                    &self_spks,
                    &notebook_spks,
                    &mlkem_secrets,
                );
                let mut new_notes = 0usize;
                let mut received_notes = 0usize;
                for r in &recovered {
                    let id_hex = r.id.clone();
                    if r.received {
                        received_notes += 1;
                    }
                    // Merge keyed by (id, from): a received note can never
                    // overwrite an own note sharing its id (its txid).
                    match st
                        .notes
                        .iter_mut()
                        .find(|n| n.id == id_hex && n.from.as_deref() == r.sender.as_deref())
                    {
                        Some(existing) => {
                            existing.height = r.height.or(existing.height);
                            existing.blocktime = r.blocktime.or(existing.blocktime);
                            if existing.height.is_some() {
                                existing.status = "confirmed".into();
                            }
                        }
                        None => {
                            new_notes += 1;
                            st.notes.push(NoteRec {
                                id: id_hex.clone(),
                                text: r.text.clone().unwrap_or_else(|| {
                                    if r.pq_flags != 0 {
                                        "(locked — unlock to read)".into()
                                    } else if r.received {
                                        "(directed note — could not decrypt)".into()
                                    } else {
                                        "(sealed under another key)".into()
                                    }
                                }),
                                private: r.private,
                                txid: id_hex,
                                raw_hex: String::new(),
                                fee: 0,
                                vsize: 0,
                                chunks: 0,
                                height: r.height,
                                blocktime: r.blocktime,
                                status: if r.height.is_some() {
                                    "confirmed".into()
                                } else {
                                    "pending".into()
                                },
                                directed: r.directed,
                                to: r.recipient.clone(),
                                from: r.sender.clone(),
                                recipients: r.recipients.clone(),
                                pq_flags: r.pq_flags,
                                locked: r.locked.clone(),
                            });
                        }
                    }
                }

                // Split the bundle's UTXOs by owner: no `owner_address` (or
                // one matching the notebook's own address) is a notebook
                // coin; an address matching a KNOWN spending-wallet `used`
                // entry routes to the spending ledger (tagged with its
                // chain/index so signing can re-derive the key). A coin at
                // an owner address the device hasn't recorded as used yet
                // is GAP-ADOPTED below (funding-unification device-port
                // fix, 2026-07-19) rather than dropped.
                //
                // Gap-adoption: the device has no chain access to probe
                // blindly like the graffito desktop app's discover_spending() does,
                // so instead it derives the bounded candidate set — both
                // chains, `next_receive`/`next_change` .. +SPENDING_ADOPT_GAP
                // (= 20, same constant the app's gap scan uses) — and
                // compares each candidate's address against the coin's own
                // owner_address. A match is exactly the kind of address the
                // device would have marked `used` had it ever revealed or
                // spent it, so it's ADOPTED: `mark_used` (idempotent,
                // advances the index past it) and the coin is kept instead
                // of dropped. Cheap and exact — each index's address is
                // unique, so no false positives are possible.
                //
                // Companion gap-discovery, option (b) (2026-07-19): the
                // device also exports a lookahead WATCH WINDOW (next 20
                // receive + next 20 change addresses, Settings' spending
                // card) so the companion can probe addresses it hasn't seen
                // a coin at yet. The companion reports back every window
                // address with ANY on-chain history — coin or not — as
                // `bundle.owner_used`; those resolve through the exact same
                // gap window below and get adopted even with no live coin.
                // This is the convergence piece: a restore whose early
                // addresses are used-but-spent-empty must still advance past
                // them, or the device would forever re-offer an already-
                // spent address as "next receive".
                const SPENDING_ADOPT_GAP: u32 = 20;
                let net_v = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
                let mut nb_utxos: Vec<UtxoRec> = Vec::new();
                let mut sp_utxos: Vec<spending::SpendingUtxo> = Vec::new();
                let mut newly_used: Vec<spending::SpendingAddress> = Vec::new();
                let mut next_recv = section.as_ref().map(|s| s.next_receive).unwrap_or(0);
                let mut next_chg = section.as_ref().map(|s| s.next_change).unwrap_or(0);

                // Shared gap derive-and-compare resolver (companion gap-
                // discovery option (b), 2026-07-19): given ANY owner-tagged
                // address — whether it came with a live coin or just a bare
                // "this address has history" marker — find it among already-
                // known `used` entries (persisted from a prior import, or
                // adopted earlier in THIS SAME import via `newly_used`, which
                // a pre-loop `section` clone can't see) or by deriving the
                // bounded candidate window ahead of next_receive/next_change.
                // A match is exactly the kind of address the device would
                // have marked `used` had it ever revealed or spent it, so
                // it's adopted: `next_recv`/`next_chg` advance past it and it
                // is queued in `newly_used` for `mark_used` below. Returns
                // `(address, true)` only the FIRST time an address resolves
                // via derivation this import — callers use that to log
                // exactly once per genuine adoption, never on repeat lookups
                // (e.g. a second coin at the same already-adopted address).
                let mut resolve_owner = |a: &str| -> Option<(spending::SpendingAddress, bool)> {
                    let already_known = section
                        .as_ref()
                        .and_then(|s| s.used.iter().find(|x| x.address == a).cloned())
                        .or_else(|| newly_used.iter().find(|x| x.address == a).cloned());
                    if let Some(addr) = already_known {
                        return Some((addr, false));
                    }
                    // `app_seed_get` hands back a concrete `&Option<[u8; 32]>`,
                    // so `.as_ref()` is unambiguously `Option::as_ref` here.
                    let Some(seed) = app_seed_get(&app_seed).as_ref() else { return None };
                    let mut found_addr: Option<spending::SpendingAddress> = None;
                    'gap: for chain in [0u32, 1u32] {
                        let base = if chain == 0 { next_recv } else { next_chg };
                        for index in base..base.saturating_add(SPENDING_ADOPT_GAP) {
                            if let Ok(key) = notes_core::seeds::derive_spending_key(
                                seed, ctx.0, net_v, ctx.1, chain, index,
                            ) {
                                if key.address == a {
                                    found_addr = Some(spending::SpendingAddress {
                                        chain,
                                        index,
                                        address: key.address.clone(),
                                        spk_hex: hex::encode(&key.script_pubkey),
                                    });
                                    break 'gap;
                                }
                            }
                        }
                    }
                    if let Some(addr) = &found_addr {
                        if addr.chain == 0 {
                            next_recv = next_recv.max(addr.index + 1);
                        } else {
                            next_chg = next_chg.max(addr.index + 1);
                        }
                        newly_used.push(addr.clone());
                    }
                    found_addr.map(|addr| (addr, true))
                };

                // 1) Used-only markers FIRST — every watch-window address the
                // companion found ANY history for, coin or not. This must run
                // BEFORE the coin loop below so a coin at a later index
                // benefits from the advanced next_recv/next_chg window in the
                // SAME import: a restore whose early addresses are used-but-
                // spent-empty must still converge past them to reach a later
                // real coin, not get stuck re-deriving from index 0 forever.
                for a in &bundle.owner_used {
                    if a == &notebook_addr {
                        continue; // the notebook identity is a separate address space
                    }
                    if let Some((addr, is_new)) = resolve_owner(a) {
                        if is_new {
                            log::info!(
                                "cb: spending-adopt chain={} index={} used-only",
                                addr.chain, addr.index
                            );
                        }
                    }
                    // else: still unknown beyond the gap — nothing to advance.
                }

                // 2) Coins — log line shape UNCHANGED from before this
                // companion gap-discovery extension (today's e2e greps it).
                for u in &bundle.utxos {
                    match &u.owner_address {
                        None => {
                            nb_utxos.push(UtxoRec { txid: u.txid.clone(), vout: u.vout, value: u.value })
                        }
                        Some(a) if *a == notebook_addr => {
                            nb_utxos.push(UtxoRec { txid: u.txid.clone(), vout: u.vout, value: u.value })
                        }
                        Some(a) => {
                            if let Some((addr, is_new)) = resolve_owner(a) {
                                if is_new {
                                    log::info!(
                                        "cb: spending-adopt chain={} index={}",
                                        addr.chain, addr.index
                                    );
                                }
                                sp_utxos.push(spending::SpendingUtxo {
                                    txid: u.txid.clone(),
                                    vout: u.vout,
                                    value: u.value,
                                    chain: addr.chain,
                                    index: addr.index,
                                });
                            }
                            // else: still unknown beyond the gap — dropped, unchanged.
                        }
                    }
                }
                st.utxos = nb_utxos;
                if section.is_some() || !newly_used.is_empty() {
                    let mut ix = notebooks.borrow_mut();
                    let sec = ix.spending_mut(&net_s, ctx.0, ctx.1);
                    for addr in newly_used {
                        sec.mark_used(addr);
                    }
                    sec.set_utxos(sp_utxos);
                    save_notebooks(&fs, &ix);
                }
                st.tip_height = Some(bundle.tip_height);
                st.bundle_time = Some(bundle.bundle_time);
                // Chunk size is a pure device setting — any relay-policy
                // field in the bundle is deliberately ignored.
                if bundle.fee_rates.economy > 0.0 {
                    st.fee_economy = bundle.fee_rates.economy;
                }
                if bundle.fee_rates.half_hour > 0.0 {
                    st.fee_normal = bundle.fee_rates.half_hour;
                }
                if bundle.fee_rates.fastest > 0.0 {
                    st.fee_fast = bundle.fee_rates.fastest;
                }
                st.btc_usd = bundle.btc_usd.or(st.btc_usd);
                save_state(&fs, &st);

                log::info!(
                    "cb: import-bundle {src} notes={} new={new_notes} received={received_notes} utxos={} tip={} ok",
                    recovered.len(),
                    st.utxos.len(),
                    bundle.tip_height
                );
                Ok(format!(
                    "Imported ({src}): {} note(s) ({new_notes} new), {} utxo(s), height {}.",
                    recovered.len(),
                    st.utxos.len(),
                    bundle.tip_height
                ))
            }
        })
    };

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let refresh_home = refresh_home.clone();
        let apply_bundle = apply_bundle.clone();
        ui.global::<Callbacks>().on_import_bundle(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let result = (|| -> Result<String, String> {
                let (name, loc, loc_label) =
                    first_inbox_bundle(&fs).ok_or("no .json bundle in /graffito/inbox")?;
                let json = read_text(&fs, &format!("{INBOX_DIR}/{name}"), loc)?;
                if loc == Location::Airlock {
                    unmount_airlock(&fs);
                }
                apply_bundle(&json, &format!("file={name} loc={loc_label}"))
            })();
            match result {
                Ok(msg) => {
                    ui.global::<Sync>().set_result(msg.into());
                    ui.global::<Ui>().set_error("".into());
                }
                Err(e) => {
                    log::warn!("cb: import-bundle err={e}");
                    ui.global::<Sync>().set_result(e.into());
                }
            }
            refresh_home();
        });
    }

    // Import picker: list the bundle files actually present in the inboxes
    // so the user chooses one, instead of silently auto-picking the first.
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_list_bundles(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let sync = ui.global::<Sync>();
            let found = list_inbox_bundles(&fs);
            let rows: Vec<BundleRow> = found
                .iter()
                .map(|(name, loc, _)| {
                    let (loc_name, loc_idx) = if *loc == Location::Airlock {
                        ("Airlock", 1)
                    } else {
                        ("Internal", 0)
                    };
                    BundleRow {
                        name: name.clone().into(),
                        label: format!("{name}  ·  {loc_name}").into(),
                        loc: loc_idx,
                    }
                })
                .collect();
            sync.set_bundles(Rc::new(VecModel::from(rows)).into());
            sync.set_empty_hint(
                "No bundle files found. Put a .json bundle in /graffito/inbox on Internal (or the Airlock volume), then tap Refresh — or use \"Scan bundle\" to import by QR from the companion.".into(),
            );
            sync.set_picking(true);
            log::info!("cb: list-bundles n={}", found.len());
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let refresh_home = refresh_home.clone();
        let apply_bundle = apply_bundle.clone();
        ui.global::<Callbacks>().on_pick_bundle(move |name, loc_idx| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let loc = if loc_idx == 1 { Location::Airlock } else { Location::User };
            let result = (|| -> Result<String, String> {
                if loc == Location::Airlock {
                    ensure_airlock_mounted(&fs)?;
                }
                let json = read_text(&fs, &format!("{INBOX_DIR}/{name}"), loc);
                if loc == Location::Airlock {
                    unmount_airlock(&fs);
                }
                let loc_label = if loc == Location::Airlock { "airlock" } else { "internal" };
                apply_bundle(&json?, &format!("file={name} loc={loc_label}"))
            })();
            let sync = ui.global::<Sync>();
            sync.set_picking(false);
            match result {
                Ok(msg) => {
                    sync.set_result(msg.into());
                    ui.global::<Ui>().set_error("".into());
                }
                Err(e) => {
                    log::warn!("cb: pick-bundle err={e}");
                    sync.set_result(e.into());
                }
            }
            refresh_home();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let refresh_home = refresh_home.clone();
        let apply_bundle = apply_bundle.clone();
        ui.global::<Callbacks>().on_scan_bundle(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let opts = ScanQrOptions {
                header_title: "Scan sync bundle".into(),
                message: "Point at the companion's bundle QR (static or animated)".into(),
                ..ScanQrOptions::default()
            };
            // Blocks while the system scanner modal owns the screen; it
            // reassembles animated UR sequences itself (foundation-ur).
            let (kind, data) = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr { data, .. })) => ("qr", data),
                Ok(Some(ScanQrResult::Ur2 { ur_type, data, .. })) => {
                    log::info!("cb: scan-bundle ur-type={ur_type}");
                    ("ur", data)
                }
                Ok(_) => {
                    log::info!("cb: scan-bundle cancelled");
                    return;
                }
                Err(e) => {
                    log::warn!("cb: scan-bundle err=scanner {e:?}");
                    ui.global::<Sync>()
                        .set_result(format!("QR scanner unavailable: {e:?}").into());
                    return;
                }
            };
            log::info!("cb: scan-bundle kind={kind} bytes={}", data.len());
            let result = decode_scanned(&data)
                .map_err(|e| e.to_string())
                .and_then(|json| apply_bundle(&json, &format!("src=scan-{kind}")));
            match result {
                Ok(msg) => {
                    ui.global::<Sync>().set_result(msg.into());
                    ui.global::<Ui>().set_error("".into());
                }
                Err(e) => {
                    log::warn!("cb: scan-bundle err={e}");
                    ui.global::<Sync>().set_result(format!("Scan failed: {e}").into());
                }
            }
            refresh_home();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_export_pending(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let pending: Vec<&NoteRec> = st
                .notes
                .iter()
                .filter(|n| n.status == "pending" && !n.raw_hex.is_empty())
                .collect();
            let mut written = 0usize;
            let airlock_ok = ensure_airlock_mounted(&fs).is_ok();
            for n in &pending {
                let file = format!("{OUTBOX_DIR}/{}.hex", n.txid);
                if ensure_dir(&fs, OUTBOX_DIR, Location::User)
                    .and_then(|_| write_file(&fs, &file, Location::User, n.raw_hex.as_bytes()))
                    .is_ok()
                {
                    written += 1;
                }
                if airlock_ok {
                    let _ = ensure_dir(&fs, OUTBOX_DIR, Location::Airlock).and_then(|_| {
                        write_file(&fs, &file, Location::Airlock, n.raw_hex.as_bytes())
                    });
                }
            }
            if airlock_ok {
                unmount_airlock(&fs);
            }
            log::info!(
                "cb: export-pending n={written} airlock={}",
                if airlock_ok { "ok" } else { "err" }
            );
            ui.global::<Sync>()
                .set_result(format!("Exported {written} pending tx(s) to {OUTBOX_DIR}.").into());
        });
    }

    // Sign an external transaction (PSBT) — stage A: scan it, validate it
    // pays THIS device's taproot address, and show the universal confirm
    // gate (screen 4) built from the UNSIGNED tx's own bytes + each input's
    // witness_utxo. The actual signing (+ outbox export) is stage B, in the
    // confirm-sign dispatcher below — nothing about a scanned PSBT touches
    // disk until the user taps Sign.
    {
        let ui_weak = ui_weak.clone();
        let identity = identity.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let app_seed = app_seed.clone();
        let psbt_pending = psbt_pending.clone();
        ui.global::<Callbacks>().on_sign_psbt(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let id_guard = identity.borrow();
            let Some(id) = id_guard.as_ref() else {
                ui.global::<Sync>().set_result("Device locked — no signing key.".into());
                return;
            };
            let opts = ScanQrOptions {
                header_title: "Scan transaction".into(),
                message: "Point at the desktop app's PSBT QR".into(),
                ..ScanQrOptions::default()
            };
            let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr { data: d, .. })) | Ok(Some(ScanQrResult::Ur2 { data: d, .. })) => d,
                Ok(_) => {
                    log::info!("cb: sign-psbt cancelled");
                    return;
                }
                Err(e) => {
                    log::warn!("cb: sign-psbt err=scanner {e:?}");
                    ui.global::<Sync>().set_result(format!("QR scanner unavailable: {e:?}").into());
                    return;
                }
            };
            let bytes = normalize_psbt_bytes(&data);
            let psbt = match notes_core::psbt::Psbt::deserialize(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("cb: sign-psbt err={e}");
                    ui.global::<Sync>().set_result(format!("Not a PSBT: {e}").into());
                    return;
                }
            };
            let our_spk = p2tr_script_pubkey(&id.output_x);
            let ours = psbt
                .inputs
                .iter()
                .filter(|i| {
                    i.witness_utxo.as_ref().map(|w| w.script_pubkey == our_spk).unwrap_or(false)
                })
                .count();
            if ours == 0 {
                ui.global::<Sync>()
                    .set_result("No inputs belong to this device's address.".into());
                return;
            }

            let net_dev = net.borrow().clone();
            let mut network = Network::from_str_opt(&net_dev).unwrap_or(Network::Mainnet);
            let wallet_ctx = (*seed_idx.borrow(), *bip_account.borrow());
            let ix = notebooks.borrow();
            let (self_spks, spending_spks) = confirm_self_spks(&ix, app_seed_get(&app_seed), &net_dev, wallet_ctx);
            drop(ix);

            // Port B (network-display fix, 2026-07-19): a PSBT's
            // scriptPubKeys carry NO network/HRP information at all — HRP
            // is purely an address-ENCODING artifact, never part of the
            // wire format — so rendering every address below with the
            // DEVICE's current network setting is wrong whenever this PSBT
            // was built for a different chain (it will show the right
            // bytes with the wrong prefix). The only honest signal
            // available at this call site is a BIP32 derivation path
            // attached to one of OUR OWN recognized inputs (an external
            // tool that imported this device's `export.rs` account
            // descriptor would naturally embed one) — its hardened
            // coin-type level (`seeds::coin_type`: 0' mainnet, else 1')
            // reflects what that tool believed the network to be. Only
            // inputs already proven ours (`witness_utxo.script_pubkey ==
            // our_spk`) are consulted; a foreign/external-funding input's
            // derivation convention is none of this device's business.
            // coin-type 1' can't distinguish testnet4/signet/regtest from
            // one another (this crate's own `coin_type()` doesn't either),
            // but testnet4 and signet already share the "tb" HRP here, so
            // `Testnet4` is the right display for the overwhelming
            // majority of that bucket; a real external tool handing a
            // REGTEST PSBT to a physical device is not a scenario this
            // display-only fix needs to get byte-perfect. No derivation
            // signal at all (the common case today) changes nothing —
            // this only ever ADDS information on top of the existing
            // device-network fallback, never removes it, and it can never
            // affect signing/validation/tx bytes (display only).
            let device_network_label = network.as_str();
            let mut coin_types: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
            for (i, inp) in psbt.inputs.iter().enumerate() {
                let is_ours = inp.witness_utxo.as_ref().map(|w| w.script_pubkey == our_spk).unwrap_or(false);
                if !is_ours {
                    continue;
                }
                if let Some(ct) = psbt.input_derivation_coin_type(i) {
                    coin_types.insert(ct);
                }
            }
            let mut network_warn: Option<String> = None;
            if let [only] = coin_types.iter().collect::<Vec<_>>()[..] {
                let derived_mainnet = *only == 0;
                let device_mainnet = network == Network::Mainnet;
                if derived_mainnet != device_mainnet {
                    let derived_label = if derived_mainnet { "mainnet" } else { "a test network" };
                    network_warn = Some(format!(
                        "this transaction's key derivation indicates {derived_label}, but the device is set to {device_network_label} - addresses below use the derived network's encoding"
                    ));
                    network = if derived_mainnet { Network::Mainnet } else { Network::Testnet4 };
                }
            }

            let mut prevouts: BTreeMap<String, notes_core::confirm::PrevoutInfo> = BTreeMap::new();
            for (i, txin) in psbt.unsigned_tx.inputs.iter().enumerate() {
                let Some(wu) = psbt.inputs.get(i).and_then(|p| p.witness_utxo.as_ref()) else {
                    continue;
                };
                let mut t = txin.txid;
                t.reverse();
                let is_ours = wu.script_pubkey == our_spk;
                let address = notes_core::address::address_from_spk(&wu.script_pubkey, network);
                let source =
                    if is_ours { "This notebook".to_string() } else { "External funding".to_string() };
                prevouts.insert(
                    format!("{}:{}", hex::encode(t), txin.vout),
                    notes_core::confirm::PrevoutInfo { value: wu.value, address, source },
                );
            }
            let note_preview = confirm_note_preview(&psbt.unsigned_tx.outputs);

            let cctx = notes_core::confirm::ConfirmCtx {
                network,
                prevouts,
                self_spks,
                spending_spks,
                expected_change: None,
                recipient: None,
                recipient_name: None,
                recipients: Vec::new(),
                note_preview,
            };
            let raw_hex = hex::encode(psbt.unsigned_tx.serialize_legacy());
            drop(id_guard);

            match show_confirm_screen(&ui, "psbt", &raw_hex, &cctx, "External funding tx".to_string(), "Sign & export") {
                Ok(()) => {
                    if let Some(msg) = &network_warn {
                        log::info!("cb: confirm network-mismatch derived={}", network.as_str());
                        let cs = ui.global::<ConfirmSign>();
                        let existing = cs.get_warn().to_string();
                        cs.set_warn(
                            if existing.is_empty() { msg.clone().into() } else { format!("{existing}; {msg}").into() },
                        );
                    }
                    *psbt_pending.borrow_mut() = Some(psbt);
                }
                Err(e) => {
                    log::warn!("cb: confirm summarize err={e}");
                    ui.global::<Sync>().set_result(format!("Cannot show confirm: {e}").into());
                }
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let fs = fs.clone();
        let net = net.clone();
        let active = active.clone();
        let device_chunk = device_chunk.clone();
        let notebooks = notebooks.clone();
        let app_seed = app_seed.clone();
        let persist_config = persist_config.clone();
        let refresh_home = refresh_home.clone();
        let refresh_notes = refresh_notes.clone();
        let refresh_coins = refresh_coins.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        ui.global::<Callbacks>().on_cycle_network(move || {
            // Network is device-level (wallet-wide): flush the active
            // notebook, cycle the shared network, persist it in config, and
            // reload the active notebook's ledger for the new chain (each
            // notebook keeps a per-network ledger in state-<net>-<account>).
            if active.borrow().is_some() {
                save_state(&fs, &state.borrow());
            }
            let next = match net.borrow().as_str() {
                "mainnet" => "testnet4",
                "testnet4" => "signet",
                "signet" => "regtest",
                _ => "mainnet",
            }
            .to_string();
            *net.borrow_mut() = next.clone();
            persist_config();
            log::info!("cb: set-network {next}");
            if let Some(account) = *active.borrow() {
                let mut fresh = load_state(&fs, &next, account);
                fresh.chunk_override = *device_chunk.borrow();
                *state.borrow_mut() = fresh;
                // Legacy identities are network-independent (only the
                // address ENCODING changes), but bip86 notebooks use the
                // BIP-44 coin type — their keys differ per network, so
                // always re-derive from the meta.
                if let Some(m) = notebooks.borrow().get(account) {
                    *identity.borrow_mut() = derive_identity(app_seed_get(&app_seed), m, &next);
                }
            }
            let _ = &ui_weak;
            refresh_home();
            refresh_notes();
            refresh_coins();
            refresh_notebooks();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let device_chunk = device_chunk.clone();
        let persist_config = persist_config.clone();
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_chunk_changed(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let settings = ui.global::<Settings>();
            let mut st = state.borrow_mut();
            match settings.get_chunk_mode() {
                0 => st.chunk_override = None,
                1 => st.chunk_override = Some(80),
                _ => {
                    match settings.get_chunk_text().trim().parse::<usize>() {
                        Ok(n) if (MIN_CHUNK..=DEFAULT_CHUNK).contains(&n) => {
                            st.chunk_override = Some(n);
                        }
                        _ => {
                            let msg = format!(
                                "Chunk size must be {MIN_CHUNK}–{DEFAULT_CHUNK} bytes."
                            );
                            log::warn!("cb: set-chunk-size err={msg}");
                            settings.set_chunk_error(msg.into());
                            // Leave the user's text in place to fix.
                            return;
                        }
                    }
                }
            }
            log::info!(
                "cb: set-chunk-size {} ok",
                st.chunk_override.map(|n| n.to_string()).unwrap_or("auto".into())
            );
            settings.set_chunk_error("".into());
            save_state(&fs, &st);
            // Chunk is device-level (wallet-wide): persist it in config too.
            *device_chunk.borrow_mut() = st.chunk_override;
            persist_config();
            drop(st);
            // Reflect the effective size back into the field (auto/compat),
            // without touching a valid custom value.
            refresh_home();
            // Re-price the draft immediately so the compose cost line is
            // already current when the user returns to it.
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }

    // Transaction locktime (anti-fee-sniping). Wallet-level like the chunk
    // size, so it lives in config.json rather than any notebook's state.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let lock_policy = lock_policy.clone();
        let persist_config = persist_config.clone();
        ui.global::<Callbacks>().on_locktime_changed(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let settings = ui.global::<Settings>();
            let policy = match settings.get_locktime_mode() {
                0 => LockTimePolicy::Tip,
                1 => LockTimePolicy::Zero,
                _ => match settings.get_locktime_text().trim().parse::<u32>() {
                    // A height at or above 500_000_000 is read by consensus
                    // as a UNIX timestamp, which is never what someone
                    // typing a block height means — reject it here rather
                    // than silently build an unspendable-until-2035 tx.
                    Ok(h) if h < 500_000_000 => LockTimePolicy::Custom { height: h },
                    _ => {
                        let msg = "Locktime must be a block height below 500000000.".to_string();
                        log::warn!("cb: set-locktime err={msg}");
                        settings.set_locktime_error(msg.into());
                        // Leave the user's text in place to fix.
                        return;
                    }
                },
            };
            *lock_policy.borrow_mut() = policy;
            persist_config();
            settings.set_locktime_error("".into());
            let tip = state.borrow().tip_height;
            let effective = resolve_locktime(policy, tip);
            settings.set_locktime_effective(locktime_caption(policy, tip).into());
            log::info!("cb: set-locktime {} effective={effective} ok", policy.as_str());
        });
    }

    // Compose "too large" dialog → raise the chunk size to Standard (auto) and
    // reprice the draft in place. Only offered when the note fits at Standard.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_oversize_bump(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            {
                let mut st = state.borrow_mut();
                st.chunk_override = None; // Standard / auto = DEFAULT_CHUNK
                save_state(&fs, &st);
            }
            log::info!("cb: set-chunk-size auto ok (oversize-bump)");
            let compose = ui.global::<Compose>();
            compose.set_show_oversize(false);
            ui.global::<Settings>().set_chunk_mode(0); // mirror into the settings pill
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }

    {
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_refresh_home(move || refresh_home());
    }
    {
        let refresh_notes = refresh_notes.clone();
        ui.global::<Callbacks>().on_refresh_notes(move || refresh_notes());
    }
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let refresh_notes = refresh_notes.clone();
        ui.global::<Callbacks>().on_toggle_sender(move |key, excluded| {
            let Some(_ui) = ui_weak.upgrade() else { return };
            {
                let mut st = state.borrow_mut();
                st.set_excluded(key.as_str(), excluded);
                save_state(&fs, &st);
                log::info!(
                    "cb: toggle-sender excluded={excluded} hidden={}",
                    st.excluded_senders.len()
                );
            }
            refresh_notes();
        });
    }
    {
        let refresh_contacts = refresh_contacts.clone();
        ui.global::<Callbacks>().on_refresh_contacts(move || refresh_contacts());
    }

    // ---- notebook callbacks (screen 20 list) ----
    {
        let switch_notebook = switch_notebook.clone();
        ui.global::<NotebookCb>().on_open(move |account| switch_notebook(account.max(0) as u32));
    }
    {
        // Create: open the name dialog in create mode (-2). Nothing is
        // derived/persisted until Save — the device create is name-only
        // (no address picker: no network on-device to probe used/new).
        let ui_weak = ui_weak.clone();
        ui.global::<NotebookCb>().on_create(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let nb = ui.global::<NotebooksUi>();
            nb.set_name_text("".into());
            nb.set_name_account(-2);
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let notebooks = notebooks.clone();
        ui.global::<NotebookCb>().on_rename(move |account| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let nb = ui.global::<NotebooksUi>();
            // Prefill the RAW local name (the display name may be an addr
            // short form, which must not become a name by accident).
            let raw = notebooks
                .borrow()
                .get(account.max(0) as u32)
                .map(|m| m.name.clone())
                .unwrap_or_default();
            nb.set_name_text(raw.into());
            nb.set_name_account(account);
        });
    }
    {
        let ui_weak = ui_weak.clone();
        ui.global::<NotebookCb>().on_name_cancel(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.global::<NotebooksUi>().set_name_account(-1);
            }
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        let switch_notebook = switch_notebook.clone();
        ui.global::<NotebookCb>().on_name_save(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let nb = ui.global::<NotebooksUi>();
            let sel = nb.get_name_account();
            if sel == -1 {
                return;
            }
            let name = nb.get_name_text().trim().to_string();
            nb.set_name_account(-1);
            nb.set_name_text("".into());
            if sel == -2 {
                // CREATE: a bip86 notebook at the next unused receive
                // index of the active (seed, account) context — the
                // recovery-seeds scheme, words-recoverable anywhere.
                // (Legacy notebooks are never created anymore.)
                if app_seed_get(&app_seed).is_none() {
                    ui.global::<Ui>().set_error("Device locked — can't create a notebook.".into());
                    return;
                }
                let (seed, bacct) = (*seed_idx.borrow(), *bip_account.borrow());
                let account = {
                    let mut ix = notebooks.borrow_mut();
                    let account = ix.create_bip86(seed, bacct, &name);
                    save_notebooks(&fs, &ix);
                    account
                };
                let index = notebooks.borrow().get(account).map(|m| m.index).unwrap_or(0);
                log::info!(
                    "cb: create-notebook account={account} scheme=bip86 seed={seed} bip-account={bacct} index={index}"
                );
                refresh_notebooks();
                switch_notebook(account);
            } else {
                let account = sel as u32;
                {
                    let mut ix = notebooks.borrow_mut();
                    ix.rename(account, &name);
                    save_notebooks(&fs, &ix);
                }
                log::info!("cb: rename-notebook account={account}");
                refresh_notebooks();
                // If it's the open notebook, update its home title.
                if *active.borrow() == Some(account) {
                    let title = notebooks
                        .borrow()
                        .get(account)
                        .map(|m| m.name.clone())
                        .filter(|n| !n.trim().is_empty());
                    if let Some(t) = title {
                        nb.set_title(t.into());
                    }
                }
            }
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        ui.global::<NotebookCb>().on_archive(move |account, archived| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let account = account.max(0) as u32;
            if archived {
                // Guard: a notebook with coins must be emptied first
                // (sweep/consolidate). Zero active notebooks is allowed.
                let bal = load_state(&fs, &net.borrow(), account).balance();
                if bal > 0 {
                    ui.global::<Ui>()
                        .set_error(format!("This notebook holds {bal} sats — empty it first.").into());
                    return;
                }
            }
            {
                let mut ix = notebooks.borrow_mut();
                ix.set_archived(account, archived);
                save_notebooks(&fs, &ix);
            }
            log::info!("cb: archive-notebook account={account} archived={archived}");
            refresh_notebooks();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let state = state.clone();
        let active = active.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        ui.global::<NotebookCb>().on_back_to_list(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if active.borrow().is_some() {
                save_state(&fs, &state.borrow());
            }
            refresh_notebooks();
            ui.global::<Ui>().set_screen(20);
        });
    }

    // ---- recovery seeds (screen 21 + wallet context) ----

    // Derive the ACTIVE seed's 24 words + SeedQR into the Recovery props.
    // Everything is re-derived on demand and lives only in UI properties
    // until reveal-close wipes them; nothing is persisted or logged. Shared
    // by the reveal button AND the Switch action (which refreshes the words
    // to the new seed while they're shown). Keeps the SeedQR in sync.
    let reveal_words: Rc<dyn Fn()> = {
        let ui_weak = ui_weak.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        Rc::new(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let recovery = ui.global::<Recovery>();
            let index = *seed_idx.borrow();
            let Some(seed) = app_seed_get(&app_seed).as_ref() else {
                ui.global::<Ui>().set_error("Device locked — seed unavailable.".into());
                log::warn!("cb: reveal-seed index={index} err=locked");
                return;
            };
            let entropy = notes_core::keys::derive_seed_entropy(seed, index);
            let words = match notes_core::bip39::entropy_to_mnemonic(&entropy) {
                Ok(w) => w,
                Err(e) => {
                    ui.global::<Ui>().set_error(format!("Derivation failed: {e}").into());
                    log::warn!("cb: reveal-seed index={index} err={e}");
                    return;
                }
            };
            let list: Vec<&str> = words.split_whitespace().collect();
            let col = |range: std::ops::Range<usize>| -> String {
                range
                    .map(|i| format!("{:2}. {}", i + 1, list[i]))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            recovery.set_words_col1(col(0..12).into());
            recovery.set_words_col2(col(12..24).into());
            // Standard SeedQR: the 4-digit wordlist indices, concatenated.
            let digits: String = notes_core::bip39::entropy_to_indices(&entropy)
                .unwrap_or_default()
                .iter()
                .map(|i| format!("{i:04}"))
                .collect();
            recovery.set_qr(qr_image(&digits));
            recovery.set_show_qr(false);
            recovery.set_title_line(format!("Seed {index} · 24 words").into());
            log::info!("cb: reveal-seed index={index} ok");
        })
    };
    {
        let reveal_words = reveal_words.clone();
        ui.global::<Callbacks>().on_reveal_seed(move || reveal_words());
    }
    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_reveal_close(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let recovery = ui.global::<Recovery>();
            recovery.set_words_col1("".into());
            recovery.set_words_col2("".into());
            recovery.set_title_line("".into());
            recovery.set_qr(Image::default());
            recovery.set_show_qr(false);
            log::info!("cb: reveal-seed cancelled");
        });
    }
    // ---- export keys (screen 23) ----
    // Reveal the active (seed, account) context's importable formats:
    // account xpub + tr() descriptor cover the WHOLE account (all
    // addresses); hex + WIF are one notebook's leaf, picked from the
    // notebook list. No private xprv on the device (the 24 words recover
    // the whole seed). Values live in UI props only, wiped on close;
    // never logged.
    let apply_export: Rc<dyn Fn(i32)> = {
        let ui_weak = ui_weak.clone();
        Rc::new(move |which: i32| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            let nb = r.get_export_nb_name();
            let (label, value): (String, _) = match which {
                0 => {
                    ("Account xpub · all addresses · watch-only".to_string(), r.get_export_xpub())
                }
                1 => (
                    "Descriptor (tr) · all addresses · watch-only".to_string(),
                    r.get_export_descriptor(),
                ),
                2 => (format!("Notebook \"{nb}\" · hex"), r.get_export_hex()),
                _ => (format!("Notebook \"{nb}\" · WIF"), r.get_export_wif()),
            };
            r.set_export_which(which);
            r.set_export_label(label.into());
            r.set_export_value(value.clone());
            r.set_export_qr(qr_image(value.as_str()));
        })
    };
    // The active account's notebooks as picker rows (index/name/short addr)
    // plus the default selection (first notebook, else a synthetic index 0).
    let export_rows: Rc<dyn Fn(u32, u32, &str, Network) -> (Vec<ExportNbRow>, i32, String)> = {
        let app_seed = app_seed.clone();
        let notebooks = notebooks.clone();
        Rc::new(move |si: u32, acct: u32, net_s: &str, network: Network| {
            let mut rows: Vec<ExportNbRow> = Vec::new();
            let ixb = notebooks.borrow();
            for m in ixb.visible(si, acct) {
                let addr = derive_identity(app_seed_get(&app_seed), m, net_s)
                    .map(|id| id.address(network))
                    .unwrap_or_default();
                let short = short_addr(&addr);
                let name = if m.name.trim().is_empty() {
                    notebooks::default_name(m.index)
                } else {
                    m.name.clone()
                };
                rows.push(ExportNbRow {
                    index: m.index as i32,
                    name: name.into(),
                    addr: short.into(),
                });
            }
            let (sel, sel_name) = rows
                .first()
                .map(|r0| (r0.index, r0.name.to_string()))
                .unwrap_or((0, "index 0".to_string()));
            if rows.is_empty() {
                rows.push(ExportNbRow { index: 0, name: "index 0".into(), addr: "".into() });
            }
            (rows, sel, sel_name)
        })
    };
    {
        let ui_weak = ui_weak.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let net = net.clone();
        let apply_export = apply_export.clone();
        let export_rows = export_rows.clone();
        ui.global::<Callbacks>().on_reveal_public(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            let si = *seed_idx.borrow();
            let acct = *bip_account.borrow();
            let Some(seed) = app_seed_get(&app_seed).as_ref() else {
                ui.global::<Ui>().set_error("Device locked — seed unavailable.".into());
                log::warn!("cb: reveal-public seed={si} account={acct} err=locked");
                return;
            };
            let network = Network::from_str_opt(&net.borrow()).unwrap_or(Network::Mainnet);
            let derived = (|| -> Result<(), notes_core::Error> {
                r.set_export_xpub(notes_core::export::account_xpub(seed, si, network, acct)?.into());
                r.set_export_descriptor(
                    notes_core::export::account_descriptor(seed, si, network, acct)?.into(),
                );
                Ok(())
            })();
            if let Err(e) = derived {
                ui.global::<Ui>().set_error(format!("Export failed: {e}").into());
                log::warn!("cb: reveal-public seed={si} account={acct} err={e}");
                return;
            }
            r.set_export_seed_view(false);
            r.set_export_title(export_title(seed, si, acct).into());
            apply_export(0);
            log::info!("cb: reveal-public seed={si} account={acct} ok");
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let net = net.clone();
        let apply_export = apply_export.clone();
        let export_rows = export_rows.clone();
        let reveal_words = reveal_words.clone();
        ui.global::<Callbacks>().on_reveal_private(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            let si = *seed_idx.borrow();
            let acct = *bip_account.borrow();
            let Some(seed) = app_seed_get(&app_seed).as_ref() else {
                ui.global::<Ui>().set_error("Device locked — seed unavailable.".into());
                log::warn!("cb: reveal-private seed={si} account={acct} err=locked");
                return;
            };
            let net_s = net.borrow().clone();
            let network = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
            let (rows, sel, sel_name) = export_rows(si, acct, &net_s, network);
            let derived = (|| -> Result<(), notes_core::Error> {
                let (hex, wif) = export_leaf_formats(seed, si, network, acct, sel as u32)?;
                r.set_export_hex(hex.into());
                r.set_export_wif(wif.into());
                Ok(())
            })();
            if let Err(e) = derived {
                ui.global::<Ui>().set_error(format!("Export failed: {e}").into());
                log::warn!("cb: reveal-private seed={si} account={acct} err={e}");
                return;
            }
            r.set_export_notebooks(Rc::new(VecModel::from(rows)).into());
            r.set_export_nb_index(sel);
            r.set_export_nb_name(sel_name.into());
            // The 24 words (whole seed) into words-col1/2 + SeedQR.
            reveal_words();
            r.set_export_title(export_title(seed, si, acct).into());
            r.set_export_seed_view(true); // default to the seed-words view
            apply_export(2); // pre-load the hex value/QR for a quick pill switch
            log::info!("cb: reveal-private seed={si} account={acct} ok");
        });
    }
    {
        let apply_export = apply_export.clone();
        ui.global::<Callbacks>().on_export_select(move |which| apply_export(which));
    }
    {
        // Pick which notebook's private key hex/WIF export (hex/WIF only).
        let ui_weak = ui_weak.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let net = net.clone();
        let notebooks = notebooks.clone();
        let apply_export = apply_export.clone();
        ui.global::<Callbacks>().on_export_pick_notebook(move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            let si = *seed_idx.borrow();
            let acct = *bip_account.borrow();
            let Some(seed) = app_seed_get(&app_seed).as_ref() else { return };
            let net_s = net.borrow().clone();
            let network = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
            let name = {
                let ixb = notebooks.borrow();
                let n = ixb
                    .visible(si, acct)
                    .find(|m| m.index as i32 == index)
                    .map(|m| {
                        if m.name.trim().is_empty() {
                            notebooks::default_name(m.index)
                        } else {
                            m.name.clone()
                        }
                    })
                    .unwrap_or_else(|| format!("index {index}"));
                n
            };
            r.set_export_nb_index(index);
            r.set_export_nb_name(name.into());
            if let Ok((hex, wif)) = export_leaf_formats(seed, si, network, acct, index as u32) {
                r.set_export_hex(hex.into());
                r.set_export_wif(wif.into());
            }
            let which = r.get_export_which();
            if which >= 2 {
                apply_export(which);
            }
        });
    }
    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_export_close(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            r.set_export_xpub("".into());
            r.set_export_descriptor("".into());
            r.set_export_hex("".into());
            r.set_export_wif("".into());
            r.set_export_value("".into());
            r.set_export_label("".into());
            r.set_export_title("".into());
            r.set_export_qr(Image::default());
            r.set_export_which(0);
            r.set_export_notebooks(Rc::new(VecModel::from(Vec::<ExportNbRow>::new())).into());
            r.set_export_nb_index(0);
            r.set_export_nb_name("".into());
            // Also wipe the seed-words view (shared with reveal-seed props).
            r.set_export_seed_view(false);
            r.set_words_col1("".into());
            r.set_words_col2("".into());
            r.set_title_line("".into());
            r.set_qr(Image::default());
            r.set_show_qr(false);
            log::info!("cb: reveal-export cancelled");
        });
    }
    {
        // Commit the wallet context (seed index + BIP-86 account) from the
        // Recovery fields, then STAY on the Recovery screen (Sal 2026-07-12
        // — Switch used to jump to the list): persist, flush the open
        // notebook, refresh the list underneath so it's ready when the user
        // navigates back themselves, re-derive the revealed words/SeedQR for
        // the new seed, and show an inline saved confirmation.
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let state = state.clone();
        let active = active.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let persist_config = persist_config.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        let reveal_words = reveal_words.clone();
        ui.global::<Callbacks>().on_set_context(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let recovery = ui.global::<Recovery>();
            let parse = |s: &str| -> Option<u32> {
                s.trim().parse::<u32>().ok().filter(|n| *n <= 9999)
            };
            let (Some(new_seed), Some(new_acct)) = (
                parse(recovery.get_seed_text().as_str()),
                parse(recovery.get_account_text().as_str()),
            ) else {
                recovery.set_saved_msg("".into());
                recovery.set_context_error("Seed and account must be 0–9999.".into());
                return;
            };
            recovery.set_context_error("".into());
            let seed_changed = *seed_idx.borrow() != new_seed;
            let acct_changed = *bip_account.borrow() != new_acct;
            if seed_changed || acct_changed {
                if active.borrow().is_some() {
                    save_state(&fs, &state.borrow());
                    *active.borrow_mut() = None;
                }
                *seed_idx.borrow_mut() = new_seed;
                *bip_account.borrow_mut() = new_acct;
                persist_config();
                if seed_changed {
                    log::info!("cb: set-seed-index {new_seed}");
                }
                if acct_changed {
                    log::info!("cb: set-account {new_acct}");
                }
                // Rebuild the (now background) notebook list for the new
                // context, and refresh the revealed words to the new seed.
                refresh_notebooks();
                if !recovery.get_words_col1().is_empty() {
                    reveal_words();
                }
            }
            recovery.set_saved_msg(
                format!("Saved · seed {new_seed} · account {new_acct}").into(),
            );
        });
    }

    // Boot: the notebook list is the main screen. Migrate/seed the index,
    // then land on the list (a fresh install starts empty). Seed/account
    // fields mirror the persisted wallet context.
    //
    // NOTHING here may read the app seed: `GetAppSeed` prompts on SDK 1.0.0
    // and the prompt cannot be answered until `ui.run()` is pumping, so a read
    // on this path hangs the app at launch (see `app_seed_get`). The list is
    // therefore painted seed-free first — rows render without their addresses
    // — and the timer below primes the seed once the loop is live, then
    // repaints the list with them.
    ui.global::<Recovery>().set_seed_text(format!("{}", *seed_idx.borrow()).into());
    ui.global::<Recovery>().set_account_text(format!("{}", *bip_account.borrow()).into());
    ui.global::<Ui>().set_screen(20);

    let boot_seed = {
        let ui_weak = ui_weak.clone();
        let app_seed = app_seed.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            // First read of the seed in the app's life: this is what raises
            // the one-time "App-scoped seed" consent prompt, and the running
            // loop is what lets the user answer it.
            let available = app_seed_get(&app_seed).is_some();
            ui.global::<Recovery>().set_seed_available(available);
            if !available {
                ui.global::<Ui>().set_error("Device locked or seed unavailable".into());
            }
            // Repaint: the rows drawn before the seed existed have no address.
            refresh_notebooks();
        }
    };
    // A frame's grace so the list is on screen behind the consent prompt,
    // rather than the prompt appearing over a blank window.
    Timer::single_shot(Duration::from_millis(150), boot_seed);

    ui.run().expect("UI running");
}

/// A single QR (v40, alphanumeric via uppercase hex) holds ~4000 chars —
/// plenty for any normal note tx. Larger txs fall back to file export
/// (animated multi-part UR is future work, with the bundle-in leg).
const MAX_QR_HEX_CHARS: usize = 4000;

fn set_view_qr(view: &View<'_>, n: &NoteRec) {
    let eligible =
        n.status == "pending" && !n.raw_hex.is_empty() && n.raw_hex.len() <= MAX_QR_HEX_CHARS;
    view.set_has_qr(eligible);
    if eligible {
        view.set_qr(qr_image(&n.raw_hex.to_uppercase()));
    }
}

fn qr_image(payload: &str) -> Image {
    qrcode::render(
        payload.as_bytes(),
        Color::from_rgb_u8(0, 0, 0),
        Color::from_rgb_u8(255, 255, 255),
    )
}

/// Raw PSBT bytes from a scanned payload: the system scanner reassembles a
/// crypto-psbt UR into raw bytes; a plain QR may instead carry a hex string.
fn normalize_psbt_bytes(data: &[u8]) -> Vec<u8> {
    if data.starts_with(b"psbt\xff") {
        return data.to_vec();
    }
    // A spec crypto-psbt UR message wraps the PSBT in a CBOR byte string
    // (BCR-2020-006) — what Sparrow, our desktop app, and the KeyOS scanner
    // hand back. Unwrap it.
    if let Some(inner) = cbor_unwrap_bstr(data) {
        if inner.starts_with(b"psbt\xff") {
            return inner;
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(b) = hex::decode(s.trim()) {
            if b.starts_with(b"psbt\xff") {
                return b;
            }
        }
    }
    data.to_vec()
}

/// Minimal CBOR byte-string unwrap (major type 2) — enough for crypto-psbt;
/// avoids a CBOR dependency on-device.
fn cbor_unwrap_bstr(data: &[u8]) -> Option<Vec<u8>> {
    let b0 = *data.first()?;
    let (len, hdr) = match b0 {
        0x40..=0x57 => ((b0 - 0x40) as usize, 1),
        0x58 => (*data.get(1)? as usize, 2),
        0x59 => (u16::from_be_bytes([*data.get(1)?, *data.get(2)?]) as usize, 3),
        0x5a => (
            u32::from_be_bytes([*data.get(1)?, *data.get(2)?, *data.get(3)?, *data.get(4)?]) as usize,
            5,
        ),
        _ => return None,
    };
    data.get(hdr..hdr + len).map(<[u8]>::to_vec)
}

/// Fee = sum(input amounts from witness_utxo) − sum(output amounts).
fn psbt_fee(p: &notes_core::psbt::Psbt) -> u64 {
    let ins: u64 = p.inputs.iter().filter_map(|i| i.witness_utxo.as_ref().map(|w| w.value)).sum();
    let outs: u64 = p.unsigned_tx.outputs.iter().map(|o| o.value).sum();
    ins.saturating_sub(outs)
}

/// A one-line note summary decoded from the PSBT's OP_RETURN output.
fn psbt_note_summary(p: &notes_core::psbt::Psbt) -> String {
    let payloads: Vec<Vec<u8>> = p
        .unsigned_tx
        .outputs
        .iter()
        .filter_map(|o| notes_core::tx::op_return_payload(&o.script_pubkey))
        .map(<[u8]>::to_vec)
        .collect();
    let Some(decoded) = notes_core::envelope::decode_note(&payloads) else {
        return "Note: (no note found)".into();
    };
    if decoded.is_private() {
        return "Note: encrypted".into();
    }
    match String::from_utf8(decoded.body) {
        Ok(t) => {
            let short: String = t.chars().take(40).collect();
            format!("Note: {short}")
        }
        Err(_) => "Note: (public)".into(),
    }
}
