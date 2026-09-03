mod notebooks;
mod screens;
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
use graffito_core::seclabel::{self, MlKemLevel, SecurityChoice, SelfNoteCopy};
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

/// Short display name ("ML-KEM-768") — the shared crate's `MlKemLevel::
/// name()`, byte-identical on every platform.
fn mlkem_alg_name(alg: pq::MlKemAlg) -> &'static str {
    MlKemLevel::from(alg).name()
}

/// Level-picker sentence — the shared crate's `MlKemLevel::describe()`,
/// so a contact importing a Prime device's exported key sees identical
/// copy in either app.
fn mlkem_alg_describe(alg: pq::MlKemAlg) -> &'static str {
    MlKemLevel::from(alg).describe()
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

/// Post-quantum status line for the compose Security section — the shared
/// policy in `graffito_core::seclabel` (PLAN-graffito-arch.md, phase 2),
/// rendered in this app's `Detailed` self-note flavor; the table is pinned
/// there in `tests/seclabel_table.rs`, this fn only maps the shell's state
/// onto it. Reachable from two shapes: a directed private single-recipient
/// draft (`directed == true`, both layers possible) and a private SELF-note
/// (`directed == false`, PLAN-graffito-self-pw.md for the passphrase layer;
/// PLAN-graffito-quantum-key.md for `mlkem_level`, which is `Some` on a
/// self-note ONLY when the device's personal quantum key is active for this
/// draft — a self-note never offers a seed-derived KEM, so `Some` here
/// always means the non-seed device key). `passphrase_verified` = the typed
/// text is byte-identical to the last `passphrase::generate()` output (the
/// ONLY way a passphrase counts toward quantum resistance — an unverified
/// typed/pasted phrase never does, however long); with no strength
/// estimator on the device, `SecurityChoice::without_estimator` is the
/// documented mapping of (active, verified) onto the shared inputs.
fn pq_security_label(
    private: bool,
    directed: bool,
    passphrase_active: bool,
    passphrase_verified: bool,
    mlkem_level: Option<pq::MlKemAlg>,
) -> String {
    seclabel::security_label(
        &SecurityChoice::without_estimator(
            private,
            directed,
            passphrase_active,
            passphrase_verified,
            mlkem_level.map(MlKemLevel::from),
        ),
        SelfNoteCopy::Detailed,
    )
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

/// The cached lookup over the cache FIELD alone, for callers that hold
/// another `App` field borrowed (state, identity) — field borrows are
/// disjoint, a `&mut self` method call is not.
pub(crate) fn device_quantum_key_in(
    cache: &mut Option<Option<pq::MlKemKeypair>>,
    fs: &Fs,
) -> Option<pq::MlKemKeypair> {
    if let Some(cached) = cache.as_ref() {
        return cached.clone();
    }
    let kp = load_device_quantum_key(fs);
    *cache = Some(kp.clone());
    kp
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
    ui.global::<Ui>().set_screen(Screen::ConfirmSign);
    Ok(())
}

// ---------------------------------------------------------------- main

/// The shell's live, non-persisted-as-such state (PLAN-graffito-arch.md
/// phase 4b): what `app_main` used to keep as ~15 ambient `Rc<RefCell<T>>`
/// locals, each callback cloning a dozen of them. One `Rc<RefCell<App>>`
/// handle now; per-notebook persisted state stays in [`State`].
///
/// Borrow discipline (the ONE runtime hazard of a `RefCell`): read fields
/// into locals at the top of a callback, write with a scoped
/// `app.borrow_mut().field = …`, never hold a `Ref`/`RefMut` across a call
/// into anything that may borrow `app` again — `Timer::single_shot`
/// bodies and nested closures are where that bites.
struct App {
    // ---- guard-held cells (kept as their own RefCell on purpose) --------
    // These four are borrowed as `let mut st = state.borrow_mut();` guards
    // held across other calls all over the callbacks. Keeping each behind
    // its own cell — reached as `let state = app.borrow().state.clone();`
    // at the top of a callback — preserves today's borrow granularity
    // exactly; flattening one into a plain field means restructuring
    // every callback that holds it, a per-field follow-up with the suite
    // board as the net.

    /// The app seed (GetAppSeed, PIN-gated on hardware) — kept so each
    /// notebook's identity can be derived on demand (`Identity::from_bip86`
    /// over the notebook's rotation seed + BIP-86 account/index). EMPTY
    /// until the boot timer primes it: the fetch prompts the user on SDK
    /// 1.0.0 (the app-scoped-seed sheet) and so cannot happen before the
    /// event loop runs — see `app_seed_get`.
    app_seed: OnceCell<Option<[u8; 32]>>,
    /// Notebooks: the index (account -> name/archived) persisted in
    /// `/.graffito/notebooks.json`. A notebook = an indexed identity; boot
    /// lands on the notebook LIST (empty on a fresh install — no onboarding).
    notebooks: notebooks::NotebookIndex,
    /// The ACTIVE notebook's persisted state (notes, UTXO ledger, fee
    /// tiers, contacts — `state-<net>-<account>.json`); an empty placeholder
    /// until a notebook is opened, swapped on notebook switch.
    state: State,
    /// The ACTIVE notebook's derived identity (keys + address), swapped
    /// with `state`; `None` on the list.
    identity: Option<Identity>,

    // ---- wallet-level config (persisted in config.json) ----------------
    /// Device-level network (wallet-wide; `"mainnet" | "testnet4" |
    /// "signet" | "regtest"`): one setting shared by every notebook — each
    /// notebook's ledger is per-network on disk (`state-<net>-<account>.json`).
    /// Persisted in `config.json` (`DeviceConfig.network`).
    net: String,
    /// The Settings chunk-size override (`None` = the DEFAULT_CHUNK relay
    /// default): purely device-side relay policy, copied into the active
    /// notebook's `State.chunk_override` on load so the compose cost line
    /// prices with it. Persisted (`DeviceConfig.chunk_override`).
    device_chunk: Option<usize>,
    /// Active wallet context (recovery seeds): the rotation seed index.
    /// New notebooks derive under (seed_idx, bip_account); the notebook list
    /// and every wallet-level feature scope to that pair. Persisted
    /// (`DeviceConfig.seed_index`).
    seed_idx: u32,
    /// Active wallet context: the BIP-86 account under `seed_idx`.
    /// Persisted (`DeviceConfig.account`).
    bip_account: u32,
    /// Anti-fee-sniping `nLockTime` policy (wallet-level, like network and
    /// chunk) — `Tip` by default, resolved against the last imported
    /// bundle's tip at build time. Persisted (`DeviceConfig.lock_time`).
    lock_policy: LockTimePolicy,
    /// Default ML-KEM level id (`pq::MlKemAlg::id()`) the Quantum-keys
    /// screen pre-selects. Persisted (`DeviceConfig.mlkem_level`).
    mlkem_level: u8,

    // ---- live session state (never persisted) ------------------------
    /// The ACTIVE notebook's BIP-86 account key — `None` on the notebook
    /// list (Screen.notebooks). Set when the user taps a row; cleared when
    /// the wallet context changes.
    active: Option<u32>,
    /// Quantum-keys screen: which notebook's ML-KEM key is shown — `None`
    /// until the picker is touched, meaning "active-or-first-visible" (the
    /// screen's original single-notebook default); `Some(index)` once the
    /// user picks a specific notebook from the picker.
    quantum_nb: Option<u32>,
    /// Personal device quantum key (PLAN-graffito-quantum-key.md,
    /// Screen.device-quantum-key): lazily loaded/cached — outer `None` =
    /// not looked up yet, `Some(None)` = looked up, no key on disk,
    /// `Some(Some(kp))` = loaded. NOT read at boot; the first touch is a
    /// screen open, a compose eligibility check, or an unlock attempt.
    device_pq_key: Option<Option<pq::MlKemKeypair>>,
    /// The compose Plan built by Continue and consumed by the confirm
    /// screen's Sign (`take()`n there) — the universal confirm gate keeps
    /// nothing committed until Sign.
    plan: Option<Plan>,
    /// Same for a sweep/consolidate in progress.
    sweep_plan: Option<SweepPlan>,
    /// External PSBT signing (funding-unification): the deserialized-but-
    /// UNSIGNED Psbt scanned in stage A (`on_sign_psbt`), stashed until the
    /// universal confirm screen's Sign tap actually signs it in stage B —
    /// nothing about it is persisted before then.
    psbt_pending: Option<notes_core::psbt::Psbt>,
    /// Post-quantum Security section (pq.rs): the exact text the last
    /// `passphrase::generate()` call produced — a typed passphrase counts
    /// toward quantum resistance ONLY while it's still byte-identical to
    /// this (any edit un-certifies it). `None` until Generate is tapped.
    pq_generated: Option<String>,
    /// Funding-unification: the per-coin funding pick for the compose in
    /// progress. Reset to the default rule whenever a fresh compose is
    /// entered (see `pick_contact`).
    funding_pick: FundingPick,
    /// The change-destination pick for the compose in progress (reset with
    /// `funding_pick`).
    change_pick: ChangePickState,
    /// Edge-tracks whether the compose draft is over the broadcast ceiling,
    /// so the "too large" dialog pops once on crossing — not on every
    /// keystroke.
    compose_oversize: bool,
}

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

/// One line per slint callback: clones the three shell handles and
/// forwards into an `App` method (or a money-path associated fn).
///
///   wire!(ui, app, ui_weak, fs; Callbacks.on_x(a, b) => app.borrow_mut().on_x(&ui_weak, &fs, a, b));
///
/// Every forwarder used to be a 4-6 line block of `let x = x.clone();`
/// preludes around the same closure (phase 4b); the clones are the whole
/// point, so they stay — just written once, here.
macro_rules! wire {
    ($ui:ident, $app:ident, $ui_weak:ident, $fs:ident; $global:ident . $cb:ident ( $($arg:ident),* ) => $($body:tt)*) => {{
        #[allow(unused_variables)]
        let $app = $app.clone();
        #[allow(unused_variables)]
        let $ui_weak = $ui_weak.clone();
        #[allow(unused_variables)]
        let $fs = $fs.clone();
        $ui.global::<$global>().$cb(move |$($arg),*| $($body)*);
    }};
}

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);

    let fs = cx.fs.clone();
    let ui_weak = ui.as_weak();

    // The app seed (GetAppSeed, PIN-gated on hardware) — kept so each
    // notebook's identity can be derived on demand (`Identity::from_bip86`
    // over the notebook's rotation seed + BIP-86 account/index).
    //
    // EMPTY here on purpose: the fetch prompts the user on SDK 1.0.0 and so
    // cannot happen before the event loop runs (see `app_seed_get`). The boot
    // timer at the end of `app_main` primes it.

    // Notebooks: the index (account -> name/archived) + the ACTIVE notebook.
    // A notebook = an indexed identity; boot lands on the notebook LIST and
    // the active notebook is set when the user taps a row (empty on a fresh
    // install — the device has no onboarding).
    let notebooks = boot_notebooks(&fs);
    // Device-level network (wallet-wide): one setting shared by every
    // notebook; each notebook's ledger is per-network on disk.
    let device_cfg = boot_config(&fs, &notebooks);
    // The named app state (PLAN-graffito-arch.md phase 4b) — ONE handle every
    // callback clones, instead of one `Rc<RefCell<T>>` per field. Borrow
    // discipline: read a field into a local (`let x = app.borrow().x;`),
    // write with a scoped `app.borrow_mut().x = …;`, and NEVER hold a borrow
    // across a call that may borrow again — a double borrow compiles clean
    // and panics at runtime.
    let app: Rc<RefCell<App>> = Rc::new(RefCell::new(App {
        app_seed: OnceCell::new(),
        notebooks,
        state: State::default(),
        identity: None,
        net: device_cfg.network.clone(),
        device_chunk: device_cfg.chunk_override,
        seed_idx: device_cfg.seed_index,
        bip_account: device_cfg.account,
        lock_policy: device_cfg.lock_time,
        mlkem_level: device_cfg.mlkem_level,
        active: None,
        quantum_nb: None,
        device_pq_key: None,
        plan: None,
        sweep_plan: None,
        psbt_pending: None,
        pq_generated: None,
        funding_pick: FundingPick::default(),
        change_pick: ChangePickState::default(),
        compose_oversize: false,
    }));

    // Persist the device config from the current cells (single source of
    // truth — inline DeviceConfig constructions drift as fields grow).

    // Coins screen (9): the UTXO ledger as of the last sync bundle, biggest
    // first. Viewer-first — consolidate is the screen's single action.

    // Sweep screen (10) repricing — every tier tap / rate keystroke. Pure
    // arithmetic (estimate_sweep_vsize is byte-exact vs build_sweep_tx).

    // Rebuild the Pay-from screen's rows/summaries, the compose nav row's
    // label, AND Settings' spending card (same underlying section) from
    // `state` + the active notebook's spending section + `funding_pick`.

    // Rebuild the compose nav row's Change label + the Change screen's
    // "Auto" sub-line from `change_pick` + whether the CURRENT funding pick
    // spends any spending-wallet coin.

    // A notebook's display name: its local name, else the 1-based default

    // Rebuild the notebook list (screen 20) from the index + each
    // notebook's state file. Device has no live balance — the row meta is
    // address-short · note count.

    // Open a notebook: save the current one, swap identity + state to the
    // target account, refresh every per-notebook view, and show its home.

    // The single pick funnel (self row / recent row / manual entry / scan):
    // validates, bumps recency, sets the compose recipient + label, and
    // navigates. Invalid manual input stays on the picker with an error.

    wire!(ui, app, ui_weak, fs; Callbacks.on_pick_contact(addr) => app.borrow_mut().pick_contact(&ui_weak, &fs, addr.as_str()));

    // Compose's "+ Add recipient" row — opens the contacts picker in
    // append mode (Contacts.picking-extra), modeled on how the home
    // screen's "Compose note" button opens it in replace mode.
    wire!(ui, app, ui_weak, fs; Callbacks.on_add_recipient_open() => app.borrow().on_add_recipient_open(&ui_weak));

    // Drop an address from Compose.to-extra — no navigation.
    wire!(ui, app, ui_weak, fs; Callbacks.on_remove_recipient(addr) => app.borrow().on_remove_recipient(&ui_weak, addr));

    wire!(ui, app, ui_weak, fs; Callbacks.on_scan_contact() => app.borrow_mut().on_scan_contact(&ui_weak, &fs));

    // Quantum key scan (naming modal "Scan quantum key"): armored
    // ML-KEM public key only — `pq::import_public` rejects anything else
    // with a clear message (a private-key armor, a note, an address QR).
    // Scoped to `Contacts.naming-address` (set when the modal opened), so
    // scanning does NOT require re-saving the name field.
    wire!(ui, app, ui_weak, fs; Callbacks.on_scan_contact_pq() => app.borrow_mut().on_scan_contact_pq(&ui_weak, &fs));

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

    wire!(ui, app, ui_weak, fs; Callbacks.on_open_quantum_keys() => app.borrow_mut().on_open_quantum_keys(&ui_weak));

    wire!(ui, app, ui_weak, fs; Callbacks.on_quantum_key_level(level_idx) => app.borrow_mut().on_quantum_key_level(&ui_weak, &fs, level_idx));

    wire!(ui, app, ui_weak, fs; Callbacks.on_quantum_key_pick_notebook(index) => app.borrow_mut().on_quantum_key_pick_notebook(&ui_weak, index));

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

    wire!(ui, app, ui_weak, fs; Callbacks.on_open_device_quantum_key() => app.borrow_mut().on_open_device_quantum_key(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_device_quantum_key_close() => app.borrow().on_device_quantum_key_close(&ui_weak));

    wire!(ui, app, ui_weak, fs; Callbacks.on_device_quantum_key_gen_level(level_idx) => app.borrow().on_device_quantum_key_gen_level(&ui_weak, level_idx));

    wire!(ui, app, ui_weak, fs; Callbacks.on_device_quantum_key_generate() => app.borrow_mut().on_device_quantum_key_generate(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_device_quantum_key_import() => app.borrow_mut().on_device_quantum_key_import(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_device_quantum_key_reveal_private() => app.borrow_mut().on_device_quantum_key_reveal_private(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_device_quantum_key_hide_private() => app.borrow().on_device_quantum_key_hide_private(&ui_weak));

    wire!(ui, app, ui_weak, fs; Callbacks.on_device_quantum_key_replace_confirm() => app.borrow_mut().on_device_quantum_key_replace_confirm(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_device_quantum_key_delete_confirm() => app.borrow_mut().on_device_quantum_key_delete_confirm(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_device_quantum_key_qr_zoom(open) => app.borrow().on_device_quantum_key_qr_zoom(open));

    wire!(ui, app, ui_weak, fs; Callbacks.on_save_contact_name() => app.borrow_mut().on_save_contact_name(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_refresh_coins() => app.borrow().refresh_coins(&ui_weak, &fs));

    // Coins → the shared sweep screen with kind=consolidate, dest=self.
    wire!(ui, app, ui_weak, fs; Callbacks.on_consolidate_open() => app.borrow().on_consolidate_open(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_sweep_changed() => app.borrow().update_sweep(&ui_weak, &fs));

    // Build + sign the sweep (ALL coins, key-path), then the confirm dialog.
    wire!(ui, app, ui_weak, fs; Callbacks.on_sweep_continue() => App::on_sweep_continue(&app, &ui_weak, &fs));

    // Spending wallet: Settings toggle.
    wire!(ui, app, ui_weak, fs; Callbacks.on_set_spending_enabled(on) => app.borrow_mut().on_set_spending_enabled(&ui_weak, &fs, on));

    // Pay-from screen (25): notebook / spending-wallet per-coin selection.
    wire!(ui, app, ui_weak, fs; Callbacks.on_funding_open() => app.borrow().on_funding_open(&ui_weak));
    wire!(ui, app, ui_weak, fs; Callbacks.on_funding_toggle_coin(key) => app.borrow_mut().on_funding_toggle_coin(&ui_weak, &fs, key));
    wire!(ui, app, ui_weak, fs; Callbacks.on_funding_done() => app.borrow().on_funding_done());

    // Change screen (26): compose destination for change.
    wire!(ui, app, ui_weak, fs; Callbacks.on_change_open() => app.borrow().on_change_open(&ui_weak));
    wire!(ui, app, ui_weak, fs; Callbacks.on_change_pick(choice) => app.borrow_mut().on_change_pick(&ui_weak, &fs, choice));
    wire!(ui, app, ui_weak, fs; Callbacks.on_change_address_changed() => app.borrow_mut().on_change_address_changed(&ui_weak, &fs));
    wire!(ui, app, ui_weak, fs; Callbacks.on_change_done() => app.borrow_mut().on_change_done(&ui_weak, &fs));

    // Keystroke cost estimator — pure arithmetic, no crypto runs (see
    // notes-core crypt::SEAL_OVERHEAD), so per-keystroke recompute is free.
    wire!(ui, app, ui_weak, fs; Callbacks.on_compose_changed() => app.borrow_mut().compose_changed(&ui_weak, &fs));

    // Post-quantum Security section: a typed edit un-certifies the
    // passphrase (compose-changed recomputes `pq-passphrase-verified`
    // from `pq_generated` vs. the current text) — this callback is just
    // the "recompute now" trigger `edited` fires, same shape as every
    // other compose field's `edited => { Callbacks.compose-changed(); }`.
    wire!(ui, app, ui_weak, fs; Callbacks.on_pq_passphrase_changed() => app.borrow_mut().on_pq_passphrase_changed(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_pq_generate_passphrase() => app.borrow_mut().on_pq_generate_passphrase(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_compose_continue() => App::on_compose_continue(&app, &ui_weak, &fs));

    // Universal Confirm & sign gate (screen 4) — dispatches on
    // ConfirmSign.kind to the three sign bodies (each was its own
    // dedicated callback before the confirm-gate refactor; merged here so
    // Sign always fires through one place, no callback-from-callback
    // re-entrancy). Ledger/outbox mutations happen ONLY past this point.
    wire!(ui, app, ui_weak, fs; Callbacks.on_confirm_sign() => App::on_confirm_sign(&app, &ui_weak, &fs));

    // Back from the universal Confirm & sign screen (4): discard whatever
    // was staged (Plan/SweepPlan/the stashed Psbt) and clear the shown
    // rows, then return to the kind's origin screen.
    wire!(ui, app, ui_weak, fs; Callbacks.on_confirm_cancel() => app.borrow_mut().on_confirm_cancel(&ui_weak));

    wire!(ui, app, ui_weak, fs; Callbacks.on_open_note(id) => app.borrow_mut().on_open_note(&ui_weak, &fs, id));

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
    wire!(ui, app, ui_weak, fs; Callbacks.on_unlock_note(password) => app.borrow_mut().on_unlock_note(&ui_weak, &fs, password));

    // Reply: fresh compose draft addressed to View.reply-address. Routed
    // through the SAME `pick_contact` funnel a manual pick uses (contact
    // name resolution, recency bump, funding/change reset, → screen 3) —
    // it already clears Compose.to-extra on its replace path, so a stale
    // extra-recipient list from a previous draft can't leak in.
    wire!(ui, app, ui_weak, fs; Callbacks.on_reply_to_note() => app.borrow_mut().on_reply_to_note(&ui_weak, &fs));

    // Reply-all: primary = the first address in View.reply-set (via the
    // same `pick_contact` funnel, which also resets to-extra), every
    // remaining address pushed directly onto Compose.to-extra — NOT
    // re-run through `pick_contact` (that would re-reset funding/change
    // and re-navigate on every entry).
    wire!(ui, app, ui_weak, fs; Callbacks.on_reply_all_to_note() => app.borrow_mut().on_reply_all_to_note(&ui_weak, &fs));

    // Shared by file import AND camera scan: parse + merge a bundle,
    // logging `cb: import-bundle {src} … ok` (src keeps the file=/loc=
    // shape the UI tests grep).

    wire!(ui, app, ui_weak, fs; Callbacks.on_import_bundle() => app.borrow_mut().on_import_bundle(&ui_weak, &fs));

    // Import picker: list the bundle files actually present in the inboxes
    // so the user chooses one, instead of silently auto-picking the first.
    wire!(ui, app, ui_weak, fs; Callbacks.on_list_bundles() => app.borrow().on_list_bundles(&ui_weak, &fs));
    wire!(ui, app, ui_weak, fs; Callbacks.on_pick_bundle(name, loc_idx) => app.borrow_mut().on_pick_bundle(&ui_weak, &fs, name, loc_idx));

    wire!(ui, app, ui_weak, fs; Callbacks.on_scan_bundle() => app.borrow_mut().on_scan_bundle(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_export_pending() => app.borrow().on_export_pending(&ui_weak, &fs));

    // Sign an external transaction (PSBT) — stage A: scan it, validate it
    // pays THIS device's taproot address, and show the universal confirm
    // gate (screen 4) built from the UNSIGNED tx's own bytes + each input's
    // witness_utxo. The actual signing (+ outbox export) is stage B, in the
    // confirm-sign dispatcher below — nothing about a scanned PSBT touches
    // disk until the user taps Sign.
    wire!(ui, app, ui_weak, fs; Callbacks.on_sign_psbt() => app.borrow_mut().on_sign_psbt(&ui_weak));

    wire!(ui, app, ui_weak, fs; Callbacks.on_cycle_network() => app.borrow_mut().on_cycle_network(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_chunk_changed() => app.borrow_mut().on_chunk_changed(&ui_weak, &fs));

    // Transaction locktime (anti-fee-sniping). Wallet-level like the chunk
    // size, so it lives in config.json rather than any notebook's state.
    wire!(ui, app, ui_weak, fs; Callbacks.on_locktime_changed() => app.borrow_mut().on_locktime_changed(&ui_weak, &fs));

    // Compose "too large" dialog → raise the chunk size to Standard (auto) and
    // reprice the draft in place. Only offered when the note fits at Standard.
    wire!(ui, app, ui_weak, fs; Callbacks.on_oversize_bump() => app.borrow_mut().on_oversize_bump(&ui_weak, &fs));

    wire!(ui, app, ui_weak, fs; Callbacks.on_refresh_home() => app.borrow().refresh_home(&ui_weak));
    wire!(ui, app, ui_weak, fs; Callbacks.on_refresh_notes() => app.borrow().refresh_notes(&ui_weak));
    wire!(ui, app, ui_weak, fs; Callbacks.on_toggle_sender(key, excluded) => app.borrow_mut().on_toggle_sender(&ui_weak, &fs, key, excluded));
    wire!(ui, app, ui_weak, fs; Callbacks.on_refresh_contacts() => app.borrow().refresh_contacts(&ui_weak));

    // ---- notebook callbacks (screen 20 list) ----
    wire!(ui, app, ui_weak, fs; NotebookCb.on_open(account) => app.borrow_mut().switch_notebook(&ui_weak, &fs, account.max(0) as u32));
    wire!(ui, app, ui_weak, fs; NotebookCb.on_create() => app.borrow().on_create(&ui_weak));
    wire!(ui, app, ui_weak, fs; NotebookCb.on_rename(account) => app.borrow().on_rename(&ui_weak, account));
    wire!(ui, app, ui_weak, fs; NotebookCb.on_name_cancel() => app.borrow().on_name_cancel(&ui_weak));
    wire!(ui, app, ui_weak, fs; NotebookCb.on_name_save() => app.borrow_mut().on_name_save(&ui_weak, &fs));
    wire!(ui, app, ui_weak, fs; NotebookCb.on_archive(account, archived) => app.borrow_mut().on_archive(&ui_weak, &fs, account, archived));
    wire!(ui, app, ui_weak, fs; NotebookCb.on_back_to_list() => app.borrow().on_back_to_list(&ui_weak, &fs));

    // ---- recovery seeds (screen 21 + wallet context) ----

    // Derive the ACTIVE seed's 24 words + SeedQR into the Recovery props.
    // Everything is re-derived on demand and lives only in UI properties
    // until reveal-close wipes them; nothing is persisted or logged. Shared
    // by the reveal button AND the Switch action (which refreshes the words
    // to the new seed while they're shown). Keeps the SeedQR in sync.
    wire!(ui, app, ui_weak, fs; Callbacks.on_reveal_seed() => app.borrow().reveal_words(&ui_weak));
    wire!(ui, app, ui_weak, fs; Callbacks.on_reveal_close() => app.borrow().on_reveal_close(&ui_weak));
    // ---- export keys (screen 23) ----
    // Reveal the active (seed, account) context's importable formats:
    // account xpub + tr() descriptor cover the WHOLE account (all
    // addresses); hex + WIF are one notebook's leaf, picked from the
    // notebook list. No private xprv on the device (the 24 words recover
    // the whole seed). Values live in UI props only, wiped on close;
    // never logged.
    // The active account's notebooks as picker rows (index/name/short addr)
    // plus the default selection (first notebook, else a synthetic index 0).
    wire!(ui, app, ui_weak, fs; Callbacks.on_reveal_public() => app.borrow().on_reveal_public(&ui_weak));
    wire!(ui, app, ui_weak, fs; Callbacks.on_reveal_private() => app.borrow().on_reveal_private(&ui_weak));
    wire!(ui, app, ui_weak, fs; Callbacks.on_export_select(which) => app.borrow().apply_export(&ui_weak, which));
    wire!(ui, app, ui_weak, fs; Callbacks.on_export_pick_notebook(index) => app.borrow().on_export_pick_notebook(&ui_weak, index));
    wire!(ui, app, ui_weak, fs; Callbacks.on_export_close() => app.borrow().on_export_close(&ui_weak));
    wire!(ui, app, ui_weak, fs; Callbacks.on_set_context() => app.borrow_mut().on_set_context(&ui_weak, &fs));

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
    ui.global::<Recovery>().set_seed_text(format!("{}", app.borrow().seed_idx).into());
    ui.global::<Recovery>().set_account_text(format!("{}", app.borrow().bip_account).into());
    ui.global::<Ui>().set_screen(Screen::Notebooks);

    // A frame's grace so the list is on screen behind the consent prompt,
    // rather than the prompt appearing over a blank window.
    Timer::single_shot(Duration::from_millis(150), {
        let app = app.clone();
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        move || app.borrow().boot_seed(&ui_weak, &fs)
    });

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
