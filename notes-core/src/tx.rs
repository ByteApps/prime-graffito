//! Minimal bitcoin transaction model: exactly what a note tx needs —
//! P2TR key-path inputs, OP_RETURN outputs, one P2TR change output.
//! Segwit (BIP144) serialization, txid, weight/vsize, fee estimation,
//! coin selection and end-to-end note-tx construction.

use crate::address::p2tr_script_pubkey;
use crate::keys::double_sha256;
use crate::sighash::taproot_key_spend_sighash;
use crate::sign::schnorr_sign;
use crate::{Error, DUST_LIMIT};

/// What `nLockTime` a newly built transaction carries.
///
/// Bitcoin Core, Electrum, Sparrow and BDK all default to setting
/// `nLockTime` to the current chain height ("anti-fee-sniping"): a miner
/// considering a re-org to steal a high-fee transaction cannot re-mine it
/// into an *earlier* block, because the transaction is not valid there.
/// Every input this crate builds already signals RBF (`0xfffffffd < 0xffffffff`),
/// which is what makes `nLockTime` enforced at all.
///
/// The secondary benefit is anonymity-set: a transaction with
/// `nLockTime == 0` is visibly not from a mainstream wallet.
///
/// This crate does NOT implement Core's extra 10%-of-the-time random
/// height in `[tip-100, tip]`. That would need randomness inside the
/// builders, making every build non-deterministic and every byte-exact
/// test pin need a seeded RNG — a poor trade for a marginal gain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum LockTimePolicy {
    /// Anti-fee-sniping: the last chain height we know about. This is the
    /// default and matches Core/BDK.
    ///
    /// The Prime device is offline, so its "last known" height comes from
    /// the most recently imported sync bundle and may be stale. A stale
    /// height is still perfectly valid — the transaction is simply already
    /// final — it just buys proportionally less anti-sniping protection.
    Tip,
    /// Always `0`: no locktime constraint. This crate's behavior before
    /// anti-fee-sniping existed, kept as an explicit opt-out.
    Zero,
    /// A caller-chosen absolute height. Values at or above 500_000_000 are
    /// interpreted by consensus as a UNIX timestamp rather than a height;
    /// that is the caller's choice and is passed through untouched.
    Custom { height: u32 },
}

impl Default for LockTimePolicy {
    fn default() -> Self {
        LockTimePolicy::Tip
    }
}

impl LockTimePolicy {
    /// The concrete `nLockTime` to build with. `tip` is the last chain
    /// height the caller knows (`None` when nothing has ever been synced),
    /// which only [`LockTimePolicy::Tip`] consults.
    ///
    /// A `Tip` policy with no known tip falls back to `0` rather than
    /// guessing a height: an `nLockTime` in the FUTURE would make the
    /// transaction non-final and get it rejected from the mempool, so
    /// under-shooting is the only safe direction to err.
    pub fn resolve(self, tip: Option<u32>) -> u32 {
        match self {
            LockTimePolicy::Tip => tip.unwrap_or(0),
            LockTimePolicy::Zero => 0,
            LockTimePolicy::Custom { height } => height,
        }
    }

    /// Stable identifier for config files, log lines and UI state.
    pub fn as_str(self) -> &'static str {
        match self {
            LockTimePolicy::Tip => "tip",
            LockTimePolicy::Zero => "zero",
            LockTimePolicy::Custom { .. } => "custom",
        }
    }
}

/// An unspent output of OUR notes address (all inputs are ours by
/// construction). `txid` is internal byte order (reversed display hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
}

/// `u`'s outpoint exactly as it appears on the wire: txid in
/// internal/little-endian order (already how [`Utxo::txid`] is stored) ||
/// vout as `u32`-LE — the directed-private AAD's `outpoint` field
/// (dm.rs, PLAN-pnte-redesign.md).
pub fn outpoint_bytes(u: &Utxo) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..32].copy_from_slice(&u.txid);
    out[32..].copy_from_slice(&u.vout.to_le_bytes());
    out
}

/// Select inputs for a note tx exactly the way [`build_note_tx_with_change`]
/// does (largest-first, growing the selection until a change output OR a
/// sub-dust no-change remainder is affordable) — but stop short of
/// building/signing. Exists so a caller that needs to know the tx's FIRST
/// input's outpoint BEFORE the OP_RETURN body can be produced (a
/// directed-private note's AAD binds the outpoint — dm.rs) can select
/// inputs, seal, then build the exact same tx via [`build_note_tx_exact`].
///
/// `payload_lens` and `recipient_spk_len` fully determine the fee/vsize
/// search — the actual OP_RETURN bytes never matter to selection, only
/// their lengths (true for any AEAD seal, since ciphertext length depends
/// only on plaintext length, never on AAD content) — so a caller may pass
/// lengths computed from a body it hasn't sealed yet, as long as the body
/// it eventually seals has the identical length (guaranteed for XChaCha20-
/// Poly1305: `crypt::SEAL_OVERHEAD` is a fixed constant).
pub fn select_note_inputs(
    available: &[Utxo],
    payload_lens: &[usize],
    recipient_spk_len: Option<usize>,
    recipient_amount: u64,
    fee_rate: f64,
) -> Result<Vec<Utxo>, Error> {
    let sent: u64 = if recipient_spk_len.is_some() { recipient_amount } else { 0 };
    let mut candidates = available.to_vec();
    candidates.sort_by(|a, b| b.value.cmp(&a.value));
    let mut selected: Vec<Utxo> = Vec::new();
    let mut in_value: u64 = 0;
    for utxo in candidates {
        selected.push(utxo);
        in_value += selected.last().expect("just pushed").value;
        for change in [true, false] {
            let vsize = estimate_vsize(selected.len(), payload_lens, recipient_spk_len, change);
            let fee = (vsize as f64 * fee_rate).ceil() as u64;
            if in_value < fee + sent {
                continue;
            }
            let change_value = in_value - fee - sent;
            if change && change_value < DUST_LIMIT {
                continue;
            }
            if !change && change_value > DUST_LIMIT {
                continue;
            }
            return Ok(selected);
        }
    }
    Err(Error::InsufficientFunds)
}

/// [`select_note_inputs`] generalized to N recipient outputs, mirroring
/// [`build_note_tx_multi_with_change`]'s selection loop (`estimate_vsize_multi`).
pub fn select_note_inputs_multi(
    available: &[Utxo],
    payload_lens: &[usize],
    recipient_lens: &[usize],
    sent: u64,
    fee_rate: f64,
) -> Result<Vec<Utxo>, Error> {
    let mut candidates = available.to_vec();
    candidates.sort_by(|a, b| b.value.cmp(&a.value));
    let mut selected: Vec<Utxo> = Vec::new();
    let mut in_value: u64 = 0;
    for utxo in candidates {
        selected.push(utxo);
        in_value += selected.last().expect("just pushed").value;
        for change in [true, false] {
            let vsize =
                estimate_vsize_multi(selected.len(), payload_lens, recipient_lens, change);
            let fee = (vsize as f64 * fee_rate).ceil() as u64;
            if in_value < fee + sent {
                continue;
            }
            let change_value = in_value - fee - sent;
            if change && change_value < DUST_LIMIT {
                continue;
            }
            if !change && change_value > DUST_LIMIT {
                continue;
            }
            return Ok(selected);
        }
    }
    Err(Error::InsufficientFunds)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub lock_time: u32,
    pub inputs: Vec<Utxo>,
    pub outputs: Vec<TxOut>,
    /// One witness stack per input; empty until signed.
    pub witnesses: Vec<Vec<Vec<u8>>>,
}

pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// OP_RETURN script with a single canonical push of `payload`.
pub fn op_return_script(payload: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(payload.len() + 4);
    script.push(0x6a); // OP_RETURN
    match payload.len() {
        0..=75 => script.push(payload.len() as u8),
        76..=255 => {
            script.push(0x4c); // OP_PUSHDATA1
            script.push(payload.len() as u8);
        }
        _ => {
            script.push(0x4d); // OP_PUSHDATA2
            script.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        }
    }
    script.extend_from_slice(payload);
    script
}

/// Extract the pushed payload from an OP_RETURN scriptPubKey (the scanner
/// side of `op_return_script`). None for non-OP_RETURN or multi-push.
pub fn op_return_payload(script: &[u8]) -> Option<&[u8]> {
    if script.first() != Some(&0x6a) {
        return None;
    }
    let rest = &script[1..];
    let (len, data) = match rest.first()? {
        n @ 1..=75 => (*n as usize, &rest[1..]),
        0x4c => (*rest.get(1)? as usize, &rest[2..]),
        0x4d => (
            u16::from_le_bytes([*rest.get(1)?, *rest.get(2)?]) as usize,
            &rest[3..],
        ),
        _ => return None,
    };
    (data.len() == len).then_some(data)
}

impl Transaction {
    fn serialize_common_prefix(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
    }

    fn serialize_in_outs(&self, out: &mut Vec<u8>) {
        write_varint(out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.txid);
            out.extend_from_slice(&input.vout.to_le_bytes());
            out.push(0); // empty scriptSig (segwit)
            out.extend_from_slice(&0xffff_fffdu32.to_le_bytes()); // RBF-signaling
        }
        write_varint(out, self.outputs.len() as u64);
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            write_varint(out, output.script_pubkey.len() as u64);
            out.extend_from_slice(&output.script_pubkey);
        }
    }

    /// Legacy (no-witness) serialization — this is what txid hashes.
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize_common_prefix(&mut out);
        self.serialize_in_outs(&mut out);
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// Full BIP144 serialization with witnesses (what gets broadcast).
    pub fn serialize_segwit(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize_common_prefix(&mut out);
        out.push(0x00); // marker
        out.push(0x01); // flag
        self.serialize_in_outs(&mut out);
        for witness in &self.witnesses {
            write_varint(&mut out, witness.len() as u64);
            for item in witness {
                write_varint(&mut out, item.len() as u64);
                out.extend_from_slice(item);
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// txid in internal byte order (reverse for display hex).
    pub fn txid(&self) -> [u8; 32] {
        double_sha256(&self.serialize_legacy())
    }

    /// Display txid: reversed hex, as explorers and bitcoin-cli show it.
    pub fn txid_hex(&self) -> String {
        let mut id = self.txid();
        id.reverse();
        hex::encode(id)
    }

    /// weight = base*3 + total (BIP141); vsize = ceil(weight/4).
    pub fn vsize(&self) -> usize {
        let base = self.serialize_legacy().len();
        let total = self.serialize_segwit().len();
        (base * 3 + total).div_ceil(4)
    }
}

/// Predicted vsize of a note tx BEFORE it exists — pure arithmetic for the
/// keystroke cost estimator. Key-path P2TR: 57.5 weight-units of input
/// witness (66 witness bytes + marker/flag amortized), matched by tests
/// against real signed transactions.
pub fn estimate_vsize(
    n_inputs: usize,
    payload_lens: &[usize],
    recipient_spk_len: Option<usize>,
    change: bool,
) -> usize {
    // Base (non-witness) bytes.
    let mut base = 4 + 4; // version + locktime
    base += varint_len(n_inputs) + n_inputs * (32 + 4 + 1 + 4);
    let n_outputs =
        payload_lens.len() + usize::from(recipient_spk_len.is_some()) + usize::from(change);
    base += varint_len(n_outputs);
    for &len in payload_lens {
        base += 8 + varint_len_script(len) + script_len(len);
    }
    if let Some(spk_len) = recipient_spk_len {
        base += 8 + varint_len(spk_len) + spk_len;
    }
    if change {
        base += 8 + 1 + 34;
    }
    // Witness bytes: marker+flag plus one 64-byte-sig stack per input.
    let witness = 2 + n_inputs * (1 + 1 + 64);
    (base * 4 + witness).div_ceil(4)
}

fn varint_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        _ => 5,
    }
}

fn script_len(payload: usize) -> usize {
    op_return_script_len(payload)
}

fn op_return_script_len(payload: usize) -> usize {
    1 + match payload {
        0..=75 => 1,
        76..=255 => 2,
        _ => 3,
    } + payload
}

fn varint_len_script(payload: usize) -> usize {
    varint_len(op_return_script_len(payload))
}

/// [`estimate_vsize`] generalized to N recipient outputs instead of a
/// single optional one — the multi-recipient directed-note estimator
/// (FLAG_MULTI, 2..=255 recipients). `recipient_spk_lens` empty = self-note
/// (matches `estimate_vsize(.., None, ..)`), one entry = a legacy
/// single-recipient directed note (matches `estimate_vsize(.., Some(len),
/// ..)` exactly — same arithmetic, generalized), N entries = a
/// multi-recipient one. Kept as a separate function (not a refactor of
/// `estimate_vsize`) so that function's body stays byte-identical/untouched.
pub fn estimate_vsize_multi(
    n_inputs: usize,
    payload_lens: &[usize],
    recipient_spk_lens: &[usize],
    change: bool,
) -> usize {
    let mut base = 4 + 4; // version + locktime
    base += varint_len(n_inputs) + n_inputs * (32 + 4 + 1 + 4);
    let n_outputs = payload_lens.len() + recipient_spk_lens.len() + usize::from(change);
    base += varint_len(n_outputs);
    for &len in payload_lens {
        base += 8 + varint_len_script(len) + script_len(len);
    }
    for &len in recipient_spk_lens {
        base += 8 + varint_len(len) + len;
    }
    if change {
        base += 8 + 1 + 34;
    }
    let witness = 2 + n_inputs * (1 + 1 + 64);
    (base * 4 + witness).div_ceil(4)
}

/// A fully built, signed note transaction plus its accounting.
#[derive(Debug, Clone)]
pub struct NoteTx {
    pub tx: Transaction,
    pub fee: u64,
    pub change: u64,
    /// Sats delivered to a directed-note recipient (0 for self-notes and
    /// sweeps; DUST_LIMIT for directed notes).
    pub sent: u64,
    pub vsize: usize,
    pub txid_hex: String,
    pub raw_hex: String,
    pub spent_outpoints: Vec<([u8; 32], u32)>,
}

/// Predicted vsize of a sweep tx BEFORE it exists: `n_inputs` key-path
/// P2TR inputs into a single output of `dest_spk_len` script bytes.
/// Byte-exact vs `build_sweep_tx` by construction — it is the same
/// arithmetic that function prices its fee with.
pub fn estimate_sweep_vsize(n_inputs: usize, dest_spk_len: usize) -> usize {
    let base = 4
        + varint_len(n_inputs)
        + n_inputs * 41
        + 1
        + (8 + varint_len(dest_spk_len) + dest_spk_len)
        + 4;
    let witness = 2 + n_inputs * 66;
    (base * 4 + witness).div_ceil(4)
}

/// Build and sign a sweep: spend ALL `available` UTXOs (ours, key-path)
/// into a single external output `dest_spk`, everything minus fee. Used to
/// move funds off the notes address (e.g. returning testnet coins) and,
/// with `dest_spk` = our own address, to consolidate coins into one.
pub fn build_sweep_tx(
    available: &[Utxo],
    our_output_x: &[u8; 32],
    dest_spk: Vec<u8>,
    fee_rate: f64,
    lock_time: u32,
    tweaked_seckey: &[u8; 32],
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    build_sweep_tx_multi(
        &[SweepSource { utxos: available, output_x: *our_output_x, tweaked_seckey }],
        dest_spk,
        fee_rate,
        lock_time,
        aux,
    )
}

/// One address's contribution to a multi-source sweep: its coins plus the
/// key that owns them (the notebooks feature's wallet-level consolidate).
pub struct SweepSource<'a> {
    pub utxos: &'a [Utxo],
    pub output_x: [u8; 32],
    pub tweaked_seckey: &'a [u8; 32],
}

/// [`build_sweep_tx`] across MANY addresses: every source's coins ride in
/// one transaction — each input signed with its own source's key — into a
/// single output at `dest_spk`. Input order is source order, flattened.
/// ADDITIVE: `build_sweep_tx` delegates here with one source and stays
/// byte-identical to its previous behavior (same estimator — all inputs
/// are P2TR key-path, so input count is all that matters — same ordering,
/// same aux sequence).
pub fn build_sweep_tx_multi(
    sources: &[SweepSource],
    dest_spk: Vec<u8>,
    fee_rate: f64,
    lock_time: u32,
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    // Flatten inputs, remembering each input's owning source for signing.
    let mut inputs: Vec<Utxo> = Vec::new();
    let mut owner: Vec<usize> = Vec::new();
    for (si, src) in sources.iter().enumerate() {
        for u in src.utxos {
            inputs.push(u.clone());
            owner.push(si);
        }
    }
    if inputs.is_empty() {
        return Err(Error::InsufficientFunds);
    }
    let in_value: u64 = inputs.iter().map(|u| u.value).sum();
    let vsize = estimate_sweep_vsize(inputs.len(), dest_spk.len());
    let fee = (vsize as f64 * fee_rate).ceil() as u64;
    if in_value <= fee || in_value - fee < DUST_LIMIT {
        return Err(Error::InsufficientFunds);
    }

    let mut tx = Transaction {
        version: 2,
        lock_time,
        inputs,
        outputs: vec![TxOut { value: in_value - fee, script_pubkey: dest_spk }],
        witnesses: Vec::new(),
    };
    let spks: Vec<Vec<u8>> = sources.iter().map(|s| p2tr_script_pubkey(&s.output_x)).collect();
    let prevout_spks: Vec<Vec<u8>> = owner.iter().map(|si| spks[*si].clone()).collect();
    for index in 0..tx.inputs.len() {
        let sighash = taproot_key_spend_sighash(&tx, &prevout_spks, index);
        let sig = schnorr_sign(sources[owner[index]].tweaked_seckey, &sighash, &aux()?)?;
        tx.witnesses.push(vec![sig.to_vec()]);
    }
    Ok(NoteTx {
        fee,
        change: 0,
        sent: 0,
        vsize: tx.vsize(),
        txid_hex: tx.txid_hex(),
        raw_hex: hex::encode(tx.serialize_segwit()),
        spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
        tx,
    })
}

/// Sweep analog of [`build_note_tx_mixed_exact`]: spend EXACTLY the given
/// mixed-source inputs (coin control — notebook taproot coins and
/// spending-wallet P2WPKH coins riding in the SAME tx, e.g. sweeping every
/// active notebook plus the spending wallet in one go) into a SINGLE
/// output at `dest_spk`, everything minus fee. Like `build_sweep_tx_multi`,
/// there is no OP_RETURN, no dust-to-self, and no change — a sweep sends
/// 100% of input value to `dest_spk` by definition. Sized via
/// `estimate_vsize_mixed` with an empty payload list and one extra output
/// (the destination), and signed in one pass via
/// [`crate::wpkh::sign_mixed_inputs`], exactly like
/// `build_note_tx_mixed_exact` signs its mixed inputs.
pub fn build_sweep_tx_mixed(
    inputs: &[MixedInput],
    dest_spk: Vec<u8>,
    fee_rate: f64,
    lock_time: u32,
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if inputs.is_empty() {
        return Err(Error::InsufficientFunds);
    }
    let kinds: Vec<InputKind> = inputs.iter().map(|i| i.kind).collect();
    let in_value: u64 = inputs.iter().map(|i| i.utxo.value).sum();
    let vsize = estimate_vsize_mixed(&kinds, &[], &[dest_spk.len()]);
    let fee = (vsize as f64 * fee_rate).ceil() as u64;
    if in_value <= fee || in_value - fee < DUST_LIMIT {
        return Err(Error::InsufficientFunds);
    }

    let mut tx = Transaction {
        version: 2,
        lock_time,
        inputs: inputs.iter().map(|i| i.utxo.clone()).collect(),
        outputs: vec![TxOut { value: in_value - fee, script_pubkey: dest_spk }],
        witnesses: Vec::new(),
    };
    let prevout_spks: Vec<Vec<u8>> = inputs.iter().map(|i| i.prevout_spk.clone()).collect();
    let keys: Vec<crate::wpkh::InputKey> = inputs
        .iter()
        .map(|i| match i.kind {
            InputKind::Taproot => crate::wpkh::InputKey::Taproot { tweaked_seckey: &i.seckey },
            InputKind::P2wpkh => crate::wpkh::InputKey::P2wpkh { seckey: &i.seckey },
        })
        .collect();
    crate::wpkh::sign_mixed_inputs(&mut tx, &prevout_spks, &keys, &mut aux)?;

    Ok(NoteTx {
        fee,
        change: 0,
        sent: 0,
        vsize: tx.vsize(),
        txid_hex: tx.txid_hex(),
        raw_hex: hex::encode(tx.serialize_segwit()),
        spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
        tx,
    })
}

/// Build and sign a note tx: OP_RETURN outputs for `payloads`, then — for
/// directed notes — a DUST_LIMIT output to `recipient_spk`, then change
/// back to `output_x` (our own tweaked key). Inputs selected largest-first
/// from `available` until value covers fee (+ dust) at `fee_rate` sat/vB.
/// `tweaked_seckey` is the taproot-tweaked signing key; `aux` supplies
/// BIP340 aux randomness per input.
#[allow(clippy::too_many_arguments)]
pub fn build_note_tx(
    available: &[Utxo],
    output_x: &[u8; 32],
    payloads: &[Vec<u8>],
    recipient_spk: Option<&[u8]>,
    fee_rate: f64,
    lock_time: u32,
    tweaked_seckey: &[u8; 32],
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    build_note_tx_with_change(
        available, output_x, payloads, recipient_spk, DUST_LIMIT, None, fee_rate, lock_time,
        tweaked_seckey, aux,
    )
}

/// Like `build_note_tx`, but when `change_out` is Some the change output
/// pays that script instead of the notes address. Inputs are always the
/// notes address, so sighashing (which uses the address's own spk for
/// every prevout) is unchanged; only the change OUTPUT differs.
#[allow(clippy::too_many_arguments)]
pub fn build_note_tx_with_change(
    available: &[Utxo],
    output_x: &[u8; 32],
    payloads: &[Vec<u8>],
    recipient_spk: Option<&[u8]>,
    // Value of the recipient (directed) output. Ignored when recipient_spk is
    // None (self-note). Must be >= DUST_LIMIT.
    recipient_amount: u64,
    change_out: Option<&[u8]>,
    fee_rate: f64,
    lock_time: u32,
    tweaked_seckey: &[u8; 32],
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if payloads.is_empty() {
        return Err(Error::Envelope("no payloads"));
    }
    if recipient_spk.is_some() && recipient_amount < DUST_LIMIT {
        return Err(Error::Envelope("gift amount below dust limit"));
    }
    let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();
    let sent: u64 = if recipient_spk.is_some() { recipient_amount } else { 0 };
    let mut candidates = available.to_vec();
    candidates.sort_by(|a, b| b.value.cmp(&a.value));

    // `change_spk` is the notes address's own spk — used for BOTH the
    // input prevout scripts (sighash) and, by default, the change output.
    let change_spk = p2tr_script_pubkey(output_x);
    // Where the change value actually goes (self unless overridden).
    let change_out_spk = change_out.map(<[u8]>::to_vec).unwrap_or_else(|| change_spk.clone());
    let mut selected: Vec<Utxo> = Vec::new();
    let mut in_value: u64 = 0;

    for utxo in candidates {
        selected.push(utxo.clone());
        in_value += utxo.value;

        // Try with a change output first; fall back to no-change.
        for change in [true, false] {
            let vsize = estimate_vsize(
                selected.len(),
                &payload_lens,
                recipient_spk.map(<[u8]>::len),
                change,
            );
            let fee = (vsize as f64 * fee_rate).ceil() as u64;
            if in_value < fee + sent {
                continue;
            }
            let change_value = in_value - fee - sent;
            if change && change_value < DUST_LIMIT {
                continue;
            }
            if !change && change_value > DUST_LIMIT {
                // Overshoot without change would burn > dust into fees;
                // prefer adding the change output (previous iteration).
                continue;
            }

            let mut outputs: Vec<TxOut> = payloads
                .iter()
                .map(|p| TxOut { value: 0, script_pubkey: op_return_script(p) })
                .collect();
            if let Some(spk) = recipient_spk {
                outputs.push(TxOut { value: sent, script_pubkey: spk.to_vec() });
            }
            if change {
                outputs
                    .push(TxOut { value: change_value, script_pubkey: change_out_spk.clone() });
            }

            let mut tx = Transaction {
                version: 2,
                lock_time,
                inputs: selected.clone(),
                outputs,
                witnesses: Vec::new(),
            };

            let prevout_spks: Vec<Vec<u8>> =
                tx.inputs.iter().map(|_| change_spk.clone()).collect();
            for index in 0..tx.inputs.len() {
                let sighash = taproot_key_spend_sighash(&tx, &prevout_spks, index);
                let sig = schnorr_sign(tweaked_seckey, &sighash, &aux()?)?;
                tx.witnesses.push(vec![sig.to_vec()]);
            }

            let actual_fee = in_value - sent - if change { change_value } else { 0 };
            return Ok(NoteTx {
                fee: actual_fee,
                change: if change { change_value } else { 0 },
                sent,
                vsize: tx.vsize(),
                txid_hex: tx.txid_hex(),
                raw_hex: hex::encode(tx.serialize_segwit()),
                spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
                tx,
            });
        }
    }
    Err(Error::InsufficientFunds)
}

/// Multi-recipient (2..=255) analog of [`build_note_tx_with_change`]: many
/// directed-note recipients instead of one, each with its own amount
/// (`>= DUST_LIMIT`). `recipients` is `(script_pubkey, amount)` pairs in
/// OUTPUT order. Output order: OP_RETURN chunk(s), then recipient outputs
/// in `recipients` order, then change. A single-entry `recipients`
/// DELEGATES to `build_note_tx_with_change` and is therefore byte-identical
/// to it — every existing single-recipient wire byte is unaffected by this
/// function's existence.
#[allow(clippy::too_many_arguments)]
pub fn build_note_tx_multi_with_change(
    available: &[Utxo],
    output_x: &[u8; 32],
    payloads: &[Vec<u8>],
    recipients: &[(Vec<u8>, u64)],
    change_out: Option<&[u8]>,
    fee_rate: f64,
    lock_time: u32,
    tweaked_seckey: &[u8; 32],
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if recipients.is_empty() || recipients.len() > 255 {
        return Err(Error::Envelope("recipients: 1..=255"));
    }
    if recipients.len() == 1 {
        let (spk, amount) = &recipients[0];
        return build_note_tx_with_change(
            available, output_x, payloads, Some(spk), *amount, change_out, fee_rate, lock_time,
            tweaked_seckey, aux,
        );
    }
    if payloads.is_empty() {
        return Err(Error::Envelope("no payloads"));
    }
    if recipients.iter().any(|(_, amount)| *amount < DUST_LIMIT) {
        return Err(Error::Envelope("gift amount below dust limit"));
    }
    let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();
    let recipient_lens: Vec<usize> = recipients.iter().map(|(spk, _)| spk.len()).collect();
    let sent: u64 = recipients.iter().map(|(_, amount)| amount).sum();
    let mut candidates = available.to_vec();
    candidates.sort_by(|a, b| b.value.cmp(&a.value));

    let change_spk = p2tr_script_pubkey(output_x);
    let change_out_spk = change_out.map(<[u8]>::to_vec).unwrap_or_else(|| change_spk.clone());
    let mut selected: Vec<Utxo> = Vec::new();
    let mut in_value: u64 = 0;

    for utxo in candidates {
        selected.push(utxo.clone());
        in_value += utxo.value;

        for change in [true, false] {
            let vsize =
                estimate_vsize_multi(selected.len(), &payload_lens, &recipient_lens, change);
            let fee = (vsize as f64 * fee_rate).ceil() as u64;
            if in_value < fee + sent {
                continue;
            }
            let change_value = in_value - fee - sent;
            if change && change_value < DUST_LIMIT {
                continue;
            }
            if !change && change_value > DUST_LIMIT {
                continue;
            }

            let mut outputs: Vec<TxOut> = payloads
                .iter()
                .map(|p| TxOut { value: 0, script_pubkey: op_return_script(p) })
                .collect();
            for (spk, amount) in recipients {
                outputs.push(TxOut { value: *amount, script_pubkey: spk.clone() });
            }
            if change {
                outputs
                    .push(TxOut { value: change_value, script_pubkey: change_out_spk.clone() });
            }

            let mut tx = Transaction {
                version: 2,
                lock_time,
                inputs: selected.clone(),
                outputs,
                witnesses: Vec::new(),
            };
            let prevout_spks: Vec<Vec<u8>> =
                tx.inputs.iter().map(|_| change_spk.clone()).collect();
            for index in 0..tx.inputs.len() {
                let sighash = taproot_key_spend_sighash(&tx, &prevout_spks, index);
                let sig = schnorr_sign(tweaked_seckey, &sighash, &aux()?)?;
                tx.witnesses.push(vec![sig.to_vec()]);
            }

            let actual_fee = in_value - sent - if change { change_value } else { 0 };
            return Ok(NoteTx {
                fee: actual_fee,
                change: if change { change_value } else { 0 },
                sent,
                vsize: tx.vsize(),
                txid_hex: tx.txid_hex(),
                raw_hex: hex::encode(tx.serialize_segwit()),
                spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
                tx,
            });
        }
    }
    Err(Error::InsufficientFunds)
}

/// Multi-recipient (2..=255) analog of [`build_note_tx_exact`]: coin
/// control (spend EXACTLY `inputs`, no auto-selection) with many directed
/// recipients. Same delegation rule as [`build_note_tx_multi_with_change`]:
/// a single-entry `recipients` calls `build_note_tx_exact` and is
/// byte-identical to it.
#[allow(clippy::too_many_arguments)]
pub fn build_note_tx_multi_exact(
    inputs: &[Utxo],
    output_x: &[u8; 32],
    payloads: &[Vec<u8>],
    recipients: &[(Vec<u8>, u64)],
    change_out: Option<&[u8]>,
    fee_rate: f64,
    lock_time: u32,
    tweaked_seckey: &[u8; 32],
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if recipients.is_empty() || recipients.len() > 255 {
        return Err(Error::Envelope("recipients: 1..=255"));
    }
    if recipients.len() == 1 {
        let (spk, amount) = &recipients[0];
        return build_note_tx_exact(
            inputs, output_x, payloads, Some(spk), *amount, change_out, fee_rate, lock_time,
            tweaked_seckey, aux,
        );
    }
    if payloads.is_empty() {
        return Err(Error::Envelope("no payloads"));
    }
    if inputs.is_empty() {
        return Err(Error::InsufficientFunds);
    }
    if recipients.iter().any(|(_, amount)| *amount < DUST_LIMIT) {
        return Err(Error::Envelope("gift amount below dust limit"));
    }
    let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();
    let recipient_lens: Vec<usize> = recipients.iter().map(|(spk, _)| spk.len()).collect();
    let sent: u64 = recipients.iter().map(|(_, amount)| amount).sum();
    let change_spk = p2tr_script_pubkey(output_x);
    let change_out_spk = change_out.map(<[u8]>::to_vec).unwrap_or_else(|| change_spk.clone());
    let in_value: u64 = inputs.iter().map(|u| u.value).sum();

    for change in [true, false] {
        let vsize = estimate_vsize_multi(inputs.len(), &payload_lens, &recipient_lens, change);
        let fee = (vsize as f64 * fee_rate).ceil() as u64;
        if in_value < fee + sent {
            continue;
        }
        let change_value = in_value - fee - sent;
        if change && change_value < DUST_LIMIT {
            continue;
        }
        if !change && change_value > DUST_LIMIT {
            continue;
        }

        let mut outputs: Vec<TxOut> = payloads
            .iter()
            .map(|p| TxOut { value: 0, script_pubkey: op_return_script(p) })
            .collect();
        for (spk, amount) in recipients {
            outputs.push(TxOut { value: *amount, script_pubkey: spk.clone() });
        }
        if change {
            outputs.push(TxOut { value: change_value, script_pubkey: change_out_spk.clone() });
        }

        let mut tx = Transaction {
            version: 2,
            lock_time,
            inputs: inputs.to_vec(),
            outputs,
            witnesses: Vec::new(),
        };
        let prevout_spks: Vec<Vec<u8>> = tx.inputs.iter().map(|_| change_spk.clone()).collect();
        for index in 0..tx.inputs.len() {
            let sighash = taproot_key_spend_sighash(&tx, &prevout_spks, index);
            let sig = schnorr_sign(tweaked_seckey, &sighash, &aux()?)?;
            tx.witnesses.push(vec![sig.to_vec()]);
        }
        let actual_fee = in_value - sent - if change { change_value } else { 0 };
        return Ok(NoteTx {
            fee: actual_fee,
            change: if change { change_value } else { 0 },
            sent,
            vsize: tx.vsize(),
            txid_hex: tx.txid_hex(),
            raw_hex: hex::encode(tx.serialize_segwit()),
            spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
            tx,
        });
    }
    Err(Error::InsufficientFunds)
}

// ---------------------------------------------------------------------
// Mixed-source (taproot + P2WPKH) note transactions — the Prime device's
// spending-wallet port (PLAN-graffito-funding-unification.md, "Prime
// device" + "New signing surface: P2WPKH in notes-core"). Unlike every
// builder above (always P2TR key-path, one shared `tweaked_seckey`), a
// spending-wallet coin is a P2WPKH input owned by ITS OWN fresh-address
// key, and multiple selected coins can each carry a DIFFERENT key — so
// this builder takes one key PER INPUT and signs via `wpkh::sign_mixed_inputs`
// in a single pass, taproot inputs riding along (schnorr) when a notebook
// dust coin is spent alongside spending-wallet coins (e.g. topping up a
// note's fee from the notebook).
// ---------------------------------------------------------------------

/// One input's key material for [`build_note_tx_mixed_exact`]: either the
/// notebook's taproot-tweaked key-path secret, or a spending-wallet P2WPKH
/// leaf secret (raw, no tweak). Both are 32 bytes; which signing algorithm
/// applies is decided by `kind`, kept alongside for fee estimation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Taproot,
    P2wpkh,
}

/// One EXACT input to a mixed-source note tx: the coin, its spent
/// scriptPubKey (BIP341 sighashing commits every input's prevout spk even
/// for inputs that aren't themselves taproot — see `wpkh::sign_mixed_inputs`'s
/// doc comment), and its owning key.
pub struct MixedInput {
    pub utxo: Utxo,
    pub prevout_spk: Vec<u8>,
    pub kind: InputKind,
    /// Taproot: the already-tweaked key-path secret. P2WPKH: the raw leaf
    /// secret (no tweak — unlike taproot, P2WPKH has no output-key tweak).
    pub seckey: [u8; 32],
}

/// Weight-unit cost of one input's witness stack by kind: 66 for a
/// key-path taproot spend (1 count + 1 len + 64-byte schnorr sig, matching
/// `estimate_vsize`'s existing all-taproot assumption), 108 for a P2WPKH
/// spend assuming the worst-case low-S DER signature (1 count + 1 len +
/// 72-byte sig+sighash-byte + 1 len + 33-byte compressed pubkey) — the same
/// conservative budgeting convention most wallets use (a real signature is
/// often 1-2 bytes shorter, so the fee is a slight, harmless overpay).
/// Together with the shared 41-byte base these reproduce
/// PLAN-graffito-funding-unification.md's cost table exactly: P2TR input
/// 57.5 vB, P2WPKH input 68 vB ((41*4 + 66)/4 = 57.5, (41*4 + 108)/4 = 68).
fn mixed_input_witness_wu(kind: InputKind) -> usize {
    match kind {
        InputKind::Taproot => 66,
        InputKind::P2wpkh => 108,
    }
}

/// Like [`estimate_vsize`], generalized to mixed input kinds and an
/// explicit list of every NON-OP_RETURN output's scriptPubKey length (in
/// output order) instead of a single hardcoded P2TR change output — a
/// mixed-source note always has at least the notebook dust-to-self output,
/// often a directed recipient too, and change of whichever kind the
/// destination picker chose (fresh spending bc1q, or notebook bc1p).
pub fn estimate_vsize_mixed(
    kinds: &[InputKind],
    payload_lens: &[usize],
    extra_output_lens: &[usize],
) -> usize {
    let mut base = 4 + 4; // version + locktime
    base += varint_len(kinds.len()) + kinds.len() * (32 + 4 + 1 + 4);
    let n_outputs = payload_lens.len() + extra_output_lens.len();
    base += varint_len(n_outputs);
    for &len in payload_lens {
        base += 8 + varint_len_script(len) + script_len(len);
    }
    for &len in extra_output_lens {
        base += 8 + varint_len(len) + len;
    }
    let witness: usize =
        2 + kinds.iter().map(|k| mixed_input_witness_wu(*k)).sum::<usize>();
    (base * 4 + witness).div_ceil(4)
}

/// Build and sign a note tx spending EXACTLY the given mixed-source inputs
/// (coin control only — no automatic selection, matching
/// `build_note_tx_exact`'s coin-control shape). ALWAYS emits a
/// `DUST_LIMIT`-sat output to `notebook_dust_spk` (decision 4 in the PLAN,
/// "Dust-to-self stays": a funded note must still pay the notebook or it
/// never appears in its address history, which is the whole discoverability
/// mechanism) — callers use this builder precisely when funding is NOT
/// pure-notebook, so that output is unconditional here, unlike the optional
/// `recipient_spk` dust of the all-taproot builders above. Output order:
/// OP_RETURN chunk(s), optional directed recipient, notebook dust, change —
/// matching the already-shipped external-funding PSBT shape byte-for-byte.
///
/// Kept byte-identical for existing callers; prefer
/// [`build_note_tx_mixed_exact_anchored`] for new callers — it skips this
/// dust output when the tx is already input-anchored to the notebook.
#[allow(clippy::too_many_arguments)]
pub fn build_note_tx_mixed_exact(
    inputs: &[MixedInput],
    payloads: &[Vec<u8>],
    recipient_spk: Option<&[u8]>,
    recipient_amount: u64,
    notebook_dust_spk: &[u8],
    change_spk: &[u8],
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    build_note_tx_mixed_exact_inner(
        inputs,
        payloads,
        recipient_spk,
        recipient_amount,
        notebook_dust_spk,
        change_spk,
        fee_rate,
        lock_time,
        true, // always emit the dust-to-self anchor, matching this fn's historical behavior
        aux,
    )
}

/// Like [`build_note_tx_mixed_exact`], but the notebook dust-to-self anchor
/// is emitted ONLY when no input already spends from `notebook_dust_spk`
/// (design decision, funding-unification, 2026-07-18): a tx with a notebook
/// coin among its inputs is already anchored in that address's history and
/// already owned by the OWN-note rule (`spends_from_self` / input-prevout-spk
/// matching), so the dust output would be pure waste (~43 vB now, ~58 vB
/// again whenever the minted dust coin is later spent). The skip condition
/// is computed HERE, from the inputs actually being spent — it is `true`
/// (dust emitted) unless some `inputs[i].prevout_spk == notebook_dust_spk`.
/// Fee/change math and the order of every OTHER output (OP_RETURNs,
/// optional recipient, then change) are unchanged; the dust output simply
/// drops out of that order when skipped.
#[allow(clippy::too_many_arguments)]
pub fn build_note_tx_mixed_exact_anchored(
    inputs: &[MixedInput],
    payloads: &[Vec<u8>],
    recipient_spk: Option<&[u8]>,
    recipient_amount: u64,
    notebook_dust_spk: &[u8],
    change_spk: &[u8],
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let anchored_by_input = inputs.iter().any(|i| i.prevout_spk == notebook_dust_spk);
    build_note_tx_mixed_exact_inner(
        inputs,
        payloads,
        recipient_spk,
        recipient_amount,
        notebook_dust_spk,
        change_spk,
        fee_rate,
        lock_time,
        !anchored_by_input,
        aux,
    )
}

/// Shared implementation of `build_note_tx_mixed_exact` /
/// `build_note_tx_mixed_exact_anchored` — `emit_dust` decides whether the
/// `DUST_LIMIT`-sat notebook output is included; everything else (fee math,
/// coin data, remaining output order) is identical between the two public
/// entry points.
#[allow(clippy::too_many_arguments)]
fn build_note_tx_mixed_exact_inner(
    inputs: &[MixedInput],
    payloads: &[Vec<u8>],
    recipient_spk: Option<&[u8]>,
    recipient_amount: u64,
    notebook_dust_spk: &[u8],
    change_spk: &[u8],
    fee_rate: f64,
    lock_time: u32,
    emit_dust: bool,
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if payloads.is_empty() {
        return Err(Error::Envelope("no payloads"));
    }
    if inputs.is_empty() {
        return Err(Error::InsufficientFunds);
    }
    if recipient_spk.is_some() && recipient_amount < DUST_LIMIT {
        return Err(Error::Envelope("gift amount below dust limit"));
    }
    let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();
    let sent: u64 = if recipient_spk.is_some() { recipient_amount } else { 0 };
    let dust: u64 = if emit_dust { DUST_LIMIT } else { 0 };
    let kinds: Vec<InputKind> = inputs.iter().map(|i| i.kind).collect();
    let in_value: u64 = inputs.iter().map(|i| i.utxo.value).sum();

    for change in [true, false] {
        let mut extra_lens: Vec<usize> = Vec::with_capacity(3);
        if let Some(spk) = recipient_spk {
            extra_lens.push(spk.len());
        }
        if emit_dust {
            extra_lens.push(notebook_dust_spk.len());
        }
        if change {
            extra_lens.push(change_spk.len());
        }
        let vsize = estimate_vsize_mixed(&kinds, &payload_lens, &extra_lens);
        let fee = (vsize as f64 * fee_rate).ceil() as u64;
        if in_value < fee + sent + dust {
            continue;
        }
        let change_value = in_value - fee - sent - dust;
        if change && change_value < DUST_LIMIT {
            continue;
        }
        if !change && change_value > DUST_LIMIT {
            // Overshoot without change would burn > dust into fees; prefer
            // the change-output branch (tried first in this loop).
            continue;
        }

        let mut outputs: Vec<TxOut> = payloads
            .iter()
            .map(|p| TxOut { value: 0, script_pubkey: op_return_script(p) })
            .collect();
        if let Some(spk) = recipient_spk {
            outputs.push(TxOut { value: sent, script_pubkey: spk.to_vec() });
        }
        if emit_dust {
            outputs.push(TxOut { value: DUST_LIMIT, script_pubkey: notebook_dust_spk.to_vec() });
        }
        if change {
            outputs.push(TxOut { value: change_value, script_pubkey: change_spk.to_vec() });
        }

        let mut tx = Transaction {
            version: 2,
            lock_time,
            inputs: inputs.iter().map(|i| i.utxo.clone()).collect(),
            outputs,
            witnesses: Vec::new(),
        };
        let prevout_spks: Vec<Vec<u8>> = inputs.iter().map(|i| i.prevout_spk.clone()).collect();
        let keys: Vec<crate::wpkh::InputKey> = inputs
            .iter()
            .map(|i| match i.kind {
                InputKind::Taproot => crate::wpkh::InputKey::Taproot { tweaked_seckey: &i.seckey },
                InputKind::P2wpkh => crate::wpkh::InputKey::P2wpkh { seckey: &i.seckey },
            })
            .collect();
        crate::wpkh::sign_mixed_inputs(&mut tx, &prevout_spks, &keys, &mut aux)?;

        let actual_fee = in_value - sent - dust - if change { change_value } else { 0 };
        return Ok(NoteTx {
            fee: actual_fee,
            change: if change { change_value } else { 0 },
            sent,
            vsize: tx.vsize(),
            txid_hex: tx.txid_hex(),
            raw_hex: hex::encode(tx.serialize_segwit()),
            spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
            tx,
        });
    }
    Err(Error::InsufficientFunds)
}

/// Multi-recipient (0/1..=255) analog of [`build_note_tx_mixed_exact_anchored`]:
/// many directed-note recipients (`recipients` as `(scriptPubKey, amount)`
/// pairs in OUTPUT order) instead of at most one, each amount `>= DUST_LIMIT`.
/// Same anchored-dust-skip rule as the singular function (no dust-to-self
/// output when an input already spends `notebook_dust_spk`). A `recipients`
/// slice of length 0 or 1 delegates to `build_note_tx_mixed_exact_anchored`
/// and is therefore byte-identical to it — every mixed-funded self-note or
/// single-recipient directed note this function's existence touches is
/// unaffected. Output order: OP_RETURN chunk(s), recipient outputs in
/// `recipients` order, optional notebook dust, change — matching
/// [`build_note_tx_multi_with_change`]/[`build_note_tx_multi_exact`]'s
/// recipient-then-other-outputs convention.
#[allow(clippy::too_many_arguments)]
pub fn build_note_tx_mixed_exact_anchored_multi(
    inputs: &[MixedInput],
    payloads: &[Vec<u8>],
    recipients: &[(Vec<u8>, u64)],
    notebook_dust_spk: &[u8],
    change_spk: &[u8],
    fee_rate: f64,
    lock_time: u32,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if recipients.len() > 255 {
        return Err(Error::Envelope("recipients: 1..=255"));
    }
    if recipients.len() <= 1 {
        let (spk, amount) = match recipients.first() {
            Some((spk, amount)) => (Some(spk.as_slice()), *amount),
            None => (None, 0),
        };
        return build_note_tx_mixed_exact_anchored(
            inputs,
            payloads,
            spk,
            amount,
            notebook_dust_spk,
            change_spk,
            fee_rate,
            lock_time,
            aux,
        );
    }
    let anchored_by_input = inputs.iter().any(|i| i.prevout_spk == notebook_dust_spk);
    build_note_tx_mixed_exact_inner_multi(
        inputs,
        payloads,
        recipients,
        notebook_dust_spk,
        change_spk,
        fee_rate,
        lock_time,
        !anchored_by_input,
        aux,
    )
}

/// Multi-recipient sibling of [`build_note_tx_mixed_exact_inner`] — same
/// fee-search loop and signing, generalized from `Option<one recipient>` to
/// a `recipients` slice. Kept as a SEPARATE function (not a refactor of the
/// existing inner) so `build_note_tx_mixed_exact`/`build_note_tx_mixed_exact_anchored`
/// are untouched by this addition; only reached via
/// [`build_note_tx_mixed_exact_anchored_multi`] for `recipients.len() >= 2`.
#[allow(clippy::too_many_arguments)]
fn build_note_tx_mixed_exact_inner_multi(
    inputs: &[MixedInput],
    payloads: &[Vec<u8>],
    recipients: &[(Vec<u8>, u64)],
    notebook_dust_spk: &[u8],
    change_spk: &[u8],
    fee_rate: f64,
    lock_time: u32,
    emit_dust: bool,
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if payloads.is_empty() {
        return Err(Error::Envelope("no payloads"));
    }
    if inputs.is_empty() {
        return Err(Error::InsufficientFunds);
    }
    if recipients.iter().any(|(_, amount)| *amount < DUST_LIMIT) {
        return Err(Error::Envelope("gift amount below dust limit"));
    }
    let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();
    let sent: u64 = recipients.iter().map(|(_, amount)| amount).sum();
    let dust: u64 = if emit_dust { DUST_LIMIT } else { 0 };
    let kinds: Vec<InputKind> = inputs.iter().map(|i| i.kind).collect();
    let in_value: u64 = inputs.iter().map(|i| i.utxo.value).sum();

    for change in [true, false] {
        let mut extra_lens: Vec<usize> = Vec::with_capacity(recipients.len() + 2);
        for (spk, _) in recipients {
            extra_lens.push(spk.len());
        }
        if emit_dust {
            extra_lens.push(notebook_dust_spk.len());
        }
        if change {
            extra_lens.push(change_spk.len());
        }
        let vsize = estimate_vsize_mixed(&kinds, &payload_lens, &extra_lens);
        let fee = (vsize as f64 * fee_rate).ceil() as u64;
        if in_value < fee + sent + dust {
            continue;
        }
        let change_value = in_value - fee - sent - dust;
        if change && change_value < DUST_LIMIT {
            continue;
        }
        if !change && change_value > DUST_LIMIT {
            // Overshoot without change would burn > dust into fees; prefer
            // the change-output branch (tried first in this loop).
            continue;
        }

        let mut outputs: Vec<TxOut> = payloads
            .iter()
            .map(|p| TxOut { value: 0, script_pubkey: op_return_script(p) })
            .collect();
        for (spk, amount) in recipients {
            outputs.push(TxOut { value: *amount, script_pubkey: spk.clone() });
        }
        if emit_dust {
            outputs.push(TxOut { value: DUST_LIMIT, script_pubkey: notebook_dust_spk.to_vec() });
        }
        if change {
            outputs.push(TxOut { value: change_value, script_pubkey: change_spk.to_vec() });
        }

        let mut tx = Transaction {
            version: 2,
            lock_time,
            inputs: inputs.iter().map(|i| i.utxo.clone()).collect(),
            outputs,
            witnesses: Vec::new(),
        };
        let prevout_spks: Vec<Vec<u8>> = inputs.iter().map(|i| i.prevout_spk.clone()).collect();
        let keys: Vec<crate::wpkh::InputKey> = inputs
            .iter()
            .map(|i| match i.kind {
                InputKind::Taproot => crate::wpkh::InputKey::Taproot { tweaked_seckey: &i.seckey },
                InputKind::P2wpkh => crate::wpkh::InputKey::P2wpkh { seckey: &i.seckey },
            })
            .collect();
        crate::wpkh::sign_mixed_inputs(&mut tx, &prevout_spks, &keys, &mut aux)?;

        let actual_fee = in_value - sent - dust - if change { change_value } else { 0 };
        return Ok(NoteTx {
            fee: actual_fee,
            change: if change { change_value } else { 0 },
            sent,
            vsize: tx.vsize(),
            txid_hex: tx.txid_hex(),
            raw_hex: hex::encode(tx.serialize_segwit()),
            spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
            tx,
        });
    }
    Err(Error::InsufficientFunds)
}

/// Build a note tx spending EXACTLY the given inputs (coin control) —
/// no automatic selection. Change (self or `change_out`) is the leftover
/// after the note payloads, optional dust recipient, and fee. Fails if
/// the inputs don't cover fee + dust.
#[allow(clippy::too_many_arguments)]
pub fn build_note_tx_exact(
    inputs: &[Utxo],
    output_x: &[u8; 32],
    payloads: &[Vec<u8>],
    recipient_spk: Option<&[u8]>,
    recipient_amount: u64,
    change_out: Option<&[u8]>,
    fee_rate: f64,
    lock_time: u32,
    tweaked_seckey: &[u8; 32],
    mut aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    if payloads.is_empty() {
        return Err(Error::Envelope("no payloads"));
    }
    if inputs.is_empty() {
        return Err(Error::InsufficientFunds);
    }
    if recipient_spk.is_some() && recipient_amount < DUST_LIMIT {
        return Err(Error::Envelope("gift amount below dust limit"));
    }
    let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();
    let sent: u64 = if recipient_spk.is_some() { recipient_amount } else { 0 };
    let change_spk = p2tr_script_pubkey(output_x);
    let change_out_spk = change_out.map(<[u8]>::to_vec).unwrap_or_else(|| change_spk.clone());
    let in_value: u64 = inputs.iter().map(|u| u.value).sum();

    // Prefer a change output; fall back to folding a sub-dust remainder
    // into the fee.
    for change in [true, false] {
        let vsize =
            estimate_vsize(inputs.len(), &payload_lens, recipient_spk.map(<[u8]>::len), change);
        let fee = (vsize as f64 * fee_rate).ceil() as u64;
        if in_value < fee + sent {
            continue;
        }
        let change_value = in_value - fee - sent;
        if change && change_value < DUST_LIMIT {
            continue;
        }
        if !change && change_value > DUST_LIMIT {
            continue;
        }

        let mut outputs: Vec<TxOut> = payloads
            .iter()
            .map(|p| TxOut { value: 0, script_pubkey: op_return_script(p) })
            .collect();
        if let Some(spk) = recipient_spk {
            outputs.push(TxOut { value: sent, script_pubkey: spk.to_vec() });
        }
        if change {
            outputs.push(TxOut { value: change_value, script_pubkey: change_out_spk.clone() });
        }

        let mut tx = Transaction {
            version: 2,
            lock_time,
            inputs: inputs.to_vec(),
            outputs,
            witnesses: Vec::new(),
        };
        let prevout_spks: Vec<Vec<u8>> = tx.inputs.iter().map(|_| change_spk.clone()).collect();
        for index in 0..tx.inputs.len() {
            let sighash = taproot_key_spend_sighash(&tx, &prevout_spks, index);
            let sig = schnorr_sign(tweaked_seckey, &sighash, &aux()?)?;
            tx.witnesses.push(vec![sig.to_vec()]);
        }
        let actual_fee = in_value - sent - if change { change_value } else { 0 };
        return Ok(NoteTx {
            fee: actual_fee,
            change: if change { change_value } else { 0 },
            sent,
            vsize: tx.vsize(),
            txid_hex: tx.txid_hex(),
            raw_hex: hex::encode(tx.serialize_segwit()),
            spent_outpoints: tx.inputs.iter().map(|i| (i.txid, i.vout)).collect(),
            tx,
        });
    }
    Err(Error::InsufficientFunds)
}
