//! Honest-fee-label prediction: whether a FIXED, already-known coin
//! selection will fold a sub-dust leftover into the fee instead of paying
//! it out as a discretionary change output — the with-change/no-change
//! decision every builder in `tx.rs` makes
//! (`build_note_tx_with_change`/`_exact`, `build_note_tx_mixed_exact`/
//! `_anchored`: `if !change && change_value > DUST_LIMIT { continue }`,
//! i.e. a leftover too small to be its own output rides along on top of
//! the fee instead). Without a UI split, a tiny selection's fee reads as
//! unexplainably high (Sal hit this on testnet4: a single 330-sat coin
//! composed a valid tx whose whole value went to "fee").
//!
//! Ported from the graffito desktop app's `app-core/src/mixed.rs`
//! (`predict_fold`/`predict_notebook_fold`/`predict_funded_fold`,
//! 2026-07-18) onto THIS crate's own estimators, so the Prime device shows
//! the identical honest split its Mac/mobile sibling does. Pure
//! prediction only — nothing here builds or signs a transaction; every
//! function is pin-tested in `tests/fold.rs` against this crate's real
//! builders so the split shown before signing always matches what the
//! signed tx actually pays.

use crate::tx::{estimate_vsize_mixed, InputKind};
use crate::DUST_LIMIT;

/// The shared with-change/no-change decision every builder in `tx.rs`
/// makes, for a FIXED selection (`in_value` already known — no coin-set
/// growing, matching every device call site: coin control always composes
/// from an exact, already-selected set). `fixed_out` is every non-change
/// output value that ISN'T change (recipient/gift amount, notebook dust
/// anchor — whichever apply). `fee_with_change`/`fee_no_change` are the
/// byte-true fees for the two shapes at the caller's chosen rate (from
/// `estimate_vsize`/`estimate_vsize_mixed`).
///
/// Returns `Some((nominal, folded))` exactly when the no-change shape is
/// what a real build would take: `nominal` is the real fee for that
/// shape, `folded` is the sub-dust leftover riding along on top of it (so
/// `nominal + folded` is the byte-true total fee the signed tx pays).
/// `None` when a change output is affordable, or nothing folds (leftover
/// is exactly zero — an exact-fit selection, not a fold).
///
/// `cap_at_dust`: every builder in this crate's `tx.rs` refuses a
/// no-change leftover ABOVE dust (`if !change && change_value >
/// DUST_LIMIT { continue }`, in both `build_note_tx_with_change`/`_exact`
/// and `build_note_tx_mixed_exact_inner`) — for a FIXED selection that
/// means the real build would simply fail (`Err(InsufficientFunds)`)
/// rather than fold an oversized leftover, so every wrapper below passes
/// `true`. The parameter is kept explicit (rather than hardcoded) so a
/// future builder without that ceiling doesn't have to duplicate this
/// function, matching the graffito desktop app's `app_core::mixed::predict_fold`
/// API shape.
pub fn predict_fold(
    in_value: u64,
    fixed_out: u64,
    fee_with_change: u64,
    fee_no_change: u64,
    cap_at_dust: bool,
) -> Option<(u64, u64)> {
    if in_value >= fixed_out.saturating_add(fee_with_change) {
        let change_wc = in_value - fixed_out - fee_with_change;
        if change_wc >= DUST_LIMIT {
            return None; // a change output is affordable — no fold
        }
    }
    if in_value < fixed_out.saturating_add(fee_no_change) {
        return None; // can't even afford the no-change shape
    }
    let leftover = in_value - fixed_out - fee_no_change;
    if leftover == 0 {
        return None; // exact fit — nothing folds
    }
    if cap_at_dust && leftover > DUST_LIMIT {
        return None; // the real (fixed-selection) build would refuse this shape
    }
    Some((fee_no_change, leftover))
}

/// The exact vsize a notebook (pure key-path taproot) note tx would have
/// WITHOUT its discretionary change output, derived algebraically from the
/// WITH-CHANGE vsize (e.g. `estimate_vsize(.., true)`'s result): weight is
/// exactly linear in whether the change output is present (8-byte value +
/// a 1-byte length varint + the script itself — every change script this
/// predictor is used for is well under the 253-byte varint threshold,
/// same assumption `estimate_vsize` itself makes for its hardcoded 34-byte
/// P2TR change), so subtracting an integer before or after
/// `ceil(weight/4)` gives the same vsize. This is an EXACT match for
/// calling `estimate_vsize(.., false)` directly, not an approximation —
/// `predict_notebook_fold_matches_build_note_tx_exact` proves the two
/// agree.
pub fn notebook_vsize_no_change(vsize_with_change: usize, change_len: usize) -> usize {
    vsize_with_change.saturating_sub(9 + change_len) // 8 (value) + 1 (length varint) + script bytes
}

/// [`predict_fold`] for the notebook (pure self-funded taproot) shape —
/// `build_note_tx_with_change`/`_exact`. `vsize_with_change` mirrors
/// `estimate_vsize(n_inputs, payload_lens, recipient_spk_len, true)`;
/// `sent` is the recipient/gift amount (0 for a self-note).
pub fn predict_notebook_fold(
    in_value: u64,
    sent: u64,
    vsize_with_change: usize,
    change_len: usize,
    fee_rate: f64,
) -> Option<(u64, u64)> {
    let vsize_no_change = notebook_vsize_no_change(vsize_with_change, change_len);
    let fee_wc = (vsize_with_change as f64 * fee_rate).ceil().max(0.0) as u64;
    let fee_nc = (vsize_no_change as f64 * fee_rate).ceil().max(0.0) as u64;
    predict_fold(in_value, sent, fee_wc, fee_nc, true)
}

/// [`predict_fold`] for the mixed/coin-control shape (device "Pay from"
/// coin control — pure notebook subset, pure spending-wallet, or a mix of
/// both) — `build_note_tx_mixed_exact`/`_anchored`. Unlike
/// the graffito desktop app's `app-core` (a separate crate that has to re-derive an
/// `estimate_funded_fee`/`_no_change` pair), this crate already exposes
/// [`estimate_vsize_mixed`] with an explicit extra-output-length list, so
/// the with-change/no-change fee pair is simply two calls to the SAME
/// estimator, with and without `change_len` appended to
/// `fixed_extra_lens`. `fixed_extra_lens` is every NON-change extra output
/// length (in output order) — the optional recipient spk and/or the
/// notebook dust-to-self spk, exactly as the caller would pass to
/// `estimate_vsize_mixed` for the no-change shape; `fixed_out` is those
/// same outputs' VALUES summed (recipient/gift amount + notebook dust,
/// whichever apply).
#[allow(clippy::too_many_arguments)]
pub fn predict_mixed_fold(
    kinds: &[InputKind],
    payload_lens: &[usize],
    fixed_extra_lens: &[usize],
    change_len: usize,
    in_value: u64,
    fixed_out: u64,
    fee_rate: f64,
) -> Option<(u64, u64)> {
    let mut lens_wc: Vec<usize> = Vec::with_capacity(fixed_extra_lens.len() + 1);
    lens_wc.extend_from_slice(fixed_extra_lens);
    lens_wc.push(change_len);
    let vsize_wc = estimate_vsize_mixed(kinds, payload_lens, &lens_wc);
    let vsize_nc = estimate_vsize_mixed(kinds, payload_lens, fixed_extra_lens);
    let fee_wc = (vsize_wc as f64 * fee_rate).ceil().max(0.0) as u64;
    let fee_nc = (vsize_nc as f64 * fee_rate).ceil().max(0.0) as u64;
    predict_fold(in_value, fixed_out, fee_wc, fee_nc, true)
}
