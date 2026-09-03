//! Screen.compose — draft, cost line, pq layers, Continue (compose_continue is the money path)
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/compose.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Rebuild the notebook list (screen 20) from the index + each
    /// notebook's state file. Device has no live balance — the row meta is
    /// address-short · note count.
    /// Open a notebook: save the current one, swap identity + state to the
    /// target account, refresh every per-notebook view, and show its home.
    /// The single pick funnel (self row / recent row / manual entry / scan):
    /// validates, bumps recency, sets the compose recipient + label, and
    /// navigates. Invalid manual input stays on the picker with an error.
    /// Keystroke cost estimator — pure arithmetic, no crypto runs (see
    /// notes-core crypt::SEAL_OVERHEAD), so per-keystroke recompute is free.
    pub(crate) fn compose_changed(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let compose = ui.global::<Compose>();
        let st = &self.state;
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
            device_quantum_key_in(&mut self.device_pq_key, fs)
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
            && self.pq_generated.as_deref() == Some(pq_passphrase_text.as_str());
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
            self.compose_oversize = false; // clearing the draft re-arms the dialog
            return;
        }
        let ix = &self.notebooks;
        let ctx = notebook_ctx(&ix, self.active)
            .unwrap_or((self.seed_idx, self.bip_account));
        let net_s = self.net.clone();
        let section = ix.spending(&net_s, ctx.0, ctx.1).cloned();
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
            let was_oversize = std::mem::replace(&mut self.compose_oversize, true);
        if !was_oversize {
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
        self.compose_oversize = false;

        let pick = self.funding_pick.clone();
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
        let cp = self.change_pick.clone();
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
    }

    /// Compose's "+ Add recipient" row — opens the contacts picker in
    /// append mode (Contacts.picking-extra), modeled on how the home
    /// screen's "Compose note" button opens it in replace mode.
    pub(crate) fn on_add_recipient_open(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        ui.global::<Contacts>().set_picking_extra(true);
        ui.global::<Contacts>().set_pick_mode("compose".into());
        self.refresh_contacts(ui_weak);
        ui.global::<Ui>().set_screen(Screen::Contacts);
    }


    /// Drop an address from Compose.to-extra — no navigation.
    pub(crate) fn on_remove_recipient(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, addr: SharedString) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let compose = ui.global::<Compose>();
        let kept: Vec<ToRow> =
            compose.get_to_extra().iter().filter(|r| r.address != addr).collect();
        compose.set_to_extra(Rc::new(VecModel::from(kept)).into());
        log::info!("cb: remove-recipient addr={addr}");
    }


    /// Post-quantum Security section: a typed edit un-certifies the
    /// passphrase (compose-changed recomputes `pq-passphrase-verified`
    /// from `pq_generated` vs. the current text) — this callback is just
    /// the "recompute now" trigger `edited` fires, same shape as every
    /// other compose field's `edited => { Callbacks.compose-changed(); }`.
    pub(crate) fn on_pq_passphrase_changed(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(_ui) = ui_weak.upgrade() else { return };
        self.compose_changed(ui_weak, fs);
    }

    pub(crate) fn on_pq_generate_passphrase(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        match passphrase::generate() {
            Ok(phrase) => {
                ui.global::<Compose>().set_pq_passphrase_text(phrase.clone().into());
                self.pq_generated = Some(phrase);
                log::info!("cb: pq-generate bits={:.0}", passphrase::GENERATED_BITS);
                self.compose_changed(ui_weak, fs);
            }
            Err(e) => {
                log::warn!("cb: pq-generate err={e}");
            }
        }
    }


    /// Compose "too large" dialog → raise the chunk size to Standard (auto) and
    /// reprice the draft in place. Only offered when the note fits at Standard.
    pub(crate) fn on_oversize_bump(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        {
            let st = &mut self.state;
            st.chunk_override = None; // Standard / auto = DEFAULT_CHUNK
            save_state(&fs, &st);
        }
        log::info!("cb: set-chunk-size auto ok (oversize-bump)");
        let compose = ui.global::<Compose>();
        compose.set_show_oversize(false);
        ui.global::<Settings>().set_chunk_mode(0); // mirror into the settings pill
        self.compose_changed(ui_weak, fs);
    }

    /// Pure motion from app_main (phase 4b cluster d): the money path keeps
    /// its `Rc` handle because the work runs in a deferred `Timer` body;
    /// every `app.borrow()` inside is byte-identical to the callback it was.
    pub(crate) fn on_compose_continue(app: &Rc<RefCell<App>>, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        ui.global::<Ui>().set_busy(true);
        let ui_weak = ui_weak.clone();
        let app = app.clone();
        let fs = fs.clone();
        // Let the busy overlay paint one frame before the blocking work.
        let app = app.clone();
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
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
            // `a` is held for the whole identity + state span (Identity is not
            // Clone): nothing below may `app.borrow_mut()` until `drop(a)`.
            let a = app.borrow();
            let st = &a.state;
            let id_guard = &a.identity;
            let pick = a.funding_pick.clone();
            let change_choice = app.borrow().change_pick.clone();
            let ix = &a.notebooks;
            let ctx = notebook_ctx(&ix, app.borrow().active)
                .unwrap_or((app.borrow().seed_idx, app.borrow().bip_account));
            let net_s = app.borrow().net.clone();
            let section = ix.spending(&net_s, ctx.0, ctx.1).cloned();

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
                            // peek, not the caching lookup: `a` (a shared App borrow) is live here
                            let kp = a.device_quantum_key_peek(&fs).ok_or(
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
                            let app_seed_copy = *app_seed_get(&app.borrow().app_seed);
                        // Byte-identical input selection to before this
                        // feature — change destination is still
                        // independently resolvable (the picker screen).
                        let (change_spk, _) = resolve_change(
                            &change_choice.choice,
                            &change_choice.custom_address,
                            st.network(),
                            &id.output_x,
                            false,
                            &*app_seed_copy.as_ref().ok_or("identity unavailable")?,
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
                                resolve_locktime(app.borrow().lock_policy, st.tip_height),
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
                                resolve_locktime(app.borrow().lock_policy, st.tip_height),
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
                                resolve_locktime(app.borrow().lock_policy, st.tip_height),
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
                                resolve_locktime(app.borrow().lock_policy, st.tip_height),
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
                            let app_seed_copy = *app_seed_get(&app.borrow().app_seed);
                        let (change_spk, _) = resolve_change(
                            &change_choice.choice,
                            &change_choice.custom_address,
                            st.network(),
                            &id.output_x,
                            false,
                            &*app_seed_copy.as_ref().ok_or("identity unavailable")?,
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
                                resolve_locktime(app.borrow().lock_policy, st.tip_height),
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
                                resolve_locktime(app.borrow().lock_policy, st.tip_height),
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
                                resolve_locktime(app.borrow().lock_policy, st.tip_height),
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
                                resolve_locktime(app.borrow().lock_policy, st.tip_height),
                                || generate_aux_rand(),
                            )
                        }
                        .map_err(|e| e.to_string())?;
                        Ok((note, Vec::new(), None, change_is_notebook, false, pq_flags_out))
                    } else {
                            let app_seed_copy = *app_seed_get(&app.borrow().app_seed);
                        // Spending-wallet participates (pure spending or
                        // mixed with notebook coins) — mixed builder. The
                        // notebook dust-to-self anchor is emitted ONLY
                        // when no notebook coin is among the selected
                        // inputs (`build_note_tx_mixed_exact_anchored`'s
                        // skip condition, funding-unification
                        // 2026-07-18) — a notebook input already anchors
                        // the tx to the notebook's address history.
                        let seed: &[u8; 32] =
                            &*app_seed_copy.as_ref().ok_or("identity unavailable")?;
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
                            resolve_locktime(app.borrow().lock_policy, st.tip_height),
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
                    let active_acct = app.borrow().active.unwrap_or(0);
                    let ix = &a.notebooks;
                    let active_name = {
                        let short = id_guard
                            .as_ref()
                            .map(|id| short_addr(&id.address(st.network())))
                            .unwrap_or_default();
                        notebook_name(&ix, active_acct, &short)
                    };
                    let (mut self_spks, mut spending_spks) =
                        confirm_self_spks(&ix, app_seed_get(&app.borrow().app_seed), &net_s, ctx);
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
                                    let app_seed_copy = *app_seed_get(&app.borrow().app_seed);
                                    let seed_bytes = app_seed_copy.as_ref()?;
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
                            drop(a);
                            app.borrow_mut().plan = Some(Plan {
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
    }
}
