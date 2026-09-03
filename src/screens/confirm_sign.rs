//! Screen.confirm-sign — the universal confirm gate: Sign / Cancel (money path)
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/confirm-sign.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Back from the universal Confirm & sign screen (4): discard whatever
    /// was staged (Plan/SweepPlan/the stashed Psbt) and clear the shown
    /// rows, then return to the kind's origin screen.
    pub(crate) fn on_confirm_cancel(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let kind = ui.global::<ConfirmSign>().get_kind().to_string();
        log::info!("cb: confirm cancel kind={kind}");
        self.plan = None;
        self.sweep_plan = None;
        self.psbt_pending = None;
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
            "sweep" | "consolidate" => Screen::Sweep,
            "psbt" => Screen::Sync,
            _ => Screen::Compose,
        };
        ui.global::<Ui>().set_screen(back);
    }


    /// Universal Confirm & sign gate (screen 4) — dispatches on
    /// ConfirmSign.kind to the three sign bodies (each was its own
    /// dedicated callback before the confirm-gate refactor; merged here so
    /// Sign always fires through one place, no callback-from-callback
    /// re-entrancy). Ledger/outbox mutations happen ONLY past this point.
    /// Pure motion from app_main (phase 4b cluster d): the money path keeps
    /// its `Rc` handle because the work runs in a deferred `Timer` body;
    /// every `app.borrow()` inside is byte-identical to the callback it was.
    pub(crate) fn on_confirm_sign(app: &Rc<RefCell<App>>, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let identity = app.borrow().identity.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let kind = ui.global::<ConfirmSign>().get_kind().to_string();
        let txid = ui.global::<ConfirmSign>().get_txid().to_string();
        log::info!("cb: confirm sign kind={kind} txid={txid}");
        match kind.as_str() {
            "sweep" | "consolidate" => {
                let Some(p) = app.borrow_mut().sweep_plan.take() else { return };
                ui.global::<Ui>().set_busy(true);
                let ui_weak = ui_weak.clone();
                let fs = fs.clone();
                let app = app.clone();
                Timer::single_shot(Duration::from_millis(150), move || {
                    let state = app.borrow().state.clone();
                    let Some(ui) = ui_weak.upgrade() else { return };
                    let mut st = state.borrow_mut();
                    let active_acct = app.borrow().active.unwrap_or(p.dest_account);

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
                            let mut other = load_state(&fs, &app.borrow().net, *acct);
                            other.utxos.retain(|u| !spent.contains(&(u.txid.clone(), u.vout)));
                            save_state(&fs, &other);
                        }
                    }
                    if p.kind == "consolidate" {
                        let coin = UtxoRec { txid: p.tx.txid_hex.clone(), vout: 0, value: recv };
                        if p.dest_account == active_acct {
                            st.utxos.push(coin);
                        } else {
                            let mut dest = load_state(&fs, &app.borrow().net, p.dest_account);
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
                    sp.set_back_screen(Screen::Home);

                    // Reset the sweep flow so nothing leaks into the next run.
                    let sweep = ui.global::<Sweep>();
                    sweep.set_dest("".into());
                    sweep.set_dest_label("".into());
                    sweep.set_tier(1);
                    sweep.set_cost_line("".into());
                    sweep.set_can_continue(false);
                    ui.global::<Contacts>().set_pick_mode("compose".into());

                    ui.global::<Ui>().set_busy(false);
                    app.borrow().refresh_home(&ui_weak);
                    ui.global::<Ui>().set_screen(Screen::Signed);
                });
            }
            "psbt" => {
                let Some(psbt) = app.borrow_mut().psbt_pending.take() else { return };
                let id_guard = identity.borrow();
                let Some(id) = id_guard.as_ref() else {
                    drop(id_guard);
                    ui.global::<Sync>().set_result("Device locked — no signing key.".into());
                    ui.global::<Ui>().set_screen(Screen::Sync);
                    return;
                };
                let output_x = id.output_x;
                let tweaked_seckey = id.tweaked_seckey;
                drop(id_guard);
                ui.global::<Ui>().set_busy(true);
                let ui_weak = ui_weak.clone();
                let fs = fs.clone();
                let mut psbt = psbt;
                let ui_weak = ui_weak.clone();
                let fs = fs.clone();
                Timer::single_shot(Duration::from_millis(150), move || {
                    let Some(ui) = ui_weak.upgrade() else { return };
                    let (ours, signed) =
                        match psbt.sign_own_taproot(&output_x, &tweaked_seckey, generate_aux_rand) {
                            Ok(x) => x,
                            Err(e) => {
                                ui.global::<Ui>().set_busy(false);
                                ui.global::<Sync>().set_result(format!("Sign failed: {e}").into());
                                ui.global::<Ui>().set_screen(Screen::Sync);
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
                    ui.global::<Ui>().set_screen(Screen::Signed);
                });
            }
            _ => {
                // "compose" — the default arm.
                let Some(p) = app.borrow_mut().plan.take() else { return };
                ui.global::<Ui>().set_busy(true);
                let ui_weak = ui_weak.clone();
                let fs = fs.clone();
                let app = app.clone();
                Timer::single_shot(Duration::from_millis(150), move || {
                    let state = app.borrow().state.clone();
                    let notebooks = app.borrow().notebooks.clone();
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
                        let ctx = notebook_ctx(&ix, app.borrow().active)
                            .unwrap_or((app.borrow().seed_idx, app.borrow().bip_account));
                        let net_s = app.borrow().net.clone();
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
                    app.borrow().refresh_funding(&ui_weak);

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
                    app.borrow_mut().funding_pick = FundingPick::default();
                    app.borrow_mut().change_pick = ChangePickState::default();
                    ui.global::<ChangePick>().set_choice("auto".into());
                    ui.global::<ChangePick>().set_custom_address("".into());
                    ui.global::<Ui>().set_busy(false);
                    app.borrow().refresh_notes(&ui_weak);
                    ui.global::<Ui>().set_screen(Screen::Note);
                });
            }
        }
    }
}
