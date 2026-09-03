//! Screen.sweep — sweep / consolidate (money path)
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/sweep.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {
    /// Persist the device config from the current cells (single source of
    /// truth — inline DeviceConfig constructions drift as fields grow).
    /// Coins screen (9): the UTXO ledger as of the last sync bundle, biggest
    /// first. Viewer-first — consolidate is the screen's single action.
    /// Sweep screen (10) repricing — every tier tap / rate keystroke. Pure
    /// arithmetic (estimate_sweep_vsize is byte-exact vs build_sweep_tx).
    pub(crate) fn update_sweep(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let state = self.state.clone();
        let notebooks = self.notebooks.clone();
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
            (self.seed_idx, self.bip_account),
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


    /// Build + sign the sweep (ALL coins, key-path), then the confirm dialog.
    /// Pure motion from app_main (phase 4b cluster d): the money path keeps
    /// its `Rc` handle because the work runs in a deferred `Timer` body;
    /// every `app.borrow()` inside is byte-identical to the callback it was.
    pub(crate) fn on_sweep_continue(app: &Rc<RefCell<App>>, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
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
            let state = app.borrow().state.clone();
            let identity = app.borrow().identity.clone();
            let notebooks = app.borrow().notebooks.clone();
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
                app_seed_get(&app.borrow().app_seed),
                &st.network,
                (app.borrow().seed_idx, app.borrow().bip_account),
            );
            let dest_account = app.borrow().active.unwrap_or(0);
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
                        resolve_locktime(app.borrow().lock_policy, st.tip_height),
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
                        confirm_self_spks(&ix, app_seed_get(&app.borrow().app_seed), &st.network, (app.borrow().seed_idx, app.borrow().bip_account));
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
                            app.borrow_mut().sweep_plan = Some(SweepPlan {
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
    }
}
