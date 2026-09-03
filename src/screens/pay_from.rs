//! Screen.pay-from — per-coin funding pick
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/pay-from.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Rebuild the Pay-from screen's rows/summaries, the compose nav row's
    /// label, AND Settings' spending card (same underlying section) from
    /// `state` + the active notebook's spending section + `funding_pick`.
    pub(crate) fn refresh_funding(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let state = self.state.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let st = state.borrow();
        let active_net = self.net.clone();
        let ix = &self.notebooks;
        let ctx = notebook_ctx(&ix, self.active)
            .unwrap_or((self.seed_idx, self.bip_account));
        let section = ix.spending(&active_net, ctx.0, ctx.1).cloned();
        let pick = self.funding_pick.clone();

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
            if let Some(seed) = app_seed_get(&self.app_seed).as_ref() {
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


    /// Pay-from screen (25): notebook / spending-wallet per-coin selection.
    pub(crate) fn on_funding_open(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        log::info!("cb: funding-open");
        self.refresh_funding(&ui_weak);
    }


    /// Pay-from screen (25): notebook / spending-wallet per-coin selection.
    pub(crate) fn on_funding_toggle_coin(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, key: SharedString) {
        let Some(_ui) = ui_weak.upgrade() else { return };
        if let Some((spending_src, txid, vout)) = parse_funding_key(key.as_str()) {
            self.funding_pick.toggle(spending_src, txid, vout);
        }
        self.refresh_funding(&ui_weak);
        self.refresh_change(&ui_weak);
        self.compose_changed(ui_weak, fs);
    }

    pub(crate) fn on_funding_done(&self) {
        let pick = self.funding_pick.clone();
        log::info!(
            "cb: pay-from {} coins={}",
            pick.mode_label(),
            pick.notebook.len() + pick.spending.len()
        );
    }
}
