//! Screen.coins — wallet coins viewer + consolidate entry
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/coins.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// truth — inline DeviceConfig constructions drift as fields grow).
    /// Coins screen (9): the UTXO ledger as of the last sync bundle, biggest
    /// first. Viewer-first — consolidate is the screen's single action.
    pub(crate) fn refresh_coins(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let state = self.state.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        // Wallet-wide: every ACTIVE notebook's coins, each tagged with
        // its notebook. Flush the active notebook first so its file is
        // current, then read all from disk.
        save_state(&fs, &state.borrow());
        let ix = &self.notebooks;
        let active_net = self.net.clone();
        let ctx = (self.seed_idx, self.bip_account);
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
            let short = derive_identity(app_seed_get(&self.app_seed), m, &active_net)
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


    /// Coins → the shared sweep screen with kind=consolidate, dest=self.
    pub(crate) fn on_consolidate_open(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let sweep = ui.global::<Sweep>();
        sweep.set_kind("consolidate".into());
        sweep.set_dest("".into());
        sweep.set_dest_label("to: self — one consolidated coin".into());
        sweep.set_tier(1);
        log::info!("cb: sweep-open kind=consolidate to=self");
        self.update_sweep(&ui_weak, &fs);
        ui.global::<Ui>().set_screen(Screen::Sweep);
    }
}
