//! Screen.accounts — wallet context (seed index + BIP-86 account)
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/accounts.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Commit the wallet context (seed index + BIP-86 account) from the
    /// Recovery fields, then STAY on the Recovery screen (Sal 2026-07-12
    /// — Switch used to jump to the list): persist, flush the open
    /// notebook, refresh the list underneath so it's ready when the user
    /// navigates back themselves, re-derive the revealed words/SeedQR for
    /// the new seed, and show an inline saved confirmation.
    pub(crate) fn on_set_context(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let state = self.state.clone();
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
        let seed_changed = self.seed_idx != new_seed;
        let acct_changed = self.bip_account != new_acct;
        if seed_changed || acct_changed {
            if self.active.is_some() {
                save_state(&fs, &state.borrow());
                self.active = None;
            }
            self.seed_idx = new_seed;
            self.bip_account = new_acct;
            self.persist_config(&fs);
            if seed_changed {
                log::info!("cb: set-seed-index {new_seed}");
            }
            if acct_changed {
                log::info!("cb: set-account {new_acct}");
            }
            // Rebuild the (now background) notebook list for the new
            // context, and refresh the revealed words to the new seed.
            self.refresh_notebooks(&ui_weak, &fs);
            if !recovery.get_words_col1().is_empty() {
                self.reveal_words(&ui_weak);
            }
        }
        recovery.set_saved_msg(
            format!("Saved · seed {new_seed} · account {new_acct}").into(),
        );
    }
}
