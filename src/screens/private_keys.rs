//! Screen.private-keys — private-key reveal
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/private-keys.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// plus the default selection (first notebook, else a synthetic index 0).
    pub(crate) fn on_reveal_private(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let r = ui.global::<Recovery>();
        let si = self.seed_idx;
        let acct = self.bip_account;
        let Some(seed) = app_seed_get(&self.app_seed).as_ref() else {
            ui.global::<Ui>().set_error("Device locked — seed unavailable.".into());
            log::warn!("cb: reveal-private seed={si} account={acct} err=locked");
            return;
        };
        let net_s = self.net.clone();
        let network = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
        let (rows, sel, sel_name) = self.export_rows(si, acct, &net_s, network);
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
        self.reveal_words(&ui_weak);
        r.set_export_title(export_title(seed, si, acct).into());
        r.set_export_seed_view(true); // default to the seed-words view
        self.apply_export(&ui_weak, 2); // pre-load the hex value/QR for a quick pill switch
        log::info!("cb: reveal-private seed={si} account={acct} ok");
    }
}
