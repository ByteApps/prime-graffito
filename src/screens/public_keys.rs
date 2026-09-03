//! Screen.public-keys — importable-format export
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/public-keys.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// ---- export keys (screen 23) ----
    /// Reveal the active (seed, account) context's importable formats:
    /// account xpub + tr() descriptor cover the WHOLE account (all
    /// addresses); hex + WIF are one notebook's leaf, picked from the
    /// notebook list. No private xprv on the device (the 24 words recover
    /// the whole seed). Values live in UI props only, wiped on close;
    /// never logged.
    pub(crate) fn apply_export(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, which: i32) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let r = ui.global::<Recovery>();
        let nb = r.get_export_nb_name();
        let (label, value): (String, _) = match which {
            0 => {
                ("Account xpub · all addresses · watch-only".to_string(), r.get_export_xpub())
            }
            1 => (
                "Descriptor (tr) · all addresses · watch-only".to_string(),
                r.get_export_descriptor(),
            ),
            2 => (format!("Notebook \"{nb}\" · hex"), r.get_export_hex()),
            _ => (format!("Notebook \"{nb}\" · WIF"), r.get_export_wif()),
        };
        r.set_export_which(which);
        r.set_export_label(label.into());
        r.set_export_value(value.clone());
        r.set_export_qr(qr_image(value.as_str()));
    }


    /// ---- export keys (screen 23) ----
    /// Reveal the active (seed, account) context's importable formats:
    /// account xpub + tr() descriptor cover the WHOLE account (all
    /// addresses); hex + WIF are one notebook's leaf, picked from the
    /// notebook list. No private xprv on the device (the 24 words recover
    /// the whole seed). Values live in UI props only, wiped on close;
    /// never logged.
    /// The active account's notebooks as picker rows (index/name/short addr)
    /// plus the default selection (first notebook, else a synthetic index 0).
    pub(crate) fn export_rows(&self, si: u32, acct: u32, net_s: &str, network: Network) -> (Vec<ExportNbRow>, i32, String) {
        let app_seed = self.app_seed.clone();
        let notebooks = self.notebooks.clone();
        let mut rows: Vec<ExportNbRow> = Vec::new();
        let ixb = notebooks.borrow();
        for m in ixb.visible(si, acct) {
            let addr = derive_identity(app_seed_get(&app_seed), m, net_s)
                .map(|id| id.address(network))
                .unwrap_or_default();
            let short = short_addr(&addr);
            let name = if m.name.trim().is_empty() {
                notebooks::default_name(m.index)
            } else {
                m.name.clone()
            };
            rows.push(ExportNbRow {
                index: m.index as i32,
                name: name.into(),
                addr: short.into(),
            });
        }
        let (sel, sel_name) = rows
            .first()
            .map(|r0| (r0.index, r0.name.to_string()))
            .unwrap_or((0, "index 0".to_string()));
        if rows.is_empty() {
            rows.push(ExportNbRow { index: 0, name: "index 0".into(), addr: "".into() });
        }
        (rows, sel, sel_name)
    }


    /// addresses); hex + WIF are one notebook's leaf, picked from the
    /// notebook list. No private xprv on the device (the 24 words recover
    /// the whole seed). Values live in UI props only, wiped on close;
    /// never logged.
    /// The active account's notebooks as picker rows (index/name/short addr)
    /// plus the default selection (first notebook, else a synthetic index 0).
    pub(crate) fn on_reveal_public(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let app_seed = self.app_seed.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let r = ui.global::<Recovery>();
        let si = self.seed_idx;
        let acct = self.bip_account;
        let Some(seed) = app_seed_get(&app_seed).as_ref() else {
            ui.global::<Ui>().set_error("Device locked — seed unavailable.".into());
            log::warn!("cb: reveal-public seed={si} account={acct} err=locked");
            return;
        };
        let network = Network::from_str_opt(&self.net).unwrap_or(Network::Mainnet);
        let derived = (|| -> Result<(), notes_core::Error> {
            r.set_export_xpub(notes_core::export::account_xpub(seed, si, network, acct)?.into());
            r.set_export_descriptor(
                notes_core::export::account_descriptor(seed, si, network, acct)?.into(),
            );
            Ok(())
        })();
        if let Err(e) = derived {
            ui.global::<Ui>().set_error(format!("Export failed: {e}").into());
            log::warn!("cb: reveal-public seed={si} account={acct} err={e}");
            return;
        }
        r.set_export_seed_view(false);
        r.set_export_title(export_title(seed, si, acct).into());
        self.apply_export(&ui_weak, 0);
        log::info!("cb: reveal-public seed={si} account={acct} ok");
    }

    pub(crate) fn on_export_close(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let r = ui.global::<Recovery>();
        r.set_export_xpub("".into());
        r.set_export_descriptor("".into());
        r.set_export_hex("".into());
        r.set_export_wif("".into());
        r.set_export_value("".into());
        r.set_export_label("".into());
        r.set_export_title("".into());
        r.set_export_qr(Image::default());
        r.set_export_which(0);
        r.set_export_notebooks(Rc::new(VecModel::from(Vec::<ExportNbRow>::new())).into());
        r.set_export_nb_index(0);
        r.set_export_nb_name("".into());
        // Also wipe the seed-words view (shared with reveal-seed props).
        r.set_export_seed_view(false);
        r.set_words_col1("".into());
        r.set_words_col2("".into());
        r.set_title_line("".into());
        r.set_qr(Image::default());
        r.set_show_qr(false);
        log::info!("cb: reveal-export cancelled");
    }


    /// Pick which notebook's private key hex/WIF export (hex/WIF only).
    pub(crate) fn on_export_pick_notebook(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, index: i32) {
        let app_seed = self.app_seed.clone();
        let notebooks = self.notebooks.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let r = ui.global::<Recovery>();
        let si = self.seed_idx;
        let acct = self.bip_account;
        let Some(seed) = app_seed_get(&app_seed).as_ref() else { return };
        let net_s = self.net.clone();
        let network = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
        let name = {
            let ixb = notebooks.borrow();
            let n = ixb
                .visible(si, acct)
                .find(|m| m.index as i32 == index)
                .map(|m| {
                    if m.name.trim().is_empty() {
                        notebooks::default_name(m.index)
                    } else {
                        m.name.clone()
                    }
                })
                .unwrap_or_else(|| format!("index {index}"));
            n
        };
        r.set_export_nb_index(index);
        r.set_export_nb_name(name.into());
        if let Ok((hex, wif)) = export_leaf_formats(seed, si, network, acct, index as u32) {
            r.set_export_hex(hex.into());
            r.set_export_wif(wif.into());
        }
        let which = r.get_export_which();
        if which >= 2 {
            self.apply_export(&ui_weak, which);
        }
    }
}
