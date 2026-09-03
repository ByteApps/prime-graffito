//! Screen.recovery-words — 24-word / SeedQR reveal
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/recovery-words.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// ---- recovery seeds (screen 21 + wallet context) ----
    /// Derive the ACTIVE seed's 24 words + SeedQR into the Recovery props.
    /// Everything is re-derived on demand and lives only in UI properties
    /// until reveal-close wipes them; nothing is persisted or logged. Shared
    /// by the reveal button AND the Switch action (which refreshes the words
    /// to the new seed while they're shown). Keeps the SeedQR in sync.
    pub(crate) fn reveal_words(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let recovery = ui.global::<Recovery>();
        let index = self.seed_idx;
        let Some(seed) = app_seed_get(&self.app_seed).as_ref() else {
            ui.global::<Ui>().set_error("Device locked — seed unavailable.".into());
            log::warn!("cb: reveal-seed index={index} err=locked");
            return;
        };
        let entropy = notes_core::keys::derive_seed_entropy(seed, index);
        let words = match notes_core::bip39::entropy_to_mnemonic(&entropy) {
            Ok(w) => w,
            Err(e) => {
                ui.global::<Ui>().set_error(format!("Derivation failed: {e}").into());
                log::warn!("cb: reveal-seed index={index} err={e}");
                return;
            }
        };
        let list: Vec<&str> = words.split_whitespace().collect();
        let col = |range: std::ops::Range<usize>| -> String {
            range
                .map(|i| format!("{:2}. {}", i + 1, list[i]))
                .collect::<Vec<_>>()
                .join("\n")
        };
        recovery.set_words_col1(col(0..12).into());
        recovery.set_words_col2(col(12..24).into());
        // Standard SeedQR: the 4-digit wordlist indices, concatenated.
        let digits: String = notes_core::bip39::entropy_to_indices(&entropy)
            .unwrap_or_default()
            .iter()
            .map(|i| format!("{i:04}"))
            .collect();
        recovery.set_qr(qr_image(&digits));
        recovery.set_show_qr(false);
        recovery.set_title_line(format!("Seed {index} · 24 words").into());
        log::info!("cb: reveal-seed index={index} ok");
    }


    /// to the new seed while they're shown). Keeps the SeedQR in sync.
    pub(crate) fn on_reveal_close(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let recovery = ui.global::<Recovery>();
        recovery.set_words_col1("".into());
        recovery.set_words_col2("".into());
        recovery.set_title_line("".into());
        recovery.set_qr(Image::default());
        recovery.set_show_qr(false);
        log::info!("cb: reveal-seed cancelled");
    }
}
