//! Screen.change — change destination pick
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/change.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Rebuild the Pay-from screen's rows/summaries, the compose nav row's
    /// label, AND Settings' spending card (same underlying section) from
    /// `state` + the active notebook's spending section + `funding_pick`.
    /// Rebuild the compose nav row's Change label + the Change screen's
    /// "Auto" sub-line from `change_pick` + whether the CURRENT funding pick
    /// spends any spending-wallet coin.
    pub(crate) fn refresh_change(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let participates = !self.funding_pick.spending.is_empty();
        let cp = self.change_pick.clone();
        let auto_label = if participates {
            "Fresh spending-wallet address — protects the change from address reuse."
        } else {
            "Notebook address — the same address it goes to today."
        };
        ui.global::<ChangePick>().set_auto_label(auto_label.into());
        let label = match cp.choice.as_str() {
            "custom" if !cp.custom_address.is_empty() => short_addr(&cp.custom_address),
            "custom" => "custom address".to_string(),
            "notebook" => "notebook".to_string(),
            _ if participates => "fresh spending address".to_string(),
            _ => "back to you".to_string(),
        };
        ui.global::<Compose>().set_change_label(label.into());
    }


    /// Change screen (26): compose destination for change.
    pub(crate) fn on_change_open(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        self.refresh_change(&ui_weak);
    }


    /// Change screen (26): compose destination for change.
    pub(crate) fn on_change_pick(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, choice: SharedString) {
        let Some(ui) = ui_weak.upgrade() else { return };
        self.change_pick.choice = choice.to_string();
        ui.global::<ChangePick>().set_choice(choice.clone());
        ui.global::<ChangePick>().set_custom_error("".into());
        log::info!("cb: change-pick {choice}");
        self.refresh_change(&ui_weak);
        self.compose_changed(ui_weak, fs);
    }

    pub(crate) fn on_change_address_changed(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        self.change_pick.custom_address =
            ui.global::<ChangePick>().get_custom_address().to_string();
        ui.global::<ChangePick>().set_custom_error("".into());
        self.compose_changed(ui_weak, fs);
    }

    pub(crate) fn on_change_done(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(_ui) = ui_weak.upgrade() else { return };
        self.compose_changed(ui_weak, fs);
    }
}
