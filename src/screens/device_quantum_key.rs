//! Screen.device-quantum-key — the personal (non-seed) ML-KEM keypair
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/device-quantum-key.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {
    pub(crate) fn device_quantum_key(&mut self, fs: &Fs) -> Option<pq::MlKemKeypair> {
        if let Some(cached) = self.device_pq_key.as_ref() {
            return cached.clone();
        }
        let kp = load_device_quantum_key(fs);
        self.device_pq_key = Some(kp.clone());
        kp
    }


    /// Personal device quantum key (PLAN-graffito-quantum-key.md, screen
    /// 28) — Settings → "Quantum key…". A single, NON-seed-derived ML-KEM
    /// keypair, generated on-device (fresh TRNG mixed with optional user
    /// entropy — `pq::MlKemKeypair::generate_with_extra`) or imported,
    /// stored plain in AppData (`QUANTUM_KEY_PATH`). Distinct from the
    /// per-notebook seed-derived keys the "Quantum keys" screen above
    /// shows: this key is NOT recovered by the 24 words and dies with app
    /// uninstall — it is what makes the self-note ML-KEM compose pill
    /// (compose-changed, earlier) meaningful at all (pq.rs's module doc:
    /// encapsulating to a seed-derived receive key on a self-note is
    /// security theater, since that key shares the enc key's root).
    /// ---------------------------------------------------------------------
    pub(crate) fn refresh_device_quantum_key(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        // Bound to a local first: a `match` scrutinee's temporaries live
        // through the arms, and this one is a RefMut<App>.
        let device_kp = self.device_quantum_key(fs);
        match device_kp {
            Some(kp) => {
                dq.set_has_key(true);
                dq.set_fingerprint(kp.fingerprint().into());
                dq.set_level_name(mlkem_alg_name(kp.alg()).into());
                let armor = pq::export_public(kp.alg(), kp.ek());
                dq.set_public_qr(qr_image(&armor));
                dq.set_public_armor(armor.into());
            }
            None => {
                dq.set_has_key(false);
                dq.set_fingerprint("".into());
                dq.set_level_name("".into());
                dq.set_public_armor("".into());
                dq.set_public_qr(Image::default());
            }
        }
    }


    /// uninstall — it is what makes the self-note ML-KEM compose pill
    /// (compose-changed, earlier) meaningful at all (pq.rs's module doc:
    /// encapsulating to a seed-derived receive key on a self-note is
    /// security theater, since that key shares the enc key's root).
    /// ---------------------------------------------------------------------
    pub(crate) fn on_open_device_quantum_key(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        // Reopening always starts at the summary/generate-or-import
        // state, never wherever the last visit left off.
        dq.set_view("".into());
        dq.set_gen_level(1);
        dq.set_gen_level_caption(mlkem_alg_describe(pq::MlKemAlg::MlKem768).into());
        dq.set_gen_extra_text("".into());
        dq.set_gen_error("".into());
        dq.set_import_error("".into());
        dq.set_qr_zoom(false);
        dq.set_show_replace_confirm(false);
        dq.set_show_delete_confirm(false);
        self.refresh_device_quantum_key(&ui_weak, &fs);
    }

    pub(crate) fn on_device_quantum_key_close(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        // Wipe the sensitive private-key view (armor + QR) on the way
        // out — never lingers in a UI prop after the screen closes,
        // same hygiene as reveal-close/export-close.
        dq.set_private_armor("".into());
        dq.set_private_qr(Image::default());
        dq.set_view("".into());
        dq.set_qr_zoom(false);
    }

    pub(crate) fn on_device_quantum_key_gen_level(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, level_idx: i32) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        let alg = match level_idx {
            0 => pq::MlKemAlg::MlKem512,
            2 => pq::MlKemAlg::MlKem1024,
            _ => pq::MlKemAlg::MlKem768,
        };
        dq.set_gen_level(level_idx);
        dq.set_gen_level_caption(mlkem_alg_describe(alg).into());
    }

    pub(crate) fn on_device_quantum_key_generate(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        let alg = match dq.get_gen_level() {
            0 => pq::MlKemAlg::MlKem512,
            2 => pq::MlKemAlg::MlKem1024,
            _ => pq::MlKemAlg::MlKem768,
        };
        let extra = dq.get_gen_extra_text().to_string();
        let result = pq::MlKemKeypair::generate_with_extra(alg, extra.as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|kp| save_device_quantum_key(&fs, kp.alg(), kp.seed()).map(|_| kp));
        match result {
            Ok(kp) => {
                self.device_pq_key = Some(Some(kp));
                dq.set_gen_error("".into());
                dq.set_gen_extra_text("".into());
                log::info!("cb: quantum-key generate level={} ok", mlkem_alg_name(alg));
                self.refresh_device_quantum_key(&ui_weak, &fs);
            }
            Err(e) => {
                log::warn!("cb: quantum-key generate level={} err={e}", mlkem_alg_name(alg));
                dq.set_gen_error(format!("Couldn't generate a key: {e}").into());
            }
        }
    }

    pub(crate) fn on_device_quantum_key_import(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        let opts = ScanQrOptions {
            header_title: "Import quantum key".into(),
            message: "Point at an armored GRAFFITO ML-KEM PRIVATE KEY QR — from a backup, \
                      this device's own export, or the graffito Mac app."
                .into(),
            ..ScanQrOptions::default()
        };
        let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
            Ok(Some(ScanQrResult::Qr { data, .. })) | Ok(Some(ScanQrResult::Ur2 { data, .. })) => {
                data
            }
            Ok(_) => {
                log::info!("cb: quantum-key import cancelled");
                return;
            }
            Err(e) => {
                log::warn!("cb: quantum-key import err=scanner {e:?}");
                dq.set_import_error(format!("QR scanner unavailable: {e:?}").into());
                return;
            }
        };
        let armor = String::from_utf8(data).unwrap_or_default();
        match pq::import_private(&armor) {
            Ok((alg, seed)) => match save_device_quantum_key(&fs, alg, &seed) {
                Ok(()) => {
                    self.device_pq_key =
                        Some(Some(pq::MlKemKeypair::from_seed(alg, &seed)));
                    dq.set_import_error("".into());
                    log::info!("cb: quantum-key import ok");
                    self.refresh_device_quantum_key(&ui_weak, &fs);
                }
                Err(e) => {
                    log::warn!("cb: quantum-key import err={e}");
                    dq.set_import_error(format!("Couldn't save the key: {e}").into());
                }
            },
            Err(e) => {
                // A clearer message for the common mix-up: scanning a
                // PUBLIC key armor (this screen's own "Share public
                // key" QR, or a contact's) instead of a private one.
                let msg = if pq::import_public(&armor).is_ok() {
                    "That's a PUBLIC quantum key — this needs the PRIVATE key armor \
                     instead (\"Export private key…\" on the device that holds it)."
                        .to_string()
                } else {
                    format!("Not a private quantum key: {e}")
                };
                log::warn!("cb: quantum-key import err={e}");
                dq.set_import_error(msg.into());
            }
        }
    }

    pub(crate) fn on_device_quantum_key_reveal_private(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        let device_kp = self.device_quantum_key(fs);
        let Some(kp) = device_kp else {
            // Shouldn't be reachable (the button only shows when
            // has-key is true) — fail safe back to the summary view.
            dq.set_view("".into());
            return;
        };
        let armor = pq::export_private(kp.alg(), kp.seed());
        dq.set_private_armor(armor.clone().into());
        if qr_fits(&armor) {
            dq.set_private_fits_qr(true);
            dq.set_private_qr(qr_image(&armor));
        } else {
            // Never reachable in practice — a private armor is always
            // a fixed 66-byte payload regardless of level — but this
            // is the same size guard `qr_image` needs everywhere else
            // (it panics past capacity), so it stays generic rather
            // than assuming the current sizes forever.
            dq.set_private_fits_qr(false);
            dq.set_private_qr(Image::default());
        }
        dq.set_view("private".into());
        log::info!("cb: quantum-key export-private ok fp={}", kp.fingerprint());
    }

    pub(crate) fn on_device_quantum_key_hide_private(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        dq.set_private_armor("".into());
        dq.set_private_qr(Image::default());
        dq.set_view("".into());
        dq.set_qr_zoom(false);
    }

    pub(crate) fn on_device_quantum_key_replace_confirm(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        // "Replace…" = delete the current key, then land back on the
        // generate/import state — the confirm dialog is what named the
        // consequence (notes sealed to it become unreadable) before
        // this ran.
        if let Err(e) = delete_device_quantum_key(fs) {
            log::warn!("cb: quantum-key replace err={e}");
        }
        self.device_pq_key = Some(None);
        dq.set_show_replace_confirm(false);
        dq.set_view("".into());
        dq.set_private_armor("".into());
        dq.set_private_qr(Image::default());
        dq.set_gen_level(1);
        dq.set_gen_level_caption(mlkem_alg_describe(pq::MlKemAlg::MlKem768).into());
        dq.set_gen_extra_text("".into());
        log::info!("cb: quantum-key replace ok");
        self.refresh_device_quantum_key(&ui_weak, &fs);
    }

    pub(crate) fn on_device_quantum_key_delete_confirm(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let dq = ui.global::<DeviceQuantumKey>();
        if let Err(e) = delete_device_quantum_key(fs) {
            log::warn!("cb: quantum-key delete err={e}");
        }
        self.device_pq_key = Some(None);
        dq.set_show_delete_confirm(false);
        dq.set_view("".into());
        dq.set_private_armor("".into());
        dq.set_private_qr(Image::default());
        log::info!("cb: quantum-key delete ok");
        self.refresh_device_quantum_key(&ui_weak, &fs);
    }

    pub(crate) fn on_device_quantum_key_qr_zoom(&self, open: bool) {
        log::info!("cb: quantum-key qr-zoom={}", if open { "open" } else { "closed" });
    }
}
