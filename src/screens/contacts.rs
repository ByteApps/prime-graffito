//! Screen.contacts — send-to picker, scan, naming
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/contacts.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Persist the device config from the current cells (single source of
    /// truth — inline DeviceConfig constructions drift as fields grow).
    pub(crate) fn refresh_contacts(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let st = &self.state;
        // State order IS recency (front = latest use) — no re-sort.
        let rows: Vec<ContactRow> = st
            .contacts
            .iter()
            .map(|c| ContactRow {
                address: c.address.clone().into(),
                name: c.name.clone().into(),
                label: if c.name.is_empty() { short_addr(&c.address) } else { c.name.clone() }
                    .into(),
                meta: short_addr(&c.address).into(),
                pq_caption: c
                    .mlkem_ek
                    .as_deref()
                    .map(contact_pq_caption)
                    .unwrap_or_default()
                    .into(),
            })
            .collect();
        log::info!("cb: refresh-contacts n={}", rows.len());
        ui.global::<Contacts>().set_rows(Rc::new(VecModel::from(rows)).into());
    }

    pub(crate) fn pick_contact(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, addr_raw: &str) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let addr = addr_raw.trim().to_string();
        let contacts_g = ui.global::<Contacts>();
        let sweep_mode = contacts_g.get_pick_mode() == "sweep";
        let compose = ui.global::<Compose>();

        // Appending an EXTRA recipient to an in-progress directed draft
        // (Callbacks.add-recipient-open set this) — pushes onto
        // Compose.to-extra instead of replacing the primary, and does
        // NOT touch funding/change picks or navigate anywhere but back
        // to compose (this is editing a draft, not starting a fresh
        // one — unlike the replace path below, which intentionally
        // resets those for a brand-new compose target).
        if !sweep_mode && contacts_g.get_picking_extra() {
            if addr.is_empty() {
                contacts_g
                    .set_input_error("Can't add yourself as an extra recipient.".into());
                log::warn!("cb: pick-contact err=self extra=true");
                return;
            }
            let st = &mut self.state;
            if Recipient::parse(st.network(), &addr).is_err() {
                contacts_g
                    .set_input_error(format!("Not a valid {} address.", st.network).into());
                log::warn!("cb: pick-contact err=invalid address extra=true");
                return;
            }
            let primary = compose.get_to_address().to_string();
            let current_extra: Vec<ToRow> = compose.get_to_extra().iter().collect();
            if addr == primary || current_extra.iter().any(|r| r.address == addr) {
                contacts_g.set_input_error("Already a recipient of this note.".into());
                log::warn!("cb: pick-contact err=duplicate extra=true");
                return;
            }
            if 1 + current_extra.len() + 1 > 255 {
                contacts_g.set_input_error("Too many recipients (max 255).".into());
                log::warn!("cb: pick-contact err=too-many extra=true");
                return;
            }
            upsert_contact(st, &addr);
            save_state(&fs, &st);
            let label = to_label_for(&st, &addr);
            let mut new_extra = current_extra;
            new_extra.push(ToRow { address: addr.as_str().into(), label: label.into() });
            compose.set_to_extra(Rc::new(VecModel::from(new_extra)).into());
            contacts_g.set_picking_extra(false);
            contacts_g.set_input_text("".into());
            contacts_g.set_input_error("".into());
            contacts_g.set_naming_address("".into());
            log::info!("cb: pick-contact to={addr} extra=true");
            ui.global::<Ui>().set_screen(Screen::Compose);
            return;
        }

        if addr.is_empty() {
            // Self: compose only — the sweep picker hides the Self card
            // (sweep-to-self is the Coins screen's consolidate).
            if sweep_mode {
                return;
            }
            compose.set_to_address("".into());
            compose.set_to_label("to: self — my notebook".into());
            compose.set_to_extra(Rc::new(VecModel::from(Vec::<ToRow>::new())).into());
            log::info!("cb: pick-contact to=self");
        } else {
            let st = &mut self.state;
            if Recipient::parse(st.network(), &addr).is_err() {
                contacts_g
                    .set_input_error(format!("Not a valid {} address.", st.network).into());
                log::warn!("cb: pick-contact err=invalid address");
                return;
            }
            upsert_contact(st, &addr);
            save_state(&fs, &st);
            if sweep_mode {
                let sweep = ui.global::<Sweep>();
                sweep.set_kind("sweep".into());
                sweep.set_dest(addr.as_str().into());
                sweep.set_dest_label(to_label_for(&st, &addr).into());
                sweep.set_tier(1);
                log::info!("cb: sweep-open kind=sweep to={addr}");
            } else {
                compose.set_to_address(addr.as_str().into());
                compose.set_to_label(to_label_for(&st, &addr).into());
                compose.set_to_extra(Rc::new(VecModel::from(Vec::<ToRow>::new())).into());
                log::info!("cb: pick-contact to={addr}");
            }
        }
        contacts_g.set_input_text("".into());
        contacts_g.set_input_error("".into());
        contacts_g.set_naming_address("".into());
        if sweep_mode {
            self.update_sweep(ui_weak, fs);
            ui.global::<Ui>().set_screen(Screen::Sweep);
        } else {
            // Fresh compose: reset the funding/change picks to their
            // default rule (spending only when enabled AND funded).
            let st = &self.state;
            let ix = &self.notebooks;
            let ctx = notebook_ctx(&ix, self.active)
                .unwrap_or((self.seed_idx, self.bip_account));
            let section = ix.spending(&self.net, ctx.0, ctx.1).cloned();
            self.funding_pick = default_funding_pick(&st, section.as_ref());
            self.change_pick = ChangePickState::default();
            self.refresh_funding(&ui_weak);
            self.refresh_change(&ui_weak);
            // Direct call, not `invoke_compose_changed()`: this method holds
            // the App borrow, and the callback would borrow it again.
            self.compose_changed(ui_weak, fs);
            ui.global::<Ui>().set_screen(Screen::Compose);
        }
    }

    pub(crate) fn on_scan_contact(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let opts = ScanQrOptions {
            header_title: "Scan recipient address".into(),
            message: "Point at an address QR (a companion page or another Prime's home screen)"
                .into(),
            ..ScanQrOptions::default()
        };
        let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
            Ok(Some(ScanQrResult::Qr { data, .. })) | Ok(Some(ScanQrResult::Ur2 { data, .. })) => data,
            Ok(_) => {
                log::info!("cb: scan-contact cancelled");
                return;
            }
            Err(e) => {
                log::warn!("cb: scan-contact err=scanner {e:?}");
                ui.global::<Contacts>()
                    .set_input_error(format!("QR scanner unavailable: {e:?}").into());
                return;
            }
        };
        // Address QRs are plain text, possibly a BIP21 URI, and
        // legitimately ALL-UPPERCASE (our own home QR is) — normalize.
        let text = String::from_utf8(data).unwrap_or_default();
        let mut addr = text.trim();
        if addr.len() >= 8 && addr[..8].eq_ignore_ascii_case("bitcoin:") {
            addr = &addr[8..];
        }
        let addr = addr.split('?').next().unwrap_or("").trim().to_string();
        let st = &self.state;
        let network = st.network();
        let network_name = st.network.clone();
        let resolved = if Recipient::parse(network, &addr).is_ok() {
            Some(addr.clone())
        } else {
            let lower = addr.to_lowercase();
            Recipient::parse(network, &lower).is_ok().then_some(lower)
        };
        match resolved {
            Some(a) => {
                log::info!("cb: scan-contact ok addr={a}");
                self.pick_contact(&ui_weak, &fs, &a);
            }
            None => {
                log::warn!("cb: scan-contact err=not an address");
                ui.global::<Contacts>().set_input_error(
                    format!("QR didn't contain a valid {network_name} address.").into(),
                );
            }
        }
    }


    /// Quantum key scan (naming modal "Scan quantum key"): armored
    /// ML-KEM public key only — `pq::import_public` rejects anything else
    /// with a clear message (a private-key armor, a note, an address QR).
    /// Scoped to `Contacts.naming-address` (set when the modal opened), so
    /// scanning does NOT require re-saving the name field.
    pub(crate) fn on_scan_contact_pq(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let contacts_g = ui.global::<Contacts>();
        let addr = contacts_g.get_naming_address().to_string();
        if addr.is_empty() {
            return;
        }
        let opts = ScanQrOptions {
            header_title: "Scan quantum key".into(),
            message: "Point at a contact's ML-KEM public-key QR (their Settings → \
                      \"Quantum keys…\" screen)."
                .into(),
            ..ScanQrOptions::default()
        };
        let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
            Ok(Some(ScanQrResult::Qr { data, .. })) | Ok(Some(ScanQrResult::Ur2 { data, .. })) => {
                data
            }
            Ok(_) => {
                log::info!("cb: contact-pq-key cancelled");
                return;
            }
            Err(e) => {
                log::warn!("cb: contact-pq-key err=scanner {e:?}");
                contacts_g.set_naming_pq_error(format!("QR scanner unavailable: {e:?}").into());
                return;
            }
        };
        let armor = String::from_utf8(data).unwrap_or_default();
        match pq::import_public(&armor) {
            Ok((alg, ek)) => {
                let fp = pq::fingerprint(alg, &ek);
                let st = &mut self.state;
                if let Some(c) = st.contacts.iter_mut().find(|c| c.address == addr) {
                    c.mlkem_ek = Some(armor);
                }
                save_state(&fs, &st);
                log::info!("cb: contact-pq-key ok fp={fp}");
                contacts_g
                    .set_naming_pq_caption(format!("{} · {fp}", mlkem_alg_name(alg)).into());
                contacts_g.set_naming_pq_error("".into());
                self.refresh_contacts(&ui_weak);
            }
            Err(e) => {
                log::warn!("cb: contact-pq-key err={e}");
                contacts_g.set_naming_pq_error(format!("Not a quantum public key: {e}").into());
            }
        }
    }

    pub(crate) fn on_save_contact_name(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let contacts_g = ui.global::<Contacts>();
        let addr = contacts_g.get_naming_address().to_string();
        if addr.is_empty() {
            return;
        }
        let name = contacts_g.get_name_text().trim().to_string();
        let st = &mut self.state;
        // Naming does NOT bump recency — only use does, so the row
        // being edited never jumps mid-interaction.
        if let Some(c) = st.contacts.iter_mut().find(|c| c.address == addr) {
            c.name = name.clone();
        }
        save_state(&fs, &st);
        log::info!("cb: save-contact addr={addr} name-len={}", name.len());
        contacts_g.set_naming_address("".into());
        contacts_g.set_name_text("".into());
        self.refresh_contacts(&ui_weak);
    }
}
