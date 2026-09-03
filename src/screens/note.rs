//! Screen.note — note view, unlock, reply
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/note.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {
    pub(crate) fn on_open_note(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, id: SharedString) {
        let state = self.state.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let st = state.borrow();
        let Some(n) = st.notes.iter().find(|n| n.id == id.as_str()) else { return };
        let view = ui.global::<View>();
        view.set_id(n.id.clone().into());
        view.set_text(n.text.clone().into());
        view.set_badge(if n.private { "PRIVATE" } else { "PUBLIC" }.into());
        let where_line = match n.height {
            Some(h) => format!("confirmed at block {h}"),
            None => "pending — scan the tx QR with the companion to broadcast".to_string(),
        };
        let who_line = if n.recipients.len() > 1 {
            let mut line = format!("\nto ({}): {}", n.recipients.len(), n.recipients[0]);
            for addr in &n.recipients[1..] {
                line.push_str(&format!("\n    {addr}"));
            }
            line
        } else {
            match (&n.from, &n.to) {
                (Some(from), _) => format!("\nfrom: {from}"),
                (None, Some(to)) => format!("\nto: {to}"),
                _ => String::new(),
            }
        };
        view.set_meta(format!("{where_line}{who_line}\ntxid: {}", n.txid).into());
        set_view_qr(&view, n);
        view.set_show_qr(false);

        // Post-quantum lock state (pq.rs) — mirrors the Mac app's
        // `refresh_note_unlock_ui`: an own (sent) DIRECTED note
        // carrying FLAG_MLKEM can NEVER be re-opened (the ct was
        // encapsulated to the RECIPIENT only — checked first,
        // unconditionally, even if FLAG_PW is also set); a
        // received/unlockable note with FLAG_PW gets the password
        // field; anything else locked (a received ML-KEM-only note
        // this device somehow couldn't auto-decrypt at scan time)
        // gets an explanatory caption only.
        //
        // Self-notes have no sender OR recipient, so `n.from.is_none()`
        // alone can't disambiguate a self-locked body from an own
        // directed-sent one the way it used to — `is_self_locked`
        // (`LockedBody::is_self`) does. A self body sealed under
        // FLAG_MLKEM (PLAN-graffito-quantum-key.md) is now tried
        // against this device's own personal quantum key, if one is
        // stored: KEM-only unlocks automatically (view-only — nothing
        // persisted, matching every other self-pq unlock); KEM+FLAG_PW
        // still needs the typed password too, so it falls through to
        // the normal password field with the stored key supplied
        // alongside it at Unlock (`on_unlock_note`). No device key, or
        // a present key that doesn't decrypt (e.g. after a Replace),
        // falls back to an honest caption — never the directed
        // "sealed to the recipient's key" message (there IS no
        // recipient).
        let locked = n.locked.is_some();
        let is_self_locked = n.locked.as_ref().map(pq::LockedBody::is_self).unwrap_or(false);
        let sender_cannot_reopen = locked
            && !is_self_locked
            && n.from.is_none()
            && n.pq_flags & notes_core::envelope::FLAG_MLKEM != 0;
        let self_kem_locked =
            locked && is_self_locked && n.pq_flags & notes_core::envelope::FLAG_MLKEM != 0;
        let self_kem_also_pw =
            self_kem_locked && n.pq_flags & notes_core::envelope::FLAG_PW != 0;
        let mut kem_auto_text: Option<String> = None;
        let mut kem_key_present = false;
        let mut kem_key_wrong = false;
        if self_kem_locked {
            // Bound first: an `if let` scrutinee's RefMut would live
            // through the whole block.
            let device_kp = self.device_quantum_key(fs);
            if let Some(kp) = device_kp {
                kem_key_present = true;
                if !self_kem_also_pw {
                    if let (Some(locked_body), Some(ident)) =
                        (n.locked.as_ref(), self.identity.as_ref())
                    {
                        match pq::unlock_self(
                            locked_body,
                            &ident.enc_key,
                            Some(&kp.secret()),
                            None,
                        ) {
                            Ok(bytes) => {
                                // Log-contract line for the UI suite
                                // (graffito-selfpq.sh): the auto-unlock
                                // is otherwise invisible to log greps.
                                log::info!("cb: unlock-note auto=kem ok");
                                kem_auto_text = Some(String::from_utf8_lossy(&bytes).to_string())
                            }
                            Err(_) => {
                                log::warn!("cb: unlock-note auto=kem err=mismatch");
                                kem_key_wrong = true;
                            }
                        }
                    }
                }
            }
        }
        let needs_password = (locked
            && !sender_cannot_reopen
            && !self_kem_locked
            && n.pq_flags & notes_core::envelope::FLAG_PW != 0)
            || (self_kem_also_pw && kem_key_present);
        view.set_locked(locked && kem_auto_text.is_none());
        view.set_needs_password(needs_password);
        view.set_lock_caption(
            if sender_cannot_reopen {
                "Can't re-read this note — it's sealed to the recipient's key."
            } else if self_kem_locked && (kem_auto_text.is_some() || needs_password) {
                ""
            } else if self_kem_locked && kem_key_wrong {
                "This note's quantum key doesn't match the one stored on this device."
            } else if self_kem_locked {
                "Locked with a quantum key this device doesn't hold."
            } else if locked && !needs_password {
                "Sealed to a quantum key this device doesn't hold."
            } else {
                ""
            }
            .into(),
        );
        if let Some(text) = &kem_auto_text {
            view.set_text(text.clone().into());
        }
        view.set_unlock_password("".into());
        view.set_unlock_error("".into());

        // Reply / Reply-all: a small local equivalent of notes-core's
        // `bundle::reply_set` operating on the persisted `NoteRec`
        // (plain display/UX logic, not a notes-core FROZEN invariant —
        // deliberately not routed through notes-core, which only has
        // the heavier `RecoveredNote` shape). `full_set` = {from} ∪
        // recipients minus my own address, deduped, sender-first.
        let my_address = self.identity.as_ref().map(|id| id.address(st.network()));
        let mut full_set: Vec<String> = Vec::new();
        let mut push_addr = |addr: &str, out: &mut Vec<String>| {
            if Some(addr) != my_address.as_deref() && !out.iter().any(|a| a == addr) {
                out.push(addr.to_string());
            }
        };
        if let Some(from) = &n.from {
            push_addr(from, &mut full_set);
        }
        if !n.recipients.is_empty() {
            for r in &n.recipients {
                push_addr(r, &mut full_set);
            }
        } else if let Some(to) = &n.to {
            push_addr(to, &mut full_set);
        }
        // Received note: Reply is ALWAYS addressed to the sender,
        // regardless of full_set's size. Own note: Reply is addressed
        // to the sole other party only when there is exactly one — 2+
        // hides Reply in favor of Reply-all (never both for an own
        // note). A pure self-note (full_set empty) shows neither.
        let reply_address = if let Some(from) = &n.from {
            from.clone()
        } else if full_set.len() == 1 {
            full_set[0].clone()
        } else {
            String::new()
        };
        view.set_reply_address(reply_address.into());
        let full_set_shared: Vec<SharedString> =
            full_set.iter().map(SharedString::from).collect();
        view.set_reply_set(Rc::new(VecModel::from(full_set_shared)).into());

        log::info!(
            "cb: open-note id={} status={}{} qr={}",
            n.id,
            n.status,
            n.from.as_deref().map(|f| format!(" from={f}")).unwrap_or_default(),
            view.get_has_qr()
        );
        ui.global::<Ui>().set_screen(Screen::Note);
    }


    /// notebook alongside the typed password (covers a combined
    /// FLAG_MLKEM|FLAG_PW note, which `extract_notes_pq` never auto-tries);
    /// an own (sent) DIRECTED note goes through `unlock_sent` instead —
    /// already filtered to FLAG_PW-alone by `on_open_note`'s
    /// `needs_password` gate, so `unlock_sent`'s `SenderCannotReopen` is
    /// never actually reachable from here.
    pub(crate) fn on_unlock_note(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, password: SharedString) {
        let state = self.state.clone();
        let notebooks = self.notebooks.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let id_str = ui.global::<View>().get_id().to_string();
        let mut st = state.borrow_mut();
        let Some(n) = st.notes.iter_mut().find(|n| n.id == id_str) else { return };
        let Some(locked) = n.locked.clone() else { return };
        // The caching key lookup needs `&mut self`; take it BEFORE borrowing
        // the identity for the rest of the unlock.
        let device_kp = if locked.pq_flags & notes_core::envelope::FLAG_MLKEM != 0 {
            self.device_quantum_key(fs)
        } else {
            None
        };
        let id_guard = &self.identity;
        let Some(ident) = id_guard.as_ref() else {
            log::warn!("cb: unlock-note err=identity-unavailable");
            return;
        };
        let pw = password.to_string();
        let pw_opt = if pw.is_empty() { None } else { Some(pw.as_str()) };
        let is_self = locked.is_self();
        let result: Result<Vec<u8>, notes_core::Error> = if is_self {
            // PLAN-graffito-quantum-key.md: a self body carrying
            // FLAG_MLKEM only reaches here (needs_password set by
            // `on_open_note`) when it ALSO carries FLAG_PW and the
            // device key is present — KEM-only self bodies are tried
            // automatically on open and never show the Unlock button.
            let mlkem_secret = device_kp.as_ref().map(|kp| kp.secret());
            pq::unlock_self(&locked, &ident.enc_key, mlkem_secret.as_ref(), pw_opt)
        } else {
            let received = n.from.is_some();
            if received {
                if locked.pq_flags & notes_core::envelope::FLAG_MLKEM != 0 {
                    let ix = notebooks.borrow();
                    let net_s = self.net.clone();
                    let leaf = (self.active)
                        .and_then(|acc| ix.get(acc))
                        .and_then(|meta| derive_leaf_secret(app_seed_get(&self.app_seed), meta, &net_s));
                    drop(ix);
                    let mut last = notes_core::Error::DecryptFailed;
                    let mut ok: Option<Vec<u8>> = None;
                    if let Some(leaf) = leaf {
                        for kp in derive_mlkem_keypairs(&leaf) {
                            let secret = kp.secret();
                            match pq::unlock_received(&locked, &ident.tweaked_seckey, Some(&secret), pw_opt)
                            {
                                Ok(pt) => {
                                    ok = Some(pt);
                                    break;
                                }
                                Err(e) => last = e,
                            }
                        }
                    }
                    ok.ok_or(last)
                } else {
                    pq::unlock_received(&locked, &ident.tweaked_seckey, None, pw_opt)
                }
            } else {
                pq::unlock_sent(&locked, &ident.tweaked_seckey, &ident.output_x, pw_opt)
            }
        };
        match result {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).to_string();
                // Self-pw unlock is VIEW-ONLY (PLAN-graffito-self-pw.md):
                // the plaintext is shown for THIS viewing only —
                // `n.text`/`n.locked` in the persisted store are left
                // untouched, so re-opening the note (or a fresh boot)
                // asks for the password again. A directed note's
                // unlock keeps its existing fill-and-clear semantics.
                if !is_self {
                    n.text = text.clone();
                    n.locked = None;
                    save_state(&fs, &st);
                }
                log::info!("cb: unlock-note ok");
                drop(st);
                let view = ui.global::<View>();
                view.set_text(text.into());
                view.set_locked(false);
                view.set_needs_password(false);
                view.set_lock_caption("".into());
                view.set_unlock_error("".into());
                view.set_unlock_password("".into());
            }
            Err(e) => {
                log::warn!("cb: unlock-note err={e}");
                ui.global::<View>().set_unlock_error(format!("{e}").into());
            }
        }
    }


    /// Reply: fresh compose draft addressed to View.reply-address. Routed
    /// through the SAME `pick_contact` funnel a manual pick uses (contact
    /// name resolution, recency bump, funding/change reset, → screen 3) —
    /// it already clears Compose.to-extra on its replace path, so a stale
    /// extra-recipient list from a previous draft can't leak in.
    pub(crate) fn on_reply_to_note(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let addr = ui.global::<View>().get_reply_address().to_string();
        if addr.is_empty() {
            return;
        }
        self.pick_contact(&ui_weak, &fs, &addr);
    }


    /// Reply-all: primary = the first address in View.reply-set (via the
    /// same `pick_contact` funnel, which also resets to-extra), every
    /// remaining address pushed directly onto Compose.to-extra — NOT
    /// re-run through `pick_contact` (that would re-reset funding/change
    /// and re-navigate on every entry).
    pub(crate) fn on_reply_all_to_note(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let state = self.state.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let set: Vec<String> =
            ui.global::<View>().get_reply_set().iter().map(|s| s.to_string()).collect();
        let Some((first, rest)) = set.split_first() else { return };
        self.pick_contact(&ui_weak, &fs, first);
        let st = state.borrow();
        let extra: Vec<ToRow> = rest
            .iter()
            .map(|a| ToRow { address: a.as_str().into(), label: to_label_for(&st, a).into() })
            .collect();
        drop(st);
        ui.global::<Compose>().set_to_extra(Rc::new(VecModel::from(extra)).into());
    }
}
