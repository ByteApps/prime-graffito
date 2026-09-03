//! Screen.notes — the notes list + sender filter
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/notes.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Persist the device config from the current cells (single source of
    /// truth — inline DeviceConfig constructions drift as fields grow).
    pub(crate) fn refresh_notes(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let st = &self.state;
        // Sender filter: build the checklist + filter the list. A note
        // is hidden iff its sender key is in the persisted exclusion set.
        let senders: Vec<SenderRow> = st
            .senders()
            .into_iter()
            .map(|(key, count)| {
                let label = if key == "self" {
                    "Self".to_string()
                } else {
                    st.contacts
                        .iter()
                        .find(|c| c.address == key && !c.name.is_empty())
                        .map(|c| c.name.clone())
                        .unwrap_or_else(|| short_addr(&key))
                };
                SenderRow {
                    excluded: st.is_excluded(&key),
                    key: key.into(),
                    label: label.into(),
                    sub: format!("{count} note(s)").into(),
                }
            })
            .collect();
        let hidden = senders.iter().filter(|s| s.excluded).count();
        let notes_g = ui.global::<Notes>();
        notes_g.set_senders(Rc::new(VecModel::from(senders)).into());
        notes_g.set_hidden_label(
            if hidden == 0 { "".to_string() } else { format!("{hidden} sender(s) hidden") }.into(),
        );
        let mut recs: Vec<&NoteRec> =
            st.notes.iter().filter(|n| !st.is_excluded(&State::sender_key(n))).collect();
        // Pending first, then newest confirmed first.
        recs.sort_by_key(|n| match n.height {
            None => (0u8, 0i64),
            Some(h) => (1u8, -(h as i64)),
        });
        let rows: Vec<NoteRow> = recs
            .iter()
            .map(|n| NoteRow {
                id: n.id.clone().into(),
                preview: preview_of(&n.text).into(),
                meta: {
                    let base = match n.height {
                        Some(h) => format!("block {h} · {} chunk(s)", n.chunks.max(1)),
                        None => format!("pending · fee {} sats", n.fee),
                    };
                    match (&n.from, &n.to) {
                        (Some(from), _) => format!("{base} · from {}", short_addr(from)),
                        (None, Some(to)) => format!("{base} · to {}", short_addr(to)),
                        _ => base,
                    }
                }
                .into(),
                badge: if n.private { "PRIVATE" } else { "PUBLIC" }.into(),
                // Post-quantum (pq.rs): pq mirrors the contacts picker's
                // "PQ" badge (a passphrase and/or ML-KEM layer was
                // used); locked mirrors the note-view screen's lock
                // state (a received pq note this device couldn't
                // auto-decrypt at scan time — still visually distinct
                // from an unlocked pq note in the list).
                pq: n.pq_flags != 0,
                locked: n.locked.is_some(),
            })
            .collect();
        log::info!("cb: refresh-notes n={} hidden={hidden}", rows.len());
        notes_g.set_rows(Rc::new(VecModel::from(rows)).into());
    }

    pub(crate) fn on_toggle_sender(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, key: SharedString, excluded: bool) {
        let Some(_ui) = ui_weak.upgrade() else { return };
        {
            let st = &mut self.state;
            st.set_excluded(key.as_str(), excluded);
            save_state(&fs, &st);
            log::info!(
                "cb: toggle-sender excluded={excluded} hidden={}",
                st.excluded_senders.len()
            );
        }
        self.refresh_notes(&ui_weak);
    }
}
