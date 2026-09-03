//! Screen.notebooks — the notebook list (boot screen), create/rename/archive, notebook switch, boot seed
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/notebooks.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// for an account with no index entry at all.
    /// Rebuild the notebook list (screen 20) from the index + each
    /// notebook's state file. Device has no live balance — the row meta is
    /// address-short · note count.
    pub(crate) fn refresh_notebooks(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let ix = &self.notebooks;
        let active_acct = self.active;
        let dev_net = self.net.clone();
        let ctx = (self.seed_idx, self.bip_account);
        let build = |m: &notebooks::NotebookMeta| -> NotebookRow {
            let st = load_state(&fs, &dev_net, m.account);
            let addr = derive_identity(app_seed_get(&self.app_seed), m, &dev_net)
                .map(|id| id.address(Network::from_str_opt(&dev_net).unwrap_or(Network::Mainnet)))
                .unwrap_or_default();
            let short = short_addr(&addr);
            let n = st.notes.len();
            NotebookRow {
                account: m.account as i32,
                name: notebook_name(&ix, m.account, &short).into(),
                meta: format!(
                    "{short} · {n} note{}",
                    if n == 1 { "" } else { "s" }
                )
                .into(),
                active: active_acct == Some(m.account),
            }
        };
        let rows: Vec<NotebookRow> = ix.visible(ctx.0, ctx.1).map(build).collect();
        let archived: Vec<NotebookRow> =
            ix.archived_in_context(ctx.0, ctx.1).map(build).collect();
        let nb = ui.global::<NotebooksUi>();
        nb.set_empty_line(
            if rows.is_empty() {
                if !archived.is_empty() {
                    "All notebooks are archived.".into()
                } else {
                    "No notebooks yet — create one to start writing.".into()
                }
            } else {
                "".into()
            },
        );
        nb.set_archived_label(
            if archived.is_empty() {
                "".to_string()
            } else {
                format!("Archived ({})", archived.len())
            }
            .into(),
        );
        log::info!("cb: notebooks list n={} archived={}", rows.len(), archived.len());
        nb.set_rows(Rc::new(VecModel::from(rows)).into());
        nb.set_archived_rows(Rc::new(VecModel::from(archived)).into());
    }


    /// spends any spending-wallet coin.
    /// A notebook's display name: its local name, else the 1-based default
    /// Rebuild the notebook list (screen 20) from the index + each
    /// notebook's state file. Device has no live balance — the row meta is
    /// address-short · note count.
    /// Open a notebook: save the current one, swap identity + state to the
    /// target account, refresh every per-notebook view, and show its home.
    pub(crate) fn switch_notebook(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, account: u32) {
        let state = self.state.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        if self.active.is_some() {
            save_state(&fs, &state.borrow());
        }
        self.active = Some(account);
        self.identity = self.notebooks
            .get(account)
            .and_then(|m| derive_identity(app_seed_get(&self.app_seed), m, &self.net));
        let mut loaded = load_state(&fs, &self.net, account);
        loaded.chunk_override = self.device_chunk; // chunk is device-level
        *state.borrow_mut() = loaded;
        let short = self
            .identity
            .as_ref()
            .map(|id| short_addr(&id.address(state.borrow().network())))
            .unwrap_or_default();
        let title = notebook_name(&self.notebooks, account, &short);
        ui.global::<NotebooksUi>().set_title(title.into());
        log::info!("cb: open-notebook account={account}");
        self.refresh_home(&ui_weak);
        self.refresh_notes(&ui_weak);
        self.refresh_coins(&ui_weak, &fs);
        self.refresh_contacts(&ui_weak);
        self.refresh_funding(&ui_weak);
        ui.global::<Ui>().set_screen(Screen::Home);
    }


    /// NOTHING here may read the app seed: `GetAppSeed` prompts on SDK 1.0.0
    /// and the prompt cannot be answered until `ui.run()` is pumping, so a read
    /// on this path hangs the app at launch (see `app_seed_get`). The list is
    /// therefore painted seed-free first — rows render without their addresses
    /// — and the timer below primes the seed once the loop is live, then
    /// repaints the list with them.
    pub(crate) fn boot_seed(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        // First read of the seed in the app's life: this is what raises
        // the one-time "App-scoped seed" consent prompt, and the running
        // loop is what lets the user answer it.
        let available = app_seed_get(&self.app_seed).is_some();
        ui.global::<Recovery>().set_seed_available(available);
        if !available {
            ui.global::<Ui>().set_error("Device locked or seed unavailable".into());
        }
        // Repaint: the rows drawn before the seed existed have no address.
        self.refresh_notebooks(&ui_weak, &fs);
    }

    pub(crate) fn on_rename(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, account: i32) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let nb = ui.global::<NotebooksUi>();
        // Prefill the RAW local name (the display name may be an addr
        // short form, which must not become a name by accident).
        let raw = self.notebooks
            .get(account.max(0) as u32)
            .map(|m| m.name.clone())
            .unwrap_or_default();
        nb.set_name_text(raw.into());
        nb.set_name_account(account);
    }

    pub(crate) fn on_name_cancel(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        if let Some(ui) = ui_weak.upgrade() {
            ui.global::<NotebooksUi>().set_name_account(-1);
        }
    }

    pub(crate) fn on_name_save(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let nb = ui.global::<NotebooksUi>();
        let sel = nb.get_name_account();
        if sel == -1 {
            return;
        }
        let name = nb.get_name_text().trim().to_string();
        nb.set_name_account(-1);
        nb.set_name_text("".into());
        if sel == -2 {
            // CREATE: a bip86 notebook at the next unused receive
            // index of the active (seed, account) context — the
            // recovery-seeds scheme, words-recoverable anywhere.
            // (Legacy notebooks are never created anymore.)
            if app_seed_get(&self.app_seed).is_none() {
                ui.global::<Ui>().set_error("Device locked — can't create a notebook.".into());
                return;
            }
            let (seed, bacct) = (self.seed_idx, self.bip_account);
            let account = {
                let ix = &mut self.notebooks;
                let account = ix.create_bip86(seed, bacct, &name);
                save_notebooks(&fs, &ix);
                account
            };
            let index = self.notebooks.get(account).map(|m| m.index).unwrap_or(0);
            log::info!(
                "cb: create-notebook account={account} scheme=bip86 seed={seed} bip-account={bacct} index={index}"
            );
            self.refresh_notebooks(&ui_weak, &fs);
            self.switch_notebook(&ui_weak, &fs, account);
        } else {
            let account = sel as u32;
            {
                let ix = &mut self.notebooks;
                ix.rename(account, &name);
                save_notebooks(&fs, &ix);
            }
            log::info!("cb: rename-notebook account={account}");
            self.refresh_notebooks(&ui_weak, &fs);
            // If it's the open notebook, update its home title.
            if self.active == Some(account) {
                let title = self.notebooks
                    .get(account)
                    .map(|m| m.name.clone())
                    .filter(|n| !n.trim().is_empty());
                if let Some(t) = title {
                    nb.set_title(t.into());
                }
            }
        }
    }

    pub(crate) fn on_archive(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, account: i32, archived: bool) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let account = account.max(0) as u32;
        if archived {
            // Guard: a notebook with coins must be emptied first
            // (sweep/consolidate). Zero active notebooks is allowed.
            let bal = load_state(&fs, &self.net, account).balance();
            if bal > 0 {
                ui.global::<Ui>()
                    .set_error(format!("This notebook holds {bal} sats — empty it first.").into());
                return;
            }
        }
        {
            let ix = &mut self.notebooks;
            ix.set_archived(account, archived);
            save_notebooks(&fs, &ix);
        }
        log::info!("cb: archive-notebook account={account} archived={archived}");
        self.refresh_notebooks(&ui_weak, &fs);
    }

    pub(crate) fn on_back_to_list(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let state = self.state.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        if self.active.is_some() {
            save_state(&fs, &state.borrow());
        }
        self.refresh_notebooks(&ui_weak, &fs);
        ui.global::<Ui>().set_screen(Screen::Notebooks);
    }


    /// Create: open the name dialog in create mode (-2). Nothing is
    /// derived/persisted until Save — the device create is name-only
    /// (no address picker: no network on-device to probe used/new).
    pub(crate) fn on_create(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let nb = ui.global::<NotebooksUi>();
        nb.set_name_text("".into());
        nb.set_name_account(-2);
    }
}
