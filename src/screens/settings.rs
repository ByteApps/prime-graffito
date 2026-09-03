//! Screen.settings — wallet-level config (network, chunk, locktime, spending) + config.json persistence
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/settings.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {
    /// The persisted projection of the wallet-level fields — the ONE
    /// place `config.json`'s shape is assembled from live state.
    pub(crate) fn device_config(&self) -> DeviceConfig {
        DeviceConfig {
            network: self.net.clone(),
            chunk_override: self.device_chunk,
            seed_index: self.seed_idx,
            account: self.bip_account,
            lock_time: self.lock_policy,
            mlkem_level: self.mlkem_level,
        }
    }


    /// Persist the wallet-level fields to config.json.
    pub(crate) fn persist_config(&self, fs: &Fs) {
        save_config(fs, &self.device_config());
    }


    /// Spending wallet: Settings toggle.
    pub(crate) fn on_set_spending_enabled(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, on: bool) {
        let notebooks = self.notebooks.clone();
        let mut ix = notebooks.borrow_mut();
        let ctx = notebook_ctx(&ix, self.active)
            .unwrap_or((self.seed_idx, self.bip_account));
        let net_s = self.net.clone();
        ix.spending_mut(&net_s, ctx.0, ctx.1).enabled = on;
        save_notebooks(&fs, &ix);
        drop(ix);
        log::info!("cb: set-spending enabled={on}");
        self.refresh_funding(&ui_weak);
    }

    pub(crate) fn on_cycle_network(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let state = self.state.clone();
        let identity = self.identity.clone();
        let notebooks = self.notebooks.clone();
        let app_seed = self.app_seed.clone();
        // Network is device-level (wallet-wide): flush the active
        // notebook, cycle the shared network, persist it in config, and
        // reload the active notebook's ledger for the new chain (each
        // notebook keeps a per-network ledger in state-<net>-<account>).
        if self.active.is_some() {
            save_state(&fs, &state.borrow());
        }
        let next = match self.net.as_str() {
            "mainnet" => "testnet4",
            "testnet4" => "signet",
            "signet" => "regtest",
            _ => "mainnet",
        }
        .to_string();
        self.net = next.clone();
        self.persist_config(&fs);
        log::info!("cb: set-network {next}");
        let active = self.active;
        if let Some(account) = active {
            let mut fresh = load_state(&fs, &next, account);
            fresh.chunk_override = self.device_chunk;
            *state.borrow_mut() = fresh;
            // Legacy identities are network-independent (only the
            // address ENCODING changes), but bip86 notebooks use the
            // BIP-44 coin type — their keys differ per network, so
            // always re-derive from the meta.
            if let Some(m) = notebooks.borrow().get(account) {
                *identity.borrow_mut() = derive_identity(app_seed_get(&app_seed), m, &next);
            }
        }
        let _ = &ui_weak;
        self.refresh_home(&ui_weak);
        self.refresh_notes(&ui_weak);
        self.refresh_coins(&ui_weak, &fs);
        self.refresh_notebooks(&ui_weak, &fs);
    }

    pub(crate) fn on_chunk_changed(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let state = self.state.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let settings = ui.global::<Settings>();
        let mut st = state.borrow_mut();
        match settings.get_chunk_mode() {
            0 => st.chunk_override = None,
            1 => st.chunk_override = Some(80),
            _ => {
                match settings.get_chunk_text().trim().parse::<usize>() {
                    Ok(n) if (MIN_CHUNK..=DEFAULT_CHUNK).contains(&n) => {
                        st.chunk_override = Some(n);
                    }
                    _ => {
                        let msg = format!(
                            "Chunk size must be {MIN_CHUNK}–{DEFAULT_CHUNK} bytes."
                        );
                        log::warn!("cb: set-chunk-size err={msg}");
                        settings.set_chunk_error(msg.into());
                        // Leave the user's text in place to fix.
                        return;
                    }
                }
            }
        }
        log::info!(
            "cb: set-chunk-size {} ok",
            st.chunk_override.map(|n| n.to_string()).unwrap_or("auto".into())
        );
        settings.set_chunk_error("".into());
        save_state(&fs, &st);
        // Chunk is device-level (wallet-wide): persist it in config too.
        self.device_chunk = st.chunk_override;
        self.persist_config(&fs);
        drop(st);
        // Reflect the effective size back into the field (auto/compat),
        // without touching a valid custom value.
        self.refresh_home(&ui_weak);
        // Re-price the draft immediately so the compose cost line is
        // already current when the user returns to it.
        self.compose_changed(ui_weak, fs);
    }


    /// Transaction locktime (anti-fee-sniping). Wallet-level like the chunk
    /// size, so it lives in config.json rather than any notebook's state.
    pub(crate) fn on_locktime_changed(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let state = self.state.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let settings = ui.global::<Settings>();
        let policy = match settings.get_locktime_mode() {
            0 => LockTimePolicy::Tip,
            1 => LockTimePolicy::Zero,
            _ => match settings.get_locktime_text().trim().parse::<u32>() {
                // A height at or above 500_000_000 is read by consensus
                // as a UNIX timestamp, which is never what someone
                // typing a block height means — reject it here rather
                // than silently build an unspendable-until-2035 tx.
                Ok(h) if h < 500_000_000 => LockTimePolicy::Custom { height: h },
                _ => {
                    let msg = "Locktime must be a block height below 500000000.".to_string();
                    log::warn!("cb: set-locktime err={msg}");
                    settings.set_locktime_error(msg.into());
                    // Leave the user's text in place to fix.
                    return;
                }
            },
        };
        self.lock_policy = policy;
        self.persist_config(&fs);
        settings.set_locktime_error("".into());
        let tip = state.borrow().tip_height;
        let effective = resolve_locktime(policy, tip);
        settings.set_locktime_effective(locktime_caption(policy, tip).into());
        log::info!("cb: set-locktime {} effective={effective} ok", policy.as_str());
    }
}
