//! Screen.home — a notebook's home (address QR, balance, Notes/Compose/Sync)
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/home.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {
    /// Persist the device config from the current cells (single source of
    /// truth — inline DeviceConfig constructions drift as fields grow).
    pub(crate) fn refresh_home(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let st = &self.state;
        let home = ui.global::<Home>();
        home.set_network(self.net.clone().into()); // device-level network
        if let Some(id) = self.identity.as_ref() {
            let addr = id.address(st.network());
            home.set_qr(qr_image(&addr.to_uppercase()));
            home.set_address(addr.into());
        }
        home.set_balance_line(sats_line(st.balance(), st.btc_usd).into());
        let sync_line = match st.tip_height {
            Some(h) => format!("synced to height {h}"),
            None => "never synced".to_string(),
        };
        home.set_sync_line(sync_line.into());
        let sync = ui.global::<Sync>();
        sync.set_status(
            format!(
                "network: {}\nbalance: {} sats · {} utxos\nchain height: {}\nfees (sat/vB): {}/{}/{} · chunk: {} bytes",
                st.network,
                st.balance(),
                st.utxos.len(),
                st.tip_height.map(|h| h.to_string()).unwrap_or("—".into()),
                st.fee_economy,
                st.fee_normal,
                st.fee_fast,
                st.effective_chunk()
            )
            .into(),
        );
        let settings = ui.global::<Settings>();
        let dchunk = self.device_chunk;
        settings.set_chunk_mode(match dchunk {
            None => 0,
            Some(80) => 1,
            Some(_) => 2,
        });
        let eff = dchunk.map(|c| c.clamp(MIN_CHUNK, DEFAULT_CHUNK)).unwrap_or(DEFAULT_CHUNK);
        settings.set_chunk_text(format!("{eff}").into());
        let policy = self.lock_policy;
        settings.set_locktime_mode(match policy {
            LockTimePolicy::Tip => 0,
            LockTimePolicy::Zero => 1,
            LockTimePolicy::Custom { .. } => 2,
        });
        // Mirror the height the policy would actually use, so the
        // Custom field opens pre-filled with the current value.
        settings.set_locktime_text(format!("{}", resolve_locktime(policy, st.tip_height)).into());
        settings.set_locktime_effective(locktime_caption(policy, st.tip_height).into());
        log::info!(
            "cb: home balance={} utxos={} tip={}",
            st.balance(),
            st.utxos.len(),
            st.tip_height.map(|h| h.to_string()).unwrap_or("none".into())
        );
    }
}
