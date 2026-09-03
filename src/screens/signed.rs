//! Screen.signed — external PSBT signing hand-off
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/signed.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Sign an external transaction (PSBT) — stage A: scan it, validate it
    /// pays THIS device's taproot address, and show the universal confirm
    /// gate (screen 4) built from the UNSIGNED tx's own bytes + each input's
    /// witness_utxo. The actual signing (+ outbox export) is stage B, in the
    /// confirm-sign dispatcher below — nothing about a scanned PSBT touches
    /// disk until the user taps Sign.
    pub(crate) fn on_sign_psbt(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let identity = self.identity.clone();
        let notebooks = self.notebooks.clone();
        let app_seed = self.app_seed.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let id_guard = identity.borrow();
        let Some(id) = id_guard.as_ref() else {
            ui.global::<Sync>().set_result("Device locked — no signing key.".into());
            return;
        };
        let opts = ScanQrOptions {
            header_title: "Scan transaction".into(),
            message: "Point at the desktop app's PSBT QR".into(),
            ..ScanQrOptions::default()
        };
        let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
            Ok(Some(ScanQrResult::Qr { data: d, .. })) | Ok(Some(ScanQrResult::Ur2 { data: d, .. })) => d,
            Ok(_) => {
                log::info!("cb: sign-psbt cancelled");
                return;
            }
            Err(e) => {
                log::warn!("cb: sign-psbt err=scanner {e:?}");
                ui.global::<Sync>().set_result(format!("QR scanner unavailable: {e:?}").into());
                return;
            }
        };
        let bytes = normalize_psbt_bytes(&data);
        let psbt = match notes_core::psbt::Psbt::deserialize(&bytes) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("cb: sign-psbt err={e}");
                ui.global::<Sync>().set_result(format!("Not a PSBT: {e}").into());
                return;
            }
        };
        let our_spk = p2tr_script_pubkey(&id.output_x);
        let ours = psbt
            .inputs
            .iter()
            .filter(|i| {
                i.witness_utxo.as_ref().map(|w| w.script_pubkey == our_spk).unwrap_or(false)
            })
            .count();
        if ours == 0 {
            ui.global::<Sync>()
                .set_result("No inputs belong to this device's address.".into());
            return;
        }

        let net_dev = self.net.clone();
        let mut network = Network::from_str_opt(&net_dev).unwrap_or(Network::Mainnet);
        let wallet_ctx = (self.seed_idx, self.bip_account);
        let ix = notebooks.borrow();
        let (self_spks, spending_spks) = confirm_self_spks(&ix, app_seed_get(&app_seed), &net_dev, wallet_ctx);
        drop(ix);

        // Port B (network-display fix, 2026-07-19): a PSBT's
        // scriptPubKeys carry NO network/HRP information at all — HRP
        // is purely an address-ENCODING artifact, never part of the
        // wire format — so rendering every address below with the
        // DEVICE's current network setting is wrong whenever this PSBT
        // was built for a different chain (it will show the right
        // bytes with the wrong prefix). The only honest signal
        // available at this call site is a BIP32 derivation path
        // attached to one of OUR OWN recognized inputs (an external
        // tool that imported this device's `export.rs` account
        // descriptor would naturally embed one) — its hardened
        // coin-type level (`seeds::coin_type`: 0' mainnet, else 1')
        // reflects what that tool believed the network to be. Only
        // inputs already proven ours (`witness_utxo.script_pubkey ==
        // our_spk`) are consulted; a foreign/external-funding input's
        // derivation convention is none of this device's business.
        // coin-type 1' can't distinguish testnet4/signet/regtest from
        // one another (this crate's own `coin_type()` doesn't either),
        // but testnet4 and signet already share the "tb" HRP here, so
        // `Testnet4` is the right display for the overwhelming
        // majority of that bucket; a real external tool handing a
        // REGTEST PSBT to a physical device is not a scenario this
        // display-only fix needs to get byte-perfect. No derivation
        // signal at all (the common case today) changes nothing —
        // this only ever ADDS information on top of the existing
        // device-network fallback, never removes it, and it can never
        // affect signing/validation/tx bytes (display only).
        let device_network_label = network.as_str();
        let mut coin_types: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        for (i, inp) in psbt.inputs.iter().enumerate() {
            let is_ours = inp.witness_utxo.as_ref().map(|w| w.script_pubkey == our_spk).unwrap_or(false);
            if !is_ours {
                continue;
            }
            if let Some(ct) = psbt.input_derivation_coin_type(i) {
                coin_types.insert(ct);
            }
        }
        let mut network_warn: Option<String> = None;
        if let [only] = coin_types.iter().collect::<Vec<_>>()[..] {
            let derived_mainnet = *only == 0;
            let device_mainnet = network == Network::Mainnet;
            if derived_mainnet != device_mainnet {
                let derived_label = if derived_mainnet { "mainnet" } else { "a test network" };
                network_warn = Some(format!(
                    "this transaction's key derivation indicates {derived_label}, but the device is set to {device_network_label} - addresses below use the derived network's encoding"
                ));
                network = if derived_mainnet { Network::Mainnet } else { Network::Testnet4 };
            }
        }

        let mut prevouts: BTreeMap<String, notes_core::confirm::PrevoutInfo> = BTreeMap::new();
        for (i, txin) in psbt.unsigned_tx.inputs.iter().enumerate() {
            let Some(wu) = psbt.inputs.get(i).and_then(|p| p.witness_utxo.as_ref()) else {
                continue;
            };
            let mut t = txin.txid;
            t.reverse();
            let is_ours = wu.script_pubkey == our_spk;
            let address = notes_core::address::address_from_spk(&wu.script_pubkey, network);
            let source =
                if is_ours { "This notebook".to_string() } else { "External funding".to_string() };
            prevouts.insert(
                format!("{}:{}", hex::encode(t), txin.vout),
                notes_core::confirm::PrevoutInfo { value: wu.value, address, source },
            );
        }
        let note_preview = confirm_note_preview(&psbt.unsigned_tx.outputs);

        let cctx = notes_core::confirm::ConfirmCtx {
            network,
            prevouts,
            self_spks,
            spending_spks,
            expected_change: None,
            recipient: None,
            recipient_name: None,
            recipients: Vec::new(),
            note_preview,
        };
        let raw_hex = hex::encode(psbt.unsigned_tx.serialize_legacy());
        drop(id_guard);

        match show_confirm_screen(&ui, "psbt", &raw_hex, &cctx, "External funding tx".to_string(), "Sign & export") {
            Ok(()) => {
                if let Some(msg) = &network_warn {
                    log::info!("cb: confirm network-mismatch derived={}", network.as_str());
                    let cs = ui.global::<ConfirmSign>();
                    let existing = cs.get_warn().to_string();
                    cs.set_warn(
                        if existing.is_empty() { msg.clone().into() } else { format!("{existing}; {msg}").into() },
                    );
                }
                self.psbt_pending = Some(psbt);
            }
            Err(e) => {
                log::warn!("cb: confirm summarize err={e}");
                ui.global::<Sync>().set_result(format!("Cannot show confirm: {e}").into());
            }
        }
    }
}
