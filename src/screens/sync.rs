//! Screen.sync — bundle import (file/scan), export, apply_bundle
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/sync.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Shared by file import AND camera scan: parse + merge a bundle,
    /// logging `cb: import-bundle {src} … ok` (src keeps the file=/loc=
    /// shape the UI tests grep).
    pub(crate) fn apply_bundle(&self, fs: &Fs, json: &str, src: &str) -> Result<String, String> {
        let state = self.state.clone();
        let identity = self.identity.clone();
        let notebooks = self.notebooks.clone();
        let app_seed = self.app_seed.clone();
        let id_guard = identity.borrow();
        let id = id_guard.as_ref().ok_or("identity unavailable")?;
        {
            let bundle =
                SyncBundle::from_json(json).map_err(|e| format!("bad bundle: {e}"))?;
            let mut st = state.borrow_mut();
            if !bundle.network.is_empty() && bundle.network != st.network {
                return Err(format!(
                    "bundle is for {}, app is on {} — switch network first",
                    bundle.network, st.network
                ));
            }

            // Spending-unification: the self-spk SET is the notebook's
            // own spk plus every address the spending wallet has issued
            // (`SpendingSection.self_spks`) — extends OWN detection to
            // funded/mixed-source notes (extract_notes_multi_deduped ORs
            // with the producer's spends_from_self, never narrows).
            let ix = notebooks.borrow();
            let ctx = notebook_ctx(&ix, self.active)
                .unwrap_or((self.seed_idx, self.bip_account));
            let net_s = self.net.clone();
            let section = ix.spending(&net_s, ctx.0, ctx.1).cloned();
            // DISPLAY-OWNER dedup anchor set (device CLAUDE.md): every
            // VISIBLE (non-archived) notebook's own spk in the active
            // wallet context, derived ONCE per import — never per tx —
            // by reusing the same per-notebook identity derivation
            // `confirm_self_spks` already does for the confirm screen.
            // Archived notebooks are excluded by `visible()`, so an
            // archived notebook's input can never suppress a note in an
            // active one.
            let notebook_spks = wallet_notebook_spks(&ix, app_seed_get(&app_seed), &net_s, ctx);
            // Post-quantum auto-unlock candidates: the ACTIVE notebook's
            // three derived ML-KEM receive secrets (512/768/1024) — the
            // only notebook whose received notes this scan could ever
            // be decrypting (the scan itself is already scoped to `id`,
            // this notebook's Identity). Empty when the leaf secret
            // isn't derivable (device locked) — `extract_notes_pq` with
            // no candidates behaves exactly like the pre-pq extraction,
            // just leaving every pq note `locked`.
            let mlkem_secrets: Vec<pq::MlKemSecret> =
                (self.active).and_then(|acc| ix.get(acc)).and_then(|meta| {
                    derive_leaf_secret(app_seed_get(&app_seed), meta, &net_s)
                }).map(|leaf| {
                    derive_mlkem_keypairs(&leaf).into_iter().map(|kp| kp.secret()).collect()
                }).unwrap_or_default();
            drop(ix);
            let notebook_addr = id.address(st.network());
            let self_spks: Vec<Vec<u8>> = {
                let mut v = vec![p2tr_script_pubkey(&id.output_x)];
                if let Some(s) = &section {
                    v.extend(s.self_spks());
                }
                v
            };

            let recovered = extract_notes_pq(
                &bundle,
                id,
                st.network(),
                &self_spks,
                &notebook_spks,
                &mlkem_secrets,
            );
            let mut new_notes = 0usize;
            let mut received_notes = 0usize;
            for r in &recovered {
                let id_hex = r.id.clone();
                if r.received {
                    received_notes += 1;
                }
                // Merge keyed by (id, from): a received note can never
                // overwrite an own note sharing its id (its txid).
                match st
                    .notes
                    .iter_mut()
                    .find(|n| n.id == id_hex && n.from.as_deref() == r.sender.as_deref())
                {
                    Some(existing) => {
                        existing.height = r.height.or(existing.height);
                        existing.blocktime = r.blocktime.or(existing.blocktime);
                        if existing.height.is_some() {
                            existing.status = "confirmed".into();
                        }
                    }
                    None => {
                        new_notes += 1;
                        st.notes.push(NoteRec {
                            id: id_hex.clone(),
                            text: r.text.clone().unwrap_or_else(|| {
                                if r.pq_flags != 0 {
                                    "(locked — unlock to read)".into()
                                } else if r.received {
                                    "(directed note — could not decrypt)".into()
                                } else {
                                    "(sealed under another key)".into()
                                }
                            }),
                            private: r.private,
                            txid: id_hex,
                            raw_hex: String::new(),
                            fee: 0,
                            vsize: 0,
                            chunks: 0,
                            height: r.height,
                            blocktime: r.blocktime,
                            status: if r.height.is_some() {
                                "confirmed".into()
                            } else {
                                "pending".into()
                            },
                            directed: r.directed,
                            to: r.recipient.clone(),
                            from: r.sender.clone(),
                            recipients: r.recipients.clone(),
                            pq_flags: r.pq_flags,
                            locked: r.locked.clone(),
                        });
                    }
                }
            }

            // Split the bundle's UTXOs by owner: no `owner_address` (or
            // one matching the notebook's own address) is a notebook
            // coin; an address matching a KNOWN spending-wallet `used`
            // entry routes to the spending ledger (tagged with its
            // chain/index so signing can re-derive the key). A coin at
            // an owner address the device hasn't recorded as used yet
            // is GAP-ADOPTED below (funding-unification device-port
            // fix, 2026-07-19) rather than dropped.
            //
            // Gap-adoption: the device has no chain access to probe
            // blindly like the graffito desktop app's discover_spending() does,
            // so instead it derives the bounded candidate set — both
            // chains, `next_receive`/`next_change` .. +SPENDING_ADOPT_GAP
            // (= 20, same constant the app's gap scan uses) — and
            // compares each candidate's address against the coin's own
            // owner_address. A match is exactly the kind of address the
            // device would have marked `used` had it ever revealed or
            // spent it, so it's ADOPTED: `mark_used` (idempotent,
            // advances the index past it) and the coin is kept instead
            // of dropped. Cheap and exact — each index's address is
            // unique, so no false positives are possible.
            //
            // Companion gap-discovery, option (b) (2026-07-19): the
            // device also exports a lookahead WATCH WINDOW (next 20
            // receive + next 20 change addresses, Settings' spending
            // card) so the companion can probe addresses it hasn't seen
            // a coin at yet. The companion reports back every window
            // address with ANY on-chain history — coin or not — as
            // `bundle.owner_used`; those resolve through the exact same
            // gap window below and get adopted even with no live coin.
            // This is the convergence piece: a restore whose early
            // addresses are used-but-spent-empty must still advance past
            // them, or the device would forever re-offer an already-
            // spent address as "next receive".
            const SPENDING_ADOPT_GAP: u32 = 20;
            let net_v = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
            let mut nb_utxos: Vec<UtxoRec> = Vec::new();
            let mut sp_utxos: Vec<spending::SpendingUtxo> = Vec::new();
            let mut newly_used: Vec<spending::SpendingAddress> = Vec::new();
            let mut next_recv = section.as_ref().map(|s| s.next_receive).unwrap_or(0);
            let mut next_chg = section.as_ref().map(|s| s.next_change).unwrap_or(0);

            // Shared gap derive-and-compare resolver (companion gap-
            // discovery option (b), 2026-07-19): given ANY owner-tagged
            // address — whether it came with a live coin or just a bare
            // "this address has history" marker — find it among already-
            // known `used` entries (persisted from a prior import, or
            // adopted earlier in THIS SAME import via `newly_used`, which
            // a pre-loop `section` clone can't see) or by deriving the
            // bounded candidate window ahead of next_receive/next_change.
            // A match is exactly the kind of address the device would
            // have marked `used` had it ever revealed or spent it, so
            // it's adopted: `next_recv`/`next_chg` advance past it and it
            // is queued in `newly_used` for `mark_used` below. Returns
            // `(address, true)` only the FIRST time an address resolves
            // via derivation this import — callers use that to log
            // exactly once per genuine adoption, never on repeat lookups
            // (e.g. a second coin at the same already-adopted address).
            let mut resolve_owner = |a: &str| -> Option<(spending::SpendingAddress, bool)> {
                let already_known = section
                    .as_ref()
                    .and_then(|s| s.used.iter().find(|x| x.address == a).cloned())
                    .or_else(|| newly_used.iter().find(|x| x.address == a).cloned());
                if let Some(addr) = already_known {
                    return Some((addr, false));
                }
                // `app_seed_get` hands back a concrete `&Option<[u8; 32]>`,
                // so `.as_ref()` is unambiguously `Option::as_ref` here.
                let Some(seed) = app_seed_get(&app_seed).as_ref() else { return None };
                let mut found_addr: Option<spending::SpendingAddress> = None;
                'gap: for chain in [0u32, 1u32] {
                    let base = if chain == 0 { next_recv } else { next_chg };
                    for index in base..base.saturating_add(SPENDING_ADOPT_GAP) {
                        if let Ok(key) = notes_core::seeds::derive_spending_key(
                            seed, ctx.0, net_v, ctx.1, chain, index,
                        ) {
                            if key.address == a {
                                found_addr = Some(spending::SpendingAddress {
                                    chain,
                                    index,
                                    address: key.address.clone(),
                                    spk_hex: hex::encode(&key.script_pubkey),
                                });
                                break 'gap;
                            }
                        }
                    }
                }
                if let Some(addr) = &found_addr {
                    if addr.chain == 0 {
                        next_recv = next_recv.max(addr.index + 1);
                    } else {
                        next_chg = next_chg.max(addr.index + 1);
                    }
                    newly_used.push(addr.clone());
                }
                found_addr.map(|addr| (addr, true))
            };

            // 1) Used-only markers FIRST — every watch-window address the
            // companion found ANY history for, coin or not. This must run
            // BEFORE the coin loop below so a coin at a later index
            // benefits from the advanced next_recv/next_chg window in the
            // SAME import: a restore whose early addresses are used-but-
            // spent-empty must still converge past them to reach a later
            // real coin, not get stuck re-deriving from index 0 forever.
            for a in &bundle.owner_used {
                if a == &notebook_addr {
                    continue; // the notebook identity is a separate address space
                }
                if let Some((addr, is_new)) = resolve_owner(a) {
                    if is_new {
                        log::info!(
                            "cb: spending-adopt chain={} index={} used-only",
                            addr.chain, addr.index
                        );
                    }
                }
                // else: still unknown beyond the gap — nothing to advance.
            }

            // 2) Coins — log line shape UNCHANGED from before this
            // companion gap-discovery extension (today's e2e greps it).
            for u in &bundle.utxos {
                match &u.owner_address {
                    None => {
                        nb_utxos.push(UtxoRec { txid: u.txid.clone(), vout: u.vout, value: u.value })
                    }
                    Some(a) if *a == notebook_addr => {
                        nb_utxos.push(UtxoRec { txid: u.txid.clone(), vout: u.vout, value: u.value })
                    }
                    Some(a) => {
                        if let Some((addr, is_new)) = resolve_owner(a) {
                            if is_new {
                                log::info!(
                                    "cb: spending-adopt chain={} index={}",
                                    addr.chain, addr.index
                                );
                            }
                            sp_utxos.push(spending::SpendingUtxo {
                                txid: u.txid.clone(),
                                vout: u.vout,
                                value: u.value,
                                chain: addr.chain,
                                index: addr.index,
                            });
                        }
                        // else: still unknown beyond the gap — dropped, unchanged.
                    }
                }
            }
            st.utxos = nb_utxos;
            if section.is_some() || !newly_used.is_empty() {
                let mut ix = notebooks.borrow_mut();
                let sec = ix.spending_mut(&net_s, ctx.0, ctx.1);
                for addr in newly_used {
                    sec.mark_used(addr);
                }
                sec.set_utxos(sp_utxos);
                save_notebooks(&fs, &ix);
            }
            st.tip_height = Some(bundle.tip_height);
            st.bundle_time = Some(bundle.bundle_time);
            // Chunk size is a pure device setting — any relay-policy
            // field in the bundle is deliberately ignored.
            if bundle.fee_rates.economy > 0.0 {
                st.fee_economy = bundle.fee_rates.economy;
            }
            if bundle.fee_rates.half_hour > 0.0 {
                st.fee_normal = bundle.fee_rates.half_hour;
            }
            if bundle.fee_rates.fastest > 0.0 {
                st.fee_fast = bundle.fee_rates.fastest;
            }
            st.btc_usd = bundle.btc_usd.or(st.btc_usd);
            save_state(&fs, &st);

            log::info!(
                "cb: import-bundle {src} notes={} new={new_notes} received={received_notes} utxos={} tip={} ok",
                recovered.len(),
                st.utxos.len(),
                bundle.tip_height
            );
            Ok(format!(
                "Imported ({src}): {} note(s) ({new_notes} new), {} utxo(s), height {}.",
                recovered.len(),
                st.utxos.len(),
                bundle.tip_height
            ))
        }
    }


    /// Shared by file import AND camera scan: parse + merge a bundle,
    /// logging `cb: import-bundle {src} … ok` (src keeps the file=/loc=
    /// shape the UI tests grep).
    pub(crate) fn on_import_bundle(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let result = (|| -> Result<String, String> {
            let (name, loc, loc_label) =
                first_inbox_bundle(&fs).ok_or("no .json bundle in /graffito/inbox")?;
            let json = read_text(&fs, &format!("{INBOX_DIR}/{name}"), loc)?;
            if loc == Location::Airlock {
                unmount_airlock(&fs);
            }
            self.apply_bundle(&fs, &json, &format!("file={name} loc={loc_label}"))
        })();
        match result {
            Ok(msg) => {
                ui.global::<Sync>().set_result(msg.into());
                ui.global::<Ui>().set_error("".into());
            }
            Err(e) => {
                log::warn!("cb: import-bundle err={e}");
                ui.global::<Sync>().set_result(e.into());
            }
        }
        self.refresh_home(&ui_weak);
    }


    /// Import picker: list the bundle files actually present in the inboxes
    /// so the user chooses one, instead of silently auto-picking the first.
    pub(crate) fn on_list_bundles(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let sync = ui.global::<Sync>();
        let found = list_inbox_bundles(&fs);
        let rows: Vec<BundleRow> = found
            .iter()
            .map(|(name, loc, _)| {
                let (loc_name, loc_idx) = if *loc == Location::Airlock {
                    ("Airlock", 1)
                } else {
                    ("Internal", 0)
                };
                BundleRow {
                    name: name.clone().into(),
                    label: format!("{name}  ·  {loc_name}").into(),
                    loc: loc_idx,
                }
            })
            .collect();
        sync.set_bundles(Rc::new(VecModel::from(rows)).into());
        sync.set_empty_hint(
            "No bundle files found. Put a .json bundle in /graffito/inbox on Internal (or the Airlock volume), then tap Refresh — or use \"Scan bundle\" to import by QR from the companion.".into(),
        );
        sync.set_picking(true);
        log::info!("cb: list-bundles n={}", found.len());
    }

    pub(crate) fn on_pick_bundle(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, name: SharedString, loc_idx: i32) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let loc = if loc_idx == 1 { Location::Airlock } else { Location::User };
        let result = (|| -> Result<String, String> {
            if loc == Location::Airlock {
                ensure_airlock_mounted(&fs)?;
            }
            let json = read_text(&fs, &format!("{INBOX_DIR}/{name}"), loc);
            if loc == Location::Airlock {
                unmount_airlock(&fs);
            }
            let loc_label = if loc == Location::Airlock { "airlock" } else { "internal" };
            self.apply_bundle(&fs, &json?, &format!("file={name} loc={loc_label}"))
        })();
        let sync = ui.global::<Sync>();
        sync.set_picking(false);
        match result {
            Ok(msg) => {
                sync.set_result(msg.into());
                ui.global::<Ui>().set_error("".into());
            }
            Err(e) => {
                log::warn!("cb: pick-bundle err={e}");
                sync.set_result(e.into());
            }
        }
        self.refresh_home(&ui_weak);
    }

    pub(crate) fn on_scan_bundle(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let Some(ui) = ui_weak.upgrade() else { return };
        let opts = ScanQrOptions {
            header_title: "Scan sync bundle".into(),
            message: "Point at the companion's bundle QR (static or animated)".into(),
            ..ScanQrOptions::default()
        };
        // Blocks while the system scanner modal owns the screen; it
        // reassembles animated UR sequences itself (foundation-ur).
        let (kind, data) = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
            Ok(Some(ScanQrResult::Qr { data, .. })) => ("qr", data),
            Ok(Some(ScanQrResult::Ur2 { ur_type, data, .. })) => {
                log::info!("cb: scan-bundle ur-type={ur_type}");
                ("ur", data)
            }
            Ok(_) => {
                log::info!("cb: scan-bundle cancelled");
                return;
            }
            Err(e) => {
                log::warn!("cb: scan-bundle err=scanner {e:?}");
                ui.global::<Sync>()
                    .set_result(format!("QR scanner unavailable: {e:?}").into());
                return;
            }
        };
        log::info!("cb: scan-bundle kind={kind} bytes={}", data.len());
        let result = decode_scanned(&data)
            .map_err(|e| e.to_string())
            .and_then(|json| self.apply_bundle(&fs, &json, &format!("src=scan-{kind}")));
        match result {
            Ok(msg) => {
                ui.global::<Sync>().set_result(msg.into());
                ui.global::<Ui>().set_error("".into());
            }
            Err(e) => {
                log::warn!("cb: scan-bundle err={e}");
                ui.global::<Sync>().set_result(format!("Scan failed: {e}").into());
            }
        }
        self.refresh_home(&ui_weak);
    }

    pub(crate) fn on_export_pending(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs) {
        let state = self.state.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let st = state.borrow();
        let pending: Vec<&NoteRec> = st
            .notes
            .iter()
            .filter(|n| n.status == "pending" && !n.raw_hex.is_empty())
            .collect();
        let mut written = 0usize;
        let airlock_ok = ensure_airlock_mounted(&fs).is_ok();
        for n in &pending {
            let file = format!("{OUTBOX_DIR}/{}.hex", n.txid);
            if ensure_dir(&fs, OUTBOX_DIR, Location::User)
                .and_then(|_| write_file(&fs, &file, Location::User, n.raw_hex.as_bytes()))
                .is_ok()
            {
                written += 1;
            }
            if airlock_ok {
                let _ = ensure_dir(&fs, OUTBOX_DIR, Location::Airlock).and_then(|_| {
                    write_file(&fs, &file, Location::Airlock, n.raw_hex.as_bytes())
                });
            }
        }
        if airlock_ok {
            unmount_airlock(&fs);
        }
        log::info!(
            "cb: export-pending n={written} airlock={}",
            if airlock_ok { "ok" } else { "err" }
        );
        ui.global::<Sync>()
            .set_result(format!("Exported {written} pending tx(s) to {OUTBOX_DIR}.").into());
    }
}
