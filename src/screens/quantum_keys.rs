//! Screen.quantum-keys — seed-derived ML-KEM keys per notebook
//!
//! `impl App` methods for this screen, moved verbatim out of main.rs on
//! 2026-09-02 (PLAN-graffito-arch.md phase 4b, file split). Mirrors
//! `ui/screens/quantum-keys.slint`; the forwarders that wire the slint
//! callbacks to these methods live in `app_main`.

use crate::*;

impl App {

    /// Quantum-keys screen (27): every visible notebook in the active
    /// (seed, account) wallet context has its OWN ML-KEM receive identity
    /// (derived from its own BIP-86 leaf secret, like the Export-keys
    /// screen's hex/WIF), so the screen needs the same notebook picker —
    /// `export_pick_notebook`'s row design + selection convention, reusing
    /// the shared `ExportNbRow` struct. Default selection when the picker
    /// hasn't been touched (`quantum_nb == None`): the ACTIVE notebook when
    /// one is open, else the wallet context's first visible notebook — the
    /// screen's original single-notebook behavior, preserved as the
    /// default. Public-key only: device backup is the 24 recovery words,
    /// which already reconstruct every notebook's key.
    pub(crate) fn refresh_quantum_keys(&self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        let notebooks = self.notebooks.clone();
        let app_seed = self.app_seed.clone();
        let Some(ui) = ui_weak.upgrade() else { return };
        let qk = ui.global::<QuantumKeys>();
        let alg = mlkem_alg_from_u8(self.mlkem_level);
        let level_idx = match alg {
            pq::MlKemAlg::MlKem512 => 0,
            pq::MlKemAlg::MlKem768 => 1,
            pq::MlKemAlg::MlKem1024 => 2,
        };
        qk.set_level(level_idx);
        qk.set_level_caption(mlkem_alg_describe(alg).into());

        let ix = notebooks.borrow();
        let net_s = self.net.clone();
        let network = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
        let ctx = (self.seed_idx, self.bip_account);

        // Picker rows: every visible notebook in this wallet context,
        // same shape/derivation as `export_rows`.
        let mut rows: Vec<ExportNbRow> = Vec::new();
        for m in ix.visible(ctx.0, ctx.1) {
            let addr = derive_identity(app_seed_get(&app_seed), m, &net_s)
                .map(|id| id.address(network))
                .unwrap_or_default();
            let name = if m.name.trim().is_empty() {
                notebooks::default_name(m.index)
            } else {
                m.name.clone()
            };
            rows.push(ExportNbRow {
                index: m.index as i32,
                name: name.into(),
                addr: short_addr(&addr).into(),
            });
        }

        // Selection: an explicit picker choice (if it's still visible),
        // else the active-or-first default described above.
        let default_meta = (self.active)
            .and_then(|acc| ix.get(acc))
            .or_else(|| ix.visible(ctx.0, ctx.1).next())
            .cloned();
        let meta = self
            .quantum_nb
            .and_then(|i| ix.visible(ctx.0, ctx.1).find(|m| m.index == i).cloned())
            .or(default_meta);
        drop(ix);

        let (nb_idx, nb_name) = meta
            .as_ref()
            .map(|m| {
                let name = if m.name.trim().is_empty() {
                    notebooks::default_name(m.index)
                } else {
                    m.name.clone()
                };
                (m.index as i32, name)
            })
            .unwrap_or((0, "".to_string()));
        qk.set_notebooks(Rc::new(VecModel::from(rows)).into());
        qk.set_nb_index(nb_idx);
        qk.set_nb_name(nb_name.into());

        let leaf =
            meta.as_ref().and_then(|m| derive_leaf_secret(app_seed_get(&app_seed), m, &net_s));
        match leaf {
            Some(leaf) => {
                let kp = pq::mlkem_keypair_from_leaf(&leaf, alg);
                qk.set_qr_zoom(false); // never re-enter the screen zoomed
                qk.set_fingerprint(kp.fingerprint().into());
                // The dense armor QR is optically unverifiable at
                // device resolution (~1.2px/module), so the UI suite
                // cross-checks THIS line against notes_cli
                // pq-fingerprint's independent host derivation.
                // Public info — safe to log.
                log::info!("cb: pq-key fp={}", kp.fingerprint());
                let armor = pq::export_public(alg, kp.ek());
                qk.set_public_qr(qr_image(&armor));
                qk.set_public_armor(armor.into());
            }
            None => {
                qk.set_fingerprint("No notebook yet — create one first.".into());
                qk.set_public_armor("".into());
            }
        }
    }


    /// hasn't been touched (`quantum_nb == None`): the ACTIVE notebook when
    /// one is open, else the wallet context's first visible notebook — the
    /// screen's original single-notebook behavior, preserved as the
    /// default. Public-key only: device backup is the 24 recovery words,
    /// which already reconstruct every notebook's key.
    pub(crate) fn on_open_quantum_keys(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
        // Reopening the screen resets to the active-or-first default
        // rather than remembering the last-picked notebook from a
        // previous visit.
        self.quantum_nb = None;
        self.refresh_quantum_keys(&ui_weak);
    }

    pub(crate) fn on_quantum_key_level(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, fs: &Fs, level_idx: i32) {
        let Some(_ui) = ui_weak.upgrade() else { return };
        let alg = match level_idx {
            0 => pq::MlKemAlg::MlKem512,
            2 => pq::MlKemAlg::MlKem1024,
            _ => pq::MlKemAlg::MlKem768,
        };
        self.mlkem_level = alg.id();
        self.persist_config(&fs);
        log::info!("cb: pq-key level={}", mlkem_alg_name(alg));
        self.refresh_quantum_keys(&ui_weak);
    }

    pub(crate) fn on_quantum_key_pick_notebook(&mut self, ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, index: i32) {
        self.quantum_nb = Some(index as u32);
        log::info!("cb: pq-key notebook={index}");
        self.refresh_quantum_keys(&ui_weak);
    }
}
