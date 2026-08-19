//! Notebook index for the device app: which identities exist as
//! notebooks, their local names, and archive flags. One JSON file
//! (`/.graffito/notebooks.json`); each notebook's notes/UTXO ledger
//! lives in its own `state-<net>-<account>.json`, keyed by the unique
//! notebook KEY (`account` — the field name is historic).
//!
//! Every notebook is a BIP-86 receive index —
//! `Identity::from_bip86(app_seed, seed, net, bip_account, index)`, a
//! receive index of a BIP-86 account under a rotation seed. Recoverable
//! from the seed's 24 words alone in any taproot wallet; per-network keys
//! (coin_type 0'/1'). New notebooks are created under the device's active
//! (seed, account) context. (The pre-recovery-seeds HKDF "legacy" scheme
//! was removed before any release — PLAN-graffito-seed-rotation.md.)
//!
//! Local metadata only — names and archive flags are NOT
//! chain-recoverable after a wipe; notes recover per address, and the
//! index rebuilds by re-creating notebooks.
//! Design: ../../PLAN-graffito-notebooks.md + PLAN-graffito-seed-rotation.md.

use serde::{Deserialize, Serialize};

/// The name every notebook gets unless the user typed one: **"Notebook
/// <index+1>"** — 1-based, so the first notebook (receive index 0) reads
/// "Notebook 1" (Sal 2026-07-26, the same rule on every platform and
/// every creation path). Also the display fallback for entries that
/// predate the rule.
pub fn default_name(index: u32) -> String {
    format!("Notebook {}", index + 1)
}

/// One notebook. `account` is the unique notebook KEY (state-file
/// routing + UI plumbing); the identity is the BIP-86 leaf
/// `m/86'/{coin}'/{bip_account}'/0/{index}` under rotation `seed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookMeta {
    pub account: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub archived: bool,
    /// Rotation seed index (keys::derive_seed_entropy).
    #[serde(default)]
    pub seed: u32,
    /// The hardened BIP-86 account.
    #[serde(default)]
    pub bip_account: u32,
    /// The receive-chain address index.
    #[serde(default)]
    pub index: u32,
}

impl NotebookMeta {
    /// Does this notebook belong to the device's active wallet context
    /// (rotation `seed` + BIP-86 `bip_account`)?
    pub fn in_context(&self, seed: u32, bip_account: u32) -> bool {
        self.seed == seed && self.bip_account == bip_account
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotebookIndex {
    pub version: u32,
    pub notebooks: Vec<NotebookMeta>,
    /// Spending-wallet bookkeeping, one section per (network, seed,
    /// bip_account) context — account-level, a sibling of `notebooks`
    /// rather than a per-notebook field, because several sibling notebooks
    /// of one account share ONE spending wallet (`crate::spending`).
    #[serde(default)]
    pub spending: Vec<crate::spending::SpendingSection>,
}

impl Default for NotebookIndex {
    fn default() -> Self {
        NotebookIndex { version: 2, notebooks: Vec::new(), spending: Vec::new() }
    }
}

impl crate::spending::SpendingIndex for NotebookIndex {
    fn spending_sections(&self) -> &[crate::spending::SpendingSection] {
        &self.spending
    }
    fn spending_sections_mut(&mut self) -> &mut Vec<crate::spending::SpendingSection> {
        &mut self.spending
    }
}

impl NotebookIndex {
    pub fn get(&self, account: u32) -> Option<&NotebookMeta> {
        self.notebooks.iter().find(|n| n.account == account)
    }

    /// Create a bip86 notebook at the next unused receive index of
    /// (`seed`, `bip_account`), named `name` — or, when `name` is blank,
    /// the default `default_name(index)`. Returns its key.
    pub fn create_bip86(&mut self, seed: u32, bip_account: u32, name: &str) -> u32 {
        let account = self.next_account();
        let index = self.next_bip86_index(seed, bip_account);
        let name = match name.trim() {
            "" => default_name(index),
            n => n.to_string(),
        };
        self.notebooks.push(NotebookMeta {
            account,
            name,
            archived: false,
            seed,
            bip_account,
            index,
        });
        self.notebooks.sort_by_key(|n| n.account);
        account
    }

    /// The key a new notebook gets: one past the highest known.
    pub fn next_account(&self) -> u32 {
        self.notebooks.iter().map(|n| n.account + 1).max().unwrap_or(0)
    }

    /// Next unused receive index within (`seed`, `bip_account`).
    pub fn next_bip86_index(&self, seed: u32, bip_account: u32) -> u32 {
        self.notebooks
            .iter()
            .filter(|n| n.seed == seed && n.bip_account == bip_account)
            .map(|n| n.index + 1)
            .max()
            .unwrap_or(0)
    }

    pub fn rename(&mut self, account: u32, name: &str) {
        if let Some(n) = self.notebooks.iter_mut().find(|n| n.account == account) {
            n.name = name.trim().to_string();
        }
    }

    pub fn set_archived(&mut self, account: u32, archived: bool) {
        if let Some(n) = self.notebooks.iter_mut().find(|n| n.account == account) {
            n.archived = archived;
        }
    }

    pub fn active(&self) -> impl Iterator<Item = &NotebookMeta> {
        self.notebooks.iter().filter(|n| !n.archived)
    }

    /// Active notebooks visible in wallet context (`seed`, `bip_account`)
    /// — the set the list shows and wallet-level features operate on.
    pub fn visible(&self, seed: u32, bip_account: u32) -> impl Iterator<Item = &NotebookMeta> {
        self.active().filter(move |n| n.in_context(seed, bip_account))
    }

    /// Archived notebooks in wallet context.
    pub fn archived_in_context(
        &self,
        seed: u32,
        bip_account: u32,
    ) -> impl Iterator<Item = &NotebookMeta> {
        self.notebooks.iter().filter(move |n| n.archived && n.in_context(seed, bip_account))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_sorts_and_next_account() {
        let mut ix = NotebookIndex::default();
        let k0 = ix.create_bip86(0, 0, "");
        let k1 = ix.create_bip86(0, 0, "  Trips  ");
        assert_eq!((k0, k1), (0, 1));
        // A blank name takes the 1-based default; a typed one is kept.
        assert_eq!(ix.get(0).unwrap().name, "Notebook 1");
        assert_eq!(ix.get(1).unwrap().name, "Trips");
        assert_eq!(ix.notebooks[0].account, 0);
        assert_eq!(ix.next_account(), 2);
    }

    #[test]
    fn archive_and_rename() {
        let mut ix = NotebookIndex::default();
        ix.create_bip86(0, 0, "");
        ix.create_bip86(0, 0, "");
        ix.rename(1, "  Trips  ");
        assert_eq!(ix.get(1).unwrap().name, "Trips");
        ix.set_archived(0, true);
        assert_eq!(ix.active().count(), 1);
        assert_eq!(ix.archived_in_context(0, 0).count(), 1);
    }

    #[test]
    fn bip86_context_and_indexes() {
        let mut ix = NotebookIndex::default();
        let k1 = ix.create_bip86(0, 0, "Notes");
        let k2 = ix.create_bip86(0, 0, "");
        let k3 = ix.create_bip86(1, 0, "PostRotation");
        assert_eq!((k1, k2, k3), (0, 1, 2));
        // The default follows the RECEIVE index, not the notebook key.
        assert_eq!(ix.get(k2).unwrap().name, "Notebook 2");
        assert_eq!(ix.get(k1).unwrap().index, 0);
        assert_eq!(ix.get(k2).unwrap().index, 1); // same context → next index
        assert_eq!(ix.get(k3).unwrap().index, 0); // new seed → fresh indexes
        // seed 0 / account 0 sees its two; the seed-1 notebook is hidden.
        let vis: Vec<u32> = ix.visible(0, 0).map(|m| m.account).collect();
        assert_eq!(vis, vec![0, 1]);
        // After rotation to seed 1: only the seed-1 notebook.
        let vis: Vec<u32> = ix.visible(1, 0).map(|m| m.account).collect();
        assert_eq!(vis, vec![2]);
        // Seed 1 numbers its default names off ITS own receive indexes
        // (k3 took index 0 there), independently of seed 0's notebooks.
        let k4 = ix.create_bip86(1, 0, "");
        assert_eq!(k4, 3);
        assert_eq!(ix.get(k4).unwrap().index, 1);
        assert_eq!(ix.get(k4).unwrap().name, "Notebook 2");
    }

    #[test]
    fn roundtrip_preserves_fields() {
        let mut ix = NotebookIndex::default();
        ix.create_bip86(2, 1, "X");
        let json = serde_json::to_string(&ix).unwrap();
        let back: NotebookIndex = serde_json::from_str(&json).unwrap();
        let m = &back.notebooks[0];
        assert_eq!((m.seed, m.bip_account, m.index), (2, 1, 0));
        assert_eq!(m.name, "X");
    }
}
