//! Spending-wallet bookkeeping (PLAN-graffito-funding-unification.md,
//! "Prime device" + M2). One P2WPKH BIP-84 wallet per (network, seed,
//! bip_account) context — the SAME granularity notebooks are visible at
//! (`NotebookMeta::in_context`), since a spending wallet is a property of
//! the account, not of any one notebook within it.
//!
//! **Storage home** (chosen per the funding-unification port brief):
//! persisted as a sibling section of `notebooks.json`
//! (`NotebookIndex.spending`), NOT its own file. Why: `config.json` is a
//! single device-wide struct with no per-context slots, unsuited to holding
//! potentially many (network × seed × account) sections; `state-<net>-
//! <account>.json` is strictly per-NOTEBOOK (one identity's notes/UTXO
//! ledger) while a spending wallet is per-ACCOUNT — several sibling
//! notebooks of one account must all see the SAME spending wallet, which a
//! per-notebook file can't express without duplicating (and desyncing) the
//! bookkeeping; the graffito desktop app hit exactly this bug living
//! per-identity and fixed it by moving to its account-level
//! `notebooks-<net>-<fp8>.json`
//! (PLAN's M3.1 note). `notebooks.json` already indexes data by
//! (seed, bip_account) via `NotebookMeta`, so a new sibling array keyed the
//! same way is the natural existing home, not a new file.

use serde::{Deserialize, Serialize};

/// One address the spending wallet has issued (receive OR change chain).
/// Enough to re-derive its signing key on demand via
/// `notes_core::seeds::derive_spending_key(app_seed, seed, network,
/// bip_account, chain, index)` — never persisted itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendingAddress {
    /// 0 = receive chain, 1 = change chain (BIP-84 convention).
    pub chain: u32,
    pub index: u32,
    pub address: String,
    pub spk_hex: String,
}

/// One spending-wallet UTXO, tagged with the (chain, index) that owns it so
/// signing can re-derive the exact key — unlike the notebook ledger, a
/// spending wallet's coins can each belong to a DIFFERENT fresh address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendingUtxo {
    pub txid: String, // display hex
    pub vout: u32,
    pub value: u64,
    pub chain: u32,
    pub index: u32,
}

/// Spending-wallet bookkeeping for one (network, seed, bip_account)
/// context: whether it's turned on, the next unused receive/change index
/// (fresh-address discipline), every address issued so far (feeds the
/// scanner's self-spk SET — `notes_core::bundle::extract_notes_multi`), and
/// its own UTXO ledger (mirrors `State.utxos`' unconfirmed-chaining
/// pattern: signing drops spent inputs and adds change immediately).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct SpendingSection {
    pub network: String,
    pub seed: u32,
    pub bip_account: u32,
    pub enabled: bool,
    pub next_receive: u32,
    pub next_change: u32,
    pub used: Vec<SpendingAddress>,
    pub utxos: Vec<SpendingUtxo>,
}

impl SpendingSection {
    fn new(network: &str, seed: u32, bip_account: u32) -> Self {
        SpendingSection {
            network: network.to_string(),
            seed,
            bip_account,
            enabled: false,
            next_receive: 0,
            next_change: 0,
            used: Vec::new(),
            utxos: Vec::new(),
        }
    }

    fn matches(&self, network: &str, seed: u32, bip_account: u32) -> bool {
        self.network == network && self.seed == seed && self.bip_account == bip_account
    }

    pub fn balance(&self) -> u64 {
        self.utxos.iter().map(|u| u.value).sum()
    }

    /// Every issued address's scriptPubKey, decoded — the self-spk set this
    /// context's spending wallet contributes to the scanner (unioned with
    /// the notebook's own spk by the caller).
    pub fn self_spks(&self) -> Vec<Vec<u8>> {
        self.used.iter().filter_map(|a| hex::decode(&a.spk_hex).ok()).collect()
    }

    /// Record that (chain, index) has been issued/used (idempotent), and
    /// bump the matching next-index counter past it — fresh-address
    /// discipline: an index is never handed out twice, whether it came from
    /// an explicit "issue a receive address" action or from discovering a
    /// change output on sign.
    pub fn mark_used(&mut self, addr: SpendingAddress) {
        let next = if addr.chain == 1 { &mut self.next_change } else { &mut self.next_receive };
        if addr.index >= *next {
            *next = addr.index + 1;
        }
        if !self.used.iter().any(|a| a.chain == addr.chain && a.index == addr.index) {
            self.used.push(addr);
        }
    }

    /// Replace the UTXO ledger wholesale (bundle import — same convention
    /// as the notebook's `State.utxos`, which the CLAUDE.md state-contract
    /// documents as fully resynced from each bundle rather than merged).
    pub fn set_utxos(&mut self, utxos: Vec<SpendingUtxo>) {
        self.utxos = utxos;
    }

    /// Drop spent coins and add change (unconfirmed chaining, mirroring
    /// `State`'s notebook-ledger update on sign).
    pub fn apply_spend(&mut self, spent: &[(String, u32)], change: Option<SpendingUtxo>) {
        self.utxos.retain(|u| !spent.iter().any(|(t, v)| *t == u.txid && *v == u.vout));
        if let Some(c) = change {
            self.utxos.push(c);
        }
    }
}

/// Extension methods on the notebook index for the spending-wallet
/// sections. Kept as a trait over `notebooks::NotebookIndex` (rather than a
/// field defined there) so the notebook module stays about notebooks, and
/// this module stays the one place spending-wallet bookkeeping lives —
/// mirrors how `notebooks.rs` and this module both operate on plain
/// `notebooks.json`-shaped data without either owning the whole file.
pub trait SpendingIndex {
    fn spending_sections(&self) -> &[SpendingSection];
    fn spending_sections_mut(&mut self) -> &mut Vec<SpendingSection>;

    fn spending(&self, network: &str, seed: u32, bip_account: u32) -> Option<&SpendingSection> {
        self.spending_sections().iter().find(|s| s.matches(network, seed, bip_account))
    }

    /// Get-or-create the section for this context (does NOT enable it —
    /// callers still gate everything on `.enabled`).
    fn spending_mut(&mut self, network: &str, seed: u32, bip_account: u32) -> &mut SpendingSection {
        if !self.spending_sections().iter().any(|s| s.matches(network, seed, bip_account)) {
            self.spending_sections_mut().push(SpendingSection::new(network, seed, bip_account));
        }
        self.spending_sections_mut()
            .iter_mut()
            .find(|s| s.matches(network, seed, bip_account))
            .expect("just inserted")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fixture {
        spending: Vec<SpendingSection>,
    }
    impl SpendingIndex for Fixture {
        fn spending_sections(&self) -> &[SpendingSection] {
            &self.spending
        }
        fn spending_sections_mut(&mut self) -> &mut Vec<SpendingSection> {
            &mut self.spending
        }
    }

    #[test]
    fn get_or_create_is_scoped_by_network_seed_account() {
        let mut ix = Fixture::default();
        assert!(ix.spending("mainnet", 0, 0).is_none());
        ix.spending_mut("mainnet", 0, 0).enabled = true;
        assert!(ix.spending("mainnet", 0, 0).unwrap().enabled);
        // A different network is a DIFFERENT section, even same seed/account.
        assert!(ix.spending("testnet4", 0, 0).is_none());
        ix.spending_mut("testnet4", 0, 0);
        assert!(!ix.spending("testnet4", 0, 0).unwrap().enabled);
        // A different account is also separate.
        ix.spending_mut("mainnet", 0, 1).enabled = false;
        assert_eq!(ix.spending_sections().len(), 3);
    }

    #[test]
    fn mark_used_is_idempotent_and_advances_next_index() {
        let mut s = SpendingSection::new("mainnet", 0, 0);
        s.mark_used(SpendingAddress {
            chain: 0,
            index: 0,
            address: "bc1qA".into(),
            spk_hex: "0014aa".into(),
        });
        assert_eq!(s.next_receive, 1);
        assert_eq!(s.next_change, 0);
        s.mark_used(SpendingAddress {
            chain: 1,
            index: 3,
            address: "bc1qC".into(),
            spk_hex: "0014bb".into(),
        });
        assert_eq!(s.next_change, 4);
        // Re-marking an already-used lower index never regresses next_*.
        s.mark_used(SpendingAddress {
            chain: 0,
            index: 0,
            address: "bc1qA".into(),
            spk_hex: "0014aa".into(),
        });
        assert_eq!(s.next_receive, 1);
        assert_eq!(s.used.len(), 2);
    }

    #[test]
    fn self_spks_decodes_every_used_address() {
        let mut s = SpendingSection::new("mainnet", 0, 0);
        s.mark_used(SpendingAddress {
            chain: 0,
            index: 0,
            address: "bc1qA".into(),
            spk_hex: "0014aabbccddeeff00112233445566778899aabb".into(),
        });
        s.mark_used(SpendingAddress {
            chain: 1,
            index: 0,
            address: "bc1qB".into(),
            spk_hex: "not-hex".into(), // skipped, never panics
        });
        let spks = s.self_spks();
        assert_eq!(spks.len(), 1);
        assert_eq!(spks[0], hex::decode("0014aabbccddeeff00112233445566778899aabb").unwrap());
    }

    #[test]
    fn apply_spend_drops_inputs_and_adds_change() {
        let mut s = SpendingSection::new("mainnet", 0, 0);
        s.utxos.push(SpendingUtxo { txid: "t1".into(), vout: 0, value: 1000, chain: 0, index: 0 });
        s.utxos.push(SpendingUtxo { txid: "t2".into(), vout: 1, value: 2000, chain: 0, index: 1 });
        s.apply_spend(
            &[("t1".into(), 0)],
            Some(SpendingUtxo { txid: "t3".into(), vout: 0, value: 900, chain: 1, index: 0 }),
        );
        assert_eq!(s.balance(), 2900);
        assert_eq!(s.utxos.len(), 2);
        assert!(s.utxos.iter().any(|u| u.txid == "t3"));
        assert!(!s.utxos.iter().any(|u| u.txid == "t1"));
    }

    #[test]
    fn roundtrip_preserves_fields() {
        let mut ix = Fixture::default();
        let sec = ix.spending_mut("testnet4", 2, 1);
        sec.enabled = true;
        sec.mark_used(SpendingAddress {
            chain: 0,
            index: 0,
            address: "tb1qX".into(),
            spk_hex: "0014ff".into(),
        });
        let json = serde_json::to_string(&ix.spending).unwrap();
        let back: Vec<SpendingSection> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert!(back[0].enabled);
        assert_eq!(back[0].used.len(), 1);
        assert_eq!(back[0].network, "testnet4");
    }
}
