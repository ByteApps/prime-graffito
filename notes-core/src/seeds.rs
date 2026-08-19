//! Recovery seeds — the composed pipeline from `GetAppSeed` to a BIP-86
//! notebook leaf (PLAN-graffito-seed-rotation.md):
//!
//! ```text
//! app_seed ── keys::derive_seed_entropy(·, seed_index) ─▶ entropy   ★ FROZEN, ours
//! entropy  ── BIP-39 (24 words, empty passphrase) ──────▶ seed      standard
//! seed     ── BIP-32 master ── m/86'/{coin}'/{account}'/0/{index} ─▶ leaf
//! ```
//!
//! Everything below the ★ is the standard pipeline every wallet
//! implements — which is exactly why the 24 words alone recover a seed's
//! notebooks anywhere (funds in any taproot wallet; notes, encryption and
//! directed-note ECDH in the graffito desktop app via its plain BIP-39 import).
//! The rotation index appears ONLY inside `derive_seed_entropy`.

use zeroize::Zeroizing;

use crate::bip32::{Xprv, HARDENED};
use crate::bip39;
use crate::keys::derive_seed_entropy;
use crate::{Error, Network};

/// BIP-44 coin type for the BIP-86 path: 0' on mainnet, 1' on every test
/// network (the BIP-44 convention; matches the graffito desktop app's rule).
pub fn coin_type(network: Network) -> u32 {
    match network {
        Network::Mainnet => 0,
        _ => 1,
    }
}

/// The 24 recovery words for rotation `seed_index`. Crown jewels: the
/// caller must show them and drop them — never persist, never log.
pub fn seed_mnemonic(app_seed: &[u8; 32], seed_index: u32) -> Result<Zeroizing<String>, Error> {
    let entropy = Zeroizing::new(derive_seed_entropy(app_seed, seed_index));
    Ok(Zeroizing::new(bip39::entropy_to_mnemonic(entropy.as_ref())?))
}

/// Master xprv of rotation `seed_index` (empty BIP-39 passphrase — the
/// the graffito desktop app import convention).
pub fn seed_master(app_seed: &[u8; 32], seed_index: u32) -> Result<Xprv, Error> {
    let mnemonic = seed_mnemonic(app_seed, seed_index)?;
    let seed = Zeroizing::new(bip39::mnemonic_to_seed(&mnemonic, ""));
    Xprv::from_seed(seed.as_ref())
}

/// BIP-86 leaf secret `m/86'/{coin}'/{account}'/0/{index}` for notebook
/// `index` of `account` under rotation seed `seed_index`.
pub fn derive_leaf(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
    index: u32,
) -> Result<[u8; 32], Error> {
    let master = seed_master(app_seed, seed_index)?;
    let leaf = master.derive_path(&[
        86 | HARDENED,
        coin_type(network) | HARDENED,
        account | HARDENED,
        0,
        index,
    ])?;
    Ok(leaf.key)
}

/// Master fingerprint (8-char hex) of rotation `seed_index` — for logs
/// and store-file names, mirroring the graffito desktop app's `index_fp8`. Never
/// a secret.
pub fn seed_fingerprint_hex(app_seed: &[u8; 32], seed_index: u32) -> Result<String, Error> {
    seed_master(app_seed, seed_index)?.fingerprint_hex()
}

// ---------------------------------------------------------------------
// BIP-84 spending wallet branch (PLAN-graffito-funding-unification.md,
// "Derivation (the core spec)") — the SAME master material as the BIP-86
// notebook leaf above, second standard branch:
//
//   xprv_i ── m/84'/{coin}'/{account}'/{chain}/{index} ──▶ spending keys
//
// `chain` 0 = receive, 1 = change; P2WPKH (bc1q…), unlike the notebook's
// P2TR. Nothing bespoke below the words — words_i alone restore this
// branch in any mainstream wallet, same as the BIP-86 one.
// ---------------------------------------------------------------------

fn derive_spending_node(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
    chain: u32,
    index: u32,
) -> Result<Xprv, Error> {
    let master = seed_master(app_seed, seed_index)?;
    master.derive_path(&[
        84 | HARDENED,
        coin_type(network) | HARDENED,
        account | HARDENED,
        chain,
        index,
    ])
}

/// BIP-84 leaf secret `m/84'/{coin}'/{account}'/{chain}/{index}` of the
/// spending-wallet branch for notebook-account `account` under rotation
/// seed `seed_index`. `chain`: 0 = receive, 1 = change.
pub fn derive_spending_leaf(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
    chain: u32,
    index: u32,
) -> Result<[u8; 32], Error> {
    Ok(derive_spending_node(app_seed, seed_index, network, account, chain, index)?.key)
}

/// A derived BIP-84 spending key: the secp keypair, its compressed pubkey,
/// the P2WPKH scriptPubKey, and the bech32 (witness v0) address — the
/// one-stop shape both the wpkh signer (`wpkh.rs`) and a funding-picker UI
/// need for one receive/change index.
pub struct SpendingKey {
    pub seckey: [u8; 32],
    pub pubkey: [u8; 33],
    pub script_pubkey: Vec<u8>,
    pub address: String,
}

/// [`derive_spending_leaf`] plus the derived pubkey/scriptPubKey/address.
pub fn derive_spending_key(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
    chain: u32,
    index: u32,
) -> Result<SpendingKey, Error> {
    let node = derive_spending_node(app_seed, seed_index, network, account, chain, index)?;
    let pubkey = node.pubkey()?;
    let pubkey_hash = crate::keys::hash160(&pubkey);
    Ok(SpendingKey {
        seckey: node.key,
        pubkey,
        script_pubkey: crate::address::p2wpkh_script_pubkey(&pubkey_hash),
        address: crate::address::p2wpkh_address(network, &pubkey_hash),
    })
}
