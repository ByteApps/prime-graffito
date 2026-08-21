//! Key-export rendering for the "reveal" surfaces — every format
//! the graffito desktop app's importer (`parse_key_material`) accepts, rendered
//! from a bip86 identity so a Prime (or the app) can hand its keys off to
//! another wallet. Pure-Rust (base58check via `bs58`), so the device
//! builds it too; cross-tested byte-for-byte against rust-bitcoin.
//!
//! Granularity mirrors the graffito desktop app's import:
//! - **hex / WIF** are the single NOTEBOOK leaf `m/86'/coin'/account'/0/index`
//!   (one address — imports as a raw key).
//! - **xpub / xprv / descriptor** are the ACCOUNT `m/86'/coin'/account'`
//!   (the whole account — imports through the account picker / watch-only).
//!
//! The app seed is NEVER an output here — every path runs through the
//! one-way seed-entropy HKDF first (see `seeds.rs`). The device UI shows
//! only the subset chosen in PLAN-graffito-seed-rotation.md (no private
//! xprv); the app shows all of it.

use zeroize::Zeroizing;

use crate::bip32::{Xprv, HARDENED};
use crate::seeds::{coin_type, derive_leaf, seed_master};
use crate::{Error, Network};

/// The BIP-86 account node `m/86'/{coin}'/{account}'`.
fn account_node(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
) -> Result<Xprv, Error> {
    let master = seed_master(app_seed, seed_index)?;
    master.derive_path(&[86 | HARDENED, coin_type(network) | HARDENED, account | HARDENED])
}

/// WIF (compressed) of a 32-byte key for `network` — 0x80 mainnet / 0xEF
/// test, `0x01` compressed suffix, base58check.
fn wif(key: &[u8; 32], network: Network) -> Zeroizing<String> {
    let prefix: u8 = match network {
        Network::Mainnet => 0x80,
        _ => 0xEF,
    };
    let mut data = Zeroizing::new(Vec::with_capacity(34));
    data.push(prefix);
    data.extend_from_slice(key);
    data.push(0x01);
    Zeroizing::new(bs58::encode(data.as_slice()).with_check().into_string())
}

/// Notebook leaf private key as raw 32-byte hex — imports into
/// the graffito desktop app's hex field, reproducing this exact taproot notebook.
pub fn leaf_hex(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
    index: u32,
) -> Result<Zeroizing<String>, Error> {
    let leaf = Zeroizing::new(derive_leaf(app_seed, seed_index, network, account, index)?);
    // `.as_slice()` (an inherent `[u8; 32]` method, not the `AsRef` trait)
    // to disambiguate from the blanket `impl AsRef<hybrid_array::Array<..>>
    // for [T; N]` that ml-kem's hybrid-array dep now also brings into scope
    // — same 32 bytes, just a type-inference-safe way to reach them.
    Ok(Zeroizing::new(hex::encode(leaf.as_slice())))
}

/// Notebook leaf private key as a compressed WIF.
pub fn leaf_wif(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
    index: u32,
) -> Result<Zeroizing<String>, Error> {
    let leaf = Zeroizing::new(derive_leaf(app_seed, seed_index, network, account, index)?);
    Ok(wif(&leaf, network))
}

/// Account xpub (`xpub`/`tpub`) — public, for watch-only import elsewhere.
pub fn account_xpub(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
) -> Result<String, Error> {
    account_node(app_seed, seed_index, network, account)?.to_xpub(network)
}

/// Account xprv (`xprv`/`tprv`) — PRIVATE, unlocks the whole account.
/// the graffito desktop app only; the device reveal omits it.
pub fn account_xprv(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
) -> Result<Zeroizing<String>, Error> {
    Ok(Zeroizing::new(account_node(app_seed, seed_index, network, account)?.to_xprv(network)))
}

/// Key-origin taproot descriptor
/// `tr([<masterfp>/86'/<coin>'/<account>']<account_xpub>/<0;1>/*)` — the
/// hardware-wallet watch-only form the graffito desktop app imports.
pub fn account_descriptor(
    app_seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
) -> Result<String, Error> {
    let master = seed_master(app_seed, seed_index)?;
    let fp = master.fingerprint_hex()?;
    let coin = coin_type(network);
    let node =
        master.derive_path(&[86 | HARDENED, coin | HARDENED, account | HARDENED])?;
    let xpub = node.to_xpub(network)?;
    Ok(format!("tr([{fp}/86'/{coin}'/{account}']{xpub}/<0;1>/*)"))
}
