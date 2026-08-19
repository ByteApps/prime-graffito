//! Recovery-seeds vectors (PLAN-graffito-seed-rotation.md):
//! - our ported BIP-39 against the independent `bip39` crate + the spec's
//!   best-known vector,
//! - our ported BIP-32 against rust-bitcoin's `Xpriv` over the full
//!   BIP-86 path,
//! - the BIP-86 spec address vectors end-to-end through our pipeline,
//! - FROZEN pins for `derive_seed_entropy`, `enc_key_from_leaf`, and the
//!   whole app_seed → address pipeline (wipe recovery for bip86 notebooks
//!   depends on these never changing — same rule as the HKDF vectors in
//!   `tests/vectors.rs`).

// The external cross-check crate, aliased — `bip39` unqualified is OUR
// notes_core module below.
use ::bip39 as bip39_crate;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use notes_core::bundle::Identity;
use notes_core::keys::{derive_seed_entropy, enc_key_from_leaf};
use notes_core::{bip32, bip39, seeds, Network};
use std::str::FromStr;

fn fixed_app_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    s
}

#[test]
fn bip39_spec_vector() {
    // The canonical all-zero 128-bit vector from the BIP-39 spec.
    let mnemonic = bip39::entropy_to_mnemonic(&[0u8; 16]).unwrap();
    assert_eq!(
        mnemonic,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    // Its TREZOR-passphrase seed, from the same spec table.
    let seed = bip39::mnemonic_to_seed(&mnemonic, "TREZOR");
    assert_eq!(
        hex::encode(seed),
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    );
}

#[test]
fn bip39_cross_check_independent_crate() {
    // Our port vs the rust-bitcoin ecosystem's implementation, all three
    // entropy sizes, patterned bytes.
    for len in [16usize, 24, 32] {
        for fill in [0x00u8, 0x7f, 0xff, 0x42] {
            let mut entropy = vec![fill; len];
            for (i, b) in entropy.iter_mut().enumerate() {
                *b = b.wrapping_add(i as u8);
            }
            let ours = bip39::entropy_to_mnemonic(&entropy).unwrap();
            let theirs = bip39::mnemonic_to_seed(&ours, "");
            let reference = bip39_crate::Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(ours, reference.to_string(), "mnemonic mismatch len={len} fill={fill}");
            assert_eq!(
                theirs,
                reference.to_seed(""),
                "seed mismatch len={len} fill={fill}"
            );
        }
    }
}

#[test]
fn bip32_cross_check_rust_bitcoin() {
    // Same 64-byte seed through our Xprv and rust-bitcoin's, along the
    // full BIP-86 path (hardened AND normal steps), both networks' coins.
    let seed = bip39::mnemonic_to_seed(
        &bip39::entropy_to_mnemonic(&fixed_app_seed()).unwrap(),
        "",
    );
    let secp = Secp256k1::new();
    let ours_master = bip32::Xprv::from_seed(&seed).unwrap();
    let theirs_master = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed).unwrap();
    assert_eq!(ours_master.key, theirs_master.private_key.secret_bytes());
    assert_eq!(
        ours_master.fingerprint().unwrap(),
        theirs_master.fingerprint(&secp).to_bytes()
    );

    for (coin, account, index) in [(0u32, 0u32, 0u32), (1, 0, 0), (0, 3, 7), (1, 9999, 20)] {
        let ours = ours_master
            .derive_path(&[
                86 | bip32::HARDENED,
                coin | bip32::HARDENED,
                account | bip32::HARDENED,
                0,
                index,
            ])
            .unwrap();
        let path =
            DerivationPath::from_str(&format!("m/86'/{coin}'/{account}'/0/{index}")).unwrap();
        let theirs = theirs_master.derive_priv(&secp, &path).unwrap();
        assert_eq!(
            ours.key,
            theirs.private_key.secret_bytes(),
            "leaf mismatch m/86'/{coin}'/{account}'/0/{index}"
        );
    }
}

#[test]
fn bip86_spec_address_vectors() {
    // The BIP-86 spec's test mnemonic and first receive addresses,
    // through OUR whole stack: words → seed → path → BIP-341 tweak →
    // bech32m encoding.
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let master = bip32::Xprv::from_seed(&seed).unwrap();
    let cases = [
        (0u32, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
        (1, "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"),
    ];
    for (index, expected) in cases {
        let leaf = master
            .derive_path(&[86 | bip32::HARDENED, bip32::HARDENED, bip32::HARDENED, 0, index])
            .unwrap();
        let identity = Identity::from_leaf_secret(&leaf.key).unwrap();
        assert_eq!(identity.address(Network::Mainnet), expected, "index {index}");
    }
}

// ---------------------------------------------------------------------
// FROZEN pins — regenerating these values means every bip86 notebook's
// wipe recovery breaks. Never update; fix the code instead.
//
// REGENERATED 2026-08-18 for the Graffito crypto epoch (KEY_SALT/ENC_SALT/
// SEED_SALT/ENC_APP_SALT rebound to `prime-graffito/...`/`graffito/...` —
// see keys.rs module docs). This was a deliberate one-time break, not a
// routine update: every value below was regenerated by RUNNING the new
// code (never hand-computed), then re-frozen.
// ---------------------------------------------------------------------

#[test]
fn frozen_seed_entropy_vectors() {
    let app_seed = fixed_app_seed();
    let pins = [
        (0u32, "cfd1e49ca5942e4546d134b6a96019f9291b8025b76e830082894fca0597781c"),
        (1, "b0d449857799b35f533fe97d887e3ea873bc424187d030e5b65ee1ca55828990"),
        (9999, "b865b613d99a6d581eae638b69b553333a49a90e1cc13dd26042cc2c8b98b1e3"),
    ];
    for (index, expected) in pins {
        assert_eq!(
            hex::encode(derive_seed_entropy(&app_seed, index)),
            expected,
            "seed entropy index {index}"
        );
    }
    // Distinctness: rotation indexes must not collide.
    assert_ne!(
        derive_seed_entropy(&app_seed, 0),
        derive_seed_entropy(&app_seed, 1)
    );
    // One-way sanity: entropy is not the app seed itself in any form.
    assert_ne!(derive_seed_entropy(&app_seed, 0), app_seed);
}

#[test]
fn frozen_enc_key_from_leaf_vector() {
    // The relocated graffito-desktop-app rule — the desktop app pins the
    // same value from its side before delegating (byte-identical bar),
    // once it adopts the post-epoch `graffito/enc/v1` salt.
    let leaf = fixed_app_seed();
    assert_eq!(
        hex::encode(enc_key_from_leaf(&leaf)),
        "cad138e75c9588e0442a9b7e3bbc016263049c56eb7fce910210e5ce13895675"
    );
}

#[test]
fn frozen_pipeline_vectors() {
    // app_seed → seed 0/1 → account/index leaves → addresses. The full
    // pipeline pinned so any regression anywhere in the chain trips.
    let app_seed = fixed_app_seed();
    let pins = [
        // (seed_index, network, account, index, address)
        (0u32, Network::Mainnet, 0u32, 0u32, "bc1p0plxgrp03zh56hnydnuagyjyn6rue3e525cccm75rpfzake985lss7kc7a"),
        (0, Network::Testnet4, 0, 0, "tb1pnum8zpf8wd67mllwlgaehnv640p847d25advwfvf6tpeuskjnq3s3fdy3y"),
        (0, Network::Mainnet, 1, 2, "bc1p8dzkmvea0e6w9kalljyes2l874puhmv39drtepn4xfu8mpzgvdjsdtfsnn"),
        (1, Network::Mainnet, 0, 0, "bc1pcu6ut0h64vcs97kw628fh6rnzlauyceryj8fv9wtxt2mjacrk2zqrq9ydh"),
    ];
    for (seed_index, network, account, index, expected) in pins {
        let id = Identity::from_bip86(&app_seed, seed_index, network, account, index).unwrap();
        assert_eq!(
            id.address(network),
            expected,
            "seed {seed_index} {network:?} account {account} index {index}"
        );
    }
    // The mnemonic itself is stable (word count + fingerprint pin).
    let words = seeds::seed_mnemonic(&app_seed, 0).unwrap();
    assert_eq!(words.split_whitespace().count(), 24);
    assert_eq!(seeds::seed_fingerprint_hex(&app_seed, 0).unwrap(), "28c5ded0");
}
