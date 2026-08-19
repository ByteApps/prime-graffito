//! BIP-84 (native-segwit spending wallet) derivation —
//! PLAN-graffito-funding-unification.md M0. The spec's own test
//! mnemonic and account-0 addresses through our whole stack, plus a
//! rust-bitcoin cross-check of the full app_seed → spending-key pipeline,
//! mirroring `seed_vectors.rs`'s BIP-86 treatment.

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use notes_core::{address, bip32, bip39, keys, seeds, Network};
use std::str::FromStr;

fn app_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(5);
    }
    s
}

#[test]
fn bip84_spec_address_vectors() {
    // https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki — the
    // spec's own test mnemonic and account-0 addresses, through OUR whole
    // stack: words → seed → path → compressed pubkey → HASH160 → bech32
    // (witness v0, NOT v1/bech32m).
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = bip39::mnemonic_to_seed(mnemonic, "");
    let master = bip32::Xprv::from_seed(&seed).unwrap();
    let account =
        master.derive_path(&[84 | bip32::HARDENED, bip32::HARDENED, bip32::HARDENED]).unwrap();

    let cases = [
        (0u32, 0u32, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), // first receive
        (0, 1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),       // second receive
        (1, 0, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"),       // first change
    ];
    for (chain, index, expected) in cases {
        let leaf = account.derive_path(&[chain, index]).unwrap();
        let pubkey = leaf.pubkey().unwrap();
        let hash = keys::hash160(&pubkey);
        let addr = address::p2wpkh_address(Network::Mainnet, &hash);
        assert_eq!(addr, expected, "chain {chain} index {index}");
        let spk = address::p2wpkh_script_pubkey(&hash);
        assert_eq!(spk, [&[0x00, 0x14][..], &hash[..]].concat(), "spk chain {chain} index {index}");
    }
}

/// The full app_seed → `seeds::derive_spending_key` pipeline (BIP-84 leaf,
/// pubkey, scriptPubKey, address) cross-checked byte-for-byte against
/// rust-bitcoin over the same rotation-seed mnemonic, several
/// (coin, account, chain, index) combinations.
#[test]
fn bip84_cross_check_rust_bitcoin() {
    let seed = app_seed();
    let seed_index = 0u32;
    let secp = Secp256k1::new();
    let words = seeds::seed_mnemonic(&seed, seed_index).unwrap();
    let bip39_seed = bip39::mnemonic_to_seed(&words, "");
    let theirs_master = Xpriv::new_master(bitcoin::Network::Bitcoin, &bip39_seed).unwrap();

    let cases = [
        (0u32, 0u32, 0u32, 0u32, Network::Mainnet),
        (0, 0, 1, 0, Network::Mainnet),
        (1, 3, 0, 7, Network::Testnet4),
        (1, 9999, 1, 20, Network::Testnet4),
    ];
    for (coin, account, chain, index, net) in cases {
        let ours = seeds::derive_spending_key(&seed, seed_index, net, account, chain, index)
            .unwrap();

        let path =
            DerivationPath::from_str(&format!("m/84'/{coin}'/{account}'/{chain}/{index}"))
                .unwrap();
        let theirs = theirs_master.derive_priv(&secp, &path).unwrap();
        assert_eq!(
            ours.seckey,
            theirs.private_key.secret_bytes(),
            "seckey coin={coin} account={account} chain={chain} index={index}"
        );

        let theirs_pubkey =
            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &theirs.private_key);
        assert_eq!(
            ours.pubkey,
            theirs_pubkey.serialize(),
            "pubkey coin={coin} account={account} chain={chain} index={index}"
        );

        let compressed = bitcoin::CompressedPublicKey(theirs_pubkey);
        let btc_net = if coin == 0 { bitcoin::Network::Bitcoin } else { bitcoin::Network::Testnet4 };
        let theirs_addr = bitcoin::Address::p2wpkh(&compressed, btc_net);
        assert_eq!(
            ours.address,
            theirs_addr.to_string(),
            "address coin={coin} account={account} chain={chain} index={index}"
        );
        assert_eq!(
            ours.script_pubkey,
            theirs_addr.script_pubkey().to_bytes(),
            "spk coin={coin} account={account} chain={chain} index={index}"
        );
    }
}
