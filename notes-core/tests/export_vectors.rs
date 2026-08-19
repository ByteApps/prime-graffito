//! Cross-check the key-export rendering (`notes_core::export`) against
//! rust-bitcoin: WIF, account xprv/xpub, and the key-origin descriptor a
//! Prime (or the graffito desktop app) reveals must be byte-identical to what the
//! reference implementation produces for the same BIP-86 path — that is
//! what makes "reveal on the device, import into another wallet" sound.

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::PrivateKey;
use notes_core::{bip39, export, seeds, Network};
use std::str::FromStr;

fn app_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    s
}

fn btc_net(n: Network) -> bitcoin::Network {
    match n {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        _ => bitcoin::Network::Testnet,
    }
}

/// rust-bitcoin master xpriv for our rotation seed `seed_index`.
fn reference_master(seed_index: u32, network: Network) -> (Secp256k1<bitcoin::secp256k1::All>, Xpriv) {
    let words = seeds::seed_mnemonic(&app_seed(), seed_index).unwrap();
    let seed = bip39::mnemonic_to_seed(&words, "");
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(btc_net(network), &seed).unwrap();
    (secp, master)
}

#[test]
fn export_matches_rust_bitcoin() {
    let seed = app_seed();
    // (seed_index, network, account, notebook index)
    let cases = [
        (0u32, Network::Mainnet, 0u32, 0u32),
        (0, Network::Testnet4, 0, 5),
        (1, Network::Mainnet, 2, 3),
        (3, Network::Signet, 4, 7),
    ];

    for (si, net, acct, idx) in cases {
        let (secp, master) = reference_master(si, net);
        let coin = if matches!(net, Network::Mainnet) { 0 } else { 1 };

        // Account m/86'/coin'/account'
        let acct_path = DerivationPath::from_str(&format!("m/86'/{coin}'/{acct}'")).unwrap();
        let ref_acct = master.derive_priv(&secp, &acct_path).unwrap();
        let ref_xpub = Xpub::from_priv(&secp, &ref_acct);

        assert_eq!(
            *export::account_xprv(&seed, si, net, acct).unwrap(),
            ref_acct.to_string(),
            "xprv {si}/{coin}/{acct}"
        );
        assert_eq!(
            export::account_xpub(&seed, si, net, acct).unwrap(),
            ref_xpub.to_string(),
            "xpub {si}/{coin}/{acct}"
        );

        // Descriptor tr([fp/86'/coin'/acct']xpub/<0;1>/*)
        let fp = master.fingerprint(&secp).to_string();
        let want_desc = format!("tr([{fp}/86'/{coin}'/{acct}']{}/<0;1>/*)", ref_xpub);
        assert_eq!(
            export::account_descriptor(&seed, si, net, acct).unwrap(),
            want_desc,
            "descriptor {si}/{coin}/{acct}"
        );

        // Notebook leaf m/86'/coin'/account'/0/index
        let leaf_path =
            DerivationPath::from_str(&format!("m/86'/{coin}'/{acct}'/0/{idx}")).unwrap();
        let ref_leaf = master.derive_priv(&secp, &leaf_path).unwrap();
        let ref_sk = ref_leaf.private_key.secret_bytes();

        assert_eq!(
            *export::leaf_hex(&seed, si, net, acct, idx).unwrap(),
            hex::encode(ref_sk),
            "hex {si}/{coin}/{acct}/{idx}"
        );
        let ref_wif = PrivateKey::new(ref_leaf.private_key, btc_net(net)).to_wif();
        assert_eq!(
            *export::leaf_wif(&seed, si, net, acct, idx).unwrap(),
            ref_wif,
            "wif {si}/{coin}/{acct}/{idx}"
        );
    }
}
