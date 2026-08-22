//! Stateless CLI over notes-core for the regtest end-to-end test — plays
//! the DEVICE role from the host: derive address, compose+sign notes from
//! a sync bundle, scan a bundle back into notes. The e2e script
//! (../../scripts/regtest-e2e.sh) plays the companion with bitcoin-cli.
//!
//! App seed comes from NOTES_APP_SEED (64 hex chars), defaulting to a
//! fixed test seed. NOT part of the shipped app.

use std::io::Read;

use notes_core::address::Recipient;
use notes_core::bundle::{
    compose_directed_note, compose_directed_note_multi_with_change, compose_note, extract_notes,
    Identity, SyncBundle,
};
use notes_core::keys::generate_aux_rand;
use notes_core::tx::LockTimePolicy;
use notes_core::Network;

fn app_seed() -> [u8; 32] {
    let mut seed = [7u8; 32];
    if let Ok(hex_seed) = std::env::var("NOTES_APP_SEED") {
        hex::decode_to_slice(hex_seed.trim(), &mut seed).expect("NOTES_APP_SEED: 64 hex chars");
    }
    seed
}

fn read_bundle(path: &str) -> SyncBundle {
    let mut json = String::new();
    if path == "-" {
        std::io::stdin().read_to_string(&mut json).unwrap();
    } else {
        json = std::fs::read_to_string(path).unwrap();
    }
    SyncBundle::from_json(&json).expect("invalid sync bundle JSON")
}

/// The `nLockTime` this CLI builds with, mirroring what the device does:
/// the configured [`LockTimePolicy`] resolved against the last chain height
/// we know — which, in the device role, is the tip carried by the sync
/// bundle we were handed.
///
/// `NOTES_LOCKTIME_POLICY` overrides it for tests: `tip` (default), `zero`,
/// or a bare height for `Custom`. Defaulting to `tip` means the e2e scripts
/// exercise a real non-zero locktime without needing new flags.
fn locktime_for(tip: Option<u32>) -> u32 {
    let policy = match std::env::var("NOTES_LOCKTIME_POLICY").ok().as_deref() {
        None | Some("") | Some("tip") => LockTimePolicy::Tip,
        Some("zero") => LockTimePolicy::Zero,
        Some(h) => LockTimePolicy::Custom {
            height: h.parse().expect("NOTES_LOCKTIME_POLICY: tip|zero|<height>"),
        },
    };
    policy.resolve(tip)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let identity = Identity::from_app_seed(&app_seed()).unwrap();

    match args.get(1).map(String::as_str) {
        Some("address") => {
            let network = Network::from_str_opt(&args[2]).expect("network");
            println!("{}", identity.address(network));
        }
        // Recovery seeds (PLAN-graffito-seed-rotation.md): mirror what
        // the device derives so the e2e can cross-check the sim UI and
        // feed the words to the graffito desktop app import.
        Some("seed-words") => {
            // seed-words <seed_index>
            let index: u32 = args[2].parse().expect("seed index");
            let words = notes_core::seeds::seed_mnemonic(&app_seed(), index).unwrap();
            println!("{}", &*words);
        }
        Some("seed-address") => {
            // seed-address <network> <seed_index> <account> <index>
            let network = Network::from_str_opt(&args[2]).expect("network");
            let seed: u32 = args[3].parse().expect("seed index");
            let account: u32 = args[4].parse().expect("account");
            let index: u32 = args[5].parse().expect("receive index");
            let id = Identity::from_bip86(&app_seed(), seed, network, account, index).unwrap();
            println!("{}", id.address(network));
        }
        // Spending wallet (funding-unification, device port): stateless
        // BIP-84 leaf derivation, mirroring the graffito desktop app's `cli
        // spending-derive`/`spending-address` (same arg order as
        // `seed-address` above: network first). Prints
        // "<address> <spk_hex>" so a bash caller can seed
        // notebooks.json's spending[].used entry with both fields
        // (`ui-automation/tests/graffito.sh`'s mixed-compose leg).
        // pq-fingerprint <network> <seed_index> <account> <index> <512|768|1024>
        // — the notebook's derived ML-KEM receive-key fingerprint, host-side.
        // Byte-true cross-check surface for the device UI suite: the device
        // logs the fingerprint it RENDERS (cb: pq-key fp=…) and the suite
        // asserts equality with this independent derivation (the dense
        // armor QR is optically unverifiable at device resolution — ~1.2px
        // per module — so the fingerprint, not zbarimg, is the proof).
        Some("pq-fingerprint") => {
            let network = Network::from_str_opt(&args[2]).expect("network");
            let seed_index: u32 = args[3].parse().expect("seed index");
            let account: u32 = args[4].parse().expect("account");
            let index: u32 = args[5].parse().expect("index");
            let alg = match args[6].as_str() {
                "512" => notes_core::pq::MlKemAlg::MlKem512,
                "1024" => notes_core::pq::MlKemAlg::MlKem1024,
                _ => notes_core::pq::MlKemAlg::MlKem768,
            };
            let leaf = notes_core::seeds::derive_leaf(&app_seed(), seed_index, network, account, index)
                .expect("derive leaf");
            let kp = notes_core::pq::mlkem_keypair_from_leaf(&leaf, alg);
            println!("{}", kp.fingerprint());
        }
        Some("spending-address") => {
            // spending-address <network> <seed_index> <account> <chain> <index>
            let network = Network::from_str_opt(&args[2]).expect("network");
            let seed: u32 = args[3].parse().expect("seed index");
            let account: u32 = args[4].parse().expect("account");
            let chain: u32 = args[5].parse().expect("chain (0=receive,1=change)");
            let index: u32 = args[6].parse().expect("index");
            let key = notes_core::seeds::derive_spending_key(
                &app_seed(),
                seed,
                network,
                account,
                chain,
                index,
            )
            .unwrap();
            println!("{} {}", key.address, hex::encode(&key.script_pubkey));
        }
        // Host-side test helper ONLY (companion gap-discovery convergence
        // leg, funding-unification): sign a real P2WPKH spend from ONE
        // spending-wallet coin using the exact derived key + signer the
        // device itself uses (`wpkh::sign_mixed_inputs` via
        // `build_sweep_tx_mixed`, a single-input degenerate case of the
        // same mixed-source sweep builder the device's wallet-wide sweep
        // already exercises) — so `ui-automation/tests/graffito.sh` can
        // simulate "this watch-window address was already spent to empty"
        // without driving device UI for every leg. Prints "<txid> <raw_hex>".
        Some("spending-sweep") => {
            // spending-sweep <network> <seed_index> <account> <chain> <index> <txid> <vout> <value> <dest_address> <fee_rate>
            let network = Network::from_str_opt(&args[2]).expect("network");
            let seed: u32 = args[3].parse().expect("seed index");
            let account: u32 = args[4].parse().expect("account");
            let chain: u32 = args[5].parse().expect("chain (0=receive,1=change)");
            let index: u32 = args[6].parse().expect("index");
            let txid_hex = &args[7];
            let vout: u32 = args[8].parse().expect("vout");
            let value: u64 = args[9].parse().expect("value");
            let dest_address = &args[10];
            let fee_rate: f64 = args[11].parse().expect("fee_rate");

            let key = notes_core::seeds::derive_spending_key(
                &app_seed(),
                seed,
                network,
                account,
                chain,
                index,
            )
            .unwrap();
            let mut txid = [0u8; 32];
            hex::decode_to_slice(txid_hex, &mut txid).expect("txid: 64 hex chars");
            txid.reverse(); // display order -> internal order, same as SyncBundle::utxos()
            let dest_spk =
                notes_core::address::address_to_script_pubkey(network, dest_address).unwrap();
            let input = notes_core::tx::MixedInput {
                utxo: notes_core::tx::Utxo { txid, vout, value },
                prevout_spk: key.script_pubkey.clone(),
                kind: notes_core::tx::InputKind::P2wpkh,
                seckey: key.seckey,
            };
            // No bundle in this arm, so no known tip: `Tip` resolves to 0
            // unless NOTES_LOCKTIME_POLICY overrides it.
            let swept = notes_core::tx::build_sweep_tx_mixed(
                &[input],
                dest_spk,
                fee_rate,
                locktime_for(None),
                || generate_aux_rand(),
            )
            .unwrap();
            println!("{} {}", swept.txid_hex, swept.raw_hex);
        }
        Some("compose") => {
            // compose <bundle.json|-> <public|private> <fee_rate> <max_or> <text>
            let bundle = read_bundle(&args[2]);
            let private = match args[3].as_str() {
                "private" => true,
                "public" => false,
                other => panic!("visibility must be public|private, got {other}"),
            };
            let fee_rate: f64 = args[4].parse().unwrap();
            let max_or: usize = args[5].parse().unwrap();
            let text = &args[6];
            let note = compose_note(
                &identity,
                &bundle.utxos(),
                text,
                private,
                max_or,
                fee_rate,
                locktime_for(Some(bundle.tip_height as u32)),
                || generate_aux_rand(),
            )
            .unwrap();
            println!(
                "{}",
                serde_json::json!({
                    "txid": note.txid_hex,
                    "raw_hex": note.raw_hex,
                    "fee": note.fee,
                    "vsize": note.vsize,
                    "change": note.change,
                    "op_returns": note.tx.outputs.iter()
                        .filter(|o| o.script_pubkey.first() == Some(&0x6a)).count(),
                })
            );
        }
        Some("send") => {
            // send <bundle.json|-> <recipient_addr> <public|private> <fee_rate> <max_or> <text>
            let bundle = read_bundle(&args[2]);
            let network = Network::from_str_opt(&bundle.network).expect("bundle network");
            let recipient = Recipient::parse(network, &args[3]).unwrap();
            let private = match args[4].as_str() {
                "private" => true,
                "public" => false,
                other => panic!("visibility must be public|private, got {other}"),
            };
            let fee_rate: f64 = args[5].parse().unwrap();
            let max_or: usize = args[6].parse().unwrap();
            let text = &args[7];
            let note = compose_directed_note(
                &identity,
                &bundle.utxos(),
                text,
                private,
                &recipient,
                max_or,
                fee_rate,
                locktime_for(Some(bundle.tip_height as u32)),
                || generate_aux_rand(),
            )
            .unwrap();
            println!(
                "{}",
                serde_json::json!({
                    "txid": note.txid_hex,
                    "raw_hex": note.raw_hex,
                    "fee": note.fee,
                    "vsize": note.vsize,
                    "change": note.change,
                    "sent": note.sent,
                    "recipient": recipient.address,
                    "op_returns": note.tx.outputs.iter()
                        .filter(|o| o.script_pubkey.first() == Some(&0x6a)).count(),
                })
            );
        }
        Some("send-multi") => {
            // send-multi <bundle.json|-> <public|private> <fee_rate> <max_or> <text> <addr:amt,addr:amt,...> [content_key_hex]
            let bundle = read_bundle(&args[2]);
            let network = Network::from_str_opt(&bundle.network).expect("bundle network");
            let private = match args[3].as_str() {
                "private" => true,
                "public" => false,
                other => panic!("visibility must be public|private, got {other}"),
            };
            let fee_rate: f64 = args[4].parse().unwrap();
            let max_or: usize = args[5].parse().unwrap();
            let text = &args[6];
            let recipients: Vec<(Recipient, u64)> = args[7]
                .split(',')
                .map(|pair| {
                    let (addr, amount) =
                        pair.split_once(':').expect("recipient must be addr:amount");
                    let recipient = Recipient::parse(network, addr).unwrap();
                    let amount: u64 = amount.parse().expect("amount");
                    (recipient, amount)
                })
                .collect();
            // content_key: caller-supplied hex, else generated from the OS
            // RNG here in the CLI only (notes-core itself never generates
            // it — see dm.rs's module docs).
            let content_key: [u8; 32] = if let Some(hex_key) = args.get(8) {
                let mut k = [0u8; 32];
                hex::decode_to_slice(hex_key, &mut k).expect("content_key: 64 hex chars");
                k
            } else {
                let mut k = [0u8; 32];
                getrandom::getrandom(&mut k).expect("OS rng");
                k
            };
            let note = compose_directed_note_multi_with_change(
                &identity,
                &bundle.utxos(),
                text,
                private,
                &recipients,
                content_key,
                None,
                max_or,
                fee_rate,
                locktime_for(Some(bundle.tip_height as u32)),
                || generate_aux_rand(),
            )
            .unwrap();
            println!(
                "{}",
                serde_json::json!({
                    "txid": note.txid_hex,
                    "raw_hex": note.raw_hex,
                    "fee": note.fee,
                    "vsize": note.vsize,
                    "change": note.change,
                    "sent": note.sent,
                    "recipients": recipients.iter().map(|(r, a)| serde_json::json!({
                        "address": r.address,
                        "amount": a,
                    })).collect::<Vec<_>>(),
                    "op_returns": note.tx.outputs.iter()
                        .filter(|o| o.script_pubkey.first() == Some(&0x6a)).count(),
                })
            );
        }
        Some("sweep") => {
            // sweep <bundle.json|-> <network> <dest_address> <fee_rate>
            let bundle = read_bundle(&args[2]);
            let network = Network::from_str_opt(&args[3]).expect("network");
            let dest_spk =
                notes_core::address::address_to_script_pubkey(network, &args[4]).unwrap();
            let fee_rate: f64 = args[5].parse().unwrap();
            let sweep = notes_core::tx::build_sweep_tx(
                &bundle.utxos(),
                &identity.output_x,
                dest_spk,
                fee_rate,
                locktime_for(Some(bundle.tip_height as u32)),
                &identity.tweaked_seckey,
                || generate_aux_rand(),
            )
            .unwrap();
            println!(
                "{}",
                serde_json::json!({
                    "txid": sweep.txid_hex,
                    "raw_hex": sweep.raw_hex,
                    "fee": sweep.fee,
                    "vsize": sweep.vsize,
                    "value_out": sweep.tx.outputs[0].value,
                })
            );
        }
        Some("scan") => {
            let bundle = read_bundle(&args[2]);
            let network = Network::from_str_opt(&bundle.network).expect("bundle network");
            let notes = extract_notes(&bundle, &identity, network);
            let out: Vec<_> = notes
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "id": n.id,
                        "txid": n.id,
                        "height": n.height,
                        "blocktime": n.blocktime,
                        "private": n.private,
                        "directed": n.directed,
                        "received": n.received,
                        "from": n.sender,
                        "to": n.recipient,
                        "recipients": n.recipients,
                        "text": n.text,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        _ => {
            eprintln!("usage: notes_cli address <network> | compose <bundle> <public|private> <fee_rate> <max_or> <text> | send <bundle> <recipient_addr> <public|private> <fee_rate> <max_or> <text> | send-multi <bundle> <public|private> <fee_rate> <max_or> <text> <addr:amt,addr:amt,...> [content_key_hex] | scan <bundle> | sweep <bundle> <network> <dest_address> <fee_rate> | spending-address <network> <seed> <account> <chain> <index> | spending-sweep <network> <seed> <account> <chain> <index> <txid> <vout> <value> <dest_address> <fee_rate>");
            std::process::exit(2);
        }
    }
}
