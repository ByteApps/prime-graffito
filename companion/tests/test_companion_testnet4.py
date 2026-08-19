#!/usr/bin/env python3
"""LIVE testnet4 verification of the companion page + mempool.space
OP_RETURN relay policy. Costs real (valueless) testnet sats and returns
every remaining sat to the funding address at the end.

Env:
  TESTNET4_WIF      funding key (P2WPKH)
  TESTNET4_ADDRESS  funding address — change AND the final sweep go here
  NOTES_APP_SEED    one-off hex seed for the throwaway notes identity
  GIFT_WALLET_DIR   bitcoin-gift-wallet checkout (segwit signer for funding)

Flow: fund 10k sats → page builds bundle (unconfirmed utxo) → compose a
>80-byte SINGLE-OP_RETURN public note → broadcast via the page against
mempool.space/testnet4 → record the relay verdict (fallback to 80-byte
chunks if rejected) → rescan → sweep everything back → verdict summary.
"""

import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[2]
NOTES_CLI = REPO / "target/debug/examples/notes_cli"
SHOTS = Path(__file__).resolve().parent / "screenshots"
SHOTS.mkdir(exist_ok=True)
API = "https://mempool.space/testnet4/api"

WIF = os.environ["TESTNET4_WIF"]
FUND_ADDR = os.environ["TESTNET4_ADDRESS"]
GIFT_DIR = Path(os.environ.get("GIFT_WALLET_DIR", os.path.expanduser("~/Projects/Gifts/bitcoin-gift-wallet")))
FUND_SATS = 10_000
NOTE_TEXT = (
    "prime-graffito testnet4 verification: a single OP_RETURN well above the old 80-byte "
    "limit, composed offline on a Passport Prime core and relayed by mempool.space. "
    "Padding to two hundred bytes: ................"
)


def cli(*args):
    env = dict(os.environ)
    out = subprocess.run([str(NOTES_CLI), *args], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def http_json(path):
    with urllib.request.urlopen(API + path, timeout=30) as r:
        return json.loads(r.read())


def build_funding_tx(dest_address):
    sys.path.insert(0, str(GIFT_DIR / "server"))
    import bitcoin_crypto as bc  # noqa: E402

    utxos = http_json(f"/address/{FUND_ADDR}/utxo")
    utxos.sort(key=lambda u: u["value"])
    pick = next(u for u in utxos if u["value"] > FUND_SATS + 1000)
    fee = 160  # 1-in-2-out P2WPKH ≈ 141 vB @ 1 sat/vB, rounded up
    change = pick["value"] - FUND_SATS - fee
    assert change > 546, "change would be dust"
    decoded = bc.wif_to_private_key(WIF)
    assert not decoded["mainnet"] and decoded["compressed"]
    privkey = decoded["private_key"]
    raw = bc.build_signed_segwit_sweep_tx(
        privkey,
        [{"txid": pick["txid"], "vout": pick["vout"], "value_sat": pick["value"]}],
        dest_address,
        FUND_SATS,
        extra_outputs=[{"address": FUND_ADDR, "value": change}],
    )
    print(f"funding: {pick['value']} sat utxo → {FUND_SATS} to notes, {change} change, {fee} fee")
    return raw


def wait_log(page, sel, needle, timeout=60000):
    page.wait_for_function(
        "([sel, needle]) => (document.querySelector(sel)?.textContent || '').includes(needle)",
        arg=[sel, needle], timeout=timeout,
    )


def broadcast_via_page(page, name, hex_str, expect_ok=True):
    page.fill("#hexPaste", hex_str)
    page.click("#broadcastBtn")
    wait_log(page, "#bcastLog", "accepted" if expect_ok else "REJECTED")
    text = page.locator("#bcastLog").text_content()
    page.fill("#hexPaste", "")
    return text


def build_and_download(page, tmp, tag):
    page.locator("#syncLog").evaluate("el => el.textContent = ''")
    page.click("#buildBtn")
    with page.expect_download() as dl:
        wait_log(page, "#syncLog", "Bundle ready")
        page.click("#downloadBtn")
    path = tmp / f"{tag}-{dl.value.suggested_filename}"
    dl.value.save_as(path)
    return path


def main():
    address = cli("address", "testnet4")
    print(f"notes identity (throwaway): {address}")
    tmp = Path(tempfile.mkdtemp(prefix="companion_t4_"))
    verdict = {}

    funding_hex = build_funding_tx(address)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(f"file://{REPO}/companion/index.html")  # static mode, like GitHub Pages
        page.wait_for_selector("#network")
        assert page.locator('#network option[value="regtest"]').count() == 0, \
            "regtest option must be hidden in static mode"
        page.select_option("#network", "testnet4")
        page.fill("#address", address)

        out = broadcast_via_page(page, "funding", funding_hex)
        funding_txid = [l for l in out.splitlines() if "accepted" in l][0].split()[-1]
        print(f"PASS funding broadcast via page: {funding_txid}")

        b1 = build_and_download(page, tmp, "b1")
        bundle1 = json.loads(b1.read_text())
        assert any(u["value"] == FUND_SATS for u in bundle1["utxos"]), bundle1["utxos"]
        print(f"PASS page sees the unconfirmed funding utxo (tip {bundle1['tip_height']})")
        page.screenshot(path=str(SHOTS / "t4-bundle.png"), full_page=True)

        # THE CHUNK-POLICY PROBE: single OP_RETURN, ~212-byte payload.
        note = json.loads(cli("compose", str(b1), "public", "1", "100000", NOTE_TEXT))
        assert note["op_returns"] == 1
        print(f"probe: single OP_RETURN, {len(NOTE_TEXT)} text bytes, vsize {note['vsize']}")
        page.fill("#hexPaste", note["raw_hex"])
        page.click("#broadcastBtn")
        page.wait_for_function(
            "() => /accepted|REJECTED/.test(document.querySelector('#bcastLog')?.textContent || '')",
            timeout=60000,
        )
        log_text = page.locator("#bcastLog").text_content()
        page.screenshot(path=str(SHOTS / "t4-probe.png"), full_page=True)
        if "accepted" in log_text:
            verdict = {"accepted_large_single_op_return": True, "bytes": len(NOTE_TEXT) + 12,
                       "txid": note["txid"]}
            note_txid = note["txid"]
            print(f"VERDICT: mempool.space/testnet4 ACCEPTED a {len(NOTE_TEXT)+12}-byte single "
                  f"OP_RETURN → Core v30 defaults. txid {note_txid}")
        else:
            reason = log_text.split("REJECTED —")[-1].strip()
            verdict = {"accepted_large_single_op_return": False, "reject_reason": reason}
            print(f"VERDICT: REJECTED large single OP_RETURN: {reason}")
            print("falling back to 80-byte chunks…")
            note = json.loads(cli("compose", str(b1), "public", "1", "80", NOTE_TEXT))
            assert note["op_returns"] > 1
            out = broadcast_via_page(page, "chunked", note["raw_hex"])
            note_txid = note["txid"]
            verdict["chunked_fallback_txid"] = note_txid
            print(f"PASS 80-byte chunked fallback accepted: {note_txid}")

        b2 = build_and_download(page, tmp, "b2")
        scan = json.loads(cli("scan", str(b2)))
        assert any(n["text"] == NOTE_TEXT for n in scan), [n["text"] for n in scan]
        print("PASS note recovered from page-built testnet bundle")

        # Return every remaining sat to the funding address.
        sweep = json.loads(cli("sweep", str(b2), "testnet4", FUND_ADDR, "1"))
        out = broadcast_via_page(page, "sweep", sweep["raw_hex"])
        print(f"PASS sweep back to {FUND_ADDR}: {sweep['txid']} "
              f"({sweep['value_out']} sats returned, {sweep['fee']} fee)")
        page.screenshot(path=str(SHOTS / "t4-sweep.png"), full_page=True)

        b3 = build_and_download(page, tmp, "b3")
        bundle3 = json.loads(b3.read_text())
        assert not bundle3["utxos"], "notes address should be empty after sweep"
        print("PASS notes address empty — all funds returned")
        browser.close()

    print("\nSUMMARY")
    print(json.dumps({
        "funding_txid": funding_txid,
        "note_txid": note_txid,
        "sweep_txid": sweep["txid"],
        "verdict": verdict,
        "explorer": "https://mempool.space/testnet4",
    }, indent=2))


if __name__ == "__main__":
    main()
