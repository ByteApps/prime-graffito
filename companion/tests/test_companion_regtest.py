#!/usr/bin/env python3
"""Drive the companion page headlessly against the local regtest shim.

Flow (the page does the work — this script only clicks and types):
  faucet → build bundle → download bundle.json → notes_cli compose →
  upload .hex → broadcast (auto-mined) → rebuild bundle → notes_cli scan
  → note text recovered.

Prereqs: companion/server.py serving :8091, pointed at the ONE shared
node — the Pi's persistent regtest chain, never a local throwaway one
(PLAN-one-regtest-node.md):

    ../../../ui-automation/node-env.sh regtest python3 companion/server.py 8091

and `cargo build -p notes-core --example notes_cli` done (target/debug).

Regtest-only by construction: every leg depends on POST .../mine
auto-confirming a broadcast instantly, and there is no testnet4
equivalent (mining is 409 there — see the plan's "two verbs, not one").
If CN_NETWORK names anything other than regtest this file prints a loud
SKIP and exits instead of quietly proving less. Each run also derives a
FRESH NOTES_APP_SEED: the Pi's chain is shared and persistent, so a
fixed seed would accumulate notes across runs and break the
exact-text/exact-txid assertions below.
"""

import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = "http://localhost:8091"
REPO = Path(__file__).resolve().parents[2]
NOTES_CLI = REPO / "target/debug/examples/notes_cli"
SHOTS = Path(__file__).resolve().parent / "screenshots"
SHOTS.mkdir(exist_ok=True)

NETWORK = os.environ.get("CN_NETWORK", "regtest")

NOTE_TEXT = "companion-page note: built, broadcast and rescanned through the real UI"
VIEWER_NOTE_TEXT = "public note rendered by the viewer page"
DIRECTED_PUB_TEXT = "directed public note: postcard from A to B"
DIRECTED_PRIV_TEXT = "directed private note: sealed for B via static-static ECDH"


def cli(*args, env=None):
    out = subprocess.run([str(NOTES_CLI), *args], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def wait_log(section, needle, page, timeout=30000):
    page.wait_for_function(
        "([sel, needle]) => (document.querySelector(sel)?.textContent || '').includes(needle)",
        arg=[section, needle], timeout=timeout,
    )


def build_and_download(page, tmp):
    page.click("#buildBtn")
    with page.expect_download() as dl:
        wait_log("#syncLog", "Bundle ready", page)
        page.click("#downloadBtn")
    path = tmp / dl.value.suggested_filename
    dl.value.save_as(path)
    return path


def main():
    if NETWORK != "regtest":
        print(f"SKIP companion-regtest-e2e (regtest-only: every leg depends on "
              f"POST .../mine auto-confirming instantly, unavailable on {NETWORK})")
        print("0 PASS · 1 SKIP")
        return 0

    # Per-run-fresh identity: the Pi's regtest is shared and persistent,
    # so a fixed NOTES_APP_SEED would accumulate notes across runs and
    # eventually break the exact-text/exact-txid assertions below.
    os.environ["NOTES_APP_SEED"] = secrets.token_hex(32)

    address = cli("address", "regtest")
    print(f"notes address: {address}")
    tmp = Path(tempfile.mkdtemp(prefix="companion_e2e_"))

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(BASE)
        page.wait_for_function("document.querySelector('#modePill').textContent.includes('regtest')")
        assert page.locator('#network').input_value() == "regtest", "regtest should be auto-selected in server mode"

        page.fill("#address", address)
        page.click("#faucetBtn")
        wait_log("#syncLog", "Faucet sent", page)
        print("PASS faucet through the page")

        bundle1 = build_and_download(page, tmp)
        b1 = json.loads(bundle1.read_text())
        assert b1["network"] == "regtest" and b1["utxos"], b1
        assert "max_op_return_bytes" not in b1, "chunk policy is device-side now"
        print(f"PASS bundle built+downloaded ({bundle1.name}: {len(b1['utxos'])} utxo, tip {b1['tip_height']})")
        page.screenshot(path=str(SHOTS / "companion-bundle.png"), full_page=True)

        note = json.loads(cli("compose", str(bundle1), "private", "2", "100000", NOTE_TEXT))
        hex_file = tmp / f"{note['txid']}.hex"
        hex_file.write_text(note["raw_hex"])
        assert note["op_returns"] == 1, "100k policy → single OP_RETURN"

        page.set_input_files("#hexFiles", str(hex_file))
        page.click("#broadcastBtn")
        wait_log("#bcastLog", "accepted", page)
        assert note["txid"] in page.locator("#bcastLog").text_content()
        print(f"PASS broadcast through the page, txid {note['txid']}")
        page.screenshot(path=str(SHOTS / "companion-broadcast.png"), full_page=True)

        # Negative: garbage hex must surface a reject reason, not a txid.
        page.fill("#hexPaste", "02" * 60)
        page.set_input_files("#hexFiles", [])
        page.click("#broadcastBtn")
        wait_log("#bcastLog", "REJECTED", page)
        print("PASS reject-reason surfaced for bad hex")

        bundle2 = build_and_download(page, tmp)
        b2 = json.loads(bundle2.read_text())
        b2_entry = next(t for t in b2["notes_onchain"] if t["txid"] == note["txid"])
        assert b2_entry["spends_from_self"], b2_entry
        # funding-unification M1: the field is always present (device-side
        # notes-core defaults + ORs it with spends_from_self), but regtest's
        # server.py shim carries no raw prevout scriptPubKey hex (only
        # scriptpubkey_address — see index.html's Esplora-shape gotcha
        # comment), so on regtest it's expected empty, never fabricated.
        assert b2_entry["input_prevout_spks"] == [], b2_entry
        scan = json.loads(cli("scan", str(bundle2)))
        texts = [n["text"] for n in scan]
        assert NOTE_TEXT in texts, texts
        confirmed = next(n for n in scan if n["text"] == NOTE_TEXT)
        assert confirmed["height"] is not None, "auto-mine should have confirmed it"
        print(f"PASS note recovered from page-built bundle, confirmed at height {confirmed['height']}")

        # ---- input_prevout_spks: prove the field faithfully threads real
        # prevout scriptPubKey hex through when it IS present (real esplora
        # carries it; regtest's shim doesn't — see above), by intercepting
        # one page response to inject it, matching the shape a real
        # mainnet/testnet4 API response would have.
        FAKE_SPK = "5120" + "ab" * 32  # p2tr-shaped scriptPubKey hex, arbitrary test value

        def inject_spk(route):
            resp = route.fetch()
            body = resp.json()
            if isinstance(body, list):
                for t in body:
                    if t.get("txid") == note["txid"]:
                        for v in t.get("vin", []):
                            if v.get("prevout"):
                                v["prevout"]["scriptpubkey"] = FAKE_SPK
            route.fulfill(response=resp, json=body)

        page.route("**/regtest/api/address/**", inject_spk)
        bundle_spk = build_and_download(page, tmp)
        page.unroute("**/regtest/api/address/**", inject_spk)
        b_spk = json.loads(bundle_spk.read_text())
        spk_entry = next(t for t in b_spk["notes_onchain"] if t["txid"] == note["txid"])
        assert spk_entry["input_prevout_spks"] == [FAKE_SPK], spk_entry
        print("PASS bundle threads real prevout scriptpubkey hex into input_prevout_spks when present")

        # ---- viewer.html: seed a PUBLIC note, then check both entry paths
        # (launcher button with URL params, and standalone manual load).
        note3 = json.loads(cli("compose", str(bundle2), "public", "2", "100000",
                               VIEWER_NOTE_TEXT))
        page.fill("#hexPaste", note3["raw_hex"])
        page.set_input_files("#hexFiles", [])
        page.click("#broadcastBtn")
        wait_log("#bcastLog", "accepted", page)
        assert note3["txid"] in page.locator("#bcastLog").text_content()

        with page.expect_popup() as pop:
            page.click("#viewBtn")
        viewer = pop.value
        assert "viewer.html" in viewer.url and address in viewer.url \
            and "network=regtest" in viewer.url, viewer.url
        wait_log("#notes", VIEWER_NOTE_TEXT, viewer)  # params auto-load the notes
        shown = viewer.locator("#notes").text_content()
        assert "Encrypted (private)" in shown, shown       # note1 stays sealed
        assert NOTE_TEXT not in shown                      # plaintext never leaks
        assert note3["txid"] in shown, shown
        assert viewer.locator("#notes .note-meta a").count() == 0, "regtest has no explorer links"
        assert viewer.locator("#notes .permalink").count() == len(
            viewer.evaluate("__cnViewer.notes")), "every note card has a permalink"
        newest = viewer.evaluate("window.__cnViewer.notes[0]")
        assert newest["text"] == VIEWER_NOTE_TEXT, newest  # newest-first ordering
        viewer.screenshot(path=str(SHOTS / "companion-viewer.png"), full_page=True)
        print("PASS viewer opened via button: public text, private placeholder, order")

        viewer.goto(BASE + "/viewer.html")                 # standalone path
        viewer.wait_for_function(
            "document.querySelector('#modePill').textContent.includes('regtest')")
        viewer.fill("#address", address)
        viewer.click("#loadBtn")
        wait_log("#notes", VIEWER_NOTE_TEXT, viewer)
        print("PASS viewer standalone load")

        # ---- note.html permalinks: public via click, private via direct URL.
        ids = viewer.evaluate("__cnViewer.notes.map(n => [n.noteId, n.private])")
        pub_id = next(i for i, priv in ids if not priv)
        priv_id = next(i for i, priv in ids if priv)
        viewer.click(f'#notes a[href*="note={pub_id}"]')
        wait_log("#note", VIEWER_NOTE_TEXT, viewer)
        assert "note.html" in viewer.url and f"note={pub_id}" in viewer.url, viewer.url
        assert "Encrypted (private)" not in viewer.locator("#note").text_content()
        viewer.goto(BASE + f"/note.html?address={address}&network=regtest&note={priv_id}")
        wait_log("#note", "Encrypted (private)", viewer)
        assert NOTE_TEXT not in viewer.locator("#note").text_content()
        viewer.screenshot(path=str(SHOTS / "companion-note.png"), full_page=True)
        viewer.close()
        print("PASS single-note page: public via permalink click, private via direct link")

        # Fresh bundle so the camera-test note can't double-spend note3's coin.
        bundle3 = build_and_download(page, tmp)

        browser.close()

        # ---- Leg 1 of the QR transport: scan-from-device via fake camera.
        # Compose another note, render its uppercase hex as a QR (exactly
        # what the device's "Show tx QR" displays), feed it to Chromium as
        # a fake webcam, and let the page decode + auto-broadcast it.
        import qrcode

        note2 = json.loads(cli("compose", str(bundle3), "private", "2", "100000",
                               "broadcast me via the camera"))
        img = qrcode.make(note2["raw_hex"].upper(), box_size=6, border=4)
        png = tmp / "tx-qr.png"
        img.save(png)
        y4m = tmp / "tx-qr.y4m"
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-loop", "1", "-i", str(png),
             "-vf", "scale=640:640:flags=neighbor,format=yuv420p", "-t", "5", "-r", "10", str(y4m)],
            check=True,
        )
        browser = p.chromium.launch(args=[
            "--use-fake-ui-for-media-stream",
            "--use-fake-device-for-media-stream",
            f"--use-file-for-fake-video-capture={y4m}",
        ])
        page = browser.new_page()
        page.goto(BASE)
        page.wait_for_function("document.querySelector('#modePill').textContent.includes('regtest')")
        page.click("#scanBtn")
        wait_log("#bcastLog", "accepted", page)
        assert note2["txid"] in page.locator("#bcastLog").text_content()
        print(f"PASS QR scanned from fake camera and auto-broadcast, txid {note2['txid']}")
        page.screenshot(path=str(SHOTS / "companion-scan.png"), full_page=True)
        browser.close()

        # ---- directed notes: A sends public + private to identity B ----
        b_env = {**os.environ, "NOTES_APP_SEED": secrets.token_hex(32)}
        b_address = cli("address", "regtest", env=b_env)
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(BASE)
        page.wait_for_function("document.querySelector('#modePill').textContent.includes('regtest')")
        page.fill("#address", address)

        bundle4 = build_and_download(page, tmp)
        send_pub = json.loads(cli("send", str(bundle4), b_address, "public", "2", "100000",
                                  DIRECTED_PUB_TEXT))
        assert send_pub["sent"] == 330 and send_pub["recipient"] == b_address, send_pub
        page.fill("#hexPaste", send_pub["raw_hex"])
        page.click("#broadcastBtn")
        wait_log("#bcastLog", "accepted", page)
        bundle5 = build_and_download(page, tmp)     # fresh change for the second send
        send_priv = json.loads(cli("send", str(bundle5), b_address, "private", "2", "100000",
                                   DIRECTED_PRIV_TEXT))
        page.fill("#hexPaste", send_priv["raw_hex"])
        page.click("#broadcastBtn")
        wait_log("#bcastLog", "accepted", page)
        print(f"PASS A sent public+private directed notes to B ({send_pub['txid'][:8]}…, "
              f"{send_priv['txid'][:8]}…)")

        # B's bundle via the page carries the additive directed fields.
        page.fill("#address", b_address)
        bundle_b = build_and_download(page, tmp)
        bb = json.loads(bundle_b.read_text())
        entry = next(t for t in bb["notes_onchain"] if t["txid"] == send_pub["txid"])
        assert entry["pays_self"] and not entry["spends_from_self"], entry
        assert entry["sender"] == address, entry
        scan_b = json.loads(cli("scan", str(bundle_b), env=b_env))
        by_text = {n["text"]: n for n in scan_b}
        assert DIRECTED_PUB_TEXT in by_text and by_text[DIRECTED_PUB_TEXT]["received"] \
            and by_text[DIRECTED_PUB_TEXT]["from"] == address, scan_b
        assert DIRECTED_PRIV_TEXT in by_text and by_text[DIRECTED_PRIV_TEXT]["private"] \
            and by_text[DIRECTED_PRIV_TEXT]["directed"], scan_b
        print("PASS B recovered both directed notes (private decrypted via ECDH), from=A")

        # A third seed cannot read B's private note.
        scan_c = json.loads(cli("scan", str(bundle_b),
                                env={**os.environ, "NOTES_APP_SEED": secrets.token_hex(32)}))
        assert DIRECTED_PRIV_TEXT not in [n["text"] for n in scan_c], scan_c
        print("PASS wrong-seed scan leaves the directed-private note sealed")

        # A-side: sent notes appear with to=B; the private one decrypts via
        # the dust-output key (the post-wipe sender recovery story).
        page.fill("#address", address)
        bundle_a = build_and_download(page, tmp)
        scan_a = json.loads(cli("scan", str(bundle_a)))
        sent_priv = next(n for n in scan_a if n["text"] == DIRECTED_PRIV_TEXT)
        assert sent_priv["directed"] and not sent_priv["received"] \
            and sent_priv["to"] == b_address, sent_priv
        print("PASS A re-reads its own sent private-directed note, to=B")

        # Viewer at B's address: public text + from pill, private placeholder.
        viewer = browser.new_page()
        viewer.goto(BASE + f"/viewer.html?address={b_address}&network=regtest")
        wait_log("#notes", DIRECTED_PUB_TEXT, viewer)
        shown = viewer.locator("#notes").text_content()
        assert "Encrypted (directed)" in shown, shown
        assert DIRECTED_PRIV_TEXT not in shown, "directed-private plaintext leaked!"
        assert "from " in shown, shown
        viewer.screenshot(path=str(SHOTS / "companion-directed.png"), full_page=True)
        # note.html permalink on the received public note still works.
        viewer.click(f'#notes a[href*="note={send_pub["txid"]}"]')
        wait_log("#note", DIRECTED_PUB_TEXT, viewer)
        viewer.close()
        print("PASS viewer at B shows received notes (from pill, sealed private, permalink)")

        # ---- funding-unification: viewer's optional &mine=<addr,...> param
        # (chain-scan.js's myAddresses) reclassifies a received tx OWN when
        # one of its input prevouts matches — here A's own address, which is
        # exactly the input that funded the directed note it sent B. This is
        # the mechanism (no default UI affordance): WITHOUT the param the
        # note still renders received-from-A (today's behavior, unchanged).
        # Post-dedup contract (DISPLAY-OWNER rule, 2026-07-18 — supersedes
        # this leg's original pre-dedup expectation): &mine=<A> makes the
        # A-anchored own note render on A's OWN page only; B's page with
        # &mine=A reclassifies it OWN and therefore DROPS it (the anchor is
        # A, not B). The note must still be fully visible at A.
        viewer_mine = browser.new_page()
        viewer_mine.goto(BASE + f"/viewer.html?address={b_address}&network=regtest&mine={address}")
        viewer_mine.wait_for_function(
            "document.querySelector('#notesHeader').textContent.includes('note')"
        )
        notes_mine = viewer_mine.evaluate("window.__cnViewer.notes")
        assert not any(n["text"] == DIRECTED_PUB_TEXT for n in notes_mine), \
            f"A-anchored own note must be deduped off B's &mine= page: {notes_mine}"
        viewer_mine.goto(BASE + f"/viewer.html?address={address}&network=regtest")
        wait_log("#notes", DIRECTED_PUB_TEXT, viewer_mine)
        pub_at_a = next(n for n in viewer_mine.evaluate("window.__cnViewer.notes")
                        if n["text"] == DIRECTED_PUB_TEXT)
        assert not pub_at_a["received"] and pub_at_a["to"] == b_address, pub_at_a
        print("PASS viewer &mine= DISPLAY-OWNER dedup: own note renders at its anchor (A), dropped from B")

        viewer_mine.goto(BASE + f"/viewer.html?address={b_address}&network=regtest")
        wait_log("#notes", DIRECTED_PUB_TEXT, viewer_mine)
        notes_default = viewer_mine.evaluate("window.__cnViewer.notes")
        pub_default = next(n for n in notes_default if n["text"] == DIRECTED_PUB_TEXT)
        assert pub_default["received"] and pub_default["from"] == address, \
            f"without &mine=, must stay received-from-funder (today's behavior): {pub_default}"
        print("PASS viewer WITHOUT &mine= keeps today's received-from-funder rendering")
        viewer_mine.close()
        browser.close()
    print("COMPANION REGTEST E2E PASSED")


if __name__ == "__main__":
    sys.exit(main())
