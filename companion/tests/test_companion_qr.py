#!/usr/bin/env python3
"""Leg-2 companion verification, no camera needed:

1. Build a bundle through the page (server on :8091, regtest or
   testnet4), click "Show as QR" → STATIC case: decode the rendered QR
   image (cv2),
   strip CNB1, inflate, compare to the bundle JSON.
2. Force the ANIMATED path (payload > threshold): collect the UR part
   strings the page generated and feed them into notes-core's ur_decode
   example — the EXACT decoder (foundation-ur) the device scanner runs —
   then strip/inflate/compare again.

Prereqs: companion/server.py serving :8091, pointed at the ONE shared
node — the Pi's persistent regtest or testnet4 chain, never a local
throwaway one (PLAN-one-regtest-node.md):

    ../../../ui-automation/node-env.sh <regtest|testnet4> python3 companion/server.py 8091

and cargo examples built. This leg never faucets or mines — it only
builds a bundle and round-trips it through the QR encoder/decoder — so
unlike test_companion_regtest.py it genuinely runs on either network,
selected via CN_NETWORK (default regtest). Each run still derives a
fresh NOTES_APP_SEED: the shared chain persists across runs, and a
growing on-chain history at a fixed address could eventually push the
bundle past the static/animated QR size threshold and change which path
the first click exercises.
"""

import os
import secrets
import subprocess
import zlib
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = "http://localhost:8091"
REPO = Path(__file__).resolve().parents[2]
NOTES_CLI = REPO / "target/debug/examples/notes_cli"
UR_DECODE = REPO / "target/debug/examples/ur_decode"
SHOTS = Path(__file__).resolve().parent / "screenshots"
SHOTS.mkdir(exist_ok=True)

NETWORK = os.environ.get("CN_NETWORK", "regtest")


def inflate_cnb1(payload: bytes) -> str:
    assert payload[:4] == b"CNB1", payload[:8]
    return zlib.decompress(payload[4:], wbits=-15).decode()


# Decode the rendered QR *in the page* with jsQR (raw binaryData — no
# text transcoding, unlike cv2's QRCodeDetector).
JSQR_DECODE = """
async () => {
  const img = new Image();
  img.src = document.querySelector('#qrImg').src;
  await img.decode();
  const c = document.createElement('canvas');
  c.width = img.width; c.height = img.height;
  const ctx = c.getContext('2d');
  ctx.drawImage(img, 0, 0);
  const d = ctx.getImageData(0, 0, c.width, c.height);
  const hit = jsQR(d.data, d.width, d.height);
  return hit ? Array.from(hit.binaryData) : null;
}
"""


def main():
    # Per-run-fresh identity — see the module docstring.
    cli_env = {**os.environ, "NOTES_APP_SEED": secrets.token_hex(32)}
    address = subprocess.run(
        [str(NOTES_CLI), "address", NETWORK], capture_output=True, text=True, env=cli_env
    ).stdout.strip()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(BASE)
        page.wait_for_function(
            f"document.querySelector('#modePill').textContent.includes('{NETWORK}')"
        )
        page.fill("#address", address)
        page.click("#buildBtn")
        page.wait_for_function(
            "(document.querySelector('#syncLog')?.textContent || '').includes('Bundle ready')"
        )

        # ---- static path
        page.click("#showQrBtn")
        page.wait_for_function("window.__cnQr && window.__cnQr.kind === 'static'")
        qr = page.evaluate("window.__cnQr")
        bundle_json = page.evaluate("JSON.stringify(bundle)")
        payload = bytes(qr["payload"])
        assert inflate_cnb1(payload) == bundle_json
        print(f"PASS CNB1 payload matches bundle ({len(payload)} bytes from {len(bundle_json)})")

        decoded_list = page.evaluate(JSQR_DECODE)
        assert decoded_list is not None, "jsQR could not detect the rendered QR"
        assert bytes(decoded_list) == payload, (len(decoded_list), len(payload))
        print("PASS rendered static QR decodes to the exact payload (jsQR binaryData)")
        page.screenshot(path=str(SHOTS / "companion-bundle-qr.png"), full_page=True)

        # ---- animated path (force by shrinking the threshold)
        page.click("#showQrBtn")  # hide
        page.evaluate("STATIC_QR_MAX = 0; UR_FRAGMENT_LEN = 60")
        page.click("#showQrBtn")
        page.wait_for_function("window.__cnQr && window.__cnQr.kind === 'ur'")
        qr = page.evaluate("window.__cnQr")
        parts, payload = qr["parts"], bytes(qr["payload"])
        assert len(parts) >= 2, parts
        out = subprocess.run(
            [str(UR_DECODE)], input="\n".join(parts), capture_output=True, text=True
        )
        assert out.returncode == 0, out.stderr
        assert "ur_type=bytes" in out.stderr
        reassembled = bytes.fromhex(out.stdout.strip())
        assert reassembled == payload
        assert inflate_cnb1(reassembled) == bundle_json
        print(f"PASS {len(parts)} animated UR parts reassemble via foundation-ur "
              "(the device scanner's own decoder) to the exact bundle")
        page.screenshot(path=str(SHOTS / "companion-bundle-ur.png"), full_page=True)

        browser.close()
    print("COMPANION QR (LEG 2) VERIFICATION PASSED")


if __name__ == "__main__":
    main()
