#!/usr/bin/env python3
"""Local companion server for prime-chain-notes.

Serves the static companion page AND — when regtest is enabled — exposes a
local Bitcoin Core regtest node through a **mempool.space-shaped API** at
/regtest/api/*. That's the improvement over the bitcoin-gift-wallet
pattern this borrows from: the page needs no regtest special-casing beyond
a base-URL map, because the local shim speaks the same dialect as
https://mempool.space/api (esplora-style endpoints + /v1/fees, /v1/prices).

Usage:
    python3 server.py [port]                # static only (page hides regtest)
    python3 server.py [port] --regtest      # manage a throwaway regtest node
    python3 server.py [port] --datadir DIR  # attach to an existing regtest node

Stdlib only. GET  /api/health                    → {"status":"ok","regtest":bool}
             GET  /regtest/api/blocks/tip/height
             GET  /regtest/api/address/A               → esplora-style chain_stats/mempool_stats
             GET  /regtest/api/address/A/txs[/chain][?after_txid=T]
             GET  /regtest/api/address/A/utxo
             GET  /regtest/api/v1/fees/recommended
             GET  /regtest/api/v1/prices
             POST /regtest/api/tx               (auto-mines 1 block after accept)
             POST /regtest/api/mine?blocks=N
             POST /regtest/api/faucet           {"address": A, "amount": btc}
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
PAGE_SIZE = 25  # esplora /txs/chain pagination size

_datadir = None      # regtest datadir (managed or attached)
_managed_proc = None  # bitcoind process if we started it
# The managed node deliberately does NOT use bitcoind's default regtest ports.
# 18443 is also what an SSH tunnel to a remote regtest node forwards, and what
# any other local suite would grab, so defaulting there made a tunnel and a
# test run mutually exclusive — the clash surfaced as a misleading "bitcoind
# did not come up" and cost several debugging rounds. Override with
# CN_REGTEST_RPCPORT if 18453/18454 are themselves busy.
_rpcport = int(os.environ.get("CN_REGTEST_RPCPORT", "18453"))
_watch_imported = set()


class TxNotFound(RuntimeError):
    """A DEFINITIVELY unknown txid — bitcoind RPC error code -5. Esplora
    answers this with a plain 404, not a 400; chain-notes-app's dropped-tx
    detection (TxLookupStatus::NotFound) depends on the real status code,
    so this must never fire for a transport/other error (those keep
    raising a plain RuntimeError -> 400, unchanged)."""


def cli(*args):
    out = subprocess.run(
        ["bitcoin-cli", "-regtest", f"-rpcport={_rpcport}",
         f"-datadir={_datadir}", *args],
        capture_output=True, text=True, timeout=60,
    )
    if out.returncode != 0:
        err = out.stderr.strip() or out.stdout.strip()
        if "error code: -5" in err:
            raise TxNotFound(err)
        raise RuntimeError(err)
    return out.stdout.strip()


def cli_json(*args):
    return json.loads(cli(*args))


def wallet(*args, wallet_name="cn-watch"):
    return cli(f"-rpcwallet={wallet_name}", *args)


def wallet_json(*args, wallet_name="cn-watch"):
    return json.loads(wallet(*args, wallet_name=wallet_name))


def start_managed_node():
    global _datadir, _managed_proc
    _datadir = tempfile.mkdtemp(prefix="cn_regtest_")
    (Path(_datadir) / "bitcoin.conf").write_text(
        "regtest=1\nserver=1\ntxindex=1\nfallbackfee=0.0001\n"
    )
    # -rpcport/-port on the command line apply to the selected network, so
    # they do NOT need a [regtest] section the way bitcoin.conf entries would.
    _managed_proc = subprocess.Popen(
        ["bitcoind", f"-datadir={_datadir}", "-regtest", "-daemon=0",
         f"-rpcport={_rpcport}", f"-port={_rpcport + 1}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        try:
            cli("getblockchaininfo")
            break
        except Exception:
            time.sleep(0.5)
    else:
        raise RuntimeError("bitcoind did not come up")
    cli("createwallet", "miner")
    ensure_watch_wallet()
    mine(101)
    print(f"regtest node up (datadir {_datadir}, rpc {_rpcport}), 101 blocks mined")


def ensure_watch_wallet():
    try:
        cli("createwallet", "cn-watch", "true", "true")
    except RuntimeError as e:
        if "already exists" not in str(e):
            try:
                cli("loadwallet", "cn-watch")
            except RuntimeError as e2:
                if "already loaded" not in str(e2):
                    raise


def ensure_address_watched(address):
    if address in _watch_imported:
        return
    ensure_watch_wallet()
    desc = cli_json("getdescriptorinfo", f"addr({address})")["descriptor"]
    wallet(
        "importdescriptors",
        json.dumps([{"desc": desc, "timestamp": 0}]),
    )
    _watch_imported.add(address)


def mine(blocks=1):
    addr = wallet("getnewaddress", wallet_name="miner")
    wallet("generatetoaddress", str(blocks), addr, wallet_name="miner")
    # Wallet block-processing is ASYNC in bitcoind (validation-interface
    # callbacks drain on the scheduler thread AFTER generatetoaddress
    # returns) — without this, a listunspent served right after a mine can
    # answer from the PRE-block view: freshly-spent coins still listed,
    # fresh outputs missing. The chain-notes-app UI suite's mixed-sweep leg
    # raced exactly that (scanned its consolidate's spent inputs as
    # spendable → missing-inputs on broadcast). Best-effort: the drain is
    # a consistency optimization — a hiccup in this hidden RPC must never
    # turn a successful mine into a dropped connection for the POST /tx or
    # faucet request that triggered it.
    try:
        cli("syncwithvalidationinterfacequeue")
    except Exception:
        pass


def tip_height():
    return int(cli("getblockcount"))


def sats(btc_value):
    return int(round(float(btc_value) * 1e8))


def esplora_tx(txid, tip):
    """Map `getrawtransaction txid 2` onto the esplora tx shape the page
    consumes (only the fields it reads)."""
    raw = cli_json("getrawtransaction", txid, "2")
    conf = raw.get("confirmations", 0) or 0
    status = {"confirmed": conf > 0}
    if conf > 0:
        status["block_height"] = tip - conf + 1
        status["block_time"] = raw.get("blocktime")
    vin = []
    for i in raw.get("vin", []):
        prevout = i.get("prevout") or {}
        spk = prevout.get("scriptPubKey") or {}
        vin.append({
            "txid": i.get("txid"),
            "vout": i.get("vout"),
            "prevout": {
                "scriptpubkey_address": spk.get("address"),
                "value": sats(prevout.get("value", 0)),
            },
        })
    vout = []
    for o in raw.get("vout", []):
        spk = o.get("scriptPubKey", {})
        vout.append({
            "scriptpubkey": spk.get("hex"),
            "scriptpubkey_type": "op_return" if spk.get("type") == "nulldata" else spk.get("type"),
            "scriptpubkey_address": spk.get("address"),
            "value": sats(o.get("value", 0)),
        })
    return {"txid": txid, "status": status, "vin": vin, "vout": vout}


def address_txids(address):
    """All wallet-known txids touching `address`, newest first (mempool
    first, then by confirmations ascending)."""
    ensure_address_watched(address)
    entries = wallet_json("listtransactions", "*", "10000", "0", "true")
    seen, ordered = set(), []
    for e in sorted(entries, key=lambda e: (e.get("confirmations", 0), -e.get("time", 0))):
        txid = e.get("txid")
        if txid and txid not in seen:
            seen.add(txid)
            ordered.append(txid)
    return ordered


def handle_api(handler, method, path, query, body):
    tip = None
    if path == "/api/health":
        return {"status": "ok", "regtest": _datadir is not None}
    if _datadir is None:
        handler.send_error(404, "regtest not enabled")
        return None

    if path == "/regtest/api/blocks/tip/height":
        return tip_height()
    if path == "/regtest/api/v1/fees/recommended":
        return {"fastestFee": 3, "halfHourFee": 2, "hourFee": 1, "economyFee": 1, "minimumFee": 1}
    if path == "/regtest/api/v1/prices":
        return {"time": int(time.time()), "USD": 100000}

    parts = path.split("/")
    # /regtest/api/address/{addr} — esplora-style aggregate stats, no
    # trailing sub-resource segment. Must be checked BEFORE the
    # /txs|/utxo branch below (longer `parts`) so it isn't shadowed.
    if len(parts) == 5 and parts[3] == "address" and parts[4]:
        address = parts[4]
        ensure_address_watched(address)
        tip = tip_height()
        stats = {
            "chain_stats": {
                "funded_txo_count": 0, "funded_txo_sum": 0,
                "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": 0,
            },
            "mempool_stats": {
                "funded_txo_count": 0, "funded_txo_sum": 0,
                "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": 0,
            },
        }
        # address_txids is already ordered deterministically (newest
        # first); iterate that order so repeated calls with no chain/
        # mempool change produce byte-identical output.
        for txid in address_txids(address):
            tx = esplora_tx(txid, tip)
            bucket = stats["chain_stats"] if tx["status"]["confirmed"] else stats["mempool_stats"]
            touches = False
            for o in tx["vout"]:
                if o.get("scriptpubkey_address") == address:
                    bucket["funded_txo_count"] += 1
                    bucket["funded_txo_sum"] += o["value"]
                    touches = True
            for i in tx["vin"]:
                prevout = i.get("prevout") or {}
                if prevout.get("scriptpubkey_address") == address:
                    bucket["spent_txo_count"] += 1
                    bucket["spent_txo_sum"] += prevout["value"]
                    touches = True
            if touches:
                bucket["tx_count"] += 1
        return stats

    # /regtest/api/address/{addr}/txs[/chain]
    if len(parts) >= 6 and parts[3] == "address" and parts[5] in ("txs", "utxo"):
        address = parts[4]
        tip = tip_height()
        if parts[5] == "utxo":
            ensure_address_watched(address)
            utxos = wallet_json("listunspent", "0", "9999999", json.dumps([address]))
            return [
                {
                    "txid": u["txid"],
                    "vout": u["vout"],
                    "value": sats(u["amount"]),
                    "status": (
                        {"confirmed": True, "block_height": tip - u["confirmations"] + 1}
                        if u["confirmations"] > 0 else {"confirmed": False}
                    ),
                }
                for u in utxos
            ]
        txids = address_txids(address)
        chain_only = len(parts) >= 7 and parts[6] == "chain"
        after = query.get("after_txid", [None])[0]
        txs = [esplora_tx(t, tip) for t in txids]
        # The watch wallet is SHARED across every address ever queried, so
        # listtransactions returns other addresses' txs too — keep only txs
        # that actually touch this address (an input prevout or an output),
        # like real esplora. Without this, gap-limit descriptor scans never
        # find an unused address and walk forever.
        txs = [
            t for t in txs
            if any((v.get("prevout") or {}).get("scriptpubkey_address") == address for v in t["vin"])
            or any(o.get("scriptpubkey_address") == address for o in t["vout"])
        ]
        if chain_only:
            txs = [t for t in txs if t["status"]["confirmed"]]
        if after:
            idx = next((i for i, t in enumerate(txs) if t["txid"] == after), None)
            txs = txs[idx + 1:] if idx is not None else []
        return txs[:50 if not chain_only else PAGE_SIZE]

    # /regtest/api/tx/{txid}[/hex] — single-tx lookup (esplora shape / raw hex),
    # what the chain-notes-app watch-mode bump/rebroadcast path reads.
    if method == "GET" and len(parts) >= 5 and parts[3] == "tx" and parts[4]:
        if len(parts) >= 6 and parts[5] == "hex":
            return cli("getrawtransaction", parts[4])
        return esplora_tx(parts[4], tip_height())

    if method == "POST" and path == "/regtest/api/tx":
        raw_hex = body.decode().strip()
        accept = cli_json("testmempoolaccept", json.dumps([raw_hex]))[0]
        if not accept.get("allowed"):
            handler.send_response(400)
            handler.send_header("Content-Type", "text/plain")
            handler.end_headers()
            reason = accept.get("reject-reason", "rejected")
            handler.wfile.write(f"sendrawtransaction RPC error: {reason}".encode())
            return None
        txid = cli("sendrawtransaction", raw_hex)
        mine(1)  # regtest convenience: instant confirmation
        return txid

    if method == "POST" and path == "/regtest/api/mine":
        n = int(query.get("blocks", ["1"])[0])
        mine(n)
        return {"mined": n, "tip": tip_height()}

    if method == "POST" and path == "/regtest/api/faucet":
        req = json.loads(body or b"{}")
        txid = wallet(
            "sendtoaddress", req["address"], str(req.get("amount", 0.001)),
            wallet_name="miner",
        )
        mine(1)
        return {"txid": txid}

    handler.send_error(404)
    return None


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(HERE), **kwargs)

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        if not (parsed.path.startswith("/api/") or parsed.path.startswith("/regtest/api/")):
            if method == "GET":
                return super().do_GET()
            return self.send_error(405)
        body = b""
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
        try:
            result = handle_api(self, method, parsed.path, parse_qs(parsed.query), body)
        except TxNotFound:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Transaction not found")
            return
        except Exception as e:  # surface RPC errors like mempool.space does
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(str(e).encode())
            return
        if result is None:
            return  # handler already responded
        payload = result if isinstance(result, str) else json.dumps(result)
        data = str(payload).encode()
        self.send_response(200)
        ctype = "text/plain" if isinstance(result, (str, int)) else "application/json"
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def main():
    global _datadir
    port = 8091
    regtest = False
    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == "--regtest":
            regtest = True
        elif a == "--datadir":
            _datadir = args.pop(0)
        elif a.isdigit():
            port = int(a)
    if regtest and _datadir is None:
        start_managed_node()
    elif _datadir:
        ensure_watch_wallet()
        print(f"attached to regtest node at {_datadir}")

    def shutdown(*_):
        if _managed_proc:
            try:
                cli("stop")
                _managed_proc.wait(timeout=15)
            except Exception:
                _managed_proc.kill()
            shutil.rmtree(_datadir, ignore_errors=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    print(f"companion on http://localhost:{port}  (regtest: {'on' if _datadir else 'off'})")
    # request_queue_size: the default listen backlog (5) is too small for
    # the chain-notes-app's scan workers — each opens its own connection,
    # and a burst of queued scans can fill the backlog so a broadcast
    # POST's connect gets REFUSED ("error sending request"). This server
    # is single-threaded on purpose (deterministic ordering for tests);
    # a deeper backlog just lets bursts queue instead of bounce. Must be
    # a CLASS attribute — HTTPServer.__init__ calls listen() with it.
    class DeepBacklogServer(HTTPServer):
        request_queue_size = 64

    DeepBacklogServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
