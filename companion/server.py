#!/usr/bin/env python3
"""Local companion server for prime-graffito.

Serves the static companion page AND — when a node is configured — exposes
a **remote** Bitcoin Core node (regtest or testnet4; reached over an SSH
tunnel or the tailnet, never spawned locally) through a **mempool.space-
shaped API** at /node/api/*. That's the improvement over the
bitcoin-gift-wallet pattern this borrows from: the page needs no special-
casing beyond a base-URL map, because the shim speaks the same dialect as
https://mempool.space/api (esplora-style endpoints + /v1/fees, /v1/prices).

/regtest/api/* is a **permanent alias** for /node/api/* — historical name
(this server used to manage its own throwaway regtest node), kept forever
because it's a wire contract with index.html, chain-scan.js, viewer.html,
note.html and every suite. Both prefixes always answer identically.

Usage:
    python3 server.py [port]                                # static only (page hides the node)
    python3 server.py [port] --node HOST:PORT --network NET  # NET = regtest | testnet4

--node/--network fall back to the CN_NODE_HOST/CN_NODE_PORT/CN_NETWORK
environment variables when the flags are absent. CORE_RPC_USER and
CORE_RPC_PASS are ALWAYS read from the environment, never from a flag —
see ../../ui-automation/node-env.sh, which decrypts the Pi's RPC
credentials for a given network and execs a command with all five of
these exported. This file is part of a PUBLIC repo: it must never read
../private/ or print a credential value.

CN_WATCH_WALLET (env only, no flag) overrides the bitcoind wallet this
server watches addresses through — default "graffito-watch", the
wallet shared by every suite and every run on the Pi. A harness run
should instead pass its OWN unique per-run wallet name (see
ui-automation/node-suite-lib.sh) so `listtransactions "*"` in
address_txids() below stays O(this run's handful of addresses) instead of
O(every address any suite has ever watched). The miner wallet name is
NOT configurable — it's ours, never shared, no cost problem to fix.

Stdlib only. GET  /api/health                       → {"status":"ok","network":...,"node":"host:port","regtest":bool}
             GET  /node/api/blocks/tip/height                  (alias: /regtest/api/...)
             GET  /node/api/address/A[?new=1]            → esplora-style chain_stats/mempool_stats
             GET  /node/api/address/A/txs[/chain][?after_txid=T][&new=1]
             GET  /node/api/address/A/utxo[?new=1]
             GET  /node/api/v1/fees/recommended
             GET  /node/api/v1/prices
             POST /node/api/tx                 (regtest: auto-mines 1 block after accept)
             POST /node/api/mine?blocks=N      (regtest only — 409 on testnet4, you cannot mine there)
             POST /node/api/faucet             {"address": A, "amount": btc}  (regtest only)

`?new=1` on an /address route is an opt-in hint that the address has NEVER
been used — the caller (e.g. a suite that just derived a fresh per-run
identity) is asserting there is no history to find. It imports the watch
descriptor at timestamp "now" instead of 0, which bitcoind treats as "no
rescan needed" (see ensure_address_watched). Default (no `new`, or `new=0`)
is unchanged: timestamp 0, a real rescan, because restore/recovery flows
depend on finding genuinely historical addresses. Getting this wrong for
an address that DOES have history silently hides it — only pass it when
you are certain.
"""

import json
import os
import subprocess
import sys
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
PAGE_SIZE = 25  # esplora /txs/chain pagination size

DEFAULT_PORT_BY_NETWORK = {"regtest": 18443, "testnet4": 48332}
# The watch wallet name is configurable (CN_WATCH_WALLET) so a harness run
# can point this server at its OWN per-run wallet instead of the shared
# "graffito-watch" — see PLAN-one-regtest-node.md, "Two things now grow
# without bound": that wallet is shared by every suite and every run
# forever, so `listtransactions "*"` in address_txids() below is O(all
# history ever recorded on the node), not O(this run). Measured 2026-08-03
# at 444 entries / 6.5-6.7s per address query with no caching or
# improvement on repeat. Defaulting to "graffito-watch" keeps every
# caller that doesn't opt in (a bare `server.py --node ... --network ...`
# with no CN_WATCH_WALLET set) byte-identical to before.
WATCH_WALLET = os.environ.get("CN_WATCH_WALLET", "graffito-watch")
MINER_WALLET = "graffito-miner"  # ours; NEVER touch the Pi's `testwallet`
DEFAULT_RPC_TIMEOUT = 60
# How far back a lazily-imported address is scanned. 0 means GENESIS, which
# is the only correct DEFAULT — a restore/recovery flow legitimately needs
# history older than this process. But a genesis rescan of testnet4 (146,900+
# blocks) takes minutes, far longer than the app's 30s HTTP timeout, so ANY
# address this shim has not seen before kills the request that triggered it.
#
# A harness whose addresses are all created DURING the run can therefore set
# CN_IMPORT_TIMESTAMP to its start time and skip the rescan entirely. That is
# strictly a test affordance: pre-registering each address one by one is
# whack-a-mole, because the app derives addresses dynamically and the first
# one nobody enumerated pays full price. Leave it unset in production.
DEFAULT_IMPORT_TIMESTAMP = int(os.environ.get("CN_IMPORT_TIMESTAMP", "0"))

# A first-time `importdescriptors` at timestamp:0 is a rescan from GENESIS.
# On the Pi's ~726-block regtest that's free — which is exactly why this
# path shipped broken in build 52 (see regtest-hides-cost-bugs /
# PLAN-one-regtest-node.md "Why he's right"). On testnet4 (~146k blocks and
# growing) the same rescan is hundreds of seconds; the default 60s RPC
# timeout would kill it mid-flight, so the import call alone gets a much
# longer, bounded budget.
IMPORT_RPC_TIMEOUT = 1800
# bitcoind's exact wording for RPC error -4 while a wallet-level rescan
# (ours or ANOTHER consumer's — the watch wallet is shared) is in flight:
# "Wallet is currently rescanning. Abort existing rescan or wait." Matched
# as a substring, deliberately narrow: -4 is a generic "wallet error" code
# (insufficient funds, keypool exhausted, ...) and only THIS specific
# condition is safe to retry — anything else must surface immediately.
RESCAN_ERROR = "currently rescanning"

# None => static-only mode (page hides the node). Otherwise a dict with
# host/port/user/password/network — see parse_node_config().
_node = None
_watch_imported = set()  # process-local fast-path cache, NOT the only guard
_wallets_ready = set()   # wallets we've confirmed loaded this process


class TxNotFound(RuntimeError):
    """A DEFINITIVELY unknown txid — bitcoind RPC error code -5. Esplora
    answers this with a plain 404, not a 400; the graffito desktop app's dropped-tx
    detection (TxLookupStatus::NotFound) depends on the real status code,
    so this must never fire for a transport/other error (those keep
    raising a plain RuntimeError -> 400, unchanged)."""


def cli(*args, timeout=DEFAULT_RPC_TIMEOUT, retry_budget=0):
    """retry_budget: total extra seconds to retry a RESCAN_ERROR -4 (a
    concurrent rescan — ours or another consumer's on the shared watch
    wallet) with backoff, instead of surfacing it. 0 (the default, used by
    every non-wallet RPC — they're never wallet-scoped, so this condition
    can't occur on them) means no retry. `wallet()`/`wallet_json()` pass a
    generous default; nothing else needs to opt in."""
    deadline = time.time() + retry_budget
    delay = 0.5
    while True:
        out = subprocess.run(
            ["bitcoin-cli", f"-{_node['network']}",
             f"-rpcconnect={_node['host']}", f"-rpcport={_node['port']}",
             f"-rpcuser={_node['user']}", f"-rpcpassword={_node['password']}",
             *args],
            capture_output=True, text=True, timeout=timeout,
        )
        if out.returncode == 0:
            return out.stdout.strip()
        err = out.stderr.strip() or out.stdout.strip()
        if "error code: -5" in err:
            raise TxNotFound(err)
        if "error code: -4" in err and RESCAN_ERROR in err and time.time() < deadline:
            time.sleep(delay)
            delay = min(delay * 2, 5.0)
            continue
        raise RuntimeError(err)


def cli_json(*args, timeout=DEFAULT_RPC_TIMEOUT, retry_budget=0):
    return json.loads(cli(*args, timeout=timeout, retry_budget=retry_budget))


def wallet(*args, wallet_name=WATCH_WALLET, timeout=DEFAULT_RPC_TIMEOUT,
           retry_budget=IMPORT_RPC_TIMEOUT):
    return cli(f"-rpcwallet={wallet_name}", *args, timeout=timeout, retry_budget=retry_budget)


def wallet_json(*args, wallet_name=WATCH_WALLET, timeout=DEFAULT_RPC_TIMEOUT,
                 retry_budget=IMPORT_RPC_TIMEOUT):
    return json.loads(
        wallet(*args, wallet_name=wallet_name, timeout=timeout, retry_budget=retry_budget)
    )


def _ensure_wallet_loaded(name, *createwallet_extra_args):
    """Idempotent create-or-load for a wallet WE own (never testwallet).
    Handles all three states the Pi's persistent node can hand us: the
    wallet doesn't exist yet, it exists but isn't currently loaded, or
    it's already loaded (by us, an earlier run, or another suite).
    Memoized per process — once confirmed ready, no further create/load
    RPCs are issued for it this run (mine() used to pay this on EVERY
    call)."""
    if name in _wallets_ready:
        return
    try:
        cli("createwallet", name, *createwallet_extra_args)
    except RuntimeError as e:
        msg = str(e)
        if "already exists" not in msg and "already loaded" not in msg:
            raise
        try:
            cli("loadwallet", name)
        except RuntimeError as e2:
            if "already loaded" not in str(e2):
                raise
    _wallets_ready.add(name)


def ensure_watch_wallet():
    _ensure_wallet_loaded(WATCH_WALLET, "true", "true")  # disable_private_keys, blank


def ensure_miner_wallet():
    _ensure_wallet_loaded(MINER_WALLET)


def _wait_for_rescan(timeout=IMPORT_RPC_TIMEOUT):
    """Block until the watch wallet's async rescan (started by a
    timestamp:0 importdescriptors, ours or another consumer's — the
    wallet is shared) finishes. importdescriptors at timestamp:0 RETURNS
    before the scan completes; every wallet RPC issued while it's still
    running gets RPC error -4 "Wallet is currently rescanning" (the
    build-52-shaped bug this closes). Callers of ensure_address_watched
    must never see that error — they should just observe a delay."""
    deadline = time.time() + timeout
    while True:
        info = wallet_json("getwalletinfo")
        if not info.get("scanning"):
            return
        if time.time() >= deadline:
            raise RuntimeError(
                f"rescan on wallet {WATCH_WALLET} did not finish within {timeout}s"
            )
        time.sleep(1)


def ensure_address_watched(address, fresh=False):
    """Idempotent against the NODE, not just process memory — a fresh
    server.py process must NOT re-import (and re-rescan-from-genesis) an
    address the watch wallet already knows about. `_watch_imported` is
    only a fast path on top; `getaddressinfo` is the real, node-level
    guard. Import at timestamp:0 is required by default (addresses may
    already have history), so the cost this avoids on a repeat hit is a
    full rescan — free on a short regtest chain, hundreds of seconds on
    testnet4.

    `fresh=True` (routes: `?new=1`) is an opt-in from a caller who KNOWS
    the address has no history yet (e.g. a suite's just-derived per-run
    identity): import at timestamp "now" instead of 0, which bitcoind
    treats as needing no rescan at all — never use this for an address
    that might already have activity, or that history goes undiscovered.

    Either way, if bitcoind DOES start an async rescan (only the
    timestamp:0 path), block here until it finishes rather than let a
    subsequent request race it and observe RPC -4."""
    if address in _watch_imported:
        return
    ensure_watch_wallet()
    info = wallet_json("getaddressinfo", address)
    if info.get("ismine") or info.get("iswatchonly"):
        _watch_imported.add(address)
        return
    desc = cli_json("getdescriptorinfo", f"addr({address})")["descriptor"]
    timestamp = "now" if fresh else DEFAULT_IMPORT_TIMESTAMP
    wallet(
        "importdescriptors",
        json.dumps([{"desc": desc, "timestamp": timestamp}]),
        timeout=IMPORT_RPC_TIMEOUT,
    )
    if not fresh:
        _wait_for_rescan()
    _watch_imported.add(address)


def mine(blocks=1):
    ensure_miner_wallet()
    addr = wallet("getnewaddress", wallet_name=MINER_WALLET)
    wallet("generatetoaddress", str(blocks), addr, wallet_name=MINER_WALLET)
    # Wallet block-processing is ASYNC in bitcoind (validation-interface
    # callbacks drain on the scheduler thread AFTER generatetoaddress
    # returns) — without this, a listunspent served right after a mine can
    # answer from the PRE-block view: freshly-spent coins still listed,
    # fresh outputs missing. The graffito desktop app's UI suite's mixed-sweep leg
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


def _parent_output(parent_txid, vout):
    """(address, value_btc) of one output of `parent_txid` — the fallback for
    a mempool input whose prevout bitcoind declines to inline. Best-effort:
    an unreachable parent yields (None, 0), exactly the shape the caller
    would otherwise have produced."""
    try:
        parent = cli_json("getrawtransaction", parent_txid, "1")
    except Exception:
        return None, 0
    outs = parent.get("vout") or []
    if not isinstance(vout, int) or vout >= len(outs):
        return None, 0
    out = outs[vout]
    return (out.get("scriptPubKey") or {}).get("address"), out.get("value", 0)


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
        address, value = spk.get("address"), prevout.get("value", 0)
        if address is None and i.get("txid") is not None:
            # `getrawtransaction verbosity=2` OMITS prevout for MEMPOOL inputs,
            # even when the parent is perfectly well known — verified against a
            # live node: a mempool vin has no `prevout` key at all, a confirmed
            # one does. Without this fallback every unconfirmed tx reports
            # `scriptpubkey_address: null` for its inputs, and a consumer that
            # identifies ownership by input address (the graffito desktop app's
            # spending-wallet-funded self-notes) mis-files its OWN note as
            # `received` until a block arrives.
            #
            # app-core's Core RPC transport already does exactly this
            # (`CoreRpcTransport::resolve_prevout`), and real esplora returns
            # mempool prevouts natively, so this shim was the only thing that
            # ever saw the gap — despite chain.rs describing the two as
            # field-for-field mirrors.
            address, value = _parent_output(i["txid"], i.get("vout", 0))
        vin.append({
            "txid": i.get("txid"),
            "vout": i.get("vout"),
            "prevout": {
                "scriptpubkey_address": address,
                "value": sats(value),
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


def _wants_fresh(query):
    """Parse the `?new=1` opt-in — see the module docstring and
    ensure_address_watched. Absent/0/false = default (possibly-historical
    address, real rescan)."""
    return query.get("new", ["0"])[0].lower() in ("1", "true", "yes")


def address_txids(address, fresh=False):
    """All wallet-known txids touching `address`, newest first (mempool
    first, then by confirmations ascending)."""
    ensure_address_watched(address, fresh=fresh)
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
        if _node is None:
            return {"status": "ok", "network": None, "node": None, "regtest": False}
        return {
            "status": "ok",
            "network": _node["network"],
            "node": f"{_node['host']}:{_node['port']}",
            "regtest": _node["network"] == "regtest",
        }
    if _node is None:
        handler.send_error(404, "node not configured")
        return None

    if path == "/node/api/blocks/tip/height":
        return tip_height()
    if path == "/node/api/v1/fees/recommended":
        return {"fastestFee": 3, "halfHourFee": 2, "hourFee": 1, "economyFee": 1, "minimumFee": 1}
    if path == "/node/api/v1/prices":
        return {"time": int(time.time()), "USD": 100000}

    parts = path.split("/")
    # /node/api/address/{addr} — esplora-style aggregate stats, no
    # trailing sub-resource segment. Must be checked BEFORE the
    # /txs|/utxo branch below (longer `parts`) so it isn't shadowed.
    if len(parts) == 5 and parts[3] == "address" and parts[4]:
        address = parts[4]
        fresh = _wants_fresh(query)
        ensure_address_watched(address, fresh=fresh)
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
        for txid in address_txids(address, fresh=fresh):
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

    # /node/api/address/{addr}/txs[/chain]
    if len(parts) >= 6 and parts[3] == "address" and parts[5] in ("txs", "utxo"):
        address = parts[4]
        fresh = _wants_fresh(query)
        tip = tip_height()
        if parts[5] == "utxo":
            ensure_address_watched(address, fresh=fresh)
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
        txids = address_txids(address, fresh=fresh)
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

    # /node/api/tx/{txid}[/hex] — single-tx lookup (esplora shape / raw hex),
    # what the graffito desktop app's watch-mode bump/rebroadcast path reads.
    if method == "GET" and len(parts) >= 5 and parts[3] == "tx" and parts[4]:
        if len(parts) >= 6 and parts[5] == "hex":
            return cli("getrawtransaction", parts[4])
        return esplora_tx(parts[4], tip_height())

    if method == "POST" and path == "/node/api/tx":
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
        if _node["network"] == "regtest":
            mine(1)  # regtest convenience: instant confirmation
        # testnet4: a successful broadcast IS the observable — there is no
        # "mine a block" equivalent (see PLAN-one-regtest-node.md's
        # settle/confirm split). Leave it unconfirmed in the mempool.
        return txid

    if method == "POST" and path == "/node/api/mine":
        if _node["network"] != "regtest":
            handler.send_response(409)
            handler.send_header("Content-Type", "text/plain")
            handler.end_headers()
            handler.wfile.write(
                f"cannot mine on {_node['network']}: mining is regtest-only".encode()
            )
            return None
        n = int(query.get("blocks", ["1"])[0])
        mine(n)
        return {"mined": n, "tip": tip_height()}

    if method == "POST" and path == "/node/api/faucet":
        if _node["network"] != "regtest":
            handler.send_response(409)
            handler.send_header("Content-Type", "text/plain")
            handler.end_headers()
            handler.wfile.write(
                f"cannot fund on {_node['network']}: faucet is regtest-only".encode()
            )
            return None
        req = json.loads(body or b"{}")
        ensure_miner_wallet()
        txid = wallet(
            "sendtoaddress", req["address"], str(req.get("amount", 0.001)),
            wallet_name=MINER_WALLET,
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
        path = parsed.path
        # /regtest/api/* is a permanent alias for /node/api/* — see the
        # module docstring. Normalize once, here, so every route body
        # below is written exactly once against the canonical prefix.
        if path == "/regtest/api" or path.startswith("/regtest/api/"):
            path = "/node/api" + path[len("/regtest/api"):]
        if not (path.startswith("/api/") or path.startswith("/node/api/")):
            if method == "GET":
                return super().do_GET()
            return self.send_error(405)
        body = b""
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
        try:
            result = handle_api(self, method, path, parse_qs(parsed.query), body)
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


def parse_node_config(argv):
    """Resolve --node/--network (+ CN_NODE_HOST/CN_NODE_PORT/CN_NETWORK env
    fallbacks) into (port, node_config). node_config is None for static-only
    mode — no --network flag AND no CN_NETWORK env var. CORE_RPC_USER /
    CORE_RPC_PASS are ALWAYS read from the environment, never a flag."""
    port = 8091
    node_arg = None
    network = None
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--node":
            if not args:
                sys.exit("server.py: --node requires HOST:PORT")
            node_arg = args.pop(0)
        elif a == "--network":
            if not args:
                sys.exit("server.py: --network requires regtest or testnet4")
            network = args.pop(0)
        elif a.isdigit():
            port = int(a)
        else:
            sys.exit(f"server.py: unrecognized argument {a!r}")

    network = network or os.environ.get("CN_NETWORK")
    if node_arg is not None and network is None:
        sys.exit(
            "server.py: --node was given without --network (or CN_NETWORK) — "
            "pass --network regtest|testnet4, or drop --node for static-only mode"
        )
    if network is None:
        return port, None
    if network not in DEFAULT_PORT_BY_NETWORK:
        sys.exit(f"server.py: --network must be regtest or testnet4, got {network!r}")

    host = None
    node_port = None
    if node_arg:
        if ":" not in node_arg:
            sys.exit("server.py: --node must be HOST:PORT")
        host, _, port_str = node_arg.rpartition(":")
        try:
            node_port = int(port_str)
        except ValueError:
            sys.exit(f"server.py: --node port must be numeric, got {port_str!r}")
    host = host or os.environ.get("CN_NODE_HOST") or "127.0.0.1"
    if node_port is None:
        env_port = os.environ.get("CN_NODE_PORT")
        node_port = int(env_port) if env_port else DEFAULT_PORT_BY_NETWORK[network]

    user = os.environ.get("CORE_RPC_USER")
    password = os.environ.get("CORE_RPC_PASS")
    if not user or not password:
        sys.exit(
            "server.py: CORE_RPC_USER and CORE_RPC_PASS must be set in the "
            "environment (see ui-automation/node-env.sh, which supplies them "
            "for a given network)."
        )

    return port, {
        "host": host, "port": node_port,
        "user": user, "password": password,
        "network": network,
    }


def main():
    global _node
    port, _node = parse_node_config(sys.argv[1:])

    if _node:
        print(f"companion node mode: {_node['network']} @ {_node['host']}:{_node['port']}")
    else:
        print("companion static-only (no --network / CN_NETWORK given)")

    print(f"companion on http://localhost:{port}  (node: {_node['network'] if _node else 'off'})")
    # request_queue_size: the default listen backlog (5) is too small for
    # the graffito desktop app's scan workers — each opens its own connection,
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
