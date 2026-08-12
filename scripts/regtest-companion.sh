#!/usr/bin/env bash
# Companion-role helper against the ONE shared node (the Pi's persistent
# regtest, or testnet4 — see ../../PLAN-one-regtest-node.md), shared by the
# regtest e2e and the simulator UI test. This script never starts, stops,
# wipes, or reindexes any bitcoind — it is a client of a node someone else
# owns and other suites/units may be touching at the same time.
#
# Env contract (identical across every suite in this workspace):
#   CN_NETWORK    regtest | testnet4          (default regtest)
#   CN_NODE_HOST  RPC host                    (default 127.0.0.1)
#   CN_NODE_PORT  RPC port                    (default 18443 regtest / 48332 testnet4)
#   CORE_RPC_USER / CORE_RPC_PASS             required, read from the
#     environment ONLY — this is a PUBLIC repo, never read a credential
#     from ../private/ or print one. Run via
#     ../../ui-automation/node-env.sh <network> bash scripts/regtest-companion.sh ...
#   CN_STATE_DIR  a small LOCAL scratch dir for this script's own
#     cross-invocation bookkeeping (the notes address `setup` recorded, for
#     `bundle` to read back) — NOT a bitcoind datadir. Replaces the old
#     DATADIR now that the node itself is remote and shared. Only needed by
#     `setup`/`bundle`.
#
#   regtest-companion.sh setup <notes_address>            # watch the address; fund it
#                                                          # from the Pi's testwallet (regtest)
#                                                          # or the gift wallet (testnet4)
#   regtest-companion.sh bundle <out.json> [owner_addr ...]  # sync bundle from the watch wallet,
#                                                          # + owner_address-tagged coins for
#                                                          # each extra address (spending wallet;
#                                                          # mirrors companion/index.html's
#                                                          # "Spending wallet addresses" merge —
#                                                          # scanned via scantxoutset, no wallet
#                                                          # import needed since these addresses
#                                                          # are never mined-to/spent-from here)
#                                                          # + an ADDITIVE owner_used list: every
#                                                          # owner_addr with ANY on-chain history
#                                                          # (companion gap-discovery option (b))
#                                                          # even when since spent to empty and
#                                                          # scantxoutset finds nothing left —
#                                                          # goes through the watch wallet instead:
#                                                          # import + getreceivedbyaddress
#   regtest-companion.sh broadcast <file.hex>    # sendrawtransaction
#   regtest-companion.sh mine [n]                # regtest-only: mine n blocks. FAILS LOUDLY
#                                                          # on testnet4 — you cannot mine there;
#                                                          # use `settle`/`confirm` instead.
#   regtest-companion.sh settle [txid]           # "make the chain reflect this tx": regtest
#                                                          # mines 1 block; testnet4 polls until
#                                                          # the node knows the txid, then returns
#   regtest-companion.sh confirm <txid> [timeout_secs]    # "this must be in a block": regtest
#                                                          # mines 1 block; testnet4 polls for a
#                                                          # REAL confirmation (default 1800s) —
#                                                          # a timeout FAILS
set -euo pipefail

# --- shared node contract -----------------------------------------------
CN_NETWORK="${CN_NETWORK:-regtest}"
CN_NODE_HOST="${CN_NODE_HOST:-127.0.0.1}"
case "$CN_NETWORK" in
    regtest)  DEFAULT_PORT=18443 ;;
    testnet4) DEFAULT_PORT=48332 ;;
    *) echo "CN_NETWORK must be regtest or testnet4, got '$CN_NETWORK'" >&2; exit 2 ;;
esac
CN_NODE_PORT="${CN_NODE_PORT:-$DEFAULT_PORT}"
: "${CORE_RPC_USER:?CORE_RPC_USER is required — run via ui-automation/node-env.sh $CN_NETWORK ...}"
: "${CORE_RPC_PASS:?CORE_RPC_PASS is required — run via ui-automation/node-env.sh $CN_NETWORK ...}"

CLI() { bitcoin-cli "-$CN_NETWORK" "-rpcconnect=$CN_NODE_HOST" "-rpcport=$CN_NODE_PORT" \
    "-rpcuser=$CORE_RPC_USER" "-rpcpassword=$CORE_RPC_PASS" "$@"; }

# Default "chain-notes-watch" matches companion/server.py's default — but
# that wallet is SHARED by every suite and every run on the Pi, forever,
# so a wallet-wide `listtransactions` (below, and in the `bundle`
# subcommand) is O(all history anyone has ever recorded), not O(this
# run) — measured 2026-08-03 at 444 entries / 6.5-6.7s per query, no
# caching, strictly growing (PLAN-one-regtest-node.md, "Two things now
# grow without bound"). A harness run should export CN_WATCH_WALLET to
# its OWN unique per-run name (ui-automation/node-suite-lib.sh does this
# and this script picks it up automatically) so this script only ever
# scans its own handful of addresses. Unset callers keep today's shared-
# wallet behavior unchanged.
WATCH_WALLET="${CN_WATCH_WALLET:-chain-notes-watch}"
MINER_WALLET="chain-notes-miner"   # ours; NEVER the Pi's `testwallet`
IMPORT_TIMEOUT=1800                # a genuinely historical importdescriptors (timestamp:0) rescans
                                    # from genesis — free on a fresh regtest, hundreds of seconds on
                                    # testnet4 or a chain that's grown (the rescan trap)
# `importdescriptors` at timestamp:0 starts an ASYNCHRONOUS rescan — the
# call can return before the scan finishes, and every other RPC against
# `chain-notes-watch` (ours or another suite's, since the wallet is
# SHARED) is rejected with -4 "Wallet is currently rescanning" until it
# completes. Found live against the Pi once the chain passed ~1,500
# blocks. Every WATCH call gets a retry-with-backoff safety net for
# exactly this — importing is fixed at the source (see ensure_watched
# below), but another consumer can start a rescan under us at any moment.
WATCH() {
    # Bounded by WALL CLOCK, not attempt count — a competing rescan on
    # this shared wallet can legitimately run for many minutes (a
    # historical-mode import over a big chain), and an attempt-count cap
    # with capped exponential backoff can expire well before that (found
    # live: 8 attempts topping out at 30s each stalls out around 2
    # minutes, which undershot a real concurrent rescan on the Pi).
    local start out rc delay=1
    start=$(date +%s)
    while true; do
        out="$(CLI "-rpcwallet=$WATCH_WALLET" "$@" 2>&1)"
        rc=$?
        if (( rc == 0 )); then
            printf '%s\n' "$out"
            return 0
        fi
        if [[ "$out" == *"currently rescanning"* ]] && (( $(date +%s) - start < IMPORT_TIMEOUT )); then
            sleep "$delay"
            (( delay < 30 )) && delay=$(( delay * 2 ))
            continue
        fi
        printf '%s\n' "$out" >&2
        return "$rc"
    done
}
MINER() { CLI "-rpcwallet=$MINER_WALLET" "$@"; }
TESTWALLET() { CLI "-rpcwallet=testwallet" "$@"; }

ensure_wallet_loaded() { # name [createwallet extra args...]
    local name="$1"; shift
    local out
    if out="$(CLI createwallet "$name" "$@" 2>&1)"; then
        return 0
    fi
    if [[ "$out" == *"already exists"* || "$out" == *"already loaded"* ]]; then
        local out2
        if out2="$(CLI loadwallet "$name" 2>&1)"; then
            return 0
        fi
        [[ "$out2" == *"already loaded"* ]] && return 0
        echo "ensure_wallet_loaded($name): $out2" >&2; exit 1
    else
        echo "ensure_wallet_loaded($name): $out" >&2; exit 1
    fi
}
_watch_wallet_ready=0
ensure_watch_wallet() {
    [[ "$_watch_wallet_ready" == 1 ]] && return 0
    ensure_wallet_loaded "$WATCH_WALLET" true true   # disable_private_keys, blank
    _watch_wallet_ready=1
}
_miner_wallet_ready=0
ensure_miner_wallet() {
    [[ "$_miner_wallet_ready" == 1 ]] && return 0
    ensure_wallet_loaded "$MINER_WALLET"
    _miner_wallet_ready=1
}

# Idempotent AGAINST THE NODE (getaddressinfo first) — the rescan trap.
# Plain space-delimited list, not an associative array — macOS ships bash
# 3.2 (no `declare -A`) and this script must run under the system bash.
_watched_list=""

# Wait for chain-notes-watch's own background rescan to finish (only ever
# needed after a `historical`-mode import below).
wait_for_rescan() {
    local max="${1:-$IMPORT_TIMEOUT}" waited=0 info
    while (( waited < max )); do
        info="$(WATCH getwalletinfo)"
        jq -e '.scanning == false' <<<"$info" >/dev/null 2>&1 && return 0
        sleep 3; waited=$((waited+3))
    done
    return 1
}

# mode fresh (default): timestamp "now" — NO rescan at all. Use ONLY for
# an address you KNOW has no history before this instant. `setup`'s notes
# address qualifies (imported before it's ever funded). This is the main
# fix, not just a tolerance for the async-rescan race — a fresh address
# has no history to miss, so timestamp:0 buys nothing while costing a
# real rescan (hundreds of seconds on testnet4, for nothing).
# mode historical: timestamp 0, and WAITS for the async rescan to finish
# before returning — for an address that may have genuine prior history.
# `bundle`'s caller-supplied owner/spending-wallet addresses need this:
# they may be real addresses with real history, which is the entire point
# of the owner_used gap-discovery check below.
ensure_watched() { # addr [mode]
    local addr="$1" mode="${2:-fresh}"
    case " $_watched_list " in *" $addr "*) return 0 ;; esac
    ensure_watch_wallet
    local info
    info="$(WATCH getaddressinfo "$addr")"
    if jq -e '(.ismine // false) or (.iswatchonly // false)' <<<"$info" >/dev/null; then
        _watched_list="$_watched_list $addr"
        return 0
    fi
    local desc ts
    desc="$(CLI getdescriptorinfo "addr($addr)" | jq -r .descriptor)"
    if [[ "$mode" == historical ]]; then ts=0; else ts='"now"'; fi
    WATCH "-rpcclienttimeout=$IMPORT_TIMEOUT" importdescriptors \
        "[{\"desc\":\"$desc\",\"timestamp\":$ts}]" >/dev/null
    if [[ "$mode" == historical ]]; then
        wait_for_rescan "$IMPORT_TIMEOUT" || {
            echo "ensure_watched($addr): still rescanning after ${IMPORT_TIMEOUT}s" >&2
            exit 1
        }
    fi
    _watched_list="$_watched_list $addr"
}

# settle(txid): "make the chain reflect this tx". Regtest mines a block;
# testnet4 polls (mempool or already-mined) until the node knows it.
settle_txid() { # txid (optional on regtest)
    local txid="${1:-}"
    if [[ "$CN_NETWORK" == regtest ]]; then
        ensure_miner_wallet
        MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null
        CLI syncwithvalidationinterfacequeue >/dev/null 2>&1 || true
    elif [[ -n "$txid" ]]; then
        local i
        for i in $(seq 1 30); do
            CLI getmempoolentry "$txid" >/dev/null 2>&1 && return 0
            CLI getrawtransaction "$txid" >/dev/null 2>&1 && return 0
            sleep 1
        done
        echo "settle: node at $CN_NODE_HOST:$CN_NODE_PORT never learned of $txid" >&2
        exit 1
    fi
}

# confirm(txid, timeout): "this must be in a block". Regtest mines a block;
# testnet4 polls for a REAL confirmation, bounded — a timeout FAILS.
confirm_txid() { # txid timeout_secs
    local txid="${1:?txid}" timeout="${2:-1800}"
    if [[ "$CN_NETWORK" == regtest ]]; then
        settle_txid "$txid"
        return 0
    fi
    local waited=0 conf
    while (( waited < timeout )); do
        conf="$(CLI getrawtransaction "$txid" true 2>/dev/null | jq -r '.confirmations // 0')"
        (( conf >= 1 )) && return 0
        sleep 5; waited=$((waited+5))
    done
    echo "confirm: $txid did not confirm within ${timeout}s" >&2
    exit 1
}

# --- funding: regtest spends FROM the Pi's testwallet (never created/
# loaded/reset by us); testnet4 spends from a separate gift-wallet WIF via
# a hand-built raw tx (no wallet import, no rescan) — mirrors
# graffito/scripts/testnet4-live.sh. ---------------------------------
CN_FUND_SATS="${CN_FUND_SATS:-100000}"   # 0.001 BTC, matches the pre-shared-node default

fund_addr() { # dest_addr sats -> echoes txid
    local dest="$1" sats="$2"
    if [[ "$CN_NETWORK" == regtest ]]; then
        local btc
        btc="$(awk "BEGIN{printf \"%.8f\", $sats/1e8}")"
        TESTWALLET sendtoaddress "$dest" "$btc"
    else
        fund_from_wif "$dest" "$sats"
    fi
}

fund_from_wif() { # dest_addr sats -> echoes txid  (testnet4 only)
    local dest="$1" sats="$2"
    : "${FUND_WIF:?testnet4 funding needs FUND_WIF in the environment (never printed) — see graffito/scripts/testnet4-live.sh}"
    local cap="${CN_FUND_SATS_CAP:-200000}"
    (( sats <= cap )) || { echo "refusing to fund $sats sats > cap $cap sats (CN_FUND_SATS_CAP)" >&2; exit 1; }
    local fund_addr="${CN_FUND_ADDR:-tb1q2ylq48ne37ng9clds23xjcrxp8hmn707j5vpyk}"
    local scan
    scan="$(CLI scantxoutset start "[\"addr($fund_addr)\"]")"
    local cand utxo_txid="" utxo_vout="" utxo_sats=""
    cand="$(jq -r '.unspents | sort_by(-.amount) | .[] | "\(.txid) \(.vout) \((.amount*1e8)|round)"' <<<"$scan")"
    while read -r ctxid cvout csats; do
        [[ -z "$ctxid" ]] && continue
        local live
        live="$(CLI gettxout "$ctxid" "$cvout" 2>/dev/null || true)"
        if [[ -n "$live" && "$live" != "null" ]]; then
            utxo_txid="$ctxid"; utxo_vout="$cvout"; utxo_sats="$csats"
            break
        fi
    done <<<"$cand"
    [[ -n "$utxo_txid" ]] || { echo "no usable (not already mempool-spent) gift-wallet UTXO at $fund_addr" >&2; exit 1; }
    local fee_sats=300
    local change_sats=$(( utxo_sats - sats - fee_sats ))
    (( change_sats >= 1000 )) || { echo "gift-wallet UTXO too small ($utxo_sats sats) to fund $sats sats + fee + change" >&2; exit 1; }
    local amt_btc change_btc raw signed hex
    amt_btc="$(awk "BEGIN{printf \"%.8f\", $sats/1e8}")"
    change_btc="$(awk "BEGIN{printf \"%.8f\", $change_sats/1e8}")"
    raw="$(CLI createrawtransaction \
        "[{\"txid\":\"$utxo_txid\",\"vout\":$utxo_vout,\"sequence\":4294967293}]" \
        "{\"$dest\":$amt_btc,\"$fund_addr\":$change_btc}")"
    signed="$(printf '%s\n%s\n' "$raw" "[\"$FUND_WIF\"]" | CLI -stdin signrawtransactionwithkey)"
    FUND_WIF=""   # scrub the instant it's no longer needed
    [[ "$(jq -r .complete <<<"$signed")" == "true" ]] || { echo "signrawtransactionwithkey (funding) did not complete" >&2; exit 1; }
    hex="$(jq -r .hex <<<"$signed")"
    CLI sendrawtransaction "$hex"
}

case "${1:?subcommand}" in
setup)
    ADDR="${2:?notes address}"
    : "${CN_STATE_DIR:?set CN_STATE_DIR to a local scratch dir for this scripts own cross-call bookkeeping, replacing the old DATADIR}"
    mkdir -p "$CN_STATE_DIR"
    echo "$ADDR" > "$CN_STATE_DIR/notes-address"
    ensure_watched "$ADDR"
    FUND_TXID="$(fund_addr "$ADDR" "$CN_FUND_SATS")"
    settle_txid "$FUND_TXID"
    echo "funded $ADDR with $CN_FUND_SATS sats"
    ;;
bundle)
    OUT="${2:?output path}"
    shift 2
    : "${CN_STATE_DIR:?set CN_STATE_DIR to a local scratch dir for this scripts own cross-call bookkeeping, replacing the old DATADIR}"
    ADDR="$(cat "$CN_STATE_DIR/notes-address")"
    ensure_watched "$ADDR"
    tip="$(CLI getblockcount)"
    utxos="$(WATCH listunspent 0 9999999 "[\"$ADDR\"]" | jq '[.[] | {txid, vout, value: (.amount*1e8|round), height: (if .confirmations > 0 then '"$tip"' - .confirmations + 1 else null end)}]')"
    # Extra owner-tagged addresses (funding-unification spending wallet):
    # scanned directly via scantxoutset (node-level, no wallet import
    # needed — these addresses are only ever funded/observed, never
    # mined-to or spent-from by this script) for a CURRENT coin, tagged
    # owner_address.
    #
    # ALSO checked for ANY on-chain history (companion gap-discovery
    # option (b)): a spent-then-emptied address has nothing left for
    # scantxoutset to find, but the device still needs to know it was used
    # so its next_receive/next_change bookkeeping converges past it.
    # scantxoutset can't see historical (spent) outputs, so this check
    # goes through the watch wallet instead — idempotent against the node
    # (ensure_watched), never a blind re-import. These are CALLER-SUPPLIED
    # spending-wallet addresses, not ones this script derived fresh this
    # run — they may carry real prior history (finding it is the entire
    # point of owner_used), so this import genuinely needs mode=historical
    # (timestamp 0, waits out its own rescan) rather than the fresh/"now"
    # path used everywhere else in this file.
    owner_used="[]"
    for OWNER in "$@"; do
        owner_utxos="$(CLI scantxoutset start "[\"addr($OWNER)\"]" \
            | jq --arg a "$OWNER" '[.unspents[] | {txid, vout, value: (.amount*1e8|round), height: (if .height > 0 then .height else null end), owner_address: $a}]')"
        utxos="$(jq -c --argjson extra "$owner_utxos" '. + $extra' <<<"$utxos")"

        ensure_watched "$OWNER" historical
        RECEIVED="$(WATCH getreceivedbyaddress "$OWNER" 0 2>/dev/null || echo 0)"
        if awk "BEGIN{exit !($RECEIVED > 0)}"; then
            owner_used="$(jq -c --arg a "$OWNER" '. + [$a]' <<<"$owner_used")"
        fi
    done
    notes_onchain="[]"
    # The watch wallet is SHARED across every address this script (and
    # other runs/suites) ever imports on this persistent node — filter to
    # txs that actually TOUCH $ADDR, or a wallet-wide listtransactions view
    # leaks other identities' notes into this bundle (mirrors
    # companion/server.py's address_txids fix).
    for txid in $(WATCH listtransactions '*' 1000 0 true | jq -r '[.[].txid] | unique | .[]'); do
        raw="$(CLI getrawtransaction "$txid" 2)"
        payloads="$(jq '[.vout[] | select(.scriptPubKey.type=="nulldata") | .scriptPubKey.asm | split(" ") | .[-1]]' <<<"$raw")"
        [[ "$payloads" == "[]" ]] && continue
        self=false; touches=false
        # select(.txid != null) skips coinbase inputs (no prevout to
        # resolve) — a real hazard now that the watch wallet is SHARED
        # across every address on the node: a coinbase-reward tx to some
        # OTHER identity's address can legitimately show up in this
        # wallet's listtransactions and would otherwise crash the
        # prevout lookup below (found live against the Pi, 2026-08-03).
        for prev in $(jq -r '.vin[] | select(.txid != null) | "\(.txid):\(.vout)"' <<<"$raw"); do
            pspk_addr="$(CLI getrawtransaction "${prev%%:*}" 2 | jq -r ".vout[${prev##*:}].scriptPubKey.address // empty")"
            [[ "$pspk_addr" == "$ADDR" ]] && self=true && touches=true && break
        done
        if [[ "$touches" == false ]]; then
            jq -e --arg a "$ADDR" '[.vout[] | select(.scriptPubKey.address == $a)] | length > 0' <<<"$raw" >/dev/null && touches=true
        fi
        [[ "$touches" == false ]] && continue
        conf="$(WATCH gettransaction "$txid" true | jq .confirmations)"
        if (( conf > 0 )); then
            height=$(( tip - conf + 1 ))
            blocktime="$(WATCH gettransaction "$txid" true | jq .blocktime)"
        else
            height=null; blocktime=null
        fi
        # Addresses of every non-OP_RETURN ("nulldata") output, ascending
        # vout order — mirrors notes-core's OnchainTx.output_addrs /
        # companion/index.html's output_addrs (FLAG_MULTI recipient-list
        # decode: recipients are output_addrs[0..count], preceding change).
        output_addrs="$(jq '[.vout[] | select(.scriptPubKey.type != "nulldata") | .scriptPubKey.address] | map(select(. != null))' <<<"$raw")"
        # The tx's FIRST input's prevout, as "<txid>:<vout>" (display-order
        # txid — notes-core's bundle::format_outpoint convention;
        # PLAN-pnte-redesign.md: the directed-private AAD binds this
        # outpoint instead of the now-nonexistent note_id). A coinbase
        # input (no .txid) yields JSON null, same as index.html's mirror.
        first_input_outpoint="$(jq 'if ((.vin[0].txid // "") != "") then "\(.vin[0].txid):\(.vin[0].vout)" else null end' <<<"$raw")"
        notes_onchain="$(jq --argjson tx "{\"txid\":\"$txid\",\"height\":$height,\"blocktime\":$blocktime,\"spends_from_self\":$self,\"payloads\":$payloads,\"output_addrs\":$output_addrs,\"first_input_outpoint\":$first_input_outpoint}" '. + [$tx]' <<<"$notes_onchain")"
    done
    jq -n --argjson utxos "$utxos" --argjson notes "$notes_onchain" --argjson tip "$tip" --argjson owner_used "$owner_used" --arg net "$CN_NETWORK" '{
        network: $net, full: true, tip_height: $tip,
        bundle_time: 1750000000, max_op_return_bytes: 100000,
        fee_rates: {fastestFee: 3, halfHourFee: 2, hourFee: 1, economyFee: 1, minimumFee: 1},
        btc_usd: 100000,
        utxos: $utxos, owner_used: $owner_used, notes_onchain: $notes
    }' > "$OUT"
    echo "bundle → $OUT ($(jq '.utxos|length' "$OUT") utxos, $(jq '.owner_used|length' "$OUT") owner_used, $(jq '.notes_onchain|length' "$OUT") note-txs, tip $tip)"
    ;;
broadcast)
    HEX="$(cat "${2:?hex file}")"
    CLI testmempoolaccept "[\"$HEX\"]" | jq -e '.[0].allowed' >/dev/null || {
        echo "REJECTED: $(CLI testmempoolaccept "[\"$HEX\"]" | jq -r '.[0]["reject-reason"]')" >&2
        exit 1
    }
    CLI sendrawtransaction "$HEX"
    ;;
mine)
    if [[ "$CN_NETWORK" != regtest ]]; then
        echo "mine: cannot mine on $CN_NETWORK — mining is regtest-only. Use 'settle [txid]' to make the node aware of a broadcast, or 'confirm <txid>' to wait for a real block." >&2
        exit 1
    fi
    ensure_miner_wallet
    MINER generatetoaddress "${2:-1}" "$(MINER getnewaddress)" >/dev/null
    CLI syncwithvalidationinterfacequeue >/dev/null 2>&1 || true
    echo "mined ${2:-1}"
    ;;
settle)
    settle_txid "${2:-}"
    echo "settled${2:+ $2}"
    ;;
confirm)
    TXID="${2:?txid}"
    TIMEOUT="${3:-${CN_CONFIRM_TIMEOUT:-1800}}"
    confirm_txid "$TXID" "$TIMEOUT"
    echo "confirmed $TXID"
    ;;
*)
    echo "unknown subcommand $1" >&2
    exit 2
    ;;
esac
