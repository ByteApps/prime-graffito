#!/usr/bin/env bash
# End-to-end proof of the graffito pipeline against the ONE shared node
# (the Pi's persistent regtest, or testnet4 — see ../../PLAN-one-regtest-node.md).
# This script no longer starts, stops, or owns any bitcoind: it is a client
# of a node that other suites/units may be touching at the same time.
#
#   device role   = notes_cli (notes-core example, host build)
#   companion role = bitcoin-cli against the shared node
#
# Env contract (identical across every suite in this workspace):
#   CN_NETWORK    regtest | testnet4          (default regtest)
#   CN_NODE_HOST  RPC host                    (default 127.0.0.1)
#   CN_NODE_PORT  RPC port                    (default 18443 regtest / 48332 testnet4)
#   CORE_RPC_USER / CORE_RPC_PASS             required, read from the
#     environment ONLY — this is a PUBLIC repo, never read a credential
#     from ../private/ or print one. Run this script through
#     ../../ui-automation/node-env.sh <network> bash scripts/regtest-e2e.sh
#     to get all five set correctly.
#
# Precondition: `cargo` must already be on PATH before running the line
# above — node-env.sh only sets the credential/node contract, it does not
# touch PATH (e.g. `nix develop ~/.foundation/sdk/current --command`
# wrapping the whole invocation, or a shell that already has it).
#
# The chain is SHARED, persistent, and NOT ours: this script never wipes,
# resets, reindexes, or creates/loads/renames the Pi's `testwallet` — it
# only ever SPENDS FROM it (regtest) or from a separate gift-wallet WIF
# (testnet4, see fund_from_wif below). Every identity this script derives
# (the notes address, and the B/C/D directed-note recipients) uses a FRESH
# random seed each run, so no address any assertion depends on has ever
# been touched by a previous run — the same technique
# graffito/scripts/regtest-e2e.sh's --pi-regtest mode uses.
#
# `settle`/`confirm` two-verb split (see the plan's "Two verbs, not one"):
#   settle  = make the chain reflect a broadcast tx. Regtest: mine 1 block
#             + syncwithvalidationinterfacequeue. Testnet4: a successful
#             broadcast already IS the observable — poll until the node
#             knows the txid, then return; no block is produced.
#   confirm = the tx must land in an actual block. Regtest: same as
#             settle. Testnet4: this would mean polling for a REAL block
#             (~10 minutes, uncontrollable) — far too slow for a smoke e2e
#             run repeated a dozen times, so this script never calls it;
#             every assertion that genuinely needs a mined confirmation is
#             gated behind require_regtest and loudly SKIPPED on testnet4
#             instead (regtest-companion.sh, used by the UI suites, DOES
#             expose a real `confirm` subcommand for callers that can
#             afford to wait).
#
# Testnet4 you cannot mine on, so most of this script's interleaved
# "mine 1 block" calls are actually settle()s (they exist to move state off
# pure-mempool, not because a later assertion needs a block) and run on
# both networks; the ones that DO need a real confirmation are gated.
set -euo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; NC=$'\033[0m'
PASS_N=0
pass() { echo "${GRN}PASS${NC} $*"; PASS_N=$((PASS_N+1)); }
fail() { echo "${RED}FAIL${NC} $*"; exit 1; }

SKIP_N=0
SKIPPED_LEGS=()
require_regtest() { # $1 = leg name  $2 = why (regtest-only)
    if [[ "$CN_NETWORK" == "regtest" ]]; then
        return 0
    fi
    echo "${YEL}SKIP${NC} $1 (regtest-only: $2)"
    SKIPPED_LEGS+=("$1")
    SKIP_N=$((SKIP_N+1))
    return 1
}

rand32() { openssl rand -hex 32; }

# --- shared node contract -----------------------------------------------
CN_NETWORK="${CN_NETWORK:-regtest}"
CN_NODE_HOST="${CN_NODE_HOST:-127.0.0.1}"
case "$CN_NETWORK" in
    regtest)  DEFAULT_PORT=18443; TAPROOT_PREFIX="bcrt1p" ;;
    testnet4) DEFAULT_PORT=48332; TAPROOT_PREFIX="tb1p" ;;
    *) fail "CN_NETWORK must be regtest or testnet4, got '$CN_NETWORK'" ;;
esac
CN_NODE_PORT="${CN_NODE_PORT:-$DEFAULT_PORT}"
: "${CORE_RPC_USER:?CORE_RPC_USER is required — run via ui-automation/node-env.sh $CN_NETWORK ...}"
: "${CORE_RPC_PASS:?CORE_RPC_PASS is required — run via ui-automation/node-env.sh $CN_NETWORK ...}"

CLI() { bitcoin-cli "-$CN_NETWORK" "-rpcconnect=$CN_NODE_HOST" "-rpcport=$CN_NODE_PORT" \
    "-rpcuser=$CORE_RPC_USER" "-rpcpassword=$CORE_RPC_PASS" "$@"; }

WATCH_WALLET="graffito-watch"   # matches companion/server.py's convention — reused, not reinvented
MINER_WALLET="graffito-miner"   # ours; NEVER the Pi's `testwallet`
IMPORT_TIMEOUT=1800                # a genuinely historical importdescriptors (timestamp:0) rescans
                                    # from genesis — free on a fresh regtest, hundreds of seconds on
                                    # testnet4 or a chain that's grown (the rescan trap)
# `importdescriptors` at timestamp:0 starts an ASYNCHRONOUS rescan — the
# call can return before the scan finishes, and every other RPC against
# `graffito-watch` (ours or another suite's, since the wallet is
# SHARED) is rejected with -4 "Wallet is currently rescanning" until it
# completes. Found live against the Pi once the chain passed ~1,500
# blocks (the throwaway ~100-block chain this used to run against never
# gave the race room to lose). Every WATCH call gets a retry-with-backoff
# safety net for exactly this — importing is fixed at the source (see
# ensure_watched below), but another consumer can start a rescan under us
# at any moment.
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
        fail "ensure_wallet_loaded($name): $out2"
    else
        fail "ensure_wallet_loaded($name): $out"
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

# Idempotent AGAINST THE NODE (getaddressinfo first), never just against
# process memory — the fast-path cache below is only a speedup on top.
# `graffito-watch` is SHARED across every identity this script derives
# (A, B, C, D) AND across other suites/runs on this persistent node, so a
# wallet-wide `listtransactions` can return other identities' txs too —
# build_bundle filters by address-touch below for exactly that reason.
# Plain space-delimited list, not an associative array — macOS ships bash
# 3.2 (no `declare -A`) and this script must run under the system bash.
_watched_list=""

# Wait for graffito-watch's own background rescan to finish (only ever
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
# an address you KNOW has no history before this instant (this script's
# per-run identities: derived fresh, imported before their first funding
# tx). This is the main fix, not just a tolerance for the async-rescan
# race — a fresh address has no history to miss, so timestamp:0 buys
# nothing while costing a real rescan (and on testnet4, hundreds of
# seconds for nothing).
# mode historical: timestamp 0, and WAITS for the async rescan to finish
# before returning — for an address that may have genuine prior history.
# Not used by this script today (every identity here is freshly derived),
# kept for parity with regtest-companion.sh's owner-address case.
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
        wait_for_rescan "$IMPORT_TIMEOUT" \
            || fail "ensure_watched($addr): still rescanning after ${IMPORT_TIMEOUT}s"
    fi
    _watched_list="$_watched_list $addr"
}

# settle(txid): make the chain reflect a just-broadcast tx.
settle() { # txid (optional on regtest, ignored there)
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
        fail "settle: node at $CN_NODE_HOST:$CN_NODE_PORT never learned of $txid"
    fi
}

# --- funding: regtest spends FROM the Pi's testwallet (never created/
# loaded/reset by us); testnet4 spends from a separate gift-wallet WIF via
# a hand-built raw tx (no wallet import, no rescan) — see
# graffito/scripts/testnet4-live.sh, which this mirrors. -------------
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
    (( sats <= cap )) || fail "refusing to fund $sats sats > cap $cap sats (CN_FUND_SATS_CAP)"
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
    [[ -n "$utxo_txid" ]] || fail "no usable (not already mempool-spent) gift-wallet UTXO at $fund_addr"
    local fee_sats=300
    local change_sats=$(( utxo_sats - sats - fee_sats ))
    (( change_sats >= 1000 )) || fail "gift-wallet UTXO too small ($utxo_sats sats) to fund $sats sats + fee + change"
    local amt_btc change_btc raw signed hex
    amt_btc="$(awk "BEGIN{printf \"%.8f\", $sats/1e8}")"
    change_btc="$(awk "BEGIN{printf \"%.8f\", $change_sats/1e8}")"
    raw="$(CLI createrawtransaction \
        "[{\"txid\":\"$utxo_txid\",\"vout\":$utxo_vout,\"sequence\":4294967293}]" \
        "{\"$dest\":$amt_btc,\"$fund_addr\":$change_btc}")"
    signed="$(printf '%s\n%s\n' "$raw" "[\"$FUND_WIF\"]" | CLI -stdin signrawtransactionwithkey)"
    FUND_WIF=""   # scrub the instant it's no longer needed
    [[ "$(jq -r .complete <<<"$signed")" == "true" ]] || fail "signrawtransactionwithkey (funding) did not complete"
    hex="$(jq -r .hex <<<"$signed")"
    CLI sendrawtransaction "$hex"
}

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${E2E_WORK:-$(mktemp -d /tmp/graffito-e2e.XXXXXX)}"
NOTES="$WORK/notes_cli"
SRV_PID=""

# We never own the node — cleanup only ever touches OUR OWN subprocess
# (the companion server.py test harness at the very end), never `CLI stop`.
cleanup() { kill "${SRV_PID:-}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== build notes_cli (host) =="
( cd "$REPO" && cargo build -q -p notes-core --example notes_cli )
cp "$REPO/target/debug/examples/notes_cli" "$NOTES"

echo "== preflight: reach the shared $CN_NETWORK node at $CN_NODE_HOST:$CN_NODE_PORT =="
if ! CLI getblockchaininfo >/dev/null 2>"$WORK/preflight.err"; then
    fail "cannot reach $CN_NETWORK node at $CN_NODE_HOST:$CN_NODE_PORT (is the SSH tunnel up? see ui-automation/node-env.sh): $(cat "$WORK/preflight.err")"
fi
if [[ "$CN_NETWORK" == regtest ]]; then
    CLI listwallets | jq -e 'index("testwallet") != null' >/dev/null \
        || fail "testwallet is not loaded on the node — this script must never load/create/reset it itself; ask the node owner to load it first"
fi

# Fresh, never-before-touched identity every run (the node is shared and
# persistent) — mirrors graffito/scripts/regtest-e2e.sh --pi-regtest.
export NOTES_APP_SEED="$(rand32)"

ADDR="$("$NOTES" address "$CN_NETWORK")"
echo "notes address: $ADDR"
[[ "$ADDR" == ${TAPROOT_PREFIX}* ]] || fail "expected a $TAPROOT_PREFIX... taproot address"

# Watch it BEFORE it ever receives a sat — this is what makes the "fresh"
# (timestamp "now", no rescan) import mode correct rather than merely
# convenient: there is no history earlier than "now" for this address,
# because nothing has happened to it yet.
ensure_watched "$ADDR"

echo "== fund: send $CN_FUND_SATS sats to the notes address from $([[ "$CN_NETWORK" == regtest ]] && echo "the Pi's testwallet" || echo "the gift wallet") =="
FUND_TXID="$(fund_addr "$ADDR" "$CN_FUND_SATS")"
settle "$FUND_TXID"

# ---------------------------------------------------------------------------
# Companion role: build a sync bundle from the watch wallet.
#   - UTXOs from listunspent, address-scoped (minconf=0, unconfirmed
#     chaining support)
#   - history from listtransactions, filtered to txs that actually TOUCH
#     $addr — the watch wallet is shared across every identity this script
#     (and other runs/suites) ever imports, so an unfiltered wallet-wide
#     view would leak cross-identity notes into this bundle (mirrors
#     companion/server.py's address_txids fix).
# ---------------------------------------------------------------------------
build_bundle() { # $1 = output path, $2 = address (default $ADDR)
    local out="$1" addr="${2:-$ADDR}"
    ensure_watched "$addr"
    local tip utxos notes_onchain
    tip="$(CLI getblockcount)"
    utxos="$(WATCH listunspent 0 9999999 "[\"$addr\"]" | jq '[.[] | {txid, vout, value: (.amount*1e8|round), height: (if .confirmations > 0 then '"$tip"' - .confirmations + 1 else null end)}]')"
    notes_onchain="[]"
    for txid in $(WATCH listtransactions '*' 1000 0 true | jq -r '[.[].txid] | unique | .[]'); do
        local raw payloads self sender pays_self recipient output_addrs height blocktime touches first_input_outpoint
        raw="$(CLI getrawtransaction "$txid" 2 2>/dev/null || WATCH gettransaction "$txid" true true | jq .decoded)"
        # The decrypt AAD binds the tx's first input's prevout (PNTE v1
        # redesign) — same shape regtest-companion.sh's producer emits.
        first_input_outpoint="$(jq 'if ((.vin[0].txid // "") != "") then "\(.vin[0].txid):\(.vin[0].vout)" else null end' <<<"$raw")"
        payloads="$(jq '[.vout[] | select(.scriptPubKey.type=="nulldata") | .scriptPubKey.asm | split(" ") | .[-1]]' <<<"$raw")"
        [[ "$payloads" == "[]" ]] && continue
        self=false; sender=""; touches=false
        # select(.txid != null) skips coinbase inputs (no prevout to
        # resolve) — a real hazard now that the watch wallet is SHARED
        # across every address on the node: a coinbase-reward tx to some
        # OTHER identity's address can legitimately show up in this
        # wallet's listtransactions and would otherwise crash the
        # prevout lookup below (found live against the Pi, 2026-08-03).
        for prev in $(jq -r '.vin[] | select(.txid != null) | "\(.txid):\(.vout)"' <<<"$raw"); do
            local ptxid=${prev%%:*} pvout=${prev##*:}
            local pspk_addr
            pspk_addr="$(CLI getrawtransaction "$ptxid" 2 2>/dev/null | jq -r ".vout[$pvout].scriptPubKey.address // empty")"
            [[ "$pspk_addr" == "$addr" ]] && { self=true; touches=true; }
            [[ -z "$sender" && "$pspk_addr" == ${TAPROOT_PREFIX}* ]] && sender="$pspk_addr"
        done
        pays_self="$(jq --arg a "$addr" '[.vout[] | select(.scriptPubKey.address == $a)] | length > 0' <<<"$raw")"
        [[ "$pays_self" == "true" ]] && touches=true
        if [[ "$touches" == false ]]; then
            continue
        fi
        recipient="$(jq --arg a "$addr" --arg pfx "$TAPROOT_PREFIX" -r '[.vout[] | select(.scriptPubKey.type != "nulldata") | .scriptPubKey.address // empty | select(. != $a and . != "")] | (map(select(startswith($pfx))) + .) | .[0] // empty' <<<"$raw")"
        output_addrs="$(jq '[.vout[] | select(.scriptPubKey.type != "nulldata") | .scriptPubKey.address] | map(select(. != null))' <<<"$raw")"
        local conf
        conf="$(WATCH gettransaction "$txid" true | jq .confirmations)"
        if (( conf > 0 )); then
            height=$(( tip - conf + 1 ))
            blocktime="$(WATCH gettransaction "$txid" true | jq .blocktime)"
        else
            height=null; blocktime=null
        fi
        local sender_json recipient_json
        sender_json="$([[ -n "$sender" ]] && echo "\"$sender\"" || echo null)"
        recipient_json="$([[ -n "$recipient" ]] && echo "\"$recipient\"" || echo null)"
        notes_onchain="$(jq --argjson tx "{\"txid\":\"$txid\",\"height\":$height,\"blocktime\":$blocktime,\"spends_from_self\":$self,\"pays_self\":$pays_self,\"sender\":$sender_json,\"recipient\":$recipient_json,\"payloads\":$payloads,\"output_addrs\":$output_addrs,\"first_input_outpoint\":$first_input_outpoint}" '. + [$tx]' <<<"$notes_onchain")"
    done
    jq -n --argjson utxos "$utxos" --argjson notes "$notes_onchain" --argjson tip "$tip" --arg net "$CN_NETWORK" '{
        network: $net, full: true, tip_height: $tip,
        bundle_time: 1750000000, max_op_return_bytes: 80,
        fee_rates: {fastestFee: 2, halfHourFee: 2, hourFee: 1, economyFee: 1, minimumFee: 1},
        utxos: $utxos, notes_onchain: $notes
    }' > "$out"
}

broadcast() { # $1 = compose json -> txid
    local hex txid
    hex="$(jq -r .raw_hex <<<"$1")"
    CLI testmempoolaccept "[\"$hex\"]" | jq -e '.[0].allowed' >/dev/null \
        || fail "testmempoolaccept rejected: $(CLI testmempoolaccept "[\"$hex\"]" | jq -r '.[0]["reject-reason"]')"
    txid="$(CLI sendrawtransaction "$hex")"
    [[ "$txid" == "$(jq -r .txid <<<"$1")" ]] || fail "txid mismatch: ours $(jq -r .txid <<<"$1") vs node $txid"
    echo "$txid"
}

echo "== note 1: private, 80-byte chunk policy =="
build_bundle "$WORK/bundle1.json"
N1="$("$NOTES" compose "$WORK/bundle1.json" private 2 80 'private note #1: remember the airlock lifecycle')"
T1="$(broadcast "$N1")"; pass "note1 broadcast+txid-match $T1 (fee $(jq .fee <<<"$N1") sats, $(jq .op_returns <<<"$N1") OP_RETURNs)"

echo "== note 2: public, spends note1's UNCONFIRMED change =="
build_bundle "$WORK/bundle2.json"
jq -e '.utxos | length == 1' "$WORK/bundle2.json" >/dev/null || fail "expected exactly the unconfirmed change UTXO, got: $(jq .utxos "$WORK/bundle2.json")"
jq -e '.utxos[0].height == null' "$WORK/bundle2.json" >/dev/null || fail "change UTXO should be unconfirmed"
N2="$("$NOTES" compose "$WORK/bundle2.json" public 2 80 'public note: hello, blockchain — proof I existed on regtest')"
T2="$(broadcast "$N2")"; pass "note2 chained onto unconfirmed change $T2"

settle "$T2"

echo "== note 3: long private note → multiple 80-byte OP_RETURN outputs =="
build_bundle "$WORK/bundle3.json"
LONG="chunked note: $(printf '~%.0s' {1..200})"   # 214 chars → 4 chunks sealed
N3="$("$NOTES" compose "$WORK/bundle3.json" private 2 80 "$LONG")"
(( $(jq .op_returns <<<"$N3") > 1 )) || fail "expected multiple OP_RETURN outputs"
T3="$(broadcast "$N3")"; pass "note3 multi-chunk ($(jq .op_returns <<<"$N3") OP_RETURNs) $T3"

echo "== note 4: >80-byte SINGLE OP_RETURN (Core v30 datacarrier default) =="
BIG="big single-output note $(printf '=%.0s' {1..300})"   # 323 bytes, one output
build_bundle "$WORK/bundle4.json"
N4="$("$NOTES" compose "$WORK/bundle4.json" public 2 100000 "$BIG")"
jq -e '.op_returns == 1' <<<"$N4" >/dev/null || fail "expected one big OP_RETURN"
T4="$(broadcast "$N4")"; pass "note4 large single OP_RETURN relayed by v30 defaults $T4"

settle "$T4"

echo "== wipe-restore: full rescan from chain, no local state =="
build_bundle "$WORK/restore.json"
SCAN="$("$NOTES" scan "$WORK/restore.json")"
echo "$SCAN" | jq -r '.[] | "\(.height)\t\(.private)\t\(.text | tostring | .[0:60])"'
(( $(jq length <<<"$SCAN") == 4 )) || fail "expected 4 recovered notes, got $(jq length <<<"$SCAN")"
jq -e '[.[] | select(.text == null)] | length == 0' >/dev/null <<<"$SCAN" || fail "null text in scan"
grep -q 'private note #1' <<<"$SCAN" || fail "note1 text missing"
grep -q 'proof I existed' <<<"$SCAN" || fail "note2 text missing"
grep -q 'chunked note' <<<"$SCAN" || fail "note3 text missing"
grep -q 'big single-output note' <<<"$SCAN" || fail "note4 text missing"
if require_regtest "wipe-restore-all-confirmed" "notes only land in a block on regtest; testnet4 leaves them unconfirmed for the whole run"; then
    jq -e '[.[] | select(.height != null)] | length == 4' >/dev/null <<<"$SCAN" || fail "all notes should be confirmed"
fi
pass "all 4 notes recovered from bare chain data (texts, heights, visibility)"

echo "== anti-fee-sniping: composed txs carry nLockTime = the bundle's tip =="
# Every tx above was built with the DEFAULT LockTimePolicy::Tip, so each
# one already relayed AND (on regtest) confirmed with a non-zero locktime.
# Pin the value so a regression to 0 is caught here, not on mainnet:
# compose once more against a known tip and decode the last 4 bytes of the
# raw tx (nLockTime, little-endian). Node-agnostic — `tip` just comes from
# the shared node's current height.
build_bundle "$WORK/locktime.json"
LT_TIP="$(jq -r '.tip_height' "$WORK/locktime.json")"
LT_RAW="$("$NOTES" compose "$WORK/locktime.json" public 2.0 80 'locktime pin' | jq -r '.raw_hex')"
LT_GOT="$(python3 -c "import sys; print(int.from_bytes(bytes.fromhex(sys.argv[1][-8:]),'little'))" "$LT_RAW")"
[ "$LT_GOT" = "$LT_TIP" ] || fail "nLockTime $LT_GOT != bundle tip $LT_TIP"
[ "$LT_GOT" != "0" ] || fail "nLockTime is 0 — anti-fee-sniping regressed"
# The opt-out must still work.
LT_ZERO="$(NOTES_LOCKTIME_POLICY=zero "$NOTES" compose "$WORK/locktime.json" public 2.0 80 'locktime zero' | jq -r '.raw_hex')"
LT_ZGOT="$(python3 -c "import sys; print(int.from_bytes(bytes.fromhex(sys.argv[1][-8:]),'little'))" "$LT_ZERO")"
[ "$LT_ZGOT" = "0" ] || fail "zero policy produced nLockTime $LT_ZGOT"
pass "nLockTime = tip ($LT_GOT) by default, 0 under the zero policy"

WRONG_SEED="$(rand32)"

echo "== negative: a different seed cannot read the private notes =="
WRONG="$(NOTES_APP_SEED=$WRONG_SEED "$NOTES" scan "$WORK/restore.json")"
jq -e '[.[] | select(.private and .text != null)] | length == 0' >/dev/null <<<"$WRONG" \
    || fail "foreign seed decrypted a private note!"
jq -e '[.[] | select(.private == false and .text != null)] | length == 2' >/dev/null <<<"$WRONG" \
    || fail "public notes should still be readable by anyone"
pass "private notes unreadable under a foreign seed; public notes readable"

echo "== public note is genuinely plaintext on-chain =="
CLI getrawtransaction "$T2" 2 | jq -r '.vout[].scriptPubKey.asm' | grep -q "$(printf 'public note: hello, blockchain — proof I existed on regtest' | xxd -p -c 10000 | head -c 40)" \
    && pass "note2 plaintext visible in raw chain data" \
    || fail "could not find plaintext payload in note2's tx"

echo "== directed notes: A sends public + private to identity B =="
SEED_B="$(rand32)"
ADDR_B="$(NOTES_APP_SEED=$SEED_B "$NOTES" address "$CN_NETWORK")"
ensure_watched "$ADDR_B"   # before A's first send to B — see the fresh-import note above

build_bundle "$WORK/dsend1.json"
D1="$("$NOTES" send "$WORK/dsend1.json" "$ADDR_B" public 2 100000 'directed public: postcard from A to B')"
jq -e '.sent == 330' <<<"$D1" >/dev/null || fail "directed note must carry 330 sats of dust"
TD1="$(broadcast "$D1")"
settle "$TD1"
build_bundle "$WORK/dsend2.json"
D2="$("$NOTES" send "$WORK/dsend2.json" "$ADDR_B" private 2 100000 'directed private: sealed for B alone')"
TD2="$(broadcast "$D2")"
settle "$TD2"
pass "A sent public+private directed notes to B ($TD1, $TD2)"

echo "== B recovers both from bare chain data (wipe-restore story) =="
build_bundle "$WORK/bundleB.json" "$ADDR_B"
SCANB="$(NOTES_APP_SEED=$SEED_B "$NOTES" scan "$WORK/bundleB.json")"
(( $(jq length <<<"$SCANB") == 2 )) || fail "B expected 2 received notes, got $(jq length <<<"$SCANB")"
jq -e --arg a "$ADDR" '[.[] | select(.received and .directed and .from == $a)] | length == 2' >/dev/null <<<"$SCANB" \
    || fail "received notes must be attributed from=A"
grep -q 'postcard from A to B' <<<"$SCANB" || fail "B cannot read the public directed note"
grep -q 'sealed for B alone' <<<"$SCANB" || fail "B failed to ECDH-decrypt the private directed note"
pass "B decrypted the private directed note via static-static ECDH, from=A"

echo "== negative: a third seed cannot read B's private directed note =="
WRONGB="$(NOTES_APP_SEED=$WRONG_SEED "$NOTES" scan "$WORK/bundleB.json")"
grep -q 'sealed for B alone' <<<"$WRONGB" && fail "foreign seed decrypted a directed note!"
grep -q 'postcard from A to B' <<<"$WRONGB" || fail "public directed note should be readable by anyone"
pass "directed-private unreadable under a foreign seed; public readable"

echo "== A re-reads its own sent notes (sender-side ECDH re-derivation) =="
build_bundle "$WORK/restoreA.json"
SCANA="$("$NOTES" scan "$WORK/restoreA.json")"
jq -e --arg b "$ADDR_B" '[.[] | select(.directed and (.received | not) and .to == $b)] | length == 2' >/dev/null <<<"$SCANA" \
    || fail "A's directed notes must carry to=B"
grep -q 'sealed for B alone' <<<"$SCANA" || fail "A cannot re-read its own sent private directed note"
pass "A re-derived the DM key from the dust output and read its sent note"

echo "== multi-recipient directed notes: A sends private to {B,C} and public to {B,C,D} =="
SEED_C="$(rand32)"
ADDR_C="$(NOTES_APP_SEED=$SEED_C "$NOTES" address "$CN_NETWORK")"
ensure_watched "$ADDR_C"
SEED_D="$(rand32)"
ADDR_D="$(NOTES_APP_SEED=$SEED_D "$NOTES" address "$CN_NETWORK")"
ensure_watched "$ADDR_D"

build_bundle "$WORK/multi1.json"
DM1="$("$NOTES" send-multi "$WORK/multi1.json" private 2 100000 'private multi: sealed for B and C only' "$ADDR_B:400,$ADDR_C:500")"
jq -e '.recipients | length == 2' <<<"$DM1" >/dev/null || fail "expected 2 recipients in private multi compose"
TDM1="$(broadcast "$DM1")"
settle "$TDM1"

build_bundle "$WORK/multi2.json"
DM2="$("$NOTES" send-multi "$WORK/multi2.json" public 2 100000 'public multi: postcard to B, C, and D' "$ADDR_B:330,$ADDR_C:330,$ADDR_D:330")"
jq -e '.recipients | length == 3' <<<"$DM2" >/dev/null || fail "expected 3 recipients in public multi compose"
TDM2="$(broadcast "$DM2")"
settle "$TDM2"
pass "A sent private-multi(B,C) and public-multi(B,C,D) ($TDM1, $TDM2)"

echo "== B and C both decrypt the private multi note =="
build_bundle "$WORK/multiB.json" "$ADDR_B"
SCAN_MB="$(NOTES_APP_SEED=$SEED_B "$NOTES" scan "$WORK/multiB.json")"
grep -q 'sealed for B and C only' <<<"$SCAN_MB" || fail "B failed to decrypt the multi-recipient private note"
jq -e '[.[] | select(.text == "private multi: sealed for B and C only")] | .[0].recipients | length == 2' >/dev/null <<<"$SCAN_MB" \
    || fail "B's recovered multi note should list both recipients"
build_bundle "$WORK/multiC.json" "$ADDR_C"
SCAN_MC="$(NOTES_APP_SEED=$SEED_C "$NOTES" scan "$WORK/multiC.json")"
grep -q 'sealed for B and C only' <<<"$SCAN_MC" || fail "C failed to decrypt the multi-recipient private note"
pass "both B and C independently decrypted the shared content key"

echo "== B, C, D all see the public multi note text =="
build_bundle "$WORK/multiD.json" "$ADDR_D"
SCAN_MD="$(NOTES_APP_SEED=$SEED_D "$NOTES" scan "$WORK/multiD.json")"
grep -q 'postcard to B, C, and D' <<<"$SCAN_MB" || fail "B cannot read public multi text"
grep -q 'postcard to B, C, and D' <<<"$SCAN_MC" || fail "C cannot read public multi text"
grep -q 'postcard to B, C, and D' <<<"$SCAN_MD" || fail "D cannot read public multi text"
pass "B, C, D all read the public multi-recipient note"

echo "== A re-reads its own private multi note from a fresh state (wipe recovery: seed + bundle only) =="
build_bundle "$WORK/restoreA_multi.json"
SCANA_MULTI="$("$NOTES" scan "$WORK/restoreA_multi.json")"
grep -q 'sealed for B and C only' <<<"$SCANA_MULTI" || fail "A failed to re-read its own multi-recipient private note after a wipe"
jq -e '[.[] | select(.text == "private multi: sealed for B and C only")] | .[0].recipients | length == 2' >/dev/null <<<"$SCANA_MULTI" \
    || fail "A's recovered multi note should list both recipients"
pass "A re-derived the multi-recipient DM key from a recipient output key and read its sent note; recipients recorded"

echo "== companion server.py: unknown-txid 404 vs found-txid 200 =="
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
python3 "$REPO/companion/server.py" "$PORT" --node "$CN_NODE_HOST:$CN_NODE_PORT" --network "$CN_NETWORK" >/dev/null 2>&1 &
SRV_PID=$!
for _ in $(seq 1 20); do
    curl -s "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break
    sleep 0.3
done
UNKNOWN_TXID="$(printf 'ff%.0s' $(seq 1 32))"
STATUS="$(curl -s -o "$WORK/body_unknown.txt" -w '%{http_code}' "http://127.0.0.1:$PORT/regtest/api/tx/$UNKNOWN_TXID")"
[[ "$STATUS" == "404" ]] || fail "expected 404 for unknown txid, got $STATUS: $(cat "$WORK/body_unknown.txt")"
pass "unknown txid -> HTTP 404 (dropped-tx detection sees a real 404, not a 400)"
STATUS="$(curl -s -o "$WORK/body_found.txt" -w '%{http_code}' "http://127.0.0.1:$PORT/regtest/api/tx/$T4")"
[[ "$STATUS" == "200" ]] || fail "expected 200 for known txid $T4, got $STATUS: $(cat "$WORK/body_found.txt")"
pass "known txid ($T4) -> HTTP 200, found-tx path unaffected"

echo "== companion server.py: /address/{a} esplora-style stats =="
STATUS="$(curl -s -o "$WORK/addr_stats.json" -w '%{http_code}' "http://127.0.0.1:$PORT/regtest/api/address/$ADDR")"
[[ "$STATUS" == "200" ]] || fail "expected 200 for address stats, got $STATUS: $(cat "$WORK/addr_stats.json")"
# $ADDR was funded once at setup but is then repeatedly self-spent with
# change returned to itself by every note this script composes/sends from
# it, so its lifetime funded_txo_sum by this point in the run is NOT just
# the initial funding amount — cross-check against the watch wallet's own
# confirmed-received total (an independent computation, minconf=1) instead
# of a hardcoded figure. On testnet4 nothing confirms during the run, so
# both sides are legitimately 0 — still a valid self-consistency check.
EXPECT_FUNDED_SATS="$(python3 -c "print(round(float(\"$(WATCH getreceivedbyaddress "$ADDR" 1)\") * 1e8))")"
jq -e --argjson v "$EXPECT_FUNDED_SATS" '.chain_stats.funded_txo_sum == $v' "$WORK/addr_stats.json" >/dev/null \
    || fail "address stats funded_txo_sum mismatch: expected $EXPECT_FUNDED_SATS, got $(jq .chain_stats.funded_txo_sum "$WORK/addr_stats.json")"
if require_regtest "address-stats-confirmed-tx-count" "chain_stats.tx_count needs >=1 CONFIRMED tx; testnet4 leaves everything unconfirmed for the run"; then
    jq -e '.chain_stats.tx_count >= 1' "$WORK/addr_stats.json" >/dev/null \
        || fail "address stats chain_stats.tx_count should be >= 1 for a funded, confirmed address"
fi
pass "address stats: chain_stats.funded_txo_sum == watch wallet's confirmed-received total ($EXPECT_FUNDED_SATS sats), tx_count=$(jq .chain_stats.tx_count "$WORK/addr_stats.json")"

echo "== companion server.py: /address/{a} stats stable across identical calls (unchanged-notebook short-circuit) =="
curl -s -o "$WORK/addr_stats2.json" "http://127.0.0.1:$PORT/regtest/api/address/$ADDR"
diff "$WORK/addr_stats.json" "$WORK/addr_stats2.json" >/dev/null \
    || fail "address stats not stable across identical calls (breaks the app's unchanged-notebook scan short-circuit)"
pass "address stats byte-identical across two identical calls with no chain change in between"

kill "$SRV_PID" >/dev/null 2>&1 || true

echo
echo "${GRN}$PASS_N PASS${NC} · ${YEL}$SKIP_N SKIP${NC}  (network: $CN_NETWORK, workdir: $WORK)"
if (( SKIP_N > 0 )); then
    echo "Skipped (regtest-only):"
    for leg in "${SKIPPED_LEGS[@]}"; do echo "  - $leg"; done
fi
