#!/usr/bin/env bash
# End-to-end proof of the chain-notes pipeline on a private regtest chain.
#
#   device role   = notes_cli (notes-core example, host build)
#   companion role = bitcoin-cli against a throwaway bitcoind -regtest
#
# Covers: funding, private note, public note, multi-chunk 80-byte-policy
# note, >80-byte single-OP_RETURN note (Core v30 datacarrier default),
# unconfirmed-change chaining, full-history rescan ("wipe restore"), and
# the wrong-seed negative check.
set -euo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; NC=$'\033[0m'
pass() { echo "${GRN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*"; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${E2E_WORK:-$(mktemp -d /tmp/chain-notes-e2e.XXXXXX)}"
DATADIR="$WORK/bitcoind"
mkdir -p "$DATADIR"
CLI() { bitcoin-cli -regtest -datadir="$DATADIR" "$@"; }
WATCH() { CLI -rpcwallet=watch "$@"; }
MINER() { CLI -rpcwallet=miner "$@"; }
NOTES="$WORK/notes_cli"
SRV_PID=""

cleanup() { CLI stop >/dev/null 2>&1 || true; sleep 1; kill "${SRV_PID:-}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== build notes_cli (host) =="
( cd "$REPO" && cargo build -q -p notes-core --example notes_cli )
cp "$REPO/target/debug/examples/notes_cli" "$NOTES"

echo "== start throwaway bitcoind -regtest in $WORK =="
# -txindex: the companion resolves arbitrary prevouts to compute
# spends_from_self (mempool.space has this by construction).
bitcoind -regtest -datadir="$DATADIR" -daemonwait -txindex=1 -fallbackfee=0.0001 >/dev/null
CLI createwallet miner >/dev/null

ADDR="$("$NOTES" address regtest)"
echo "notes address: $ADDR"
[[ "$ADDR" == bcrt1p* ]] || fail "expected a bcrt1p taproot address"

echo "== watch-only companion wallet (descriptor import — the 'scanner') =="
CLI createwallet watch true true >/dev/null   # disable_private_keys, blank
DESC="$(CLI getdescriptorinfo "addr($ADDR)" | jq -r .descriptor)"
WATCH importdescriptors "[{\"desc\":\"$DESC\",\"timestamp\":0}]" >/dev/null

echo "== fund: miner matures coins, sends 0.001 BTC to the notes address =="
MINER generatetoaddress 101 "$(MINER getnewaddress)" >/dev/null
MINER sendtoaddress "$ADDR" 0.001 >/dev/null
MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null

# ---------------------------------------------------------------------------
# Companion role: build a sync bundle from the watch wallet.
#   - UTXOs from listunspent minconf=0 (unconfirmed chaining support)
#   - history from listtransactions; per tx, OP_RETURN payloads and the
#     spends-from-self flag (does any input's prevout pay our address?)
# ---------------------------------------------------------------------------
build_bundle() { # $1 = output path, $2 = address (default $ADDR), $3 = wallet (default watch)
    local out="$1" addr="${2:-$ADDR}" wallet="${3:-watch}"
    local tip utxos txids notes_onchain
    W() { CLI -rpcwallet="$wallet" "$@"; }
    tip="$(CLI getblockcount)"
    utxos="$(W listunspent 0 9999999 | jq '[.[] | {txid, vout, value: (.amount*1e8|round), height: (if .confirmations > 0 then '"$tip"' - .confirmations + 1 else null end)}]')"
    txids="$(W listtransactions '*' 1000 | jq -r '[.[].txid] | unique | .[]')"
    notes_onchain="[]"
    for txid in $txids; do
        local raw payloads self sender pays_self recipient output_addrs height blocktime
        raw="$(CLI getrawtransaction "$txid" 2 2>/dev/null || CLI -rpcwallet="$wallet" gettransaction "$txid" true true | jq .decoded)"
        # asm for nulldata is "OP_RETURN <payload-hex>"; take the data token.
        payloads="$(jq '[.vout[] | select(.scriptPubKey.type=="nulldata") | .scriptPubKey.asm | split(" ") | .[-1]]' <<<"$raw")"
        [[ "$payloads" == "[]" ]] && continue
        self=false; sender=""
        for prev in $(jq -r '.vin[] | "\(.txid):\(.vout)"' <<<"$raw"); do
            local ptxid=${prev%%:*} pvout=${prev##*:}
            local pspk_addr
            pspk_addr="$(CLI getrawtransaction "$ptxid" 2 2>/dev/null | jq -r ".vout[$pvout].scriptPubKey.address // empty")"
            [[ "$pspk_addr" == "$addr" ]] && self=true
            [[ -z "$sender" && "$pspk_addr" == bcrt1p* ]] && sender="$pspk_addr"
        done
        # Directed-note additive fields: pays_self gates received notes,
        # sender attributes them, recipient records who an own note paid.
        pays_self="$(jq --arg a "$addr" '[.vout[] | select(.scriptPubKey.address == $a)] | length > 0' <<<"$raw")"
        recipient="$(jq --arg a "$addr" -r '[.vout[] | select(.scriptPubKey.type != "nulldata") | .scriptPubKey.address // empty | select(. != $a and . != "")] | (map(select(startswith("bcrt1p"))) + .) | .[0] // empty' <<<"$raw")"
        # Multi-recipient decode (FLAG_MULTI): every non-OP_RETURN output's
        # address, in ascending vout order (recipients precede change by
        # construction — bundle.rs slices output_addrs[0..count]).
        output_addrs="$(jq '[.vout[] | select(.scriptPubKey.type != "nulldata") | .scriptPubKey.address] | map(select(. != null))' <<<"$raw")"
        local conf
        conf="$(W gettransaction "$txid" true | jq .confirmations)"
        if (( conf > 0 )); then
            height=$(( tip - conf + 1 ))
            blocktime="$(W gettransaction "$txid" true | jq .blocktime)"
        else
            height=null; blocktime=null
        fi
        local sender_json recipient_json
        sender_json="$([[ -n "$sender" ]] && echo "\"$sender\"" || echo null)"
        recipient_json="$([[ -n "$recipient" ]] && echo "\"$recipient\"" || echo null)"
        notes_onchain="$(jq --argjson tx "{\"txid\":\"$txid\",\"height\":$height,\"blocktime\":$blocktime,\"spends_from_self\":$self,\"pays_self\":$pays_self,\"sender\":$sender_json,\"recipient\":$recipient_json,\"payloads\":$payloads,\"output_addrs\":$output_addrs}" '. + [$tx]' <<<"$notes_onchain")"
    done
    jq -n --argjson utxos "$utxos" --argjson notes "$notes_onchain" --argjson tip "$tip" '{
        network: "regtest", full: true, tip_height: $tip,
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

MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null

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

MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null

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
jq -e '[.[] | select(.height != null)] | length == 4' >/dev/null <<<"$SCAN" || fail "all notes should be confirmed"
pass "all 4 notes recovered from bare chain data (texts, heights, visibility)"

echo "== anti-fee-sniping: composed txs carry nLockTime = the bundle's tip =="
# Every tx above was built with the DEFAULT LockTimePolicy::Tip, so each
# one already relayed AND confirmed on a real bitcoind with a non-zero
# locktime. Pin the value so a regression to 0 is caught here, not on
# mainnet: compose once more against a known tip and decode the last 4
# bytes of the raw tx (nLockTime, little-endian).
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

echo "== negative: a different seed cannot read the private notes =="
WRONG="$(NOTES_APP_SEED=$(printf '99%.0s' {1..32}) "$NOTES" scan "$WORK/restore.json")"
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
SEED_B="$(printf '09%.0s' {1..32})"
ADDR_B="$(NOTES_APP_SEED=$SEED_B "$NOTES" address regtest)"
CLI createwallet watch_b true true >/dev/null
DESC_B="$(CLI getdescriptorinfo "addr($ADDR_B)" | jq -r .descriptor)"
CLI -rpcwallet=watch_b importdescriptors "[{\"desc\":\"$DESC_B\",\"timestamp\":0}]" >/dev/null

build_bundle "$WORK/dsend1.json"
D1="$("$NOTES" send "$WORK/dsend1.json" "$ADDR_B" public 2 100000 'directed public: postcard from A to B')"
jq -e '.sent == 330' <<<"$D1" >/dev/null || fail "directed note must carry 330 sats of dust"
TD1="$(broadcast "$D1")"
MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null
build_bundle "$WORK/dsend2.json"
D2="$("$NOTES" send "$WORK/dsend2.json" "$ADDR_B" private 2 100000 'directed private: sealed for B alone')"
TD2="$(broadcast "$D2")"
MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null
pass "A sent public+private directed notes to B ($TD1, $TD2)"

echo "== B recovers both from bare chain data (wipe-restore story) =="
build_bundle "$WORK/bundleB.json" "$ADDR_B" watch_b
SCANB="$(NOTES_APP_SEED=$SEED_B "$NOTES" scan "$WORK/bundleB.json")"
(( $(jq length <<<"$SCANB") == 2 )) || fail "B expected 2 received notes, got $(jq length <<<"$SCANB")"
jq -e --arg a "$ADDR" '[.[] | select(.received and .directed and .from == $a)] | length == 2' >/dev/null <<<"$SCANB" \
    || fail "received notes must be attributed from=A"
grep -q 'postcard from A to B' <<<"$SCANB" || fail "B cannot read the public directed note"
grep -q 'sealed for B alone' <<<"$SCANB" || fail "B failed to ECDH-decrypt the private directed note"
pass "B decrypted the private directed note via static-static ECDH, from=A"

echo "== negative: a third seed cannot read B's private directed note =="
WRONGB="$(NOTES_APP_SEED=$(printf '99%.0s' {1..32}) "$NOTES" scan "$WORK/bundleB.json")"
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
SEED_C="$(printf '10%.0s' {1..32})"
ADDR_C="$(NOTES_APP_SEED=$SEED_C "$NOTES" address regtest)"
CLI createwallet watch_c true true >/dev/null
DESC_C="$(CLI getdescriptorinfo "addr($ADDR_C)" | jq -r .descriptor)"
CLI -rpcwallet=watch_c importdescriptors "[{\"desc\":\"$DESC_C\",\"timestamp\":0}]" >/dev/null

SEED_D="$(printf '11%.0s' {1..32})"
ADDR_D="$(NOTES_APP_SEED=$SEED_D "$NOTES" address regtest)"
CLI createwallet watch_d true true >/dev/null
DESC_D="$(CLI getdescriptorinfo "addr($ADDR_D)" | jq -r .descriptor)"
CLI -rpcwallet=watch_d importdescriptors "[{\"desc\":\"$DESC_D\",\"timestamp\":0}]" >/dev/null

build_bundle "$WORK/multi1.json"
DM1="$("$NOTES" send-multi "$WORK/multi1.json" private 2 100000 'private multi: sealed for B and C only' "$ADDR_B:400,$ADDR_C:500")"
jq -e '.recipients | length == 2' <<<"$DM1" >/dev/null || fail "expected 2 recipients in private multi compose"
TDM1="$(broadcast "$DM1")"
MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null

build_bundle "$WORK/multi2.json"
DM2="$("$NOTES" send-multi "$WORK/multi2.json" public 2 100000 'public multi: postcard to B, C, and D' "$ADDR_B:330,$ADDR_C:330,$ADDR_D:330")"
jq -e '.recipients | length == 3' <<<"$DM2" >/dev/null || fail "expected 3 recipients in public multi compose"
TDM2="$(broadcast "$DM2")"
MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null
pass "A sent private-multi(B,C) and public-multi(B,C,D) ($TDM1, $TDM2)"

echo "== B and C both decrypt the private multi note =="
build_bundle "$WORK/multiB.json" "$ADDR_B" watch_b
SCAN_MB="$(NOTES_APP_SEED=$SEED_B "$NOTES" scan "$WORK/multiB.json")"
grep -q 'sealed for B and C only' <<<"$SCAN_MB" || fail "B failed to decrypt the multi-recipient private note"
jq -e '[.[] | select(.text == "private multi: sealed for B and C only")] | .[0].recipients | length == 2' >/dev/null <<<"$SCAN_MB" \
    || fail "B's recovered multi note should list both recipients"
build_bundle "$WORK/multiC.json" "$ADDR_C" watch_c
SCAN_MC="$(NOTES_APP_SEED=$SEED_C "$NOTES" scan "$WORK/multiC.json")"
grep -q 'sealed for B and C only' <<<"$SCAN_MC" || fail "C failed to decrypt the multi-recipient private note"
pass "both B and C independently decrypted the shared content key"

echo "== B, C, D all see the public multi note text =="
build_bundle "$WORK/multiD.json" "$ADDR_D" watch_d
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
python3 "$REPO/companion/server.py" "$PORT" --datadir "$DATADIR" >/dev/null 2>&1 &
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
# $ADDR was funded once at setup (sendtoaddress 0.001 BTC = 100000 sats,
# line ~51) but is then repeatedly self-spent with change returned to
# itself by every note this script composes/sends from it, so its
# lifetime funded_txo_sum by this point in the run is NOT just the
# initial 100000 — cross-check against the watch wallet's own
# confirmed-received total (an independent computation) instead of a
# hardcoded figure that would go stale the moment an earlier step changes.
EXPECT_FUNDED_SATS="$(python3 -c "print(round(float(\"$(WATCH getreceivedbyaddress "$ADDR" 1)\") * 1e8))")"
jq -e --argjson v "$EXPECT_FUNDED_SATS" '.chain_stats.funded_txo_sum == $v' "$WORK/addr_stats.json" >/dev/null \
    || fail "address stats funded_txo_sum mismatch: expected $EXPECT_FUNDED_SATS, got $(jq .chain_stats.funded_txo_sum "$WORK/addr_stats.json")"
jq -e '.chain_stats.tx_count >= 1' "$WORK/addr_stats.json" >/dev/null \
    || fail "address stats chain_stats.tx_count should be >= 1 for a funded, confirmed address"
pass "address stats: chain_stats.funded_txo_sum == watch wallet's confirmed-received total ($EXPECT_FUNDED_SATS sats), tx_count=$(jq .chain_stats.tx_count "$WORK/addr_stats.json")"

echo "== companion server.py: /address/{a} stats stable across identical calls (unchanged-notebook short-circuit) =="
curl -s -o "$WORK/addr_stats2.json" "http://127.0.0.1:$PORT/regtest/api/address/$ADDR"
diff "$WORK/addr_stats.json" "$WORK/addr_stats2.json" >/dev/null \
    || fail "address stats not stable across identical calls (breaks the app's unchanged-notebook scan short-circuit)"
pass "address stats byte-identical across two identical calls with no chain change in between"

kill "$SRV_PID" >/dev/null 2>&1 || true

echo
echo "${GRN}ALL E2E CHECKS PASSED${NC}  (workdir: $WORK)"
