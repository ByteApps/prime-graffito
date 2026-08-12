#!/usr/bin/env node
// Unit test for the shipped companion/chain-scan.js (the JS port of the
// FROZEN PNTE envelope + extract_notes), PLAN-pnte-redesign.md shape: one
// note = one transaction, id = txid, multiple OP_RETURN outputs of the
// SAME tx concatenate in vout order (header only on the first) — no more
// cross-tx chunk reassembly, no more note_id.
//
// Covers: intra-tx multi-output concatenation, the directed-notes
// acceptance rules — own notes need spends-from-self (spoof resistance),
// pays-me PNTE txs surface as RECEIVED notes attributed to their taproot
// input — and the funding-unification myAddresses extension (mirrors
// notes-core's extract_notes_multi self-spk-SET rule): additive-only, old
// 2-arg callers byte-identical, an unrelated address never falsely OWNs.
// And the 2026-07-18 DISPLAY-OWNER dedup (`notebookAddresses`, mirrors
// notes-core's extract_notes_multi_deduped): first-notebook-input-in-tx-
// order wins, order-flip flips the owner, a non-notebook input earlier in
// the tx never steals the anchor, dedup is opt-in (omitted/empty arg is a
// byte-identical no-op), and a note with no notebook input at all is
// unaffected.
//
// No network, no browser: chain-scan.js runs in a vm context against a
// fetch stub serving synthetic esplora JSON.  Run: node tests/test_chain_scan.js
"use strict";
const vm = require("vm");
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "chain-scan.js"), "utf8");

const ADDR = "bcrt1ptestaddress";           // the scanned address (taproot-ish prefix)
const PEER = "bcrt1ppeeraddress";           // a taproot counterparty
const V0 = "bcrt1qsomeoneelse";             // a non-taproot address
const FUNDER = "bcrt1qfunderfunderfunder";  // a P2WPKH funding-wallet address (not taproot)
const NB2 = "bcrt1pnotebooktwoaddress";     // a SIBLING notebook address (also taproot)
const FLAG_PRIVATE = 0x01;
const FLAG_DIRECTED = 0x02;

const hexByte = (n) => n.toString(16).padStart(2, "0");
const utf8Hex = (s) => Buffer.from(s, "utf8").toString("hex");

// "PNTE" || '1' || flags(2 ASCII hex chars) || [count(2 ASCII hex chars)
// iff multi] || ' ' (envelope.rs::build_header, PLAN-pnte-redesign.md).
// The WHOLE header is printable ASCII, so build it as a string and hex-
// encode once — the flags/count fields are ASCII hex DIGITS, not raw
// binary bytes (e.g. flags=6 is the two wire bytes '0','6', not 0x06).
function pnteHeaderHex(flags, multiCount) {
  let s = "PNTE1" + hexByte(flags);
  if (multiCount != null) s += hexByte(multiCount);
  s += " ";
  return utf8Hex(s);
}

// OP_RETURN scriptPubKey around a hex payload (matches chain-scan.js's
// opReturnPayload decode: <=75 direct push, 76-255 OP_PUSHDATA1).
function opReturnSpk(payloadHex) {
  const len = payloadHex.length / 2;
  let pushHex;
  if (len <= 75) pushHex = hexByte(len);
  else if (len <= 255) pushHex = "4c" + hexByte(len);
  else throw new Error("payload too long for this test helper");
  return "6a" + pushHex + payloadHex;
}

// The FIRST OP_RETURN output of a note tx: header + this piece's body.
function headSpk(flags, dataUtf8, multiCount) {
  return opReturnSpk(pnteHeaderHex(flags, multiCount) + utf8Hex(dataUtf8));
}
// A LATER OP_RETURN output of the same tx: raw body bytes, no header.
function bodySpk(dataUtf8) {
  return opReturnSpk(utf8Hex(dataUtf8));
}

// A tx carrying `spks` OP_RETURNs (vout order = array order). opts: vinAddr
// (single prevout address), vinAddrs (MULTIPLE prevout addresses, in tx
// order — overrides vinAddr; for the DISPLAY-OWNER dedup tests), voutAddrs
// (non-OP_RETURN payment outputs, in order).
function tx(txid, spks, height, opts = {}) {
  const vinAddrs = opts.vinAddrs ?? [opts.vinAddr ?? ADDR];
  const voutAddrs = opts.voutAddrs ?? [ADDR];
  return {
    txid,
    vin: vinAddrs.map((a) => (a == null ? {} : { prevout: { scriptpubkey_address: a } })),
    vout: [
      ...spks.map((spk) => ({ scriptpubkey_type: "op_return", scriptpubkey: spk })),
      ...voutAddrs.map((a) => ({
        scriptpubkey_type: /1p/.test(a) ? "v1_p2tr" : "v0_p2wpkh",
        scriptpubkey_address: a,
        value: 5000,
      })),
    ],
    status: { confirmed: height != null, block_height: height ?? undefined,
              block_time: height != null ? 1700000000 + height : undefined },
  };
}

const HISTORIES = {
  // Intra-tx multi-output concatenation (PLAN-pnte-redesign.md's
  // replacement for the old cross-tx chunking): ONE tx, two OP_RETURN
  // outputs — the header + "hello " on the first, raw "world" on the
  // second — must concatenate into one note, in vout order.
  multiOutput: [
    tx("tx_multi", [headSpk(0, "hello "), bodySpk("world")], 101),
  ],
  // A tx with an invalid header (bad version byte) must be foreign/nonPnte,
  // never a crash, even though it's own-spent and otherwise well formed.
  badHeader: [
    tx("tx_bad", [opReturnSpk(utf8Hex("PNTE2 wrong version"))], 102),
  ],
  // Directed notes at the RECIPIENT (ADDR): a public and a private note
  // from PEER; plus a non-PNTE pays-me tx and a tx that neither spends
  // from nor pays ADDR (pure foreign).
  directed: [
    tx("tx_dm", [headSpk(FLAG_DIRECTED, "note for you!")], 201, { vinAddr: PEER }),
    tx("tx_dmp", [headSpk(FLAG_DIRECTED | FLAG_PRIVATE, "\x10\x20\x30")], 203,
       { vinAddr: PEER }),
    tx("tx_junk", ["6a04deadbeef"], 204, { vinAddr: V0 }),
    tx("tx_foreign", [headSpk(0, "not yours")], 205, { vinAddr: V0, voutAddrs: [V0] }),
  ],
  // Directed note at the SENDER (ADDR): own tx paying PEER + change to self.
  sent: [
    tx("tx_sent", [headSpk(FLAG_DIRECTED, "dear peer")], 301, { voutAddrs: [PEER, ADDR] }),
  ],
  // funding-unification: a self-note funded by an external (non-taproot)
  // wallet — spends from FUNDER, dust-pays ADDR. Without myAddresses this
  // is indistinguishable from a stranger's pays-me note (today's behavior,
  // and no taproot input means no `from` attribution either); passing
  // myAddresses=[FUNDER] must classify it OWN — the self-spk-SET rule
  // mirrored from notes-core's extract_notes_multi.
  funded: [
    tx("tx_funded", [headSpk(0, "funded by external wallet")], 401,
       { vinAddr: FUNDER, voutAddrs: [ADDR] }),
  ],
  // DISPLAY-OWNER dedup (2026-07-18): a tx spending from TWO notebook
  // addresses, ADDR first then NB2. The stub `fetch` ignores which address
  // was actually requested (keyed by scenario name only), so scanning this
  // SAME history as both ADDR and NB2 mirrors two independent notebooks
  // scanning the identical tx.
  dual: [
    tx("tx_dual", [headSpk(0, "owned by two notebooks")], 500,
       { vinAddrs: [ADDR, NB2], voutAddrs: [ADDR] }),
  ],
  // Same shape, notebook inputs reversed (NB2 first) — the owner must flip.
  dualFlipped: [
    tx("tx_dual_flip", [headSpk(0, "owned by two notebooks, reversed")], 501,
       { vinAddrs: [NB2, ADDR], voutAddrs: [ADDR] }),
  ],
  // A non-notebook (funding-wallet) input at position 0, the notebook
  // (ADDR) input at position 1 — the refinement: FUNDER must not steal the
  // anchor away from ADDR.
  dualWpkhFirst: [
    tx("tx_dual_wpkh", [headSpk(0, "wallet-funded but notebook-anchored")],
       502, { vinAddrs: [FUNDER, ADDR], voutAddrs: [ADDR] }),
  ],
  // One input has no `prevout` data at all (esplora sometimes omits it) —
  // the anchor search must skip it without crashing, still finding the
  // real notebook input that follows.
  dualMissingPrevout: [
    tx("tx_dual_missing", [headSpk(0, "missing prevout data on input 0")],
       503, { vinAddrs: [null, ADDR], voutAddrs: [ADDR] }),
  ],
};

const ctx = {
  fetch: async (url) => {
    const scenario = url.match(/^stub:(\w+)/)[1];
    const body = url.includes("/txs/chain") ? [] : HISTORIES[scenario];
    return { ok: true, text: async () => JSON.stringify(body) };
  },
  TextDecoder, console, process,
};
vm.createContext(ctx);
vm.runInContext(src, ctx);

vm.runInContext(`
(async () => {
  const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

  const multi = await scanAddress("stub:multiOutput", ${JSON.stringify(ADDR)});
  assert(multi.notes.length === 1, "multiOutput: expected 1 note");
  const nm = multi.notes[0];
  assert(nm.text === "hello world", "multiOutput: bad concatenation: " + JSON.stringify(nm.text));
  assert(nm.noteId === "tx_multi", "multiOutput: note id must be the txid: " + nm.noteId);
  assert(nm.txids.length === 1 && nm.txids[0] === "tx_multi", "multiOutput: txids must be [txid]");
  assert(nm.height === 101, "multiOutput: bad height " + nm.height);
  assert(!nm.received && !nm.directed, "multiOutput: plain own note");
  console.log("PASS intra-tx multi-output OP_RETURN concatenation (vout order, header on first only)");

  const bad = await scanAddress("stub:badHeader", ${JSON.stringify(ADDR)});
  assert(bad.notes.length === 0, "badHeader: an invalid header must decode to no note");
  assert(bad.noteTxs === 1 && bad.nonPnte === 1,
         "badHeader: still counts as an own tx, but nonPnte (not a valid note): " +
         JSON.stringify({ noteTxs: bad.noteTxs, nonPnte: bad.nonPnte }));
  console.log("PASS a malformed header is foreign data, not a crash");

  const dir = await scanAddress("stub:directed", ${JSON.stringify(ADDR)});
  assert(dir.notes.length === 2, "directed: expected 2 notes, got " + dir.notes.length);
  const dpub = dir.notes.find((x) => !x.private);
  assert(dpub.received && dpub.directed && dpub.text === "note for you!"
         && dpub.from === ${JSON.stringify(PEER)},
         "directed: received public note with sender: " + JSON.stringify(dpub));
  assert(dpub.height === 201, "directed: bad height " + dpub.height);
  const dpriv = dir.notes.find((x) => x.private);
  assert(dpriv.received && dpriv.directed && dpriv.text === null,
         "directed: received private stays sealed");
  assert(dir.receivedTxs === 3 && dir.foreign === 1 && dir.nonPnte === 1,
         "directed: counters recv=" + dir.receivedTxs + " foreign=" + dir.foreign +
         " nonPnte=" + dir.nonPnte);
  console.log("PASS received directed notes (public text + from, private sealed, foreign ignored)");

  const sent = await scanAddress("stub:sent", ${JSON.stringify(ADDR)});
  const s = sent.notes[0];
  assert(!s.received && s.directed && s.to === ${JSON.stringify(PEER)}
         && s.text === "dear peer",
         "sent: own directed note carries to=PEER: " + JSON.stringify(s));
  console.log("PASS own directed note carries its recipient");

  // funding-unification: myAddresses is additive-only. Old callers passing
  // no 4th arg must be byte-identical to pre-change behavior — the
  // funded-by-FUNDER tx stays RECEIVED (from unattributable: no taproot
  // input) exactly like an old bundle/caller that never heard of
  // myAddresses.
  const fundedDefault = await scanAddress("stub:funded", ${JSON.stringify(ADDR)});
  const fd = fundedDefault.notes[0];
  assert(fd.received && fd.from === null && fd.text === "funded by external wallet",
         "funded (no myAddresses): must render as received, unattributed: " + JSON.stringify(fd));
  console.log("PASS funded note without myAddresses renders as received (old behavior, unchanged)");

  // Passing myAddresses=[FUNDER] (e.g. viewer.html's optional &mine=)
  // extends OWN detection to that address — an OR, never a narrowing.
  const fundedOwn = await scanAddress("stub:funded", ${JSON.stringify(ADDR)}, undefined,
                                       [${JSON.stringify(FUNDER)}]);
  const fo = fundedOwn.notes[0];
  assert(!fo.received && fo.text === "funded by external wallet",
         "funded (myAddresses=[FUNDER]): must classify OWN: " + JSON.stringify(fo));
  console.log("PASS funded note WITH myAddresses=[FUNDER] classifies OWN (self-spk-SET rule)");

  // A myAddresses entry that never appears as an input prevout changes
  // nothing (still an OR against the real inputs, not a wildcard).
  const fundedUnrelated = await scanAddress("stub:funded", ${JSON.stringify(ADDR)}, undefined,
                                             [${JSON.stringify(PEER)}]);
  assert(fundedUnrelated.notes[0].received,
         "funded (myAddresses=[unrelated PEER]): must stay received: " +
         JSON.stringify(fundedUnrelated.notes[0]));
  console.log("PASS unrelated myAddresses entry does not falsely mark a note OWN");

  // --- DISPLAY-OWNER dedup (2026-07-18, mirrors extract_notes_multi_deduped) ---

  // (a) A tx spending from ADDR then NB2: scanning the SAME history as
  // both notebooks independently, exactly one keeps the note — the
  // first-notebook-input owner, ADDR. Never-zero across both scans.
  const dualAsAddr = await scanAddress("stub:dual", ${JSON.stringify(ADDR)}, undefined, [],
                                        [${JSON.stringify(NB2)}]);
  const dualAsNb2 = await scanAddress("stub:dual", ${JSON.stringify(NB2)}, undefined, [],
                                       [${JSON.stringify(ADDR)}]);
  assert(dualAsAddr.notes.length === 1, "dual: ADDR (first notebook input) must keep the note");
  assert(dualAsNb2.notes.length === 0, "dual: NB2 must not also display it");
  assert(dualAsAddr.notes.length + dualAsNb2.notes.length === 1,
         "dual: never-zero — exactly one scan keeps the note");
  console.log("PASS DISPLAY-OWNER dedup: first-notebook-input (in tx order) wins, never-zero");

  // (b) Same shape, inputs reversed — the owner flips to NB2.
  const flipAsAddr = await scanAddress("stub:dualFlipped", ${JSON.stringify(ADDR)}, undefined,
                                        [], [${JSON.stringify(NB2)}]);
  const flipAsNb2 = await scanAddress("stub:dualFlipped", ${JSON.stringify(NB2)}, undefined,
                                       [], [${JSON.stringify(ADDR)}]);
  assert(flipAsAddr.notes.length === 0, "dualFlipped: ADDR is no longer first, must not keep");
  assert(flipAsNb2.notes.length === 1, "dualFlipped: NB2 (now first) must keep the note");
  console.log("PASS DISPLAY-OWNER dedup: owner flips with input order");

  // (c) A funding-wallet (non-notebook) input at position 0 must not steal
  // the anchor from the real notebook input that follows.
  const wpkhFirst = await scanAddress("stub:dualWpkhFirst", ${JSON.stringify(ADDR)}, undefined,
                                       [], [${JSON.stringify(NB2)}]);
  assert(wpkhFirst.notes.length === 1 && !wpkhFirst.notes[0].received,
         "dualWpkhFirst: notebook input still anchors despite a non-notebook input first: " +
         JSON.stringify(wpkhFirst.notes[0]));
  console.log("PASS DISPLAY-OWNER dedup: non-notebook input at position 0 does not steal the anchor");

  // (d) A note with NO notebook input at all (pure funding-wallet shape,
  // reusing the "funded" fixture) is unaffected by dedup being enabled —
  // the anchor search finds nothing, so it's kept exactly as before.
  const fundedDeduped = await scanAddress("stub:funded", ${JSON.stringify(ADDR)}, undefined,
                                           [${JSON.stringify(FUNDER)}], [${JSON.stringify(NB2)}]);
  assert(!fundedDeduped.notes[0].received,
         "funded + notebookAddresses set: no notebook input present, must stay kept/OWN: " +
         JSON.stringify(fundedDeduped.notes[0]));
  console.log("PASS DISPLAY-OWNER dedup: no-op when the tx has no notebook input at all");

  // (e) notebookAddresses omitted (old 2/4-arg calls) and an explicit empty
  // array must be byte-identical to each other — dedup is strictly opt-in.
  const dualOld = await scanAddress("stub:dual", ${JSON.stringify(ADDR)});
  const dualEmptyArr = await scanAddress("stub:dual", ${JSON.stringify(ADDR)}, undefined, [], []);
  assert(dualOld.notes.length === 1 && dualEmptyArr.notes.length === 1,
         "dual: omitted/empty notebookAddresses must both keep the note (dedup off)");
  console.log("PASS DISPLAY-OWNER dedup: omitted/empty notebookAddresses is a byte-identical no-op");

  // (f) A missing "prevout" field on one input (esplora sometimes omits
  // it) must not crash the anchor search — it's skipped, and the real
  // notebook input that follows still anchors correctly.
  const missingPrevout = await scanAddress("stub:dualMissingPrevout", ${JSON.stringify(ADDR)},
                                            undefined, [], [${JSON.stringify(NB2)}]);
  assert(missingPrevout.notes.length === 1 && !missingPrevout.notes[0].received,
         "dualMissingPrevout: a prevout-less input must not crash or block the real anchor: " +
         JSON.stringify(missingPrevout.notes[0]));
  console.log("PASS DISPLAY-OWNER dedup: a missing-prevout input is skipped, not fatal");

  console.log("CHAIN-SCAN UNIT TESTS PASSED");
})().catch((e) => { console.error("FAIL " + e.message); process.exit(1); });
`, ctx);
