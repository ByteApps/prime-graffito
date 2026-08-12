#!/usr/bin/env node
// Unit test for FLAG_MULTI (multi-recipient directed notes) decode in the
// shipped companion/chain-scan.js — the JS port of notes-core's PNTE
// envelope + bundle.rs scanner, PLAN-pnte-redesign.md shape.
//
// Wire spec (notes-core/src/envelope.rs FLAG_MULTI, frozen on this
// branch):
//   flags bit 2 (0x04), only ever set together with FLAG_DIRECTED (0x02).
//   The recipient count is a HEADER field now (2 ASCII hex chars,
//   `01`..`ff`), never a body byte:
//     public  (FLAG_PRIVATE clear): body = the UTF-8 text, verbatim
//     private (FLAG_PRIVATE set):   body = count*wrap(72B) || sealed_body
//   count is LIBERAL at the envelope level, but a zero count now makes the
//   WHOLE HEADER undecodable (envelope.rs::parse_header) — the tx never
//   registers as a note at all, unlike the pre-redesign body-byte scheme
//   where the envelope still parsed. Recipients are the first `count`
//   non-OP_RETURN outputs of the tx, ascending vout order (they precede
//   change by construction).
//
// Byte-parity cross-check against Rust (tests A/B/C below): the envelope
// bytes (flags/count/body) are taken verbatim from notes-core's
// notes-core/tests/multi_recipient.rs unit-test vectors —
// decode_liberal_count_one_accepted, decode_liberal_count_zero_rejected,
// decode_liberal_truncated_wraps_rejected — so this proves the JS decoder
// agrees with the Rust decoder byte-for-byte on those exact payloads, not
// just "the same logic re-implemented".
//
// No network, no browser: chain-scan.js runs in a vm context against a
// fetch stub serving synthetic esplora JSON, same harness as
// tests/test_chain_scan.js.  Run: node tests/test_multi_decode.js
"use strict";
const vm = require("vm");
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "chain-scan.js"), "utf8");

const FLAG_PRIVATE = 0x01;
const FLAG_DIRECTED = 0x02;
const FLAG_MULTI = 0x04;

const ADDR = "bcrt1ptestscannedaddr";  // the scanned address (also B, a recipient)
const SENDER = "bcrt1palicesender";    // the note's author (not `mine`)
const CAROL = "bcrt1pcarolrecipient";  // a second recipient
const CHANGE = "bcrt1qsenderchange";   // sender's change (non-taproot, non-recipient)

const hexByte = (n) => n.toString(16).padStart(2, "0");
const utf8Hex = (s) => Buffer.from(s, "utf8").toString("hex");

// "PNTE" || '1' || flags(2 ASCII hex chars) || count(2 ASCII hex chars) ||
// ' ' — the WHOLE header is printable ASCII (envelope.rs::build_header).
function pnteHeaderHex(flags, multiCount) {
  let s = "PNTE1" + hexByte(flags);
  if (multiCount != null) s += hexByte(multiCount);
  s += " ";
  return utf8Hex(s);
}

// OP_RETURN scriptPubKey around a hex payload (matches chain-scan.js's
// opReturnPayload decode: <=75 direct push, 76-255 OP_PUSHDATA1, else
// OP_PUSHDATA2).
function opReturnSpk(payloadHex) {
  const len = payloadHex.length / 2;
  let pushHex;
  if (len <= 75) pushHex = hexByte(len);
  else if (len <= 255) pushHex = "4c" + hexByte(len);
  else {
    const lo = len & 0xff, hi = (len >> 8) & 0xff;
    pushHex = "4d" + hexByte(lo) + hexByte(hi);
  }
  return "6a" + pushHex + payloadHex;
}

// A single-OP_RETURN note tx's first (only) output: header + body.
function noteSpk(flags, multiCount, bodyHex) {
  return opReturnSpk(pnteHeaderHex(flags, multiCount) + bodyHex);
}

const hex = (s) => Buffer.from(s, "utf8").toString("hex");

// A single-OP_RETURN tx. `vinAddr` (default SENDER, not `mine`) drives
// spendsFromSelf; `voutAddrs` are the non-OP_RETURN outputs in vout order
// (index 0 = whatever chain-scan.js's `outputAddrs`/multi-recipient slice
// sees first).
function tx(txid, spkHex, height, { vinAddr = SENDER, voutAddrs = [ADDR] } = {}) {
  return {
    txid,
    vin: [{ prevout: { scriptpubkey_address: vinAddr } }],
    vout: [
      { scriptpubkey_type: "op_return", scriptpubkey: spkHex },
      ...voutAddrs.map((a) => ({
        scriptpubkey_type: /1p/.test(a) ? "v1_p2tr" : "v0_p2wpkh",
        scriptpubkey_address: a,
        value: 330,
      })),
    ],
    status: { confirmed: height != null, block_height: height ?? undefined,
              block_time: height != null ? 1700000000 + height : undefined },
  };
}

const HISTORIES = {
  // === A: cross-check vs multi_recipient.rs::decode_liberal_count_one_accepted ===
  // flags = FLAG_DIRECTED|FLAG_MULTI, count=1, body = "solo via multi
  // flag" — byte-identical to the Rust vector (envelope::encode_outputs(
  // flags, Some(1), body, 100_000)). Rust's output_addrs there is
  // [b.address(NET)] (one recipient = the scanned address itself);
  // mirrored here as voutAddrs:[ADDR].
  countOne: [
    tx("tx_a", noteSpk(FLAG_DIRECTED | FLAG_MULTI, 1, hex("solo via multi flag")), 100,
       { voutAddrs: [ADDR] }),
  ],
  // === B: cross-check vs decode_liberal_count_zero_rejected ===
  // Same shape, count=0 — the WHOLE HEADER is undecodable (envelope.rs:
  // `if c == 0 { return None; }`), so the tx never registers as a note at
  // all (notes-core: "the tx never registers as a note at all").
  countZero: [
    tx("tx_b", noteSpk(FLAG_DIRECTED | FLAG_MULTI, 0, hex("nobody")), 101,
       { voutAddrs: [ADDR] }),
  ],
  // === C: cross-check vs decode_liberal_truncated_wraps_rejected ===
  // flags = FLAG_DIRECTED|FLAG_MULTI|FLAG_PRIVATE, count=2, body = 10 zero
  // bytes (claims 2*72=144 wrap bytes, has 10) — text must stay
  // undecodable (the browser never even attempts private decrypt), but
  // per notes-core's bundle.rs the recipient LIST is derived from `count`
  // alone (an envelope.rs-level fact), before any wrap-length check — so
  // recipients must still come back as both output addresses.
  truncated: [
    tx("tx_c", noteSpk(FLAG_DIRECTED | FLAG_MULTI | FLAG_PRIVATE, 2, "00".repeat(10)), 102,
       { voutAddrs: [ADDR, CAROL] }),
  ],
  // === D: public, 2 recipients + a 3rd non-recipient output (change) ===
  // Proves recipients are SLICED to `count`, not "every non-OP_RETURN
  // output" — the trailing CHANGE output must be excluded.
  publicTwo: [
    tx("tx_d", noteSpk(FLAG_DIRECTED | FLAG_MULTI, 2, hex("hi both of you")), 103,
       { voutAddrs: [ADDR, CAROL, CHANGE] }),
  ],
  // === E: private, 2 real-shaped 72-byte wraps + a sealed-body blob ===
  // The browser cannot decrypt — text must stay the placeholder (null),
  // but recipients still resolve from `count`.
  privateTwo: [
    tx("tx_e", noteSpk(FLAG_DIRECTED | FLAG_MULTI | FLAG_PRIVATE, 2,
       "aa".repeat(72) + "aa".repeat(72) + "bb".repeat(24)), 104,
       { voutAddrs: [ADDR, CAROL] }),
  ],
  // === F: single-recipient regression — FLAG_MULTI CLEAR ===
  // Plain directed note, own side (ADDR spends from itself to CAROL +
  // change to self) — must decode exactly as before this feature existed:
  // multi:false, recipients:[], `to` populated the old way.
  singleRegression: [
    tx("tx_f", noteSpk(FLAG_DIRECTED, null, hex("dear carol")), 105,
       { vinAddr: ADDR, voutAddrs: [CAROL, ADDR] }),
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

  // --- A: count=1 accepted (cross-check vs decode_liberal_count_one_accepted) ---
  const a = await scanAddress("stub:countOne", ${JSON.stringify(ADDR)});
  assert(a.notes.length === 1, "countOne: expected 1 note");
  const na = a.notes[0];
  assert(na.multi === true, "countOne: multi flag must be set");
  assert(na.text === "solo via multi flag",
         "countOne: text must match the Rust vector byte-for-byte, got " + JSON.stringify(na.text));
  assert(JSON.stringify(na.recipients) === JSON.stringify([${JSON.stringify(ADDR)}]),
         "countOne: recipients must be the single output address: " + JSON.stringify(na.recipients));
  console.log("PASS A: count=1 public multi note — text + recipients match Rust vector");

  // --- B: count=0 rejected (cross-check vs decode_liberal_count_zero_rejected) ---
  const b = await scanAddress("stub:countZero", ${JSON.stringify(ADDR)});
  assert(b.notes.length === 0,
         "countZero: a count=0 header is undecodable at the envelope level — no note at all: " +
         JSON.stringify(b.notes));
  assert(b.nonPnte === 1, "countZero: must count as nonPnte, not a crash: " + b.nonPnte);
  console.log("PASS B: count=0 makes the whole header undecodable (liberal decode), does not throw");

  // --- C: truncated wraps (cross-check vs decode_liberal_truncated_wraps_rejected) ---
  const c = await scanAddress("stub:truncated", ${JSON.stringify(ADDR)});
  assert(c.notes.length === 1, "truncated: expected 1 note");
  const nc = c.notes[0];
  assert(nc.private === true && nc.multi === true, "truncated: private+multi flags");
  assert(nc.text === null, "truncated: private body is never attempted in-browser, must stay null");
  assert(JSON.stringify(nc.recipients) === JSON.stringify([${JSON.stringify(ADDR)}, ${JSON.stringify(CAROL)}]),
         "truncated: recipient list comes from the header count alone (before any wrap-length check): " +
         JSON.stringify(nc.recipients));
  console.log("PASS C: truncated private wraps — text stays sealed, recipients still resolve, no throw");

  // --- D: public, recipients sliced to count (change output excluded) ---
  const d = await scanAddress("stub:publicTwo", ${JSON.stringify(ADDR)});
  const nd = d.notes[0];
  assert(nd.text === "hi both of you", "publicTwo: bad text: " + JSON.stringify(nd.text));
  assert(JSON.stringify(nd.recipients) === JSON.stringify([${JSON.stringify(ADDR)}, ${JSON.stringify(CAROL)}]),
         "publicTwo: recipients must be sliced to count=2, excluding change: " + JSON.stringify(nd.recipients));
  console.log("PASS D: public 2-recipient note — recipients sliced from a 3-output list, change excluded");

  // --- E: private, real-shaped wraps — placeholder text, recipients resolve ---
  const e = await scanAddress("stub:privateTwo", ${JSON.stringify(ADDR)});
  const ne = e.notes[0];
  assert(ne.private === true && ne.multi === true, "privateTwo: private+multi flags");
  assert(ne.text === null, "privateTwo: private body must render as the placeholder (text:null)");
  assert(JSON.stringify(ne.recipients) === JSON.stringify([${JSON.stringify(ADDR)}, ${JSON.stringify(CAROL)}]),
         "privateTwo: recipients must resolve even though the body is sealed: " + JSON.stringify(ne.recipients));
  console.log("PASS E: private 2-recipient note (72B wraps + sealed body) — placeholder text, recipients resolve");

  // --- F: single-recipient regression, FLAG_MULTI clear ---
  const f = await scanAddress("stub:singleRegression", ${JSON.stringify(ADDR)});
  const nf = f.notes[0];
  assert(nf.multi === false, "singleRegression: multi must be false");
  assert(Array.isArray(nf.recipients) && nf.recipients.length === 0,
         "singleRegression: recipients must be empty for a non-multi note: " + JSON.stringify(nf.recipients));
  assert(!nf.received && nf.directed && nf.to === ${JSON.stringify(CAROL)},
         "singleRegression: legacy 'to' field must still populate exactly as before: " + JSON.stringify(nf));
  assert(nf.text === "dear carol", "singleRegression: bad text: " + JSON.stringify(nf.text));
  console.log("PASS F: single-recipient directed note (FLAG_MULTI clear) decodes byte-identical to before");

  console.log("MULTI-DECODE UNIT TESTS PASSED");
})().catch((e) => { console.error("FAIL " + e.message); process.exit(1); });
`, ctx);
