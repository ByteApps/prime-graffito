#!/usr/bin/env node
// Cross-language byte-parity test for the PNTE v1 envelope decoder
// (PLAN-pnte-redesign.md) shipped in companion/chain-scan.js.
//
// Every vector below is copied VERBATIM (byte-for-byte, not
// re-derived/re-implemented) from the Rust reference implementation's own
// test suite:
//   - notes-core/src/envelope.rs's module doc comment (`PNTE100 ` = the
//     exact 8-byte common-case header).
//   - notes-core/tests/roundtrip.rs::envelope_rejects_bad_shapes (every
//     negative/foreign-data case: wrong magic, too short, wrong version,
//     non-hex flags, missing separator, the reserved FLAG_CONT bit, an
//     unassigned bit, FLAG_MULTI without FLAG_DIRECTED, an empty payload
//     list).
//   - notes-core/tests/multi_recipient.rs::decode_liberal_count_one_accepted
//     (flags=FLAG_DIRECTED|FLAG_MULTI=0x06, count=1 -> header
//     "PNTE10601 ", exactly matching envelope::encode_outputs's own
//     output for that input).
//
// This proves the JS decoder agrees with envelope.rs's parse_header/
// decode_note byte-for-byte on real Rust-produced/Rust-tested bytes, not
// merely "the same logic re-implemented in two languages".
//
// No network, no browser: chain-scan.js runs in a vm context, same harness
// as tests/test_chain_scan.js.  Run: node tests/test_envelope_v1.js
"use strict";
const vm = require("vm");
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "chain-scan.js"), "utf8");

const ctx = { TextDecoder, console, process };
vm.createContext(ctx);
vm.runInContext(src, ctx);

const assert = (cond, msg) => { if (!cond) throw new Error("FAIL " + msg); };
// decodeNote takes an ARRAY of Uint8Array payloads (one per OP_RETURN
// output of the tx, vout order) — this single-payload helper exercises the
// common one-output case every Rust vector below describes. "binary"
// (latin1) keeps every JS string char code as exactly one byte — the "₿"
// vector below is written as raw \xNN UTF-8 byte escapes for that reason.
ctx.decodeNote_ = (s) => vm.runInContext("decodeNote", ctx)([Uint8Array.from(Buffer.from(s, "binary"))]);

// --- 1. Positive: envelope.rs's own doc-comment example, "PNTE100 " ------
// (module doc: "Common case is exactly 8 bytes: `PNTE100 `.")
{
  const d = ctx.decodeNote_("PNTE100 hola \xe2\x82\xbf"); // "hola ₿" utf-8
  assert(d !== null, "PNTE100 header must decode");
  assert(d.flags === 0, "flags must be 0, got " + d.flags);
  assert(d.multiCount === null, "multiCount must be null for a non-multi header");
  const text = Buffer.from(d.body).toString("utf8");
  assert(text === "hola ₿", "body must be the bytes after the 8-byte header, got " + JSON.stringify(text));
  console.log("PASS PNTE100 (envelope.rs doc-comment example) decodes flags=0, body verbatim");
}

// --- 2. Positive: multi_recipient.rs::decode_liberal_count_one_accepted --
// flags=FLAG_DIRECTED|FLAG_MULTI=0x06, count=1 -> header "PNTE10601 ",
// exactly what envelope::encode_outputs(0x06, Some(1), body, 100_000)
// produces for that Rust test's input.
{
  const d = ctx.decodeNote_("PNTE10601 solo via multi flag");
  assert(d !== null, "PNTE10601 header must decode");
  assert(d.flags === 0x06, "flags must be 0x06 (DIRECTED|MULTI), got " + d.flags);
  assert(d.multiCount === 1, "multiCount must be 1, got " + d.multiCount);
  const text = Buffer.from(d.body).toString("utf8");
  assert(text === "solo via multi flag", "body mismatch: " + JSON.stringify(text));
  console.log("PASS PNTE10601 (multi_recipient.rs decode_liberal_count_one_accepted) matches Rust vector");
}

// --- 3. Negative vectors, VERBATIM from roundtrip.rs::envelope_rejects_bad_shapes ---
const negatives = [
  ["nonsense-not-pnte", "wrong magic"],
  ["PNTE", "too short"],
  ["PNTE2 hi", "wrong version"],
  ["PNTE1zz hi", "non-hex flags"],
  ["PNTE100hi", "missing separator"],
  ["PNTE108 1/1 hi", "reserved FLAG_CONT bit (0x08) set"],
  ["PNTE110 hi", "FLAG_PW (0x10) without FLAG_PRIVATE"],
  ["PNTE120 hi", "FLAG_MLKEM (0x20) without FLAG_PRIVATE"],
  ["PNTE140 hi", "unassigned bit (0x40) set"],
  // Rust's literal vector for this case is labeled "FLAG_MULTI without
  // FLAG_DIRECTED" in roundtrip.rs, but byte-for-byte it's ALSO a wrong
  // version (payload[4] is '0', not the VERSION byte '1') — copied
  // verbatim regardless, since the assertion (undecodable) holds either
  // way; the MULTI-without-DIRECTED rule specifically is isolated below.
  ["PNTE0401 hi", "wrong version (roundtrip.rs's own FLAG_MULTI-without-FLAG_DIRECTED vector)"],
];
for (const [s, why] of negatives) {
  const d = ctx.decodeNote_(s);
  assert(d === null, `${JSON.stringify(s)} (${why}) must be undecodable, got ${JSON.stringify(d)}`);
}
console.log("PASS all roundtrip.rs::envelope_rejects_bad_shapes negative vectors agree (undecodable)");

// FLAG_MULTI without FLAG_DIRECTED, isolated: version correct, flags =
// FLAG_MULTI (0x04) alone — exercises envelope.rs's specific rejection
// rule directly (parse_header checks flags semantics only after magic +
// version already matched, so the vector just above never reaches it).
{
  const d = ctx.decodeNote_("PNTE104 hi");
  assert(d === null, "FLAG_MULTI (0x04) without FLAG_DIRECTED must be undecodable");
  console.log("PASS FLAG_MULTI without FLAG_DIRECTED is undecodable (envelope.rs parse_header rule)");
}

// Self-pq extension (PLAN-graffito-self-pw.md, 2026-08-22): pq bits are
// valid with FLAG_PRIVATE alone — the viewer must DECODE these (rendering
// the ordinary private placeholder), not drop them as foreign. Mirrors
// envelope.rs validate_pq + tests/pq.rs's decode vectors.
{
  for (const [hex, flags, why] of [
    ["11", 0x11, "self-pw (PW|PRIVATE)"],
    ["21", 0x21, "self-kem (MLKEM|PRIVATE)"],
    ["31", 0x31, "self both layers"],
    ["13", 0x13, "directed pw"],
    ["23", 0x23, "directed kem"],
  ]) {
    const d = ctx.decodeNote_(`PNTE1${hex} hi`);
    assert(d !== null && d.flags === flags, `${why} (0x${hex}) must decode`);
  }
  const bad = ctx.decodeNote_("PNTE11702 hi"); // PW|MULTI|DIRECTED|PRIVATE
  assert(bad === null, "pq with FLAG_MULTI must stay undecodable");
  console.log("PASS pq flag validity matches envelope.rs (self + directed forms, MULTI excluded)");
}

// Empty payload list.
{
  const d = vm.runInContext("decodeNote([])", ctx);
  assert(d === null, "an empty payload list must be undecodable");
  console.log("PASS empty payload list is undecodable");
}

// --- 4. Intra-tx multi-output concatenation: later OP_RETURN outputs of
// the SAME tx carry ZERO header bytes and just concatenate (envelope.rs
// module doc: "Every LATER OP_RETURN output of the SAME tx is raw body
// bytes, no header, no marker"). Round-trips the `PNTE100 ` header split
// across two payloads.
{
  const p1 = Uint8Array.from(Buffer.from("PNTE100 hello ", "binary"));
  const p2 = Uint8Array.from(Buffer.from("world", "binary"));
  ctx.__p1 = p1; ctx.__p2 = p2;
  const d = vm.runInContext("decodeNote([__p1, __p2])", ctx);
  assert(d !== null, "two-output note must decode");
  assert(d.flags === 0, "flags must be 0");
  const text = Buffer.from(d.body).toString("utf8");
  assert(text === "hello world", "concatenated body mismatch: " + JSON.stringify(text));
  console.log("PASS later OP_RETURN outputs concatenate as raw body bytes (no header)");
}

console.log("ENVELOPE V1 CROSS-LANGUAGE BYTE-PARITY TESTS PASSED");
