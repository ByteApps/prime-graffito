// Shared chain-scanning core for viewer.html and note.html: esplora fetch
// + pagination, the JS port of the FROZEN PNTE envelope
// (notes-core/src/envelope.rs, PLAN-pnte-redesign.md), and the note-card
// renderer.
//
// PLAN-pnte-redesign.md (2026-08-11): one note = one transaction. The note
// id IS the txid — no separate note_id, no cross-tx chunk reassembly. All
// OP_RETURN outputs of a tx, in vout order, concatenate into the note body;
// the ASCII-armored header appears ONLY in the first OP_RETURN output.
//
// Note text is arbitrary attacker-writable chain data — every renderer
// here builds DOM via textContent, never innerHTML.
"use strict";

const API = {
  mainnet:  { base: "https://mempool.space/api",          explorer: "https://mempool.space" },
  testnet4: { base: "https://mempool.space/testnet4/api", explorer: "https://mempool.space/testnet4" },
  signet:   { base: "https://mempool.space/signet/api",   explorer: "https://mempool.space/signet" },
  regtest:  { base: "/regtest/api",                       explorer: null },
};

// flags bit 0: 1 = private (AEAD blob), 0 = public (plaintext UTF-8).
const FLAG_PRIVATE = 0x01;
// flags bit 1: 1 = directed (dust output to another taproot address).
const FLAG_DIRECTED = 0x02;
// flags bit 2: multi-recipient directed note (2..=255 recipients), valid
// only together with FLAG_DIRECTED. The recipient count lives in the
// header (2 ASCII hex chars, `01`..`ff`) — NOT a body byte anymore. Body
// framing:
//   public  (FLAG_PRIVATE clear): the UTF-8 text, verbatim (no count byte)
//   private (FLAG_PRIVATE set):   count × wrap(72B) || sealed_body
// The browser has no decryption key for the wraps/sealed_body — a private
// multi note renders the same encrypted placeholder as any other private
// note.
const FLAG_MULTI = 0x04;
// flags bit 3: RESERVED for continuation (chained notes spanning several
// transactions). Never emitted; a header with this bit set is undecodable
// today (forward-compat guard — see envelope.rs).
const FLAG_CONT = 0x08;
// flags bits 4-5: post-quantum sealing layers (notes-core/src/pq.rs) — an
// Argon2id password layer (FLAG_PW) and/or an ML-KEM layer (FLAG_MLKEM),
// on a PRIVATE note, directed or (since 2026-08-22, the self-pq
// extension) not. The browser can never decrypt any private body, so a
// pq note renders the same encrypted placeholder as any other private
// note — these bits only need to be DECODABLE here, or the viewer would
// drop pq notes as foreign data instead of showing the placeholder.
const FLAG_PW = 0x10;
const FLAG_MLKEM = 0x20;
// Every flag bit this decoder understands — any other set bit (6-7, or
// FLAG_CONT until it ships) makes the header undecodable.
const KNOWN_FLAGS = FLAG_PRIVATE | FLAG_DIRECTED | FLAG_MULTI | FLAG_PW | FLAG_MLKEM;

const P2TR_RE = /^(bc|tb|bcrt)1p/;

const shortAddr = (a) => (a && a.length > 17 ? `${a.slice(0, 8)}…${a.slice(-6)}` : a || "unknown");
// A note id is a full txid (64 hex chars) — truncate for display the same
// way the old fixed-8-hex note id used to render.
const shortId = (id) => (id && id.length > 8 ? id.slice(0, 8) : id || "");

const hexToBytes = (h) => Uint8Array.from(h.match(/../g) || [], (b) => parseInt(b, 16));

async function esploraText(base, path, opts) {
  const resp = await fetch(base + path, opts);
  const text = await resp.text();
  if (!resp.ok) throw new Error(text || resp.statusText);
  return text;
}
const esploraJson = async (base, path) => JSON.parse(await esploraText(base, path));

// scriptPubKey hex → pushed payload hex (single canonical push), or null.
function opReturnPayload(spkHex) {
  const b = spkHex.toLowerCase();
  if (!b.startsWith("6a")) return null;
  let rest = b.slice(2);
  const op = parseInt(rest.slice(0, 2), 16);
  let len, data;
  if (op >= 1 && op <= 75)      { len = op; data = rest.slice(2); }
  else if (op === 0x4c)         { len = parseInt(rest.slice(2, 4), 16); data = rest.slice(4); }
  else if (op === 0x4d)         { len = parseInt(rest.slice(4, 6) + rest.slice(2, 4), 16); data = rest.slice(6); }
  else return null;
  return data.length === len * 2 ? data : null;
}

async function fullHistory(base, address, onPage) {
  // First page: /txs = up to 50 mempool + first 25 confirmed.
  const txs = await esploraJson(base, `/address/${address}/txs`);
  let confirmed = txs.filter((t) => t.status.confirmed);
  let last = confirmed.length ? confirmed[confirmed.length - 1].txid : null;
  // Paginate the confirmed chain until a short page.
  while (last) {
    const page = await esploraJson(base, `/address/${address}/txs/chain?after_txid=${last}`);
    if (!page.length) break;
    txs.push(...page);
    if (onPage) onPage(page.length);
    last = page.length >= 25 ? page[page.length - 1].txid : null;
  }
  const seen = new Set();
  return txs.filter((t) => !seen.has(t.txid) && seen.add(t.txid));
}

// --------------------------------------------------------------- envelope
// Lowercase-hex-only nibble decode (the encoder never emits uppercase, so
// this decoder — deliberately strict here — treats uppercase as foreign,
// same as any other non-matching byte). Mirrors envelope.rs::hex_nibble.
function hexNibble(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;       // '0'-'9'
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;  // 'a'-'f'
  return null;
}
function hexByte(hi, lo) {
  const h = hexNibble(hi);
  const l = hexNibble(lo);
  return h === null || l === null ? null : (h << 4) | l;
}

// Fixed length of the first output's header EXCLUDING the optional
// multi-recipient count field: "PNTE" (4) + version (1) + flags (2) +
// separator (1) = 8 bytes. Mirrors envelope.rs::HEADER_FIXED_LEN.
const HEADER_FIXED_LEN = 8;
const MULTI_COUNT_LEN = 2;

// Parse the FIRST OP_RETURN output's PNTE header (a Uint8Array). Returns
// {flags, multiCount, offset} or null — foreign data: wrong magic/version,
// non-hex flag chars, an unassigned or reserved (FLAG_CONT) flag bit set,
// FLAG_MULTI without FLAG_DIRECTED, a zero/bad-hex multi count, or a
// missing separator. Liberal decoding, mirrors envelope.rs::parse_header
// byte-for-byte.
function parseHeader(payload) {
  if (payload.length < HEADER_FIXED_LEN) return null;
  // "PNTE"
  if (payload[0] !== 0x50 || payload[1] !== 0x4e || payload[2] !== 0x54 || payload[3] !== 0x45) return null;
  if (payload[4] !== 0x31) return null; // '1' version byte
  const flags = hexByte(payload[5], payload[6]);
  if (flags === null) return null;
  if (flags & FLAG_CONT) return null; // reserved, never decodable today
  if (flags & ~KNOWN_FLAGS) return null; // unassigned bits
  const multi = (flags & FLAG_MULTI) !== 0;
  if (multi && (flags & FLAG_DIRECTED) === 0) return null;
  // pq bits require FLAG_PRIVATE and exclude FLAG_MULTI (envelope.rs
  // validate_pq — DIRECTED is optional since the self-pq extension).
  if (flags & (FLAG_PW | FLAG_MLKEM)) {
    if ((flags & FLAG_PRIVATE) === 0) return null;
    if (multi) return null;
  }
  let idx = 7;
  let multiCount = null;
  if (multi) {
    if (payload.length < idx + MULTI_COUNT_LEN) return null;
    const c = hexByte(payload[idx], payload[idx + 1]);
    if (c === null) return null;
    idx += MULTI_COUNT_LEN;
    if (c === 0) return null;
    multiCount = c;
  }
  if (payload[idx] !== 0x20) return null; // ' ' separator
  idx += 1;
  return { flags, multiCount, offset: idx };
}

// Decode a full note body from all OP_RETURN payloads of ONE transaction
// (Uint8Array[]), in vout order. `null` = the first output isn't a valid
// PNTE header — foreign data, silently ignored; the whole tx is either one
// note or nothing at all, since header presence is checked ONLY on the
// first output. Mirrors envelope.rs::decode_note.
function decodeNote(payloads) {
  if (!payloads.length) return null;
  const first = payloads[0];
  const h = parseHeader(first);
  if (!h) return null;
  let total = first.length - h.offset;
  for (let i = 1; i < payloads.length; i++) total += payloads[i].length;
  const body = new Uint8Array(total);
  let off = 0;
  const firstPiece = first.subarray(h.offset);
  body.set(firstPiece, off);
  off += firstPiece.length;
  for (let i = 1; i < payloads.length; i++) {
    body.set(payloads[i], off);
    off += payloads[i].length;
  }
  return { flags: h.flags, multiCount: h.multiCount, body };
}

// ----------------------------------------------------------------- scan
// Classify + decode a single tx into (at most) one note. `mine` is the set
// of "my" addresses (self-spk-SET ownership rule, funding-unification);
// `notebookSet` (or null) drives the DISPLAY-OWNER dedup rule below.
// Returns { accepted: "own"|"received"|null, note, dedupSkip }.
// `accepted` mirrors notes-core's is_own/received split — set even when
// the note itself fails to decode, so scanAddress's noteTxs/receivedTxs
// counters match a tx's origin, not just successfully-decoded notes.
function noteFromTx(t, address, mine, notebookSet) {
  const payloads = t.vout
    .filter((o) => o.scriptpubkey_type === "op_return")
    .map((o) => opReturnPayload(o.scriptpubkey))
    .filter(Boolean);
  if (!payloads.length) return { accepted: null, note: null };

  const spendsFromSelf = t.vin.some(
    (i) => i.prevout && mine.has(i.prevout.scriptpubkey_address)
  );
  const paysSelf = t.vout.some((o) => o.scriptpubkey_address === address);

  let received, from = null, to = null;
  if (spendsFromSelf) {
    received = false;
    const outs = t.vout.filter(
      (o) =>
        o.scriptpubkey_type !== "op_return" &&
        o.scriptpubkey_address &&
        o.scriptpubkey_address !== address
    );
    to = (outs.find((o) => P2TR_RE.test(o.scriptpubkey_address)) || outs[0])
      ?.scriptpubkey_address || null;
  } else if (paysSelf) {
    received = true;
    from =
      t.vin
        .map((i) => i.prevout && i.prevout.scriptpubkey_address)
        .find((a) => a && P2TR_RE.test(a)) || null;
  } else {
    return { accepted: null, note: null }; // neither from nor to us — pure spoof
  }
  const accepted = received ? "received" : "own";

  // DISPLAY-OWNER dedup (own notes only, mirrors notes-core's
  // tx_notebook_anchor / extract_notes_multi_deduped, 2026-07-18): keep
  // this note only if the FIRST input (in tx order) whose prevout address
  // is a notebook address is either absent (no notebook input at all) or
  // equal to `address` itself.
  if (!received && notebookSet) {
    const hit = t.vin.find((i) => i.prevout && notebookSet.has(i.prevout.scriptpubkey_address));
    const anchor = hit ? hit.prevout.scriptpubkey_address : null;
    if (anchor && anchor !== address) {
      return { accepted, note: null, dedupSkip: true };
    }
  }

  const bodies = payloads.map(hexToBytes);
  const decoded = decodeNote(bodies);
  if (!decoded) return { accepted, note: null };

  const flags = decoded.flags;
  const priv = (flags & FLAG_PRIVATE) !== 0;
  const directed = (flags & FLAG_DIRECTED) !== 0;
  const multi = (flags & FLAG_MULTI) !== 0;

  // Every NON-OP_RETURN output's address, ascending vout order — the
  // FLAG_MULTI recipient list is `outputAddrs[0..count]` (recipients
  // precede change by construction; mirrors notes-core's
  // OnchainTx.output_addrs). Not filtered against `address`: the spec is
  // "the first count non-OP_RETURN outputs", full stop.
  const outputAddrs = t.vout
    .filter((o) => o.scriptpubkey_type !== "op_return")
    .map((o) => o.scriptpubkey_address)
    .filter(Boolean);

  let recipients = [];
  let text = null;
  if (multi) {
    // multiCount is header-carried (never 0 — parseHeader already
    // rejected that) — recipients resolve regardless of whether the
    // private body's wraps are even long enough (mirrors notes-core:
    // wrap-truncation is a dm.rs/decrypt-layer concern, not envelope).
    recipients = outputAddrs.slice(0, decoded.multiCount);
    if (!priv) {
      try { text = new TextDecoder("utf-8", { fatal: true }).decode(decoded.body); }
      catch { text = null; }
    }
  } else if (!priv) {
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(decoded.body); }
    catch { text = null; }
  }

  const txHeight = t.status.confirmed ? t.status.block_height : null;
  const txTime = t.status.confirmed ? t.status.block_time : null;

  const note = {
    noteId: t.txid,
    private: priv,
    directed,
    multi,
    received,
    from: received ? from : null,
    to: received ? null : (directed && !multi ? to : null),
    recipients,
    bodyLen: decoded.body.length,
    text,
    txids: [t.txid],
    height: txHeight,
    blocktime: txTime,
  };
  return { accepted, note };
}

// Port of notes-core extract_notes/extract_notes_multi (bundle.rs),
// PLAN-pnte-redesign.md shape: one tx is at most one note (its id IS the
// txid), so there is no cross-tx bucketing to keep separate anymore.
//
// Acceptance: a tx that SPENDS FROM the notebook address, OR from any
// address in the optional `myAddresses` set (funding-unification PLAN,
// "Attribution & scanner changes" — e.g. a separate spending wallet),
// carries an OWN note (spoof resistance — anyone can send OP_RETURNs *to*
// an address, so those never count as yours); a tx that only PAYS the
// address and carries a valid PNTE header on its first OP_RETURN output is
// a RECEIVED note, attributed to its (unforgeable) taproot input address.
// `myAddresses` defaults to just [address], so every existing caller's
// behavior is byte-identical — this is a pure extension, never a
// narrowing, mirroring the Rust self-spk-SET rule exactly (OR, not
// replace).
//
// Optional `notebookAddresses` (5th arg): mirrors notes-core's
// `extract_notes_multi_deduped` DISPLAY-OWNER rule — see `noteFromTx`.
// Omitting `notebookAddresses` (undefined/empty, the default) disables
// dedup entirely — byte-identical to before, so every existing caller is
// unaffected.
// Returns { notes (newest-first), noteTxs, receivedTxs, txsScanned, foreign, nonPnte }.
async function scanAddress(base, address, onPage, myAddresses, notebookAddresses) {
  const mine = new Set([address, ...(myAddresses || [])]);
  const notebookSet = notebookAddresses && notebookAddresses.length
    ? new Set([address, ...notebookAddresses])
    : null;
  const txs = await fullHistory(base, address, onPage);

  const notes = [];
  let foreign = 0, nonPnte = 0, noteTxs = 0, receivedTxs = 0;
  for (const t of txs) {
    const r = noteFromTx(t, address, mine, notebookSet);
    if (!r.accepted) { foreign++; continue; }
    if (r.accepted === "own") noteTxs++; else receivedTxs++;
    if (r.dedupSkip) continue;
    if (!r.note) { nonPnte++; continue; }
    notes.push(r.note);
  }
  // Newest first: unconfirmed on top, then height descending.
  const sortKey = (n) => (n.height == null ? Number.MAX_SAFE_INTEGER : n.height);
  notes.sort((a, b) => sortKey(b) - sortKey(a));

  return { notes, noteTxs, receivedTxs, txsScanned: txs.length, foreign, nonPnte };
}

// Single-note lookup by txid (note.html): the note id IS the txid, so this
// fetches exactly one tx instead of scanning the whole address history.
// Returns the note, or null when the tx doesn't exist / isn't accepted at
// `address` / doesn't carry a valid PNTE header.
async function fetchNote(base, txid, address, myAddresses, notebookAddresses) {
  const t = await esploraJson(base, `/tx/${txid}`);
  const mine = new Set([address, ...(myAddresses || [])]);
  const notebookSet = notebookAddresses && notebookAddresses.length
    ? new Set([address, ...notebookAddresses])
    : null;
  const r = noteFromTx(t, address, mine, notebookSet);
  return r.note || null;
}

// One note → a .note card element. permalinkHref (optional) adds a
// right-aligned link to the single-note page.
function buildNoteCard(n, explorer, permalinkHref) {
  const card = document.createElement("div");
  card.className = "note";

  const head = document.createElement("div");
  head.className = "note-head";
  const id = document.createElement("span");
  id.textContent = `note ${shortId(n.noteId)}`;
  head.appendChild(id);
  const pill = (label) => {
    const s = document.createElement("span");
    s.className = "pill";
    s.textContent = label;
    head.appendChild(s);
  };
  pill(n.private ? "private" : "public");
  if (n.received) pill(`from ${shortAddr(n.from)}`);
  else if (n.multi && n.recipients.length) pill(`to ${n.recipients.length} recipients`);
  else if (n.directed && n.to) pill(`to ${shortAddr(n.to)}`);
  if (n.height == null) pill("unconfirmed");
  if (permalinkHref) {
    const a = document.createElement("a");
    a.className = "permalink";
    a.href = permalinkHref;
    a.textContent = "permalink";
    head.appendChild(a);
  }
  card.appendChild(head);

  // Full recipient list for an own multi-recipient note — the "to N
  // recipients" pill names the count, this line names them (consistent
  // with a single directed note's "to <addr>" pill, just plural).
  if (!n.received && n.multi && n.recipients.length) {
    const rec = document.createElement("div");
    rec.className = "note-meta";
    rec.textContent = "to: " + n.recipients.map(shortAddr).join(", ");
    card.appendChild(rec);
  }

  const body = document.createElement("div");
  body.className = "note-body";
  if (n.private) {
    body.classList.add("enc");
    body.textContent = n.directed
      ? "Encrypted (directed) — readable only on the sender's and recipient's devices."
      : "Encrypted (private) — readable only on the device.";
  } else if (n.text != null) {
    body.textContent = n.text;
  } else {
    body.classList.add("dim");
    body.textContent = `Public note but not valid UTF-8 (${n.bodyLen} bytes).`;
  }
  card.appendChild(body);

  const meta = document.createElement("div");
  meta.className = "note-meta";
  meta.textContent = n.height != null
    ? `height ${n.height} · ${new Date(n.blocktime * 1000).toLocaleString()} · `
    : "unconfirmed · ";
  n.txids.forEach((txid, i) => {
    if (i) meta.appendChild(document.createTextNode(", "));
    if (explorer) {
      const a = document.createElement("a");
      a.href = `${explorer}/tx/${txid}`;
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = txid;
      meta.appendChild(a);
    } else {
      const c = document.createElement("code");
      c.textContent = txid;
      meta.appendChild(c);
    }
  });
  card.appendChild(meta);
  return card;
}
