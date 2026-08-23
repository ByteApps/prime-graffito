//! The PNTE on-chain envelope (v1 redesign, 2026-08-11 —
//! `PLAN-pnte-redesign.md`): **one note = one transaction**, the note id
//! IS the txid, and chunk order is simply OP_RETURN vout order within that
//! one tx — no per-chunk binary header, no `note_id`/`seq`/`total`.
//!
//! The header is ASCII-armored and appears ONLY in the tx's FIRST
//! OP_RETURN output:
//!
//! ```text
//! bytes 0-3  "PNTE"                  (magic)
//! byte  4    '1' (0x31)              (version, printable ASCII)
//! bytes 5-6  flags as ASCII hex      '00'..'ff' (two lowercase chars)
//! [bytes 7-8 recipient count, 2 ASCII hex chars — present IFF FLAG_MULTI]
//! byte       ' ' (0x20)              (separator)
//! [then      i(decimal) '/' n(decimal) ' ' — present IFF FLAG_CONT;
//!            nothing emits this today, see FLAG_CONT below]
//! rest       body bytes
//! ```
//!
//! Common case is exactly 8 bytes: `PNTE100 `. Every LATER OP_RETURN
//! output of the SAME tx is raw body bytes, no header, no marker — vout
//! order is the grouping (our own composer builds the whole tx, so
//! nothing foreign can interleave a chunk).
//!
//! FROZEN FORMAT — every confirmed note is encoded this way forever; only
//! additive versioning (a new flag bit, or shipping FLAG_CONT) is allowed.
//! The decoder is LIBERAL: anything that doesn't parse as a valid header
//! is foreign data, silently ignored (`None`), never a panic or an `Err`.
//!
//! Additive (2026): bits 4-5, `FLAG_PW`/`FLAG_MLKEM` (notes-core/src/pq.rs)
//! — optional post-quantum sealing layers, hybrid on top of the existing
//! base key (dm.rs ECDH for a directed note; the notebook enc key for a
//! SELF-note — the 2026-08-22 self-pq extension, PLAN-graffito-self-pw.md),
//! never a replacement for it. Header ENCODING is unchanged (flags already
//! occupy a full byte); only the body FRAMING is new (extra prefix blocks
//! ahead of the sealed blob — see pq.rs). A header carrying either bit
//! without FLAG_PRIVATE, or together with FLAG_MULTI, is undecodable.

use crate::Error;

pub const MAGIC: [u8; 4] = *b"PNTE";
/// Version byte, printable ASCII '1' (0x31) — NOT the old binary 0x01.
pub const VERSION: u8 = b'1';

/// flags bit 0: 1 = private (AEAD blob), 0 = public (plaintext UTF-8).
pub const FLAG_PRIVATE: u8 = 0x01;
/// flags bit 1: 1 = directed (note addressed to another taproot address via
/// a dust output; private bodies sealed under the dm.rs ECDH key, not the
/// self enc_key).
pub const FLAG_DIRECTED: u8 = 0x02;
/// flags bit 2: 1 = multi-recipient directed note (2..=255 recipients).
/// Valid only together with FLAG_DIRECTED — the decoder rejects MULTI
/// without DIRECTED as undecodable. The recipient count that used to be a
/// binary body byte now lives in the header (2 ASCII hex chars,
/// `01`..`ff`). FROZEN body framing once this bit is set (see dm.rs for
/// the multi-recipient crypto that fills it in):
///   public  (FLAG_PRIVATE clear): the UTF-8 text, verbatim (no count byte)
///   private (FLAG_PRIVATE set):   `count × wrap(72B each) || sealed_body`
/// `count` is the number of recipients (the tx's recipient outputs,
/// `output_addrs[0..count]`, precede change by construction).
pub const FLAG_MULTI: u8 = 0x04;
/// flags bit 3: RESERVED for continuation (chained notes spanning several
/// transactions — see PLAN-pnte-redesign.md). Never emitted by anything in
/// this crate today; decoding a header with this bit set always yields
/// `None` (liberal/forward-compat: a decoder that doesn't understand
/// chaining must never render a fragment as if it were a whole note).
pub const FLAG_CONT: u8 = 0x08;
/// flags bit 4: post-quantum password layer (notes-core/src/pq.rs) — an
/// Argon2id-stretched password, hybrid ON TOP of the note's base key
/// (dm.rs ECDH when DIRECTED; the notebook enc key on a SELF-note —
/// PLAN-graffito-self-pw.md), never a replacement for it. Requires
/// `FLAG_PRIVATE` (DIRECTED optional since 2026-08-22) and is INVALID
/// with `FLAG_MULTI` — a violating header is undecodable (`None`). May
/// combine with `FLAG_MLKEM`.
pub const FLAG_PW: u8 = 0x10;
/// flags bit 5: post-quantum ML-KEM layer (notes-core/src/pq.rs) — a
/// FIPS-203 key-encapsulation ciphertext, hybrid ON TOP of the note's
/// base key: addressed to the RECIPIENT's ek when DIRECTED, or (self-pq
/// extension) to a keypair of the AUTHOR's choosing on a SELF-note —
/// meaningful there only for a NON-seed-derived keypair, see pq.rs. Same
/// validity rule as `FLAG_PW`; may combine with it.
pub const FLAG_MLKEM: u8 = 0x20;

/// Every flag bit this decoder understands. Any OTHER set bit (6-7, or
/// FLAG_CONT until it ships) makes the header undecodable — the same
/// forward-compat guard as FLAG_CONT.
const KNOWN_FLAGS: u8 = FLAG_PRIVATE | FLAG_DIRECTED | FLAG_MULTI | FLAG_PW | FLAG_MLKEM;

/// Fixed length of the first output's header EXCLUDING the optional
/// multi-recipient count field: `PNTE` (4) + version (1) + flags (2) +
/// separator (1) = 8 bytes total once the (absent) count is accounted for
/// — see [`header_len`].
const HEADER_FIXED_LEN: usize = MAGIC.len() + 1 + 2 + 1;
/// Length of the multi-recipient count field (2 ASCII hex chars).
const MULTI_COUNT_LEN: usize = 2;

/// Total header length for the first OP_RETURN output. `PNTE100 ` (no
/// FLAG_MULTI) is exactly 8 bytes; a multi-recipient note's header is 10
/// bytes (`PNTE10403 `-shaped: 2 extra hex chars for the count).
pub fn header_len(multi: bool) -> usize {
    HEADER_FIXED_LEN + if multi { MULTI_COUNT_LEN } else { 0 }
}

fn hex_digit(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn hex_byte_chars(b: u8) -> [u8; 2] {
    [hex_digit(b >> 4), hex_digit(b & 0x0f)]
}

/// Lowercase-hex-only nibble decode (the encoder never emits uppercase, so
/// this decoder — deliberately strict here — treats uppercase as foreign,
/// same as any other non-matching byte).
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
    Some((hex_nibble(hi)? << 4) | hex_nibble(lo)?)
}

fn build_header(flags: u8, multi_count: Option<u8>) -> Vec<u8> {
    let mut h = Vec::with_capacity(header_len(multi_count.is_some()));
    h.extend_from_slice(&MAGIC);
    h.push(VERSION);
    h.extend_from_slice(&hex_byte_chars(flags));
    if let Some(c) = multi_count {
        h.extend_from_slice(&hex_byte_chars(c));
    }
    h.push(b' ');
    h
}

/// `flags`/`multi_count` internal consistency: FLAG_MULTI requires a
/// nonzero count and vice versa.
fn validate_multi(flags: u8, multi_count: Option<u8>) -> Result<(), Error> {
    let wants_multi = flags & FLAG_MULTI != 0;
    match (wants_multi, multi_count) {
        (true, None) | (true, Some(0)) => {
            Err(Error::Envelope("FLAG_MULTI requires a nonzero recipient count"))
        }
        (false, Some(_)) => Err(Error::Envelope("recipient count given without FLAG_MULTI")),
        _ => Ok(()),
    }
}

/// `flags`'s pq bits (`FLAG_PW`/`FLAG_MLKEM`) validity, and both are
/// invalid together with `FLAG_MULTI` (no multi-recipient pq support —
/// notes-core/src/pq.rs):
///
/// Both bits require `FLAG_PRIVATE`, with OR without `FLAG_DIRECTED`
/// (2026-08-22, PLAN-graffito-self-pw.md — the ADDITIVE extension the
/// frozen format permits): the directed forms are the original pq
/// layers; `PW|PRIVATE` / `MLKEM|PRIVATE` without DIRECTED are
/// pq-layered SELF-notes (pq.rs `seal_self_pq`/`unlock_self` — including
/// the seed-derived-ek warning that makes a self-KEM meaningful ONLY for
/// a non-seed-derived keypair). Decoders older than this rule treat the
/// self combinations as undecodable and skip them silently — graceful,
/// by design.
fn validate_pq(flags: u8) -> Result<(), Error> {
    if flags & (FLAG_PW | FLAG_MLKEM) == 0 {
        return Ok(());
    }
    if flags & FLAG_PRIVATE == 0 {
        return Err(Error::Envelope("FLAG_PW/FLAG_MLKEM require FLAG_PRIVATE"));
    }
    if flags & FLAG_MULTI != 0 {
        return Err(Error::Envelope("FLAG_PW/FLAG_MLKEM are incompatible with FLAG_MULTI"));
    }
    Ok(())
}

/// Output lengths [`encode_outputs`] would produce for a body of `body_len`
/// bytes — pure arithmetic, no actual body bytes needed. Used by the
/// cost estimator (no crypto/body available yet) and by directed-private
/// compose, which must pick its inputs — and therefore know the tx's first
/// input's outpoint, which the AAD binds (dm.rs) — BEFORE the body can be
/// sealed. An AEAD's ciphertext length never depends on its AAD, so coin
/// selection only ever needs lengths, not real bytes.
pub fn payload_lens_for(
    flags: u8,
    multi_count: Option<u8>,
    body_len: usize,
    max_payload: usize,
) -> Result<Vec<usize>, Error> {
    validate_multi(flags, multi_count)?;
    validate_pq(flags)?;
    if body_len == 0 {
        return Err(Error::Envelope("empty body"));
    }
    let hlen = header_len(multi_count.is_some());
    if max_payload <= hlen {
        return Err(Error::Envelope("max_payload smaller than header"));
    }
    let first_room = max_payload - hlen;
    let mut lens = Vec::new();
    if body_len <= first_room {
        lens.push(hlen + body_len);
    } else {
        lens.push(max_payload);
        let remaining = body_len - first_room;
        let full = remaining / max_payload;
        let tail = remaining % max_payload;
        for _ in 0..full {
            lens.push(max_payload);
        }
        if tail > 0 {
            lens.push(tail);
        }
    }
    if lens.len() > u8::MAX as usize {
        return Err(Error::PayloadTooLarge);
    }
    Ok(lens)
}

/// Split `body` (already-sealed blob for private notes, UTF-8 for public)
/// into enveloped OP_RETURN payloads of at most `max_payload` bytes each.
/// The header lands ONLY in the first payload; every later payload is raw
/// body bytes. `multi_count` must be `Some` iff `flags & FLAG_MULTI != 0`.
pub fn encode_outputs(
    flags: u8,
    multi_count: Option<u8>,
    body: &[u8],
    max_payload: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    let lens = payload_lens_for(flags, multi_count, body.len(), max_payload)?;
    let header = build_header(flags, multi_count);
    let mut out = Vec::with_capacity(lens.len());
    let mut rest = body;
    for (i, &len) in lens.iter().enumerate() {
        if i == 0 {
            let piece_len = len - header.len();
            let (piece, r) = rest.split_at(piece_len);
            let mut payload = Vec::with_capacity(len);
            payload.extend_from_slice(&header);
            payload.extend_from_slice(piece);
            out.push(payload);
            rest = r;
        } else {
            let (piece, r) = rest.split_at(len);
            out.push(piece.to_vec());
            rest = r;
        }
    }
    Ok(out)
}

/// A decoded note: the flags/count from the first output's header, and the
/// full concatenated body across every OP_RETURN output of the tx.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub flags: u8,
    /// Recipient count from the header, only when FLAG_MULTI is set.
    pub multi_count: Option<u8>,
    pub body: Vec<u8>,
}

impl Decoded {
    pub fn is_private(&self) -> bool {
        self.flags & FLAG_PRIVATE != 0
    }
    pub fn is_directed(&self) -> bool {
        self.flags & FLAG_DIRECTED != 0
    }
    pub fn is_multi(&self) -> bool {
        self.flags & FLAG_MULTI != 0
    }
}

/// Parse the FIRST OP_RETURN output's PNTE header. Returns
/// `(flags, multi_count, body_offset)` — `body_offset` is where this
/// output's own body bytes start. `None` = foreign data: wrong
/// magic/version, non-hex flag chars, an unassigned or reserved
/// (FLAG_CONT) flag bit set, FLAG_MULTI without FLAG_DIRECTED, a
/// zero/bad-hex multi count, or a missing separator — liberal decoding,
/// never a panic.
pub fn parse_header(payload: &[u8]) -> Option<(u8, Option<u8>, usize)> {
    if payload.len() < HEADER_FIXED_LEN || payload[..MAGIC.len()] != MAGIC {
        return None;
    }
    if payload[MAGIC.len()] != VERSION {
        return None;
    }
    let flags = hex_byte(payload[5], payload[6])?;
    if flags & FLAG_CONT != 0 {
        return None; // reserved, never decodable today
    }
    if flags & !KNOWN_FLAGS != 0 {
        return None; // unassigned bits
    }
    let multi = flags & FLAG_MULTI != 0;
    if multi && flags & FLAG_DIRECTED == 0 {
        return None;
    }
    if validate_pq(flags).is_err() {
        return None;
    }
    let mut idx = 7;
    let multi_count = if multi {
        if payload.len() < idx + MULTI_COUNT_LEN {
            return None;
        }
        let c = hex_byte(payload[idx], payload[idx + 1])?;
        idx += MULTI_COUNT_LEN;
        if c == 0 {
            return None;
        }
        Some(c)
    } else {
        None
    };
    if payload.get(idx) != Some(&b' ') {
        return None;
    }
    idx += 1;
    Some((flags, multi_count, idx))
}

/// Decode a full note body from all OP_RETURN payloads of ONE transaction,
/// in vout order (already filtered to just the OP_RETURN outputs).
/// `None` = the first output isn't a valid PNTE header — foreign data,
/// silently ignored by the scanner; the whole tx is either one note or
/// nothing at all, since header presence is checked ONLY on the first
/// output.
pub fn decode_note(payloads: &[Vec<u8>]) -> Option<Decoded> {
    let first = payloads.first()?;
    let (flags, multi_count, offset) = parse_header(first)?;
    let mut body =
        Vec::with_capacity(first.len() - offset + payloads[1..].iter().map(Vec::len).sum::<usize>());
    body.extend_from_slice(&first[offset..]);
    for p in &payloads[1..] {
        body.extend_from_slice(p);
    }
    Some(Decoded { flags, multi_count, body })
}
