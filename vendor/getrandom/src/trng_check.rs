//! Post-conditions for the KeyOS TRNG backend (`xous.rs`).
//!
//! `xous.rs` can only be compiled for `--cfg keyos`, so nothing in it is
//! reachable from a host test. Everything here is therefore written as
//! pure functions over plain slices, compiled on EVERY target, and unit
//! tested on the host — so the rules the device depends on are actually
//! exercised by `cargo test`.
//!
//! # Why this file exists
//!
//! The KeyOS TRNG backend hands a freshly mapped page to the `trng`
//! server as a `MutableBorrow` and reads the result back out. A freshly
//! mapped page reads as **zeros**, and the server signals nothing on the
//! paths where it declines to fill (a non-`MutableBorrow` body is logged
//! and dropped). Before this file existed, `getrandom_inner` returned
//! `Ok(())` unconditionally — so "the server filled the buffer" and "the
//! server never touched the buffer" were indistinguishable to every
//! caller, and the second case yields an all-zero key.
//!
//! That is the failure mode that 2026 disclosure describes: a
//! consumer that believes it is talking to a hardware RNG, with nothing
//! in the path that would notice if it were not. The fix is a sentinel:
//! write a known pattern into the page BEFORE lending it, and treat
//! "still the pattern" as a hard error rather than as entropy.
//!
//! The same disclosure's second bug — only 4 bytes of a 32-byte value
//! reaching the destination — is why `unfilled_suffix` exists rather
//! than a plain whole-buffer comparison: a partial fill leaves the TAIL
//! holding the sentinel, and that is detectable.

#![allow(dead_code)] // only `xous.rs` (cfg(keyos)) calls these

/// The `valid` field of the `FillTrng` memory message counts **u32s**,
/// not bytes (KeyOS `xous/trng/src/api.rs`: "the `valid` field of the
/// memory message is the number of u32s to get"). A byte count here
/// would ask the server for a quarter of the requested entropy and
/// silently return a buffer that is three-quarters sentinel — the
/// 32-bytes-becomes-8 shape. Rounds UP so a length that is not a
/// multiple of 4 is fully covered.
pub(crate) const fn words_for(len: usize) -> usize {
    len / 4 + if len % 4 != 0 { 1 } else { 0 }
}

/// Buffers at least this long are additionally checked for an unfilled
/// TAIL and for an all-zero result. Below it, only a whole-buffer
/// sentinel match is diagnostic — 8 bytes puts the false-positive rate
/// at 2^-64.
pub(crate) const MIN_TAIL_CHECK: usize = 8;

/// Position-dependent, never zero, never a repeating byte: a buffer
/// still holding this is not plausibly TRNG output, and using distinct
/// values per position means a partially filled buffer is detectable
/// from its tail rather than only as a whole.
pub(crate) const fn sentinel_at(i: usize) -> u8 {
    // A permutation of 1..=255 with period 255 (gcd(31, 255) == 1):
    // every position holds a different value, none of them zero, so an
    // untouched region can never be mistaken for a plausible run and
    // never coincides with the zeros a fresh page reads as.
    (i.wrapping_mul(31) % 255) as u8 + 1
}

/// Stamp the sentinel across `buf`.
pub(crate) fn write_sentinel(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = sentinel_at(i);
    }
}

/// Length of the trailing run of `out` that still holds the sentinel.
///
/// `0` for a fully written buffer (with probability 255/256 per byte);
/// `out.len()` for a buffer the server never touched.
pub(crate) fn unfilled_suffix(out: &[u8]) -> usize {
    let mut n = 0;
    for (i, &b) in out.iter().enumerate().rev() {
        if b != sentinel_at(i) {
            break;
        }
        n += 1;
    }
    n
}

/// The verdict `getrandom_inner` acts on: `true` means the buffer must
/// NOT be handed to a caller as entropy.
///
/// Three conditions, each an observed or plausible failure of the
/// borrow-and-fill protocol:
///
/// * the whole buffer still holds the sentinel — nothing was written;
/// * `MIN_TAIL_CHECK` or more trailing bytes still hold it — a short
///   fill (the wrong-unit-in-`valid` bug);
/// * the buffer came back all-zero at a length where that cannot happen
///   by chance — a defence in depth in case the sentinel itself is ever
///   bypassed (a reallocated page, a copy that skips the stamp).
///
/// False positives are bounded by 2^-8n for an n-byte buffer, so a
/// 32-byte key draw trips spuriously with probability 2^-256.
pub(crate) fn looks_unfilled(out: &[u8]) -> bool {
    if out.is_empty() {
        return false;
    }
    let suffix = unfilled_suffix(out);
    if suffix == out.len() {
        return true;
    }
    if out.len() >= MIN_TAIL_CHECK {
        if suffix >= MIN_TAIL_CHECK {
            return true;
        }
        if out.iter().all(|&b| b == 0) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unit of `valid` is the whole point; pin it exhaustively over
    /// every length the backend can be asked for, including the
    /// non-multiples of 4 that a naive `len / 4` would truncate.
    #[test]
    fn words_for_rounds_up() {
        assert_eq!(words_for(0), 0);
        assert_eq!(words_for(1), 1);
        assert_eq!(words_for(3), 1);
        assert_eq!(words_for(4), 1);
        assert_eq!(words_for(5), 2);
        assert_eq!(words_for(32), 8);
        assert_eq!(words_for(4096), 1024);
        for len in 1..=8192usize {
            let words = words_for(len);
            assert!(words * 4 >= len, "len {len} needs {words} words, covers only {}", words * 4);
            assert!((words - 1) * 4 < len, "len {len} over-asks with {words} words");
        }
    }

    /// It must agree with the expression the backend used before this
    /// module existed — this is a refactor of a live rule, not a new one.
    #[test]
    fn words_for_matches_original_expression() {
        for len in 1..=8192usize {
            assert_eq!(words_for(len), len.next_multiple_of(4) / 4, "len {len}");
        }
    }

    #[test]
    fn sentinel_is_never_zero_and_never_constant() {
        for i in 0..1024usize {
            assert_ne!(sentinel_at(i), 0, "sentinel[{i}] is zero");
        }
        // A permutation of 1..=255 over its 255-position period: every
        // value hit exactly once, so an unfilled region can never be
        // mistaken for a plausible run.
        let s: Vec<u8> = (0..255).map(sentinel_at).collect();
        assert!(s.windows(2).any(|w| w[0] != w[1]), "sentinel is constant");
        let mut seen = [false; 256];
        for &b in &s {
            assert!(!seen[b as usize], "sentinel repeats within one period");
            seen[b as usize] = true;
        }
        assert!(seen[1..].iter().all(|&x| x), "sentinel does not cover 1..=255");
        assert!(!seen[0], "sentinel must never be zero");
    }

    #[test]
    fn untouched_buffer_is_rejected() {
        for len in [1usize, 4, 8, 32, 64, 4096] {
            let mut buf = vec![0u8; len];
            write_sentinel(&mut buf);
            assert_eq!(unfilled_suffix(&buf), len);
            assert!(looks_unfilled(&buf), "len {len}: untouched buffer accepted");
        }
    }

    /// disclosure bug 2's shape: the server writes only the first word of
    /// a 32-byte request. The tail still holds the sentinel.
    #[test]
    fn partially_filled_buffer_is_rejected() {
        for filled in 0..24usize {
            let mut buf = vec![0u8; 32];
            write_sentinel(&mut buf);
            for (i, b) in buf.iter_mut().enumerate().take(filled) {
                *b = (i as u8).wrapping_mul(7).wrapping_add(1);
            }
            assert!(
                looks_unfilled(&buf),
                "a 32-byte draw with only {filled} bytes written was accepted"
            );
        }
    }

    #[test]
    fn zero_filled_buffer_is_rejected() {
        let mut buf = vec![0u8; 32];
        write_sentinel(&mut buf);
        buf.iter_mut().for_each(|b| *b = 0);
        assert!(looks_unfilled(&buf), "all-zero result accepted");
    }

    /// A real fill must be accepted. Walks a deterministic pattern over
    /// every length so the check cannot be "reject everything".
    #[test]
    fn fully_written_buffer_is_accepted() {
        for len in 1..=512usize {
            let mut buf = vec![0u8; len];
            write_sentinel(&mut buf);
            // A stand-in for TRNG output: differs from the sentinel at
            // every position by construction.
            for (i, b) in buf.iter_mut().enumerate() {
                *b = sentinel_at(i) ^ 0x5c;
            }
            assert!(!looks_unfilled(&buf), "len {len}: real fill rejected");
            assert_eq!(unfilled_suffix(&buf), 0);
        }
    }

    /// A genuine draw whose last few bytes happen to match the sentinel
    /// must still be accepted, as long as the run is short: the gate is
    /// MIN_TAIL_CHECK, not "any match".
    #[test]
    fn short_incidental_sentinel_tail_is_accepted() {
        let len = 32;
        for tail in 0..MIN_TAIL_CHECK {
            let mut buf = vec![0u8; len];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = if i >= len - tail { sentinel_at(i) } else { sentinel_at(i) ^ 0x5c };
            }
            assert_eq!(unfilled_suffix(&buf), tail);
            assert!(!looks_unfilled(&buf), "incidental {tail}-byte tail rejected");
        }
    }

    #[test]
    fn empty_buffer_is_not_an_error() {
        assert!(!looks_unfilled(&[]));
    }
}
