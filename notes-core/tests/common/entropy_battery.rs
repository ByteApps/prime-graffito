//! Canonical entropy battery — shared VERBATIM across the workspace.
//!
//! Copied byte-identical into every repo that generates key material:
//!
//!   chain-notes-app/app-core/tests/entropy_battery.rs
//!   prime-chain-notes/notes-core/tests/entropy_battery.rs
//!   prime-paper-wallet/wallet-core/tests/entropy_battery.rs
//!   prime-pgp-keychain/pgp-core/tests/entropy_battery.rs
//!
//! **Do not fork it per repo.** A threshold that drifts in one copy is a
//! silently-weaker gate in that repo. Change it in one place and re-copy.
//!
//! # What this can and cannot prove
//!
//! Written after a 2026 public disclosure of an RNG failure in a shipped
//! hardware wallet's firmware,
//! whose two bugs are the two failure modes this file is built around:
//!
//! 1. **Predictable fallback** — the consumer believed it was calling a
//!    hardware RNG and was actually calling a deterministic PRNG.
//! 2. **32-bit reseed** — only 4 bytes of a 32-byte hash reached the
//!    reseed, so the *whole* generator had at most 2^32 states.
//!
//! Bug 2 IS statistically detectable, and `collision_freedom` detects it:
//! a generator with a state space of `S` produces a repeated 32-byte
//! output after roughly `sqrt(S)` draws, no matter how good its
//! whitening. Bug 1 is **not** detectable from a single stream — a
//! fixed-seed ChaCha8 is statistically perfect. The only detectors for it
//! are structural, and they live outside this file:
//!
//!   * the dependency-graph / backend contract tests per repo (which RNG
//!     did we actually link?), and
//!   * cross-boot independence on real hardware.
//!
//! `NEGATIVE CONTROLS` at the bottom exist so this battery can never be
//! silently green: each control is a broken source that MUST fail, and
//! the fixed-seed ChaCha8 control asserts the *limit* above — it passes
//! the statistics, and saying so out loud is the point.
//!
//! No dependencies beyond `std`, deliberately: every repo can host it.

#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt::Write as _;

/// Default stream size for the distribution checks: 256 KiB = 2^21 bits.
/// At this size a 6-sigma monobit gate trips on a ~0.2% bit bias.
pub const STREAM_BYTES: usize = 256 * 1024;

/// Draws for `collision_freedom`. 400k 32-byte draws yields ~18.6
/// expected collisions against a 2^32-state generator (P(miss) ~ 8e-9)
/// and 0 against a real source (birthday over 2^256).
pub const COLLISION_DRAWS: usize = 400_000;

/// Every z-scored check fails outside +/-6 sigma: ~2e-9 false positives
/// each, ~1.6e-8 over the whole battery. CI-flake-free by construction.
const Z_MAX: f64 = 6.0;

// ---------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------

#[derive(Debug)]
pub struct Check {
    pub name: &'static str,
    pub detail: String,
    pub passed: bool,
}

#[derive(Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, name: &'static str, passed: bool, detail: String) {
        self.checks.push(Check { name, detail, passed });
    }

    pub fn failed(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    pub fn passed(&self) -> bool {
        self.failed().is_empty()
    }

    /// Names of the checks that failed — what the negative controls assert
    /// on, so a control can prove it fails *for the right reason*.
    pub fn failed_names(&self) -> Vec<&'static str> {
        self.failed().iter().map(|c| c.name).collect()
    }

    pub fn summary(&self) -> String {
        let mut s = String::new();
        for c in &self.checks {
            let _ = writeln!(s, "  [{}] {:<22} {}", if c.passed { "ok" } else { "FAIL" }, c.name, c.detail);
        }
        s
    }

    /// Panic with the full report unless every check passed.
    #[track_caller]
    pub fn assert_ok(&self, what: &str) {
        assert!(
            self.passed(),
            "entropy battery FAILED for {what}:\n{}\n\
             A failure here means the source feeding key material is not \
             behaving like a CSPRNG. Do not weaken a threshold to make this \
             pass — find the source.",
            self.summary()
        );
    }
}

// ---------------------------------------------------------------------
// The battery
// ---------------------------------------------------------------------

/// Run every distribution check over one contiguous stream.
pub fn battery(bytes: &[u8]) -> Report {
    assert!(
        bytes.len() >= 64 * 1024,
        "battery needs >=64 KiB to have any power; got {} bytes",
        bytes.len()
    );
    let mut r = Report::default();
    not_degenerate(bytes, &mut r);
    monobit(bytes, &mut r);
    byte_chi_square(bytes, &mut r);
    bit_position_bias(bytes, &mut r);
    runs(bytes, &mut r);
    longest_run(bytes, &mut r);
    serial_correlation(bytes, &mut r);
    shannon_entropy(bytes, &mut r);
    min_entropy(bytes, &mut r);
    repeated_blocks(bytes, &mut r);
    r
}

/// Fill `STREAM_BYTES` from `src` (called in the same chunk size a real
/// caller would use) and run the battery over it.
pub fn battery_from(chunk: usize, mut src: impl FnMut(&mut [u8])) -> Report {
    let mut buf = vec![0u8; STREAM_BYTES];
    for c in buf.chunks_mut(chunk) {
        src(c);
    }
    battery(&buf)
}

/// Degenerate outputs: a stream that is all-zero, all-ones, or a single
/// repeated byte. Catches the "server never wrote the buffer" shape,
/// where a freshly mapped (zeroed) page is returned as success.
fn not_degenerate(b: &[u8], r: &mut Report) {
    let first = b[0];
    let constant = b.iter().all(|&x| x == first);
    r.push(
        "not_degenerate",
        !constant,
        if constant { format!("entire stream is 0x{first:02x}") } else { "varied".into() },
    );
}

/// NIST frequency (monobit) test as a z-score.
fn monobit(b: &[u8], r: &mut Report) {
    let ones: u64 = b.iter().map(|x| x.count_ones() as u64).sum();
    let n = (b.len() * 8) as f64;
    let z = (ones as f64 - n / 2.0) / (n.sqrt() / 2.0);
    r.push("monobit", z.abs() <= Z_MAX, format!("ones={ones} z={z:+.3}"));
}

/// Byte-value chi-square (255 df), normal-approximated for the tail.
fn byte_chi_square(b: &[u8], r: &mut Report) {
    let mut counts = [0u64; 256];
    for &x in b {
        counts[x as usize] += 1;
    }
    let expected = b.len() as f64 / 256.0;
    let chi2: f64 = counts.iter().map(|&c| { let d = c as f64 - expected; d * d / expected }).sum();
    let df = 255.0;
    let z = (chi2 - df) / (2.0 * df).sqrt();
    r.push("byte_chi_square", z.abs() <= Z_MAX, format!("chi2={chi2:.1} df=255 z={z:+.3}"));
}

/// Per-bit-position bias. Catches sources where only some bits vary —
/// e.g. a partial fill, a stuck bit, or a masked byte.
fn bit_position_bias(b: &[u8], r: &mut Report) {
    let n = b.len() as f64;
    let mut worst = 0.0f64;
    let mut worst_bit = 0usize;
    for bit in 0..8 {
        let ones = b.iter().filter(|&&x| x & (1 << bit) != 0).count() as f64;
        let z = (ones - n / 2.0) / (n.sqrt() / 2.0);
        if z.abs() > worst.abs() {
            worst = z;
            worst_bit = bit;
        }
    }
    r.push(
        "bit_position_bias",
        worst.abs() <= Z_MAX,
        format!("worst bit {worst_bit} z={worst:+.3}"),
    );
}

/// NIST runs test over the bit stream (alternation rate).
fn runs(b: &[u8], r: &mut Report) {
    let bits: Vec<u8> = b.iter().flat_map(|&x| (0..8).rev().map(move |i| (x >> i) & 1)).collect();
    let n = bits.len() as f64;
    let ones = bits.iter().filter(|&&x| x == 1).count() as f64;
    let pi = ones / n;
    // The runs test is only meaningful once monobit is roughly satisfied;
    // a wildly biased stream is already caught above.
    let transitions = bits.windows(2).filter(|w| w[0] != w[1]).count() as f64;
    let v = transitions + 1.0;
    let expected = 2.0 * n * pi * (1.0 - pi);
    let sd = 2.0 * (n).sqrt() * pi * (1.0 - pi);
    let z = if sd > 0.0 { (v - expected) / sd } else { f64::INFINITY };
    r.push("runs", z.abs() <= Z_MAX, format!("runs={v} expected={expected:.1} z={z:+.3}"));
}

/// Longest run of identical bits. For 2^21 bits the expected maximum is
/// ~21; 60 is unreachable for a real source and trivially reached by a
/// zero-filled or constant region.
fn longest_run(b: &[u8], r: &mut Report) {
    const BOUND: u32 = 60;
    let mut best = 0u32;
    let mut cur = 0u32;
    let mut prev = 2u8;
    for &x in b {
        for i in (0..8).rev() {
            let bit = (x >> i) & 1;
            if bit == prev {
                cur += 1;
            } else {
                cur = 1;
                prev = bit;
            }
            best = best.max(cur);
        }
    }
    r.push("longest_run", best <= BOUND, format!("longest={best} bound={BOUND}"));
}

/// Lag-1 serial correlation over bytes. Catches counters and LCG-ish
/// structure that survives the frequency tests.
fn serial_correlation(b: &[u8], r: &mut Report) {
    let n = b.len();
    let mean = b.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
    let mut num = 0.0;
    let mut den = 0.0;
    for i in 0..n {
        let a = b[i] as f64 - mean;
        let c = b[(i + 1) % n] as f64 - mean;
        num += a * c;
        den += a * a;
    }
    let rho = if den > 0.0 { num / den } else { 1.0 };
    // sd ~ 1/sqrt(n); at 256 KiB that is ~0.002, so 0.02 is ~10 sigma.
    let bound = 10.0 / (n as f64).sqrt();
    r.push("serial_correlation", rho.abs() <= bound, format!("rho={rho:+.5} bound={bound:.5}"));
}

/// Shannon entropy per byte. A real source lands within ~0.001 of 8.
fn shannon_entropy(b: &[u8], r: &mut Report) {
    const FLOOR: f64 = 7.99;
    let mut counts = [0u64; 256];
    for &x in b {
        counts[x as usize] += 1;
    }
    let n = b.len() as f64;
    let h: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / n; -p * p.log2() })
        .sum();
    r.push("shannon_entropy", h >= FLOOR, format!("H={h:.4} bits/byte floor={FLOOR}"));
}

/// Most-common-value min-entropy (the NIST SP 800-90B "most common value"
/// estimator, without the confidence correction). Shannon entropy is
/// forgiving of a single over-represented value; min-entropy is not.
fn min_entropy(b: &[u8], r: &mut Report) {
    const FLOOR: f64 = 7.5;
    let mut counts = [0u64; 256];
    for &x in b {
        counts[x as usize] += 1;
    }
    let top = *counts.iter().max().unwrap() as f64;
    let h = -(top / b.len() as f64).log2();
    r.push("min_entropy", h >= FLOOR, format!("Hmin={h:.4} bits/byte floor={FLOOR}"));
}

/// No two aligned 16-byte blocks may repeat. Birthday over 2^128 is
/// unreachable for a real source; a page that is refilled from a short
/// cycle, or copied twice, trips this immediately.
fn repeated_blocks(b: &[u8], r: &mut Report) {
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut dup = 0usize;
    for blk in b.chunks_exact(16) {
        if !seen.insert(blk) {
            dup += 1;
        }
    }
    r.push("repeated_blocks", dup == 0, format!("duplicate 16B blocks={dup}"));
}

// ---------------------------------------------------------------------
// Collision freedom — the 32-bit-reseed detector
// ---------------------------------------------------------------------

/// Draw `COLLISION_DRAWS` independent 32-byte values and require every
/// one to be distinct.
///
/// This is the check that catches disclosure bug 2 (and any bounded-state
/// generator): whitening cannot expand a state space, so a generator with
/// `S` reachable states repeats a full output after ~`sqrt(S)` draws.
/// 400k draws gives ~18.6 expected collisions at `S = 2^32` while a real
/// source collides with probability ~2^-193.
pub fn collision_freedom(mut draw: impl FnMut(&mut [u8; 32])) -> Report {
    let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(COLLISION_DRAWS);
    let mut collisions = 0usize;
    let mut example = None;
    for _ in 0..COLLISION_DRAWS {
        let mut v = [0u8; 32];
        draw(&mut v);
        if !seen.insert(v) {
            collisions += 1;
            example.get_or_insert(v);
        }
    }
    let mut r = Report::default();
    r.push(
        "collision_freedom",
        collisions == 0,
        match example {
            None => format!("{COLLISION_DRAWS} distinct 32-byte draws"),
            Some(v) => format!(
                "{collisions} repeated draw(s) in {COLLISION_DRAWS}, e.g. {} \
                 => effective state space is bounded (~2^{:.0} or less)",
                hex(&v[..8]),
                2.0 * (COLLISION_DRAWS as f64).log2()
            ),
        },
    );
    r
}

/// Consecutive draws must never be equal, and a draw must never come back
/// all-zero or all-ones. Cheap, and it is the shape a dead TRNG takes.
pub fn draw_sanity(n: usize, mut draw: impl FnMut(&mut [u8; 32])) -> Report {
    let mut r = Report::default();
    let mut prev = [0u8; 32];
    let mut repeats = 0usize;
    let mut zeros = 0usize;
    let mut ones = 0usize;
    for i in 0..n {
        let mut v = [0u8; 32];
        draw(&mut v);
        if v == [0u8; 32] {
            zeros += 1;
        }
        if v == [0xffu8; 32] {
            ones += 1;
        }
        if i > 0 && v == prev {
            repeats += 1;
        }
        prev = v;
    }
    r.push("draw_never_zero", zeros == 0, format!("all-zero draws={zeros}/{n}"));
    r.push("draw_never_ones", ones == 0, format!("all-ones draws={ones}/{n}"));
    r.push("draw_never_repeats", repeats == 0, format!("consecutive repeats={repeats}/{n}"));
    r
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------
// NEGATIVE CONTROLS
//
// Broken sources with known failure modes. Every repo's entropy test
// module runs these so the battery is proven to DISCRIMINATE — a battery
// that only ever sees a good source cannot tell you it works.
// ---------------------------------------------------------------------

pub mod controls {
    /// All zeros — a mapped-but-never-written page.
    pub fn zeros(out: &mut [u8]) {
        out.fill(0);
    }

    /// A little-endian counter: uniform low byte, constant high bytes.
    #[derive(Default)]
    pub struct Counter(pub u64);
    impl Counter {
        pub fn fill(&mut self, out: &mut [u8]) {
            for c in out.chunks_mut(8) {
                let v = self.0.to_le_bytes();
                let n = c.len();
                c.copy_from_slice(&v[..n]);
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    /// disclosure bug 2, exactly: only the first `KEPT` bytes of each
    /// 32-byte draw are actually filled; the rest stays as the caller
    /// left it (a zeroed buffer).
    pub struct Truncated<F> {
        pub inner: F,
        pub kept: usize,
    }
    impl<F: FnMut(&mut [u8])> Truncated<F> {
        pub fn fill(&mut self, out: &mut [u8]) {
            out.fill(0);
            for c in out.chunks_mut(32) {
                let k = self.kept.min(c.len());
                (self.inner)(&mut c[..k]);
            }
        }
    }

    /// A stuck low bit.
    pub struct StuckBit<F>(pub F);
    impl<F: FnMut(&mut [u8])> StuckBit<F> {
        pub fn fill(&mut self, out: &mut [u8]) {
            (self.0)(out);
            for b in out.iter_mut() {
                *b |= 0x01;
            }
        }
    }

    /// A masked source — 7 bits of every byte.
    pub struct Biased<F>(pub F);
    impl<F: FnMut(&mut [u8])> Biased<F> {
        pub fn fill(&mut self, out: &mut [u8]) {
            (self.0)(out);
            for b in out.iter_mut() {
                *b &= 0x7f;
            }
        }
    }

    /// One random page, repeated forever (a buffer that is never refilled).
    pub struct RepeatingPage {
        pub page: Vec<u8>,
        pub pos: usize,
    }
    impl RepeatingPage {
        pub fn new(mut src: impl FnMut(&mut [u8]), page: usize) -> Self {
            let mut p = vec![0u8; page];
            src(&mut p);
            Self { page: p, pos: 0 }
        }
        pub fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                *b = self.page[self.pos % self.page.len()];
                self.pos += 1;
            }
        }
    }

    /// A **statistically perfect** PRNG whose whole state is 32 bits —
    /// disclosure bug 2's real shape: a good generator whose reseed
    /// receives only 4 bytes of a 32-byte hash, so however unpredictable
    /// those 4 bytes are, the output is drawn from a 2^32-element family.
    ///
    /// It passes every distribution check in this file and is caught ONLY
    /// by `collision_freedom`.
    ///
    /// The 32-bit seeds are drawn *uniformly* (not walked sequentially) —
    /// that is what the real bug does, and it is also what makes the
    /// birthday bound apply. A generator that enumerated distinct seeds
    /// would be just as broken but would not collide.
    pub struct Reseed32 {
        entropy: ChaCha20,
    }
    impl Reseed32 {
        pub fn new(seed: u8) -> Self {
            Self { entropy: ChaCha20::new(&[seed; 32], 0) }
        }
        /// One draw: pull 4 random bytes, key a fresh generator with them.
        pub fn draw32(&mut self, out: &mut [u8; 32]) {
            let mut reseed = [0u8; 4];
            self.entropy.fill(&mut reseed);
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&reseed);
            ChaCha20::new(&key, 0).fill(out);
        }
        pub fn fill(&mut self, out: &mut [u8]) {
            for c in out.chunks_mut(32) {
                let mut v = [0u8; 32];
                self.draw32(&mut v);
                let n = c.len();
                c.copy_from_slice(&v[..n]);
            }
        }
    }

    /// A fixed-seed CSPRNG: disclosure bug 1's shape. Statistically
    /// perfect — the battery CANNOT catch it, and the test that asserts
    /// so is the honest statement of this file's limits.
    pub struct FixedSeed(ChaCha20);
    impl FixedSeed {
        pub fn new(seed: u8) -> Self {
            Self(ChaCha20::new(&[seed; 32], 0))
        }
        pub fn fill(&mut self, out: &mut [u8]) {
            self.0.fill(out);
        }
    }

    /// Minimal ChaCha20 keystream — test scaffolding only, so the
    /// controls need no dependency. Never used for anything real.
    pub struct ChaCha20 {
        key: [u32; 8],
        counter: u64,
        buf: [u8; 64],
        used: usize,
    }

    impl ChaCha20 {
        pub fn new(key: &[u8; 32], counter: u64) -> Self {
            let mut k = [0u32; 8];
            for (i, c) in key.chunks_exact(4).enumerate() {
                k[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            }
            Self { key: k, counter, buf: [0; 64], used: 64 }
        }

        fn block(&mut self) {
            const C: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
            let mut s = [0u32; 16];
            s[..4].copy_from_slice(&C);
            s[4..12].copy_from_slice(&self.key);
            s[12] = self.counter as u32;
            s[13] = (self.counter >> 32) as u32;
            let orig = s;
            for _ in 0..10 {
                qr(&mut s, 0, 4, 8, 12);
                qr(&mut s, 1, 5, 9, 13);
                qr(&mut s, 2, 6, 10, 14);
                qr(&mut s, 3, 7, 11, 15);
                qr(&mut s, 0, 5, 10, 15);
                qr(&mut s, 1, 6, 11, 12);
                qr(&mut s, 2, 7, 8, 13);
                qr(&mut s, 3, 4, 9, 14);
            }
            for i in 0..16 {
                let v = s[i].wrapping_add(orig[i]);
                self.buf[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
            self.counter = self.counter.wrapping_add(1);
            self.used = 0;
        }

        pub fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                if self.used == 64 {
                    self.block();
                }
                *b = self.buf[self.used];
                self.used += 1;
            }
        }
    }

    fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    }
}
