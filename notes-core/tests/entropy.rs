//! Entropy/randomness tests for notes-core's real key-material sources.
//!
//! Prompted by a 2026 public disclosure of an RNG failure in a
//! shipped hardware wallet's firmware: bug 1 was a
//! deterministic-PRNG fallback silently standing in for the hardware RNG,
//! bug 2 was a reseed where only 4 of 32 bytes reached the generator,
//! capping it at 2^32 states. This file exercises notes-core's actual
//! entropy consumer (`keys::generate_aux_rand`) against the shared
//! canonical battery, plus the negative controls that prove the battery
//! discriminates rather than being silently green.
//!
//! Ported from the validated reference harness
//! (`battery-check/tests/validate.rs`, 11/11 passing against
//! `/dev/urandom`), swapping in notes-core's own TRNG-backed generator.
//!
//! PLAN-pnte-redesign.md (2026-08-11) removed `keys::generate_note_id`/
//! `pick_unique_note_id` entirely — the note id IS the txid now (unique by
//! construction, no on-chain field, no TRNG draw), one fewer TRNG consumer
//! than before. The distribution-battery/collision-guard coverage that
//! used to live here for it is gone with the functions themselves.
//!
//! `keys::derive_seed_entropy` (the recovery-seed KDF) is NOT a TRNG
//! consumer — it is HKDF-SHA256 over `GetAppSeed`, so it inherits entropy
//! from the device master seed rather than drawing fresh randomness. It
//! gets its own section below, testing what is actually testable for a
//! KDF: determinism, separation, the one-way property, and that its
//! output still looks uniform (catching a broken/constant KDF wiring).

#[path = "common/entropy_battery.rs"]
mod battery;

use battery::controls;
use bip39::Mnemonic;
use notes_core::keys::{self, generate_aux_rand};
use notes_core::seeds;

// =======================================================================
// Task 1a: keys::generate_aux_rand — the primary 32-byte TRNG source
// (BIP340 signing aux randomness).
// =======================================================================

fn aux_rand32(out: &mut [u8; 32]) {
    *out = generate_aux_rand().expect("generate_aux_rand should not fail on host");
}

/// Fill an arbitrary-length buffer from `generate_aux_rand`, 32 bytes at a
/// time — used both as the primary source under test and as the "good"
/// inner source the negative controls corrupt.
fn aux_fill(out: &mut [u8]) {
    for c in out.chunks_mut(32) {
        let v = generate_aux_rand().expect("generate_aux_rand should not fail on host");
        let n = c.len();
        c.copy_from_slice(&v[..n]);
    }
}

#[test]
fn aux_rand_passes_battery() {
    let r = battery::battery_from(32, aux_fill);
    println!("{}", r.summary());
    r.assert_ok("keys::generate_aux_rand");
}

#[test]
fn aux_rand_draw_sanity() {
    battery::draw_sanity(10_000, aux_rand32).assert_ok("generate_aux_rand draws");
}

#[test]
fn aux_rand_collision_free() {
    let t = std::time::Instant::now();
    let r = battery::collision_freedom(aux_rand32);
    println!("collision test took {:?}\n{}", t.elapsed(), r.summary());
    r.assert_ok("generate_aux_rand collisions");
}

// =======================================================================
// Task 2: recovery-seed entropy (`keys::derive_seed_entropy`,
// `seeds::seed_mnemonic`) — HKDF-SHA256 over GetAppSeed. There is no RNG
// here, so determinism is REQUIRED (not a bug) and collision/distinctness
// tests do not apply. What's testable: exact bit length, 24-word/checksum
// shape, determinism, index/seed separation, the FROZEN one-way property
// (a rotation seed's entropy — or any prefix of it — must never equal the
// app seed), and that the KDF output still looks uniform across indexes
// (catches a broken/constant KDF wiring, e.g. an index that never reaches
// the info string).
//
// FROZEN: this file does not change (and must never change) the
// derivation, salt, or info string in notes-core/src/keys.rs — see this
// repo's CLAUDE.md. Tests only.
// =======================================================================

fn app_seed(fill: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = fill.wrapping_add(i as u8);
    }
    s
}

#[test]
fn seed_entropy_is_256_bits() {
    let e = keys::derive_seed_entropy(&app_seed(0), 0);
    assert_eq!(e.len(), 32, "derive_seed_entropy must return exactly 256 bits");
}

#[test]
fn seed_mnemonic_is_24_words_and_valid_bip39() {
    let seed = app_seed(7);
    for index in [0u32, 1, 42, 9999] {
        let words = seeds::seed_mnemonic(&seed, index).expect("seed_mnemonic");
        let count = words.split_whitespace().count();
        assert_eq!(count, 24, "index {index}: expected 24 words, got {count}");
        Mnemonic::parse(words.as_str())
            .unwrap_or_else(|e| panic!("index {index}: mnemonic failed BIP-39 checksum: {e:?}"));
    }
}

#[test]
fn seed_entropy_is_deterministic() {
    let seed = app_seed(3);
    for index in [0u32, 1, 500, 9999] {
        let a = keys::derive_seed_entropy(&seed, index);
        let b = keys::derive_seed_entropy(&seed, index);
        assert_eq!(a, b, "derive_seed_entropy must be deterministic at index {index} (it's a KDF, not an RNG)");
    }
}

#[test]
fn seed_entropy_index_separation() {
    let seed = app_seed(11);
    let mut seen = std::collections::HashSet::new();
    for index in 0u32..1000 {
        let e = keys::derive_seed_entropy(&seed, index);
        assert!(seen.insert(e), "index {index} collided with an earlier index's entropy");
        // One-way: the entropy must never equal the app seed, in full or
        // by any leading-prefix match — this is the FROZEN guarantee that
        // no rotation seed can ever recover the app seed.
        assert_ne!(e, seed, "index {index} entropy equals the app seed itself");
        for prefix_len in [4usize, 8, 16, 24, 32] {
            assert_ne!(
                &e[..prefix_len],
                &seed[..prefix_len],
                "index {index} entropy shares a {prefix_len}-byte prefix with the app seed"
            );
        }
    }
}

#[test]
fn seed_entropy_seed_separation() {
    let a = app_seed(1);
    let b = app_seed(2);
    for index in [0u32, 1, 100, 9999] {
        assert_ne!(
            keys::derive_seed_entropy(&a, index),
            keys::derive_seed_entropy(&b, index),
            "two different app seeds must not agree at index {index}"
        );
    }
}

#[test]
fn seed_entropy_distribution_battery() {
    // Concatenate 8192 consecutive indexes' entropy (256 KiB, the
    // battery's default stream size) and run the distribution checks —
    // this is the check that would catch a KDF wired so the index never
    // reaches the info string (every draw silently identical/patterned).
    let seed = app_seed(5);
    let mut index = 0u32;
    let gen = move |out: &mut [u8]| {
        let e = keys::derive_seed_entropy(&seed, index);
        out.copy_from_slice(&e);
        index += 1;
    };
    let r = battery::battery_from(32, gen);
    println!("{}", r.summary());
    r.assert_ok("keys::derive_seed_entropy across 8192 consecutive indexes");
}

// ---------------------------------------------------------------------
// NEGATIVE CONTROLS — ported verbatim in intent from the validated
// reference harness (battery-check/tests/validate.rs), swapping
// /dev/urandom for notes-core's own generate_aux_rand. These exist so
// the battery can never be silently green in this repo either: each
// control is a known-broken source that MUST fail, for the RIGHT reason.
// ---------------------------------------------------------------------

fn assert_fails(r: &battery::Report, expect: &[&str], what: &str) {
    assert!(!r.passed(), "{what} MUST fail the battery but passed:\n{}", r.summary());
    let failed = r.failed_names();
    for e in expect {
        assert!(
            failed.contains(e),
            "{what} should have tripped `{e}`; tripped {failed:?}\n{}",
            r.summary()
        );
    }
    println!("{what} correctly failed: {failed:?}");
}

#[test]
fn control_zeros_fails() {
    let r = battery::battery_from(32, controls::zeros);
    assert_fails(&r, &["not_degenerate", "monobit", "longest_run", "shannon_entropy"], "all-zero source");
}

#[test]
fn control_counter_fails() {
    let mut c = controls::Counter::default();
    let r = battery::battery_from(8, |o| c.fill(o));
    assert_fails(&r, &["byte_chi_square"], "counter source");
}

#[test]
fn control_truncated_fails() {
    // disclosure bug 2: 4 of every 32 bytes actually filled.
    let mut t = controls::Truncated { inner: aux_fill, kept: 4 };
    let r = battery::battery_from(32, |o| t.fill(o));
    assert_fails(&r, &["monobit", "shannon_entropy"], "4-of-32-bytes source");
}

#[test]
fn control_stuck_bit_fails() {
    let mut s = controls::StuckBit(aux_fill);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert_fails(&r, &["bit_position_bias"], "stuck-low-bit source");
}

#[test]
fn control_biased_fails() {
    let mut s = controls::Biased(aux_fill);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert_fails(&r, &["monobit", "bit_position_bias"], "7-bit masked source");
}

#[test]
fn control_repeating_page_fails() {
    let mut s = controls::RepeatingPage::new(aux_fill, 4096);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert_fails(&r, &["repeated_blocks"], "never-refilled page");
}

#[test]
fn control_reseed32_caught_only_by_collisions() {
    // A perfect CSPRNG with a 32-bit state: passes the distribution
    // battery, caught by the birthday test. This is the whole reason
    // collision_freedom exists.
    let mut s = controls::Reseed32::new(1);
    let dist = battery::battery_from(32, |o| s.fill(o));
    println!("reseed32 distribution report:\n{}", dist.summary());

    let mut s2 = controls::Reseed32::new(7);
    let t = std::time::Instant::now();
    let coll = battery::collision_freedom(|o| s2.draw32(o));
    println!("reseed32 collision test took {:?}\n{}", t.elapsed(), coll.summary());
    assert!(!coll.passed(), "32-bit-state generator MUST collide within {} draws", battery::COLLISION_DRAWS);
}

#[test]
fn control_fixed_seed_passes_and_that_is_the_point() {
    // disclosure bug 1: statistically perfect, undetectable here. The
    // detectors are the backend/graph contract tests (rng_backend.rs)
    // and cross-boot independence on hardware.
    let mut s = controls::FixedSeed::new(0x42);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert!(
        r.passed(),
        "a fixed-seed CSPRNG is expected to PASS the statistics; if it now \
         fails, the battery changed meaning:\n{}",
        r.summary()
    );
    let mut a = controls::FixedSeed::new(0x42);
    let mut b = controls::FixedSeed::new(0x42);
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    a.fill(&mut x);
    b.fill(&mut y);
    assert_eq!(x, y, "two instances of a fixed-seed PRNG must agree — that IS the bug shape");
}
