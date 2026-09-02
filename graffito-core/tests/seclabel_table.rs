//! Contract: the user-visible security copy for every state
//! `SecurityChoice` can represent, in BOTH self-note flavors — the compose
//! screen's Security caption plus the quantum-resistance badge. Strings are
//! pinned copy: a change here is a product decision, not a refactor.
//!
//! Provenance:
//! - `Flat` rows: graffito's `app-core/tests/security_label_contract.rs`
//!   (2026-09-01, phase 1 of PLAN-graffito-arch.md), byte-for-byte. That
//!   file keeps exercising app-core's re-exported surface; this one pins
//!   the shared crate itself.
//! - `Detailed` rows: prime-graffito `src/main.rs` `pq_security_label` as
//!   shipped before the move (phase 2), byte-for-byte, driven through the
//!   `SecurityChoice::without_estimator` mapping that shell uses.
//! - Public/directed rows are shared: identical in both flavors.

use graffito_core::seclabel::{
    describe, is_quantum_resistant, security_label, MlKemLevel, SecurityChoice, SelfNoteCopy,
    GENERATED_BITS, REQUIRED_BITS,
};

const FLAT: SelfNoteCopy = SelfNoteCopy::Flat;
const DETAILED: SelfNoteCopy = SelfNoteCopy::Detailed;
const KEM: Option<MlKemLevel> = Some(MlKemLevel::MlKem768);
const LEVELS: [MlKemLevel; 3] = [MlKemLevel::MlKem512, MlKemLevel::MlKem768, MlKemLevel::MlKem1024];

fn choice(
    private: bool,
    directed: bool,
    passphrase_bits: Option<f64>,
    passphrase_verified: bool,
    mlkem: Option<MlKemLevel>,
) -> SecurityChoice {
    SecurityChoice { private, directed, passphrase_bits, passphrase_verified, mlkem }
}

/// One row: choice -> (quantum-resistant badge, exact label) in one flavor.
fn assert_row(c: SecurityChoice, flavor: SelfNoteCopy, want_qr: bool, want_label: &str) {
    assert_eq!(is_quantum_resistant(&c), want_qr, "is_quantum_resistant mismatch for {c:?}");
    assert_eq!(security_label(&c, flavor), want_label, "label mismatch for {c:?} ({flavor:?})");
    // describe() is defined as exactly the pair — keep it that way.
    assert_eq!(describe(&c, flavor), (want_qr, want_label.to_string()));
}

/// A shared row: identical in BOTH flavors.
fn assert_shared(c: SecurityChoice, want_qr: bool, want_label: &str) {
    assert_row(c, FLAT, want_qr, want_label);
    assert_row(c, DETAILED, want_qr, want_label);
}

// ---- public notes: never quantum-resistant, layers change nothing -------

#[test]
fn public_note() {
    assert_shared(
        choice(false, false, None, false, None),
        false,
        "Public note: anyone can read it on the blockchain, forever.",
    );
}

#[test]
fn public_note_ignores_layers_and_direction() {
    for directed in [false, true] {
        for (bits, verified) in [(None, false), (Some(GENERATED_BITS), true)] {
            for mlkem in [None, KEM] {
                assert_shared(
                    choice(false, directed, bits, verified, mlkem),
                    false,
                    "Public note: anyone can read it on the blockchain, forever.",
                );
            }
        }
    }
}

// ---- self-notes, Flat flavor (graffito) ---------------------------------

#[test]
fn flat_self_note_plain() {
    assert_row(
        choice(true, false, None, false, None),
        FLAT,
        true,
        "Private note: sealed with a key derived from your seed. Already \
         quantum-resistant — no public-key material ever touches the chain.",
    );
}

#[test]
fn flat_self_note_password_layer() {
    // Flat across verified/unverified and any bits value: the layer guards
    // a different threat (seed compromise / harvested xpub), so the label
    // warns about loss, not strength.
    for (bits, verified) in [
        (Some(GENERATED_BITS), true),
        (Some(GENERATED_BITS), false),
        (Some(30.0), false),
        (Some(REQUIRED_BITS), true),
    ] {
        assert_row(
            choice(true, false, bits, verified, None),
            FLAT,
            true,
            "Password layer added — forgetting it loses this note forever, even \
             with your seed.",
        );
    }
}

#[test]
fn flat_self_note_quantum_key_layer() {
    // "your quantum key", never "the imported key": the slot has held
    // generated keys since PLAN-graffito-quantum-key.md.
    for level in LEVELS {
        assert_row(
            choice(true, false, None, false, Some(level)),
            FLAT,
            true,
            "Quantum-key layer added — losing your quantum key loses this note \
             forever, even with your seed.",
        );
    }
}

#[test]
fn flat_self_note_both_layers() {
    for (bits, verified) in [(Some(GENERATED_BITS), true), (Some(12.0), false)] {
        assert_row(
            choice(true, false, bits, verified, KEM),
            FLAT,
            true,
            "Password + quantum-key layer added — forgetting either the password \
             or the quantum key loses this note forever, even with your seed.",
        );
    }
}

// ---- self-notes, Detailed flavor (the KeyOS app) ------------------------
// Inputs built exactly the way that shell builds them:
// SecurityChoice::without_estimator(private, directed, active, verified, mlkem).

#[test]
fn detailed_self_note_plain() {
    assert_row(
        SecurityChoice::without_estimator(true, false, false, false, None),
        DETAILED,
        true,
        "Private note: sealed with a key derived from your seed. Already \
         quantum-resistant — no public-key material ever touches the chain.",
    );
}

#[test]
fn detailed_self_note_verified_password() {
    assert_row(
        SecurityChoice::without_estimator(true, false, true, true, None),
        DETAILED,
        true,
        "Password-protected: not even your seed reads this back without it \
         (~132-bit passphrase). Forget it and the note is gone forever, seed \
         or no seed.",
    );
}

#[test]
fn detailed_self_note_unverified_password() {
    assert_row(
        SecurityChoice::without_estimator(true, false, true, false, None),
        DETAILED,
        true,
        "Password added — strength unverifiable. Forget it and the note is \
         gone forever, seed or no seed.",
    );
    // With an estimator (graffito-style bits) the verdict is the same
    // whenever the phrase does not count: unverified at any estimate, or
    // verified but under the bar.
    for (bits, verified) in [(Some(200.0), false), (Some(REQUIRED_BITS - 1.0), true)] {
        assert_row(
            choice(true, false, bits, verified, None),
            DETAILED,
            true,
            "Password added — strength unverifiable. Forget it and the note is \
             gone forever, seed or no seed.",
        );
    }
}

#[test]
fn detailed_self_note_quantum_key() {
    for level in LEVELS {
        assert_row(
            SecurityChoice::without_estimator(true, false, false, false, Some(level)),
            DETAILED,
            true,
            &format!(
                "Quantum-resistant: readable only on this device — or another holding your \
                 {} personal quantum key. Losing that key loses the note, seed or no seed.",
                level.name()
            ),
        );
    }
    // Spelled out once, so the format above can't drift silently.
    assert_eq!(
        security_label(&SecurityChoice::without_estimator(true, false, false, false, KEM), DETAILED),
        "Quantum-resistant: readable only on this device — or another holding your ML-KEM-768 personal quantum key. Losing that key loses the note, seed or no seed."
    );
}

#[test]
fn detailed_self_note_quantum_key_plus_verified_password() {
    assert_row(
        SecurityChoice::without_estimator(true, false, true, true, KEM),
        DETAILED,
        true,
        "Quantum-resistant: readable only where your ML-KEM-768 personal quantum key is \
         present, plus a strong passphrase (~132 bits). Losing either loses the \
         note.",
    );
}

#[test]
fn detailed_self_note_quantum_key_plus_unverified_password() {
    assert_row(
        SecurityChoice::without_estimator(true, false, true, false, Some(MlKemLevel::MlKem1024)),
        DETAILED,
        true,
        "Quantum-resistant: readable only where your ML-KEM-1024 personal quantum key is \
         present — passphrase layer added but unverified.",
    );
}

// ---- directed notes: shared policy, identical in both flavors ----------

#[test]
fn directed_plain() {
    assert_shared(
        choice(true, true, None, false, None),
        false,
        "Directed note: end-to-end encrypted (~128-bit ECDH), but NOT quantum-resistant.",
    );
}

#[test]
fn directed_verified_passphrase_counts() {
    assert_shared(
        choice(true, true, Some(GENERATED_BITS), true, None),
        true,
        "Quantum-resistant: protected by a strong passphrase (~132 bits).",
    );
}

#[test]
fn directed_unverified_passphrase_does_not_count() {
    assert_shared(
        choice(true, true, Some(200.0), false, None),
        false,
        "Passphrase added — strength unverifiable, not counted as quantum-resistant.",
    );
}

#[test]
fn directed_verified_but_below_bar_does_not_count() {
    // Defensive: verified yet under REQUIRED_BITS reads as not counting.
    assert_shared(
        choice(true, true, Some(REQUIRED_BITS - 1.0), true, None),
        false,
        "Passphrase added — strength unverifiable, not counted as quantum-resistant.",
    );
}

#[test]
fn directed_mlkem() {
    assert_shared(
        choice(true, true, None, false, KEM),
        true,
        "Quantum-resistant: protected by ML-KEM-768 hybrid encryption.",
    );
}

#[test]
fn directed_mlkem_plus_verified_passphrase() {
    assert_shared(
        choice(true, true, Some(GENERATED_BITS), true, KEM),
        true,
        "Quantum-resistant: ML-KEM-768 hybrid encryption plus a strong passphrase (~132 bits).",
    );
}

#[test]
fn directed_mlkem_plus_unverified_passphrase() {
    assert_shared(
        choice(true, true, Some(50.0), false, KEM),
        true,
        "Quantum-resistant via ML-KEM-768 hybrid encryption — passphrase layer added but unverified.",
    );
}

// ---- the device's full input space, through its own construction --------

#[test]
fn directed_rows_via_without_estimator_match_the_device_table() {
    // (active, verified) -> expected directed copy, per pq_security_label
    // as shipped, for every level.
    for level in LEVELS {
        let n = level.name();
        let rows: [(bool, bool, Option<MlKemLevel>, bool, String); 6] = [
            (false, false, None, false, "Directed note: end-to-end encrypted (~128-bit ECDH), but NOT quantum-resistant.".into()),
            (true, false, None, false, "Passphrase added — strength unverifiable, not counted as quantum-resistant.".into()),
            (true, true, None, true, "Quantum-resistant: protected by a strong passphrase (~132 bits).".into()),
            (false, false, Some(level), true, format!("Quantum-resistant: protected by {n} hybrid encryption.")),
            (true, true, Some(level), true, format!("Quantum-resistant: {n} hybrid encryption plus a strong passphrase (~132 bits).")),
            (true, false, Some(level), true, format!("Quantum-resistant via {n} hybrid encryption — passphrase layer added but unverified.")),
        ];
        for (active, verified, mlkem, want_qr, want) in rows {
            assert_row(
                SecurityChoice::without_estimator(true, true, active, verified, mlkem),
                DETAILED,
                want_qr,
                &want,
            );
        }
    }
}

#[test]
fn shared_rows_never_depend_on_flavor() {
    // Every non-self-note choice renders identically in both flavors.
    for private in [false, true] {
        for (bits, verified) in [
            (None, false),
            (Some(0.0), false),
            (Some(50.0), false),
            (Some(GENERATED_BITS), true),
            (Some(REQUIRED_BITS - 1.0), true),
        ] {
            for mlkem in [None, Some(MlKemLevel::MlKem512), KEM, Some(MlKemLevel::MlKem1024)] {
                let c = choice(private, true, bits, verified, mlkem);
                assert_eq!(describe(&c, FLAT), describe(&c, DETAILED), "flavor leaked into {c:?}");
                let p = choice(private, false, bits, verified, mlkem);
                if !private {
                    assert_eq!(describe(&p, FLAT), describe(&p, DETAILED), "flavor leaked into {p:?}");
                }
            }
        }
    }
}

#[test]
fn stale_wording_never_returns() {
    for flavor in [FLAT, DETAILED] {
        for private in [false, true] {
            for directed in [false, true] {
                for (bits, verified) in [(None, false), (Some(0.0), false), (Some(GENERATED_BITS), true)] {
                    for mlkem in [None, KEM] {
                        let label = security_label(&choice(private, directed, bits, verified, mlkem), flavor);
                        assert!(!label.contains("imported"), "stale wording in {flavor:?}: {label}");
                    }
                }
            }
        }
    }
}

#[test]
fn serde_round_trips_as_variant_name() {
    for (level, name) in [
        (MlKemLevel::MlKem512, "\"MlKem512\""),
        (MlKemLevel::MlKem768, "\"MlKem768\""),
        (MlKemLevel::MlKem1024, "\"MlKem1024\""),
    ] {
        let json = serde_json::to_string(&level).unwrap();
        assert_eq!(json, name);
        assert_eq!(serde_json::from_str::<MlKemLevel>(&json).unwrap(), level);
    }
}
