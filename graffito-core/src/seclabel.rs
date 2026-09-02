//! Security copy for the compose screen's Security section — the ONE
//! table both shells render from: which note states are quantum-resistant
//! ([`is_quantum_resistant`], the header badge) and the sentence that says
//! so ([`security_label`], the section caption).
//!
//! Moved here from graffito's `app-core/src/passphrase.rs` (2026-09-01,
//! PLAN-graffito-arch.md phase 2) after the policy had drifted across three
//! copies — app-core's function, a stale override in graffito's `src/lib.rs`
//! (which shipped a "losing the imported key" warning to users who had
//! GENERATED their key), and the device app's `pq_security_label`. The
//! function is TOTAL over [`SecurityChoice`]: a shell picks a
//! [`SelfNoteCopy`] flavor and renders the result; it never patches it.
//!
//! # Two flavors, one table
//!
//! The public and directed rows are identical on every platform. The
//! self-note rows carry two deliberately different wordings, both pinned
//! here and in `tests/seclabel_table.rs`:
//!
//! - [`SelfNoteCopy::Flat`] — graffito (Mac/iOS/Android): one loss warning
//!   per layer combination, independent of passphrase strength ("Password
//!   layer added — forgetting it loses this note forever, even with your
//!   seed.").
//! - [`SelfNoteCopy::Detailed`] — the KeyOS app: per-state wording that
//!   distinguishes a verified (generated) passphrase from an unverified one
//!   and names the device ("readable only on this device — or another
//!   holding your ML-KEM-768 personal quantum key").
//!
//! Unifying the two is a product decision (PLAN-graffito-arch.md phase
//! 1b); until it is made, both live here, total and tested, and the
//! workspace's `scripts/check-seclabel-parity.py` keeps the shared rows
//! locked.
//!
//! # Passphrase strength without an estimator
//!
//! [`SecurityChoice::passphrase_bits`] is an entropy reading. graffito's
//! app-core fills it from zxcvbn (typed input, an ESTIMATE that can never
//! reach [`REQUIRED_BITS`] — see app-core's module doc) or from the
//! closed-form [`GENERATED_BITS`] of its generator. The KeyOS app has no
//! estimator at all: a typed/pasted passphrase is simply "strength can't
//! be verified", and only a freshly generated, byte-unmodified phrase is
//! certified. Its construction is [`SecurityChoice::without_estimator`]:
//! `Some(GENERATED_BITS)` when the passphrase layer is active AND verified,
//! `Some(0.0)` when active but unverified, `None` when off, with
//! `passphrase_verified` passed through. Under that mapping the
//! [`SelfNoteCopy::Detailed`] and directed rows reproduce the device's
//! historical output byte-for-byte (pinned in `tests/seclabel_table.rs`).
//!
//! # Why 128 bits (`REQUIRED_BITS`)
//!
//! A directed note's ciphertext sits on the blockchain forever, public,
//! and an attacker can try guesses entirely offline with no rate limit.
//! 128 bits is the number security consensus treats as putting brute
//! force out of reach for an offline, unlimited-attempt attacker; Argon2id
//! slows each guess but cannot manufacture entropy the passphrase never
//! had. An entropy claim that is only ASSUMED, never measured against what
//! the user typed, is exactly how a "strong passphrase" quietly turns out
//! not to be one (RANDOMNESS-AUDIT-2026-08-01.md) — hence the verified /
//! unverified distinction below.

use notes_core::pq::MlKemAlg;

/// Minimum classical entropy, in bits, before a passphrase is considered
/// strong enough for the passphrase layer to carry quantum-resistance on
/// its own (module doc). Gates [`is_quantum_resistant`] and the directed
/// rows of [`security_label`].
pub const REQUIRED_BITS: f64 = 128.0;

/// A generated passphrase's EXACT entropy: 12 words drawn independently
/// and uniformly from the 2048-word BIP-39 English list, 11 bits/word
/// (`log2(2048) = 11`), `12 * 11 = 132`. A closed-form fact about the
/// draw, not an estimate. Both shells' generators (app-core's `generate`
/// and the device's `passphrase::generate`) implement exactly this draw.
pub const GENERATED_BITS: f64 = 132.0;

/// The three ML-KEM (FIPS 203) parameter sets offered for the note's PQ
/// hybrid-encryption layer, ordered by parameter size (not necessarily by
/// UI display order). `Serialize`/`Deserialize` (app-core's `pqkeys::
/// PqKeySource` persists which level a per-notebook derived key — or an
/// imported one's declared level — uses) round-trip as the plain variant
/// name (`"MlKem512"`/`"MlKem768"`/`"MlKem1024"`) via serde's default enum
/// representation — pinned by a test in app-core's `pqkeys.rs` and by
/// `serde_round_trips_as_variant_name` here.
///
/// This is the UI/policy-side twin of the wire-level
/// [`notes_core::pq::MlKemAlg`]; the two convert losslessly through
/// `From` in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MlKemLevel {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemLevel {
    /// The level pre-selected in the picker UI — NIST's and most
    /// deployments' standard recommendation for general use, balancing
    /// ciphertext/key size against security margin.
    pub const DEFAULT: MlKemLevel = MlKemLevel::MlKem768;

    /// Short display name, e.g. for composing "ML-KEM-768 hybrid" in
    /// [`security_label`]. Distinct from [`describe`](Self::describe),
    /// which returns the longer explanatory sentence.
    pub fn name(self) -> &'static str {
        match self {
            MlKemLevel::MlKem512 => "ML-KEM-512",
            MlKemLevel::MlKem768 => "ML-KEM-768",
            MlKemLevel::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// One-sentence explanation for the level-picker UI. Wording/AES
    /// comparisons are the exact strings reviewed and approved for that
    /// picker — treat them as pinned copy, not paraphrasable. Identical on
    /// every platform, so a contact importing a Prime device's exported
    /// key sees the same sentence in either app.
    pub fn describe(self) -> &'static str {
        match self {
            MlKemLevel::MlKem512 => {
                "Lowest parameter size; offers security roughly comparable to AES-128."
            }
            MlKemLevel::MlKem768 => {
                "Standard recommendation for most general applications; provides security comparable to AES-192."
            }
            MlKemLevel::MlKem1024 => {
                "Highest parameter size; offers security comparable to AES-256 for maximum long-term protection."
            }
        }
    }
}

impl From<MlKemAlg> for MlKemLevel {
    fn from(alg: MlKemAlg) -> Self {
        match alg {
            MlKemAlg::MlKem512 => MlKemLevel::MlKem512,
            MlKemAlg::MlKem768 => MlKemLevel::MlKem768,
            MlKemAlg::MlKem1024 => MlKemLevel::MlKem1024,
        }
    }
}

impl From<MlKemLevel> for MlKemAlg {
    fn from(level: MlKemLevel) -> Self {
        match level {
            MlKemLevel::MlKem512 => MlKemAlg::MlKem512,
            MlKemLevel::MlKem768 => MlKemAlg::MlKem768,
            MlKemLevel::MlKem1024 => MlKemAlg::MlKem1024,
        }
    }
}

/// Which self-note wording a shell renders (module doc, "Two flavors, one
/// table"). Public and directed rows do not depend on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfNoteCopy {
    /// graffito (Mac/iOS/Android): one loss warning per layer combination,
    /// strength-independent.
    Flat,
    /// The KeyOS app: per-state wording, verified vs unverified passphrase
    /// distinguished, the device named.
    Detailed,
}

/// The compose screen's selected protection for one note — enough to
/// derive both [`security_label`] and [`is_quantum_resistant`] without
/// reaching into the actual encryption code.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SecurityChoice {
    /// `false` for a public note (plaintext OP_RETURN content, readable by
    /// anyone). `true` for an encrypted note (self or directed).
    pub private: bool,
    /// `true` for a directed note (ECDH-sealed to a recipient); `false`
    /// for a self-note (symmetric key from the sender's own seed). Only
    /// meaningful when `private` is `true`.
    pub directed: bool,
    /// Estimated/exact entropy of the passphrase-layer passphrase, if the
    /// passphrase layer is enabled (`None` when it isn't). Offered on
    /// directed notes and — since PLAN-graffito-self-pw.md (2026-08-22) —
    /// self-notes too, though it never changes [`is_quantum_resistant`]'s
    /// answer for a self-note (already `true` regardless — see that fn's
    /// doc). A shell without a strength estimator fills this per
    /// [`SecurityChoice::without_estimator`].
    pub passphrase_bits: Option<f64>,
    /// `true` iff the CURRENT passphrase text came out of the shell's
    /// generator this session, untouched since. A generated phrase's
    /// entropy is a closed-form fact ([`GENERATED_BITS`]); anything typed
    /// or pasted, or a generated phrase the user has since edited, has at
    /// best an ESTIMATE — so an unverified passphrase must never count
    /// toward quantum-resistance no matter how high its estimate reads.
    /// The compose screen flips this back to `false` the instant the
    /// generated text changes.
    pub passphrase_verified: bool,
    /// The ML-KEM level, if the hybrid layer is enabled. `None` when it
    /// isn't in use. Offered on directed notes and — since
    /// PLAN-graffito-self-pw.md — self-notes too (there, ONLY when sealed
    /// to a non-seed-derived personal quantum key — a compose-side
    /// obligation this struct can't see); same quantum-resistance caveat
    /// as `passphrase_bits` above.
    pub mlkem: Option<MlKemLevel>,
}

impl SecurityChoice {
    /// The construction for a shell with NO passphrase-strength estimator
    /// (the KeyOS app — module doc, "Passphrase strength without an
    /// estimator"): the passphrase layer is either off (`None`), active and
    /// certified by the generator (`Some(GENERATED_BITS)`), or active with
    /// an unverifiable typed/pasted phrase (`Some(0.0)` — present, never
    /// counting). `passphrase_verified` passes through unchanged.
    pub fn without_estimator(
        private: bool,
        directed: bool,
        passphrase_active: bool,
        passphrase_verified: bool,
        mlkem: Option<MlKemLevel>,
    ) -> Self {
        let passphrase_bits = match (passphrase_active, passphrase_verified) {
            (false, _) => None,
            (true, true) => Some(GENERATED_BITS),
            (true, false) => Some(0.0),
        };
        SecurityChoice { private, directed, passphrase_bits, passphrase_verified, mlkem }
    }

    /// The passphrase layer is on AND its phrase counts toward
    /// quantum-resistance: verified (generated, unedited) and at/above
    /// [`REQUIRED_BITS`]. An unverified estimate never counts, however
    /// high it reads (module doc).
    fn passphrase_counts(&self) -> bool {
        self.passphrase_verified
            && matches!(self.passphrase_bits, Some(bits) if bits >= REQUIRED_BITS)
    }

    /// The passphrase layer is on at all (counting or not).
    fn passphrase_present(&self) -> bool {
        self.passphrase_bits.is_some()
    }
}

/// Whether the SELECTED protection resists a quantum adversary — the same
/// logic [`security_label`] describes in prose, exposed separately so the
/// UI can key a badge/icon off it without parsing the label string. Flavor
/// independent.
///
/// - Public note: never quantum-resistant (there's no encryption at all).
/// - Private self-note: always quantum-resistant — a symmetric key
///   derived from the seed puts no public-key material on-chain for a
///   quantum algorithm (e.g. Shor's) to attack in the first place.
/// - Private directed note: quantum-resistant iff the ML-KEM hybrid layer
///   is enabled, OR the passphrase layer is enabled with a VERIFIED
///   (generated, unedited) passphrase whose exact entropy is at or above
///   [`REQUIRED_BITS`] (a sufficiently strong passphrase-derived key has
///   no public-key structure for a quantum algorithm to exploit either —
///   the base ECDH layer stays quantum-VULNERABLE regardless, but an
///   attacker who breaks it still hits the passphrase- or ML-KEM-derived
///   layer underneath). A typed/pasted passphrase never counts here.
pub fn is_quantum_resistant(c: &SecurityChoice) -> bool {
    if !c.private {
        return false;
    }
    if !c.directed {
        return true;
    }
    if c.mlkem.is_some() {
        return true;
    }
    c.passphrase_counts()
}

/// One line of compose-screen copy summarizing the protection
/// [`SecurityChoice`] describes, in the shell's [`SelfNoteCopy`] flavor.
/// Total over its inputs — see the module doc for the reasoning each row
/// encodes; this function only turns that reasoning into a sentence.
pub fn security_label(c: &SecurityChoice, flavor: SelfNoteCopy) -> String {
    if !c.private {
        return "Public note: anyone can read it on the blockchain, forever.".to_string();
    }
    if !c.directed {
        return self_note_label(c, flavor);
    }
    directed_label(c)
}

/// `(is_quantum_resistant(c), security_label(c, flavor))` together — the
/// compose screen's Security section always wants both for the same
/// [`SecurityChoice`] (the header status chip and the section's bottom
/// caption), so a shell makes this ONE call rather than duplicating the
/// branching those two functions already do.
pub fn describe(c: &SecurityChoice, flavor: SelfNoteCopy) -> (bool, String) {
    (is_quantum_resistant(c), security_label(c, flavor))
}

/// A self-note is already quantum-resistant on its own (symmetric,
/// seed-derived key — no public-key material ever touches the chain), so
/// [`is_quantum_resistant`] stays `true` whatever the layers say. The
/// layers protect against a DIFFERENT threat (seed compromise, an exported
/// xpub + quantum recovery of the leaf secret — PLAN-graffito-self-pw.md's
/// "Why"), so whenever one is actually on, the label surfaces the loss
/// warning instead of the generic self-note sentence: forgetting the
/// password, or losing the personal quantum key (`mlkem` on a self-note is
/// always the non-seed personal key — PLAN-graffito-quantum-key.md), makes
/// the note unrecoverable, seed or no seed.
fn self_note_label(c: &SecurityChoice, flavor: SelfNoteCopy) -> String {
    const PLAIN: &str = "Private note: sealed with a key derived from your seed. Already quantum-resistant — no public-key material ever touches the chain.";
    match flavor {
        SelfNoteCopy::Flat => match (c.passphrase_present(), c.mlkem.is_some()) {
            (false, false) => PLAIN.to_string(),
            (true, true) => "Password + quantum-key layer added — forgetting either the password or the quantum key loses this note forever, even with your seed.".to_string(),
            (true, false) => "Password layer added — forgetting it loses this note forever, even with your seed.".to_string(),
            (false, true) => "Quantum-key layer added — losing your quantum key loses this note forever, even with your seed.".to_string(),
        },
        SelfNoteCopy::Detailed => {
            let counts = c.passphrase_counts();
            match (c.mlkem, c.passphrase_present()) {
                (None, false) => PLAIN.to_string(),
                (None, true) if counts => {
                    let bits = c.passphrase_bits.expect("passphrase_counts implies Some");
                    format!("Password-protected: not even your seed reads this back without it (~{bits:.0}-bit passphrase). Forget it and the note is gone forever, seed or no seed.")
                }
                (None, true) => "Password added — strength unverifiable. Forget it and the note is gone forever, seed or no seed.".to_string(),
                (Some(level), false) => format!(
                    "Quantum-resistant: readable only on this device — or another holding your {} personal quantum key. Losing that key loses the note, seed or no seed.",
                    level.name()
                ),
                (Some(level), true) if counts => {
                    let bits = c.passphrase_bits.expect("passphrase_counts implies Some");
                    format!(
                        "Quantum-resistant: readable only where your {} personal quantum key is present, plus a strong passphrase (~{bits:.0} bits). Losing either loses the note.",
                        level.name()
                    )
                }
                (Some(level), true) => format!(
                    "Quantum-resistant: readable only where your {} personal quantum key is present — passphrase layer added but unverified.",
                    level.name()
                ),
            }
        }
    }
}

/// Directed rows — identical in every flavor. `passphrase_present` covers
/// every case where the layer is on but doesn't (yet, or ever) count:
/// unverified typed/pasted input at any estimate, or a verified-but-short
/// reading that shouldn't occur in practice but is handled the same way
/// defensively.
fn directed_label(c: &SecurityChoice) -> String {
    let counts = c.passphrase_counts();
    let present = c.passphrase_present();
    match (c.mlkem, counts, present) {
        (None, false, false) => {
            "Directed note: end-to-end encrypted (~128-bit ECDH), but NOT quantum-resistant."
                .to_string()
        }
        (None, true, _) => {
            let bits = c.passphrase_bits.expect("passphrase_counts implies Some");
            format!("Quantum-resistant: protected by a strong passphrase (~{bits:.0} bits).")
        }
        (None, false, true) => {
            "Passphrase added — strength unverifiable, not counted as quantum-resistant."
                .to_string()
        }
        (Some(level), false, false) => {
            format!("Quantum-resistant: protected by {} hybrid encryption.", level.name())
        }
        (Some(level), true, _) => {
            let bits = c.passphrase_bits.expect("passphrase_counts implies Some");
            format!(
                "Quantum-resistant: {} hybrid encryption plus a strong passphrase (~{bits:.0} bits).",
                level.name()
            )
        }
        (Some(level), false, true) => format!(
            "Quantum-resistant via {} hybrid encryption — passphrase layer added but unverified.",
            level.name()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_describe_exact_strings() {
        assert_eq!(
            MlKemLevel::MlKem512.describe(),
            "Lowest parameter size; offers security roughly comparable to AES-128."
        );
        assert_eq!(
            MlKemLevel::MlKem768.describe(),
            "Standard recommendation for most general applications; provides security comparable to AES-192."
        );
        assert_eq!(
            MlKemLevel::MlKem1024.describe(),
            "Highest parameter size; offers security comparable to AES-256 for maximum long-term protection."
        );
    }

    #[test]
    fn mlkem_default_is_768() {
        assert_eq!(MlKemLevel::DEFAULT, MlKemLevel::MlKem768);
    }

    #[test]
    fn mlkem_level_round_trips_through_wire_alg() {
        for level in [MlKemLevel::MlKem512, MlKemLevel::MlKem768, MlKemLevel::MlKem1024] {
            let alg: MlKemAlg = level.into();
            assert_eq!(MlKemLevel::from(alg), level);
            assert_eq!(MlKemLevel::from(alg).name(), level.name());
        }
        assert_eq!(MlKemAlg::from(MlKemLevel::MlKem512).id(), 0x01);
        assert_eq!(MlKemAlg::from(MlKemLevel::MlKem768).id(), 0x02);
        assert_eq!(MlKemAlg::from(MlKemLevel::MlKem1024).id(), 0x03);
    }

    #[test]
    fn without_estimator_mapping() {
        let off = SecurityChoice::without_estimator(true, false, false, false, None);
        assert_eq!(off.passphrase_bits, None);
        assert!(!off.passphrase_verified);
        // "off but verified" cannot occur in the shell; it still maps to off.
        assert_eq!(SecurityChoice::without_estimator(true, false, false, true, None).passphrase_bits, None);

        let generated = SecurityChoice::without_estimator(true, true, true, true, None);
        assert_eq!(generated.passphrase_bits, Some(GENERATED_BITS));
        assert!(generated.passphrase_verified);
        assert!(generated.passphrase_counts());

        let typed = SecurityChoice::without_estimator(true, true, true, false, None);
        assert_eq!(typed.passphrase_bits, Some(0.0));
        assert!(!typed.passphrase_verified);
        assert!(typed.passphrase_present());
        assert!(!typed.passphrase_counts());
    }

    #[test]
    fn describe_matches_the_two_underlying_calls() {
        for flavor in [SelfNoteCopy::Flat, SelfNoteCopy::Detailed] {
            let c = SecurityChoice {
                private: true,
                directed: false,
                passphrase_bits: Some(GENERATED_BITS),
                passphrase_verified: true,
                mlkem: Some(MlKemLevel::MlKem1024),
            };
            let (resistant, label) = describe(&c, flavor);
            assert_eq!(resistant, is_quantum_resistant(&c));
            assert_eq!(label, security_label(&c, flavor));
        }
    }
}
