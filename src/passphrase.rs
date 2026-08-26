//! 12-word passphrase generator for the compose screen's Security section
//! (post-quantum FLAG_PW layer, `notes_core::pq`). Mirrors the Mac app's
//! `app-core/src/passphrase.rs` — same wordlist, same rejection-sampling
//! shape — but reimplemented device-side since this crate has no `rand`
//! dependency: every draw goes straight through `getrandom` 0.2 (the
//! workspace's vendored TRNG override on `--cfg keyos` builds), matching
//! this app's RNG rule.
//!
//! **Deliberately NOT a BIP-39 mnemonic.** A real BIP-39 phrase folds a
//! checksum into its last word, so a mnemonic generator here would make a
//! note passphrase indistinguishable from a seed phrase — exactly the
//! confusion this module exists to avoid. A phrase from [`generate`] must
//! never be typed into a wallet's seed import, and a seed phrase must
//! never be reused as a note passphrase.
//!
//! The device has no `zxcvbn`-equivalent strength estimator (deliberately
//! simpler than the Mac app): a typed/pasted passphrase is always shown as
//! "strength can't be verified"; only a freshly generated (and
//! byte-unmodified) phrase is certified, at the closed-form
//! [`GENERATED_BITS`] — see `security_label` in `main.rs`.

const WORD_COUNT: usize = 12;

/// `12 * log2(2048)` — the closed-form entropy of a 12-word draw from the
/// (2048-word) BIP-39 English wordlist, uniform by construction (rejection
/// sampling below never biases toward any word). Not computed at runtime;
/// it's exact for any successful [`generate`] call.
pub const GENERATED_BITS: f64 = 132.0;

/// Draw a fresh 12-word passphrase (space-joined) from the standard
/// BIP-39 English wordlist (`notes_core::bip39::wordlist`, 2048 words) via
/// rejection-sampled TRNG draws — uniform over the wordlist, never biased.
/// The only failure mode is TRNG exhaustion/unavailability.
pub fn generate() -> Result<String, notes_core::Error> {
    let words = notes_core::bip39::wordlist();
    let bound = words.len() as u16; // 2048
    let mut out = Vec::with_capacity(WORD_COUNT);
    for _ in 0..WORD_COUNT {
        out.push(words[sample_index(bound)? as usize]);
    }
    Ok(out.join(" "))
}

/// Uniform `[0, bound)` via 2-byte TRNG draws + rejection sampling — the
/// general algorithm (kept general even though `bound == 2048` divides
/// `65536` exactly, making the discard branch unreachable today: `limit`
/// then equals `65536`, so every `u16` draw is `< limit`).
fn sample_index(bound: u16) -> Result<u16, notes_core::Error> {
    let bound32 = u32::from(bound);
    let limit = (u32::from(u16::MAX) + 1) / bound32 * bound32;
    loop {
        let mut buf = [0u8; 2];
        getrandom::getrandom(&mut buf).map_err(|_| notes_core::Error::Entropy)?;
        let v = u32::from(u16::from_le_bytes(buf));
        if v < limit {
            return Ok((v % bound32) as u16);
        }
    }
}

/// Conservative "obviously weak" gate for a TYPED (non-generated)
/// passphrase — NOT an entropy estimate. The device deliberately ships no
/// zxcvbn-equivalent (see the module doc), so this flags only what is
/// weak under ANY charitable reading: too few characters, or too few
/// words to plausibly be a diceware-style phrase. The Mac app's zxcvbn
/// estimator remains the richer readout; this gate exists so the device
/// warns while the user is still typing instead of certifying nothing
/// silently. Thresholds err toward warning: a 4-word/16-char phrase drawn
/// from a wordlist is ~44 bits — thin, but past "trivially brute-forced";
/// anything under that gets the explicit weak warning.
pub fn typed_is_weak(phrase: &str) -> bool {
    let trimmed = phrase.trim();
    let chars = trimmed.chars().count();
    let words = trimmed.split_whitespace().count();
    !(chars >= 24 || (chars >= 16 && words >= 4))
}

#[cfg(test)]
mod weak_tests {
    use super::typed_is_weak;

    #[test]
    fn short_or_few_words_is_weak() {
        for p in ["", "hunter2", "password123", "correct horse", "tiny words here"] {
            assert!(typed_is_weak(p), "{p:?} should be weak");
        }
    }

    #[test]
    fn long_or_wordy_is_not_flagged() {
        for p in [
            "correct horse battery staple",
            "brown provide arrest stairs hybrid hymn",
            "aVeryLongSingleRunOfChars24!",
        ] {
            assert!(!typed_is_weak(p), "{p:?} should not be flagged");
        }
    }

    #[test]
    fn generated_phrases_are_never_flagged() {
        // 12 words joined by spaces always clears both thresholds.
        let p = super::generate();
        if let Ok(p) = p {
            assert!(!typed_is_weak(&p));
        }
    }
}
