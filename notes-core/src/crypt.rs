//! Private-note sealing: XChaCha20-Poly1305, one nonce per NOTE (the whole
//! note is sealed once, then chunked — never per-chunk nonces; see
//! PLAN-graffito.md). Blob layout: nonce(24) || ciphertext || tag(16).
//!
//! XChaCha20 is length-preserving, so sealed_len = plaintext_len + 40 —
//! the compose screen's keystroke cost estimator depends on that constant.
//!
//! **Uniform AAD rule (PLAN-pnte-redesign.md, 2026-08-11 orchestrator
//! review):** every sealed body — self-note or directed — binds the
//! carrying tx's FIRST input's outpoint (36 bytes: txid in internal/
//! little-endian order || vout as `u32`-LE, exactly as serialized on the
//! wire — identical convention to dm.rs). Directed notes additionally bind
//! the sender/recipient output-key pair (dm.rs's `dm_aad`); a self-note's
//! AAD is the bare outpoint. Binding is not optional for self-notes
//! either: without it, a self-note's sealed blob can be copied byte-for-
//! byte out of its original tx into ANY new tx that merely PAYS my
//! address — same key, same ciphertext, and an EMPTY AAD would still
//! authenticate under that unrelated tx, surfacing my own old secret text
//! attributed to whoever sent the new payment. Binding the outpoint means
//! a copied blob only ever authenticates under the tx that originally
//! sealed it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::Error;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Fixed size overhead of a sealed blob over its plaintext.
pub const SEAL_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Seal with an explicit nonce and arbitrary AAD (directed notes bind
/// sender/recipient keys + the funding outpoint — see dm.rs; own notes
/// bind the bare outpoint — see `seal`/`open` below and the module doc's
/// "Uniform AAD rule").
pub(crate) fn seal_with_nonce_aad(
    key: &[u8; 32],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::DecryptFailed)?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Seal with a fresh TRNG/OS nonce and arbitrary AAD.
pub(crate) fn seal_aad(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Entropy)?;
    seal_with_nonce_aad(key, aad, &nonce, plaintext)
}

/// Open a sealed blob under arbitrary AAD. Failure = "not ours / corrupted".
pub(crate) fn open_aad(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, Error> {
    if blob.len() < SEAL_OVERHEAD {
        return Err(Error::DecryptFailed);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::DecryptFailed)
}

/// Seal with an explicit nonce (tests). Production callers use `seal`.
/// `outpoint` is the carrying tx's FIRST input's prevout — see the module
/// doc's "Uniform AAD rule" for why a self-note binds this too, not just
/// directed ones.
pub fn seal_with_nonce(
    key: &[u8; 32],
    outpoint: &[u8; 36],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_with_nonce_aad(key, outpoint, nonce, plaintext)
}

/// Seal a note body with a fresh TRNG/OS nonce, bound to `outpoint` (the
/// carrying tx's first input's prevout — see the module doc).
pub fn seal(key: &[u8; 32], outpoint: &[u8; 36], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Entropy)?;
    seal_with_nonce(key, outpoint, &nonce, plaintext)
}

/// Open a sealed blob bound to `outpoint`. A failure means "not ours /
/// corrupted / wrong outpoint" — callers treat it as a foreign payload,
/// not a fatal error.
pub fn open(key: &[u8; 32], outpoint: &[u8; 36], blob: &[u8]) -> Result<Vec<u8>, Error> {
    open_aad(key, outpoint, blob)
}
