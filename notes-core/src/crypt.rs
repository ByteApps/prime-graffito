//! Private-note sealing: XChaCha20-Poly1305, one nonce per NOTE (the whole
//! note is sealed once, then chunked — never per-chunk nonces; see
//! PLAN-chain-notes.md). Blob layout: nonce(24) || ciphertext || tag(16).
//!
//! XChaCha20 is length-preserving, so sealed_len = plaintext_len + 40 —
//! the compose screen's keystroke cost estimator depends on that constant.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::Error;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Fixed size overhead of a sealed blob over its plaintext.
pub const SEAL_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Seal with an explicit nonce and arbitrary AAD (directed notes bind
/// sender/recipient keys + the funding outpoint — see dm.rs; own notes use
/// an empty AAD, see `seal`/`open` below).
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
/// Self-notes carry no per-note identifier to bind (the old `note_id` AAD
/// is gone along with the field itself — PLAN-pnte-redesign.md), so the
/// AAD is empty; the key itself (derived per-identity from the app seed)
/// is what scopes decryption.
pub fn seal_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_with_nonce_aad(key, &[], nonce, plaintext)
}

/// Seal a note body with a fresh TRNG/OS nonce.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Entropy)?;
    seal_with_nonce(key, &nonce, plaintext)
}

/// Open a sealed blob. A failure means "not ours / corrupted" — callers
/// treat it as a foreign payload, not a fatal error.
pub fn open(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, Error> {
    open_aad(key, &[], blob)
}
