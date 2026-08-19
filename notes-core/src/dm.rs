//! Directed-note encryption: STATIC-STATIC x-only ECDH between two taproot
//! output keys, HKDF'd into an XChaCha20-Poly1305 key.
//!
//! CONSENSUS-CRITICAL FOR RE-DERIVATION — FROZEN like keys.rs (post-epoch):
//! the salt and info strings below, the x-only shared-secret definition,
//! and the AAD layout are baked into every directed note ever sealed.
//! NEVER change them.
//!
//! GRAFFITO EPOCH (2026-08-18): `DM_SALT` was rebound from
//! `prime-chain-notes/dm/v1` alongside keys.rs's salts — a deliberate
//! crypto epoch break, not a compatibility-preserving change. Every
//! directed note sealed under the old salt is now permanently
//! undecryptable.
//!
//! Key agreement: `shared_x = x( my_tweaked_seckey · lift_x(peer_output_x) )`.
//! The taproot-tweaked scalar `a` satisfies `a·G = ±lift_x(my_output_x)`, so
//! the four parity combinations differ only in the sign of the shared point —
//! erased by taking the x coordinate. Both directions therefore derive the
//! same key from nothing but chain-visible data plus their own seed: the
//! sender re-reads sent notes after a wipe (peer = the tx's dust-output key),
//! the recipient reads received ones (peer = the tx's input key).
//!
//! AAD binds direction and note identity: `sender_x || recipient_x ||
//! outpoint` — a sealed body replayed from a different sender address, to a
//! different recipient, or under another outpoint fails authentication.
//! PLAN-pnte-redesign.md (2026-08-11) rebinds this from the old `note_id(4)`
//! (a field that no longer exists on-chain — the note id IS the txid, which
//! can't be known before signing) to `outpoint(36)` = the tx's FIRST
//! input's prevout, serialized exactly as it appears on the wire (txid in
//! internal/little-endian order || vout as u32-LE): known before signing,
//! and unique per tx (an outpoint is spent exactly once). Everything else
//! in this module — the ECDH derivation, DM_SALT/DM_INFO, the sealing
//! algorithm — is UNCHANGED.
//!
//! ---
//!
//! Multi-recipient directed notes (envelope `FLAG_MULTI`, 2..=255
//! recipients) — FROZEN alongside everything above. A single 32-byte
//! content key `K` (caller-supplied — see
//! `bundle::compose_directed_note_multi_with_change`/`_exact`; NEVER
//! generated, stored, or returned by this module) seals the note body ONCE,
//! under `multi_body_aad(sender_x, outpoint)` (68 bytes: sender_x(32) ||
//! outpoint(36) — no recipient binding, since the sealed body is identical
//! for every recipient). `K` itself is then wrapped once PER RECIPIENT
//! under that recipient's ordinary pairwise `dm_key`/`dm_aad` from above
//! (`wrap_i`), each wrap exactly [`WRAP_LEN`] = 72 bytes
//! (`crypt::SEAL_OVERHEAD` + 32) regardless of note length. Wrap order is
//! recipient OUTPUT order (envelope.rs / tx.rs).
//!
//! Recipient: derive the ONE pairwise key with the sender (unchanged from
//! the single-recipient case above), try the wrap at your own
//! recipient-output index first, then fall back to every other wrap (a
//! robustness fallback, not a protocol requirement — see
//! [`open_received_multi`]); on success, open the shared sealed body with
//! the recovered `K`. Sender re-read (wipe recovery, the `open_sent`
//! analog): derive the pairwise key with ANY recipient's output key
//! (index 0 preferred, else the first available — [`open_sent_multi`]),
//! unwrap, open the body.

use hkdf::Hkdf;
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::ProjectivePoint;
use sha2::Sha256;

use crate::keys::scalar_from_bytes;
use crate::taproot::lift_x;
use crate::{crypt, Error};

pub const DM_SALT: &[u8] = b"prime-graffito/dm/v1";
pub const DM_INFO: &[u8] = b"dm-enc/v1";

/// x coordinate of `tweaked_seckey · lift_x(peer_output_x)`.
pub fn ecdh_shared_x(
    tweaked_seckey: &[u8; 32],
    peer_output_x: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let a = scalar_from_bytes(tweaked_seckey).ok_or(Error::InvalidPrivateKey)?;
    let peer = lift_x(peer_output_x)?;
    let shared = (ProjectivePoint::from(peer) * a).to_affine();
    if bool::from(shared.is_identity()) {
        return Err(Error::PointAtInfinity);
    }
    Ok(shared.x().into())
}

/// FROZEN: HKDF-SHA256(DM_SALT, shared_x) expanded with DM_INFO.
pub fn dm_key(shared_x: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(DM_SALT), shared_x);
    let mut okm = [0u8; 32];
    hk.expand(DM_INFO, &mut okm).expect("32 bytes is a valid HKDF length");
    okm
}

/// FROZEN AAD layout: sender_output_x(32) || recipient_output_x(32) ||
/// outpoint(36) = the tx's FIRST input's prevout (txid little-endian ||
/// vout u32-LE, i.e. exactly how it's serialized on the wire).
pub fn dm_aad(sender_x: &[u8; 32], recipient_x: &[u8; 32], outpoint: &[u8; 36]) -> [u8; 100] {
    let mut aad = [0u8; 100];
    aad[..32].copy_from_slice(sender_x);
    aad[32..64].copy_from_slice(recipient_x);
    aad[64..].copy_from_slice(outpoint);
    aad
}

fn key_for(my_tweaked_seckey: &[u8; 32], peer_output_x: &[u8; 32]) -> Result<[u8; 32], Error> {
    Ok(dm_key(&ecdh_shared_x(my_tweaked_seckey, peer_output_x)?))
}

/// Sender side: seal a directed-private body for `recipient_x`.
pub fn seal_directed(
    my_tweaked_seckey: &[u8; 32],
    my_output_x: &[u8; 32],
    recipient_x: &[u8; 32],
    outpoint: &[u8; 36],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = key_for(my_tweaked_seckey, recipient_x)?;
    crypt::seal_aad(&key, &dm_aad(my_output_x, recipient_x, outpoint), plaintext)
}

/// Recipient side: open a directed-private body sent to me by `sender_x`.
pub fn open_received(
    my_tweaked_seckey: &[u8; 32],
    my_output_x: &[u8; 32],
    sender_x: &[u8; 32],
    outpoint: &[u8; 36],
    blob: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = key_for(my_tweaked_seckey, sender_x)?;
    crypt::open_aad(&key, &dm_aad(sender_x, my_output_x, outpoint), blob)
}

/// Sender re-reading their own sent note (wipe recovery: the recipient key
/// comes from the tx's dust output, visible in the sender's own history).
pub fn open_sent(
    my_tweaked_seckey: &[u8; 32],
    my_output_x: &[u8; 32],
    recipient_x: &[u8; 32],
    outpoint: &[u8; 36],
    blob: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = key_for(my_tweaked_seckey, recipient_x)?;
    crypt::open_aad(&key, &dm_aad(my_output_x, recipient_x, outpoint), blob)
}

// ---------------------------------------------------------------------
// Multi-recipient (FLAG_MULTI) — see the module doc's "---" section above
// for the full scheme. FROZEN once shipped, same as everything above it.
// ---------------------------------------------------------------------

/// Fixed size of one [`seal_multi`] wrap: `crypt::SEAL_OVERHEAD` (24-byte
/// nonce + 16-byte tag) around a 32-byte content key — always 72 bytes,
/// regardless of note text length.
pub const WRAP_LEN: usize = crypt::SEAL_OVERHEAD + 32;

/// FROZEN AAD for the shared sealed body: `sender_output_x(32) ||
/// outpoint(36)` — no recipient binding (the body is identical for every
/// recipient; per-recipient binding lives in each wrap's `dm_aad`).
pub fn multi_body_aad(sender_x: &[u8; 32], outpoint: &[u8; 36]) -> [u8; 68] {
    let mut aad = [0u8; 68];
    aad[..32].copy_from_slice(sender_x);
    aad[32..].copy_from_slice(outpoint);
    aad
}

/// Sender side: seal a multi-recipient private body. `content_key` is
/// caller-supplied (see the module doc) — used once to seal `plaintext`
/// under [`multi_body_aad`], then wrapped once per recipient (in
/// `recipients_x` order == output order) under each recipient's ordinary
/// pairwise `dm_key`. Returns `(wraps, sealed_body)`.
pub fn seal_multi(
    my_tweaked_seckey: &[u8; 32],
    my_output_x: &[u8; 32],
    recipients_x: &[[u8; 32]],
    outpoint: &[u8; 36],
    content_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<Vec<u8>>, Vec<u8>), Error> {
    let sealed_body =
        crypt::seal_aad(content_key, &multi_body_aad(my_output_x, outpoint), plaintext)?;
    let mut wraps = Vec::with_capacity(recipients_x.len());
    for r in recipients_x {
        let k_i = key_for(my_tweaked_seckey, r)?;
        wraps.push(crypt::seal_aad(&k_i, &dm_aad(my_output_x, r, outpoint), content_key)?);
    }
    Ok((wraps, sealed_body))
}

/// Recipient side: open a multi-recipient body sent to me by `sender_x`.
/// `my_index`, when known, is tried first (my own recipient-output
/// position in `wraps`); every other wrap is tried as a fallback (e.g. the
/// caller isn't sure which output is "mine" from the bundle alone) — NOT
/// a protocol requirement, just robustness, since only one wrap can ever
/// open under my pairwise key with `sender_x`.
pub fn open_received_multi(
    my_tweaked_seckey: &[u8; 32],
    my_output_x: &[u8; 32],
    sender_x: &[u8; 32],
    outpoint: &[u8; 36],
    wraps: &[Vec<u8>],
    sealed_body: &[u8],
    my_index: Option<usize>,
) -> Result<Vec<u8>, Error> {
    let key = key_for(my_tweaked_seckey, sender_x)?;
    let aad = dm_aad(sender_x, my_output_x, outpoint);
    let mut order: Vec<usize> = Vec::with_capacity(wraps.len());
    if let Some(i) = my_index {
        if i < wraps.len() {
            order.push(i);
        }
    }
    order.extend((0..wraps.len()).filter(|i| Some(*i) != my_index));
    for i in order {
        let Ok(k_bytes) = crypt::open_aad(&key, &aad, &wraps[i]) else { continue };
        let Ok(content_key) = <[u8; 32]>::try_from(k_bytes.as_slice()) else { continue };
        if let Ok(pt) = crypt::open_aad(&content_key, &multi_body_aad(sender_x, outpoint), sealed_body)
        {
            return Ok(pt);
        }
    }
    Err(Error::DecryptFailed)
}

/// Sender re-reading their own sent multi-recipient note (wipe recovery):
/// derive the pairwise key with ANY recipient output key — tried in
/// `recipients_x`/`wraps` order (index 0 preferred, else the first
/// available), matching [`open_sent`]'s single-recipient behavior.
pub fn open_sent_multi(
    my_tweaked_seckey: &[u8; 32],
    my_output_x: &[u8; 32],
    recipients_x: &[[u8; 32]],
    outpoint: &[u8; 36],
    wraps: &[Vec<u8>],
    sealed_body: &[u8],
) -> Result<Vec<u8>, Error> {
    for (i, r) in recipients_x.iter().enumerate() {
        let Some(wrap) = wraps.get(i) else { continue };
        let Ok(key) = key_for(my_tweaked_seckey, r) else { continue };
        let aad = dm_aad(my_output_x, r, outpoint);
        let Ok(k_bytes) = crypt::open_aad(&key, &aad, wrap) else { continue };
        let Ok(content_key) = <[u8; 32]>::try_from(k_bytes.as_slice()) else { continue };
        if let Ok(pt) =
            crypt::open_aad(&content_key, &multi_body_aad(my_output_x, outpoint), sealed_body)
        {
            return Ok(pt);
        }
    }
    Err(Error::DecryptFailed)
}
