//! Scalar plumbing and the app-seed key derivations.
//!
//! CONSENSUS-CRITICAL FOR RE-DERIVATION: the HKDF salt/info strings below
//! are baked into every note ever written — the wipe-recovery story
//! (PLAN-graffito.md) depends on re-deriving the identical identity key
//! and encryption key from `GetAppSeed` after a seed restore. NEVER change
//! them (same rule as prime-paper-wallet's backup-key derivation).
//!
//! GRAFFITO EPOCH (2026-08-18): the salts below were rebound from their
//! prime-chain-notes/chain-notes-app values as a deliberate crypto epoch
//! break — Sal's directive, accepted consequence: every note (self and
//! directed) sealed under the old salts is now permanently undecryptable,
//! and the old on-chain address history is orphaned (a wipe/restore now
//! derives different identity + encryption keys from the same app seed).
//! Nothing here is a compatibility constraint — there was no in-place
//! migration and none is planned.

use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::PrimeField;
use hkdf::Hkdf;
use k256::elliptic_curve;
use k256::{ProjectivePoint, Scalar};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::Error;

const KEY_SALT: &[u8] = b"prime-graffito/key/v1";
const ENC_SALT: &[u8] = b"prime-graffito/enc/v1";
/// Recovery-seed entropy salt (PLAN-graffito-seed-rotation.md). FROZEN
/// (post-epoch).
const SEED_SALT: &[u8] = b"prime-graffito/seed/v1";
/// The graffito (desktop app) shared enc rule, relocated here so both apps
/// share one code path (app-core delegates). NEVER change — every private
/// note composed by the graffito desktop app (and by bip86-scheme device
/// notebooks) depends on these exact strings. The desktop `graffito` repo
/// adopts this identical string as a separately-scoped follow-up (it is
/// NOT changed by this commit) — see the workspace report for that repo.
const ENC_APP_SALT: &[u8] = b"graffito/enc/v1";
const ENC_APP_INFO: &[u8] = b"note-enc/v1";

/// Parse 32 bytes as a scalar, rejecting 0 and values >= the curve order.
pub(crate) fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let ct = Scalar::from_repr((*bytes).into());
    if bool::from(ct.is_some()) {
        let s = ct.unwrap();
        if bool::from(s.is_zero()) {
            None
        } else {
            Some(s)
        }
    } else {
        None
    }
}

/// X-only public key plus `odd_y` flag for a private key.
pub fn xonly_pubkey(privkey: &[u8; 32]) -> Result<([u8; 32], bool), Error> {
    let k = scalar_from_bytes(privkey).ok_or(Error::InvalidPrivateKey)?;
    let point = (ProjectivePoint::GENERATOR * k).to_affine();
    let x: [u8; 32] = point.x().into();
    Ok((x, bool::from(point.y_is_odd())))
}

pub(crate) fn double_sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(Sha256::digest(data)));
    out
}

/// HASH160 (RIPEMD160(SHA256(data))) — the P2WPKH/P2PKH pubkey-hash step
/// (mirrors `bip32::Xprv::fingerprint`, which computes the same digest over
/// a compressed pubkey and truncates to 4 bytes; this keeps all 20).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&Ripemd160::digest(Sha256::digest(data)));
    out
}

/// Derive the notes identity private key from the app seed. Expands
/// HKDF-SHA256(KEY_SALT, app_seed, "identity/" || attempt_le32) and bumps
/// `attempt` until the 32 bytes are a valid scalar (first try in all but
/// ~1 in 2^128 cases). FROZEN — see module docs.
pub fn derive_identity_key(app_seed: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(KEY_SALT), app_seed);
    let mut attempt: u32 = 0;
    loop {
        let mut info = Vec::with_capacity(9 + 4);
        info.extend_from_slice(b"identity/");
        info.extend_from_slice(&attempt.to_le_bytes());
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("32 bytes is a valid HKDF length");
        if scalar_from_bytes(&okm).is_some() {
            return okm;
        }
        attempt += 1;
    }
}

/// Derive the note-content encryption key (XChaCha20-Poly1305, 32 bytes).
/// No scalar constraint — any 32 bytes are a valid AEAD key. FROZEN.
pub fn derive_encryption_key(app_seed: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(ENC_SALT), app_seed);
    let mut okm = [0u8; 32];
    hk.expand(b"note-enc/v1", &mut okm)
        .expect("32 bytes is a valid HKDF length");
    okm
}

/// Recovery-seed entropy for rotation `index` — the ★ step of the
/// recovery-seeds pipeline, the ONLY place the rotation index enters:
/// HKDF-SHA256(SEED_SALT, app_seed, "seed/" || index_le32). Everything
/// downstream (BIP-39 words → BIP-86 tree) is the standard pipeline.
/// One-way by construction: no words ever encode the app seed itself.
/// FROZEN — see module docs.
pub fn derive_seed_entropy(app_seed: &[u8; 32], index: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SEED_SALT), app_seed);
    let mut info = Vec::with_capacity(5 + 4);
    info.extend_from_slice(b"seed/");
    info.extend_from_slice(&index.to_le_bytes());
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("32 bytes is a valid HKDF length");
    okm
}

/// Note-encryption key for a BIP-86 leaf secret — the graffito desktop
/// app's FROZEN rule, identical for all its import formats, relocated
/// here so device bip86 notebooks and the app derive byte-identically.
/// FROZEN.
pub fn enc_key_from_leaf(leaf_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(ENC_APP_SALT), leaf_secret);
    let mut okm = [0u8; 32];
    hk.expand(ENC_APP_INFO, &mut okm).expect("32 bytes is a valid HKDF length");
    okm
}

/// Fresh 32 bytes of aux randomness for BIP340 signing.
pub fn generate_aux_rand() -> Result<[u8; 32], Error> {
    let mut aux = [0u8; 32];
    getrandom::getrandom(&mut aux).map_err(|_| Error::Entropy)?;
    Ok(aux)
}
