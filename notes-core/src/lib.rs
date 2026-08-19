//! notes-core — UI-free library for prime-graffito.
//!
//! Everything needed to turn "text typed on the device" into a signed
//! bitcoin transaction carrying that text in OP_RETURN outputs, and to turn
//! a companion-produced sync bundle back into readable notes: key
//! derivation from the app seed, the PNTE envelope, XChaCha20-Poly1305
//! sealing, BIP341 key-path transaction construction and BIP340 signing.
//!
//! Host-testable: `cargo test -p notes-core`. Pure Rust throughout.

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod bundle;
pub mod confirm;
pub mod crypt;
pub mod decode;
pub mod dm;
pub mod envelope;
pub mod export;
pub mod fold;
pub mod keys;
pub mod psbt;
pub mod seeds;
pub mod sighash;
pub mod sign;
pub mod taproot;
pub mod tx;
pub mod wpkh;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Entropy,
    InvalidPrivateKey,
    InvalidPublicKey,
    TweakOutOfRange,
    PointAtInfinity,
    DecryptFailed,
    Envelope(&'static str),
    InsufficientFunds,
    PayloadTooLarge,
    RecipientNotTaproot,
    Psbt(&'static str),
    Derivation(&'static str),
    /// P2WPKH (BIP143) signing failures — `wpkh.rs`.
    Signing(&'static str),
    /// Raw-tx deserialization failures — `decode.rs` — and the confirm
    /// summarizer's own hex/shape checks (`confirm.rs`).
    Decode(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Entropy => write!(f, "entropy source failure"),
            Error::InvalidPrivateKey => write!(f, "invalid private key"),
            Error::InvalidPublicKey => write!(f, "invalid public key"),
            Error::TweakOutOfRange => write!(f, "taproot tweak out of range"),
            Error::PointAtInfinity => write!(f, "point at infinity"),
            Error::DecryptFailed => write!(f, "decryption failed"),
            Error::Envelope(m) => write!(f, "envelope: {m}"),
            Error::InsufficientFunds => write!(f, "insufficient funds"),
            Error::PayloadTooLarge => write!(f, "payload too large"),
            Error::RecipientNotTaproot => {
                write!(f, "private directed notes need a taproot (bc1p…) recipient")
            }
            Error::Psbt(m) => write!(f, "psbt: {m}"),
            Error::Derivation(m) => write!(f, "derivation: {m}"),
            Error::Signing(m) => write!(f, "signing: {m}"),
            Error::Decode(m) => write!(f, "decode: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Which chain we're on. Only affects address encoding (HRP); all crypto
/// and transaction formats are identical across networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet4,
    Signet,
    Regtest,
}

impl Network {
    pub fn hrp(self) -> bech32::Hrp {
        match self {
            Network::Mainnet => bech32::hrp::BC,
            // Testnet4 and signet share the tb HRP (BIP173/350).
            Network::Testnet4 | Network::Signet => bech32::hrp::TB,
            Network::Regtest => bech32::hrp::BCRT,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "mainnet" => Some(Network::Mainnet),
            "testnet4" | "testnet" => Some(Network::Testnet4),
            "signet" => Some(Network::Signet),
            "regtest" => Some(Network::Regtest),
            _ => None,
        }
    }
}

/// P2TR dust threshold (sats): below this a change output is not worth
/// creating and the remainder folds into the fee.
pub const DUST_LIMIT: u64 = 330;
