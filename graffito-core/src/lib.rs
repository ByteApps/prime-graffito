//! Shared Graffito policy: UI-free product decisions rendered identically
//! by every shell (the KeyOS app in this repo and the graffito Mac/mobile
//! app's `app-core`). Host-testable: `cargo test -p graffito-core`.
//!
//! First module: [`seclabel`] — the compose screen's Security copy and
//! quantum-resistance verdict. See PLAN-graffito-arch.md (phase 2) at the
//! workspace level for the move sequence that follows.

pub mod seclabel;
