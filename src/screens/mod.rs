//! Per-screen `impl App` blocks, one file per `ui/screens/<name>.slint`
//! (PLAN-graffito-arch.md phase 4b). Each file adds methods to the one
//! `App` type defined in main.rs; nothing here is a separate type.

mod accounts;
mod change;
mod coins;
mod compose;
mod confirm_sign;
mod contacts;
mod device_quantum_key;
mod home;
mod note;
mod notebooks;
mod notes;
mod pay_from;
mod private_keys;
mod public_keys;
mod quantum_keys;
mod recovery_words;
mod settings;
mod signed;
mod sweep;
mod sync;
