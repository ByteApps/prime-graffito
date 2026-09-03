//! Host tests for the KeyOS TRNG backend's post-conditions.
//!
//! `vendor/getrandom/src/xous.rs` is `cfg(keyos)`-only and never
//! compiles on the host, so its rules live in `trng_check.rs`, which is
//! compiled on every target. This test includes THAT FILE ITSELF — not a
//! copy — so the assertions run against the code the device ships.
//!
//! `cargo test -p getrandom` cannot reach it: the vendored crate enters
//! the build as a `[patch.crates-io]` path dependency, not a workspace
//! member, so cargo refuses to test it ("requires dev-dependencies and
//! is not a member of the workspace"). The `#[path]` include is the way.
#[path = "../vendor/getrandom/src/trng_check.rs"]
mod trng_check;
