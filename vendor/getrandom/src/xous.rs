//! KeyOS TRNG backend: fills from the os `trng` server over a
//! `MutableBorrow` memory message.
//!
//! Vendored from the KeyOS repo (imports/getrandom @ v1.2.1) and then
//! hardened — see `trng_check` for the reasoning. Two behavioural
//! differences from the upstream copy, both deliberate:
//!
//! 1. **It can fail.** Upstream returned `Ok(())` unconditionally and
//!    `.unwrap()`ed the syscalls, so a TRNG that produced nothing was
//!    indistinguishable from one that worked, and every caller's
//!    entropy-error path was dead code on device. Every failure is now
//!    a `getrandom::Error`, which the apps already map to their own
//!    `Error::Entropy`.
//! 2. **The result is verified.** The lent page is stamped with a
//!    sentinel before the borrow, and a result that still holds it — in
//!    full or in its tail — is an error rather than a key.
//!
//! Keep this file byte-identical across every app that vendors it.

use core::num::NonZeroUsize;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use crate::error::Error;
use crate::trng_check::{looks_unfilled, words_for, write_sentinel};

/// `FillTrng` — the opcode is baked into this file by agreement with
/// KeyOS `xous/trng/src/api.rs`, which notes that these numbers are
/// partially baked into `getrandom`.
const OPCODE_FILL_TRNG: usize = 1;

static TRNG_CONN: AtomicU32 = AtomicU32::new(0);

/// Connect to the TRNG server once, caching the connection id.
///
/// A failure here used to be `.expect("Can't connect to TRNG server")`.
/// Returning an error instead means an app can report "no entropy"
/// rather than dying mid-keygen — and, more to the point, that it can
/// never mistake a failed connection for a filled buffer.
fn trng_conn() -> Result<u32, Error> {
    let cached = TRNG_CONN.load(Ordering::SeqCst);
    if cached != 0 {
        return Ok(cached);
    }
    let sid = xous::SID::from_bytes(b"trng-server").ok_or(Error::KEYOS_TRNG_UNAVAILABLE)?;
    let conn = xous::connect(sid).map_err(|_| Error::KEYOS_TRNG_UNAVAILABLE)?;
    TRNG_CONN.store(conn, Ordering::SeqCst);
    Ok(conn)
}

pub fn getrandom_inner(dest: &mut [u8]) -> Result<(), Error> {
    if dest.is_empty() {
        return Ok(());
    }
    let conn = trng_conn()?;
    fill_bytes(conn, dest)
}

fn fill_bytes(conn: u32, data: &mut [u8]) -> Result<(), Error> {
    let mut aligned_buffer = xous::map_memory(
        None,
        None,
        data.len().next_multiple_of(4096),
        xous::MemoryFlags::W,
    )
    .map_err(|_| Error::KEYOS_TRNG_SYSCALL)?;

    // Stamp BEFORE lending the page. A freshly mapped page reads as
    // zeros, so without this a server that never writes is
    // indistinguishable from one that returns a 32-byte zero key.
    write_sentinel(&mut aligned_buffer.as_slice_mut::<u8>()[..data.len()]);

    // `valid` counts u32s, not bytes — see `trng_check::words_for`.
    let valid = NonZeroUsize::new(words_for(data.len()));
    let sent = xous::send_message(
        conn,
        xous::Message::MutableBorrow(xous::MemoryMessage {
            id: OPCODE_FILL_TRNG,
            buf: aligned_buffer,
            offset: None,
            valid,
        }),
    );

    let result = match sent {
        Err(_) => Err(Error::KEYOS_TRNG_SYSCALL),
        Ok(_) => {
            let filled = &aligned_buffer.as_slice::<u8>()[..data.len()];
            if looks_unfilled(filled) {
                Err(Error::KEYOS_TRNG_UNFILLED)
            } else {
                data.copy_from_slice(filled);
                Ok(())
            }
        }
    };

    // Always give the page back, even on the failure paths — a leaked
    // mapping per failed draw would turn a recoverable entropy error
    // into an out-of-memory one. Scrub it first: on the success path it
    // holds a copy of live key material.
    aligned_buffer.as_slice_mut::<u8>()[..data.len()].fill(0);
    let unmapped = xous::unmap_memory(aligned_buffer);

    result.and_then(|()| unmapped.map_err(|_| Error::KEYOS_TRNG_SYSCALL))
}
