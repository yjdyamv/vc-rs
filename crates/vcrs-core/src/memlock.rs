//! Ask the operating system to keep key material out of the page file.
//!
//! `zeroize` handles one half of the "secrets in memory" problem: the bytes are
//! overwritten as soon as the value is dropped. It does not stop the operating
//! system from having written a *copy* of those bytes to disk while they were
//! alive, which on Windows means `pagefile.sys` and `hiberfil.sys`. That copy
//! outlives the process, and for a volume it contains the master key.
//!
//! Everything here is best effort. The calls can be refused (working-set quota, a
//! locked-page limit, a platform without them) and none of that is fatal, so the
//! result is a `bool` rather than an error: a volume that cannot lock its key is
//! still a working volume, just one whose key may have been paged out.
//!
//! Locked pages are also **not** hidden from a crash dump: a WER dump or a manual
//! dump of the process includes locked pages, because it copies the process's
//! memory rather than reading it back through the paging path. Nothing in user
//! space can stop an administrator from configuring such a dump; the only defence
//! on that side is not to crash with the key in memory.

#[cfg(windows)]
mod platform {
    extern "system" {
        fn VirtualLock(lpAddress: *mut core::ffi::c_void, dwSize: usize) -> i32;
        fn VirtualUnlock(lpAddress: *mut core::ffi::c_void, dwSize: usize) -> i32;
    }

    pub fn lock(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }
        // SAFETY: the pointer and length describe a live slice, and the call only
        // reads them. `VirtualLock` rounds the range out to whole pages.
        unsafe { VirtualLock(bytes.as_ptr() as *mut core::ffi::c_void, bytes.len()) != 0 }
    }

    pub fn unlock(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }
        // SAFETY: as above; unlocking a range that was never locked is refused by
        // the call rather than undefined.
        unsafe { VirtualUnlock(bytes.as_ptr() as *mut core::ffi::c_void, bytes.len()) != 0 }
    }
}

#[cfg(unix)]
mod platform {
    extern "C" {
        fn mlock(addr: *const core::ffi::c_void, len: usize) -> i32;
        fn munlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    }

    pub fn lock(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }
        // SAFETY: the pointer and length describe a live slice; `mlock` only reads
        // them. It can fail with ENOMEM/EPERM, which is why the caller treats the
        // result as advice.
        unsafe { mlock(bytes.as_ptr() as *const core::ffi::c_void, bytes.len()) == 0 }
    }

    pub fn unlock(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }
        // SAFETY: as above.
        unsafe { munlock(bytes.as_ptr() as *const core::ffi::c_void, bytes.len()) == 0 }
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    pub fn lock(_bytes: &[u8]) -> bool {
        false
    }

    pub fn unlock(_bytes: &[u8]) -> bool {
        false
    }
}

/// Keep `bytes` out of the page file, best effort. Returns whether it worked.
///
/// Call this once, after the buffer has been filled and its final address is
/// known. Unlike `zeroize` it does not have to be undone for correctness — the
/// operating system drops the lock when the pages are freed or the process exits —
/// so a leaked lock only costs the process its working-set budget.
pub fn lock(bytes: &[u8]) -> bool {
    let locked = platform::lock(bytes);
    if !locked {
        // Debug level: hitting a locked-page quota is not something the user can
        // act on, and it would otherwise be noise on a machine that limits it.
        log::debug!(
            "could not lock {} bytes of key material out of the page file",
            bytes.len()
        );
    }
    locked
}

/// Release a lock taken by [`lock`], best effort.
///
/// Nothing in this crate needs it — a key buffer is locked for the rest of the
/// process's life on purpose — but a caller that opens many volumes can use it to
/// give the working-set budget back.
pub fn unlock(bytes: &[u8]) -> bool {
    platform::unlock(bytes)
}
