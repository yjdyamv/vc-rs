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
//! memory rather than reading it back through the paging path. [`exclude_from_dumps`]
//! asks Windows Error Reporting to leave one block out of every dump it takes, which
//! covers the ordinary "the program crashed, WER saved a dump" case; it does not stop
//! an administrator from configuring a dump tool that ignores the request, so a
//! machine where the key must never reach disk still needs a policy outside the
//! process (no local dumps, no hibernation).

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

/// Keep a block out of the crash dumps Windows Error Reporting writes.
#[cfg(windows)]
mod dump {
    use std::ffi::c_void;

    type Module = *mut c_void;
    /// `WerRegisterExcludedMemoryBlock(PVOID Address, DWORD Size) -> HRESULT`.
    type Register = unsafe extern "system" fn(*mut c_void, u32) -> i32;

    extern "system" {
        fn LoadLibraryW(name: *const u16) -> Module;
        fn GetProcAddress(module: Module, name: *const u8) -> *mut c_void;
    }

    fn register_fn() -> Option<Register> {
        // Windows Error Reporting lives in `wer.dll`; the call exists since Windows 8
        // and is simply absent on anything older, so it is looked up rather than
        // linked. The library is never unloaded: the registration has to outlive this
        // call.
        let name: [u16; 8] = [
            b'w' as u16,
            b'e' as u16,
            b'r' as u16,
            b'.' as u16,
            b'd' as u16,
            b'l' as u16,
            b'l' as u16,
            0,
        ];
        // SAFETY: the name is NUL terminated and outlives the call, and the entry
        // point is only used with the signature the documentation gives it.
        unsafe {
            let module = LoadLibraryW(name.as_ptr());
            if module.is_null() {
                return None;
            }
            let address = GetProcAddress(module, c"WerRegisterExcludedMemoryBlock".as_ptr() as *const u8);
            if address.is_null() {
                return None;
            }
            Some(std::mem::transmute::<*mut c_void, Register>(address))
        }
    }

    pub fn exclude(bytes: &[u8]) -> bool {
        let Ok(size) = u32::try_from(bytes.len()) else {
            return false;
        };
        let Some(register) = register_fn() else {
            return false;
        };
        // SAFETY: the pointer and length describe a live slice, and the block must not
        // move afterwards — the caller only ever registers a buffer it does not
        // grow again.
        unsafe { register(bytes.as_ptr() as *mut c_void, size) == 0 }
    }
}

#[cfg(not(windows))]
mod dump {
    pub fn exclude(_bytes: &[u8]) -> bool {
        // ELF core dumps and macOS crash reports have no equivalent request: whether
        // they are written, and what they contain, is decided outside the process.
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

/// Ask Windows Error Reporting to leave `bytes` out of any dump it writes.
///
/// The page-file lock does not help here: a dump copies the process's memory, so a
/// locked key is in it. This call does, for the dumps WER itself takes after a
/// crash (a manual dump or a configured `LocalDumps` key may ignore it, and other
/// operating systems have no equivalent).
///
/// `bytes` must be a buffer that is **not reallocated afterwards** — the registration
/// keeps the address, and a `Vec` that grows would leave it pointing at freed memory.
/// Call it once the buffer is final; registering the same block twice is harmless.
pub fn exclude_from_dumps(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let excluded = dump::exclude(bytes);
    if !excluded {
        log::debug!(
            "could not exclude {} bytes of key material from crash dumps",
            bytes.len()
        );
    }
    excluded
}
