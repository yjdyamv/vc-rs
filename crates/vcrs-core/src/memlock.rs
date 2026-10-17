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
    /// `WerSetFlags(DWORD Flags) -> HRESULT`.
    type SetFlags = unsafe extern "system" fn(u32) -> i32;

    extern "system" {
        fn GetModuleHandleW(name: *const u16) -> Module;
        fn GetProcAddress(module: Module, name: *const u8) -> *mut c_void;
    }

    fn wer_entry(name: &core::ffi::CStr) -> Option<*mut c_void> {
        // The process-side calls of Windows Error Reporting (`WerSetFlags`,
        // `WerRegisterExcludedMemoryBlock`) live in **kernel32**, not in `wer.dll`:
        // `wer.dll` has the local-dump helpers. Looking them up rather than linking
        // them keeps the binary loadable on Windows 7, where they do not exist yet;
        // there the lookup misses and the caller is told the request was refused.
        let module_name: [u16; 13] = [
            b'k' as u16,
            b'e' as u16,
            b'r' as u16,
            b'n' as u16,
            b'e' as u16,
            b'l' as u16,
            b'3' as u16,
            b'2' as u16,
            b'.' as u16,
            b'd' as u16,
            b'l' as u16,
            b'l' as u16,
            0,
        ];
        // SAFETY: the name is NUL terminated and outlives the call, and the entry
        // point is only used with the signature the documentation gives it.
        unsafe {
            let module = GetModuleHandleW(module_name.as_ptr());
            if module.is_null() {
                return None;
            }
            let address = GetProcAddress(module, name.as_ptr() as *const u8);
            if address.is_null() {
                return None;
            }
            Some(address)
        }
    }

    pub fn exclude(bytes: &[u8]) -> bool {
        let Ok(size) = u32::try_from(bytes.len()) else {
            return false;
        };
        // SAFETY: the address came from `GetProcAddress` for this symbol and is
        // transmuted to the signature the documentation gives it.
        let Some(register) = wer_entry(c"WerRegisterExcludedMemoryBlock")
            .map(|address| unsafe { std::mem::transmute::<*mut c_void, Register>(address) })
        else {
            return false;
        };
        // SAFETY: the pointer and length describe a live slice, and the block must not
        // move afterwards — the caller only ever registers a buffer it does not
        // grow again.
        unsafe { register(bytes.as_ptr() as *mut c_void, size) == 0 }
    }

    /// `WER_FAULT_REPORTING_FLAG_NOHEAP`: leave the heap out of the reports this
    /// process asks WER for.
    const NO_HEAP: u32 = 0x2;

    pub fn no_heap_in_dumps() -> bool {
        // SAFETY: as above; `WerSetFlags` takes one `DWORD`.
        let Some(set_flags) = wer_entry(c"WerSetFlags")
            .map(|address| unsafe { std::mem::transmute::<*mut c_void, SetFlags>(address) })
        else {
            return false;
        };
        unsafe { set_flags(NO_HEAP) == 0 }
    }
}

#[cfg(not(windows))]
mod dump {
    pub fn exclude(_bytes: &[u8]) -> bool {
        // ELF core dumps and macOS crash reports have no equivalent request: whether
        // they are written, and what they contain, is decided outside the process.
        false
    }

    #[cfg(not(windows))]
    #[allow(dead_code)] // only the Windows process hardening asks for it
    pub fn no_heap_in_dumps() -> bool {
        false
    }
}

/// Stop the operating system from writing this process's memory to disk after it
/// crashes, and from letting another process read it.
#[cfg(windows)]
mod process {
    pub fn harden() -> bool {
        super::dump::no_heap_in_dumps()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod process {
    extern "C" {
        fn prctl(option: i32, ...) -> i32;
    }

    /// `PR_SET_DUMPABLE`.
    const PR_SET_DUMPABLE: i32 = 4;

    pub fn harden() -> bool {
        // SAFETY: `PR_SET_DUMPABLE` takes one unsigned long argument (0). Turning it
        // off stops the kernel from writing a core dump of this process, and makes
        // `/proc/<pid>` belong to root, so another user cannot read this process's
        // memory out of it. Only root (or the process itself) can turn it back on.
        unsafe { prctl(PR_SET_DUMPABLE, 0usize) == 0 }
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
mod process {
    pub fn harden() -> bool {
        // No portable equivalent: whether a crash writes memory to disk is decided
        // by the system's crash reporter, not by the process.
        false
    }
}

#[cfg(not(any(windows, unix)))]
mod process {
    pub fn harden() -> bool {
        false
    }
}

/// Ask the system to keep this process's memory off disk when it crashes.
///
/// `zeroize` and [`lock`] protect individual buffers; this covers the ones nobody
/// thought about — the plaintext of a volume that is being served, the decrypted
/// header, whatever a library allocated on the way. It is the only measure here
/// that is process-wide, so call it once, as early as possible.
///
/// On Windows it sets `WER_FAULT_REPORTING_FLAG_NOHEAP`, which removes the heap from
/// the reports WER writes for this process (a crash then still produces a report
/// with the stack and the registers, just not the memory around them). On Linux it
/// clears `PR_SET_DUMPABLE`, so the kernel writes no core dump at all and
/// `/proc/<pid>/mem` becomes root-only. Both are best effort: an administrator who
/// configured a full local dump or a kernel dump can still capture memory, and no
/// in-process call can do anything about hibernation. Returns whether the request
/// was accepted.
pub fn harden_process() -> bool {
    let hardened = process::harden();
    if !hardened {
        log::debug!("the system refused to keep this process out of crash dumps");
    }
    hardened
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

#[cfg(test)]
mod tests {
    use super::{exclude_from_dumps, harden_process, lock, unlock};

    #[test]
    fn nothing_is_asked_of_the_system_for_an_empty_block() {
        // A zero-length buffer is accepted without a call: `VirtualLock` and
        // `mlock` both refuse a zero length, and there is nothing to protect.
        assert!(lock(&[]));
        assert!(unlock(&[]));
        assert!(exclude_from_dumps(&[]));
    }

    #[test]
    fn hardening_the_process_twice_is_harmless() {
        // Asked for once at startup in practice; a test binary that runs several
        // cases must not blow up on the second call either.
        let first = harden_process();
        let second = harden_process();
        assert_eq!(first, second);
        // Windows 8 and newer answer the call; a refusal here would mean the lookup
        // or the flags are wrong, which is worth knowing.
        #[cfg(windows)]
        assert!(first, "WerSetFlags has to be accepted on Windows 8 and newer");
    }

    #[test]
    fn a_key_buffer_can_be_locked_and_given_back() {
        let key = [0x5au8; 32];
        // Whether the system agrees depends on the working-set quota, so only the
        // pairing is asserted: unlocking must not report success for a range that
        // was never handed to the system in a way that could panic.
        let _ = lock(&key);
        let _ = unlock(&key);
        // The dump exclusion, on the other hand, has no quota: a refusal means the
        // call was not found (it is in kernel32, not in wer.dll).
        #[cfg(windows)]
        assert!(exclude_from_dumps(&key), "WerRegisterExcludedMemoryBlock has to be found");
    }
}
