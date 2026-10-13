# Can Dokany 2.x mount a raw block device from Rust? (Dokan + `dokan`/`dokan-sys` 0.3.1)

**Date:** research pass for the `vc-rs` mounting milestone
**Scope:** Windows x64, Rust `x86_64-pc-windows-msvc`, Dokany driver 2.3.1 installed, crate
`dokan 0.3.1+dokan206` / `dokan-sys 0.3.1+dokan206` (bundled Dokany source 2.0.6).

---

## 1. VERDICT

**No. Dokany 2.x cannot mount a raw block device.** Dokany is a *user-mode filesystem*
framework (the FUSE equivalent for Windows). Its entire user-mode surface is the
`DOKAN_OPERATIONS` callback table for named files/directories — the kernel driver is the
filesystem driver, so Windows will never see an unformatted volume that it can `format`
with NTFS/FAT. There is **no** `DokanCreateDiskDevice`, **no**
`DOKAN_DISK_DEVICE_INFORMATION`, and no "mount as PhysicalDrive" API in the user-mode
library, in any Dokany 2.x release.

To expose a formattable plaintext block device to Windows you must either (a) write a
kernel-mode driver (StorPort virtual miniport / disk function driver), or (b) use an
*existing Microsoft kernel driver* as the block front-end (VHD/VHDX via `vhdmp.sys`, or
iSCSI via the built-in initiator `msiscsi.sys`) with your decrypted bytes served on top.
Without a kernel driver the only realistic option is (c) implement the filesystem
(NTFS/FAT) yourself in user mode behind `DOKAN_OPERATIONS`.

Everything below is the evidence for that verdict.

---

## 2. WHAT EXISTS IN THE RUST BINDINGS (and what does not)

`dokan-sys` 0.3.1+dokan206 is **hand-written FFI**, not bindgen output, and it only wraps
the user-mode library `dokan2.dll` (bundled Dokany source version `DOKAN_VERSION 206`).

Bundled crate path (all file:line refs below):
`C:/Users/yuan/.cargo/registry/src/mirrors.ustc.edu.cn-38d0e5eb5da2abae/dokan-sys-0.3.1+dokan206/`

Exported user-mode functions — the complete `extern "stdcall"` block, **`src/lib.rs:316-372`**:

```
DokanInit, DokanShutdown, DokanMain, DokanCreateFileSystem, DokanIsFileSystemRunning,
DokanWaitForFileSystemClosed, DokanCloseHandle, DokanUnmount, DokanRemoveMountPoint,
DokanIsNameInExpression, DokanVersion, DokanDriverVersion, DokanResetTimeout,
DokanOpenRequestorToken, DokanGetMountPointList, DokanReleaseMountPointList,
DokanMapKernelToUserCreateFileFlags, DokanNotifyCreate/Delete/Update/XAttrUpdate/Rename,
DokanNtStatusFromWin32, DokanUseStdErr, DokanDebugMode, DokanSetDebugMode
```

- **No** `DokanCreateDiskDevice`, `DokanMountDisk`, or anything disk/block related.
- `DOKAN_OPERATIONS` — `src/lib.rs:123-291` — is the filesystem callback set:
  `ZwCreateFile, Cleanup, CloseFile, ReadFile, WriteFile, FlushFileBuffers,`
  `GetFileInformation, FindFiles, FindFilesWithPattern, SetFileAttributes, SetFileTime,`
  `DeleteFile, DeleteDirectory, MoveFile, SetEndOfFile, SetAllocationSize, LockFile,`
  `UnlockFile, GetDiskFreeSpace, GetVolumeInformation, Mounted, Unmounted,`
  `GetFileSecurity, SetFileSecurity, FindStreams`. Every I/O callback takes a **`FileName`
  (LPCWSTR path)** and a byte `Offset` — there is no "volume handle -> sector" callback.
- `DOKAN_OPTIONS` — `src/lib.rs:59-75` — has `MountPoint, UNCName, Timeout,`
  `AllocationUnitSize, SectorSize, VolumeSecurityDescriptor...`. No disk-device selector.
- `DOKAN_MOUNT_POINT_INFO` — `src/lib.rs:305-314` —
  `{ Type, MountPoint[260], UNCName[64], DeviceName[64], SessionId, MountOptions }`.
  `DeviceName` is an *output* describing the driver's `\Device\Volume{GUID}` object; it is
  not a request to mount a raw device.
- Only reference to a disk function in the whole bundled tree: kernel-only
  `src/dokany/sys/dokan.h:1067 DokanCreateDiskDevice(__in PDRIVER_OBJECT DriverObject, __in ULONG MountId, ...)`.
- The user-mode DLL export list `src/dokany/dokan/dokan.def` (LIBRARY `dokan2`) matches
  the Rust extern block exactly — no disk entry point.
- `DOKAN_DISK_DEVICE_INFORMATION` **does not exist anywhere** in the bundled Dokany 2.0.6
  source (searched the entire tree).

The safe `dokan` crate (path `.../dokan-0.3.1+dokan206/`) exposes only this filesystem
API: `FileSystemHandler` trait (`src/file_system_handler.rs:37`, with `create_file:49`,
`cleanup:79`, `read_file:112`, `write_file:134`), `FileSystemMounter` (`src/file_system.rs:193`),
`FileSystemMounter::mount()` (`src/file_system.rs:265` -> `DokanCreateFileSystem` and then
blocks), and `MountFlags` (`src/file_system.rs:36`). `MountFlags` offers
`NETWORK, REMOVABLE, MOUNT_MANAGER, WRITE_PROTECT, ...` — **no disk/block flag**.

---

## 3. WHY "DOKANY DISK DEVICE" IS NOT A RAW BLOCK DEVICE

Dokany *does* create a "disk device" object, but it is a *presentation* detail of a
filesystem mount, not a raw sector device:

- `src/dokany/sys/dokan.h:60` — `#define DOKAN_DISK_DEVICE_NAME L"\Device\Volume"`.
- `src/dokany/sys/init.c:608 DokanCreateGlobalDiskDevice(...)` — global FS disk device.
- `src/dokany/sys/init.c:912 DokanCreateDiskDevice(...)` — per-mount device object
  `\Device\Volume{GUID}`; called from `src/dokany/sys/event.c:920` when a **filesystem**
  mount starts (`event.c:810 case DOKAN_DISK_FILE_SYSTEM:`, enum at
  `src/dokany/sys/public.h:110 #define DOKAN_DISK_FILE_SYSTEM 0`).
- `src/dokany/sys/device.c:76 DiskDeviceControl(...)` only answers *geometry* IOCTLs;
  `src/dokany/sys/device.c:597 case IOCTL_STORAGE_GET_MEDIA_TYPES_EX:`. User-mode
  `ReadFile`/`WriteFile` are never invoked as raw sector I/O on the volume.

This "disk device support" was introduced in **Dokany 0.8.0** (`src/dokany/CHANGELOG.md:586`,
commit `08b09a3910dbac0e902a81ad9e9ae1a06d4a6d90`): *"`IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`
and `IOCTL_STORAGE_GET_MEDIA_TYPES_EX` disk device IOCTL"*. It makes Windows treat a
Dokan filesystem volume as a disk (so `chkdsk`, volume properties, etc. work) — it does
**not** let you serve sectors, and Windows will not format it with NTFS because Dokany
*already is* the filesystem on that volume.

---

## 4. EXTERNAL AUTHORITATIVE EVIDENCE

- **Maintainer, issue #564 "provide option mount img as PHYSICALDRIVE"** (closed),
  @Liryna, 2017-08-23:
  > "Unfortunately this is not possible by default with dokany but you can create a
  > file system using Dokany that would translate the Img file into the FS."
  https://github.com/dokan-dev/dokany/issues/564
- **Issue #52 "Using Dokan as a Raw Disk"** (closed) — @Maxhy:
  > "Loop device is not the purpose of Dokan and is now natively supported on Windows since 7"
  https://github.com/dokan-dev/dokany/issues/52
- **Issue #627 "Support physical disk mirror"** (closed 2020 for inactivity) — the
  physical-disk/ImDisk path was never integrated.
  https://github.com/dokan-dev/dokany/issues/627
- **PR #746 "Feature/vhdx attach supporting"** — `state=closed, merged=false, merged_at=null`.
  It proposed exactly the VHD(X) indirection (create a VHDX on a Dokan filesystem, then
  attach it so Windows sees a disk) and was **never merged**.
  https://github.com/dokan-dev/dokany/pull/746
- **Issue #524** (FUSE/LUKS use case) — same answer: Dokany exposes files, so the
  contained filesystem must be handled by the application.
  https://github.com/dokan-dev/dokany/issues/524
- Wiki `Unsupported.md` lists the only alternatives as kernel-mode mechanisms
  (MiniFilter, Network Mini-Redirector, ...) or non-free user-mode FS SDKs — no raw-block
  option. https://github.com/dokan-dev/dokany/wiki/Unsupported
- Dokany repo `samples/` contains only `dokan_memfs`, `dokan_mirror`, `fuse_mirror` — no
  disk-device sample; `documentations/mainpage.md` documents only the filesystem API.

---

## 5. IF WE NEED A REAL FORMATTABLE BLOCK DEVICE — OPTIONS

| Option | Kernel driver? | Notes |
|---|---|---|
| Dokany disk device | **No raw block** | Only geometry IOCTLs; filesystem stays Dokany. Not usable. |
| **VHD/VHDX + `vhdmp.sys`** | No *custom* driver (Microsoft's) | Create a fixed VHD/VHDX whose bytes are served by a Dokan/WinFsp filesystem (1 file = the disk image), then `Mount-VHD`/`AttachVirtualDisk`. `vhdmp.sys` is present (`C:/Windows/System32/drivers/vhdmp.sys`, 1,076,600 bytes) and gives Windows a real disk it can partition and `format` NTFS/FAT. Reads/writes to the file round-trip through the user-mode FS, so decrypt on read / encrypt on write. Convoluted and extra copy, but **no kernel code of ours**. This is PR #746's approach. |
| **iSCSI target (user-mode) + built-in Windows initiator** | No *custom* driver (Microsoft's `msiscsi.sys`) | Run an iSCSI target in-process (Rust) on 127.0.0.1 exporting one LUN backed by decrypted sectors; connect with the built-in Microsoft iSCSI Initiator. Windows sees a real disk (`\.\PhysicalDriveN`) it can format NTFS. `msiscsi.sys` is present (`C:/Windows/System32/drivers/msiscsi.sys`); service `msiscsi` is installed (currently STOPPED). No custom kernel driver. |
| WinFsp | Yes (WinFsp's own, 3rd-party) | Also a **filesystem** framework; does not expose raw block devices. Not installed here (`sc query WinFsp` -> error 1060). |
| StorPort virtual miniport (VSP) | **Yes, custom** | The "proper" way to expose a block device. Requires a signed kernel driver. `storport.sys` present. |
| Disk function/filter driver (e.g. ImDisk-style) | **Yes, custom** | Requires a signed kernel driver. |

**Bottom line:** no user-mode-only path exposes a raw formattable device directly. The two
no-custom-kernel-driver workarounds both re-introduce a Microsoft block driver
(`vhdmp.sys` or `msiscsi.sys`) and are significantly more complex than the fallback below.

**Fallback (recommended for `vc-rs`):** implement the filesystem in user mode behind
`DOKAN_OPERATIONS` (our own minimal FAT or NTFS read/write). This is what the Dokany
maintainer recommends and the only approach that keeps everything in user mode. Our
existing raw-sector decrypt layer stays; we add a filesystem interpretation layer on top
and map `read_file`/`write_file`/`create_file`/`cleanup` to it.

---

## 6. INSTALLATION STATE ON *THIS* MACHINE

Dokan is **already installed and running**:

```
winget list --name Dokan
  Name                           Id               Version         Source
  Dokan Library 2.3.1.1000 (x64) dokan-dev.Dokany 2.3.1.1000      winget

sc query dokan2
  TYPE  : 2  FILE_SYSTEM_DRIVER   STATE : 4  RUNNING

C:/Windows/System32/dokan2.dll        (559,728 bytes)
C:/Windows/System32/dokanfuse2.dll    (589,936 bytes)
C:/Windows/System32/dokannp2.dll      (452,208 bytes)
C:/Program Files/Dokan/DokanLibrary-2.3.1/{dokan2.dll, dokanctl.exe,
  driver/dokan2.sys, driver/dokan.inf, driver/dokan2.cat, x86/, ...}
```

Notes:
- The winget id is **`dokan-dev.Dokany`** (moniker `dokany`). Installer URL
  `https://github.com/dokan-dev/dokany/releases/download/v2.3.1.1000/Dokan_x64.msi`
  (SHA256 `69ff8cb37bfec3a75921c85ffd1c6370b50a9ec4ecef2cf3a009d488dcbf5465`).
  `winget search --id Dokan.Dokan` finds nothing — use `dokan-dev.Dokany`.
- The installed MSI provides **runtime only**: no `dokan2.lib` and no `dokan.h`
  (`find "C:/Program Files/Dokan" -iname '*.lib' -o -iname '*.h'` -> empty). So the crate's
  `DokanLibrary2_LibraryPath_x64` fast-path has no import library to point at here.
- Reinstall/upgrade: `winget install --id dokan-dev.Dokany -e --accept-package-agreements`
  (needs admin / UAC). The release driver is signed, so **no test-signing needed**; only the
  *debug* `DokanSetupDbg*.exe` requires test-signing/secure-boot adjustments. A reboot is
  typically required after install/uninstall.

---

## 7. MINIMUM RUST VERSION, build.rs BEHAVIOUR, CAVEATS

**MSRV:** neither crate declares `rust-version`; both are `edition = "2021"` -> Rust >= 1.56.
Built fine here with `rustc 1.98.1`.

**`dokan-sys/build.rs`** (authoritative):
1. Compiles + runs `src/generate_version.c` (needs a C compiler; MSVC or GCC) to derive
   the Dokan version and asserts it matches the crate's `+dokanNNN` suffix.
2. If env **`DokanLibrary2_LibraryPath_{x86|x64}`** is set -> only adds
   `cargo:rustc-link-search=native=<that dir>` (expects `dokan2.lib` there). Dokany's
   installer *used* to set this automatically (per dokan-rust README). Not set here and no
   `.lib` exists, so this branch does not apply.
3. Else it **builds `dokan2.dll` + `dokan2.lib` from the bundled Dokany source**
   (`cc` crate -> MSVC `cl.exe`/`link.exe`; `/DEF:.../dokan.def`; links advapi32/shell32/user32),
   then `cargo:rustc-link-lib=dylib=dokan2`.
4. `DOKAN_DLL_OUTPUT_PATH` (optional) copies the built DLL to a directory (to ship next to
   the exe).
5. There is **no `DOKAN_PATH`** env var — that name is not used by this crate.

**Verified build:** a throwaway crate depending on `dokan`/`dokan-sys` 0.3.1 compiled
successfully with `cargo build --target x86_64-pc-windows-msvc` in **18.3 s** (no admin
needed for the *build*). `cl.exe`/`link.exe` are not on `PATH`, but VS 18 Community is
installed (`C:/Program Files/Microsoft Visual Studio/18/Community/...`) and the `cc` crate
auto-detects it — no Developer Command Prompt required.

**Runtime caveat (important):** the crate's README warns the *linked import library* and
the *runtime DLL* versions should match. We linked a 2.0.6-generated import lib but the
machine loads `C:/Windows/System32/dokan2.dll` (2.3.1). It currently works because the
2.x exports are stable, but this mismatch should be pinned down for production. Observed
from a smoke test:
```
dokan::init();
dokan::get_lib_version()    // raw 0x000000E7 = 231 -> DokanVersion (2.3.1 scheme major*100+minor*10+rev)
dokan::get_driver_version() // raw 0x00000190 = 400 -> DokanDriverVersion
```

Other caveats:
- Mounting requires the `dokan2` service RUNNING (it is) and normally **admin rights** to
  assign a drive letter / mount point. A normal (non-admin) shell may mount onto an NTFS
  **folder** mount point, but `MOUNT_MANAGER` drive-letter assignment and network mounts
  need elevation. The *build* does not need admin; the *mount* generally does.
- Only x86/x64 Windows targets are supported (`build.rs` panics on other
  `CARGO_CFG_TARGET_ARCH`).
- Dokany does not support `FSCTL` (wiki `Unsupported.md`).

---

## 8. THE API WE ACTUALLY HAVE (filesystem mount, not a disk)

Minimal shape of a Dokany mount (this is the entire surface; there is no disk variant):

```rust
use dokan::{FileSystemHandler, FileSystemMounter, MountOptions, MountFlags, init, shutdown};

struct VcFs { /* opens decrypted sectors internally */ }

impl<'c, 'h> FileSystemHandler<'c, 'h> for VcFs {
    type Context = ();
    fn create_file(&'h self, file_name: &U16CStr, /* ... */ info: &mut OperationInfo<'c,'h,Self>)
        -> OperationResult<CreateFileInfo<()>> { /* ... */ }
    fn read_file(&'h self, file_name: &U16CStr, offset: i64, buffer: &mut [u8], /* ... */)
        -> OperationResult<u32> { /* decrypt + copy bytes for this FILE */ }
    fn write_file(&'h self, file_name: &U16CStr, offset: i64, buffer: &[u8], /* ... */)
        -> OperationResult<u32> { /* encrypt + store */ }
    // cleanup/close_file/get_file_information/find_files/...
}

init();
let opts = MountOptions { flags: MountFlags::empty(), ..Default::default() };
let mut mounter = FileSystemMounter::new(&fs, widestring::U16CStr::from_str("V:").unwrap(), &opts);
let _fs = mounter.mount()?;   // blocks; calls DokanCreateFileSystem
shutdown();
```

`ReadFile`/`WriteFile` here receive a **file path** and a byte offset inside that file,
never a raw volume sector. There is no `DokanCreateDiskDevice` to call.

---

## 9. REFERENCES (source of truth)

Bundled Dokany 2.0.6 (read-only crates.io mirror):
`C:/Users/yuan/.cargo/registry/src/mirrors.ustc.edu.cn-38d0e5eb5da2abae/dokan-sys-0.3.1+dokan206/`
- `src/lib.rs:59` DOKAN_OPTIONS | `:123` DOKAN_OPERATIONS | `:305` DOKAN_MOUNT_POINT_INFO | `:316` extern fns
- `src/dokany/dokan/dokan.def` (dokan2.dll exports) | `src/dokany/dokan/dokan.h:59` DOKAN_VERSION 206
- `src/dokany/sys/dokan.h:60,1067` | `src/dokany/sys/public.h:110` | `src/dokany/sys/init.c:608,912`
- `src/dokany/sys/event.c:810,920` | `src/dokany/sys/device.c:76,597` | `src/dokany/CHANGELOG.md:586`
- `src/generate_version.c` | `build.rs`

`dokan` crate:
`C:/Users/yuan/.cargo/registry/src/mirrors.ustc.edu.cn-38d0e5eb5da2abae/dokan-0.3.1+dokan206/`
- `README.md` | `src/file_system.rs:36,193,265` | `src/file_system_handler.rs:37,49,112,134`

External:
- https://github.com/dokan-dev/dokany/issues/52 (raw disk not the purpose of Dokan)
- https://github.com/dokan-dev/dokany/issues/564 (maintainer: not possible; build an FS)
- https://github.com/dokan-dev/dokany/issues/627 and https://github.com/dokan-dev/dokany/pull/746 (VHDX attach, not merged)
- https://github.com/dokan-dev/dokany/issues/524 (LUKS/whole-FS use case)
- https://github.com/dokan-dev/dokany/wiki/Unsupported
- https://github.com/dokan-dev/dokan-rust (DokanLibrary2_LibraryPath_{ARCH}, DOKAN_DLL_OUTPUT_PATH)
