# vc-rs — VeraCrypt-compatible volumes in Rust

A from-scratch Rust implementation of the **VeraCrypt volume format**, built to be
byte-level compatible with [VeraCrypt](https://veracrypt.fr) 1.26.x. Volumes created
here can be mounted by VeraCrypt, and volumes created by VeraCrypt can be read and
written here.

**当前状态 (short version):** 三项目标全部完成 —— (1) 格式完全兼容：全部 15 种加密算法组合
× 6 种 KDF 均通过测试，并与本机真实 VeraCrypt 1.26.29 双向验证（vc-rs 建的卷 VeraCrypt 能挂载，
VeraCrypt 建的卷 vc-rs 能读能写）；(2) 可创建卷（普通卷、隐藏卷、备份头、`--full` 随机填充）；
(3) 可挂载卷：`vcrs mount` 把解密后的数据区以 **iSCSI 目标**暴露给 Windows 自带的 Microsoft
iSCSI 发起程序，Windows 看到的是一块真实磁盘，于是**用 Windows 自己的 NTFS/exFAT/FAT 驱动**
格式化并读写（已实测：Windows 在此磁盘上格式化 NTFS 并写入文件，真实 VeraCrypt 挂载同一容器
能原样读到）。`vcrs format` 还能在卷内直接建 FAT 文件系统（不挂载也能用）。系统加密（预启动
认证）不在范围内。

* Crypto: [Botan](https://botan.randombit.net/) 3.13 via `botan-rs` (vendored static build).
* Mounting (Windows): an in-process **iSCSI target**; the in-box Microsoft iSCSI Initiator
  attaches it, so Windows' own signed NTFS/exFAT/FAT drivers do the filesystem work. The
  [iscsi-target](https://github.com/lawless-m/iscsi-crate) crate is vendored (patched) under
  `vendor/iscsi-target` — see [Mounting](#mounting-how-and-why).
* Not used: Dokany/WinFsp. They are *filesystem* frameworks, so they could only ever expose a
  filesystem we implement ourselves (FAT), never NTFS. See
  [Why not Dokany](#why-not-dokany); the removed implementation lives in the git history.

## Contents

| Path | What it is |
| --- | --- |
| `crates/vcrs-core` | The format: header serialization/encryption, KDFs, XTS mode, volume create/open, data I/O. No platform dependencies. |
| `crates/vcrs-mount` | Mount layer: FAT formatting inside the volume, plus an iSCSI target that presents the decrypted data area to Windows as a raw disk (any filesystem Windows supports). |
| `crates/vcrs-cli` | The `vcrs` command line tool. |
| `docs/` | Design notes: `mounting-options.md` (why iSCSI, what the alternatives were). |
| `docs/research` | Notes taken while reading the VeraCrypt sources (format layout, keyfiles, Dokan capabilities, Botan API). |
| `vendor/iscsi-target` | Local fork of the iSCSI target crate with Microsoft-initiator fixes (`PATCHES.md` documents each one). |
| `scripts/` | Build/cross-verification helpers (`msvc.sh` build wrapper, VeraCrypt round-trip scripts). |

## What is implemented

| VeraCrypt feature | Status |
| --- | --- |
| V2 normal volume create (primary + backup header, fake hidden header) | ✅ |
| Header format v4/v5 read, incl. legacy 512-byte-header volumes (v1) | ✅ |
| Master key, header CRC-32, key-area CRC-32, header byte order | ✅ |
| XTS mode, AES-256 / Serpent / Twofish / Camellia-256 / Kuznyechik | ✅ |
| All 15 cascades (`AES-Twofish-Serpent`, `Camellia-Kuznyechik`, …) | ✅ |
| KDFs: PBKDF2-HMAC-SHA-512/SHA-256/BLAKE2s/Whirlpool/Streebog (+ PIM) | ✅ |
| Argon2id (default and PIM-derived costs) | ✅ |
| Data area read/write, `--full` (randomized) formatting | ✅ |
| Hidden volumes (read/write both layouts, `create_hidden`) | ✅ |
| Dump / inspect headers, raw data read/write | ✅ |
| Backups headers usable for recovery | ✅ (open with `--backup`) |
| FAT filesystem creation inside the volume (`vcrs format`) | ✅ |
| Raw disk for Windows over iSCSI (`vcrs mount`): any filesystem Windows supports | ✅ (verified: Windows formatted NTFS through it, VeraCrypt read the files back) |
| Read-only disks, hidden volumes, `--disk-mode raw`, removable-media reporting | ✅ |
| Keyfiles (password + keyfile pool, files or a directory) | ✅ (VeraCrypt-made keyfile containers open; reverse direction checked by `scripts/vc-keyfile-test.ps1`) |
| System (pre-boot) encryption, in-place encryption of a system partition | ⬜ out of scope |

## Build

The vendored Botan build compiles its own C++, so **MSVC must be on the environment**.
Use the wrapper:

```bash
bash scripts/msvc.sh cargo build            # debug
bash scripts/msvc.sh cargo build --release  # optimized (recommended for big volumes)
bash scripts/msvc.sh cargo test             # unit + integration tests
```

`msvc.sh` invokes `vcvars64.bat` first. A plain `cargo build` also needs `python3`
(for Botan's `configure.py`) and `cl.exe` reachable; `python3` must exist in `PATH`
(Botan's build script hardcodes `python3`).

## Usage

```bash
# Create a 100 MiB container (AES-256 + XTS, PBKDF2-SHA-512, 500k iterations).
vcrs create secret.vc --size 100M --password "correct horse"

# Inspect it (prints the decrypted header) — add --backup for the backup header.
vcrs info secret.vc --password "correct horse"

# Optional: put a FAT filesystem inside (handy for small containers / other systems).
vcrs format secret.vc --password "correct horse" --label DATA

# Serve the volume as a raw iSCSI disk: Windows' own NTFS/exFAT driver does the filesystem
# work. Needs the two iscsicli commands from "Mounting" below to attach it (elevated).
vcrs mount   secret.vc --password "correct horse"      # --removable, --read-only, --disk-mode raw, …
vcrs dismount --iscsi iqn.2025-12.io.vcrs:secret

# Raw data access without mounting (offsets are inside the data area).
vcrs read  secret.vc --password "correct horse" --offset 0 --length 4096 --out head.bin
vcrs write secret.vc --password "correct horse" --offset 0 --from head.bin

# Keyfiles (`-k` is repeatable; a directory means "all files in it", like VeraCrypt):
vcrs create secret.vc --size 100M --password "correct horse" -k usb.key
vcrs info   secret.vc --password "correct horse" -k usb.key
vcrs info   secret.vc --password "correct horse" -k "D:\keyfiles"

# Cascades, other KDFs and PIM work too:
vcrs create paranoia.vc --size 200M --password pw --ea AES-Twofish-Serpent --prf Whirlpool --pim 30
```

`--password-stdin` (raw bytes) and `$VCRS_PASSWORD` are supported; prefer those over
`--password` for anything real, since command lines are visible to other processes.
`-k/--keyfile` may be repeated, and accepts a file or a directory of keyfiles; the
keyfile pool is mixed into the password exactly as VeraCrypt does (64-byte legacy pool
for passwords up to 64 bytes, 128-byte pool above that).
`RUST_LOG=debug` prints the trial-decryption details (which layout/PRF/EA matched).

## Compatibility evidence

Compatibility is not asserted, it is tested against a real VeraCrypt 1.26.29 install
(`scripts/vc-crosscheck.ps1`, `scripts/vc-crosscheck2.ps1`, `scripts/vc-hidden-test.ps1`,
`scripts/vc-iscsi-e2e.ps1`, `scripts/vc-keyfile-test.ps1`; everything that mounts with
VeraCrypt needs an elevated shell because VeraCrypt mounts through its kernel driver —
the iSCSI *target* itself needs no administration, only the initiator does).

| Direction | Test | Result |
| --- | --- | --- |
| Format | IEEE 1619 XTS-AES-256 known-answer vectors extracted from VeraCrypt's own `EncryptionTest.cpp` | ✅ byte-identical |
| VeraCrypt → vc-rs | VeraCrypt creates a volume, Windows writes a FAT16 filesystem with a file, vc-rs decrypts the whole data area and finds the file contents | ✅ |
| vc-rs → VeraCrypt | vc-rs writes that same filesystem into its own container; VeraCrypt mounts it and reads the file back | ✅ |
| vc-rs → VeraCrypt | 3-layer cascade (`AES-Twofish-Serpent`) container mounted by VeraCrypt | ✅ |
| vc-rs → VeraCrypt | Argon2id container mounted by VeraCrypt | ✅ |
| vc-rs → VeraCrypt | Container created with PIM 12 mounted by VeraCrypt | ✅ |
| Windows on a vc-rs volume | VeraCrypt mounts a vc-rs container, `format Z: /FS:FAT` succeeds, Explorer sees the label; vc-rs decrypts the newly formatted data area | ✅ |
| Double direction on one file | A vc-rs container mounted/formatted by Windows, then opened by vc-rs, then re-opened by VeraCrypt | ✅ |
| Hidden volume → VeraCrypt | VeraCrypt mounts the hidden volume vc-rs carved into a container, given only the hidden password (no switch selects it) | ✅ |
| Outer + hidden coexist | After the hidden volume was carved in, VeraCrypt still reads the outer FAT16 filesystem and its file | ✅ |
| Windows NTFS through iSCSI → VeraCrypt | Windows sees the vc-rs data area as a partitioned disk (MBR, 1 MiB synthetic prefix), formats NTFS on it, writes `from-windows.txt`, `sub/nested.txt` and a 1 MiB random file; real VeraCrypt mounts the same container and reads all three back (SHA-256 match) | ✅ (`scripts/vc-iscsi-e2e.ps1`, `RESULT: ALL OK`) |
| Persistence across sessions | Windows writes through the iSCSI disk, the disk is detached, then attached again: the files are still there (they live in the container) | ✅ |
| Windows NTFS through iSCSI, read by vc-rs | After Windows formatted the disk, `vcrs read` of data offset 0 shows the NTFS boot sector (`EB 52 90 "NTFS    "`) | ✅ |
| Removable-media reporting (`--removable`) | Windows classifies the disk as removable media (`Win32_DiskDrive.MediaType` = `Removable Media`, vs `Fixed hard disk media` for the internal NVMe disk), which is what makes exFAT show up in its format dialog | ✅ |
| VeraCrypt → vc-rs (keyfile) | VeraCrypt creates a container with `/keyfile`; `vcrs info -k` opens it and decrypts its FAT16 boot sector, while the same password without `-k` is rejected | ✅ |
| VeraCrypt → vc-rs (keyfile + 102-byte password) | Same with a password longer than 64 bytes, i.e. VeraCrypt's 128-byte keyfile pool layout | ✅ |
| vc-rs → VeraCrypt (keyfile) | `vcrs create -k` makes a container holding a VeraCrypt-created FAT16 image; VeraCrypt mounts it with `/keyfile` and reads `fromvc.txt` | ✅ (`scripts/vc-keyfile-test.ps1`) |
| Dokany-era checks (historical) | With the Dokany filesystem mount (removed since; code in git history): files written through the drive letter were read back by VeraCrypt, a file VeraCrypt wrote into the vc-rs-made FAT was read back through the mount, and the same held for hidden volumes | ✅ (`scripts/vc-dokan-crosscheck.ps1` = `ALL OK`, `scripts/vc-hidden-test.ps1` = `HIDDEN ROUND TRIP OK: True`, `FULL HIDDEN CHAIN OK: True`) |

Header encodings are also pinned by unit tests for CRC-32 (VeraCrypt's own self-test
value `0x91267E8A`), the header byte layout and the KDF parameters. Regression suite:
`crates/vcrs-core/tests/{ea_prf_matrix,hidden_volume,backup_header,xts_kat}.rs` (the matrix
test covers all 15 ciphers × 6 KDFs = 90 combinations, the backup test destroys the primary
header and recovers the volume from the backup copy) and
`crates/vcrs-mount/tests/{fat_in_volume,iscsi_device}.rs` (FAT format → write → reopen →
read with an assertion that no plaintext appears in the container; and the iSCSI device:
synthetic MBR, partition type/geometry, `raw` mode, read-only, stable disk signature, and
that writes into the synthetic prefix never reach the container).

## Mounting (how and why)

A VeraCrypt container holds a *bare* filesystem: its data area is one volume, not a
partitioned disk, and on Windows only a kernel filesystem driver can mount NTFS/exFAT.
So the mount layer has to give Windows a **block device**, and the only way to do that
from user mode — with no kernel driver of ours and no plaintext ever written to disk — is
to serve the decrypted sectors as an **iSCSI LUN**:

```text
Windows' own NTFS/exFAT/FAT driver  ──  SCSI READ(10)/WRITE(10)
      │
Microsoft iSCSI Initiator (msiscsi, in-box, signed)  ──  iSCSI over loopback TCP
      │
vcrs-mount iSCSI target            (iscsi-target crate, vendored+patched)
      │  512-byte sectors: LBA n → data offset n*512
      ▼
decrypted / re-encrypted volume data area  (vcrs-core)
```

Consequences:

* **Any filesystem Windows supports works** (NTFS, exFAT, FAT, ReFS…) because Windows'
  own drivers do the work. Nothing needs to be implemented here, and read *and* write
  come for free — Windows can even format the disk.
* The *storage* stays a genuine VeraCrypt container: only ciphertext reaches the disk,
  and our process is the only component we wrote for this path.
* The iSCSI target itself needs no administrator rights; the **initiator** does
  (`iscsicli`/Disk Management run elevated), exactly like VeraCrypt's own mounts.

Windows only mounts a filesystem that sits inside a **partition** of a disk, while the
container's data area starts at byte 0. `vcrs mount` therefore presents a disk that is
1 MiB larger than the data area and synthesises an MBR in front of it (the default
`--disk-mode partition`). That MBR exists only in memory: the container keeps its
VeraCrypt layout byte for byte, writes into the synthetic prefix are absorbed (so Windows
"initializing" the disk cannot corrupt anything), and the disk signature is derived from
the container's header salt so it stays stable across sessions. `--disk-mode raw` exposes
the bare data area instead (LBA 0 = data offset 0), which is what non-Windows initiators
and the tests use.

```powershell
# terminal 1 (normal rights): serve the volume — it prints the two commands below,
# with the IQN derived from the file name.
vcrs mount secret.vc -p "correct horse"                # add --removable / --read-only

# terminal 2 (elevated): attach it — a static target, then a normal login
cmd /c 'iscsicli AddTarget iqn.2025-12.io.vcrs:secret vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 "" "" 0 0'
iscsicli QLoginTarget iqn.2025-12.io.vcrs:secret
# → a disk "vc-rs VeraCrypt volume" appears. Format it (it starts out RAW, like a fresh
#   VeraCrypt container) and start using the drive letter:
Format-Volume -DriveLetter S -FileSystem NTFS -NewFileSystemLabel VCRS -Confirm:$false

# detach again (this takes the disk offline first, then logs the session out)
vcrs dismount --iscsi iqn.2025-12.io.vcrs:secret
```

Three things to know:

1. A *freshly created* container has no filesystem inside, so Windows asks to format the
   new disk; opening the drive letter before formatting fails with "the parameter is
   incorrect" (that is a RAW volume — exactly like a new VeraCrypt container).
2. `--removable` sets the SCSI removable-media bit. Windows only offers **exFAT** in its
   format dialogs for removable media, so that flag is how to get exFAT there (the
   container itself is unaffected; `Format-Volume -FileSystem exFAT` works either way).
   Verified: with the flag Windows reports the disk as `Removable Media`
   (`Win32_DiskDrive.MediaType`) instead of `Fixed hard disk media`.
3. `QAddTargetPortal` (a portal *scan*) does not work: the target library cannot finish
   the initiator's multi-PDU login during a discovery session. Use the static `AddTarget`
   + `QLoginTarget` pair above. Documented in `vendor/iscsi-target/PATCHES.md`.

The whole chain is covered by `scripts/vc-iscsi-e2e.ps1` (elevated), which creates a
container, serves it, logs in, checks the disk/MBR/partition geometry, formats NTFS
through it, writes a text file, a nested file and a 1 MiB random file (SHA-256 compared),
detaches, and finally has real VeraCrypt mount the same container and read all three files
back.

### Why not Dokany?

Dokany (and WinFsp) are *filesystem* frameworks: they forward file operations
(`CreateFile`/`ReadFile`/`FindFiles`…) to user mode, so using one means implementing the
filesystem that lives inside the volume. That is what `vcrs-mount` did in the earlier
milestone — FAT12/16/32 via the `fatfs` crate, exposed at a drive letter — and it worked
(and was cross-verified against VeraCrypt), but it has hard limits:

* **NTFS is out of reach**: no user-mode NTFS implementation exists for Windows (on Linux
  the equivalent situation is solved by NTFS-3G, which is why FUSE is viable there).
* Dokany is a **third-party kernel driver** that must be installed with administrator
  rights, and it is a filesystem-only interface, so it can never mount an arbitrary
  filesystem the way VeraCrypt's own driver does.
* On Linux the same trick VeraCrypt itself uses is available — its FUSE mode
  (`src/Driver/Fuse/FuseService.cpp`) exposes the decrypted volume as a single *file*
  (`/volume`, `/volume.dmg` on macOS) which you then attach with a **loop device** — but
  Windows has no equivalent (a user-mode process cannot turn a file into a block device).

The iSCSI path removes all of that: Windows' own drivers mount the filesystem, so any
filesystem works, including NTFS, and read *and* write come for free. Formatting a FAT
filesystem inside a container is still available (`vcrs format`) — it is simply no longer
a mount backend. The removed handler is `crates/vcrs-mount/src/fs_main.rs` in the git
history, should anyone want it back.

### Vendor patch list

`vendor/iscsi-target/` is a copy of the `iscsi-target` 1.0.0 crate (which was verified
only against Linux's open-iscsi) wired in with `[patch.crates-io]`. Three fixes were
needed for it to interoperate with the Microsoft initiator:

1. **Residual underflow/overflow on the final Data-In PDU** — Windows resets the
   connection whenever a command returns fewer bytes than the requested allocation
   length (e.g. `INQUIRY` VPD page 0: 8 bytes for 255 requested). RFC 7143 §11.4.5.2.
2. **SCSI status/response moved out of the `specific` array** into explicit BHS byte 2/3
   fields, and the residual count moved to `specific[24..28]` (it used to collide).
3. **Removable-media bit** made device-controlled (`ScsiBlockDevice::removable()`), the
   upstream hardcoded it to 0, which is why Windows hid exFAT.

Still unfixed upstream (documented, worked around): discovery sessions and the CRC32C
digest write path.

## Notes on passwords

VeraCrypt hashes the *raw password bytes* (plus an optional keyfile pool) and the whole
password can contain arbitrary bytes. The safe `botan-rs` KDF wrappers take a `&str`
and let Botan `strlen()` it, which cannot express that, so `vcrs-core` calls
`botan_pwdhash` directly with an explicit length. A hand-written PBKDF2 implementation
is kept behind `#[cfg(test)]` and cross-checked against Botan's own for the same
parameters.

Secrets held in memory (`master_key` in `VolumeHeader`, derived header keys) are
`zeroize`d where practical.
