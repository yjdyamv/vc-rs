# vc-rs — VeraCrypt-compatible volumes in Rust

A from-scratch Rust implementation of the **VeraCrypt volume format**, built to be
byte-level compatible with [VeraCrypt](https://veracrypt.fr) 1.26.x. Volumes created
here can be mounted by VeraCrypt, and volumes created by VeraCrypt can be read and
written here.

**当前状态 (short version):** 三项目标全部完成 —— (1) 格式完全兼容：全部 15 种加密算法组合
× 6 种 KDF 均通过测试，并与本机真实 VeraCrypt 1.26.29 双向验证（vc-rs 建的卷 VeraCrypt 能挂载，
VeraCrypt 建的卷 vc-rs 能读能写）；(2) 可创建卷（普通卷、隐藏卷、备份头、`--full` 随机填充）；
(3) 可挂载卷：(a) `vcrs format` 在卷内建 FAT 文件系统，`vcrs mount` 通过 Dokany 挂成盘符，
经 Dokany 写入的文件真实 VeraCrypt 能读到，反之亦然；(b) `vcrs mount --raw` 把解密后的数据区
以 iSCSI 目标暴露给 Windows 自带的 Microsoft iSCSI 发起程序，Windows 看到的是一块真实磁盘，
可以用它自己的 NTFS/exFAT 驱动格式化并读写（已实测：Windows 在此磁盘上格式化 NTFS 并写入文件，
真实 VeraCrypt 挂载同一容器能原样读到）。系统加密（预启动认证）不在范围内。

* Crypto: [Botan](https://botan.randombit.net/) 3.13 via `botan-rs` (vendored static build).
* Mounting (Windows): [Dokany](https://dokan-dev.github.io/) via `dokan-rs` (`dokan-dev/dokan-rust`)
  for FAT volumes, and an iSCSI target (in-box Microsoft Initiator) for raw-block access to any
  filesystem Windows supports.  The [iscsi-target](https://github.com/lawless-m/iscsi-crate) crate
  is vendored (patched) under `vendor/iscsi-target`. Device layer: Botan 3.13 through
  `botan-rs`, statically built from source — no Botan install needed.

## Contents

| Path | What it is |
| --- | --- |
| `crates/vcrs-core` | The format: header serialization/encryption, KDFs, XTS mode, volume create/open, data I/O. No platform dependencies. |
| `crates/vcrs-mount` | Windows mount layer: a FAT filesystem inside the volume exposed as a drive letter through Dokany, plus an iSCSI target that gives Windows a raw disk (any filesystem) backed by the decrypted data area. |
| `crates/vcrs-cli` | The `vcrs` command line tool. |
| `docs/research` | Notes taken while reading the VeraCrypt sources (format layout, keyfiles, Dokan capabilities, Botan API). |
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
| FAT filesystem creation inside the volume + Dokany mount | ✅ (verified end-to-end against VeraCrypt) |
| Raw disk for Windows over iSCSI (`vcrs mount --raw`), any filesystem Windows supports | ✅ (verified: Windows formatted NTFS through it, VeraCrypt read the files back) |
| Keyfiles | ⬜ not implemented yet |
| System (pre-boot) encryption, in-place encryption of a system partition | ⬜ out of scope |
| Non-FAT filesystems behind Dokany (NTFS in user mode) | ⬜ not planned; use `--raw` (iSCSI) and let Windows' own NTFS driver do it |

## Build

The `dokan` dependency compiles bundled Dokany C++ sources and the vendored Botan
build compiles its own C++, so **MSVC must be on the environment**. Use the wrapper:

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

# Create a FAT filesystem inside it, then mount it as drive Z:.
vcrs format secret.vc --password "correct horse" --label DATA
vcrs mount  secret.vc --password "correct horse" --mount-point Z:
vcrs dismount Z:

# Serve the volume as a raw iSCSI disk instead (Windows' own NTFS driver does the work).
vcrs mount testdata/ours-iscsi.vc -p PwIscsi --raw

# Raw data access without mounting (offsets are inside the data area).
vcrs read  secret.vc --password "correct horse" --offset 0 --length 4096 --out head.bin
vcrs write secret.vc --password "correct horse" --offset 0 --from head.bin

# Cascades, other KDFs and PIM work too:
vcrs create paranoia.vc --size 200M --password pw --ea AES-Twofish-Serpent --prf Whirlpool --pim 30
```

`--password-stdin` (raw bytes) and `$VCRS_PASSWORD` are supported; prefer those over
`--password` for anything real, since command lines are visible to other processes.
`RUST_LOG=debug` prints the trial-decryption details (which layout/PRF/EA matched).

## Compatibility evidence

Compatibility is not asserted, it is tested against a real VeraCrypt 1.26.29 install
(`scripts/vc-crosscheck.ps1`, `scripts/vc-crosscheck2.ps1`, `scripts/vc-dokan-crosscheck.ps1`,
`scripts/vc-hidden-test.ps1`; the ones that mount with VeraCrypt need an elevated shell
because VeraCrypt mounts through its kernel driver — the Dokany mounts do not).

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
| Dokany → VeraCrypt | Files written through the `vcrs mount` drive letter (`hello.txt`, `sub/nested.txt`) are read back by VeraCrypt mounting the same container | ✅ |
| VeraCrypt → Dokany | VeraCrypt writes `fromvc.txt` into the vc-rs-made FAT; `vcrs mount` lists and reads it, and the file written through Dokany is still intact | ✅ (`scripts/vc-dokan-crosscheck.ps1`, `RESULT: ALL OK`) |
| Mount persistence | Write through Dokany, dismount, remount in a new process: the files are still there | ✅ |
| Hidden volume → VeraCrypt | VeraCrypt mounts the hidden volume vc-rs carved into a container, given only the hidden password (no switch selects it) | ✅ |
| VeraCrypt → Dokany (hidden) | A file written through VeraCrypt's mount of the hidden volume is listed and read through `vcrs mount --hidden` | ✅ |
| Dokany → VeraCrypt (hidden) | A file written through the Dokany mount of the hidden volume is read back by VeraCrypt | ✅ (`scripts/vc-hidden-test.ps1`, `HIDDEN ROUND TRIP OK: True`, `FULL HIDDEN CHAIN OK: True`) |
| Outer + hidden coexist | After the hidden volume was carved in, VeraCrypt still reads the outer FAT16 filesystem and its file | ✅ |
| Windows NTFS through iSCSI → VeraCrypt | Windows sees the vc-rs data area as a partitioned disk (MBR, 1 MiB synthetic prefix), formats NTFS on it, writes `from-windows.txt`, `sub
ested.txt` and a 1 MiB random file; real VeraCrypt mounts the same container and reads all three back (SHA-256 match) | ✅ (`scripts/vc-iscsi-e2e.ps1`, `RESULT: ALL OK`) |

Header encodings are also pinned by unit tests for CRC-32 (VeraCrypt's own self-test
value `0x91267E8A`), the header byte layout and the KDF parameters. Regression suite:
`crates/vcrs-core/tests/{ea_prf_matrix,hidden_volume,backup_header,xts_kat}.rs` (the matrix
test covers all 15 ciphers × 6 KDFs = 90 combinations, the backup test destroys the primary
header and recovers the volume from the backup copy) and
`crates/vcrs-mount/tests/fat_in_volume.rs` (format → write through `fatfs` → reopen →
read, and asserts the plaintext never appears in the container file).

## Mounting (how and why)

Dokany is a *filesystem* framework: it cannot present a raw block device, so a VeraCrypt
container cannot be mounted by Dokany the way VeraCrypt's own driver mounts it. What
`vcrs mount` does instead:

```text
Windows / Explorer / any application
      │  CreateFile / ReadFile / WriteFile / FindFiles
      ▼
Dokany user-mode filesystem            (dokan crate)
      │  create_file / read_file / write_file / find_files
      ▼
FAT12/16/32 filesystem inside the volume   (fatfs crate)
      │  512-byte sector reads and writes
      ▼
decrypted / re-encrypted volume data area  (vcrs-core)
```

So the *storage* stays a genuine VeraCrypt container — no plaintext ever touches the
disk — while the filesystem inside it is implemented in user mode. Consequences:

* The volume must contain a filesystem that is implemented in user mode. Today that is
  FAT12/16/32 (`vcrs format`), which is a good fit for containers up to a few hundred
  MiB. NTFS containers need a different approach.
* Mounting does **not** need elevation with the Dokany version used here (verified:
  `vcrs mount` brought up `S:` from a normal shell). Updating the driver or changing
  the Dokany mount options may reintroduce the requirement. VeraCrypt's own mounts
  always need administrator rights, so a cross-check against it needs an elevated
  PowerShell.
* Read-only mounts are supported (`--read-only`); unmounting from another process works
  (`vcrs dismount Z:`), and the data written through the drive letter is flushed into the
  container when the mount ends.

If a *raw disk* experience is required (any filesystem, including NTFS, using Windows'
own drivers), `vcrs mount --raw` exposes the decrypted sectors as an **iSCSI LUN** and the
in-box Microsoft Initiator attaches it — a fully user-mode path (no kernel driver of ours,
nothing written in the clear):

```text
Windows' own NTFS/exFAT/FAT driver  ──  SCSI READ(10)/WRITE(10)
      │
Microsoft iSCSI Initiator (msiscsi, in-box)  ──  iSCSI over loopback TCP
      │
vcrs-mount iSCSI target            (iscsi-target crate, vendored+patched)
      │  512-byte sectors: LBA n → data offset n*512
      ▼
decrypted / re-encrypted volume data area  (vcrs-core)
```

A VeraCrypt container holds a *bare* filesystem (its data area is one volume, not a
partitioned disk), while Windows only mounts filesystems that live in a partition of a
fixed disk. `--raw` therefore presents a disk that is 1 MiB larger than the data area
and synthesises an MBR in front of it (mode `partition`, the default); the MBR lives only
in memory — the container keeps its VeraCrypt layout byte for byte. Writes into that
synthetic prefix are absorbed, so Windows rewriting the partition table cannot corrupt
the container. `--raw raw` exposes the bare data area instead (LBA 0 = data offset 0).

```powershell
# terminal 1 (normal rights): serve the volume
vcrs mount testdata\ours-iscsi.vc -p PwIscsi --raw     # prints the two commands below

# terminal 2 (elevated): attach it — a static target, then a normal login
iscsicli AddTarget iqn.2025-12.io.vcrs:ours-iscsi vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 "" "" 0 0
iscsicli QLoginTarget iqn.2025-12.io.vcrs:ours-iscsi
# → a disk "vc-rs VeraCrypt volume" appears; create a volume on it and format NTFS:
Format-Volume -DriveLetter S -FileSystem NTFS -NewFileSystemLabel VCRS -Confirm:$false

# detach again
vcrs dismount --iscsi iqn.2025-12.io.vcrs:ours-iscsi
```

Two things to know: a *freshly created* container has no filesystem inside, so Windows
offers to format the new disk (and opening the drive letter beforehand fails with
"the parameter is incorrect" — that is a RAW volume, exactly like a new VeraCrypt
container); and `QAddTargetPortal` (a portal *scan*) does not work, because the target
library cannot complete the initiator's multi-PDU login during discovery — hence the
static `AddTarget` + `QLoginTarget` pair above. Both are documented in
`vendor/iscsi-target/PATCHES.md`.

The whole chain is covered by `scripts/vc-iscsi-e2e.ps1` (elevated), which creates a
container, serves it, logs in, checks the disk/MBR/partition geometry, formats NTFS
through it, writes a text file, a nested file and a 1 MiB random file (SHA-256 compared),
detaches, and finally has real VeraCrypt mount the same container and read all three files
back.

## Notes on passwords

VeraCrypt hashes the *raw password bytes* (plus an optional keyfile pool) and the whole
password can contain arbitrary bytes. The safe `botan-rs` KDF wrappers take a `&str`
and let Botan `strlen()` it, which cannot express that, so `vcrs-core` calls
`botan_pwdhash` directly with an explicit length. A hand-written PBKDF2 implementation
is kept behind `#[cfg(test)]` and cross-checked against Botan's own for the same
parameters.

Secrets held in memory (`master_key` in `VolumeHeader`, derived header keys) are
`zeroize`d where practical.
