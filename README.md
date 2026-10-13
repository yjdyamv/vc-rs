# vc-rs — VeraCrypt-compatible volumes in Rust

A from-scratch Rust implementation of the **VeraCrypt volume format**, built to be
byte-level compatible with [VeraCrypt](https://veracrypt.fr) 1.26.x. Volumes created
here can be mounted by VeraCrypt, and volumes created by VeraCrypt can be read and
written here.

**当前状态 (short version):** 三项目标全部完成 —— (1) 格式完全兼容：全部 15 种加密算法组合
× 6 种 KDF 均通过测试，并与本机真实 VeraCrypt 1.26.29 双向验证（vc-rs 建的卷 VeraCrypt 能挂载，
VeraCrypt 建的卷 vc-rs 能读能写）；(2) 可创建卷（普通卷、隐藏卷、备份头、`--full` 随机填充）；
(3) 可挂载卷：`vcrs format` 在卷内建 FAT 文件系统，`vcrs mount` 通过 Dokany 挂成盘符，
经 Dokany 写入的文件真实 VeraCrypt 能读到，反之亦然。系统加密（预启动认证）不在范围内。

* Crypto: [Botan](https://botan.randombit.net/) 3.13 via `botan-rs` (vendored static build).
* Mounting (Windows): [Dokany](https://dokan-dev.github.io/) via `dokan-rs` (`dokan-dev/dokan-rust`).

## Contents

| Path | What it is |
| --- | --- |
| `crates/vcrs-core` | The format: header serialization/encryption, KDFs, XTS mode, volume create/open, data I/O. No platform dependencies. |
| `crates/vcrs-mount` | Windows mount layer: a FAT filesystem inside the volume, exposed as a drive letter through Dokany. |
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
| Keyfiles | ⬜ not implemented yet |
| System (pre-boot) encryption, in-place encryption of a system partition | ⬜ out of scope |
| Non-FAT filesystems behind the Dokany mount (NTFS) | ⬜ see *Mounting* below |

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
own drivers), the options are: writing a kernel driver, mounting through VHD/VHDX
(which would require plaintext on disk), or exposing the decrypted sectors over
**iSCSI to the in-box Microsoft initiator** — a fully user-mode path that gives Windows
a real disk while nothing is written in the clear. That last option is the intended
follow-up to the Dokany mount.

## Notes on passwords

VeraCrypt hashes the *raw password bytes* (plus an optional keyfile pool) and the whole
password can contain arbitrary bytes. The safe `botan-rs` KDF wrappers take a `&str`
and let Botan `strlen()` it, which cannot express that, so `vcrs-core` calls
`botan_pwdhash` directly with an explicit length. A hand-written PBKDF2 implementation
is kept behind `#[cfg(test)]` and cross-checked against Botan's own for the same
parameters.

Secrets held in memory (`master_key` in `VolumeHeader`, derived header keys) are
`zeroize`d where practical.
