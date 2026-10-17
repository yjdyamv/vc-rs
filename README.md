# vc-rs — VeraCrypt-compatible volumes in Rust

A from-scratch Rust implementation of the **VeraCrypt volume format**, built to be
byte-level compatible with [VeraCrypt](https://veracrypt.fr) 1.26.x. Volumes created
here can be mounted by VeraCrypt, and volumes created by VeraCrypt can be read and
written here.

**当前状态 (short version):** 三项目标全部完成 —— (1) 格式完全兼容：全部 15 种加密算法组合
× 6 种 KDF 均通过测试，并与本机真实 VeraCrypt 1.26.29 双向验证（vc-rs 建的卷 VeraCrypt 能挂载，
VeraCrypt 建的卷 vc-rs 能读能写）；(2) 可创建卷（普通卷、隐藏卷、备份头，默认全盘随机填充，
`--quick` 可跳过）；(3) 可挂载卷：`vcrs mount` 把解密后的数据区以 **iSCSI 目标**暴露给 Windows 自带的 Microsoft
iSCSI 发起程序（加 `--letter S` 就在同一条命令里挂到指定盘符，只需确认一次 UAC），Windows 看到的是一块真实磁盘，于是**用 Windows 自己的 NTFS/exFAT/FAT 驱动**
格式化并读写（已实测：Windows 在此磁盘上格式化 NTFS 并写入文件，真实 VeraCrypt 挂载同一容器
能原样读到）。`vcrs format` 还能在卷内直接建 FAT32 文件系统（不挂载也能用，数据区至少要 33 MiB）。
此外还支持
备份/恢复卷头（`backup-headers`/`restore-headers`，含从主密钥重建）、改密码
（`change`）、卷扩容、隐藏卷保护、就地加解密（文件镜像与**整个 NTFS 分区**，后者即 VeraCrypt 的
`/encdev`：缩小文件系统、锁定卸载、遮蔽卷首、自顶向下加密）、动态卷（`--sparse`，按需分配磁盘空间）、
容器时间戳保护（挂载/读写不会暴露容器的修改时间与访问时间）、可复现创建（`--random-source`，
同一个种子文件生成逐字节相同的容器，用于测试与审计）。系统加密（预启动认证）不在范围内。

* Crypto: [Botan](https://botan.randombit.net/) 3.13 via `botan-rs` (vendored static build).
* Mounting (Windows): an in-process **iSCSI target**; the in-box Microsoft iSCSI Initiator
  attaches it, so Windows' own signed NTFS/exFAT/FAT drivers do the filesystem work. The
  [iscsi-target](https://github.com/lawless-m/iscsi-crate) crate is vendored (patched) under
  `vendor/iscsi-target` — see [Mounting](#mounting-how-and-why).
## Platform support

VeraCrypt's format and every container operation are platform-independent; only the
*hosting* half is Windows-shaped, because the only iSCSI initiator this project drives is
the one Microsoft ships.

| | Windows | Linux / macOS |
| --- | --- | --- |
| Containers: `create`, `create-hidden`, `info`, `header`, `read`, `write`, `format`, `change`, `backup-headers`, `restore-headers`, `expand`, `encrypt-in-place`, `decrypt-in-place`, `create-keyfile`, `test` | yes | yes |
| Byte compatibility | yes | yes (verified both ways: a container written on Linux reads back identical on Windows and the other way round) |
| `vcrs mount` (serve the decrypted data area over iSCSI) | yes | yes (prints the `iscsiadm` lines; any initiator that speaks iSCSI works) |
| `vcrs mount --letter`, `vcrs attach`, `vcrs dismount`, `vcrs detach`, `vcrs list`, `vcrs agent` | yes | no: they drive `iscsicli` and the Microsoft initiator, so they say what to run by hand instead |
| In-place encryption of a mounted **NTFS partition** (`/encdev`) | yes (shrinks and locks the filesystem first) | no: no shrink/lock support, so encrypt an image of the partition with `encrypt-in-place` instead |

The Linux build is exercised by the full test suite; `crates/vcrs-core` has no platform
dependencies at all, `crates/vcrs-mount` talks to `/dev` block devices directly, and
`crates/vcrs-host` (the `iscsicli`/drive-letter half) is compiled to nothing off Windows.

* Not used: Dokany/WinFsp. They are *filesystem* frameworks, so they could only ever expose a
  filesystem we implement ourselves (FAT), never NTFS. See
  [Why not Dokany](#why-not-dokany); the removed implementation lives in the git history.

## Contents

| Path | What it is |
| --- | --- |
| `crates/vcrs-core` | The format: header serialization/encryption, KDFs, XTS mode, volume create/open, data I/O. No platform dependencies. |
| `crates/vcrs-mount` | Mount layer: FAT formatting inside the volume, plus an iSCSI target that presents the decrypted data area to Windows as a raw disk (any filesystem Windows supports). |
| `crates/vcrs-host` | The Windows half of hosting: putting a served volume on a drive letter (the iSCSI login, the wait for the disk, the letter, the flush and the logout), the background server that keeps serving after the prompt comes back, and the cached elevated agent behind both — callable in-process, which is what a GUI would use. |
| `crates/vcrs-cli` | The `vcrs` command line tool: a clap front end over `vcrs-host`. |
| `docs/` | Design notes: `mounting-options.md` (why iSCSI, what the alternatives were), `device-in-place.md` (VeraCrypt's `/encdev` and what Windows plumbing it needs). |
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
| Data area read/write, randomized **full format** by default (`--quick` skips it) | ✅ |
| Sparse (VeraCrypt's "dynamic") containers (`--sparse`) | ✅ (full length, only written parts allocate: a 200 MiB container is 256 KiB on disk; implies a quick format, like VeraCrypt) |
| Reproducible container creation (`--random-source FILE`) | ✅ (VeraCrypt's `--random-source` switch, but the file *is* the stream instead of extra entropy, so the same file builds the same container byte for byte — meant for tests and audits; real VeraCrypt mounts such a container like any other, `scripts/vc-random-source-test.ps1` = `ALL OK`) |
| Container timestamps are preserved (`--no-preserve-timestamp` on `mount` disables it) | ✅ (VeraCrypt's *Preserve modification timestamp of file containers*, on by default: opening, changing or mounting a container leaves its modification and access times alone) |
| Hidden volumes (read/write both layouts, `create_hidden`) | ✅ |
| Dump / inspect headers, raw data read/write | ✅ |
| Backup header usable for recovery | ✅ (open with `--backup`) |
| Header backup to a file, restore from it / from the embedded copy / from the master key | ✅ (`backup-headers`, `restore-headers --from|--embedded|--master-key`) |
| Change the password, keyfiles, PIM or hash of a volume (`change`) | ✅ |
| Free-space check before creating (refuses to write a container that cannot fit; `--no-size-check` overrides) | ✅ |
| FAT32 filesystem creation inside the volume (`vcrs format`) | ✅ (FAT32 is the only FAT vc-rs creates: FAT16 stops at 2 GiB and FAT12 at 16 MiB, so a data area smaller than ~33 MiB — the 65 525-cluster minimum — is refused instead of being given a lower FAT) |
| Raw disk for Windows over iSCSI (`vcrs mount`): any filesystem Windows supports | ✅ (verified: Windows formatted NTFS through it, VeraCrypt read the files back) |
| Choosing the drive letter (`vcrs mount --letter S`, or `vcrs attach`) | ✅ (attaching needs administrator rights because `iscsicli` does, so `vcrs mount --letter` raises the one UAC prompt itself, replays the elevated child's output and cleans up the machine state first — a stale session logged in to a dead target, or a disk device Windows left in an Error state, otherwise blocks the login; a letter Windows put on the disk by itself is taken off again so that the letter you asked for goes on (a volume that already wears one refuses a second — `SetVolumeMountPointW` answers `ERROR_INVALID_PARAMETER` and the disk would just stay on `D:`), and without `--letter` only the serving half runs and the `iscsicli` commands are printed) |
| Read-only disks, hidden volumes, `--disk-mode raw`, removable-media reporting | ✅ |
| Mounting through the backup header (`vcrs mount --backup`, VeraCrypt's `/mountoption headerbak`) | ✅ (with the whole primary header group zeroed, `vcrs mount --backup` opens the volume and starts serving it, while `vcrs info` without it reports "incorrect password/PIM/PRF or not a VeraCrypt volume") |
| Detaching every target at once (`vcrs dismount --all`, VeraCrypt's `/dismount` without a volume) | ✅ (it reuses the session parsing of `vcrs list` and the logout of `vcrs dismount --iscsi`, which the iSCSI end-to-end script covers; `--all` and `--iscsi` are mutually exclusive) |
| iSCSI target lifetime (`--idle-timeout <SECONDS>`, `0` = keep serving) | ✅ (stops by itself 5 s after the initiator logs out, so a rescan or a reboot can log back in) |
| Keyfiles (password + keyfile pool, file or directory, repeatable) | ✅ (verified against VeraCrypt both ways, incl. a 102-byte password and directories: `scripts/vc-keyfile-test.ps1` = `ALL OK`) |
| Keyfile creation (`vcrs create-keyfile`) | ✅ (128 random bytes, or `--random-source <file>` for a reproducible one; refuses to overwrite an existing file without `--force`) |
| Crypto self-test (`vcrs test`, and *Test Vectors* in the window) | ✅ (the format's CRC-32 against VeraCrypt's own check value, every header hash, all 15 algorithms over XTS, and a header round trip) |
| List attached volumes (`vcrs list`) | ✅ (session id, initiator and the disk Windows has for it; `--all` shows every iSCSI session. `iscsicli` needs an elevated prompt, so unelevated it lists the disks only; `--json` prints the same snapshot as a JSON document for a program, and it also names the background serving processes) |
| Container expansion (`vcrs expand`): bigger data area, both headers rewritten with fresh salts, master key and data untouched | ✅ (verified: Windows' own tools extend the filesystem into the new space through the iSCSI disk, files survive, VeraCrypt reads the grown container — `scripts/vc-expand-test.ps1` = `ALL OK`) |
| Hidden-volume protection while writing to the outer volume (`--protect-hidden`) | ✅ (a write that would land in the hidden volume is refused, and every later write too, exactly like VeraCrypt; the hidden volume stays byte-identical) |
| Volume sector size at creation (`--sector-size 512..4096`) | ✅ (verified: real VeraCrypt mounts a 4096-byte-sector container, Windows formatted NTFS inside it with 4096-byte sectors, and that boot sector is what lands in the container — `scripts/vc-sector-size-test.ps1` = `ALL OK`) |
| In-place encryption of a plaintext image (`vcrs encrypt-in-place`) | ✅ (verified: real VeraCrypt mounts the finished container, reads the filesystem that was encrypted in place, and writes through that mount survive — `scripts/vc-inplace-test.ps1` = `ALL OK`) |
| Permanent decryption back to a plain image (`vcrs decrypt-in-place`, `--resume` to continue an interrupted run) | ✅ (verified: the plain image is byte-identical to the original filesystem, and re-encrypting it gives a container VeraCrypt mounts and reads again — same script) |
| In-place encryption of an NTFS **partition** (`vcrs encrypt-in-place V:`, `/encdev`) | ✅ (Windows, elevated: the filesystem is shrunk, locked and dismounted, the volume head is concealed, the data area is encrypted top-down and the primary header group is written last; verified on a throwaway VHD — `scripts/device-inplace-test.ps1` = `ALL OK`, files, SHA-256 and `chkdsk` intact. Real VeraCrypt mounting the finished partition is still unproven: this host surfaces only the *first* VeraCrypt mount after a full dismount, and the same failure reproduces with a VeraCrypt-made container on the same kind of partition — see the evidence table) |
| Reading and inspecting an encrypted partition (`vcrs read V:`, `vcrs info V:`) | ✅ (a device path works everywhere a container path does: `E:`, `\.\HarddiskVolume7`, `\.\Harddisk1\Partition2`; the timestamps of a device are left alone because Windows rejects them for device handles) |
| Decryption of a partition back to a plain filesystem (`vcrs decrypt-in-place V:`) | ✅ (same VHD round trip: the filesystem is mountable by Windows again and `chkdsk` is clean) |
| In-place encryption of a *system* partition | ⬜ out of scope |

Run `vcrs test` after a fresh build: it exercises the Botan bindings (checksums,
every header hash, every encryption algorithm, a header round trip) without
touching any volume, so a broken build shows up before it writes a container.

## Build

The vendored Botan build compiles its own C++, so **MSVC must be on the environment**
on Windows (a C++ compiler and CMake are enough on Linux and macOS, where `cargo build`
just works: `sudo apt install build-essential cmake`).
Use the wrapper:

```bash
bash scripts/msvc.sh cargo build            # debug
bash scripts/msvc.sh cargo build --release  # optimized (recommended for big volumes)
bash scripts/msvc.sh cargo test             # unit + integration tests
vcrs test                                  # crypto self-test (checksums, hashes, ciphers, header)
```

`msvc.sh` invokes `vcvars64.bat` first. A plain `cargo build` also needs `python3`
(for Botan's `configure.py`) and `cl.exe` reachable; `python3` must exist in `PATH`
(Botan's build script hardcodes `python3`).

```bash
bash scripts/msvc.sh cargo clippy --workspace --all-targets   # has to stay warning-free
```

Clippy is kept at zero warnings across the whole workspace, the vendored
`iscsi-target` fork included. The source is hand-formatted and deliberately *not*
`rustfmt`-clean (a `cargo fmt` would rewrite every file for no behavioural gain and
would make future diffs against the vendored crate unreadable), so the lint gate is
clippy rather than `cargo fmt --check`.

## Usage

```bash
# Create a 100 MiB container (AES-256 + XTS, PBKDF2-SHA-512, 500k iterations).
vcrs create secret.vc --size 100M --password "correct horse"

# The new data area is filled with random data by default (like VeraCrypt's full format,
# and what plausible deniability needs). --quick skips it: unused space is then detectable
# as zeros on disk, which is why VeraCrypt refuses a quick format for a hidden-volume host.
vcrs create fast.vc --size 1G --password pw --quick

# A sparse (VeraCrypt's "dynamic") container: created at its full size, but only the
# parts that are written use disk space. A 200 MiB container of headers and an empty
# filesystem occupies a few hundred KiB. It is quick-formatted by definition (a full
# format would write every byte) and, like VeraCrypt, skips the free-space check.
vcrs create dynamic.vc --size 100G --password pw --sparse

# Containers keep their timestamps: like VeraCrypt, using a container (info, read, write,
# change, or mounting it) does not move its modification or access time, so nothing about
# the file says when it was last used. Pass --no-preserve-timestamp to mount if you want
# the operating system's normal behaviour instead.
vcrs mount secret.vc --password "correct horse" --no-preserve-timestamp

# Reproducible creation: VeraCrypt has --random-source to fill its entropy pool without
# asking the user to type random characters; ours uses the file as the actual source, so
# the container is a byte-for-byte copy of the one built from the same file. That is what
# makes an audit or a bug report reproducible -- and it means the container's keys are
# reproducible too, so never use it for a volume that is supposed to keep a secret.
vcrs create reproducible.vc --size 10M --password pw --random-source seed.bin

# Volume sector size: 512 by default. VeraCrypt's own format wizard only ever uses a
# non-512 size for device-backed volumes (its file containers are always 512), but the
# format allows 512..4096 and VeraCrypt mounts such a container fine. The filesystem
# inside has to match it (Windows refuses to mount a 512-sector filesystem on a
# 4096-sector volume), so let Windows -- through the mount -- or `vcrs format` create
# the filesystem inside the container instead of copying one in.
vcrs create big.vc --size 2T --password pw --sector-size 4096

# Inspect it (prints the decrypted header) — add --backup for the backup header.
vcrs info secret.vc --password "correct horse"

# Optional: put a FAT32 filesystem inside, without mounting (readable by Windows,
# macOS and Linux alike; the data area must be at least ~33 MiB).
vcrs format secret.vc --password "correct horse" --label DATA

# Serve the volume as a raw iSCSI disk: Windows' own NTFS/exFAT driver does the filesystem
# work. `--letter S` attaches it in the same command (one UAC prompt); without it the
# volume is only served and the two iscsicli commands from "Mounting" below are printed.
vcrs mount   secret.vc -p "correct horse" --letter S   # --removable, --read-only, --backup, --disk-mode raw, --idle-timeout 0, …
vcrs attach  --iqn iqn.2025-12.io.vcrs:secret --letter S  # the attach half alone (needs elevation)
vcrs list                                             # what is attached (--all: every iSCSI session)
vcrs dismount --iscsi iqn.2025-12.io.vcrs:secret       # or --all: every target vc-rs serves

# Raw data access without mounting (offsets are inside the data area).
vcrs read  secret.vc --password "correct horse" --offset 0 --length 4096 --out head.bin
vcrs write secret.vc --password "correct horse" --offset 0 --from head.bin

# Keyfiles (`-k` is repeatable; a directory means "all files in it", like VeraCrypt):
vcrs create-keyfile usb.key                         # 128 random bytes
vcrs create-keyfile usb.key --random-source /dev/urandom  # or a chosen source
vcrs create secret.vc --size 100M --password "correct horse" -k usb.key
vcrs info   secret.vc --password "correct horse" -k usb.key
vcrs info   secret.vc --password "correct horse" -k "D:\keyfiles"

# Cascades, other KDFs and PIM work too:
vcrs create paranoia.vc --size 200M --password pw --ea AES-Twofish-Serpent --prf Whirlpool --pim 30

# Grow a container. The filesystem inside keeps its size; extend it from the OS afterwards.
vcrs expand secret.vc --size 200M --force
# Header backups: write one, and restore from it (or from the copy inside the container,
# or rebuild the header from the master key when no backup exists).
vcrs backup-headers secret.vc --out secret.hc
vcrs restore-headers secret.vc --from secret.hc --password pw
vcrs restore-headers secret.vc --embedded --password pw
vcrs restore-headers secret.vc --master-key <128 hex chars> --data-size 200M \
    --ea AES --prf SHA-512 --password pw

# Change password / keyfiles / PIM / hash without re-encrypting the data area.
vcrs change secret.vc --password old --new-password new --new-hash SHA-256 --new-pim 12

# Turn a plain image (a filesystem plus 128 KiB of zeroes at the end) into a container
# without moving it anywhere: the data area is encrypted where it is, and an interrupted
# run can be resumed.
vcrs encrypt-in-place plain.img --password pw

# ... and permanently decrypt it again (VeraCrypt's "permanently decrypt a non-system
# partition"): the data moves back down, the file becomes the plain image it came from,
# with the 128 KiB the encryption had consumed zeroed and truncated away.
vcrs decrypt-in-place secret.vc --password pw
vcrs decrypt-in-place secret.vc --password pw --resume    # an interrupted run

# The same thing for a whole NTFS partition (VeraCrypt's "encrypt a non-system
# partition in place", /encdev). device-info only reads: it prints the geometry, the
# layout that would be created and whether the shrink is possible. Encrypting needs an
# elevated shell and --yes, and the partition must be NTFS and mounted while it starts.
vcrs device-info V:
vcrs encrypt-in-place V: --password pw --yes
vcrs info V: --password pw                       # an encrypted partition is just a volume
vcrs decrypt-in-place V: --password pw --yes     # and back to a plain filesystem

# Mount the outer volume, but refuse any write that would destroy the hidden volume inside:
vcrs mount both.vc --password outer --protect-hidden --hidden-password inner

# Require the initiator to authenticate before it may log in (CHAP):
vcrs mount both.vc --password outer --chap --letter S
```

`vcrs` serves the volume to the in-box Microsoft iSCSI Initiator over loopback TCP.
That target has no authentication of its own and hands out the decrypted volume, which
is why a non-loopback `--bind` is refused unless `--allow-remote` says it was meant
(and `--allow-remote` now requires `--chap`, so a remote bind is never unauthenticated;
it adds no encryption). On Windows, `--chap` makes
the target ask for CHAP; both halves derive the same 16-character secret from the
container's header salt, so the secret is never typed, passed on a command line or
written anywhere — a process can only log in if it can read the container file, which is
what keeps another local user's process off the loopback port. It is not a cryptographic
secret: anyone who can read the container can derive it, and they could attack the
container offline anyway. Details: `docs/research/security-review.md`.

`--password-stdin` (raw bytes), `--password-file PATH` (its first line) and
`$VCRS_PASSWORD` are supported; prefer those over `--password` for anything real, since
command lines are visible to other processes. `--password-file` also has a spelling for
every other credential `vcrs` reads (`--new-password-file`, `--hidden-password-file`,
`--master-key-file`), and it warns when the file is readable by other users. At a
terminal with none of them given, `vcrs` asks for the password itself with the echo
off — and asks twice when it is *setting* a new one (`create`, `--new-password`), so one
typo cannot lock a volume away. A piped stdin keeps the old immediate refusal, so a
script that forgot a password fails instead of waiting forever.
VeraCrypt's own switch names work too, for muscle memory: `--encryption` for `--ea`,
`--hash` for `--prf`, and `--protection-password` / `--protection-pim` /
`--protection-keyfile` for `--hidden-password` / `--hidden-pim` / `--hidden-keyfile`.
`-k/--keyfile` may be repeated, and accepts a file or a directory of keyfiles; the
keyfile pool is mixed into the password exactly as VeraCrypt does (64-byte legacy pool
for passwords up to 64 bytes, 128-byte pool above that).
`RUST_LOG=debug` prints the trial-decryption details (which layout/PRF/EA matched).
The master key is the one secret that decrypts the data area *without* the password
(it is what a VeraCrypt rescue disk stores), so `vcrs create`, `vcrs create-hidden` and
`vcrs info` print it masked; `--show-master-key` prints it in full if you really need it
(VeraCrypt's format wizard does the same: the fields show stars until “Display keys” is
ticked).

## Compatibility evidence

Compatibility is not asserted, it is tested against a real VeraCrypt 1.26.29 install
(`scripts/vc-crosscheck.ps1`, `scripts/vc-crosscheck2.ps1`, `scripts/vc-hidden-test.ps1`,
`scripts/vc-iscsi-e2e.ps1`, `scripts/vc-keyfile-test.ps1`, `scripts/vc-inplace-test.ps1`,
`scripts/vc-header-test.ps1`, `scripts/vc-sector-size-test.ps1`, `scripts/vc-random-source-test.ps1`,
`scripts/device-inplace-test.ps1`; everything that mounts with
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
| Volume sector size | `vcrs create --sector-size 4096` makes a container whose header records 4096; real VeraCrypt mounts it, Windows formats NTFS through that mount (the type shown is RAW first, as for any unused volume), and the NTFS boot sector that lands inside the container reports 4096 bytes per sector and survives a remount; the backup header carries the value too | ✅ (`scripts/vc-sector-size-test.ps1`, `RESULT: ALL OK`) |
| Windows NTFS through iSCSI, read by vc-rs | After Windows formatted the disk, `vcrs read` of data offset 0 shows the NTFS boot sector (`EB 52 90 "NTFS    "`) | ✅ |
| Removable-media reporting (`--removable`) | Windows classifies the disk as removable media (`Win32_DiskDrive.MediaType` = `Removable Media`, vs `Fixed hard disk media` for the internal NVMe disk), which is what makes exFAT show up in its format dialog | ✅ |
| VeraCrypt → vc-rs (keyfile) | VeraCrypt creates a container with `/keyfile`; `vcrs info -k` opens it and decrypts its FAT16 boot sector, while the same password without `-k` is rejected | ✅ |
| VeraCrypt → vc-rs (keyfile + 102-byte password) | Same with a password longer than 64 bytes, i.e. VeraCrypt's 128-byte keyfile pool layout | ✅ |
| vc-rs → VeraCrypt (keyfile) | `vcrs create -k` makes a container holding a VeraCrypt-created FAT16 image; VeraCrypt mounts it with `/keyfile` and reads `fromvc.txt`; without `-k` VeraCrypt refuses the volume | ✅ (`scripts/vc-keyfile-test.ps1`, `RESULT: ALL OK`) |
| Directory of keyfiles | `-k <dir>` means "all files in it" for both sides: vc-rs opens VeraCrypt's directory-keyfile container and VeraCrypt mounts vc-rs's one, reading the file back | ✅ (`scripts/vc-keyfile-test.ps1`) |
| Expansion | vc-rs grows an NTFS container from 20 MiB to 40 MiB; re-attached, the new space shows up as unallocated on the disk and Windows' own tools extend the partition and the NTFS into it; the files written before the expansion are intact, and real VeraCrypt mounts the expanded container and reads them | ✅ (`scripts/vc-expand-test.ps1`, `RESULT: ALL OK`) |
| Expansion (FAT) | An expanded container whose FAT filesystem is smaller than the data area is still fully VeraCrypt-readable after the expansion | ✅ (same script, part 2) |
| In-place encryption, interrupted | Stopping after a quarter of the data area leaves only the backup header valid (VeraCrypt's `TC_HEADER_FLAG_NONSYS_INPLACE_ENC` state); a second run resumes from it and the whole data area comes back byte-identical | ✅ (`crates/vcrs-core/tests/in_place.rs`) |
| In-place encryption → VeraCrypt | A plain FAT16 image (copied out of a VeraCrypt container) plus 128 KiB of zeroes is encrypted in place by vc-rs; real VeraCrypt mounts the result and reads `fromvc.txt`, Windows writes a new file through that mount, and the file survives a remount plus another `vcrs info` | ✅ (`scripts/vc-inplace-test.ps1`, `RESULT: ALL OK`) |
| In-place decryption → plain image → VeraCrypt again | `vcrs decrypt-in-place` turns that completed in-place container back into a 10223616-byte plain image whose boot sector is `EB 3C 90 "MSDOS5.0"` / `FAT16   `; re-encrypting it produces a container VeraCrypt mounts again, still reading both `fromvc.txt` and the file Windows wrote through the earlier mount | ✅ (same script) |
| Partition in-place encryption (vc-rs side) | A 512 MiB VHD partition with an NTFS filesystem and three files (one of them 1 MiB of pseudo-random bytes) is encrypted in place: the filesystem is shrunk to 535490560 bytes, the run takes ~90 s, `vcrs read V:` returns the NTFS boot sector of the finished volume and `vcrs info V:` its header, `vcrs decrypt-in-place` takes ~55 s, and afterwards the files are back with identical SHA-256 and `chkdsk /scan` is clean (the partition keeps its 535756800 bytes throughout) | ✅ (`scripts/device-inplace-test.ps1`, `RESULT: ALL OK`; `crates/vcrs-core/tests/in_place.rs` covers the file-level algorithm) |
| Partition in-place encryption → VeraCrypt | **Not proven on this host, and not a vc-rs defect.** VeraCrypt mounts a container here, but only the first one after a full dismount: with nothing mounted, `/volume testdata\smoke.vc /letter Y …` produces `Y:`; a mount issued right after it — `/volume testdata\smoke.vc /letter Z …` — returns exit 0 (VeraCrypt's success code) and no drive letter ever appears (`/dismount /quit /silent` frees the slot again; no VeraCrypt process is left behind, so it is not a background-task handoff). The identical fingerprint appears with a **VeraCrypt-made** container on the same kind of VHD partition: `VeraCrypt /volume \Device\HarddiskVolume9 /letter Z /password PwDevHost /quit /silent` → exit 0, still no drive letter after 40 s. Version 1.26.29, driver running (`sc query veracrypt`); a filesystem minifilter of a security product is loaded (`fltmc filters`, driver `sysdiag`), the prime suspect. `scripts/device-inplace-test.ps1` mounts the partition as the first volume, on a free letter, and only judges the run when its control container mounts. The vc-rs side of the round trip is verified above | ⚠️ blocked by the host |
| Hidden-volume protection | Writes overlapping the hidden volume's data area fail (`HiddenVolumeProtected`) and so does every later write (`HiddenVolumeProtectionActive`); the hidden volume's bytes are unchanged and its own password still opens it | ✅ (`crates/vcrs-core/tests/hidden_protection.rs`, `crates/vcrs-mount/tests/iscsi_device.rs`) |
| Header backup/restore → VeraCrypt | vc-rs writes a header backup, both header groups of the container are zeroed (unopenable), `vcrs restore-headers --from` puts it back, and real VeraCrypt mounts the container and reads the file inside | ✅ (`scripts/vc-header-test.ps1`, `RESULT: ALL OK`) |
| Restore from the embedded copy | Only the primary header group is zeroed; `restore-headers --embedded` recovers the volume and VeraCrypt mounts it again | ✅ (same script) |
| Change credentials → VeraCrypt | `vcrs change` rewrites both header copies with a new password, new hash and new PIM; the old password is refused and VeraCrypt mounts the volume with the new credentials and reads the data | ✅ (same script) |
| Backup file layout | Each 64 KiB half of the `.hc` file is a self-contained header region (password + its own salt opens it) — the layout VeraCrypt's own restore reads | ✅ (`crates/vcrs-core/tests/header_restore.rs`) |
| Backup/restore/change round trip | 11 tests: restore from file / from the embedded copy / from the master key, a wrong backup leaves the container alone, both header copies rewritten, the outer volume's slots untouched when a hidden volume is changed, quick vs full detection | ✅ (`crates/vcrs-core/tests/header_restore.rs`) |
| Sparse (dynamic) container | A 4 MiB `--sparse` container round-trips data, really occupies less than a quarter of that on disk (`GetCompressedFileSize`), and a full format is refused | ✅ (`crates/vcrs-core/tests/sparse.rs`) |
| iSCSI target lifetime | The target stops by itself once the initiator has logged out and stayed away for the idle timeout, and `--idle-timeout 0` keeps it serving without one | ✅ (`crates/vcrs-mount/tests/iscsi_device.rs`; `scripts/vc-iscsi-e2e.ps1` waits for the process to exit: `target-exited`) |
| Container timestamps | A container whose times are set 30 days back keeps **both** its modification and access time through `vcrs info`, `read`, `write` and `expand`, and while it is served over iSCSI; a control test shows a write *does* move the time when the freeze is off | ✅ (`crates/vcrs-core/tests/timestamps.rs`, `crates/vcrs-mount/tests/iscsi_device.rs`) |
| Reproducible creation (`--random-source`) | Two containers built from the same seed file are byte-identical, a different seed gives different bytes, and real VeraCrypt mounts the deterministic container and reads the `fromvc.txt` inside the VeraCrypt-made FAT16 image it holds (`MSDOS5.0` boot sector) | ✅ (`scripts/vc-random-source-test.ps1` = `RESULT: ALL OK`, `crates/vcrs-core/tests/random_source.rs`) |
| Dokany-era checks (historical) | With the Dokany filesystem mount (removed since; code in git history): files written through the drive letter were read back by VeraCrypt, a file VeraCrypt wrote into the vc-rs-made FAT was read back through the mount, and the same held for hidden volumes | ✅ (`scripts/vc-dokan-crosscheck.ps1` = `ALL OK`, `scripts/vc-hidden-test.ps1` = `HIDDEN ROUND TRIP OK: True`, `FULL HIDDEN CHAIN OK: True`) |

Header encodings are also pinned by unit tests for CRC-32 (VeraCrypt's own self-test
value `0x91267E8A`), the header byte layout and the KDF parameters. Regression suite:
`crates/vcrs-core/tests/{ea_prf_matrix,hidden_volume,backup_header,header_restore,xts_kat,in_place,sparse,sector_size,timestamps,random_source}.rs` (the matrix
test covers all 15 ciphers × 6 KDFs = 90 combinations, the backup test destroys the primary
header and recovers the volume from the backup copy) and
`crates/vcrs-mount/tests/{fat_in_volume,iscsi_device}.rs` (FAT format → write → reopen →
read with an assertion that no plaintext appears in the container; and the iSCSI device:
synthetic MBR, partition type/geometry, `raw` mode, read-only, stable disk signature, and
that writes into the synthetic prefix never reach the container).

The device/partition side cannot live in `cargo test` (it needs administrator rights and a
real partition), so it is a tracked script instead: `scripts/device-inplace-test.ps1`
builds its own VHD and runs the whole round trip on it.

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

The serving process stops by itself after the last initiator logs out (`--idle-timeout
<SECONDS>`, default 5, `0` = never; the background server that `--letter` starts uses 30 s,
long enough for the initiator to drop and re-establish its connection while the attach is
still running — with a 5 s clock that server used to walk away mid-attach, and the mount
then failed with "Windows did not show the disk"), so a Windows rescan or a reboot can
log back in without you restarting it — and `vcrs dismount --iscsi <iqn>` plus a logout
leaves no stray process behind.

```powershell
# one command: serve the volume and attach it to the letter you want. Attaching needs
# administrator rights (`iscsicli` carries a requireAdministrator manifest), so vcrs asks
# for them itself — one UAC prompt. Without `--letter` Windows picks the next free letter.
vcrs mount secret.vc -p "correct horse" --letter S     # add --removable / --read-only / --backup

# → a disk "vc-rs VeraCrypt volume" appears on S:. Format it (it starts out RAW, like a
#   fresh VeraCrypt container):
Format-Volume -DriveLetter S -FileSystem NTFS -NewFileSystemLabel VCRS -Confirm:$false

# detach again (this takes the disk offline first, then logs the session out)
vcrs dismount --iscsi iqn.2025-12.io.vcrs:secret       # or --all
```

If you would rather drive every step yourself, leave `--letter` off: `vcrs mount` then
only serves the volume and prints the two commands below, and `vcrs attach` does the
initiator half on its own (from an already elevated prompt it asks for nothing at all):

```powershell
# terminal 1 (normal rights): serve the volume — it prints the two commands below,
# with the IQN derived from the file name.
vcrs mount secret.vc -p "correct horse"

# terminal 2 (elevated): attach it — a static target, then a normal login
cmd /c 'iscsicli AddTarget iqn.2025-12.io.vcrs:secret vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 "" "" 0 0'
iscsicli QLoginTarget iqn.2025-12.io.vcrs:secret
# — or the same thing through vcrs, which also puts the disk on the letter you want:
vcrs attach --iqn iqn.2025-12.io.vcrs:secret --letter S
```

### Mounting on Linux

`vcrs mount` does the same job there as `--letter` does on Windows: it starts the target
in the background, logs the kernel in with open-iscsi, mounts the filesystem and returns.
One command in, one command out — the only difference is that the two commands need
`sudo`, because an iSCSI login creates a block device and `mount(8)` needs `CAP_SYS_ADMIN`:

```bash
sudo apt install open-iscsi          # once; the kernel module loads by itself
sudo vcrs mount secret.vc -p "correct horse"
#   mounted secret.vc on /media/vcrs/<label>

ls /media/vcrs/<label>               # ordinary filesystem, ordinary user rights
sudo vcrs dismount secret.vc         # unmounts, logs out, stops the server
```

`--disk-mode` decides which node carries the filesystem: the default presents a synthetic
MBR, so the kernel creates a partition and `vcrs mount` takes `/dev/sdX1`; `raw` presents the
bare data area, so it takes `/dev/sdX` itself. `vcrs format` writes the filesystem where both
presentations find it, so one container mounts either way.

The mount point is chosen from the volume's filesystem label (`/media/vcrs/<label>`, with
`-2`, `-3`… for a second volume with the same label); `--mount-point <DIR>` picks another
one. `vcrs list` shows what is mounted, where, on which device and under which IQN, and
`vcrs dismount --all` takes everything off. `--foreground` keeps the old behaviour of
serving in the terminal (that is what the background command runs internally, and what the
manual recipe below used to be needed for).

A dismount that fails because the filesystem is busy names the processes that are holding
it (`fuser -m` plus `/proc/<pid>/comm`): the usual culprit is a shell whose working directory
is inside the mount, which `umount`'s "target is busy" never says. The mount stays recorded in
that case, so `vcrs list` shows it and the same command retries it afterwards.

A killed server or a reboot leaves a mount point and a state file behind without a volume
behind them (`the kernel keeps the device node while the session is logged in, so reads
fail rather than the mount vanishing`). `vcrs list` marks those as stale, `vcrs mount` of the
same container clears the leftover before it starts a new server, and `vcrs dismount --all`
unmounts lazily (`umount -l`) when the device is gone. A recorded pid is only signalled after
`/proc/<pid>/exe` says it still runs this program: a pid is reused, and killing the stranger
that inherited the number would be worse than leaving the record.

Everything below is only for an initiator that is *not* the Microsoft one and not
open-iscsi — the two lines `--foreground` prints are the same information a hand-written
setup needs:

```bash
# terminal 1: serve in this terminal (Ctrl-C stops it)
vcrs mount secret.vc -p "correct horse" --foreground

# terminal 2 (root)
sudo iscsiadm -m discovery -t sendtargets -p 127.0.0.1:3260
sudo iscsiadm -m node -T iqn.2025-12.io.vcrs:xxxx -l     # → /dev/sdX, partition /dev/sdX1
sudo mount /dev/sdX1 /mnt/vcrs
```

Unlike the Microsoft initiator, open-iscsi can scan a portal, so no static target is
needed and nothing is left in a registry. Verified end to end on Ubuntu 26.04:
`/dev/sdX1` appeared with the volume's filesystem label, a file written inside it was
still there when a **fresh** server process served the same container afterwards.

The synthetic MBR (`--disk-mode partition`, the default) is what makes the data area
show up as `/dev/sdX1`; `--disk-mode raw` presents the bare data area instead, for an
initiator that would rather mount the device itself.

`--backup` opens the volume through the copy of the header at the end of the container
instead of the one at the front (VeraCrypt's "Use backup header embedded in volume if
available"), so a container whose primary header is damaged still serves; `--letter`
attaches the just-served volume in the same command (one UAC prompt) instead of leaving
that to a second elevated terminal; `vcrs dismount --all` detaches every target at once,
the way VeraCrypt's `/dismount` without a volume dismounts all of its volumes. A bare
`vcrs dismount` means the same thing — but it says so before it does it, so nobody loses
a second volume to a missing argument.

The hidden volume of a container is served under a target name of its own —
`iqn.2025-12.io.vcrs:<file>-hidden`, so `mount both.vc --hidden` is
`iqn.2025-12.io.vcrs:both-hidden` — which is what lets the outer and the hidden volume of
one container be mounted side by side (`vcrs mount both.vc -p outer` on `S:` and
`vcrs mount both.vc -p inner --hidden` on `T:`). Take the hidden one off by its letter, its
IQN or `--all`: `vcrs dismount <file>` names only the outer volume, because the file name
is the outer volume's target.

That elevation is asked for **once per ten minutes, not once per command**: the first
elevated run leaves an agent behind (a windowless `vcrs agent --serve`), and the
`vcrs mount --letter` / `vcrs dismount` calls after it hand their work to that agent over
a named pipe — no second prompt, and no UAC window turning up in the middle of an
unmount. It stops by itself after ten minutes without requests, or when asked:

```powershell
vcrs agent --status     # is one running, and with which pid
vcrs agent --stop       # let it go now
```

`--foreground` is the escape hatch on the serving side: it keeps `vcrs mount` serving in
the terminal it was started from, instead of handing that half to a detached copy of
itself (which is what lets `vcrs mount --letter` give your prompt straight back).

The exit code says what happened, on Windows' terms: `0` it worked, `1` it did not, `2`
the command line was wrong (clap), `1223` — Windows' `ERROR_CANCELLED` — the
elevation prompt was declined, so a script can tell the user's "no" from a real failure,
and `130` — the shell's number for SIGINT — an in-place run the user stopped with Ctrl-C.
That last one is not a success even though it is resumable, so a script does not read
"done" out of a run that stopped a third of the way through.

For a program, `--json` prints a machine-readable document instead of the usual lines:
`vcrs list --json` (the same snapshot as the text form — the iSCSI sessions, the background
servers, and the disks Windows has), `vcrs info --json` (the volume header and the layout,
with the master key still hidden unless `--show-master-key` is given), `vcrs header --json`
(the header bytes as hex), `vcrs test --json` (every self-test check with its result),
`vcrs device-info --json` (the device, its filesystem, and what an in-place run would have to
work with), and the mounting commands: `vcrs mount --json` (the mount point, the disk
Windows gave it and the target to detach later — or, without `--letter`, what a caller needs
to log the initiator in itself), `vcrs attach --json` and `vcrs dismount --json` (the letters
released, the serving processes stopped, the sessions logged out and the devices forgotten).
The flag is global, so it can be written anywhere on the command line. Everything that is
meant for a person — the elevation note, the progress lines, the serving banner — goes to
**stderr**, so stdout carries either lines or one document, never both.

Five things to know:

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
4. A mounted container is held **exclusively** — VeraCrypt locks the file (so does
   `vcrs mount`) — so `vcrs info`/`read`/`write` on that same file fail with a sharing
   violation or "access is denied" until it is dismounted. Work on one side at a time.
5. Windows sometimes offers to format a disk that already contains a filesystem, and
   **cancelling that dialog is harmless**: it is Explorer's cached view of the volume, which
   goes stale when the disk is re-attached or when the container's size changed (after
   `vcrs expand`). Dismiss it and re-read the disk (`Update-HostStorageCache`, a
   `diskpart rescan`, or a detach/attach cycle) — the filesystem mounts normally. The
   prompt is only *real* for a container that has no filesystem inside yet
   (`vcrs read` of data offset 0 shows a boot sector like `EB 52 90 "NTFS    "` when one
   exists, and random-looking garbage when it does not).

### Expanding a container

`vcrs expand <file> --size <new size> [--force]` grows a file-hosted normal container the
way VeraCrypt's volume expander does:

* the file grows and the new part of the data area is filled with random data encrypted
  under a throwaway key (so "empty" looks random, like VeraCrypt's full format),
* `VolumeDataSize`/`EncryptedAreaLength` grow while `EncryptedAreaStart` and the **master
  key** stay the same, which is why everything already written is untouched,
* both headers are rewritten with **new random salts** (the backup header moves to the end
  of the now larger file) and the old backup-header area in the middle is overwritten,
* `--force` is needed because expanding destroys any hidden volume inside the container
  (VeraCrypt asks the same question interactively).

The filesystem inside keeps its old size — growing *it* is the operating system's job.
With the iSCSI mount the new space appears as **unallocated** space on the disk (the
synthetic MBR only describes the filesystem while that is smaller than the data area), so
Windows can grow it:

```powershell
Resize-Partition -DiskNumber 1 -PartitionNumber 1 `
  -Size (Get-PartitionSupportedSize -DiskNumber 1 -PartitionNumber 1).SizeMax
# or in the GUI: Disk Management -> Extend Volume
```

Verified end to end by `scripts/vc-expand-test.ps1`: 20 MiB container → NTFS formatted by
Windows through the iSCSI disk → files written → `vcrs expand --size 40M` → re-attached →
Windows extends the NTFS into the new space → the files are intact → real VeraCrypt mounts
the expanded container, reads the files and sees the new size.

### Encrypting a plaintext image in place

`vcrs encrypt-in-place <file> [--ea …] [--prf …]` does what VeraCrypt's "encrypt a
non-system partition in place" does to a file: it turns a plain image — a bare filesystem
followed by the 128 KiB of free space the user is told to free up (zeroed, because that
space becomes the backup header group) — into an ordinary container, without needing room
for a second copy:

* the data area moves **128 KiB forward**: the low part of the image stays where it is, the
  chunks are encrypted from the **top down**, and each chunk lands 128 KiB above its source
  (`ciphertext offset = plaintext offset + TC_VOLUME_DATA_OFFSET`), which is also the XTS
  data-unit number, exactly as VeraCrypt computes it,
* only the **backup** header exists while the run is unfinished, and it carries
  `TC_HEADER_FLAG_NONSYS_INPLACE_ENC` with the pair
  (`EncryptedAreaStart` = the plaintext/ciphertext boundary, `EncryptedAreaLength` = bytes
done so far). VeraCrypt refuses to mount such a volume (`ERR_NONSYS_INPLACE_ENC_INCOMPLETE`)
  and resumes from that pair; so does vc-rs, so an interrupted run is continued with the
  same command,
* the backup header is rewritten every 64 MiB of progress and when the run stops, always
  with the **same salt and key** (VeraCrypt's `FastVolumeHeaderUpdate`), so a resume derives
  the same master key,
* at the end the primary header group is written into the space the data left behind
  (`EncryptedAreaStart` becomes 128 KiB, `EncryptedAreaLength` the whole data area) while
  the flag stays set — which is exactly how VeraCrypt leaves a finished in-place container,
  and why it mounts like any other volume afterwards.

Long runs say where they are: `encrypt-in-place` and `decrypt-in-place` (the partition
forms too), and the data-area fill of `create`, `create-hidden` and `expand`, print a line
every five percent — `  20971520 of 50069504 bytes (41%), 3s` — on
**stderr**, so a script's stdout stays what the command meant to say. The core passes that
out through `vcrs_core::Watch` (`Watch::new(&mut |done, total| …)`, then `Some(&mut watch)`
to the call), which is also what a GUI drives a progress bar with — the callback answers
`Control::Continue` or `Control::Stop`, so the stop travels the same channel as the
progress. `create`, `create-hidden` and `expand` fill their data area through the same
watcher, so they report progress the same way; stopping one of *those* is an error rather
than a pause (`Interrupted`, exit code `130`), because a container whose data area was only
half filled is not one VeraCrypt would call formatted — the command says so and leaves the
file for the user to delete (`create` starts over on the next run). An interrupted `expand`
is safe to repeat: the new header fields are only written after the fill, so a half-grown
container still describes its old size.

Ctrl-C stops one of those runs at a **chunk boundary**, never half way through one
(`IN_PLACE_CHUNK_SIZE` is 2 MiB, so the wait is well under a second): the first press asks
for a clean stop and prints `paused: …` with the hint to run the same command again, a
second press goes to Windows' own handler and ends the process where it stands — which can
leave the chunk it was in the middle of half written, so the first press is the one to use.
A run stopped that way exits `130`; the header and the data still agree, and the same
command again carries on from there.

`crates/vcrs-core/tests/in_place.rs` covers the full run, the byte-identical resume and the
refusal to overwrite a non-zero tail (a plain image's last 128 KiB must be free space, and
vc-rs checks rather than clobbers). `scripts/vc-inplace-test.ps1` (elevated) proves the
result is a real VeraCrypt volume.

`vcrs decrypt-in-place` is the mirror image — VeraCrypt's "permanently decrypt a non-system
partition". It needs a *completed* in-place container; `--resume` continues an interrupted
**decryption** and is required for a partial one, because a half-decrypted and a
half-encrypted container are indistinguishable in the header (VeraCrypt tells them apart
with its own switch, `/zinplace` versus `/resumeinplacedec`):

* the chunks move back **down** 128 KiB at a time, again from the top of the data area, and
  each chunk is decrypted with the data-unit number of the offset it is *written to*,
* `EncryptedAreaStart` walks up and `EncryptedAreaLength` walks down as it goes, so an
  interrupted decryption resumes from the backup header exactly like an interrupted
  encryption; the primary header group is gone for good (the first chunk lands on it),
* when the last chunk is in place, everything from the end of the data area to the end of
  the file is zeroed and the file is truncated to the image size — the freed 128 KiB comes
  back as zeroes, exactly as VeraCrypt zeroes from the volume size to the device end — so
  the result is the plain image the encryption started from (its filesystem byte for byte),
  and `vcrs encrypt-in-place` can be run on it again to get a container back.

### Encrypting a whole partition in place (VeraCrypt's `/encdev`)

The file case above becomes a device case with the same algorithm and a good deal of
Windows plumbing. A partition of `size` bytes gets the layout a container has: a data area
of `size - 262144` starting at 131072, a backup header group in the last 128 KiB and a
primary header group at the front. `vcrs device-info <device>` is read-only and answers
"what is this, would it work, what would be shrunk"; the encryption and decryption are
the same commands as for a file, with a device path instead:

```bash
vcrs device-info V:                                  # no elevation needed to look
vcrs encrypt-in-place V: --password pw --yes         # elevated
vcrs decrypt-in-place V: --password pw --yes         # elevated
```

* **NTFS only.** The filesystem has to give up its last 256 KiB, and on Windows only NTFS
  can be shrunk in place (`FSCTL_SHRINK_VOLUME`); FAT and exFAT have no resize API at all
  and ext4 has no Windows driver to mount the result with. VeraCrypt's own message says the
  same: *"Only partitions that contain an NTFS filesystem can be encrypted in place"*.
  The crypto itself has nothing to do with NTFS — this restriction comes entirely from the
  shrink.
* **Elevated, and mounted when it starts.** Raw access to the sectors the filesystem is
  about to give up needs `FSCTL_ALLOW_EXTENDED_DASD_IO` (the NTFS driver guards them);
  vc-rs then locks and dismounts the filesystem for the run, exactly like VeraCrypt.
* If NTFS keeps data in the bytes it has to give up, the shrink is refused; vc-rs reports
  that and asks for `defrag <drive> /X` instead of moving those clusters itself the way
  VeraCrypt's `MoveClustersBeforeThreshold` does.
* The **head of the volume is concealed** for the duration (the first 8192 bytes are XORed
  with 0xFF, VeraCrypt's `ConcealNTFS`), so Windows sees an invalid filesystem and leaves
  the volume alone while its data moves. The last chunk undoes it, and a finished run
  leaves a normal VeraCrypt volume behind.
* The partition keeps its size (devices are never truncated); when the run finishes, the
  area from the end of the data area to the end of the device is zeroed and the primary
  header group is written into the space the data left behind — with the in-place flag
  still set, which is how VeraCrypt leaves it too.
* A *system* partition is out of reach: Windows runs from it, so it can neither be
  shrunk nor locked/dismounted (and system encryption is out of scope anyway).

`scripts/device-inplace-test.ps1` (elevated) is the proof: it builds a throwaway 512 MiB
VHD with one NTFS partition, writes files into it, encrypts it in place (≈ 90 s for the
510 MiB data area), reads the finished volume **through the device path** (`vcrs read V:`
returns `EB 52 90 "NTFS    "`, `vcrs info V:` the header), decrypts it again (≈ 55 s) and
checks the files, their SHA-256 and `chkdsk`. The script also attempts VeraCrypt's own
mount of the encrypted partition, but that is reported as `SKIPPED` while this machine
cannot mount anything through VeraCrypt (see the evidence table).

### Header backup, restore and rebuilding

A VeraCrypt container keeps two copies of its header (the primary group at the start, a
backup group at the end) and VeraCrypt's "Backup Volume Header" writes a **131072-byte
file holding both copies** — the ordinary header in the first 64 KiB and, for a hidden
volume, the hidden header in the second. `vcrs` matches that layout:

```bash
vcrs backup-headers secret.vc --out secret.hc      # 131072 bytes, both slots
vcrs restore-headers secret.vc --from secret.hc --password pw
vcrs restore-headers secret.vc --embedded --password pw      # from the end of the file
vcrs restore-headers secret.vc --master-key <hex> --data-size 200M \
    --ea AES --prf SHA-512 --password pw                     # rebuild from scratch
```

* `--from <file>` restores out of a `.hc` backup; a file of the wrong size is refused and
  the container is left untouched if the backup does not actually open.
* `--embedded` takes the copy that lives in the container itself — the recovery path when
  the primary header was damaged but the end of the file is intact (open it with
  `--backup` to check).
* `--master-key` rebuilds a header when *nothing* is left: the master key is the one
  secret that does not depend on the password (it is what VeraCrypt's rescue disk carries),
  and `--data-size` says how big the data area is. The rebuilt header gets a fresh salt and
  the given password/PIM/hash, and the fake hidden header is only restored when the
  container still has one (i.e. the slots are zero).
* For a hidden volume only the hidden volume's own two slots are written, so restoring or
  changing a hidden header never disturbs the outer volume (and vice versa).
* `vcrs change <vol> --new-password … [--new-keyfile …] [--new-hash …] [--new-pim n]`
  rewrites both header copies with new salts but keeps the **master key**, so the data area
  is not touched and only the header changes. `--new-pim` defaults to the volume's current
  PIM rather than to 0, so changing just the password cannot silently drop the KDF cost.
  All of this is verified against real VeraCrypt by `scripts/vc-header-test.ps1`.

### Hidden-volume protection

`--protect-hidden --hidden-password <pw>` (plus `--hidden-keyfile`/`--hidden-pim`) makes
`vcrs` open the hidden volume as well and refuse any write from the outer volume that
would land in the hidden volume's data area — the same protection VeraCrypt offers when
mounting an outer volume, including the deliberate "every later write fails" behaviour, so
a filesystem that ignores the error cannot keep going and damage the hidden volume.
Reads are never restricted.

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

Secrets held in memory are wiped where the program can reach them: the `master_key` in
`VolumeHeader`, the derived 192-byte header keys and the stream key of `--random-source`
are zeroized when the volume is dropped. The password you type is not: it arrives from
the terminal as a `String`/`Vec<u8>`, is copied into `OpenOptions`, and those copies are
left to the allocator. Nothing here is protected from being written to disk by the
operating system either: the process is not locked into RAM (`VirtualLock`) and no
crash-dump policy is set, so a pagefile or a WER dump can hold the master key and
plaintext.

## Anti-forensics: what is covered and what is not

`--preserve-timestamp` (on by default) keeps a container's modification and access time
from moving while it is mounted, and `Volume` freezes them before its first read. That is
one trace out of several, and it is the only one this program touches. Writing to a
container still leaves, untouched: NTFS `$UsnJrnl` records (append-only, with offsets and
timestamps), Prefetch and Amcache entries for `vcrs.exe`, ETW/Defender telemetry, the
SRUM database, and — for `--letter` mounts — the IQN in the Microsoft iSCSI Initiator's
registry list and event log (random per mount unless `--target-name` gives one). Assume that *when* a container was
used is recoverable on Windows even with timestamp preservation on; what the flag buys is
that the container's own timestamp does not testify to it.

Two more things are deliberately not defended against, because they cannot be fixed inside
this program. A crash dump (a manual one, a `LocalDumps` policy, a kernel dump) contains the
process's memory: `vcrs` turns the two in-process knobs there are — `WER_FAULT_REPORTING_FLAG_NOHEAP`
on Windows, so the reports Windows Error Reporting writes for this process carry the stack
but not the heap, and `PR_SET_DUMPABLE=0` on Linux, so the kernel writes no core at all and
another user cannot read this process's memory out of `/proc` — and excludes the master key
block explicitly, but an administrator's dump policy or `hiberfil.sys` is outside the
process. And the unlock itself is observable: a larger PIM or a slower KDF makes
`--password`-based opens measurably slower, so a local process that can time them learns
something about the volume's parameters (the PIM is not stored in the header, but it is not
hidden by timing either).

A secret given on the command line (`-p`, `--password`, `--master-key`) is readable by every
process on the machine while the command runs, and some audit configurations keep a copy;
`vcrs` warns once when that happens and offers `--password-stdin`, `--password-file`, `--master-key-stdin` and
`--master-key-file` instead. The detached background server never receives a secret through
its argument list at all: it reads them from a framed payload on its standard input.

The program's own leftovers are kept out of `%TEMP%`: the background server's state file and
log live in `%LOCALAPPDATA%\vcrs` (0700/0600 on Unix), are removed when the volume is
dismounted, and are swept if a server died without one. A log that is left behind says
nothing about the volume's layout at the default level.

The **plaintext** of a mounted volume is a different matter from its key, and less can be
done about it. While a volume is mounted its contents pass through this process (in the
served disk) and through the kernel (the iSCSI initiator and the file system on top of it),
so they are ordinary memory: they can be paged into the page file, captured by
`hiberfil.sys`, and copied by a dump of either the process or the kernel. Locking them is
not practical (a transfer is megabytes and changes constantly), and no user-mode call keeps
a page out of the page file. If the machine is captured while a volume is mounted, treat
its contents as readable by whoever captured it; after a dismount the session's buffers are
gone, and the operating system's caches are the only copy left.

Two related traces are outside this program entirely: a file deleted with the ordinary
delete call can still be recovered until its sectors are reused, and if the container lives
on a volume with shadow copies (or another snapshot mechanism), an older copy of it -
encrypted, but showing that a container was there - can survive a rewrite.
