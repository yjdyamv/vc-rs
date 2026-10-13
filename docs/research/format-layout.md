# VeraCrypt 1.26.30 — Standard file-hosted V2Normal volume: creation & on-disk layout

Source of truth: VeraCrypt 1.26.30 C/C++ tree at `C:/Users/yuan/Desktop/VeraCrypt`
(`VERSION_STRING "1.26.30"`, `src/Common/Tcdefs.h:62`). All `file:line` refs below are from that tree.
This documents a **standard (non-system, non-hidden) file-hosted volume of the current format
(V2Normal)**. It does NOT cover hidden, system, in-place, or legacy V1 volumes except where noted.

---

## 1. Format constants

| Constant | Value | Definition |
|---|---|---|
| `VOLUME_HEADER_VERSION` / `CurrentHeaderVersion` | `0x0005` | `src/Common/Volumes.h:22`, `src/Volume/VolumeHeader.h` |
| `TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION` | `0x010b` | `src/Common/Volumes.h:32` |
| `TC_VOLUME_HEADER_SIZE` | `65536` (64 KiB) | `src/Common/Volumes.h:51` |
| `TC_VOLUME_HEADER_EFFECTIVE_SIZE` | `512` | `src/Common/Volumes.h:52` |
| `TC_VOLUME_HEADER_SIZE_LEGACY` | `512` | `src/Common/Volumes.h:54` |
| `TC_VOLUME_HEADER_GROUP_SIZE` = 2 x header | `131072` | `src/Common/Volumes.h:56` |
| `TC_TOTAL_VOLUME_HEADERS_SIZE` = 4 x header | `262144` | `src/Common/Volumes.h:57` |
| `TC_VOLUME_HEADER_OFFSET` | `0` | `src/Common/Volumes.h:60` |
| `TC_HIDDEN_VOLUME_HEADER_OFFSET` | `65536` | `src/Common/Volumes.h:61` |
| `TC_VOLUME_DATA_OFFSET` = header group | `131072` | `src/Common/Volumes.h:77` |
| `TC_SECTOR_SIZE_FILE_HOSTED_VOLUME` | `512` | `src/Common/Volumes.h:66` |
| `TC_MIN_VOLUME_SECTOR_SIZE` / `TC_MAX_VOLUME_SECTOR_SIZE` | `512` / `4096` | `src/Common/Volumes.h:64-65` |
| `TC_MIN_FAT_FS_SIZE` = 9 x 4096 | `36864` | `src/Common/Volumes.h:85` |
| `TC_MIN_VOLUME_SIZE` = 4x64K + 36864 | `299008` | `src/Common/Volumes.h:96` |
| `TC_MAX_VOLUME_SIZE_GENERAL` | `0x7fffFFFFffffFFFF` | `src/Common/Volumes.h:98` |
| `PKCS5_SALT_SIZE` / salt offset | `64` / `0` | `src/Common/Crypto.h` |
| `HEADER_ENCRYPTED_DATA_OFFSET` | `64` | `src/Common/Volumes.h` |
| `HEADER_ENCRYPTED_DATA_SIZE` = 512 - 64 | `448` | `src/Common/Volumes.h` |
| `HEADER_MASTER_KEYDATA_OFFSET` / `MASTER_KEYDATA_SIZE` | `256` / `256` | `src/Common/Volumes.h`, `Crypto.h` |
| `ENCRYPTION_DATA_UNIT_SIZE` | `512` | `src/Common/Crypto.h:39` |
| `TC_HEADER_FLAG_ENCRYPTED_SYSTEM` | `0x1` | `src/Common/Volumes.h:134` |
| `TC_HEADER_FLAG_NONSYS_INPLACE_ENC` | `0x2` | `src/Common/Volumes.h:135` |

All multi-byte header fields are **big-endian** (`src/Common/Endian.h`, `Endian::Big` in C++).

---

## 2. On-disk layout for a file-hosted normal volume of total size `S`

`VolumeLayoutV2Normal` (`src/Volume/VolumeLayout.cpp:98`) gives:
- `HeaderOffset = 0`, `HeaderSize = 65536`, `BackupHeaderOffset = -TC_VOLUME_HEADER_GROUP_SIZE = -131072`
- `GetDataOffset() = Header->GetEncryptedAreaStart()`, `GetDataSize() = Header->GetVolumeDataSize()`
- `GetMaxDataSize(S) = S - TC_TOTAL_VOLUME_HEADERS_SIZE = S - 262144`

| Region | Offset (start) | Length | Contents |
|---|---|---|---|
| Primary header **group** | `0` | `131072` | effective 512-B header + reserved/random + fake hidden header |
| - Effective primary header | `0` | `512` | the real header (encrypted) |
| - Reserved primary area | `512` | `65024` | random (C path) / XTS-encrypted zeros (C++ path) |
| - Fake "hidden" primary header | `65536` | `512` | valid-looking random header |
| - Rest of primary group | `66048` | `65024` | random / encrypted zeros |
| **Data area** | `131072` | `S - 262144` | encrypted user/FS data |
| Backup header **group** | `S - 131072` | `131072` | effective 512-B backup header at group start |
| - Effective backup header | `S - 131072` | `512` | encrypted, same master key, different salt |
| - Reserved backup area | `S - 130560` | `65024` | random / encrypted zeros |
| - Fake "hidden" backup header | `S - 65536` | `512` | valid-looking random header |
| - Rest of backup group | `S - 65024` | `65024` | random / encrypted zeros |

Data-area end = `131072 + (S - 262144) = S - 131072` (== backup group start). **Total file size = S.**

### Header field values written at creation

| Field | Header offset | Value |
|---|---|---|
| `HiddenVolumeDataSize` | `92` | `0` |
| `VolumeDataSize` | `100` | `S - 262144` |
| `EncryptedAreaStart` | `108` | `131072` |
| `EncryptedAreaLength` | `116` | `S - 262144` |
| `Flags` | `124` | `0` |
| `SectorSize` | `128` | `512` |

C++ path (`src/Core/VolumeCreator.cpp`): `headerOptions.VolumeDataStart = GetHeaderSize()*2 = 131072`,
`headerOptions.VolumeDataSize = Layout->GetMaxDataSize(S) = S - 262144`.

### Worked example: `S = 100 MiB = 104857600`

| Value | Bytes |
|---|---|
| `VolumeDataSize` = `EncryptedAreaLength` | `104595456` |
| `EncryptedAreaStart` | `131072` |
| `HiddenVolumeDataSize` | `0` |
| Data area | `[131072, 104726528)` |
| Backup group | `[104726528, 104857600)` |
| Backup effective header offset | `104726528` |
| Fake hidden headers (primary / backup) | `65536` / `104792064` |
| Total file size | `104857600` |

---

## 3. The 512-byte effective header — exact field map

Only the first `TC_VOLUME_HEADER_EFFECTIVE_SIZE = 512` bytes are meaningful. Offsets are absolute
within that 512-byte block:

| Offset | Size | Field | Notes |
|---|---|---|---|
| `0` | 64 | Salt | **plaintext** |
| `64` | 4 | Magic `"VERA"` (BE `0x56455241`) | encrypted |
| `68` | 2 | Header format version = `0x0005` | encrypted |
| `70` | 2 | Required min program version = `0x010b` | encrypted |
| `72` | 4 | CRC32 of master key area (`[256,512)`) | encrypted |
| `76` | 8 | Reserved (volume creation time) = `0` | encrypted |
| `84` | 8 | Reserved (header modification time) = `0` | encrypted |
| `92` | 8 | Hidden volume data size = `0` | encrypted |
| `100` | 8 | Volume data size = `S - 262144` | encrypted |
| `108` | 8 | Encrypted area start = `131072` | encrypted |
| `116` | 8 | Encrypted area length = `S - 262144` | encrypted |
| `124` | 4 | Flags = `0` | encrypted |
| `128` | 4 | Sector size = `512` | encrypted |
| `132` | 120 | Zero padding | encrypted |
| `252` | 4 | Header CRC32 over bytes `[64,252)` | encrypted |
| `256` | 256 | Master key data (XTS key pair) | encrypted, plaintext value = 2x cipher key |

Everything from byte `64` through `511` is inside the XTS-encrypted region (`[64,512)`); **only the
64-byte salt is plaintext**. Serialization: `src/Volume/VolumeHeader.cpp` `Serialize()` (`:442`) and
`src/Common/Volumes.c` `CreateVolumeHeaderInMemory()` (`:1009`); both write the same byte layout.
The key-area CRC is computed over the **plaintext** master key before encryption; the header CRC is
computed over the **plaintext** bytes `[64,252)` before encryption.

### Effective header vs 64 KiB area (Q3/Q7 nuance)

- `TC_VOLUME_HEADER_EFFECTIVE_SIZE = 512` is the only part read back (`ReadVolumeHeaderWithAbort`,
  `src/Common/Volumes.c:189`; `WriteEffectiveVolumeHeader`, `src/Common/Volumes.c:1417`).
- Header encryption is XTS `dataUnitNo = 0`, `startCipherBlockNo = 0` (`src/Common/Crypto.c:917`
  `EncryptBuffer`, `src/Common/Xts.c`). For the effective 512-byte header that is 28 blocks
  (448 bytes). The C path encrypts exactly `[64,512)`; the C++ path encrypts the entire
  `[64,65536)` (65472 bytes) but a reader only ever consumes the first 448 bytes.
- The reserved bytes `[512,65536)` of the primary area are `random` in the C path and
  `XTS-encrypted zeros` in the C++ path. They are never parsed and can be anything.

---

## 4. Random regions and exact write order (Q2)

### C path — `src/Common/Format.c` `TCFormatVolume` (used by **VeraCrypt Format.exe**)

1. `CreateVolumeHeaderInMemory(..., masterKeydata=NULL, ...)` builds the primary header + `cryptoInfo`
   (`dataAreaSize = S - 262144`). A fresh random 64-byte salt and a random master key are generated.
2. File created with `CREATE_ALWAYS`; **preallocated** to `dataAreaSize + TC_VOLUME_HEADER_GROUP_SIZE = S - 131072`
   via `SetFilePointerEx` + `SetEndOfFile` (zero-filled; `SetFileValidData` is the insecure fast path,
   sparse files used for quick format when the option is set).
3. `WriteEffectiveVolumeHeader` writes **512 bytes** at offset `0`.
4. `130560` zero bytes written at `[512, 131072)` (anti-fragmentation).
5. `FormatNoFs`:
   - **non-quick**: generate a *temporary* random master key + k2, then write encrypted zero sectors
     across the whole data area `[131072, S-131072)` (plausible deniability).
   - **quick**: for a non-hidden file container, write a single zeroed sector every 128 MiB only
     (progress / allocation); the data area is otherwise left untouched.
6. **Backup header**: `CreateVolumeHeaderInMemory` called again with `cryptoInfo->master_keydata`
   (**same master key**) but a **new random salt** -> new derived header key. `WriteEffectiveVolumeHeader`
   writes 512 bytes at `S - 131072`.
7. `WriteRandomDataToReservedHeaderAreas(FALSE, FALSE)` (`src/Common/Volumes.c:1487`): for the primary
   group (`offset 0`) and then the backup group (`offset dataAreaSize + 131072`), read 131072 bytes,
   preserve `[0,512)`, refill `[512,131072)` with `RandgetBytesFull` random data and XTS-`EncryptBuffer`
   it with a *temporary random key*, then write the whole group back.
8. Loop twice: `CreateVolumeHeaderInMemory` with `password=NULL` (random master key + random salt) and
   `WriteEffectiveVolumeHeader` at `TC_HIDDEN_VOLUME_HEADER_OFFSET = 65536` (primary) and
   `dataAreaSize + 131072 + 65536 = S - 65536` (backup) -> a valid-looking **fake hidden header** in each group.

### C++ path — `src/Core/VolumeCreator.cpp` (used by cross-platform `veracrypt --create`)

1. `CreateVolume` (`:226`): open `CreateReadWrite`; if `Quick`, `SetLength(S)`; `SectorSize = 512`.
2. Primary 64-KiB `SecureBuffer`: `_header->Create` -> `[0,64)` salt (random), `[64,65536)` XTS-encrypted
   (fields + zeros). `SeekAt(0)`, write 64 KiB.
3. Write a fake hidden-volume 64-KiB header at offset `65536` (random key/salt).
4. Creation thread (`:53`): data start `131072`, end `S-131072`. If not quick, randomize the EA key
   temporarily and write encrypted zeros across the data area; if FAT, write the filesystem first.
5. Backup: new random 64-byte salt -> re-derive header key -> `EncryptNew` into a 64-KiB buffer;
   `SeekEnd(-131072)` (quick/hidden) or write at current end; write 64 KiB at `S-131072`.
6. Write a fake hidden 64-KiB header at `S-65536`.

**Quick vs non-quick**: only the data-area fill differs. Quick = do not initialise the data area
(C path still writes one zero sector per 128 MiB). Non-quick = write encrypted zero sectors over the
entire data area using a throwaway random key. The header groups/backup are always written identically.
*Whole-drive wipe mode* (`bWipeMode`) applies only to device/in-place formats and is not used for
file-hosted volume creation.

---

## 5. Backup header relationship (Q4)

- The backup header is **not a block copy** of the primary: both are re-created from the **same master
  key** (`DataAreaKey`) but with a **different random 64-byte salt**, so the derived header key (and the
  encrypted bytes) differ. C: `CreateVolumeHeaderInMemory(..., cryptoInfo->master_keydata, ...)`
  regenerates the salt each call (`src/Common/Volumes.c`); C++: `backupHeaderSalt` + fresh `DeriveKey`
  (`src/Core/VolumeCreator.cpp`).
- Both headers encode the same `VolumeDataSize`/`EncryptedAreaStart`/`EncryptedAreaLength` and carry the
  same 256-byte master key (encrypted under their respective header keys).
- Salt is plaintext; because it differs, the concatenated `salt||encrypted` backup bytes are not equal
  to the primary bytes. Mounting succeeds with either header.

---

## 6. Size limits and alignment (Q5)

- `TC_MIN_VOLUME_SIZE = 4x65536 + 9x4096 = 299008` bytes (~292 KiB). CLI rejects smaller volumes.
- `TC_MAX_VOLUME_SIZE_GENERAL = 0x7fffFFFFffffFFFF`.
- Total size `S` is **rounded up to a multiple of the sector size (512)** by the creation UI/CLI
  (`src/Main/TextUserInterface.cpp`; Windows `src/Format/Tcformat.c`). Since `262144` is a multiple of
  512, `VolumeDataSize = S - 262144` is then also a multiple of 512. The 64-KiB header groups are
  written in full, so the file length equals `S`.
- The data area length is `S - 262144`; no requirement beyond being a multiple of 512.

---

## 7. Versions, flags, timestamps (Q6)

- Header version = `0x0005`; `RequiredMinProgramVersion = 0x010b`.
- `Flags = 0` for a standard file-hosted normal volume (neither `ENCRYPTED_SYSTEM` nor
  `NONSYS_INPLACE_ENC`).
- Volume creation time and header modification time are **always `0`** at creation (both the C
  `memset(header,0,512)` path and the C++ `header.Zero()` path never set bytes `76..92`).
- KDF for AES/SHA-512 with PIM 0: **500000** SHA-512 iterations (`src/Common/Pkcs5.c:1256`).
  Header key = PRF(password, salt, iterations) -> first 32 bytes = XTS `k1`, next 32 = XTS `k2`.

---

## 8. Command-line oracle (Q8)

**Windows (wizard, C path — 512-byte effective headers + random reserved areas):**

```
"C:\Program Files\VeraCrypt\VeraCrypt Format.exe" /create C:\tests\vol100.hc /size 100M /password test /encryption AES /hash sha512 /filesystem None /force
```

Options: `/create <file>`, `/size N{K|M|G|T}`, `/password <pw>`, `/pim <n>`, `/keyfile <file>`,
`/hash {sha512|sha256|...}`, `/encryption {AES|Serpent|Twofish|...}`, `/filesystem {None|FAT|NTFS|ExFAT|ReFS}`,
`/quick`, `/dynamic`, `/force`, `/silent`. (`/size` + `/create` syntax per
`doc/html/en/Command Line Usage for Windows.html`; parser `src/Format/Tcformat.c` `ExtractCommandLine`.)

**Cross-platform / Unix C++ path (`Core/VolumeCreator`, 64-KiB headers):**

```
veracrypt --create --size=100M --encryption=AES --hash=SHA-512 --filesystem=none --password=test --pim=0 --keyfiles="" --non-interactive /tmp/vol100.hc
```

(`src/Main/CommandLineInterface.cpp`: `--password` `:537`, `--pim` `:544`, `--keyfiles` `:467`,
`--non-interactive` `:521`, `--random-source` `:616`.) Add `--random-source=<file>` for deterministic
salt/master-key material.

> **Caveat for byte comparison**: salts and master keys are random, so two oracle volumes are never
> byte-identical to each other. For byte-exact tests, fix the RNG (`--random-source`) or compare the
> decrypted effective header (`salt` excluded) plus structure; verify interop by mounting each side's
> volume with the other implementation.

---

## 9. Summary of creation invariants for the Rust implementation

1. File length = requested size `S` (multiple of 512, >= `299008`).
2. Write a valid 512-byte effective header at offset `0` and another at `S - 131072` (different salt,
   same 256-byte master key).
3. Fill `[131072, S - 131072)` as encrypted data (zeros under a throwaway key for a non-quick format).
4. Fill the reserved parts of both 131072-byte header groups with arbitrary random bytes; optionally
   place a valid-looking random 512-byte header at offsets `65536` and `S - 65536`.
5. Header fields: `VolumeDataSize = EncryptedAreaLength = S - 262144`, `EncryptedAreaStart = 131072`,
   `HiddenVolumeDataSize = 0`, `Flags = 0`, `SectorSize = 512`, versions `0x0005`/`0x010b`,
   times `0`, master key random (two halves must differ), salt random 64 B, KDF SHA-512 with 500000 iters.
