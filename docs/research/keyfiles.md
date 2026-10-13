# VeraCrypt Keyfile Processing — Implementation Specification

Target: byte-level compatibility with VeraCrypt 1.26.30 (`C:/Users/yuan/Desktop/VeraCrypt`).
All claims below are taken from the actual sources (paths + line numbers cited). No guessing.

## 1. Source of truth / two implementations (they are equivalent)

There are two code paths that do *exactly* the same thing and must both be reproduced:

| Path | File | Used by |
|---|---|---|
| C | `src/Common/Keyfiles.c` — `KeyFileProcess()` / `KeyFilesApply()` | Windows native GUI/CLI, Format, Mount, ExpandVolume, FormatDLL |
| C++ | `src/Volume/Keyfile.cpp` — `Keyfile::Apply()` / `Keyfile::ApplyListToPassword()` | wx/Unix/macOS GUI + `Core` |

Note: keyfiles are **not** used by the boot loader or the kernel driver (`src/Boot/` and
`src/Driver/` contain no keyfile code — documented as "not supported for system encryption").
C `KeyFilesApply` is wired into the Windows GUI/CLI, Format and ExpandVolume; C++
`ApplyListToPassword` into `Volume/Volume.cpp`, `Core/*` and the GUI front-ends.

## 2. Constants

- `src/Common/Keyfiles.h:22`  `KEYFILE_POOL_LEGACY_SIZE = 64`
- `src/Common/Keyfiles.h:23`  `KEYFILE_POOL_SIZE = 128`
- `src/Common/Keyfiles.h:24`  `KEYFILE_MAX_READ_LEN = 1024*1024` (max bytes processed per keyfile)
- `src/Volume/Keyfile.h:37`   `MinProcessedLength = 1`  (a keyfile with 0 bytes read is an error)
- `src/Volume/Keyfile.h:38`   `MaxProcessedLength = 1024*1024`
- `src/Common/Password.h:22-23` `MAX_LEGACY_PASSWORD = 64`, `MAX_PASSWORD = 128`
- `src/Volume/VolumePassword.cpp:19-20` `MaxLegacySize = 64`, `MaxSize = 128`
- `Password` buffer: `unsigned char Text[MAX_PASSWORD + 1]` = 129 bytes (`Password.h:39-40`).
  C++ `VolumePassword` allocates `MaxSize` = 128 bytes (`VolumePassword.cpp:36`).

The `#if KEYFILE_POOL_SIZE % 4 != 0 #error` guard in `Keyfiles.c:429-431`: pool size must be a
multiple of the 4-byte CRC output. Both 64 and 128 satisfy this.

## 3. Pool size selection (the only "legacy" dimension)

The pool size is decided **from the entered password length**, not from the volume type/version:

```
kpl = (password_len <= 64) ? 64 : 128          // KEYFILE_POOL_LEGACY_SIZE : KEYFILE_POOL_SIZE
```

- C: `Keyfiles.c:239` `keyPoolSize = password->Length <= MAX_LEGACY_PASSWORD ? 64 : 128;`
- C++: `Keyfile.cpp:136` `SecureBuffer keyfilePool(password->Size() <= MaxLegacySize ? MaxLegacySize : MaxSize);`

Consequence: an existing volume created with a <=64-char password + keyfile must be mounted by
choosing a 64-byte pool; one created with a >64-char password must use a 128-byte pool. A Rust
implementation must choose the pool size from the *password length the user types*, not from the
header format. (Commit `cdd1179c` "Increase password maximum length to 128 bytes from 64 bytes"
introduced exactly this split; the keyfile *algorithm* itself was untouched.)

## 4. Exact per-keyfile algorithm (current path)

Per byte `b` of a keyfile, **in order**: `crc = UPDC32(b, crc)` (starting `crc = 0xFFFFFFFF`),
then add the four bytes `crc>>24, crc>>16, crc>>8, crc` (each mod 256) into `pool` at a cursor
that advances and wraps modulo `kpl`; stop after 1 MiB. Exact pseudocode is section 11.

Evidence (identical in both implementations):
- C: `Keyfiles.c:188-203` (`KeyFileProcess`), token branch `Keyfiles.c:276-291`
- C++: `Keyfile.cpp:69-80` (file) and `Keyfile.cpp:46-60` (security-token data)

Key points:
- Bytes are accumulated per keyfile: `pool[i] += ...`, i.e. **mod-256 addition**, never overwrite.
- For each input byte **4 output bytes** are written (big-endian order of the 32-bit CRC register:
  bits 31..24, 23..16, 15..8, 7..0).
- The cursor wraps modulo `kpl`. Because `kpl % 4 == 0` and the cursor always starts at a multiple
  of 4, the mid-group wrap after `writePos++` in C can only trigger on the 4th byte; a simple
  `pos = (pos + 1) % kpl` after each byte is exactly equivalent.
- CRC state is carried across read buffers within one keyfile, and reset to `0xFFFFFFFF` for the
  next keyfile.
- Reading stops after `totalRead >= KEYFILE_MAX_READ_LEN` (1 MiB); bytes beyond are ignored
  (`Keyfiles.c:201`, `Keyfile.cpp:78`).
- A file that yields `totalRead == 0` is an error: `Keyfiles.c:210-212` sets `ERROR_HANDLE_EOF`;
  C++ `Keyfile.cpp:84-85` throws `InsufficientData`.
- C++ `Keyfile::Apply` also rejects a path that *is a directory*: `Keyfile.cpp:24-25`
  `if (Path.IsDirectory()) throw ParameterIncorrect`.

## 5. CRC-32 variant

- Polynomial: `0x04C11DB7` (comment `src/Common/Crc.c:21`), used reflected as `0xEDB88320`
  (bit-serial fallback in `Crc.c:109-121`).
- Table: `src/Common/Crc.c:22-55` (`crc_32_tab[]`), standard CRC-32/ISO-HDLC (zlib) reflected table.
  Verified byte-for-byte equal to a freshly generated reflected table.
- Initial value: `0xFFFFFFFF` (`Keyfiles.c:154`, `Crc32.h:24`).
- Final XOR: **not applied** for keyfiles. Keyfiles use the raw running state
  `crc = UPDC32(b, crc)` (`Crc.h:24-25`) / `Crc32::Process()` (`Crc32.h:29-32`), *not*
  `GetCrc32()` (`Crc.c:57-66`) or `Crc32::Get()` (`Crc32.h:27`), both of which XOR with
  `0xFFFFFFFF` at the end. Do **not** finalize.
- Input bytes: the first `min(file_size, 1 MiB)` bytes of the keyfile, in file order.
- Written into the pool as the 4 bytes of the running register in big-endian order (see section 4).

Selftest constant (useful cross-check of the table, not of keyfiles):
`CRC_SELFTEST = 0x6fcf9e13` on little-endian, `0xca87914d` on big-endian (`Crc.c:80-83`).

## 6. Combining multiple keyfiles

Each keyfile is applied to the same pool, independently, cursor restarting at 0 each time.
Because the operation is commutative addition, **order does not matter** (confirmed by the docs:
"Note that VeraCrypt never modifies the keyfile contents. You can select more than one keyfile;
the order does not matter."). A keyfile list is a linked list (`KeyFile.Next`) / `KeyfileList`
(`Keyfile.h`); all entries are applied.

Directory entries are expanded first (see section 8). C++ guard: if after expansion
`keyfilesExp.size() < 1` the password is returned unchanged (`Keyfile.cpp:130-133`).

## 7. Combining the pool with the password

Two equivalent formulations; result is byte-wise `result[i] = password[i] (0-padded) + pool[i]`
mod 256.

C (`Keyfiles.c:392-401`):
```
for i in 0..kpl-1:
    if i < password->Length: password->Text[i] += keyPool[i]
    else:                    password->Text[i]  = keyPool[i]
if password->Length < kpl:  password->Length = kpl
```
C++ (`Keyfile.cpp:136-148`):
```
keyfilePool = SecureBuffer(kpl); keyfilePool.Zero();
keyfilePool.CopyFrom(password);                 # password padded with zeros to kpl
for each keyfile k: k.Apply(keyfilePool);
newPassword.Set(keyfilePool);                   # password = entire kpl bytes
```

Consequences (must match exactly):
- Resulting password length is **always `kpl`** (64 or 128), never the original length.
- Empty password + keyfile -> password becomes the raw 64-byte pool; length 64.
- Password is **not** concatenated after the pool and not hashed here; it is 0-padded and
  byte-added to the pool. (The official doc HTML describes the mix as XOR and kpl=64; that is
  stale/incorrect — the code has always used mod-256 `+=`.)
- The resulting buffer is passed verbatim to the PRF: `src/Volume/Pkcs5Kdf.cpp:109,121,134,146,158,171`
  `derive_key_*(password.DataPtr(), (int)password.Size(), ...)` and `src/Common/Volumes.c:322`
  `crypto_loadkey(keyInfo, password->Text, (int) password->Length)`. Length is the full pool size;
  the buffer is not NUL-terminated and NUL bytes are significant.
- Max resulting length = 128 = `MAX_PASSWORD`.

## 8. Files, directories, rejection rules

`IsKeyfilePathValid` in current code is **`Token::IsKeyfilePathValid`** (`src/Common/Token.cpp:75-82`),
not a `Keyfile::` method (that name does not exist in this tree). It only recognizes security-token /
EMV URL prefixes, not file types:

```
Token::IsKeyfilePathValid(path, emv):
    return SecurityToken::IsKeyfilePathValid(path)            # path starts with TC_SECURITY_TOKEN_KEYFILE_URL_PREFIX
        || (emv && EMVToken::IsKeyfilePathValid(path));       # or TC_EMV_TOKEN_KEYFILE_URL_PREFIX
```
(`SecurityToken.cpp:425-428`, `EMVToken.cpp:136-139`.)

Non-token paths are treated as filesystem paths:

- C++ (`Keyfile.cpp:100-129`): if `FilesystemPath::IsDirectory()`, enumerate
  `Directory::GetFilePaths(path)` with `regularFilesOnly = true`
  (`Platform/Unix/Directory.cpp:46-68`): **non-recursive**, only `S_ISREG` entries
  (`FilesystemPath.cpp:50`), i.e. sub-directories, devices, FIFOs, sockets are skipped. On Unix a
  basename starting with `.` is skipped as hidden (`Keyfile.cpp:107-113`). If a directory yields 0
  files -> `KeyfilePathEmpty` (`Keyfile.cpp:123-124`).
- C (`Keyfiles.c:296-381`): `_wstat`; if `S_IFDIR`, scan with `_wfindfirst("%s\*.*")`,
  skip sub-directories (`Keyfiles.c:339-342`), skip `FILE_ATTRIBUTE_HIDDEN` files
  (`Keyfiles.c:346-350`), skip the container file itself if `volumeFileName` matches
  (`Keyfiles.c:356-360`). Directory with 0 usable files -> error `ERR_KEYFILE_PATH_EMPTY`.
  Hidden files explicitly added as files are still processed.
- Rejected / error: a directory passed directly to `Keyfile::Apply` (ParameterIncorrect);
  a zero-length file / unreadable path (`ERROR_HANDLE_EOF` / `InsufficientData`); a directory
  search path with no regular files. There is **no extension-based filtering** (all file types are
  accepted; devices/sockets are excluded only by the `S_ISREG` filter during directory expansion,
  and on Unix symlinks are followed by `stat()`).

## 9. Is a hash (BLAKE2/RIPEMD) involved?

No. Keyfile bytes go through **CRC-32 (raw, unfinalized) + mod-256 accumulation only**.
No BLAKE2/RIPEMD/SHA touches keyfile bytes; the resulting buffer is later fed as the *password*
to the normal PBKDF2/Argon2 header KDF.

## 10. The "legacy" keyfile format (TrueCrypt 6.0 / earlier)

Critical finding from the actual repository history: **there is no file-length-dependent or
content-versioned legacy keyfile format in this tree, and there never was.** Verifying with
`git log --all -S KEYFILE_POOL_LEGACY` returns exactly one commit, `cdd1179c` ("Increase password
maximum length to 128 bytes from 64 bytes"), which introduced the *pool-size* split only. There is
no keyfile format marker/version byte, and nothing reads a keyfile's total length to decide an
algorithm. The official VeraCrypt keyfile doc says the same: keyfiles have never changed except for
the 64->128 pool extension.

What this means for compatibility:

- The "legacy" behaviour that must be preserved is the **64-byte pool**, selected when the entered
  password length is `<= 64` (`Keyfiles.h:22`, `Keyfiles.c:239`, `Keyfile.cpp:136`).
- Keyfiles created by TrueCrypt 6.0/7.1a (and VeraCrypt) use the identical CRC-32 + mod-256
  accumulation; only the pool size differs. A keyfile file is never "detected" as legacy vs
  current — there is no marker — so a Rust implementation must not try to sniff the keyfile.
- The file *length* is used only as the read-loop bound: process `min(len, 1 MiB)` bytes. A keyfile
  that is empty (0 readable bytes) is an error, never a no-op.
- To reproduce legacy behaviour, choose `kpl = 64` whenever the supplied password is `<= 64` bytes
  (which is what an old TrueCrypt-6.0-era user would have used), regardless of the volume header
  version. Do not derive `kpl` from the volume's `Version` field.

## 11. Consolidated pseudocode (bit-exact reference)

```
function apply_keyfiles(password_bytes: []u8, keyfiles: [Keyfile]) -> [u8; 128]:
    kpl = (len(password_bytes) <= 64) ? 64 : 128

    pool = [0u8; kpl]                       # C++ also seeds this with the password; see below
    for kf in keyfiles:                     # directories pre-expanded; order irrelevant
        crc = 0xFFFFFFFF
        pos = 0
        total = 0
        for b in kf.bytes:                  # stop at 1 MiB
            crc = crc32_byte(crc, b)
            for k in [crc>>24, crc>>16, crc>>8, crc]:   # big-endian register bytes
                pool[pos] = pool[pos] +% u8(k); pos = pos + 1; if pos == kpl: pos = 0
            total += 1; if total == 1024*1024: break
        if total == 0: return ERROR           # empty/unreadable keyfile

    # C++ path: pool already contained the password, so nothing more to do.
    # C path: now byte-add the password into the pool:
    for i in 0 .. kpl-1:
        if i < len(password_bytes): pool[i] = pool[i] +% password_bytes[i]
    return pool                               # length is ALWAYS kpl (64 or 128)
```

`crc32_byte(crc, b) = crc_tab[(crc ^ b) & 0xFF] ^ (crc >> 8)`, reflected CRC-32/ISO-HDLC table
(`Crc.c:22-55`); `+%` is wrapping (mod 256) addition.

## 12. Test vectors

There are **no keyfile test vectors anywhere in the VeraCrypt tree** (searched `Tests/`,
`src/Common/*.c`, `src/Common/*.h`; the only "keyfile" hits are unrelated mount/format UI tests).
Values below come from an independent implementation of section 11; treat them as self-derived
until cross-checked against the real binary (section 13). Each is the final password buffer.

Shared keyfile byte sequences:
- `KF_A` = bytes `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f` (16 bytes)
- `KF_B` = ASCII `"second-keyfile"` (14 bytes)
- `KF_C` = ASCII `"keyfile"` (7 bytes)

**TV1** — password ASCII `"abc"` (`61 62 63`), keyfiles `[KF_A]`, `kpl = 64` (password <= 64):
```
8e5f7372c921dd96f7ab7680744679ecaea52c33cf1430b552a7f6067755976
0431ebcfdba9328b952d2711e6d8f369a1901b9479610a9375f9398a131311d77
```
(64 bytes; the line break is cosmetic — concatenate the two lines.)

**TV2** — empty password `""`, keyfiles `[KF_C]`, `kpl = 64` (empty counts as <= 64):
```
f79da8a205f7cabb756f545626ac5ff8872e0f8dd78afce1ea02cdc500000000
0000000000000000000000000000000000000000000000000000000000000000
```
(64 bytes; 7 keyfile bytes -> 28 pool bytes, rest zero.)

**TV3** — password = 65 bytes of `0x41` (`"AAAA…"`), keyfiles `[KF_A, KF_B]`, `kpl = 128`
(password > 64):
```
522f81a7914e70b9d22416a52f771c24788f48f659355f8cefe2c131527921dd
968c07574874b54cb40c06589efee1ebb3850d05ea86c5bda0d4d9e272725eb8
4100000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
```
(128 bytes; byte 64 = `41`, bytes 65..127 zero.)

**TV4** — CRC primitives for unit-testing your table (raw, unfinalized register):
- `crc(0xFFFFFFFF, [0x00]) = 0x2DFD1072`
- `crc(0xFFFFFFFF, "123456789") = 0x340BC6D9` (raw; the finalized `^ 0xFFFFFFFF` value is the
  standard CRC-32 check value `0xCBF43926`).

## 13. Cross-checking against real VeraCrypt (recommended)

Because no official vectors exist, verify end-to-end. (1) Create a volume with a known password +
keyfile via `VeraCrypt.exe /c /q /k <keyfile> <volume-file>` (or GUI), using e.g. `"abc"` for a
64-byte pool or a 65+-char password for a 128-byte pool.
(2) Derive the header key for that password+keyfile and decrypt the volume header (same salt / KDF /
PRF); a `TRUE`/`VERA` magic + valid header CRC means the derived password matched. A failure points
at byte order, pool size, or an unwanted CRC finalisation.
(3) Unit-test the pure pool function against TV1–TV4, and branch the pool size on the *entered*
password length while never finalising the CRC and never hashing keyfile bytes.
