# VeraCrypt 1.26.30 — Volume expansion & non-system in-place encryption

Source of truth: VeraCrypt 1.26.30 C/C++ tree at `C:/Users/yuan/Desktop/VeraCrypt`
(`VERSION_STRING "1.26.30"`, `src/Common/Tcdefs.h:62`). Every claim below carries a `file:line` ref
from that tree. This note covers, in depth, (A) growing an existing **file-hosted normal
(non-hidden, non-system) volume**, as done by `VeraCryptExpander.exe`, and (B) VeraCrypt's
**non-system in-place encryption** of a partition. It does **not** cover hidden/system volumes
except where they gate the two features.

---

## 0. Constants used throughout

| Constant | Value | Ref |
|---|---|---|
| `TC_VOLUME_HEADER_SIZE` | 65536 (64 KiB) | `src/Common/Volumes.h:51` |
| `TC_VOLUME_HEADER_EFFECTIVE_SIZE` | 512 | `src/Common/Volumes.h:52` |
| `TC_VOLUME_HEADER_GROUP_SIZE` = 2xheader | 131072 | `src/Common/Volumes.h:56` |
| `TC_TOTAL_VOLUME_HEADERS_SIZE` = 4xheader | 262144 | `src/Common/Volumes.h:57` |
| `TC_VOLUME_HEADER_OFFSET` | 0 | `src/Common/Volumes.h:60` |
| `TC_HIDDEN_VOLUME_HEADER_OFFSET` | 65536 | `src/Common/Volumes.h:61` |
| `TC_VOLUME_DATA_OFFSET` = header group | 131072 | `src/Common/Volumes.h:77` |
| `ENCRYPTION_DATA_UNIT_SIZE` | 512 | `src/Common/Crypto.h:39` |
| `TC_HEADER_FLAG_ENCRYPTED_SYSTEM` | `0x1` | `src/Common/Volumes.h:134` |
| `TC_HEADER_FLAG_NONSYS_INPLACE_ENC` | `0x2` | `src/Common/Volumes.h:135` |
| `TC_MINVAL_FS_EXPAND` | `64*1024` | `src/ExpandVolume/ExpandVolume.h:24` |

Header-field byte offsets are in `src/Volume/VolumeHeader.h` (`TC_HEADER_OFFSET_VOLUME_SIZE`,
`TC_HEADER_OFFSET_HIDDEN_VOLUME_SIZE`, `TC_HEADER_OFFSET_ENCRYPTED_AREA_START`,
`TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH`, `TC_HEADER_OFFSET_FLAGS`, `TC_HEADER_OFFSET_HEADER_CRC`).

`GetVolumeDataAreaSize(volumeSize, legacy)` = `volumeSize - (legacy ? 512 : 262144)`
(`src/ExpandVolume/ExpandVolume.c:352-366`; a different overload for the formatter lives at
`src/Common/Format.c:44`). Its inverse `GetVolumeSizeByDataAreaSize` adds the reserved size back
(`src/ExpandVolume/ExpandVolume.c:368-385`).

---

# A. VOLUME EXPANSION (file-hosted normal volume)

## A.1 Entry points

* The expander is a **separate executable**, `VeraCryptExpander.exe` (its own `wWinMain` /
  `ExpandVolumeWizard`), not a mode of `VeraCrypt.exe`. The main GUI launches it via
  `LaunchVolExpander` (`src/Mount/Mount.c:2168-2205`), wired to the menu command
  `IDM_VOLUME_EXPANDER` ("Volume Expander"); menu text `src/Common/Language.xml:263`.
* The expander window's "Expand" button calls `ExpandVolumeWizard (hwndDlg, fileName)`
  (`src/ExpandVolume/WinMain.cpp:1059`; drag&drop path `src/ExpandVolume/WinMain.cpp:1028-1059`).
* The expander has **no volume-specific CLI switches**. Its `ExtractCommandLine` only knows
  `/protectMemory` and `/protectScreen` (`src/ExpandVolume/WinMain.cpp:873-935`, `:1112-1146`).
  Expansion from a command line is therefore not a VeraCrypt feature; the GUI dialog is the only
  entry point.

## A.2 Complete operation sequence

`ExpandVolumeWizard` (`src/ExpandVolume/DlgExpandVolume.cpp:532-843`) runs, in order:

1. **Refuse system volumes** — `switch (IsSystemDevicePath(lpszVolume, hwndDlg, TRUE))`
   (`DlgExpandVolume.cpp:545`); a match aborts with `EXPANDER_SYSTEM_VOLUME_ERROR`
   (`Language.xml:1593`).
2. **Refuse mounted volumes** — `if (IsMountedVolume(lpszVolume)) { Warning("UNMOUNT_FIRST",...); }`
   (`DlgExpandVolume.cpp:556-558`). The volume must be **dismounted**.
3. `Randinit()` (`DlgExpandVolume.cpp:560`).
4. **Ask whether the volume contains a hidden volume** — `AskMultiChoice` with choices
   `DOES_VOLUME_CONTAIN_HIDDEN` / `VOLUME_CONTAINS_HIDDEN` / `VOLUME_DOES_NOT_CONTAIN_HIDDEN` /
   `IDCANCEL`. Answer 1 ("does contain") aborts:
   `MessageBoxW(..., GetString("EXPANDER_HIDDEN_VOLUME_ERROR"), ...)`
   (`DlgExpandVolume.cpp:570-581`; text `Language.xml:1592`). So an outer volume containing a hidden
   volume is actively refused (growing the outer volume destroys the hidden one).
5. `QueryVolumeInfo` gets host size / free space / max FS size (`DlgExpandVolume.cpp:590`).
6. **Open the volume and read its header** — `OpenVolumeContext` loop
   (`DlgExpandVolume.cpp:600-655`); gives the existing `EncryptedAreaStart`, `EncryptedAreaLength`,
   algorithm/mode, `HeaderFlags`, `SectorSize`, `RequiredProgramVersion`, `LegacyVolume`, master key.
7. `MountVolTemp` the volume temporarily to read the filesystem type, then `UnmountVolume`
   (`DlgExpandVolume.cpp:658-681`).
8. **Free-space / minimum-size checks** (`DlgExpandVolume.cpp:695-708`): device
   `hostSize < volSize + TC_MINVAL_FS_EXPAND` -> refuse; file `hostSizeFree < TC_MINVAL_FS_EXPAND`
   -> `EXPANDER_NO_FREE_SPACE` (`Language.xml:1594`).
9. Defaults (`DlgExpandVolume.cpp:742-744`):
   `bInitFreeSpace = (bIsLegacy && bIsDevice) ? FALSE : TRUE` (so **TRUE for a file-hosted normal
   volume**), `bQuickExpand = FALSE`, `bDisableQuickExpand = bIsDevice`. For a file container that
   is compressed or sparse (`dwFileAttrib & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)`)
   Quick Expand is disabled (`DlgExpandVolume.cpp:762-763`).
10. User picks the new size (must grow by >= `TC_MINVAL_FS_EXPAND`; `DlgExpandVolume.cpp:782-789`),
    then `ExpandVolume()` runs (`src/ExpandVolume/ExpandVolume.c:502`).

`ExpandVolume()` itself, before touching the file, does (`src/ExpandVolume/ExpandVolume.c:502-768`):

* Opens the device/file `GENERIC_READ | GENERIC_WRITE`.
* **Refuses system-encryption volumes**:
  `if (cryptoInfo->HeaderFlags & TC_HEADER_FLAG_ENCRYPTED_SYSTEM)` ->
  `ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG` (`ExpandVolume.c:709-712`).
* **Minimum/geometry checks** (`ExpandVolume.c:721-728`):
  `newHostSize % cryptoInfo->SectorSize != 0 || newHostSize > TC_MAX_VOLUME_SIZE ||
  (bDevice && newHostSize > hostSize)` -> `ERR_PARAMETER_INCORRECT`.
* `newDataAreaSize = GetVolumeDataAreaSize(newHostSize, cryptoInfo->LegacyVolume)`
  (`ExpandVolume.c:731`).
* **Growth must be >= `TC_MINVAL_FS_EXPAND`**: `newDataAreaSize < cryptoInfo->VolumeSize.Value +
  TC_MINVAL_FS_EXPAND` -> `ERR_PARAMETER_INCORRECT` (`ExpandVolume.c:758-763`).

## A.3 Growing the host file, and where the space lives

For a **file-hosted** volume (`!bDevice`) the host file is grown with the Win32 length APIs, not by
writing data (`src/ExpandVolume/ExpandVolume.c:776-812`):

```c
liNewSize.QuadPart = (LONGLONG) newHostSize;
if (hostSize != newHostSize)
{
    if (!SetFilePointerEx (dev, liNewSize, NULL, FILE_BEGIN)
        || !SetEndOfFile (dev))
        ... ERR_OS_ERROR;
    if (bQuickExpand)
    {
        if (!SetFileValidData (dev, liNewSize.QuadPart))
            ... // Quick Expand failed
    }
}
```

* `SetEndOfFile` extends the file logically (sparse/zero on NTFS); `SetFileValidData` is only
  called for **Quick Expand** (it marks the range allocated/valid without zeroing, which needs
  `SE_MANAGE_VOLUME_NAME`; cf. `EXPANDER_ERROR_QUICKEXPAND_PRIVILEGES`, `Language.xml:1602`).
* No trailing zeros are explicitly written here.

**Where the new space lives.** The data area is `[EncryptedAreaStart, EncryptedAreaStart +
VolumeDataSize)`. After expansion `VolumeDataSize = newDataAreaSize` and the start stays at the old
value (normally `TC_VOLUME_DATA_OFFSET = 131072`). So the data area grows **at the end of the
volume**: the new bytes are `[131072 + oldDataAreaSize, 131072 + newDataAreaSize)` =
`[oldHostSize, newHostSize - 131072)`. Immediately after the data area, at
`[newHostSize - 131072, newHostSize)`, sits the **relocated backup header group**
(`newHostSize - TC_VOLUME_HEADER_GROUP_SIZE`). The old backup header group at
`[oldHostSize - 131072, oldHostSize)` is now in the middle of the data area and is wiped (A.5).

Because expansion **refuses hidden volumes**, there is no real hidden-volume region to preserve.
The only hidden-related bytes are the *fake* hidden header(s): the static fake hidden header at
`TC_HIDDEN_VOLUME_HEADER_OFFSET = 65536` in the primary header group is untouched, and the fake
hidden header slot in the **new** backup group lands at `newHostSize - 65536`.

## A.4 Header field updates (exact arithmetic)

All header (re)creation uses `CreateVolumeHeaderInMemory(...)`
(`src/Common/Volumes.h:151-162`; impl `src/Common/Volumes.c:1009-1244`). For both the backup and
the primary header the expander calls it as (`src/ExpandVolume/ExpandVolume.c:884-902`):

```c
nStatus = CreateVolumeHeaderInMemory (hwndDlg, FALSE,
    buffer,
    cryptoInfo->ea,
    cryptoInfo->mode,
    pVolumePassword,
    cryptoInfo->pkcs5,
    VolumePim,
    (char*)(cryptoInfo->master_keydata),
    &ci,
    newDataAreaSize,                              // volumeSize (VolumeDataSize)
    0,                                            // hiddenVolumeSize
    cryptoInfo->EncryptedAreaStart.Value,         // encryptedAreaStart
    newDataAreaSize,                              // encryptedAreaLength
    cryptoInfo->RequiredProgramVersion,
    cryptoInfo->HeaderFlags,
    cryptoInfo->SectorSize,
    FALSE ); // use slow poll
```

Therefore, for a file-hosted normal volume after expansion:

| Header field | New value | Source |
|---|---|---|
| `VolumeDataSize` | `newDataAreaSize` = `newHostSize - 262144` | `ExpandVolume.c:893` |
| `HiddenVolumeDataSize` | `0` | `ExpandVolume.c:894` |
| `EncryptedAreaStart` | **unchanged** = old `EncryptedAreaStart.Value` (normally `131072` = `TC_VOLUME_DATA_OFFSET`) | `ExpandVolume.c:895` |
| `EncryptedAreaLength` | `newDataAreaSize` (the **whole** new data area) | `ExpandVolume.c:896` |
| `RequiredProgramVersion` | unchanged | `ExpandVolume.c:897` |
| `Flags` (`HeaderFlags`) | unchanged | `ExpandVolume.c:898` |
| `SectorSize` | unchanged | `ExpandVolume.c:899` |

The asymmetry worth spelling out: `VolumeDataSize` is the *data-area* size
(`newHostSize - 2*TC_VOLUME_HEADER_SIZE`), **not** the host size; and `EncryptedAreaLength` is set
equal to `VolumeDataSize`, i.e. the header states the volume is **fully encrypted after expansion**.
(`newDataAreaSize = newHostSize - TC_TOTAL_VOLUME_HEADERS_SIZE`, with
`TC_TOTAL_VOLUME_HEADERS_SIZE = 4*TC_VOLUME_HEADER_SIZE = 262144 = 2*TC_VOLUME_HEADER_GROUP_SIZE`.)

Legacy volumes: `ExpandVolume.c:867` guards the whole header-rewrite loop with
`while (!cryptoInfo->LegacyVolume)` — for a legacy volume the header is **not** updated at all (the
volume is only resized on disk).

## A.5 Order of header writes, fresh salt, and required credentials

The loop at `src/ExpandVolume/ExpandVolume.c:862-1006` does **backup header first, primary header
second**:

1. `backupHeader = TRUE;` and
   `headerOffset = TC_VOLUME_HEADER_OFFSET + newHostSize - TC_VOLUME_HEADER_GROUP_SIZE`
   (`ExpandVolume.c:863-864`) -> absolute offset `newHostSize - 131072`.
2. `CreateVolumeHeaderInMemory(...)` for that header, then `WriteEffectiveVolumeHeader(bDevice,
   dev, buffer)` at `headerOffset` (`ExpandVolume.c:884-924`).
3. **Fake hidden header / reserved-area fill** — only when (`ExpandVolume.c:927-935`):

   ```c
   ( backupHeader && !initFreeSpace )
   || ( bDevice && !cryptoInfo->LegacyVolume && !cryptoInfo->hiddenVolume
        && cryptoInfo->HeaderVersion == 4
        && (cryptoInfo->HeaderFlags & TC_HEADER_FLAG_NONSYS_INPLACE_ENC) != 0
        && (cryptoInfo->HeaderFlags & ~TC_HEADER_FLAG_NONSYS_INPLACE_ENC) == 0 )
   ```

   Inside: `WriteRandomDataToReservedHeaderAreas(hwndDlg, dev, cryptoInfo, newDataAreaSize,
   !backupHeader, backupHeader)` (`ExpandVolume.c:949`) fills the header group's reserved sectors
   with ciphertext under a **throwaway** key (`src/Common/Volumes.c:1487-1545`), then a *fake*
   hidden header (`hiddenVolumeSize = newDataAreaSize`, random password `NULL`) is written at
   `hiddenOffset = headerOffset + TC_HIDDEN_VOLUME_HEADER_OFFSET` (`ExpandVolume.c:961-995`). For a
   **standard file-hosted volume with `initFreeSpace == TRUE`** neither disjunct is true, so no fake
   hidden header is written during expansion (the earlier `FormatNoFs` already left ciphertext in
   that slot).
4. `FlushFileBuffers(dev)`; `backupHeader = FALSE; headerOffset = TC_VOLUME_HEADER_OFFSET;`
   (`ExpandVolume.c:998-1005`) -> **primary header at offset 0**, same call, same field values.
5. **Wipe the old backup header** at `offset = currentVolSize - TC_VOLUME_HEADER_GROUP_SIZE`
   (`ExpandVolume.c:1017-1100`; `currentVolSize` = old host size), a full wipe of one header group
   using the selected wipe algorithm, with the buffer encrypted before writing.

**Fresh salt / key / credentials.** `CreateVolumeHeaderInMemory` always generates a fresh random
salt: `RandgetBytes(hwndDlg, keyInfo.salt, PKCS5_SALT_SIZE, ...)` (`src/Common/Volumes.c:1128-1135`).
It derives the header key from the **password + PIM + keyfiles + salt**. The **master key is not
regenerated** for expansion — the existing `cryptoInfo->master_keydata` is passed in
(`ExpandVolume.c:892`), so the volume's data key is preserved. Consequently the user must supply the
**password/PIM/keyfiles again** (needed to derive the new header key), and both headers end up with
**different fresh salts** from each other and from the originals. The `ci` returned by each call
(`ExpandVolume.c:902`) is closed immediately; only the header buffer is written.

## A.6 Is the newly added area encrypted or left plaintext? (the crucial question)

**The new area is declared ENCRYPTED, not left in a "to-be-encrypted" state.**
`EncryptedAreaLength` is set to `newDataAreaSize` (A.4), equal to the new `VolumeDataSize`
(`ExpandVolume.c:896`). There is **no** call to `EncryptPartitionInPlace*` or any partial-encryption
state from the expansion path; `EncryptedAreaStart` stays at the old data offset and the encrypted
length covers the whole enlarged data area.

What is physically written into the new bytes depends on `initFreeSpace`:

* **`initFreeSpace == TRUE` (default for a file-hosted normal volume):** the entire new region
  `[currentVolSize/512, newHostSize/512)` sectors is overwritten by the *expander's own*
  `FormatNoFs` (`src/ExpandVolume/ExpandVolume.c:814-832`). That function
  (`src/ExpandVolume/InitDataArea.c:47-172`) generates a **temporary random master key and a
  temporary XTS secondary key** and writes dummy-encrypted random data (comment there: "Generate a
  random temporary key set to be used for 'dummy' encryption that will fill the free disk space").
  It then restores the original secondary key and re-inits the algorithm with the real
  `master_keydata` (`InitDataArea.c:147-160`). So the new area is physical ciphertext, but under a
  **throwaway key**, not the volume's real key.
* **`initFreeSpace == FALSE`:** the new area is left as `SetEndOfFile`/`SetFileValidData` left it
  (sparse zeros / uninitialized extents). No plaintext filesystem data is written.

In both cases the read/write path treats the new bytes as ciphertext: a file-hosted normal volume
uses `VolumeLayoutV2Normal::GetDataOffset` = `Header->GetEncryptedAreaStart()`
(`src/Volume/VolumeLayout.cpp:129-131`), so host offset `VolumeDataOffset + byteOffset`. Because
that layout's `HasDriveHeader()` is false, `Volume::Open` never sets `EncryptionNotCompleted` for
file-hosted normal volumes (`src/Volume/Volume.cpp:206-213`; the flag is set only for the
drive-header layout when `GetEncryptedAreaLength() != GetVolumeDataSize()`). `Volume::ReadSectors`
therefore always takes the full-decrypt branch:

```c
EA->DecryptSectors (buffer.GetRange (bufferOffset, length),
                    hostOffset / SectorSize, length / SectorSize, SectorSize);
```

(`src/Volume/Volume.cpp:319-339`). The Windows driver refuses a partial non-system in-place volume
at mount (`src/Driver/Ntvol.c:705-713`, `ERR_NONSYS_INPLACE_ENC_INCOMPLETE`) unless
`EncryptedAreaLength == VolumeSize`, and derives XTS data units from host offsets
(`src/Driver/EncryptedIoQueue.c:930-940,1085-1101`).

**Consequence:** when the header is updated, the new space is *logically* encrypted and reading it
with the volume key yields pseudo-random garbage (throwaway-key ciphertext, or zero-decryption
nonsense). That is harmless because it is unformatted free space: the next step
(`ExtendFileSystem`, A.7) hands those sectors to the filesystem as free clusters, and any later
write of real data is encrypted with the real volume key. VeraCrypt does **not** leave the new tail
"plaintext until an in-place pass runs" — no such pass is ever used for expansion.

## A.7 Extending the filesystem and the success message

* After the headers are updated, `ExpandVolume` calls
  `ExtendFileSystem(hwndDlg, lpszVolume, ...)` (`src/ExpandVolume/ExpandVolume.c:1120`,
  impl `:381-461`): it `MountVolTemp`s the volume read/write, issues `FSCTL_EXTEND_VOLUME`
  (`FsctlExtendVolume`, `:454`) with `newDataAreaSize/BytesPerSector`, then `UnmountVolume`. Only
  NTFS/RAW are extended; other filesystems return `ERR_SUCCESS` with a warning
  (`EXPANDER_WARNING_FAT` / `_EXFAT` / `_UNKNOWN_FS`, `Language.xml:1596-1598`).
* On success the progress dialog shows `EXPANDER_FINISH_OK` — *"Finished. Volume successfully
  expanded."* (`src/Common/Language.xml:1589`). Progress/status strings:
  `EXPANDER_STARTING_STATUS`, `EXPANDER_WRITING_RANDOM_DATA`, `EXPANDER_WRITING_ENCRYPTED_BACKUP`,
  `EXPANDER_WRITING_ENCRYPTED_PRIMARY`, `EXPANDER_WIPING_OLD_HEADER`
  (`Language.xml:1591,1622-1625`). Failures print `EXPANDER_FINISH_ERROR` / `EXPANDER_FINISH_ABORT`
  (`Language.xml:1587-1588`).
* If any step after the host file was grown fails, the file is shrunk back to its original size
  (`ExpandVolume.c:850-859`).

---

# B. NON-SYSTEM IN-PLACE ENCRYPTION

Implementation: `src/Format/InPlace.c` (`EncryptPartitionInPlaceBegin`,
`EncryptPartitionInPlaceResume`, `DecryptPartitionInPlace`, `FastVolumeHeaderUpdate`,
`OpenBackupHeader`). Constants (`src/Format/InPlace.c:53-63`):

```c
#define TC_MAX_NONSYS_INPLACE_ENC_WORK_CHUNK_SIZE     (2048 * BYTES_PER_KB)   // 2 MiB
#define TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE          (2 * TC_MAX_VOLUME_SECTOR_SIZE)
#define TC_NTFS_CONCEAL_CONSTANT                      0xFF
#define TC_NONSYS_INPLACE_ENC_HEADER_UPDATE_INTERVAL  (64 * BYTES_PER_MB)      // 64 MiB
#define TC_NONSYS_INPLACE_ENC_MIN_VOL_SIZE            (TC_TOTAL_VOLUME_HEADERS_SIZE + TC_MIN_NTFS_FS_SIZE * 2)
```

## B.1 Progress model and the read path

For a partially encrypted volume:

* `EncryptedAreaLength` = number of **contiguous bytes already encrypted**, counted **backward from
  the end of the data area**. `EncryptedAreaStart` = offset of the **first encrypted byte**; the
  encrypted region is `[EncryptedAreaStart, EncryptedAreaStart + EncryptedAreaLength)`, and
  `EncryptedAreaStart + EncryptedAreaLength = VolumeSize + TC_VOLUME_DATA_OFFSET` (end of data area)
  until the process finishes. Encryption walks **downward**: each 2 MiB chunk does
  `EncryptedAreaStart -= workChunkSize; EncryptedAreaLength += workChunkSize;`
  (`src/Format/InPlace.c:1053-1056`). The not-yet-processed region is the **low** part of the data
  area, `[TC_VOLUME_DATA_OFFSET, EncryptedAreaStart)`.

* **Read-path rule.** In the platform-independent core, `Volume::Open` sets
  `EncryptedDataSize = header->GetEncryptedAreaLength()` and, only for the drive-header layout, sets
  `EncryptionNotCompleted = true` and forces `Protection = ReadOnly` when
  `EncryptedAreaLength != VolumeDataSize` (`src/Volume/Volume.cpp:206-214`). `ReadSectors` then
  decrypts **only the intersection** with the encrypted region (the caller must pass sector-aligned
  offsets/lengths; `EncryptedDataSize` comes from the header and is a multiple of the data-unit
  size):

  ```c
  if (EncryptionNotCompleted)
  {
      // if encryption is not complete, we decrypt only the encrypted sectors
      if (hostOffset < EncryptedDataSize)
      {
          uint64 encryptedLength = VC_MIN (length, (EncryptedDataSize - hostOffset));
          EA->DecryptSectors (buffer.GetRange (bufferOffset, encryptedLength),
                              hostOffset / SectorSize,
                              encryptedLength / SectorSize, SectorSize);
      }
  }
  ```

  (`src/Volume/Volume.cpp:319-333`). Everything at/after `EncryptedDataSize` is returned **verbatim,
  i.e. as plaintext**. The Windows driver does the same via
  `GetIntersection(fragment.offset, fragment.length, EncryptedAreaStart, EncryptedAreaEnd)` and only
  decrypts/encrypts the intersecting bytes; non-intersecting bytes pass through unchanged
  (`src/Driver/EncryptedIoQueue.c:930-940`, `:1085-1101`; `EncryptedAreaEnd = EncryptedAreaLength
  - 1` is set at `src/Driver/Ntdriver.c:3428-3444`, only for partial **system** encryption).

* **However**, for **non-system** in-place encryption the partial volume is *not mountable at all*.
  `src/Driver/Ntvol.c:705-713`:

  ```c
  else if (Extension->cryptoInfo->HeaderFlags & TC_HEADER_FLAG_NONSYS_INPLACE_ENC)
  {
      if (Extension->cryptoInfo->EncryptedAreaLength.Value != Extension->cryptoInfo->VolumeSize.Value)
      {
          // Non-system in-place encryption process has not been completed on this volume
          mount->nReturnCode = ERR_NONSYS_INPLACE_ENC_INCOMPLETE;
          ntStatus = STATUS_SUCCESS; goto error;
      }
  }
  ```

  So the plaintext-tail read rule is observable for partially-encrypted **system** volumes (they
  mount read-only, `Ntvol.c:700-703`) and in the cross-platform core's drive-header path; a
  partially non-system-in-place-encrypted volume must be **resumed**, not mounted. Once finished
  (`EncryptedAreaLength == VolumeSize`) the flag may remain set and mounting is allowed.

## B.2 Resumption rules

* **Granularity:** work is done in chunks of `min(remainingBytes,
  TC_MAX_NONSYS_INPLACE_ENC_WORK_CHUNK_SIZE)` = at most **2 MiB**, and each chunk must be a multiple
  of `ENCRYPTION_DATA_UNIT_SIZE` (`src/Format/InPlace.c:778-784`, `:918-936`).
* **Header update cadence:** the backup header is refreshed whenever
  `lastHeaderUpdateDistance >= TC_NONSYS_INPLACE_ENC_HEADER_UPDATE_INTERVAL` = **every 64 MiB**
  (`src/Format/InPlace.c:1057-1071`), and once more unconditionally after the loop (`:1073-1078`).
  On error or user abort, `closing_seq` also calls `FastVolumeHeaderUpdate` if
  `bEncryptedAreaSizeChanged` (`:1243-1252`). One 64 MiB interval equals 32 x 2 MiB chunks.
* `FastVolumeHeaderUpdate` (`src/Format/InPlace.c:1826-1913`) reads the backup header at
  `offset = deviceSize - TC_VOLUME_HEADER_GROUP_SIZE` (`:1844-1852`), decrypts it, writes
  `EncryptedAreaStart`/`EncryptedAreaLength` from `masterCryptoInfo`, ORs in
  `TC_HEADER_FLAG_NONSYS_INPLACE_ENC` (`:1859-1873`), recomputes the header CRC32 (`:1875-1879`),
  re-encrypts and writes it back. Crucially it re-uses the **same** `headerCryptoInfo` (same salt and
  key), so intermediate updates do **not** re-derive a salt and do **not** need the password again
  during a single run.
* **Resumption:** `EncryptPartitionInPlaceResume` opens the **backup header** only
  (`OpenBackupHeader`, `src/Format/InPlace.c:870`, impl `:2245-2295`), which reads 512 bytes at
  `deviceSize - TC_VOLUME_HEADER_GROUP_SIZE` and calls `ReadVolumeHeader` with the user password.
  From it `remainingBytes = VolumeSize - EncryptedAreaLength` (`:912`), so work continues where it
  stopped; the master key is recovered from the backup header. On interruption the process is marked
  `NONSYS_INPLACE_ENC_STATUS_PAUSED` (`:1333`) and persisted via `SaveNonSysInPlaceEncSettings`
  (`:1211`, config reader `src/Common/Dlgcode.c:3649`).
* **Begin:** `EncryptPartitionInPlaceBegin` (`src/Format/InPlace.c:369-746`) first shrinks the NTFS
  filesystem by `TC_TOTAL_VOLUME_HEADERS_SIZE` (`NewFileSysSizeAfterShrink`, `:66-118`;
  `FSCTL_SHRINK_VOLUME`), dismounts it, then writes the **backup header first** at
  `TC_VOLUME_DATA_OFFSET + dataAreaSize` (= `deviceSize - 131072`) with
  `volumeSize=dataAreaSize, hiddenVolumeSize=0, encryptedAreaStart=TC_VOLUME_DATA_OFFSET +
  dataAreaSize, encryptedAreaLength=0` and `HeaderFlags | TC_HEADER_FLAG_NONSYS_INPLACE_ENC`
  (`:566-636`). A **fresh master key** is generated here (master keydata passed as `NULL`). It then
  verifies by reading that backup header back and requires `EncryptedAreaStart != 0` (`:656-668`),
  and hides the NTFS header (`TC_NTFS_CONCEAL_CONSTANT`).

## B.3 The encryption transform, keys, and header writes

* **XTS data-unit numbers are derived from the ciphertext (destination) host offset**, not from the
  plaintext source offset and not by subtracting `EncryptedAreaStart`. In the core loop
  (`src/Format/InPlace.c:784-786`, `:1009-1017`):

  ```c
  unitNo.Value = (remainingBytes - workChunkSize + TC_VOLUME_DATA_OFFSET) / ENCRYPTION_DATA_UNIT_SIZE;
  ...
  // read plaintext
  offset.QuadPart = masterCryptoInfo->EncryptedAreaStart.Value - workChunkSize - TC_VOLUME_DATA_OFFSET;
  ReadFile (dev, buf, workChunkSize, ...);
  EncryptDataUnits ((uint8 *) buf, &unitNo, workChunkSize / ENCRYPTION_DATA_UNIT_SIZE, masterCryptoInfo);
  // write ciphertext
  offset.QuadPart = masterCryptoInfo->EncryptedAreaStart.Value - workChunkSize;
  WriteFile (dev, buf, workChunkSize, ...);
  ```

  The ciphertext destination offset is `EncryptedAreaStart - workChunkSize`; with
  `EncryptedAreaStart = TC_VOLUME_DATA_OFFSET + remainingBytes` this equals
  `TC_VOLUME_DATA_OFFSET + remainingBytes - workChunkSize = unitNo * 512`. So **data unit =
  ciphertext (destination) host offset / 512**. The plaintext is read from `destination -
  TC_VOLUME_DATA_OFFSET`, i.e. the data area is **shifted forward by `TC_VOLUME_DATA_OFFSET`
  (131072 bytes)** to make room for the primary header group. Because encryption proceeds from the
  end downward, no source byte is overwritten before it is read; a failed write is also rolled back
  by re-decrypting (`src/Format/InPlace.c:1010-1016`, `:1030-1038`).
* **Key:** a **new master key** generated at Begin and stored in the **backup header** from the very
  start. Resume recovers that key from the backup header; the primary header is not written until
  completion. The header key/salt are the ones used to write the backup header; intermediate
  `FastVolumeHeaderUpdate` calls reuse them (B.2).
* **Header at the start:** backup header only (with `EncryptedAreaLength=0`).
* **Header at the end** (`src/Format/InPlace.c:1080-1210`): for each wipe pass the **primary** header
  is (re)created at `TC_VOLUME_HEADER_OFFSET` with the final `EncryptedAreaStart`/
  `EncryptedAreaLength` and `HeaderFlags | TC_HEADER_FLAG_NONSYS_INPLACE_ENC` (`:1101-1148`), the
  reserved header areas are re-filled (`WriteRandomDataToReservedHeaderAreas`, `:1157`), and a fake
  hidden primary header is written at `TC_VOLUME_HEADER_OFFSET + TC_HIDDEN_VOLUME_HEADER_OFFSET =
  65536` (`:1175-1205`). The last action is `SaveNonSysInPlaceEncSettings(-1, ...)` and status
  `NONSYS_INPLACE_ENC_STATUS_FINISHED` (`:1211-1215`). The flag is **not cleared** on success —
  completeness is signalled by `EncryptedAreaLength == VolumeSize`, which is what the mount check in
  B.1 tests.
* `DecryptPartitionInPlace` (`src/Format/InPlace.c:1302+`) is the inverse and re-checks
  `TC_HEADER_FLAG_NONSYS_INPLACE_ENC` and `VolumeSize == EncryptedAreaLength`.

## B.4 CLI/GUI surface and validation constraints

* **GUI:** non-system in-place encryption is started from the VeraCrypt Format wizard ("Encrypt a
  non-system partition/drive"); it cannot be started from the pure command line.
* **CLI switches** (all in `src/Format/Tcformat.c`): `/encdev` (`/e`) — elevate/resume non-sys
  device volume creation (`:9224`, handler `:9523-9527`); `/inplacedec` — start in-place *decryption*
  of a partition, requires a volume-path argument (`:9229`, `:9528-9548`); `/resumeinplacedec`
  (`:9230`, `:9554-9557`); `/zinplace` (`/z`) — resume interrupted non-system in-place *encryption*
  (`:9231`, `:9549-9552`); `/prinplace` (`/p`) — startup-sequence prompt whether to resume
  (`:9226`, `:9559-9564`). Elevation wrappers pass `/zinplace` / `/inplacedec` (`:1252`, `:1274`).
  The wizard's worker calls `EncryptPartitionInPlaceBegin` then `EncryptPartitionInPlaceResume`
  (`src/Format/Tcformat.c:2709-2723`); on resume it calls `EncryptPartitionInPlaceResume` directly.
* **Validation** — `CheckRequirementsForNonSysInPlaceEnc` (`src/Format/InPlace.c:120-330`):
  * OS major version >= 6 (`:140-147`).
  * Target path must parse as `\Device\HarddiskVolumeN` or `\Device\HarddiskN\PartitionN`
    (`:153-170`) -> **partitions/dynamic volumes only; file containers are not eligible**.
    `partitionNumber == 0` (raw device) refused (`:172-179`).
  * Access via `OpenPartitionVolume` and NTFS only (`FSCTL_GET_NTFS_VOLUME_DATA`, `:222-269`);
    volume must be mounted for Begin (`ONLY_MOUNTED_VOL_SUPPORTED_FOR_NONSYS_INPLACE_ENC`,
    `:468-479`).
  * `NewFileSysSizeAfterShrink` must succeed (`:274-286`).
  * `deviceSize >= TC_NONSYS_INPLACE_ENC_MIN_VOL_SIZE` (`:303-311`).
  * NTFS free space `FreeClusters * BytesPerCluster >= TC_TOTAL_VOLUME_HEADERS_SIZE` = 262144
    (`:325-333`).
  * `BytesPerSector <= TC_MAX_VOLUME_SECTOR_SIZE` and `BytesPerSector % ENCRYPTION_DATA_UNIT_SIZE
    == 0` (`:336-344`).
  * System encryption is a different scope: `Ntvol.c` distinguishes `bPartitionInInactiveSysEncScope`
    from the non-sys flag, and `ExpandVolume` refuses `TC_HEADER_FLAG_ENCRYPTED_SYSTEM` volumes (A.2).
    Hidden volumes: the non-system in-place flow creates a normal (outer) volume header; there is no
    in-place path that preserves a pre-existing hidden volume in the same partition.
* **Must the volume be dismounted?** Begin needs it mounted (NTFS checks and the shrink), then the
  implementation **dismounts the filesystem before touching the raw sectors**; expansion by contrast
  requires the volume fully dismounted.

## B.5 Are expansion and in-place encryption combined?

No. They are independent features:

* Expansion rewrites the header so that `EncryptedAreaLength == VolumeSize` immediately (A.4/A.6) and
  never calls `EncryptPartitionInPlace*`. For a **file-hosted** volume there is nothing left to
  encrypt afterward.
* In-place encryption is the mechanism used to turn an *existing plaintext partition* into a
  VeraCrypt volume, and it is offered for partitions only (B.4) — you cannot point it at a file
  container, and there is no "expand then encrypt the new area" driver path.
* The only interaction in the source is defensive: `ExpandVolume.c:927-935` has a special branch so
  that expanding a *device* volume that currently carries `TC_HEADER_FLAG_NONSYS_INPLACE_ENC` still
  writes fake hidden headers / reserved areas consistently. That does not combine the two
  operations; it merely keeps the header layout valid.

---

## C. Not determined / caveats

* The exact NTFS-shrink/cluster-threshold logic (`GetFreeClusterBeforeThreshold`) and the
  NTFS-conceal constant handling in `InPlace.c` were only skimmed; they do not affect the
  header/progress model documented here.
* Whether any post-1.26.30 VeraCrypt version combines expansion with a background in-place pass was
  not investigated — the 1.26.30 tree has no such code.
* The Windows *system* in-place encryption (`EncryptInPlace` under `src/Boot/`/driver) is a separate
  code path from the non-system one in `src/Format/InPlace.c`; this note only uses it to explain the
  partial-volume read rule (B.1).
