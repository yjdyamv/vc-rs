# VeraCrypt 1.26.30 — Hidden Volume Protection ("protect hidden volume against damage caused by writing to outer volume")

Source of truth: VeraCrypt 1.26.30 C/C++ tree at `C:/Users/yuan/Desktop/VeraCrypt`
(`VERSION_STRING "1.26.30"`, `src/Common/Tcdefs.h:62`). Every `file:line` below is from that tree.
This documents the feature that mounts an **outer** volume while protecting the **hidden** volume
inside it from being overwritten. It covers the user-mode engine (`src/Volume/Volume.cpp`), the
Linux/macOS FUSE driver, and the Windows kernel driver (`src/Driver/`).

Terminology:
* **host file** — the container file/device (absolute host byte coordinates).
* **data area** — the outer volume's decrypted payload, i.e. the mounted disk. Its host-file start is
  `VolumeDataOffset`; its length is `VolumeDataSize`.

---

## 1. The protected range

### 1.1 Where it is stored

`src/Volume/Volume.h`:

```cpp
125:		bool HiddenVolumeProtectionTriggered;
...
127:		uint64 ProtectedRangeStart;
128:		uint64 ProtectedRangeEnd;
```

`ProtectedRangeEnd` is **exclusive** (range is `[ProtectedRangeStart, ProtectedRangeEnd)`). The same
struct carries the volume's own data-area geometry, populated when the header is parsed:

```cpp
135:		uint64 VolumeDataOffset;
136:		uint64 VolumeDataSize;
137:		uint64 EncryptedDataSize;
```

`src/Volume/Volume.cpp:204-205` (file-hosted V2 volume):

```cpp
204:					VolumeDataOffset = layout->GetDataOffset (VolumeHostSize);
205:					VolumeDataSize  = layout->GetDataSize (VolumeHostSize);
```

For a standard file-hosted V2 volume `GetDataOffset()` = `TC_VOLUME_DATA_OFFSET` = `131072`
(`src/Common/Volumes.h:77`), i.e. the data area starts after the 4x64 KiB header group
(`TC_TOTAL_VOLUME_HEADERS_SIZE = 262144`) and ends `131072` bytes before EOF.

### 1.2 How the range is computed

Computed in `Volume::Open` while mounting the **outer** volume with
`Protection == VolumeProtection::HiddenVolumeReadOnly`. `src/Volume/Volume.cpp:233-268`:

```cpp
233:					// Volume protection
234:					if (Protection == VolumeProtection::HiddenVolumeReadOnly)
235:					{
236:						if (Type == VolumeType::Hidden)
237:							throw PasswordIncorrect (SRC_POS);
238:						else
239:						{
240:							try
241:							{
242:								Volume protectedVolume;
243:
244:								protectedVolume.Open (VolumeFile,
245:									protectionPassword, protectionPim, protectionKdf, protectionKeyfiles,
246:									emvSupportEnabled,
247:									VolumeProtection::ReadOnly,
248:									shared_ptr <VolumePassword> (), 0, shared_ptr <Pkcs5Kdf> (),
249:									shared_ptr <KeyfileList> (),
250:									VolumeType::Hidden,
251:									useBackupHeaders);
252:
253:								if (protectedVolume.GetType() != VolumeType::Hidden)
254:									ParameterIncorrect (SRC_POS);
255:
256:								ProtectedRangeStart = protectedVolume.VolumeDataOffset;
257:								ProtectedRangeEnd   = protectedVolume.VolumeDataOffset + protectedVolume.VolumeDataSize;
258:							}
259:							catch (PasswordException&)
260:							{
261:								if (protectionKeyfiles && !protectionKeyfiles->empty())
262:									throw ProtectionPasswordKeyfilesIncorrect (SRC_POS);
263:								throw ProtectionPasswordIncorrect (SRC_POS);
264:							}
265:						}
266:					}
```

So the protected range is **exactly the hidden volume's data area**:

> `ProtectedRangeStart = hidden.VolumeDataOffset`
> `ProtectedRangeEnd   = hidden.VolumeDataOffset + hidden.VolumeDataSize`

For a hidden volume `VolumeDataOffset = Header->GetEncryptedAreaStart()` and
`VolumeDataSize = Header->GetVolumeDataSize()`. There is **no padding or rounding**: the range is the
byte-exact `[EncryptedAreaStart, EncryptedAreaStart + VolumeDataSize)` recorded in the hidden header.

### 1.3 What is NOT protected

* **Not the hidden volume header.** The hidden primary header is at host offset
  `TC_HIDDEN_VOLUME_HEADER_OFFSET = 65536` (`src/Common/Volumes.h:61`), inside the first 131072-byte
  header group, i.e. *before* the outer data-area start (`131072`). The hidden backup header lives in
  the trailing 131072-byte backup group. Neither is inside the outer data area, so writes to the
  mounted outer volume cannot reach them.
* **Not the host file tail.** The range ends at `EncryptedAreaStart + VolumeDataSize`, which for a
  file-hosted hidden volume is `HostSize - 131072` — just before the backup header group, not EOF.
* **Not the "free gap".** If the hidden volume does not fill the tail region, the gap between the
  hidden data end and the outer data end is outside the protected range and stays writable.

### 1.4 Exact hidden data-area arithmetic

`src/Core/VolumeCreator.cpp` computes the hidden volume's `EncryptedAreaStart` (called
`VolumeDataStart` at creation):

```cpp
325:        if (options->Type == VolumeType::Hidden)
326:            headerOptions.VolumeDataStart = HostSize - Layout->GetHeaderSize() * 2 - options->Size;
327:        else
328:            headerOptions.VolumeDataStart = Layout->GetHeaderSize() * 2;
```

* `Layout->GetHeaderSize()` = `TC_VOLUME_HEADER_SIZE` = `65536` (`src/Common/Volumes.h:51`), so
  `2 * 65536 = 131072` (`TC_VOLUME_HEADER_GROUP_SIZE`).
* For the hidden volume: `hidden.EncryptedAreaStart = HostSize - 131072 - hiddenSize`, and
  `hidden.EncryptedAreaEnd = HostSize - 131072`.
* The outer data area is `[131072, HostSize - 131072)`. So the hidden data area is the **suffix** of
  the outer data area, ending exactly at the outer data-area end.

The hidden volume's maximum size reserves a trailing area for the host filesystem via
`VolumeLayout::GetMaxDataSize` (`src/Volume/VolumeLayout.cpp:193-201`):

* `TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE = TC_MAX_VOLUME_SECTOR_SIZE = 4096` for hosts
  smaller than `TC_VOLUME_SMALL_SIZE_THRESHOLD` (2 MiB),
* `TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH = TC_VOLUME_HEADER_GROUP_SIZE = 131072` for
  hosts >= 2 MiB (`src/Common/Volumes.h:65,72,74,75`).

That reservation only affects the maximum hidden size offered by the wizard. The protected range is
the byte-exact `EncryptedAreaStart..+VolumeDataSize` from the header, not a rounded value.

### 1.5 The overlap test

`src/Volume/Volume.cpp:42-51`:

```cpp
42:	void Volume::CheckProtectedRange (uint64 writeHostOffset, uint64 writeLength)
43:	{
44:		uint64 writeHostEndOffset = writeHostOffset + writeLength - 1;
45:
46:		if ((writeHostOffset < ProtectedRangeStart) ? (writeHostEndOffset >= ProtectedRangeStart) : (writeHostOffset <= ProtectedRangeEnd - 1))
47:		{
48:			HiddenVolumeProtectionTriggered = true;
49:			throw VolumeProtected (SRC_POS);
50:		}
51:	}
```

Plain "any byte overlaps" test (inclusive end offsets). A write is denied if it touches **any** byte
of `[ProtectedRangeStart, ProtectedRangeEnd - 1]`.

### 1.6 The Windows driver uses the identical range

`src/Driver/Ntvol.c:757-791`, mounting the outer volume with protection:

```c
761:				Extension->cryptoInfo->hiddenVolumeOffset = cryptoInfoPtr->EncryptedAreaStart.Value;
767:				// Validate the offset
768:				if (Extension->cryptoInfo->hiddenVolumeOffset % ENCRYPTION_DATA_UNIT_SIZE != 0)
769:				{
770:					mount->nReturnCode = ERR_VOL_SIZE_WRONG;       // offset must be 512-aligned
771:					ntStatus = STATUS_SUCCESS;
772:					goto error;
773:				}
...
784:					// Hidden volume protection
785:					Extension->cryptoInfo->hiddenVolume = FALSE;
786:					Extension->cryptoInfo->bProtectHiddenVolume = TRUE;
788:					Extension->cryptoInfo->hiddenVolumeProtectedSize = tmpCryptoInfo->hiddenVolumeSize;
```

So the Windows range is `[hiddenVolumeOffset, hiddenVolumeOffset + hiddenVolumeProtectedSize - 1]`
= `[EncryptedAreaStart, EncryptedAreaStart + hiddenVolumeSize - 1]`, the same bytes as the user-mode
`[ProtectedRangeStart, ProtectedRangeEnd)`.

### 1.7 Padding / alignment rules

* The range itself is **not** padded; it is the exact header value.
* Writes are validated as whole sectors: `Volume::WriteSectors` rejects a write whose length is not a
  multiple of `SectorSize`, whose offset is not `SectorSize`-aligned, or that runs past
  `VolumeDataSize` (`src/Volume/Volume.cpp:381-386`). `SectorSize` for file-hosted volumes is
  `ENCRYPTION_DATA_UNIT_SIZE = 512` (`src/Common/Crypto.h:39`,
  `TC_SECTOR_SIZE_FILE_HOSTED_VOLUME = 512`, `src/Common/Volumes.h:66`).
* The Windows driver requires the hidden `EncryptedAreaStart` to be 512-aligned
  (`src/Driver/Ntvol.c:768-773`) and requires write offset/length to be
  `ENCRYPTION_DATA_UNIT_SIZE`-aligned (`src/Driver/EncryptedIoQueue.c:955-964`).

---

## 2. When protection is active and how the hidden password is supplied

### 2.1 The option value

`VolumeProtection::Enum` (`src/Volume/Volume.h:72-80`):

```cpp
72:	struct VolumeProtection
73:	{
74:		enum Enum
75:		{
76:			None,
77:			ReadOnly,
78:			HiddenVolumeReadOnly
79:		};
80:	};
```

Carried in `MountOptions` (`src/Core/MountOptions.h:72-76`):

```cpp
72:		VolumeProtection::Enum Protection;
73:		shared_ptr <VolumePassword> ProtectionPassword;
74:		int ProtectionPim;
75:		shared_ptr <Pkcs5Kdf> ProtectionKdf;
76:		shared_ptr <KeyfileList> ProtectionKeyfiles;
```

`HiddenVolumeReadOnly` = "mount the outer volume read/write, but treat the hidden volume's data area
as read-only" — hidden-volume protection. `ReadOnly` is a different mode (throws `VolumeReadOnly`,
`Volume.cpp:389-390`).

### 2.2 The Unix/Linux CLI surface

`src/Main/CommandLineInterface.cpp`:

```cpp
116:		parser.AddOption (L"", L"protect-hidden",      _("Protect hidden volume"));
117:		parser.AddOption (L"", L"protection-hash",     _("Header key derivation algorithm for protected hidden volume"));
118:		parser.AddOption (L"", L"protection-keyfiles", _("Keyfiles for protected hidden volume"));
119:		parser.AddOption (L"", L"protection-password", _("Password for protected hidden volume"));
120:		parser.AddOption (L"", L"protection-pim",      _("PIM for protected hidden volume"));
```

Parsing (`CommandLineInterface.cpp:559-608`): `protect-hidden` at :559; `protection-keyfiles` at
:572-574 (`ArgMountOptions.ProtectionKeyfiles = ToKeyfileList (str)`); `protection-password` at
:579-581; `protection-pim` at :586-599; `protection-hash` at :604-608 (`ArgMountOptions.ProtectionKdf`).

Help text (`src/Main/UserInterface.cpp:1592-1611`) documents `--protect-hidden=yes|no`,
`--protection-keyfiles=...`, `--protection-password=PASSWORD` (plus hash/pim variants), with the
example `veracrypt -t -k "" --pim=0 --protect-hidden=no volume.hc /media/veracrypt1`
(`UserInterface.cpp:1669`).

The hidden password uses the same keyfile/PIM/hash machinery as the normal password: keyfiles via
`Keyfile::ApplyListToPassword` (`src/Core/Unix/CoreServiceProxy.h:107-108`), PIM as `ProtectionPim`,
PRF as `ProtectionKdf`.

### 2.3 The Windows surface

* GUI checkbox `IDC_PROTECT_HIDDEN_VOL` = *"Protect hidden volume against damage caused by writing to
  outer volume"* (`src/Common/Language.xml:329`), used at `src/Mount/Mount.c:4459` (`BST_CHECKED`),
  `4646`, `6115`, `6690`.
* **No Windows command-line switch** for it: the argument table (`src/Mount/Mount.c:10330-10362`)
  lists `/password`, `/pim`, `/keyfile`, `/mountoption`, etc., but nothing for hidden-volume
  protection.
* Hidden credentials come from the driver mount params (`MOUNT_STRUCT.ProtectedHidVolPassword`,
  `ProtectedHidVolPkcs5Prf`, `ProtectedHidVolPim` — `src/Common/Apidrvr.h:165,169,173`); keyfiles are
  handled by the UI (`src/Mount/Mount.c:3933, 9252`).

### 2.4 Activation during mount

Windows driver `src/Driver/Ntvol.c:620-630`:

```c
620:		if ((volumeType == TC_VOLUME_TYPE_HIDDEN) && mount->bProtectHiddenVolume)
621:		{
622:			mount->nReturnCode = ReadVolumeHeaderWCacheWithAbort (
...
626:				&mount->ProtectedHidVolPassword,
627:				mount->ProtectedHidVolPkcs5Prf,
628:				mount->ProtectedHidVolPim,
629:				&tmpCryptoInfo, ...);
630:		}
```

On the user-mode side this is the `protectedVolume.Open(...)` call (`Volume.cpp:244-251`). If
protection is requested the hidden header *must* decrypt, otherwise the whole mount is rejected
(`src/Driver/Ntvol.c:867-874`). After a successful protected mount the UI shows
`HIDVOL_PROT_WARN_AFTER_MOUNT` (`src/Mount/Mount.c:6115-6116`, text `src/Common/Language.xml:538`),
which states the whole volume will become write-protected once any write to the hidden area is
attempted.

---

## 3. What happens on a violating write

### 3.1 User-mode engine (Linux/macOS FUSE — the model the Rust core should copy)

`src/Volume/Volume.cpp:377-403`:

```cpp
377:	void Volume::WriteSectors (const ConstBufferPtr &buffer, uint64 byteOffset)
378:	{
379:		if_debug (ValidateState ());
380:
381:		uint64 length = buffer.Size();
382:		uint64 hostOffset = VolumeDataOffset + byteOffset;
383:
384:		if (length % SectorSize != 0
385:			|| byteOffset % SectorSize != 0
386:			|| byteOffset + length > VolumeDataSize)
387:			throw ParameterIncorrect (SRC_POS);
388:
389:		if (Protection == VolumeProtection::ReadOnly)
390:			throw VolumeReadOnly (SRC_POS);
391:
392:		if (HiddenVolumeProtectionTriggered)
393:			throw VolumeProtected (SRC_POS);
394:
395:		if (Protection == VolumeProtection::HiddenVolumeReadOnly)
396:			CheckProtectedRange (hostOffset, length);
397:
401:		EA->EncryptSectors (encBuf, hostOffset / SectorSize, length / SectorSize, SectorSize);
402:		VolumeFile->WriteAt (encBuf, hostOffset);
409:	}
```

* **Layer that detects overlap:** the user-mode `Volume` engine itself, in `CheckProtectedRange`
  (`Volume.cpp:42-51`), called from `WriteSectors:395-396`. The FUSE layer does no range logic; it
  delegates to `Volume::WriteSectors` (`src/Driver/Fuse/FuseService.cpp:1722-1727`).
* **Whole request fails, no partial write.** `CheckProtectedRange` throws *before* any encryption or
  `VolumeFile->WriteAt`, so nothing at all is written — not the overlapping bytes, not the
  non-overlapping bytes.
* **Error mapping (FUSE):** `FuseService::ExceptionToErrorCode` maps `VolumeProtected` to `-EPERM`
  (`src/Driver/Fuse/FuseService.cpp:1216-1223`); `VolumeReadOnly` likewise. The application sees
  `EPERM` ("Operation not permitted") on the `write(2)`. (On FreeBSD the FUSE write path returns
  success and silently drops the buffer — `FuseService.cpp:1130-1137`.)
* **One-shot trigger:** `CheckProtectedRange` sets `HiddenVolumeProtectionTriggered = true`
  (`Volume.cpp:48`) before throwing. Every later write hits `WriteSectors:392-393` and throws
  `VolumeProtected` for **all** sectors, not just the protected range. So after the first violation
  the whole outer volume is unwritable until unmount.
* **Reads unaffected** (see §4).
* **No header is modified.** The trigger path only throws; it never calls any header/backup-header
  write. The outer and backup headers on disk are untouched by a trigger.

### 3.2 Windows kernel driver

Overlap check in `src/Driver/EncryptedIoQueue.c`, after the application offset has been converted to
a host-file offset (`EncryptedIoQueue.c:977-987`); exact source `src/Driver/EncryptedIoQueue.c:989-1016`:

```c
989:				// Hidden volume protection
990:				if (item->Write && queue->CryptoInfo->bProtectHiddenVolume)
991:				{
992:					// If there has already been a write operation denied in order to protect the
993:					// hidden volume (since the volume mount time)
994:					if (queue->CryptoInfo->bHiddenVolProtectionAction)
995:					{
996:						// Do not allow writing to this volume anymore. This is to fake a complete volume
997:						// or system failure (otherwise certain kinds of inconsistency within the file
998:						// system could indicate that this volume has used hidden volume protection).
999:						CompleteOriginalIrp (item, STATUS_INVALID_PARAMETER, 0);
1000:						continue;
1001:					}
1002:
1003:					// Verify that no byte is going to be written to the hidden volume area
1004:					if (RegionsOverlap ((unsigned __int64) item->OriginalOffset.QuadPart,
1005:						(unsigned __int64) item->OriginalOffset.QuadPart + item->OriginalLength - 1,
1006:						queue->CryptoInfo->hiddenVolumeOffset,
1007:						(unsigned __int64) queue->CryptoInfo->hiddenVolumeOffset + queue->CryptoInfo->hiddenVolumeProtectedSize - 1))
1008:					{
1009:						Dump ("Hidden volume protection triggered: write %I64d-%I64d (protected %I64d-%I64d)\n", ...);
1010:						queue->CryptoInfo->bHiddenVolProtectionAction = TRUE;
1011:
1012:						// Deny this write operation to prevent the hidden volume from being overwritten
1013:						CompleteOriginalIrp (item, STATUS_INVALID_PARAMETER, 0);
1014:						continue;
1015:					}
1016:				}
```

* **Whole IRP fails** with `STATUS_INVALID_PARAMETER` (`EncryptedIoQueue.c:1013`). It is *not*
  `STATUS_MEDIA_WRITE_PROTECTED` and *not* `STATUS_ACCESS_DENIED`; the only
  `STATUS_MEDIA_WRITE_PROTECTED` in this file is the unrelated system-encryption key-data-area guard
  (`EncryptedIoQueue.c:1023`). This is why the user text warns Windows may report *"The parameter is
  incorrect"* or *"Delayed Write Failed"* (`src/Common/Language.xml:538`).
* **One-shot latch:** sets `cryptoInfo->bHiddenVolProtectionAction = TRUE`
  (`EncryptedIoQueue.c:1010`); later writes hit the early-out (`EncryptedIoQueue.c:994-1001`) and are
  denied with the same `STATUS_INVALID_PARAMETER`. The whole volume stays write-protected until
  unmount. Comment: *"This is to fake a complete volume or system failure (otherwise certain kinds of
  inconsistency within the file system could indicate that this volume has used hidden volume
  protection)."*
* The driver does **not** dismount the volume at the trigger.

### 3.3 Reporting the trigger back to the UI

The one-shot flag is surfaced through several IOCTL structures and the user-mode `VolumeInfo`:

* **Volume properties** — `TC_IOCTL_GET_VOLUME_PROPERTIES` returns `hiddenVolProtection` =
  `HIDVOL_PROT_STATUS_ACTION_TAKEN` once triggered (`src/Driver/Ntdriver.c:2673-2676`; enum in
  `src/Common/Common.h:75-80`: `NONE=0, ACTIVE, ACTION_TAKEN`; field at `src/Common/Apidrvr.h:227`).
* **Mount list** — `volumeType` becomes `PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED`
  (`src/Driver/Ntdriver.c:2621-2628`; enum `src/Common/Common.h:64-72`), which the GUI renders as
  *Read-only = Yes* and *Hidden Volume Protection = "Yes (damage prevented!)"*
  (`src/Mount/Mount.c:4995-5015`; string `HID_VOL_DAMAGE_PREVENTED` at `src/Common/Language.xml:808`).
* **Unmount** — `UNMOUNT_STRUCT.HiddenVolumeProtectionTriggered` (`src/Common/Apidrvr.h:194`) is set
  from the latch (`src/Driver/Ntdriver.c:4557`), and the UI reacts with the
  `DAMAGE_TO_HIDDEN_VOLUME_PREVENTED` warning (`src/Common/Dlgcode.c:8746-8757`; text
  `src/Common/Language.xml:540`).
* **Unix user-mode**: the FUSE process sets `HiddenVolumeProtectionTriggered` on its `Volume`;
  dismount requests propagate it through `VolumeInfo` (`src/Volume/VolumeInfo.cpp:110` — `Set()` reads
  `volume.IsHiddenVolumeProtectionTriggered()`; serialized at `VolumeInfo.cpp:31`/`79`), and the UI
  shows `DAMAGE_TO_HIDDEN_VOLUME_PREVENTED` when it next lists/dismounts the volume
  (`src/Main/UserInterface.cpp:316-317`, `391`). The `VolumeProtected` exception itself is converted
  to a generic message (`src/Main/UserInterface.cpp:2017`, `VC_CONVERT_EXCEPTION (VolumeProtected)`).

### 3.4 Summary of violation behaviour

| Aspect | Value |
|---|---|
| Layer that detects | user-mode `Volume::CheckProtectedRange`; Windows `EncryptedIoQueue.c` `RegionsOverlap` |
| Scope of failure | the **entire** write request (no partial write) |
| Windows status | `STATUS_INVALID_PARAMETER` (-> "The parameter is incorrect"/"Delayed Write Failed") |
| Unix FUSE errno | `-EPERM` (FreeBSD path: silent drop) |
| After the first violation | all further writes to the whole volume rejected until unmount (latched flag) |
| Auto-dismount | no |
| Header/backup header modified | no |
| UI report | `hiddenVolProtection=ACTION_TAKEN`, `volumeType=OUTER_VOL_WRITE_PREVENTED`, `HiddenVolumeProtectionTriggered`, `DAMAGE_TO_HIDDEN_VOLUME_PREVENTED` |

## 4. Read path and writes outside the protected range

* **Reads are always served.** Neither the user-mode check (`src/Volume/Volume.cpp:308-348`) nor the
  driver check (`src/Driver/EncryptedIoQueue.c:989-1016`) runs on reads — both are guarded by
  `if (item->Write ...)` / `write` being true. All sectors, including those inside the protected
  range, are read and decrypted normally.
* **Writes outside the range work normally** while protection is active. The check only *denies* a
  write whose byte interval overlaps `[hiddenVolumeOffset, hiddenVolumeOffset +
  hiddenVolumeProtectedSize - 1]`; every other write proceeds. The outer volume remains fully
  writable in its own (unprotected) area.
* The only thing that stops normal writes is the **latch**: after the *first* violation,
  `bHiddenVolProtectionAction` (driver) / `HiddenVolumeProtectionTriggered` (user mode) becomes
  sticky and *all* subsequent writes to the whole outer volume are rejected until unmount — not just
  writes to the protected range.

## 5. Additional implementer notes

### 5.1 Sector-size / alignment rules

* The protected offset must be a multiple of `ENCRYPTION_DATA_UNIT_SIZE`, which is `512`
  (`src/Common/Crypto.h:39`); the driver validates the offset against it
  (`src/Driver/Ntvol.c:768`). In practice `EncryptedAreaStart` is always 512-byte (sector) aligned,
  and for a hidden volume created by VeraCrypt the data area starts at `headerSize*2` from the end of
  the host file (`src/Core/VolumeCreator.cpp:325-328`), which is itself aligned.
* The *length* `hiddenVolumeSize` is the true (sector-granular) hidden data size; it is used
  verbatim with no rounding (`src/Driver/Ntvol.c:788`). Alignment is enforced at creation time, not
  at protection time: hidden-volume creation rejects a size that is not a multiple of the sector
  size, and the "hidden volume not in the free area" check uses byte ranges.
* The overlap test is **inclusive on both ends** (`RegionsOverlap(a,b,c,d)` = intervals
  `[a,b]` and `[c,d]` intersect; declared `src/Driver/Ntdriver.h:192`, defined `src/Driver/Ntdriver.c:4655-4658`), and each side is passed as
  `start .. start+length-1` (`src/Volume/Volume.cpp:42-51`,
  `src/Driver/EncryptedIoQueue.c:1004-1007`), so a write that ends exactly on the protected start
  byte-1 is fine and a write that begins exactly on the protected end byte is fine.

### 5.2 Wrong hidden password (hidden volume not present)

When the user requests protection, the hidden header **must** decrypt or the mount fails. The driver
mounts the outer volume first (loop `for (volumeType = TC_VOLUME_TYPE_NORMAL; ...)`,
`src/Driver/Ntvol.c:483-485`); with `bProtectHiddenVolume` set it does **not** return after the
outer volume succeeds (`src/Driver/Ntvol.c:845-847`) but continues to the `TC_VOLUME_TYPE_HIDDEN`
iteration, where the hidden header is decrypted with `ProtectedHidVolPassword` into `tmpCryptoInfo`
(`src/Driver/Ntvol.c:620-633`, `757-791`). If that decryption fails with `nReturnCode !=
ERR_PASSWORD_WRONG`, the loop breaks (`src/Driver/Ntvol.c:867-876`) and the mount is rejected:

> /* If we _are_ supposed to protect a hidden volume, we do not tolerate any error
> (both volume headers must be successfully decrypted). */  (`src/Driver/Ntvol.c:873-874`)

So a wrong/nonexistent hidden password is **not** a "protect nothing" mode — the whole mount fails.
The user-mode engine behaves identically: `protectedVolume.Open(...)` throws and `Volume::Open`
rethrows `ProtectionPasswordIncorrect` / `ProtectionPasswordKeyfilesIncorrect`
(`src/Volume/Volume.cpp:258-263`), surfaced to the user as a password-incorrect error
(`src/Common/Language.xml:1541`, `LINUX_EX2MSG_PROTECTIONPASSWORDINCORRECT`). The Rust core should
reject the mount with the standard wrong-password error.

### 5.3 Interaction with the in-place-encryption fields

In-place encryption stores separate `EncryptedAreaStart` / `EncryptedAreaLength` values in the header
and can shift `EncryptedAreaStart.Value` while encryption/decryption is in progress
(`src/Volume/Volume.cpp:215-228`). The hidden-volume protection offset is taken from the *decrypted
hidden header's* `EncryptedAreaStart.Value` (`src/Driver/Ntvol.c:761`), i.e. the hidden volume's own
data start, so an outer volume's in-place state does not move the protected range. The protected
range is deliberately **not** the outer volume's `EncryptedAreaStart`.

### 5.4 What an implementer must copy, and what need not be

Must copy:
1. Activation flag + hidden password/PIM (+ keyfiles) as part of mount.
2. Derive protected range = `[hiddenHeader.EncryptedAreaStart, +hiddenHeader.VolumeDataSize)`.
3. Reject **each** write whose `[offset, offset+len)` intersects the range, before any decryption.
4. Latch on the first violation and reject all further writes until unmount.
5. Surface the trigger state in the mount-list/properties surface so the UI can warn.
6. Do **not** modify header or backup header on trigger.

Need not copy (Windows-kernel specific): the `STATUS_INVALID_PARAMETER` / `Dump()` machinery, and
the "delayed write / parameter is incorrect" phrasing. A Unix-style mount should surface `EPERM`
(`FuseService` model, `src/Driver/Fuse/FuseService.cpp:1216-1223`), or an equivalent clear
`VolumeProtected` error for a `vcrs write` CLI path — but must still latch, so a caller cannot keep
retrying overlapping writes.

## Appendix: file map of the relevant source

| File:lines | What it holds |
|---|---|
| `src/Common/Apidrvr.h:165,169,173,194,227` | `MOUNT_STRUCT.ProtectedHidVolPassword` / `ProtectedHidVolPkcs5Prf` / `ProtectedHidVolPim`, `UNMOUNT_STRUCT.HiddenVolumeProtectionTriggered`, `VOLUME_PROPERTIES_STRUCT.hiddenVolProtection` |
| `src/Common/Common.h:64-80` | `PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED`, `HIDVOL_PROT_STATUS_*` |
| `src/Common/Crypto.h:39` | `ENCRYPTION_DATA_UNIT_SIZE` |
| `src/Common/Language.xml:329,538,540,808,1541` | user-visible warning strings |
| `src/Core/MountOptions.h:72` | `MountOptions::Protection` |
| `src/Core/VolumeCreator.cpp:325-328` | hidden volume data-start arithmetic |
| `src/Core/Unix/CoreUnix.cpp:275,321-327` | `DismountVolume` propagation of the trigger |
| `src/Driver/EncryptedIoQueue.c:989-1016` | Windows kernel overlap check + latch (`STATUS_INVALID_PARAMETER`) |
| `src/Driver/Ntvol.c:483-485,620-633,757-791,867-876` | hidden header decrypt, range install, wrong-password rejection |
| `src/Driver/Ntdriver.c:2620-2628,2673-2676,4557,4656` | volume-type/property + unmount reporting |
| `src/Volume/Volume.cpp:42-51,215-228,377-409` | `CheckProtectedRange`, in-place fields, `WriteSectors` |
| `src/Volume/Volume.h:109,125-128` | `HiddenVolumeProtectionTriggered`, `ProtectedRangeStart/End` |
| `src/Volume/VolumeLayout.cpp:193-201` | host-FS reserved end areas |
| `src/Volume/VolumeInfo.cpp:31,79,110` | trigger serialization |
| `src/Main/UserInterface.cpp:316-317,391,2017` | `DAMAGE_TO_HIDDEN_VOLUME_PREVENTED`, exception mapping |
| `src/Mount/Mount.c:4459,4646,4995-5015,6115,10330-10362` | GUI checkbox/CLI switch + warnings |
| `src/Driver/Fuse/FuseService.cpp:1216-1223,1441-1447,1722-1727` | FUSE read/write + `EPERM` mapping |
| `src/Documents/LegalNotices.txt` | hidden-volume damage disclaimer |
