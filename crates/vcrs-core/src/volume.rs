//! Volume creation, opening and data access.
//!
//! Everything here follows `src/Core/VolumeCreator.cpp` and
//! `src/Volume/Volume.cpp`:
//!
//! * `create()` makes a V2 normal volume: primary header at 0, backup header
//!   128 KiB before the end of the host, and a *fake* random hidden-volume
//! header in each of the two hidden header slots at offset 64 KiB and at the
//! very end (this is what VeraCrypt writes so that the hidden header areas look
//! like random data).
//! * data access is raw XTS over the host file: the data unit number of a byte
//!   offset is `host_offset / 512` regardless of where the data area starts.

use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::cipher::EncryptionAlgorithm;
use crate::keyfile::apply_keyfiles;
use crate::header::{
    VolumeHeader, VolumeType, HEADER_FLAG_NONSYS_INPLACE_ENC, HEADER_SALT_SIZE, MAX_SECTOR_SIZE,
    MIN_SECTOR_SIZE, TOTAL_VOLUME_HEADERS_SIZE, TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION,
    VOLUME_HEADER_GROUP_SIZE, VOLUME_HEADER_SIZE, VOLUME_HEADER_VERSION,
};
use crate::layout::{VolumeLayout, HIDDEN_RESERVED_END_AREA};
use crate::prf::{Prf, HEADER_KEY_SIZE};
use crate::xts::{Xts, DATA_UNIT_SIZE};
use crate::{Error, Result};

/// `TC_MIN_FAT_FS_SIZE`: 9 sectors of the largest size.
pub const MIN_FAT_FS_SIZE: u64 = 9 * MAX_SECTOR_SIZE as u64;
/// `TC_MIN_VOLUME_SIZE`.
pub const MIN_VOLUME_SIZE: u64 = TOTAL_VOLUME_HEADERS_SIZE + MIN_FAT_FS_SIZE;

/// How much a container has to grow by, at least (`TC_MINVAL_FS_EXPAND` in
/// `src/ExpandVolume/ExpandVolume.h`).
pub const MIN_EXPAND_BYTES: u64 = 64 * 1024;

/// Largest chunk VeraCrypt processes at once while encrypting a volume in place
/// (`TC_MAX_NONSYS_INPLACE_ENC_WORK_CHUNK_SIZE`, `src/Format/InPlace.c`).
pub const IN_PLACE_CHUNK_SIZE: u64 = 2 * 1024 * 1024;

/// How often the header is refreshed while encrypting in place
/// (`TC_NONSYS_INPLACE_ENC_HEADER_UPDATE_INTERVAL`).
pub const IN_PLACE_HEADER_UPDATE_INTERVAL: u64 = 64 * 1024 * 1024;

/// Smallest data area in-place encryption will work with.
pub const MIN_IN_PLACE_DATA_SIZE: u64 = 64 * 1024;

/// How far an interrupted in-place encryption has got.
///
/// VeraCrypt's non-system in-place encryption walks *downwards* through the data
/// area, so the encrypted bytes are always the *end* of the data area and the
/// bytes still to do are its *start* (`src/Format/InPlace.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InPlaceState {
    /// Bytes at the end of the data area that are already encrypted, i.e. the
    /// header's `EncryptedAreaLength`.
    pub encrypted_length: u64,
    /// Bytes at the start of the data area that are still plaintext.
    pub remaining: u64,
}

impl InPlaceState {
    /// Size of the whole data area.
    pub fn total(&self) -> u64 {
        self.encrypted_length + self.remaining
    }

    /// Fraction of the data area that has already been encrypted (0.0..=1.0).
    pub fn progress(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            1.0
        } else {
            self.encrypted_length as f64 / total as f64
        }
    }
}
/// `TC_MIN_HIDDEN_VOLUME_SIZE`.
pub const MIN_HIDDEN_VOLUME_SIZE: u64 = MIN_FAT_FS_SIZE + HIDDEN_RESERVED_END_AREA;
/// `TC_MIN_HIDDEN_VOLUME_HOST_SIZE`.
pub const MIN_HIDDEN_VOLUME_HOST_SIZE: u64 =
    MIN_VOLUME_SIZE + MIN_HIDDEN_VOLUME_SIZE + 2 * MAX_SECTOR_SIZE as u64;

/// How to create a volume.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub ea: EncryptionAlgorithm,
    pub prf: Prf,
    /// Password bytes (VeraCrypt uses the UTF-8 encoding of the password).
    pub password: Vec<u8>,
    /// Keyfiles (files or directories) whose pool is mixed into the password.
    pub keyfiles: Vec<PathBuf>,
    /// Personal Iterations Multiplier; 0 means the default iteration count.
    pub pim: i32,
    pub sector_size: u32,
    /// When false (the default, like VeraCrypt's "quick format") the data area
    /// is left as whatever the file system reports as free/empty space. When
    /// true the whole data area is filled with zeros encrypted under a
    /// throwaway key, exactly like VeraCrypt's slow format.
    pub full_format: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            ea: EncryptionAlgorithm::Aes,
            prf: Prf::Sha512,
            password: Vec::new(),
            keyfiles: Vec::new(),
            pim: 0,
            sector_size: MIN_SECTOR_SIZE,
            full_format: false,
        }
    }
}

impl CreateOptions {
    /// The password bytes the KDF sees, i.e. with the keyfile pool mixed in.
    pub fn effective_password(&self, volume: Option<&Path>) -> Result<Vec<u8>> {
        apply_keyfiles(&self.password, &self.keyfiles, volume)
    }
}

/// How to open a volume.
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub password: Vec<u8>,
    /// Keyfiles (files or directories) whose pool is mixed into the password.
    pub keyfiles: Vec<PathBuf>,
    pub pim: i32,
    /// If known, only this PRF is tried (saves one KDF per PRF).
    pub prf: Option<Prf>,
    /// If known, only this encryption algorithm is tried.
    pub ea: Option<EncryptionAlgorithm>,
    /// If known, only layouts for this volume type are tried.
    pub volume_type: Option<VolumeType>,
    /// Read the backup header instead of the primary one.
    pub use_backup_header: bool,
}

impl OpenOptions {
    /// The password bytes the KDF sees, i.e. with the keyfile pool mixed in.
    pub fn effective_password(&self, volume: Option<&Path>) -> Result<Vec<u8>> {
        apply_keyfiles(&self.password, &self.keyfiles, volume)
    }
}

/// A host-file byte range that must not be written to.
///
/// This is VeraCrypt's *hidden volume protection*: the outer volume is mounted
/// normally, but a write that would land inside the hidden volume's data area
/// fails instead of destroying it (`src/Driver/EncryptedIoQueue.c`, the
/// `bProtectHiddenVolume` / `bHiddenVolProtectionAction` logic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedRange {
    /// First protected host byte.
    pub start: u64,
    /// Number of protected bytes.
    pub length: u64,
}

impl ProtectedRange {
    /// A range starting at `start` and covering `length` host bytes.
    pub const fn new(start: u64, length: u64) -> Self {
        Self { start, length }
    }

    /// First byte past the protected range.
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.length)
    }

    /// True when `[offset, offset + len)` intersects the protected range.
    /// A zero-length write never intersects.
    pub const fn overlaps(&self, offset: u64, len: u64) -> bool {
        len > 0 && offset < self.end() && self.start < offset.saturating_add(len)
    }
}

/// An opened VeraCrypt volume.
pub struct Volume {
    file: File,
    pub header: VolumeHeader,
    pub layout: VolumeLayout,
    /// Size of the host file in bytes.
    pub host_size: u64,
    /// Host-file offset of the volume data area.
    pub data_offset: u64,
    /// Size of the volume data area in bytes.
    pub data_size: u64,
    xts: Xts,
    /// Host-file range writes must not touch (hidden-volume protection).
    protected: OnceLock<ProtectedRange>,
    /// Set once a write has been refused, after which *every* write is refused.
    protection_triggered: AtomicBool,
    /// Set when the volume's in-place encryption was interrupted, i.e. when part
    /// of the data area is still plaintext.
    in_place: Option<InPlaceState>,
}

impl Volume {
    /// Create a new normal volume in a new file called `path`.
    ///
    /// `host_size` is the size of the whole container file; the usable volume
    /// size is `host_size - 262144`.
    pub fn create(path: &Path, host_size: u64, options: &CreateOptions) -> Result<Volume> {
        let layout = VolumeLayout::V2Normal;
        validate_sector_size(options.sector_size)?;
        if host_size % DATA_UNIT_SIZE as u64 != 0 {
            return Err(Error::InvalidParameter(format!(
                "host size must be a multiple of {DATA_UNIT_SIZE}"
            )));
        }
        if host_size < MIN_VOLUME_SIZE {
            return Err(Error::InvalidParameter(format!(
                "minimum volume size is {MIN_VOLUME_SIZE} bytes, got {host_size}"
            )));
        }

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(host_size)?;

        let volume_size = layout
            .max_data_size(host_size)
            .ok_or_else(|| Error::InvalidParameter("host is too small".into()))?;
        let data_offset = layout.creation_data_offset(host_size, volume_size)?;

        let master_key = random_master_key(options.ea)?;
        // Keyfiles are mixed into the password *before* any key derivation; the
        // backup header is then derived from the same bytes with a fresh salt.
        let password = options.effective_password(Some(path))?;
        let header = VolumeHeader {
            version: VOLUME_HEADER_VERSION,
            required_min_version: TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION,
            volume_type: VolumeType::Normal,
            creation_time: 0,
            modification_time: 0,
            hidden_volume_data_size: 0,
            volume_data_size: volume_size,
            encrypted_area_start: data_offset,
            encrypted_area_length: volume_size,
            flags: 0,
            sector_size: options.sector_size,
            ea: options.ea,
            prf: options.prf,
            salt: random_bytes(HEADER_SALT_SIZE)?,
            master_key,
        };

        // Primary header, then a fake hidden header in the hidden slot.
        write_header_region(
            &file,
            layout.header_offset(),
            &header,
            &password,
            options.pim,
            &header.salt,
        )?;
        write_fake_hidden_region(&file, HIDDEN_SLOT_OFFSET, host_size, host_size, options)?;

        if options.full_format {
            randomize_data_area(&file, data_offset, volume_size, options.ea)?;
        }

        // Backup header: VeraCrypt encrypts it with a *fresh* random salt (and
        // therefore a freshly derived header key), so the two header copies are
        // independent. Then its own fake hidden header.
        let backup_offset = backup_offset_of(host_size, layout)?;
        let backup_salt = random_bytes(HEADER_SALT_SIZE)?;
        write_header_region(&file, backup_offset, &header, &password, options.pim, &backup_salt)?;
        write_fake_hidden_region(&file, backup_offset + VOLUME_HEADER_SIZE, host_size, host_size, options)?;

        file.sync_all()?;
        Volume::from_parts(file, layout, header, host_size)
    }

    /// Create a hidden volume inside the existing container `path`.
    ///
    /// `hidden_size` is the size of the hidden volume; the host file must
    /// already be large enough (`>= hidden_size + 262144`).
    pub fn create_hidden(path: &Path, hidden_size: u64, options: &CreateOptions) -> Result<Volume> {
        let layout = VolumeLayout::V2Hidden;
        validate_sector_size(options.sector_size)?;
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        let host_size = file.metadata()?.len();

        if hidden_size % DATA_UNIT_SIZE as u64 != 0 {
            return Err(Error::InvalidParameter(
                "hidden volume size must be a multiple of 512".into(),
            ));
        }
        if host_size < MIN_HIDDEN_VOLUME_HOST_SIZE {
            return Err(Error::InvalidParameter(format!(
                "hidden volumes need a host of at least {MIN_HIDDEN_VOLUME_HOST_SIZE} bytes, got {host_size}"
            )));
        }
        if hidden_size < MIN_HIDDEN_VOLUME_SIZE || hidden_size > host_size - TOTAL_VOLUME_HEADERS_SIZE
        {
            return Err(Error::InvalidParameter(format!(
                "hidden volume size must be between {MIN_HIDDEN_VOLUME_SIZE} and {} bytes",
                host_size - TOTAL_VOLUME_HEADERS_SIZE
            )));
        }

        let volume_size = layout
            .max_data_size(hidden_size)
            .ok_or_else(|| Error::InvalidParameter("hidden size too small".into()))?;
        let data_offset = layout.creation_data_offset(host_size, hidden_size)?;
        let password = options.effective_password(Some(path))?;

        let header = VolumeHeader {
            version: VOLUME_HEADER_VERSION,
            required_min_version: TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION,
            volume_type: VolumeType::Hidden,
            creation_time: 0,
            modification_time: 0,
            hidden_volume_data_size: volume_size,
            volume_data_size: volume_size,
            encrypted_area_start: data_offset,
            encrypted_area_length: volume_size,
            flags: 0,
            sector_size: options.sector_size,
            ea: options.ea,
            prf: options.prf,
            salt: random_bytes(HEADER_SALT_SIZE)?,
            master_key: random_master_key(options.ea)?,
        };

        write_header_region(
            &file,
            layout.header_offset(),
            &header,
            &password,
            options.pim,
            &header.salt,
        )?;
        let backup_offset = backup_offset_of(host_size, layout)?;
        let backup_salt = random_bytes(HEADER_SALT_SIZE)?;
        write_header_region(&file, backup_offset, &header, &password, options.pim, &backup_salt)?;

        if options.full_format {
            randomize_data_area(&file, data_offset, volume_size, options.ea)?;
        }

        file.sync_all()?;
        Volume::from_parts(file, layout, header, host_size)
    }

    /// Open an existing volume, trying the layouts, PRFs and encryption
    /// algorithms in VeraCrypt's order.
    pub fn open(path: &Path, options: &OpenOptions) -> Result<Volume> {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        let host_size = file.metadata()?.len();
        // The keyfile pool is mixed in once; every trial below derives from it.
        let password = options.effective_password(Some(path))?;

        let mut layouts: Vec<VolumeLayout> = Vec::new();
        match options.volume_type {
            Some(t) => layouts.extend(t.creation_layout().trial_variants()),
            None => {
                layouts.extend(VolumeLayout::NORMAL_TRIAL_ORDER);
                layouts.extend(VolumeLayout::HIDDEN_TRIAL_ORDER);
            }
        }

        let prfs: Vec<Prf> = match options.prf {
            Some(p) => vec![p],
            None => Prf::TRIAL_ORDER.to_vec(),
        };
        let eas: Vec<EncryptionAlgorithm> = match options.ea {
            Some(e) => vec![e],
            None => EncryptionAlgorithm::ALL.to_vec(),
        };

        let mut saw_magic: Option<String> = None;
        for layout in &layouts {
            let region_offset = match region_offset_for(&file, *layout, host_size, options.use_backup_header) {
                Ok(o) => o,
                Err(e) => {
                    log::debug!("skipping {layout:?}: {e}");
                    continue;
                }
            };
            let mut region = vec![0u8; layout.header_size()];
            if let Err(e) = read_exact_at(&file, region_offset, &mut region) {
                log::debug!("cannot read header region of {layout:?}: {e}");
                continue;
            }

            for prf in &prfs {
                let mut header_key = vec![0u8; HEADER_KEY_SIZE];
                prf.derive(&password, &region[..HEADER_SALT_SIZE], options.pim, &mut header_key)?;

                // One 192-byte derived key serves every encryption algorithm
                // (each EA consumes only its own prefix), so the cheap magic
                // probe decides which EAs are worth a full header decrypt.
                // Note: a magic mismatch for one EA says nothing about the
                // others, so never stop the loop early.
                let mut magic_seen = false;
                for ea in &eas {
                    if !VolumeHeader::region_has_magic(&region, &header_key, *ea)? {
                        continue;
                    }
                    magic_seen = true;
                    match VolumeHeader::decrypt(&region, &header_key, *ea, *prf) {
                        Ok(header) => {
                            // A zero-length encrypted area is only plausible for a volume
                            // whose in-place encryption has not written a byte yet.
                            let starting_in_place = header.flags & HEADER_FLAG_NONSYS_INPLACE_ENC != 0;
                            if (!starting_in_place && header.encrypted_area_length == 0)
                                || header.encrypted_area_start + header.encrypted_area_length > host_size
                            {
                                log::debug!(
                                    "{layout:?}/{prf}/{ea}: header parsed but area {}+{} is outside the {host_size}-byte host",
                                    header.encrypted_area_start,
                                    header.encrypted_area_length
                                );
                                continue;
                            }
                            log::info!("opened {layout:?} volume with PRF {prf} and {ea}");
                            return Volume::from_parts(file, *layout, header, host_size);
                        }
                        Err(Error::HigherVersionRequired(v)) => {
                            return Err(Error::HigherVersionRequired(v));
                        }
                        Err(Error::InvalidHeader(msg)) => {
                            log::debug!("{layout:?}/{prf}/{ea}: {msg}");
                            saw_magic = Some(msg);
                        }
                        Err(e) => return Err(e),
                    }
                }
                if !magic_seen {
                    log::debug!("no VERA magic in {layout:?} region under {prf}");
                }
            }
        }

        match saw_magic {
            // The header decrypted (its magic is in place) but failed a
            // consistency check: the password/PIM/PRF identified *something*,
            // so the better guess is corruption rather than a wrong password.
            Some(msg) => Err(Error::InvalidHeader(format!(
                "a header decrypted but failed validation ({msg}); it may be corrupt, or the password/PIM pair is wrong for this volume"
            ))),
            None => Err(Error::PasswordIncorrect),
        }
    }

    fn from_parts(file: File, layout: VolumeLayout, header: VolumeHeader, host_size: u64) -> Result<Volume> {
        let xts = Xts::new(header.ea, header.data_key())?;
        let in_place = in_place_state(&header);
        // An unfinished in-place volume describes the *boundary* between its
        // plaintext part and its ciphertext part in EncryptedAreaStart, not the
        // start of the data area, so the usual layout arithmetic does not apply:
        // the data area itself always starts at TC_VOLUME_DATA_OFFSET.
        let data_offset = if in_place.is_some() {
            VOLUME_HEADER_GROUP_SIZE
        } else {
            layout.data_offset(&header, host_size)
        };
        // A partially encrypted volume still has to report its *whole* data area:
        // reads of the plaintext part are served from before the encrypted part.
        let data_size = if in_place.is_some() {
            header.volume_data_size
        } else {
            header.encrypted_area_length
        };
        Ok(Volume {
            file,
            header,
            layout,
            host_size,
            data_offset,
            data_size,
            xts,
            protected: OnceLock::new(),
            protection_triggered: AtomicBool::new(false),
            in_place,
        })
    }

    /// The state of an interrupted in-place encryption, when this volume is in
    /// one (see [`encrypt_in_place`]).
    pub fn in_place(&self) -> Option<InPlaceState> {
        self.in_place
    }

    /// Read and decrypt raw host bytes. `host_offset` and `buf.len()` must be
    /// multiples of 512, and the range must lie inside the data area.
    pub fn read_at(&self, host_offset: u64, buf: &mut [u8]) -> Result<()> {
        if let Some(state) = self.in_place {
            return Err(Error::InPlaceIncomplete {
                remaining: state.remaining,
            });
        }
        self.read_encrypted_at(host_offset, buf)
    }

    /// Read and decrypt raw host bytes, ignoring the in-place-encryption check.
    fn read_encrypted_at(&self, host_offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check_range(host_offset, buf.len())?;
        read_exact_at(&self.file, host_offset, buf)?;
        self.xts.decrypt(buf, host_offset / DATA_UNIT_SIZE as u64)?;
        Ok(())
    }

    /// Encrypt and write raw host bytes.
    pub fn write_at(&self, host_offset: u64, buf: &[u8]) -> Result<()> {
        if let Some(state) = self.in_place {
            return Err(Error::InPlaceIncomplete {
                remaining: state.remaining,
            });
        }
        self.check_range(host_offset, buf.len())?;
        self.check_protection(host_offset, buf.len() as u64)?;
        let mut enc = buf.to_vec();
        self.xts.encrypt(&mut enc, host_offset / DATA_UNIT_SIZE as u64)?;
        write_all_at(&self.file, host_offset, &enc)?;
        Ok(())
    }

    /// Read decrypted volume bytes at `offset` relative to the start of the
    /// volume data area.
    pub fn read_data(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let Some(state) = self.in_place else {
            return self.read_at(self.data_offset + offset, buf);
        };
        self.check_data_range(offset, buf.len())?;
        // Until the run finishes the volume is half plaintext, half ciphertext,
        // counted from the *end* of the data area: the last
        // `encrypted_length` logical bytes are ciphertext, everything before them
        // is still plaintext -- and the plaintext has not moved yet, so logical
        // byte L is still at host offset L.
        let plaintext = self.data_size - state.encrypted_length;
        let mut done = 0usize;
        if offset < plaintext {
            let n = std::cmp::min(plaintext - offset, buf.len() as u64) as usize;
            read_exact_at(&self.file, offset, &mut buf[..n])?;
            done = n;
        }
        if done < buf.len() {
            let host = self.data_offset + offset + done as u64;
            self.read_encrypted_at(host, &mut buf[done..])?;
        }
        Ok(())
    }

    /// Write decrypted volume bytes at `offset` relative to the start of the
    /// volume data area.
    pub fn write_data(&self, offset: u64, buf: &[u8]) -> Result<()> {
        if let Some(state) = self.in_place {
            return Err(Error::InPlaceIncomplete {
                remaining: state.remaining,
            });
        }
        self.write_at(self.data_offset + offset, buf)
    }

    /// Read `count` decrypted sectors starting at volume sector `sector`.
    pub fn read_sectors(&self, sector: u64, count: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; count * DATA_UNIT_SIZE];
        self.read_data(sector * DATA_UNIT_SIZE as u64, &mut buf)?;
        Ok(buf)
    }

    /// Overwrite `data` (a whole number of sectors) at volume sector `sector`.
    pub fn write_sectors(&self, sector: u64, data: &[u8]) -> Result<()> {
        self.write_data(sector * DATA_UNIT_SIZE as u64, data)
    }

    /// Turn on VeraCrypt's hidden-volume protection for `range` (host bytes).
    ///
    /// Writes overlapping the range are refused, and once a write has been
    /// refused *every* subsequent write is refused as well. VeraCrypt behaves
    /// the same way (`HiddenVolumeProtectionAction` in
    /// `src/Driver/EncryptedIoQueue.c`): a filesystem that ignores the write
    /// error must not be able to quietly destroy the hidden volume.
    pub fn protect_hidden_volume(&self, range: ProtectedRange) {
        let _ = self.protected.set(range);
    }

    /// The protected range, when hidden-volume protection is enabled.
    pub fn protected_range(&self) -> Option<ProtectedRange> {
        self.protected.get().copied()
    }

    /// True once a write has been refused by hidden-volume protection.
    pub fn protection_triggered(&self) -> bool {
        self.protection_triggered.load(Ordering::Relaxed)
    }

    /// Grow the container to `new_host_size` bytes, the way VeraCrypt's Volume
    /// Expander does it for a file-hosted normal volume
    /// (`src/ExpandVolume/ExpandVolume.c`).
    ///
    /// `password` is the password as the KDF sees it, i.e. with the keyfile pool
    /// already mixed in (see [`OpenOptions::effective_password`]). Both the
    /// primary and the backup header are rewritten with *fresh* random salts, so
    /// the header key is derived from the password again; the master key is
    /// **kept**, which is why the existing data does not have to be
    /// re-encrypted. The newly exposed bytes are filled with ciphertext under a
    /// throwaway key (VeraCrypt's `FormatNoFs`, "init free space"), and the old
    /// backup header group -- now in the middle of the data area -- is
    /// overwritten with random data.
    ///
    /// The filesystem inside the volume keeps its old size: extending it is the
    /// operating system's job.
    ///
    /// Only V2 normal volumes can grow. This does **not** look for a hidden
    /// volume: growing an outer volume destroys it, so the caller has to ask the
    /// user first (which is what VeraCrypt's expansion wizard does). The caller
    /// must also have opened the volume with the same password, which is what
    /// validates it -- with a wrong `password` the headers end up encrypted under
    /// a key nobody knows.
    pub fn expand(&mut self, new_host_size: u64, password: &[u8], pim: i32) -> Result<()> {
        let layout = self.layout;
        if !matches!(layout, VolumeLayout::V2Normal) {
            return Err(Error::Unsupported(format!(
                "expanding a {layout:?} volume is not supported; VeraCrypt only expands \
                 file-hosted normal volumes"
            )));
        }
        if self.header.volume_type != VolumeType::Normal || self.header.hidden_volume_data_size != 0 {
            return Err(Error::Unsupported(
                "a hidden volume cannot be expanded (VeraCrypt refuses that too)".into(),
            ));
        }
        if self.header.is_encrypted_system() {
            return Err(Error::Unsupported(
                "a system-encryption volume cannot be expanded".into(),
            ));
        }
        let old_host_size = self.host_size;
        if new_host_size < old_host_size {
            return Err(Error::InvalidParameter(format!(
                "the new size {new_host_size} is smaller than the current {old_host_size}; \
                 containers can only grow"
            )));
        }
        if new_host_size % self.header.sector_size as u64 != 0
            || new_host_size % DATA_UNIT_SIZE as u64 != 0
        {
            return Err(Error::InvalidParameter(format!(
                "the new size must be a multiple of the sector size ({} bytes)",
                self.header.sector_size
            )));
        }
        let new_data_size = layout
            .max_data_size(new_host_size)
            .ok_or_else(|| Error::InvalidParameter("the new host is too small".into()))?;
        if new_data_size < self.data_size + MIN_EXPAND_BYTES {
            return Err(Error::InvalidParameter(format!(
                "a container has to grow by at least {MIN_EXPAND_BYTES} bytes of data area \
                 (old data area {}, requested {new_data_size})",
                self.data_size
            )));
        }

        // 1. Grow the host file (VeraCrypt: SetFilePointerEx + SetEndOfFile).
        self.file.set_len(new_host_size)?;

        // 2. Fill the newly exposed area with zeroes encrypted under a throwaway
        //    key, so the free space looks like ciphertext (FormatNoFs). This also
        //    covers the fake hidden-header slot of the new backup header group.
        randomize_data_area(
            &self.file,
            old_host_size,
            new_host_size - old_host_size,
            self.header.ea,
        )?;

        // 3. The new header fields; the master key does not change.
        let mut header = self.header.clone();
        header.volume_data_size = new_data_size;
        header.hidden_volume_data_size = 0;
        header.encrypted_area_start = self.data_offset;
        header.encrypted_area_length = new_data_size;

        // 4. Backup header first, then the primary one, each with its own fresh
        //    salt (VeraCrypt's CreateVolumeHeaderInMemory generates one per copy).
        let backup_offset = new_host_size - VOLUME_HEADER_GROUP_SIZE;
        let backup_salt = random_bytes(HEADER_SALT_SIZE)?;
        write_header_region(&self.file, backup_offset, &header, password, pim, &backup_salt)?;
        let primary_salt = random_bytes(HEADER_SALT_SIZE)?;
        write_header_region(
            &self.file,
            layout.header_offset(),
            &header,
            password,
            pim,
            &primary_salt,
        )?;
        header.salt = primary_salt;

        // 5. The old backup header group sits inside the data area now; wipe it
        //    so no stale, decryptable header survives.
        wipe_region(
            &self.file,
            old_host_size - VOLUME_HEADER_GROUP_SIZE,
            VOLUME_HEADER_GROUP_SIZE,
        )?;

        self.file.sync_all()?;
        self.host_size = new_host_size;
        self.header = header;
        self.data_size = new_data_size;
        log::info!(
            "expanded to {new_host_size} bytes (data area {new_data_size} bytes, backup header at \
             {backup_offset})"
        );
        Ok(())
    }

    fn check_protection(&self, host_offset: u64, len: u64) -> Result<()> {
        let Some(range) = self.protected.get().copied() else {
            return Ok(());
        };
        if self.protection_triggered.load(Ordering::Relaxed) {
            return Err(Error::HiddenVolumeProtectionActive);
        }
        if range.overlaps(host_offset, len) {
            self.protection_triggered.store(true, Ordering::Relaxed);
            log::warn!(
                "hidden volume protection triggered: a {len}-byte write at host offset {host_offset} \
                 overlaps the protected range {}..{}",
                range.start,
                range.end()
            );
            return Err(Error::HiddenVolumeProtected {
                offset: host_offset,
                length: len,
                start: range.start,
                end: range.end(),
            });
        }
        Ok(())
    }

    /// The raw (still encrypted) header region this volume was opened from.
    pub fn header_region(&self) -> Result<Vec<u8>> {
        let offset = self
            .layout
            .backup_header_offset()
            .map(|o| (self.host_size as i64 + o) as u64)
            .unwrap_or_else(|| self.layout.header_offset());
        let mut region = vec![0u8; self.layout.header_size()];
        read_exact_at(&self.file, offset, &mut region)?;
        Ok(region)
    }

    /// Borrow the underlying host file.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Flush pending writes to the host file.
    pub fn flush(&self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }

    fn check_range(&self, host_offset: u64, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        if host_offset % DATA_UNIT_SIZE as u64 != 0 || len % DATA_UNIT_SIZE != 0 {
            return Err(Error::InvalidParameter(format!(
                "host offset and length must be multiples of {DATA_UNIT_SIZE}, got {host_offset}/{len}"
            )));
        }
        let end = host_offset + len as u64;
        if host_offset < self.data_offset || end > self.data_offset + self.data_size {
            return Err(Error::InvalidParameter(format!(
                "range {host_offset}..{end} is outside the volume data area {}..{}",
                self.data_offset,
                self.data_offset + self.data_size
            )));
        }
        Ok(())
    }

    /// Like [`Self::check_range`], but for offsets relative to the data area.
    fn check_data_range(&self, offset: u64, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        if offset % DATA_UNIT_SIZE as u64 != 0 || len % DATA_UNIT_SIZE != 0 {
            return Err(Error::InvalidParameter(format!(
                "data offset and length must be multiples of {DATA_UNIT_SIZE}, got {offset}/{len}"
            )));
        }
        if offset + len as u64 > self.data_size {
            return Err(Error::InvalidParameter(format!(
                "range {offset}..{} is outside the {} byte volume data area",
                offset + len as u64,
                self.data_size
            )));
        }
        Ok(())
    }
}

impl VolumeLayout {
    /// Layouts to try for a requested volume type.
    pub const fn trial_variants(self) -> &'static [VolumeLayout] {
        match self {
            VolumeLayout::V2Normal => &VolumeLayout::NORMAL_TRIAL_ORDER,
            VolumeLayout::V2Hidden => &VolumeLayout::HIDDEN_TRIAL_ORDER,
            VolumeLayout::V1Normal => &VolumeLayout::NORMAL_TRIAL_ORDER,
        }
    }
}

/// Offset of the hidden volume header slot in a V2 normal volume.
const HIDDEN_SLOT_OFFSET: u64 = VOLUME_HEADER_SIZE;

fn validate_sector_size(sector_size: u32) -> Result<()> {
    if !(MIN_SECTOR_SIZE..=MAX_SECTOR_SIZE).contains(&sector_size)
        || sector_size % MIN_SECTOR_SIZE != 0
    {
        return Err(Error::InvalidParameter(format!(
            "sector size must be 512..4096 and a multiple of 512, got {sector_size}"
        )));
    }
    Ok(())
}

fn backup_offset_of(host_size: u64, layout: VolumeLayout) -> Result<u64> {
    let rel = layout
        .backup_header_offset()
        .ok_or_else(|| Error::Unsupported(format!("{layout:?} has no backup header")))?;
    let offset = (host_size as i64 + rel) as u64;
    if offset + layout.header_size() as u64 > host_size {
        return Err(Error::InvalidParameter("host is too small for a backup header".into()));
    }
    Ok(offset)
}

fn region_offset_for(
    _file: &File,
    layout: VolumeLayout,
    host_size: u64,
    backup: bool,
) -> Result<u64> {
    let offset = if backup {
        backup_offset_of(host_size, layout)?
    } else {
        layout.header_offset()
    };
    if offset + layout.header_size() as u64 > host_size {
        return Err(Error::InvalidParameter(format!(
            "{layout:?} header at {offset} does not fit in a {host_size}-byte host"
        )));
    }
    Ok(offset)
}

fn write_header_region(
    file: &File,
    offset: u64,
    header: &VolumeHeader,
    password: &[u8],
    pim: i32,
    salt: &[u8],
) -> Result<()> {
    let mut header_key = vec![0u8; HEADER_KEY_SIZE];
    header.prf.derive(password, salt, pim, &mut header_key)?;
    let region = header.encrypt_with_salt(VOLUME_HEADER_SIZE as usize, &header_key, salt)?;
    write_all_at(file, offset, &region)?;
    Ok(())
}

/// VeraCrypt writes a *fake* hidden-volume header into every hidden header slot
/// of a normal volume (`VolumeCreator::CreateVolume`, "Write fake random
/// header"). It is encrypted with a purely random header key, so it is
/// indistinguishable from random data, and no password can open it.
fn write_fake_hidden_region(
    file: &File,
    offset: u64,
    host_size: u64,
    size_for_max: u64,
    options: &CreateOptions,
) -> Result<()> {
    let layout = VolumeLayout::V2Hidden;
    let region_size = layout.header_size();
    let volume_data_size = layout.max_data_size(size_for_max).unwrap_or(0);
    let header = VolumeHeader {
        version: VOLUME_HEADER_VERSION,
        required_min_version: TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION,
        volume_type: VolumeType::Hidden,
        creation_time: 0,
        modification_time: 0,
        hidden_volume_data_size: volume_data_size,
        volume_data_size,
        // VeraCrypt computes this without a guard; for a normal volume
        // `size_for_max == host_size`, so it wraps around to a huge value. We
        // reproduce that behaviour bit for bit.
        encrypted_area_start: host_size
            .wrapping_sub(2 * VOLUME_HEADER_SIZE)
            .wrapping_sub(size_for_max),
        encrypted_area_length: volume_data_size,
        flags: 0,
        sector_size: options.sector_size,
        ea: options.ea,
        prf: options.prf,
        salt: random_bytes(HEADER_SALT_SIZE)?,
        master_key: random_master_key(options.ea)?,
    };
    let header_key = random_bytes(HEADER_KEY_SIZE)?;
    let region = header.encrypt(region_size, &header_key)?;
    write_all_at(file, offset, &region)?;
    Ok(())
}

/// Fill the data area with zeros encrypted under a throwaway key, which is how
/// VeraCrypt's slow format makes the "empty" part of the volume look random.
fn randomize_data_area(file: &File, data_offset: u64, data_size: u64, ea: EncryptionAlgorithm) -> Result<()> {
    let throwaway = random_bytes(ea.key_size() * 2)?;
    let xts = Xts::new(ea, &throwaway)?;
    const CHUNK: usize = 1024 * 1024; // must be a multiple of the data unit size
    let mut buf = vec![0u8; CHUNK];
    let mut written = 0u64;
    while written < data_size {
        let len = std::cmp::min(CHUNK as u64, data_size - written) as usize;
        // The chunk is not necessarily a whole number of data units; XTS only
        // processes whole 16-byte blocks, and both sizes are multiples of 512.
        let slice = &mut buf[..len];
        for b in slice.iter_mut() {
            *b = 0;
        }
        xts.encrypt(slice, (data_offset + written) / DATA_UNIT_SIZE as u64)?;
        write_all_at(file, data_offset + written, slice)?;
        written += len as u64;
    }
    Ok(())
}

/// Overwrite `len` bytes at `offset` with random data (one pass; VeraCrypt runs
/// the user's wipe algorithm over the old backup header group).
fn wipe_region(file: &File, offset: u64, len: u64) -> Result<()> {
    const CHUNK: usize = 1024 * 1024;
    let mut written = 0u64;
    while written < len {
        let n = std::cmp::min(CHUNK as u64, len - written) as usize;
        let buf = random_bytes(n)?;
        write_all_at(file, offset + written, &buf)?;
        written += n as u64;
    }
    Ok(())
}

/// Encrypt a plaintext device/partition image **in place**, the way VeraCrypt's
/// "Encrypt a non-system partition/volume in place" does it
/// (`src/Format/InPlace.c`) -- or resume an interrupted run. `password` is the
/// password as the KDF sees it (keyfiles already mixed in).
///
/// The image is turned into a V2 normal container without ever needing a second
/// copy of the data:
///
/// * the last `VOLUME_HEADER_GROUP_SIZE` (128 KiB) bytes of the image are used for
///   the backup header group, so the filesystem has to leave that much free at the
///   end (VeraCrypt shrinks the filesystem for you; for a raw image, make sure the
///   tail is free/zeroed),
/// * the data area is moved *forward* by the same amount, so it ends up right
///   behind the primary header group,
/// * a fresh master key is generated and stored in the backup header from the very
///   beginning, and the primary header is only written once the whole data area is
///   encrypted,
/// * the work runs from the end of the data area downwards in chunks of
///   [`IN_PLACE_CHUNK_SIZE`], so no plaintext byte is overwritten before it has
///   been read,
/// * the backup header is refreshed every [`IN_PLACE_HEADER_UPDATE_INTERVAL`], so
///   an interrupted run can simply be resumed by calling this function again: it
///   opens the backup header, finds out how much is left and continues.
///
/// The finished volume is a plain (fully encrypted) V2 normal volume whose header
/// keeps VeraCrypt's `TC_HEADER_FLAG_NONSYS_INPLACE_ENC` flag set -- exactly what
/// VeraCrypt leaves behind, and what it mounts without complaint.
///
/// When `stop_after` is `Some(n)` the run stops once `n` bytes of the data area
/// have been processed in this call, which leaves the volume in the partially
/// encrypted state (used for testing the resume path).
pub fn encrypt_in_place_stopping_after(
    path: &Path,
    password: &[u8],
    pim: i32,
    ea: EncryptionAlgorithm,
    prf: Prf,
    stop_after: Option<u64>,
) -> Result<Volume> {
    let layout = VolumeLayout::V2Normal;
    let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let file_size = file.metadata()?.len();
    if file_size % DATA_UNIT_SIZE as u64 != 0 {
        return Err(Error::InvalidParameter(format!(
            "the image size must be a multiple of {DATA_UNIT_SIZE}, got {file_size}"
        )));
    }
    let backup_offset = file_size.checked_sub(VOLUME_HEADER_GROUP_SIZE).ok_or_else(|| {
        Error::InvalidParameter(format!(
            "the image must be at least {VOLUME_HEADER_GROUP_SIZE} bytes, got {file_size}"
        ))
    })?;
    let create_options = CreateOptions {
        ea,
        prf,
        password: password.to_vec(),
        keyfiles: Vec::new(),
        pim,
        sector_size: DATA_UNIT_SIZE as u32,
        full_format: false,
    };

    // While a volume is being encrypted in place only its *backup* header is
    // valid (the primary header group would sit on top of data that has not been
    // moved up yet), and that is the copy VeraCrypt resumes from.
    let existing = read_backup_header(&file, backup_offset, password, pim, ea, prf)?;
    let (mut header, backup_salt) = match existing {
        Some(header) => {
            if header.volume_type != VolumeType::Normal || header.hidden_volume_data_size != 0 {
                return Err(Error::Unsupported(format!(
                    "{} is not a normal volume; in-place encryption only applies to normal \
                     volumes",
                    path.display()
                )));
            }
            if header.flags & HEADER_FLAG_NONSYS_INPLACE_ENC == 0 {
                return Err(Error::Unsupported(format!(
                    "{} is already a finished volume (its backup header has no in-place encryption \
                     flag), so there is nothing to encrypt",
                    path.display()
                )));
            }
            let state = in_place_state(&header).ok_or_else(|| {
                Error::Unsupported(format!(
                    "{} reports a complete in-place encryption but its lengths disagree",
                    path.display()
                ))
            })?;
            let mut salt = vec![0u8; HEADER_SALT_SIZE];
            read_exact_at(&file, backup_offset, &mut salt)?;
            log::info!(
                "resuming in-place encryption of {}: {} bytes left to encrypt ({} already done)",
                path.display(),
                state.remaining,
                state.encrypted_length
            );
            (header, salt)
        }
        None => {
            // The image is `plaintext || header group`: the plaintext area holds the
            // (about to be shrunk) filesystem, and the free space at the end is
            // where VeraCrypt puts the backup header group. Once the run finishes
            // the data area is the plaintext area minus one header group, because
            // the primary header group takes its first 128 KiB.
            let plaintext_size = backup_offset;
            let data_size = plaintext_size - VOLUME_HEADER_GROUP_SIZE;
            if data_size < MIN_IN_PLACE_DATA_SIZE || data_size % DATA_UNIT_SIZE as u64 != 0 {
                return Err(Error::InvalidParameter(format!(
                    "the image leaves {data_size} bytes for the data area; in-place encryption \
                     needs at least {MIN_IN_PLACE_DATA_SIZE} and a multiple of {DATA_UNIT_SIZE}"
                )));
            }
            let salt = random_bytes(HEADER_SALT_SIZE)?;
            let header = VolumeHeader {
                version: VOLUME_HEADER_VERSION,
                required_min_version: TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION,
                volume_type: VolumeType::Normal,
                creation_time: 0,
                modification_time: 0,
                hidden_volume_data_size: 0,
                volume_data_size: data_size,
                // Nothing is encrypted yet. VeraCrypt starts this field at the start
                // of the backup header group -- i.e. at the end of the data area --
                // and moves it down as ciphertext is written from the top down, so
                // that it is always the boundary between plaintext and ciphertext
                // and `encrypted_area_start + encrypted_area_length` stays put.
                encrypted_area_start: plaintext_size,
                encrypted_area_length: 0,
                flags: HEADER_FLAG_NONSYS_INPLACE_ENC,
                sector_size: DATA_UNIT_SIZE as u32,
                ea,
                prf,
                salt: salt.clone(),
                master_key: random_master_key(ea)?,
            };
            write_header_region(&file, backup_offset, &header, password, pim, &salt)?;
            write_fake_hidden_region(
                &file,
                backup_offset + HIDDEN_SLOT_OFFSET,
                file_size,
                file_size,
                &create_options,
            )?;
            file.sync_all()?;
            log::info!(
                "starting in-place encryption of {}: data area {data_size} bytes, backup header at \
                 {backup_offset}",
                path.display()
            );
            (header, salt)
        }
    };
    header.salt = backup_salt.clone();

    let xts = Xts::new(header.ea, header.data_key())?;
    let data_size = header.volume_data_size;
    let mut data_offset = header.encrypted_area_start;
    let mut encrypted_length = header.encrypted_area_length;
    let mut processed = 0u64;
    let mut since_update = 0u64;

    while encrypted_length < data_size {
        let mut chunk = std::cmp::min(data_size - encrypted_length, IN_PLACE_CHUNK_SIZE);
        if let Some(limit) = stop_after {
            let left = limit.saturating_sub(processed);
            if left == 0 {
                break;
            }
            chunk = std::cmp::min(chunk, left);
        }
        chunk -= chunk % DATA_UNIT_SIZE as u64;
        if chunk == 0 {
            break;
        }
        // Ciphertext is written where the plaintext will have been moved to; the
        // plaintext source sits VOLUME_HEADER_GROUP_SIZE bytes before it. XTS data
        // unit numbers come from the ciphertext (destination) offset.
        let dest = data_offset - chunk;
        let src = dest - VOLUME_HEADER_GROUP_SIZE;
        let mut buf = vec![0u8; chunk as usize];
        read_exact_at(&file, src, &mut buf)?;
        xts.encrypt(&mut buf, dest / DATA_UNIT_SIZE as u64)?;
        write_all_at(&file, dest, &buf)?;

        data_offset -= chunk;
        encrypted_length += chunk;
        processed += chunk;
        since_update += chunk;
        header.encrypted_area_start = data_offset;
        header.encrypted_area_length = encrypted_length;

        if since_update >= IN_PLACE_HEADER_UPDATE_INTERVAL || encrypted_length == data_size {
            // VeraCrypt's FastVolumeHeaderUpdate: same salt and key, new lengths.
            write_header_region(&file, backup_offset, &header, password, pim, &backup_salt)?;
            file.sync_all()?;
            since_update = 0;
        }
        if encrypted_length == data_size || processed % IN_PLACE_HEADER_UPDATE_INTERVAL == 0 {
            log::info!(
                "in-place encryption of {}: {encrypted_length}/{data_size} bytes ({:.1}%)",
                path.display(),
                encrypted_length as f64 * 100.0 / data_size as f64
            );
        }
    }

    let finished = encrypted_length >= data_size;
    if !finished && since_update > 0 {
        // Remember how far we got, so a later run resumes from here (VeraCrypt
        // rewrites the backup header every 64 MiB and when it stops, always
        // reusing the same salt and key: FastVolumeHeaderUpdate).
        write_header_region(&file, backup_offset, &header, password, pim, &backup_salt)?;
        file.sync_all()?;
    }
    if finished {
        // The whole data area is ciphertext now, so the primary header group fits
        // in front of it and EncryptedAreaStart becomes the data area start -- a
        // plain, fully encrypted V2 normal volume (VeraCrypt keeps the flag set and
        // mounts it once EncryptedAreaLength == VolumeSize).
        header.encrypted_area_start = VOLUME_HEADER_GROUP_SIZE;
        header.encrypted_area_length = data_size;
        let primary_salt = random_bytes(HEADER_SALT_SIZE)?;
        write_header_region(&file, layout.header_offset(), &header, password, pim, &primary_salt)?;
        write_fake_hidden_region(
            &file,
            HIDDEN_SLOT_OFFSET,
            file_size,
            file_size,
            &create_options,
        )?;
        write_header_region(&file, backup_offset, &header, password, pim, &backup_salt)?;
        write_fake_hidden_region(
            &file,
            backup_offset + HIDDEN_SLOT_OFFSET,
            file_size,
            file_size,
            &create_options,
        )?;
        header.salt = primary_salt;
        file.sync_all()?;
        log::info!(
            "in-place encryption of {} finished: {data_size} bytes of data area",
            path.display()
        );
    } else {
        log::info!(
            "in-place encryption of {} paused: {encrypted_length} of {data_size} bytes encrypted",
            path.display()
        );
    }
    drop(file);

    Volume::open(
        path,
        &OpenOptions {
            password: password.to_vec(),
            keyfiles: Vec::new(),
            pim,
            prf: Some(prf),
            ea: Some(ea),
            volume_type: Some(VolumeType::Normal),
            // Only the backup copy exists until the run has finished.
            use_backup_header: !finished,
        },
    )
}

/// [`encrypt_in_place_stopping_after`] with no early stop.
pub fn encrypt_in_place(
    path: &Path,
    password: &[u8],
    pim: i32,
    ea: EncryptionAlgorithm,
    prf: Prf,
) -> Result<Volume> {
    encrypt_in_place_stopping_after(path, password, pim, ea, prf, None)
}

/// The state of an unfinished in-place encryption, when the header describes one.
fn in_place_state(header: &VolumeHeader) -> Option<InPlaceState> {
    if header.flags & HEADER_FLAG_NONSYS_INPLACE_ENC == 0
        || header.encrypted_area_length >= header.volume_data_size
    {
        return None;
    }
    Some(InPlaceState {
        encrypted_length: header.encrypted_area_length,
        remaining: header.volume_data_size - header.encrypted_area_length,
    })
}

/// Read the backup header of a container file, when the slot holds one that
/// `password` opens. A slot of zeroes means the image has no header yet, i.e. a
/// fresh in-place encryption run.
fn read_backup_header(
    file: &File,
    backup_offset: u64,
    password: &[u8],
    pim: i32,
    ea: EncryptionAlgorithm,
    prf: Prf,
) -> Result<Option<VolumeHeader>> {
    let mut salt = vec![0u8; HEADER_SALT_SIZE];
    read_exact_at(file, backup_offset, &mut salt)?;
    if salt.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    let mut region = vec![0u8; VOLUME_HEADER_SIZE as usize];
    read_exact_at(file, backup_offset, &mut region)?;
    let mut header_key = vec![0u8; HEADER_KEY_SIZE];
    prf.derive(password, &region[..HEADER_SALT_SIZE], pim, &mut header_key)?;
    match VolumeHeader::decrypt(&region, &header_key, ea, prf) {
        Ok(header) => Ok(Some(header)),
        Err(e) => match e {
            // Real failures of the environment must not be papered over.
            Error::Io(_) | Error::Botan(_) | Error::BotanFfi { .. } => Err(e),
            // A slot that does not decrypt is either an unfinished container whose
            // password/PIM/keyfiles do not match, or a plain image whose tail is not
            // zeroed. Either way it must never be overwritten silently.
            _ => Err(Error::Unsupported(format!(
                "the last {VOLUME_HEADER_GROUP_SIZE} bytes of the image already hold data that is \
                 not a header this password opens ({e}); if this really is a plain image, zero \
                 those bytes (or truncate the file by {VOLUME_HEADER_GROUP_SIZE} bytes) first, \
                 otherwise check the password/PIM/keyfiles"
            ))),
        },
    }
}

fn random_master_key(ea: EncryptionAlgorithm) -> Result<Vec<u8>> {
    let key_size = ea.key_size();
    loop {
        let key = random_bytes(key_size * 2)?;
        if key[..key_size] != key[key_size..] {
            return Ok(key);
        }
        log::warn!("generated an XTS key whose halves are equal; retrying");
    }
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut rng = botan::RandomNumberGenerator::new()?;
    Ok(rng.read(len)?)
}

/// Positional read/write helpers (the host file is shared, so we avoid the
/// process-wide file cursor).
#[cfg(windows)]
pub fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => return Err(std::io::Error::from(ErrorKind::UnexpectedEof)),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn write_all_at(file: &File, mut offset: u64, mut buf: &[u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_write(buf, offset) {
            Ok(0) => return Err(std::io::Error::from(ErrorKind::WriteZero)),
            Ok(n) => {
                buf = &buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(unix)]
pub fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(unix)]
pub fn write_all_at(file: &File, offset: u64, buf: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

impl std::fmt::Debug for Volume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Volume")
            .field("layout", &self.layout)
            .field("volume_type", &self.header.volume_type)
            .field("ea", &self.header.ea)
            .field("prf", &self.header.prf)
            .field("host_size", &self.host_size)
            .field("data_offset", &self.data_offset)
            .field("data_size", &self.data_size)
            .finish()
    }
}

/// Read raw host bytes without decrypting them (diagnostics, tests, CLI).
pub fn read_region(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}
