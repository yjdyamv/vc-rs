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
use crate::random::RandomSupply;
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
    /// When false (VeraCrypt's "quick format") the data area is left as
    /// whatever the file system reports as free/empty space, which means the
    /// untouched part of the volume stays zero bytes on disk and is therefore
    /// recognisable as a region nobody ever wrote to. When true (the default,
    /// as in VeraCrypt) the whole data area is filled with zeros encrypted
    /// under a throwaway key, exactly like VeraCrypt's slow format.
    pub full_format: bool,
    /// Create the container as a sparse (VeraCrypt's "dynamic") file: it is
    /// created at its full size, but only the parts that are actually written
    /// use disk space. VeraCrypt only sets the sparse flag together with a quick
    /// format (a full format writes every byte, which would defeat the point),
    /// so the two are mutually exclusive here as well.
    pub sparse: bool,
    /// Read the random bytes that build the volume from this file instead of
    /// the operating system's generator, so the same file always produces the
    /// same container (VeraCrypt's `--random-source` switch, with reproducible
    /// results rather than extra entropy). Meant for tests and audits: with a
    /// small source file the container's keys are reproducible, so it must not
    /// be used for a volume that is supposed to keep a secret.
    pub random_source: Option<PathBuf>,
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
            full_format: true,
            sparse: false,
            random_source: None,
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
    /// Freeze the container's timestamps for as long as the volume is open and
    /// put them back when it is dropped.
    ///
    /// This is VeraCrypt's "Preserve modification timestamp of file containers",
    /// on by default there: mounting a volume, or even just checking a password,
    /// must not reveal when the container was last used. Everything that opens a
    /// volume for a user (the `vcrs` CLI, the iSCSI mount) sets this; the library
    /// leaves it off so that opening a volume has no side effects unless asked.
    pub preserve_timestamps: bool,
}

impl OpenOptions {
    /// The password bytes the KDF sees, i.e. with the keyfile pool mixed in.
    pub fn effective_password(&self, volume: Option<&Path>) -> Result<Vec<u8>> {
        apply_keyfiles(&self.password, &self.keyfiles, volume)
    }
}

/// The timestamps of the container file, saved while they are frozen.
///
/// VeraCrypt's driver freezes them when a container is mounted ("Preserve
/// modification timestamp of file containers", on by default: `bPreserveTimestamp
/// = TRUE` in `src/Common/Dlgcode.c`) so that using a volume does not reveal
/// *when* it was used -- the file's last-write time is exactly the kind of
/// metadata that gives a container away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTimestamps {
    /// Last access time, as the host file reported it before it was frozen.
    pub last_access: std::time::SystemTime,
    /// Last write time, as the host file reported it before it was frozen.
    pub last_write: std::time::SystemTime,
    /// Creation, access, write and change times in Windows `FILETIME` units
    /// (100 ns since 1601), which is what the freeze/restore calls use.
    #[cfg(windows)]
    raw: [i64; 4],
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
    /// Timestamps saved by [`OpenOptions::preserve_timestamps`], to put back when
    /// the volume (and with it the file handle) is dropped.
    timestamps: Option<FileTimestamps>,
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
        if options.sparse && options.full_format {
            return Err(Error::InvalidParameter(
                "a sparse (dynamic) container has to be quick-formatted: a full format writes \
                 every byte of the data area, which is what a sparse file is meant to avoid \
                 (VeraCrypt only sets the sparse flag for a quick format)"
                    .into(),
            ));
        }
        // Both of these are checked before the container file is touched, so a bad
        // request cannot leave a half-created container behind.
        let mut random = random_supply(options)?;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        if options.sparse {
            // Before the file is extended: everything that is never written then
            // stays unallocated and reads back as zeros, like VeraCrypt's
            // dynamic containers.
            set_sparse(&file)?;
        }
        file.set_len(host_size)?;

        let volume_size = layout
            .max_data_size(host_size)
            .ok_or_else(|| Error::InvalidParameter("host is too small".into()))?;
        let data_offset = layout.creation_data_offset(host_size, volume_size)?;

        let master_key = random_master_key(options.ea, &mut random)?;
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
            salt: random.bytes(HEADER_SALT_SIZE)?,
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
        write_fake_hidden_region(&file, HIDDEN_SLOT_OFFSET, host_size, host_size, options, &mut random)?;

        if options.full_format {
            randomize_data_area(&file, data_offset, volume_size, options.ea, &mut random)?;
        }

        // Backup header: VeraCrypt encrypts it with a *fresh* random salt (and
        // therefore a freshly derived header key), so the two header copies are
        // independent. Then its own fake hidden header.
        let backup_offset = backup_offset_of(host_size, layout)?;
        let backup_salt = random.bytes(HEADER_SALT_SIZE)?;
        write_header_region(&file, backup_offset, &header, &password, options.pim, &backup_salt)?;
        write_fake_hidden_region(
            &file,
            backup_offset + VOLUME_HEADER_SIZE,
            host_size,
            host_size,
            options,
            &mut random,
        )?;

        file.sync_all()?;
        Volume::from_parts(file, layout, header, host_size, None)
    }

    /// Create a hidden volume inside the existing container `path`.
    ///
    /// `hidden_size` is the size of the hidden volume; the host file must
    /// already be large enough (`>= hidden_size + 262144`).
    pub fn create_hidden(path: &Path, hidden_size: u64, options: &CreateOptions) -> Result<Volume> {
        let layout = VolumeLayout::V2Hidden;
        validate_sector_size(options.sector_size)?;
        let mut random = random_supply(options)?;
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
            salt: random.bytes(HEADER_SALT_SIZE)?,
            master_key: random_master_key(options.ea, &mut random)?,
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
        let backup_salt = random.bytes(HEADER_SALT_SIZE)?;
        write_header_region(&file, backup_offset, &header, &password, options.pim, &backup_salt)?;

        if options.full_format {
            randomize_data_area(&file, data_offset, volume_size, options.ea, &mut random)?;
        }

        file.sync_all()?;
        Volume::from_parts(file, layout, header, host_size, None)
    }

    /// Open an existing volume, trying the layouts, PRFs and encryption
    /// algorithms in VeraCrypt's order.
    pub fn open(path: &Path, options: &OpenOptions) -> Result<Volume> {
        // A raw partition goes through the device layer: its size has to come
        // from the disk ioctl (`GetFileSizeEx` reports 0 for some volumes), it
        // needs `FSCTL_ALLOW_EXTENDED_DASD_IO` for the sectors the filesystem
        // driver guards, and VeraCrypt forces `preserveTimestamps = FALSE` for
        // devices because their handles reject `FILE_BASIC_INFO`.
        let is_device = crate::device::looks_like_device(path);
        let (file, host_size) = if is_device {
            let device = crate::device::Device::open(path, true)?;
            // Best effort: an encrypted (RAW) device has no filesystem attached,
            // so the ioctl fails, and it is only needed when a driver guards the
            // sectors past the filesystem's end. VeraCrypt does the same.
            if let Err(e) = device.allow_extended_dasd_io() {
                log::debug!("raw access was not needed for {path:?}: {e}");
            }
            let size = device.len();
            (device.into_file(), size)
        } else {
            let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
            let size = file.metadata()?.len();
            (file, size)
        };
        // VeraCrypt freezes the timestamps of a container as soon as it opens it
        // (`OpenVolume(..., preserveTimestamps, ...)`), and the order matters:
        // the filesystem records an access when the first read happens, and once
        // it has, no later "do not update" flag takes effect (measured on this
        // machine: freezing after a read leaves the access time updated).
        let timestamps = if options.preserve_timestamps && !is_device {
            match freeze_file_timestamps(&file) {
                Ok(timestamps) => {
                    if timestamps.is_some() {
                        log::debug!("preserving the container's timestamps while it is open");
                    }
                    timestamps
                }
                Err(e) => {
                    log::warn!("could not preserve the container's timestamp: {e}");
                    None
                }
            }
        } else {
            None
        };
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
                            return Volume::from_parts(file, *layout, header, host_size, timestamps);
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

    fn from_parts(
        file: File,
        layout: VolumeLayout,
        header: VolumeHeader,
        host_size: u64,
        timestamps: Option<FileTimestamps>,
    ) -> Result<Volume> {
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
            timestamps,
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
            &mut RandomSupply::system(),
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

    /// Change the credentials of this volume's header (VeraCrypt's "Change
    /// Volume Password").
    ///
    /// Both the primary and the backup copy of the header are rewritten, each
    /// with a *fresh* random salt, encrypted under a key derived from
    /// `new_password`; the master key -- and with it the whole data area -- is
    /// not touched, so this is instant even for a huge container. The other
    /// header slot of the host file (the hidden volume's, or the fake hidden
    /// header of an ordinary container) is left alone.
    ///
    /// `new_password` is the password as the KDF sees it, i.e. with the keyfile
    /// pool already mixed in (see [`OpenOptions::effective_password`]).
    /// `new_prf` of `None` keeps the header key derivation function the volume
    /// already uses. The PIM is not stored in the header, so the caller has to
    /// remember the new one.
    pub fn change_credentials(
        &mut self,
        new_password: &[u8],
        new_pim: i32,
        new_prf: Option<Prf>,
    ) -> Result<()> {
        if matches!(self.layout, VolumeLayout::V1Normal) {
            return Err(Error::Unsupported(
                "changing the credentials of a legacy V1 volume is not supported".into(),
            ));
        }
        if self.in_place.is_some() {
            return Err(Error::Unsupported(
                "the credentials of a volume whose in-place encryption is unfinished cannot be \
                 changed; finish (or resume) that first"
                    .into(),
            ));
        }

        let mut header = self.header.clone();
        header.prf = new_prf.unwrap_or(header.prf);

        // VeraCrypt derives one key per copy from a salt generated for that copy
        // (`VolumeCreator::CreateVolumeHeaderInMemory`).
        let primary_salt = random_bytes(HEADER_SALT_SIZE)?;
        write_header_region_verified(
            &self.file,
            self.layout.header_offset(),
            &header,
            new_password,
            new_pim,
            &primary_salt,
        )?;
        let backup_salt = random_bytes(HEADER_SALT_SIZE)?;
        write_header_region_verified(
            &self.file,
            backup_offset_of(self.host_size, self.layout)?,
            &header,
            new_password,
            new_pim,
            &backup_salt,
        )?;

        let previous_prf = self.header.prf;
        header.salt = primary_salt;
        self.file.sync_all()?;
        self.header = header;
        log::info!(
            "changed the header credentials: {previous_prf} -> {} with PIM {new_pim}",
            self.header.prf
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
    let region = build_header_region(header, password, pim, salt)?;
    write_all_at(file, offset, &region)?;
    Ok(())
}

/// Like [`write_header_region`], but read the region back and compare it, so a
/// header that was only partially written (or written to the wrong place) is
/// noticed before the old one is gone for good.
fn write_header_region_verified(
    file: &File,
    offset: u64,
    header: &VolumeHeader,
    password: &[u8],
    pim: i32,
    salt: &[u8],
) -> Result<()> {
    let region = build_header_region(header, password, pim, salt)?;
    write_all_at(file, offset, &region)?;
    let mut read_back = vec![0u8; region.len()];
    read_exact_at(file, offset, &mut read_back)?;
    if read_back != region {
        return Err(Error::InvalidHeader(format!(
            "the header written at offset {offset} did not read back unchanged"
        )));
    }
    Ok(())
}

fn build_header_region(
    header: &VolumeHeader,
    password: &[u8],
    pim: i32,
    salt: &[u8],
) -> Result<Vec<u8>> {
    let mut header_key = vec![0u8; HEADER_KEY_SIZE];
    header.prf.derive(password, salt, pim, &mut header_key)?;
    header.encrypt_with_salt(VOLUME_HEADER_SIZE as usize, &header_key, salt)
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
    random: &mut RandomSupply,
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
        salt: random.bytes(HEADER_SALT_SIZE)?,
        master_key: random_master_key(options.ea, random)?,
    };
    let header_key = random.bytes(HEADER_KEY_SIZE)?;
    let region = header.encrypt(region_size, &header_key)?;
    write_all_at(file, offset, &region)?;
    Ok(())
}

/// Fill the data area with zeros encrypted under a throwaway key, which is how
/// VeraCrypt's slow format makes the "empty" part of the volume look random.
fn randomize_data_area(
    file: &File,
    data_offset: u64,
    data_size: u64,
    ea: EncryptionAlgorithm,
    random: &mut RandomSupply,
) -> Result<()> {
    let throwaway = random.bytes(ea.key_size() * 2)?;
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
        sparse: false,
        random_source: None,
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
                master_key: random_master_key(ea, &mut RandomSupply::system())?,
            };
            write_header_region(&file, backup_offset, &header, password, pim, &salt)?;
            write_fake_hidden_region(
                &file,
                backup_offset + HIDDEN_SLOT_OFFSET,
                file_size,
                file_size,
                &create_options,
                &mut RandomSupply::system(),
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
            &mut RandomSupply::system(),
        )?;
        write_header_region(&file, backup_offset, &header, password, pim, &backup_salt)?;
        write_fake_hidden_region(
            &file,
            backup_offset + HIDDEN_SLOT_OFFSET,
            file_size,
            file_size,
            &create_options,
            &mut RandomSupply::system(),
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
            preserve_timestamps: false,
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
/// Overwrite `len` bytes at `offset` with zeros.
fn zero_region(file: &File, offset: u64, len: u64) -> Result<()> {
    const CHUNK: usize = 1024 * 1024;
    let buf = vec![0u8; CHUNK];
    let mut written = 0u64;
    while written < len {
        let n = std::cmp::min(CHUNK as u64, len - written) as usize;
        write_all_at(file, offset + written, &buf[..n])?;
        written += n as u64;
    }
    Ok(())
}

/// How far an in-place decryption run got. `finished` means the file is a
/// plaintext image again; otherwise the volume is a partially decrypted
/// container and another run with `resume = true` continues it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecryptOutcome {
    /// Bytes decrypted by this run.
    pub decrypted: u64,
    /// Size of the volume's data area (all of which ends up decrypted).
    pub data_size: u64,
    /// Whether the whole data area is plaintext again.
    pub finished: bool,
}

/// Undo [`encrypt_in_place`]: turn a completed in-place volume back into the
/// plaintext image it was made from (the filesystem followed by
/// `VOLUME_HEADER_GROUP_SIZE` zero bytes), the way VeraCrypt's "Permanently
/// decrypt a non-system partition/volume" undoes in-place encryption
/// (`DecryptPartitionInPlace`, `src/Format/InPlace.c`).
///
/// The work runs from the *bottom* of the ciphertext upwards -- VeraCrypt moves
/// `EncryptedAreaStart` up and `EncryptedAreaLength` down while decrypting, so a
/// container left half decrypted carries exactly the pair of values a resumed run
/// needs -- reading each chunk before writing the plaintext
/// `VOLUME_HEADER_GROUP_SIZE` bytes below it. The first chunk overwrites the
/// primary header group, so only the backup header is live during the run; at the
/// end everything from the data area's end to the end of the file (that header and
/// the leftover ciphertext) is zeroed and the file is truncated to the image size.
///
/// A half *encrypted* and a half *decrypted* container are indistinguishable from
/// their header fields alone (VeraCrypt has the same problem and resolves it with
/// the command line switch: `/zinplace` resumes encryption, `/resumeinplacedec`
/// decryption), so a run that does not start from a complete in-place volume has to
/// be asked for with `resume = true`.
///
/// When `stop_after` is `Some(n)` the run stops once `n` bytes have been decrypted
/// in this call, which leaves the container in the partially decrypted state.
pub fn decrypt_in_place_stopping_after(
    path: &Path,
    password: &[u8],
    pim: i32,
    resume: bool,
    stop_after: Option<u64>,
) -> Result<DecryptOutcome> {
    let volume = Volume::open(
        path,
        &OpenOptions {
            password: password.to_vec(),
            keyfiles: Vec::new(),
            pim,
            prf: None,
            ea: None,
            volume_type: Some(VolumeType::Normal),
            // A resumed run has already overwritten the primary header group.
            use_backup_header: true,
            preserve_timestamps: false,
        },
    )?;
    if volume.header.flags & HEADER_FLAG_NONSYS_INPLACE_ENC == 0 {
        return Err(Error::Unsupported(format!(
            "{} was not encrypted in place (its header has no in-place encryption flag), so there \
             is nothing to decrypt",
            path.display()
        )));
    }
    let mut header = volume.header.clone();
    let data_size = header.volume_data_size;
    let mut start = header.encrypted_area_start;
    let mut remaining = header.encrypted_area_length;
    let image_size = data_size + VOLUME_HEADER_GROUP_SIZE;
    if remaining > data_size || start < VOLUME_HEADER_GROUP_SIZE || start + remaining != image_size {
        return Err(Error::InvalidParameter(format!(
            "{} reports an inconsistent in-place encrypted area (start {start}, length {remaining}, \
             data area {data_size})",
            path.display()
        )));
    }
    if !(start == VOLUME_HEADER_GROUP_SIZE && remaining == data_size) && !resume {
        return Err(Error::Unsupported(format!(
            "{} holds an unfinished in-place transformation ({remaining} of {data_size} bytes left \
             in the encrypted area); only a completed in-place volume can be decrypted from scratch, \
             and continuing an interrupted decryption has to be asked for explicitly",
            path.display()
        )));
    }

    let file = &volume.file;
    let xts = &volume.xts;
    let file_size = volume.host_size;
    let backup_offset = backup_offset_of(file_size, VolumeLayout::V2Normal)?;
    let mut backup_salt = vec![0u8; HEADER_SALT_SIZE];
    read_exact_at(file, backup_offset, &mut backup_salt)?;

    let mut processed = 0u64;
    let mut since_update = 0u64;
    while remaining > 0 {
        let mut chunk = std::cmp::min(remaining, IN_PLACE_CHUNK_SIZE);
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
        // The ciphertext still sits where the plaintext will have been moved to,
        // so the XTS data unit number comes from the source offset -- the same
        // numbering the encryption used, since it keyed on its destination.
        let mut buf = vec![0u8; chunk as usize];
        read_exact_at(file, start, &mut buf)?;
        xts.decrypt(&mut buf, start / DATA_UNIT_SIZE as u64)?;
        write_all_at(file, start - VOLUME_HEADER_GROUP_SIZE, &buf)?;

        start += chunk;
        remaining -= chunk;
        processed += chunk;
        since_update += chunk;
        header.encrypted_area_start = start;
        header.encrypted_area_length = remaining;

        if since_update >= IN_PLACE_HEADER_UPDATE_INTERVAL || remaining == 0 {
            // VeraCrypt's FastVolumeHeaderUpdate: same salt and key, new lengths.
            write_header_region(file, backup_offset, &header, password, pim, &backup_salt)?;
            file.sync_all()?;
            since_update = 0;
            log::info!(
                "in-place decryption of {}: {} bytes left ({:.1}%)",
                path.display(),
                remaining,
                (data_size - remaining) as f64 * 100.0 / data_size as f64
            );
        }
    }

    let finished = remaining == 0;
    if !finished && since_update > 0 {
        write_header_region(file, backup_offset, &header, password, pim, &backup_salt)?;
        file.sync_all()?;
    }
    if finished {
        // VeraCrypt zeroes everything from the end of the data area to the end of
        // the volume (the backup header and the remaining ciphertext). For a file
        // that is also where the image ends, so the plaintext image is exactly what
        // the container was made from.
        zero_region(file, data_size, file_size - data_size)?;
        file.set_len(image_size)?;
        file.sync_all()?;
        log::info!(
            "in-place decryption of {} finished: the file is a {image_size} byte plaintext image \
             again",
            path.display()
        );
    } else {
        log::info!(
            "in-place decryption of {} paused: {remaining} of {data_size} bytes left to decrypt",
            path.display()
        );
    }
    Ok(DecryptOutcome {
        decrypted: processed,
        data_size,
        finished,
    })
}

/// [`decrypt_in_place_stopping_after`] with no early stop and no resume.
pub fn decrypt_in_place(path: &Path, password: &[u8], pim: i32) -> Result<DecryptOutcome> {
    decrypt_in_place_stopping_after(path, password, pim, false, None)
}

/// Options for transforming a *partition* in place, i.e. VeraCrypt's non-system
/// in-place encryption of a mounted NTFS volume (`src/Format/InPlace.c`).
#[derive(Clone, Debug)]
pub struct DeviceInPlaceOptions {
    pub password: Vec<u8>,
    pub keyfiles: Vec<PathBuf>,
    pub pim: i32,
    /// The algorithm the volume is encrypted with (encryption only: decryption
    /// reads it from the header).
    pub ea: EncryptionAlgorithm,
    /// The header hash (encryption only: decryption reads it from the header).
    pub prf: Prf,
    /// See [`CreateOptions::random_source`].
    pub random_source: Option<PathBuf>,
}

impl DeviceInPlaceOptions {
    /// The password bytes the KDF sees, i.e. with the keyfile pool mixed in.
    pub fn effective_password(&self, device: Option<&Path>) -> Result<Vec<u8>> {
        apply_keyfiles(&self.password, &self.keyfiles, device)
    }

    fn random_supply(&self) -> Result<RandomSupply> {
        match &self.random_source {
            None => Ok(RandomSupply::system()),
            Some(path) => RandomSupply::from_file(path),
        }
    }
}

/// What a run over a partition did. The device keeps its size, so there is no
/// new host size to report -- only how far the transformation got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInPlaceOutcome {
    /// Bytes transformed by this call.
    pub transformed: u64,
    /// Bytes the whole transformation covers.
    pub total: u64,
    /// The extent of the filesystem once the run finishes.
    pub data_size: u64,
    /// The size of the device, which never changes.
    pub device_size: u64,
    /// Whether the transformation is complete.
    pub finished: bool,
}

impl DeviceInPlaceOutcome {
    pub fn progress(&self) -> f32 {
        if self.total == 0 {
            1.0
        } else {
            self.transformed as f32 / self.total as f32
        }
    }
}

/// The header a partition carries while it is being transformed, if the
/// password opens it. This has to try every header hash and algorithm: on a
/// resumed run the volume's own header is the only record of what they are.
fn open_in_place_header(
    region: &[u8],
    password: &[u8],
    pim: i32,
    preferred_prf: Prf,
) -> Option<VolumeHeader> {
    let prfs = std::iter::once(preferred_prf)
        .chain(Prf::ALL.into_iter().filter(|prf| *prf != preferred_prf));
    for prf in prfs {
        let mut header_key = vec![0u8; HEADER_KEY_SIZE];
        if prf
            .derive(password, &region[..HEADER_SALT_SIZE], pim, &mut header_key)
            .is_err()
        {
            continue;
        }
        for ea in EncryptionAlgorithm::ALL {
            if !VolumeHeader::region_has_magic(region, &header_key, ea).unwrap_or(false) {
                continue;
            }
            if let Ok(header) = VolumeHeader::decrypt(region, &header_key, ea, prf) {
                return Some(header);
            }
        }
    }
    None
}

/// Encrypt a partition in place: shrink the NTFS filesystem so that the header
/// areas fit behind it, conceal its boot sector and then move the whole
/// filesystem `VOLUME_HEADER_GROUP_SIZE` bytes towards the end of the device
/// while encrypting it. This is VeraCrypt's non-system in-place encryption
/// (`src/Format/InPlace.c`); the device keeps its size, and the resulting volume
/// is an ordinary VeraCrypt volume on a partition (VeraCrypt can mount it).
///
/// The volume cannot be mounted while it is half transformed: the data area does
/// not look like a filesystem any more and the primary header group, which is
/// part of the filesystem's own head, has not been written yet. The backup
/// header at the end of the device records how far the run got, so an
/// interrupted run can be continued; it is also the only header VeraCrypt can
/// use to resume its own runs.
///
/// `stop_after` stops the run early on purpose (used by the tests).
pub fn encrypt_device_in_place(
    device: &crate::device::Device,
    options: &DeviceInPlaceOptions,
    stop_after: Option<u64>,
) -> Result<DeviceInPlaceOutcome> {
    let info = device.info().clone();
    if let Some(reason) = info.blocker() {
        return Err(Error::Unsupported(reason));
    }
    validate_sector_size(info.sector_size)?;
    // Raw access has to be granted before anything is read or written: the NTFS
    // driver guards the sectors past the filesystem's end (where the backup
    // header goes), and it refuses those without this ioctl. A resume runs
    // against a volume whose filesystem our own lock/dismount released, so a
    // refusal here is reported and then judged by the first tail write.
    if let Err(e) = device.allow_extended_dasd_io() {
        log::warn!("continuing without raw access to {}: {e}", info.path.display());
    }
    let device_size = info.size;
    let data_size = info.data_area_size();
    let file = device.file();
    let password = options.effective_password(Some(&info.path))?;
    let mut random = options.random_supply()?;

    let backup_offset = device_size - VOLUME_HEADER_GROUP_SIZE;
    let mut region = vec![0u8; VOLUME_HEADER_SIZE as usize];
    read_exact_at(file, backup_offset, &mut region)
        .map_err(|e| device_io_error("reading the backup header", backup_offset, e))?;
    let existing = open_in_place_header(&region, &password, options.pim, options.prf);

    let (mut header, backup_salt, mut start, mut done, initial_done, fresh) = match existing {
        Some(header) if header.is_non_system_inplace_enc() => {
            // A run of ours that stopped half way: continue where it stopped.
            if header.volume_data_size != data_size {
                return Err(Error::InvalidParameter(format!(
                    "{} carries an in-place transformation of a {} byte data area, but the device's geometry wants {} bytes",
                    info.path.display(),
                    header.volume_data_size,
                    data_size
                )));
            }
            if header.encrypted_area_start + header.encrypted_area_length != backup_offset {
                return Err(Error::InvalidParameter(format!(
                    "{} reports an inconsistent in-place encrypted area (start {}, length {}, data area {})",
                    info.path.display(),
                    header.encrypted_area_start,
                    header.encrypted_area_length,
                    data_size
                )));
            }
            log::info!(
                "resuming the in-place encryption of {} ({} of {} bytes left)",
                info.path.display(),
                data_size - header.encrypted_area_length,
                data_size
            );
            let salt = region[..HEADER_SALT_SIZE].to_vec();
            let done = header.encrypted_area_length;
            let start = header.encrypted_area_start;
            (header, salt, start, done, done, false)
        }
        Some(_) => {
            return Err(Error::Unsupported(format!(
                "{} already holds a completed VeraCrypt volume; there is nothing to encrypt in place",
                info.path.display()
            )))
        }
        None => {
            // Make room for the two header groups: the filesystem has to give up
            // everything from the data area's end on (VeraCrypt shrinks it to
            // exactly that size, and NTFS is the only filesystem Windows can
            // shrink in place). The target comes from the filesystem's own size:
            // NTFS keeps the device's last sector for itself.
            let shrunk_to = device.shrink_ntfs_for_in_place()?;
            log::info!(
                "shrunk the filesystem of {} to {shrunk_to} bytes (the volume data area is {data_size} bytes)",
                info.path.display()
            );
            let salt = random.bytes(HEADER_SALT_SIZE)?;
            let header = VolumeHeader {
                version: VOLUME_HEADER_VERSION,
                required_min_version: TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION,
                volume_type: VolumeType::Normal,
                creation_time: 0,
                modification_time: 0,
                hidden_volume_data_size: 0,
                volume_data_size: data_size,
                // The encrypted area starts at the end of the filesystem and
                // grows towards the front, so `EncryptedAreaStart` starts out as
                // the *boundary* between the plaintext and the ciphertext, not
                // as the start of the data area (VeraCrypt's convention: the sum
                // of start and length stays at the data area's end).
                encrypted_area_start: backup_offset,
                encrypted_area_length: 0,
                flags: HEADER_FLAG_NONSYS_INPLACE_ENC,
                sector_size: info.sector_size,
                ea: options.ea,
                prf: options.prf,
                salt: salt.clone(),
                master_key: random_master_key(options.ea, &mut random)?,
            };
            (header, salt, backup_offset, 0, 0, true)
        }
    };

    let fake_options = CreateOptions {
        ea: header.ea,
        prf: header.prf,
        password: Vec::new(),
        keyfiles: Vec::new(),
        pim: 0,
        sector_size: info.sector_size,
        full_format: false,
        sparse: false,
        random_source: None,
    };

    // Nothing else may touch the device from here on: a filesystem driver
    // writing into the data area while it is being moved would destroy it. The
    // lock comes *before* the first write into the sectors the filesystem used
    // to own, because the NTFS driver refuses raw writes past the end of a
    // mounted filesystem (VeraCrypt dismounts here too, right after the shrink).
    device.lock_and_dismount()?;
    if fresh {
        // The backup header group is the only live one during the run.
        write_header_region(file, backup_offset, &header, &password, options.pim, &backup_salt)
            .map_err(|e| Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("writing the new volume's backup header at offset {backup_offset}: {e}"),
            )))?;
        write_fake_hidden_region(
            file,
            backup_offset + VOLUME_HEADER_SIZE,
            device_size,
            data_size,
            &fake_options,
            &mut random,
        )
        .map_err(|e| Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "writing the fake hidden header at offset {}: {e}",
                backup_offset + VOLUME_HEADER_SIZE
            ),
        )))?;
        file.sync_all().map_err(Error::Io)?;
    }

    // Nothing else may touch the device from here on: a filesystem driver
    // writing into the data area while it is being moved would destroy it.
    if fresh {
        // Make the filesystem look broken to Windows for the duration of the run
        // (VeraCrypt's `ConcealNTFS`): the boot sector is XORed with 0xFF, and
        // the chunk that moves it encrypts the real bytes.
        device.conceal(true)?;
        file.sync_all().map_err(Error::Io)?;
    }

    let xts = Xts::new(header.ea, header.data_key())?;
    let total = data_size;
    let mut last_update = done;
    while done < total {
        let mut chunk = (total - done).min(IN_PLACE_CHUNK_SIZE);
        if let Some(limit) = stop_after {
            if done >= limit {
                break;
            }
            chunk = chunk.min(limit - done);
        }
        let dest = start - chunk;
        let source = dest - VOLUME_HEADER_GROUP_SIZE;
        let mut buffer = vec![0u8; chunk as usize];
        read_exact_at(file, source, &mut buffer)
            .map_err(|e| device_io_error("reading the device", source, e))?;
        if source < crate::device::CONCEAL_PORTION_SIZE as u64 {
            // This chunk holds the concealed boot sector; put the real bytes
            // back before encrypting them.
            let undo = (crate::device::CONCEAL_PORTION_SIZE as u64 - source).min(chunk) as usize;
            for byte in &mut buffer[..undo] {
                *byte ^= crate::device::CONCEAL_CONSTANT;
            }
        }
        xts.encrypt(&mut buffer, dest / DATA_UNIT_SIZE as u64)?;
        write_all_at(file, dest, &buffer)
            .map_err(|e| device_io_error("writing the device", dest, e))?;
        start = dest;
        done += chunk;
        if done - last_update >= IN_PLACE_HEADER_UPDATE_INTERVAL || done == total {
            // VeraCrypt's FastVolumeHeaderUpdate: the same salt and key, so the
            // run can be resumed from the backup header at any point.
            header.encrypted_area_start = start;
            header.encrypted_area_length = done;
            write_header_region(file, backup_offset, &header, &password, options.pim, &backup_salt)?;
            file.sync_all().map_err(Error::Io)?;
            last_update = done;
        }
    }

    let finished = done >= total;
    if finished {
        // The primary header group is written last; until then the data area
        // holds a filesystem head that Windows would try to mount. The in-place
        // flag stays set, exactly as in VeraCrypt: it marks a volume whose
        // header areas are carved out of the filesystem (and which can therefore
        // be decrypted in place again).
        header.encrypted_area_start = VOLUME_HEADER_GROUP_SIZE;
        header.encrypted_area_length = total;
        let primary_salt = random.bytes(HEADER_SALT_SIZE)?;
        write_header_region(file, 0, &header, &password, options.pim, &primary_salt)?;
        write_fake_hidden_region(
            file,
            HIDDEN_SLOT_OFFSET,
            device_size,
            data_size,
            &fake_options,
            &mut random,
        )?;
        write_header_region(file, backup_offset, &header, &password, options.pim, &backup_salt)?;
        write_fake_hidden_region(
            file,
            backup_offset + VOLUME_HEADER_SIZE,
            device_size,
            data_size,
            &fake_options,
            &mut random,
        )?;
        file.sync_all().map_err(Error::Io)?;
        log::info!(
            "encrypted {} in place ({} byte data area, backup header at {})",
            info.path.display(),
            total,
            backup_offset
        );
    } else {
        log::info!(
            "paused after {} of {} bytes; resume with the same command",
            done,
            total
        );
    }

    Ok(DeviceInPlaceOutcome {
        transformed: done - initial_done,
        total,
        data_size,
        device_size,
        finished,
    })
}

/// Decrypt a partition that was encrypted in place back to a plain filesystem
/// (VeraCrypt's `DecryptPartitionInPlace`, the mirror image of
/// [`encrypt_device_in_place`]). The filesystem is moved back down, the header
/// areas at both ends (and the leftover ciphertext) are zeroed, and the device
/// keeps its size.
///
/// A half encrypted and a half decrypted partition have identical header fields,
/// so continuing an interrupted decryption has to be asked for with `resume`.
pub fn decrypt_device_in_place(
    device: &crate::device::Device,
    options: &DeviceInPlaceOptions,
    resume: bool,
    stop_after: Option<u64>,
) -> Result<DeviceInPlaceOutcome> {
    let info = device.info().clone();
    validate_sector_size(info.sector_size)?;
    let device_size = info.size;
    let file = device.file();
    let password = options.effective_password(Some(&info.path))?;

    let backup_offset = device_size - VOLUME_HEADER_GROUP_SIZE;
    let mut region = vec![0u8; VOLUME_HEADER_SIZE as usize];
    read_exact_at(file, backup_offset, &mut region).map_err(Error::Io)?;
    let mut header = open_in_place_header(&region, &password, options.pim, options.prf).ok_or(
        Error::PasswordIncorrect,
    )?;
    if !header.is_non_system_inplace_enc() {
        return Err(Error::Unsupported(format!(
            "{} holds a VeraCrypt volume that was not encrypted in place, so there is nothing to decrypt in place",
            info.path.display()
        )));
    }

    let total = header.volume_data_size;
    let backup_salt = region[..HEADER_SALT_SIZE].to_vec();
    let complete = header.encrypted_area_start == VOLUME_HEADER_GROUP_SIZE
        && header.encrypted_area_length == total;
    if !complete && !resume {
        return Err(Error::Unsupported(format!(
            "{} holds an unfinished in-place transformation ({} of {} bytes are still ciphertext); only a completed in-place volume can be decrypted from scratch, and continuing an interrupted decryption has to be asked for explicitly",
            info.path.display(),
            header.encrypted_area_length,
            total
        )));
    }

    let mut start = header.encrypted_area_start;
    let mut done = header.encrypted_area_length;
    let initial_done = done;

    device.lock_and_dismount()?;

    let xts = Xts::new(header.ea, header.data_key())?;
    let mut last_update = done;
    while done > 0 {
        let mut chunk = done.min(IN_PLACE_CHUNK_SIZE);
        if let Some(limit) = stop_after {
            if done <= limit {
                break;
            }
            chunk = chunk.min(done - limit);
        }
        let mut buffer = vec![0u8; chunk as usize];
        read_exact_at(file, start, &mut buffer).map_err(Error::Io)?;
        xts.decrypt(&mut buffer, start / DATA_UNIT_SIZE as u64)?;
        write_all_at(file, start - VOLUME_HEADER_GROUP_SIZE, &buffer).map_err(Error::Io)?;
        start += chunk;
        done -= chunk;
        if last_update - done >= IN_PLACE_HEADER_UPDATE_INTERVAL || done == 0 {
            header.encrypted_area_start = start;
            header.encrypted_area_length = done;
            write_header_region(file, backup_offset, &header, &password, options.pim, &backup_salt)?;
            file.sync_all().map_err(Error::Io)?;
            last_update = done;
        }
    }

    let finished = done == 0;
    if finished {
        // The filesystem is back at the front of the device; wipe everything
        // from its end to the last sector of the device (the backup header and
        // the ciphertext that is left over). VeraCrypt zeroes the same range;
        // unlike a container, a partition is never truncated.
        zero_region(file, total, device_size - info.sector_size as u64 - total)?;
        file.sync_all().map_err(Error::Io)?;
        log::info!(
            "decrypted {} in place ({} byte filesystem, the device keeps its {} bytes)",
            info.path.display(),
            total,
            device_size
        );
    } else {
        log::info!(
            "paused after {} of {} bytes; resume with the same command",
            initial_done - done,
            initial_done
        );
    }

    Ok(DeviceInPlaceOutcome {
        transformed: initial_done - done,
        total,
        data_size: total,
        device_size,
        finished,
    })
}

/// Wraps a device I/O failure with the offset that failed, so that a refused
/// raw access is not just "access denied" in the output.
fn device_io_error(action: &str, offset: u64, error: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(
        error.kind(),
        format!("{action} at offset {offset}: {error}"),
    ))
}

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

/// The random supply a creation run draws from: the operating system's
/// generator, or the file named by [`CreateOptions::random_source`].
fn random_supply(options: &CreateOptions) -> Result<RandomSupply> {
    let Some(path) = options.random_source.as_deref() else {
        return Ok(RandomSupply::system());
    };
    log::warn!(
        "reading the volume's random bytes from {}: this container's key material is reproducible \
         from that file, so it is only safe for tests and audits",
        path.display()
    );
    RandomSupply::from_file(path)
}

fn random_master_key(ea: EncryptionAlgorithm, random: &mut RandomSupply) -> Result<Vec<u8>> {
    let key_size = ea.key_size();
    loop {
        let key = random.bytes(key_size * 2)?;
        if key[..key_size] != key[key_size..] {
            return Ok(key);
        }
        log::warn!("generated an XTS key whose halves are equal; retrying");
    }
}

/// Windows `FILE_BASIC_INFO`, i.e. what `FileBasicInfo` returns: four
/// `FILETIME` values (100 ns since 1601) and the file attributes.
#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileBasicInfo {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
}

/// `FILE_INFO_BY_HANDLE_CLASS::FileBasicInfo`.
#[cfg(windows)]
const FILE_BASIC_INFO_CLASS: u32 = 0;

#[cfg(windows)]
mod file_info_ffi {
    use super::FileTime;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetFileInformationByHandleEx(
            handle: *mut core::ffi::c_void,
            class: u32,
            info: *mut core::ffi::c_void,
            size: u32,
        ) -> i32;

        pub fn SetFileInformationByHandle(
            handle: *mut core::ffi::c_void,
            class: u32,
            info: *mut core::ffi::c_void,
            size: u32,
        ) -> i32;

        pub fn SetFileTime(
            handle: *mut core::ffi::c_void,
            creation_time: *const FileTime,
            last_access_time: *const FileTime,
            last_write_time: *const FileTime,
        ) -> i32;
    }
}

/// A Win32 `FILETIME` (two halves of a 100 ns count since 1601).
#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileTime {
    low: u32,
    high: u32,
}

#[cfg(windows)]
impl FileTime {
    /// The timestamp `-1`, which Win32 reads as "the filesystem should not
    /// update this one" (VeraCrypt passes it for the access time in
    /// `src/Common/Dlgcode.c:12241`).
    const DONT_UPDATE: FileTime = FileTime {
        low: 0xFFFF_FFFF,
        high: 0xFFFF_FFFF,
    };
}

/// Tell the filesystem not to bump the last access time while this handle is
/// open.
///
/// Restoring the saved timestamps is not enough on its own: Windows (with
/// "last access time updates" enabled, which is the default) queues the access
/// to the file object and writes it when the handle is **closed**, i.e. after
/// the restore has already happened.
#[cfg(windows)]
fn freeze_access_time(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;

    let ok = unsafe {
        file_info_ffi::SetFileTime(
            file.as_raw_handle() as *mut core::ffi::c_void,
            std::ptr::null(),
            &FileTime::DONT_UPDATE,
            std::ptr::null(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

/// Read the container's four `FILETIME` values.
#[cfg(windows)]
fn query_file_basic_info(file: &File) -> Result<[i64; 4]> {
    let info = query_file_basic(file)?;
    Ok([
        info.creation_time,
        info.last_access_time,
        info.last_write_time,
        info.change_time,
    ])
}

#[cfg(windows)]
fn query_file_basic(file: &File) -> Result<FileBasicInfo> {
    use std::os::windows::io::AsRawHandle;

    let mut info = FileBasicInfo::default();
    let size = std::mem::size_of::<FileBasicInfo>() as u32;
    let ok = unsafe {
        file_info_ffi::GetFileInformationByHandleEx(
            file.as_raw_handle() as *mut core::ffi::c_void,
            FILE_BASIC_INFO_CLASS,
            &mut info as *mut FileBasicInfo as *mut core::ffi::c_void,
            size,
        )
    };
    if ok == 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(info)
}

/// Write the container's four `FILETIME` values, leaving the attributes as they
/// are (this is what VeraCrypt's driver does: query, overwrite the times, set).
#[cfg(windows)]
fn set_file_basic_info(file: &File, times: [i64; 4]) -> Result<()> {
    use std::os::windows::io::AsRawHandle;

    let mut info = query_file_basic(file)?;
    info.creation_time = times[0];
    info.last_access_time = times[1];
    info.last_write_time = times[2];
    info.change_time = times[3];

    let size = std::mem::size_of::<FileBasicInfo>() as u32;
    let ok = unsafe {
        file_info_ffi::SetFileInformationByHandle(
            file.as_raw_handle() as *mut core::ffi::c_void,
            FILE_BASIC_INFO_CLASS,
            &mut info as *mut FileBasicInfo as *mut core::ffi::c_void,
            size,
        )
    };
    if ok == 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Mark an open host file as sparse (Windows `FSCTL_SET_SPARSE`), so that the
/// parts of a quick-formatted container that are never written do not occupy
/// disk space. Unix filesystems do that by themselves, so it is a no-op there.
#[cfg(windows)]
fn set_sparse(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;

    /// `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)`.
    const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;

    #[link(name = "kernel32")]
    extern "system" {
        fn DeviceIoControl(
            handle: *mut core::ffi::c_void,
            code: u32,
            in_buffer: *mut core::ffi::c_void,
            in_size: u32,
            out_buffer: *mut core::ffi::c_void,
            out_size: u32,
            returned: *mut u32,
            overlapped: *mut core::ffi::c_void,
        ) -> i32;
    }

    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as *mut core::ffi::c_void,
            FSCTL_SET_SPARSE,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_sparse(_file: &File) -> Result<()> {
    // Unix filesystems allocate blocks when they are written, so a file created
    // with `set_len` is already sparse.
    Ok(())
}

/// Fill a buffer with cryptographically strong random bytes from the system
/// random generator (used for salts, master keys and keyfiles).
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
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

/// Save `file`'s timestamps and ask the filesystem to stop updating them.
///
/// This is VeraCrypt's "Preserve modification timestamp of file containers" (on
/// by default there). On Windows it uses the `FILETIME` sentinel the driver uses
/// (`src/Driver/Ntvol.c`: the timestamps are set to `-1`, which tells the
/// filesystem not to update them, after saving the original values); elsewhere
/// the values are only saved for the caller to restore.
///
/// Must run **before** the file is read for the first time: the filesystem
/// records the access on the first read, and nothing can take that back
/// afterwards (see [`OpenOptions::preserve_timestamps`]).
fn freeze_file_timestamps(file: &File) -> Result<Option<FileTimestamps>> {
    let metadata = file.metadata()?;
    let timestamps = FileTimestamps {
        last_access: metadata.accessed().unwrap_or(std::time::UNIX_EPOCH),
        last_write: metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
        #[cfg(windows)]
        raw: query_file_basic_info(file)?,
    };

    #[cfg(windows)]
    {
        // `CreationTime = 0` leaves the creation time alone, `-1` tells the
        // filesystem to stop updating the other three.
        set_file_basic_info(file, [0, -1, -1, -1])?;
        // The access time additionally needs the flag Win32 sets through
        // `SetFileTime`: `FILE_BASIC_INFO` alone does not stop NTFS from
        // recording the reads this process is about to make.
        freeze_access_time(file)?;
    }

    Ok(Some(timestamps))
}

/// Put timestamps saved by [`freeze_file_timestamps`] back.
fn restore_file_timestamps(file: &File, timestamps: FileTimestamps) -> Result<()> {
    #[cfg(windows)]
    {
        set_file_basic_info(file, timestamps.raw)?;
    }

    #[cfg(not(windows))]
    {
        let times = std::fs::FileTimes::new()
            .set_accessed(timestamps.last_access)
            .set_modified(timestamps.last_write);
        file.set_times(times)?;
    }

    Ok(())
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

/// Put back the timestamps frozen for [`OpenOptions::preserve_timestamps`] when
/// the volume is dropped, which is what closes the file handle.
impl Drop for Volume {
    fn drop(&mut self) {
        if let Some(timestamps) = self.timestamps.take() {
            if let Err(e) = restore_file_timestamps(&self.file, timestamps) {
                log::warn!("could not restore the container's timestamp: {e}");
            }
        }
    }
}

/// The whole header area of a container: the primary group (the ordinary
/// header at offset 0, the hidden header at 64 KiB) followed by the backup
/// group (the same two copies at the end of the file) -- 256 KiB.
pub fn read_header_area(path: &Path) -> Result<Vec<u8>> {
    read_region(path, 0, TOTAL_VOLUME_HEADERS_SIZE as usize)
}

/// The primary header group of a container: the ordinary header at offset 0 and
/// the hidden one at 64 KiB -- 128 KiB.
///
/// This is byte for byte what VeraCrypt's "Backup Volume Header" saves to a
/// `.hc` file (`TC_VOLUME_HEADER_GROUP_SIZE`) and what its restore reads back.
pub fn read_header_group(path: &Path) -> Result<Vec<u8>> {
    read_region(path, 0, VOLUME_HEADER_GROUP_SIZE as usize)
}

/// Write a backup copy of a container's header to `out` (VeraCrypt's "Backup
/// Volume Header").
///
/// The file holds the container's primary header group: the ordinary volume
/// header and, at 64 KiB, the hidden volume header -- or, for a container
/// without one, the random bytes that stand in for it. That is the size
/// VeraCrypt's restore insists on, so a file written here can be restored by
/// VeraCrypt, and VeraCrypt's own backups can be restored from here. Together
/// with the password such a copy is enough to open a container whose headers
/// were destroyed -- so whoever has this file needs the password and nothing
/// else.
///
/// Returns the number of bytes written.
pub fn backup_headers(path: &Path, out: &Path) -> Result<u64> {
    let group = read_header_group(path)?;
    std::fs::write(out, &group)?;
    Ok(group.len() as u64)
}

/// Restore a container's header from a backup file (VeraCrypt's "Restore Volume
/// Header").
///
/// The file has to be a 128 KiB header group; VeraCrypt rejects anything else,
/// and so does this. Only the slots belonging to `volume_type` are written, and
/// the backup copy always goes to the *current* end of the container, so
/// restoring an old backup into a container that has grown since then does not
/// scribble over the data area -- and restoring an outer volume's header leaves
/// a hidden volume inside it intact.
///
/// With a password both copies are re-encrypted under a fresh salt, exactly as
/// VeraCrypt's restore does, and the result has to open; if it does not (say
/// the file belongs to a different volume) the previous header is put back and
/// an error is returned, so a wrong file cannot brick a container that was
/// still fine. Without a password the bytes are copied as they are and nothing
/// can be verified. The opened volume is returned so the caller can report what
/// was restored.
pub fn restore_headers(
    path: &Path,
    from: &Path,
    volume_type: VolumeType,
    verify: Option<&OpenOptions>,
) -> Result<Option<Volume>> {
    let group = std::fs::read(from)?;
    if group.len() != VOLUME_HEADER_GROUP_SIZE as usize {
        return Err(Error::InvalidParameter(format!(
            "{} holds {} bytes; a header backup is {VOLUME_HEADER_GROUP_SIZE} bytes",
            from.display(),
            group.len()
        )));
    }
    let region = header_region_in_group(&group, volume_type)?;
    restore_header_region(path, region, volume_type, verify, &from.display().to_string())
}

/// Restore a container's header from the copy embedded in the container itself
/// (the backup header group at the end of the file).
///
/// The primary group is preferred and the embedded copy is used when the
/// primary one does not open with the given password -- which is the case this
/// exists for: a destroyed primary header.
pub fn restore_headers_from_embedded(
    path: &Path,
    volume_type: VolumeType,
    verify: Option<&OpenOptions>,
) -> Result<Option<Volume>> {
    let layout = volume_type.creation_layout();
    let size = layout.header_size() as usize;
    let slot = layout.header_offset();
    let host_size = std::fs::metadata(path)?.len();
    let primary = read_region(path, slot, size)?;
    let embedded = read_region(path, backup_offset_of(host_size, layout)? + slot, size)?;
    let region = match verify {
        // Without a password there is no way to tell which copy is the good one;
        // take the primary one, the same choice a plain copy makes.
        None => primary,
        Some(options) => {
            let password = options.effective_password(Some(path))?;
            if decrypt_header_region(&primary, &password, options, volume_type).is_some() {
                primary
            } else {
                embedded
            }
        }
    };
    restore_header_region(path, &region, volume_type, verify, "the embedded backup header")
}

/// The `volume_type` header of a 128 KiB header group: the ordinary one first,
/// the hidden one second (VeraCrypt reads a hidden layout's header at
/// `GetHeaderSize()` and every other layout's at 0).
fn header_region_in_group(group: &[u8], volume_type: VolumeType) -> Result<&[u8]> {
    let layout = volume_type.creation_layout();
    let offset = layout.header_offset() as usize;
    let size = layout.header_size() as usize;
    group.get(offset..offset + size).ok_or_else(|| {
        Error::InvalidParameter(format!(
            "a header group is {VOLUME_HEADER_GROUP_SIZE} bytes, got {}",
            group.len()
        ))
    })
}

/// Put `region` (a 64 KiB header as stored on disk, salt included) into both
/// slots of `volume_type`, either verbatim (no password: nothing can be
/// re-encrypted or checked) or re-encrypted under fresh salts like VeraCrypt's
/// restore does.
fn restore_header_region(
    path: &Path,
    region: &[u8],
    volume_type: VolumeType,
    verify: Option<&OpenOptions>,
    source: &str,
) -> Result<Option<Volume>> {
    let layout = volume_type.creation_layout();
    let size = layout.header_size() as usize;
    if region.len() != size {
        return Err(Error::InvalidParameter(format!(
            "{source} holds a {} byte header, expected {size}",
            region.len()
        )));
    }
    let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let host_size = file.metadata()?.len();
    let primary = layout.header_offset();
    let backup = backup_offset_of(host_size, layout)?;
    let previous_primary = read_region(path, primary, size)?;
    let previous_backup = read_region(path, backup, size)?;

    let Some(options) = verify else {
        write_all_at(&file, primary, region)?;
        write_all_at(&file, backup, region)?;
        file.sync_all()?;
        log::warn!(
            "restored the {} header from {source} without verifying it (no password was given)",
            volume_type.name()
        );
        return Ok(None);
    };

    let password = options.effective_password(Some(path))?;
    let Some(header) = decrypt_header_region(region, &password, options, volume_type) else {
        return Err(Error::InvalidHeader(format!(
            "the header from {source} does not open with those credentials (it is not a {} volume's \
             header, or it is damaged)",
            volume_type.name()
        )));
    };

    let primary_salt = random_bytes(HEADER_SALT_SIZE)?;
    let backup_salt = random_bytes(HEADER_SALT_SIZE)?;
    write_header_region_verified(&file, primary, &header, &password, options.pim, &primary_salt)?;
    write_header_region_verified(&file, backup, &header, &password, options.pim, &backup_salt)?;
    file.sync_all()?;

    let mut pinned = options.clone();
    pinned.volume_type = Some(volume_type);
    pinned.use_backup_header = false;
    match Volume::open(path, &pinned) {
        Ok(volume) => {
            log::info!(
                "restored the {} header from {source} (data area {} bytes, backup header at \
                 {backup})",
                volume_type.name(),
                volume.data_size
            );
            Ok(Some(volume))
        }
        Err(e) => {
            write_all_at(&file, primary, &previous_primary)?;
            write_all_at(&file, backup, &previous_backup)?;
            file.sync_all()?;
            Err(Error::InvalidHeader(format!(
                "the header from {source} does not open after being restored ({e}); the previous \
                 header is unchanged"
            )))
        }
    }
}

/// Decrypt a header region with the credentials of `options`, trying all the
/// KDFs and algorithms when they are not pinned, and return the header when it
/// is one for `volume_type`.
fn decrypt_header_region(
    region: &[u8],
    password: &[u8],
    options: &OpenOptions,
    volume_type: VolumeType,
) -> Option<VolumeHeader> {
    if region.len() < VOLUME_HEADER_SIZE as usize {
        return None;
    }
    let prfs: Vec<Prf> = match options.prf {
        Some(prf) => vec![prf],
        None => Prf::ALL.to_vec(),
    };
    let eas: Vec<EncryptionAlgorithm> = match options.ea {
        Some(ea) => vec![ea],
        None => EncryptionAlgorithm::ALL.to_vec(),
    };
    for prf in prfs {
        let mut header_key = vec![0u8; HEADER_KEY_SIZE];
        if prf
            .derive(password, &region[..HEADER_SALT_SIZE], options.pim, &mut header_key)
            .is_err()
        {
            continue;
        }
        for ea in &eas {
            if !VolumeHeader::region_has_magic(region, &header_key, *ea).unwrap_or(false) {
                continue;
            }
            if let Ok(header) = VolumeHeader::decrypt(region, &header_key, *ea, prf) {
                if header.volume_type == volume_type {
                    return Some(header);
                }
            }
        }
    }
    None
}

/// How to rebuild a header from a bare master key
/// ([`restore_headers_from_master_key`]).
#[derive(Debug, Clone)]
pub struct RestoreHeaderOptions {
    /// Password for the *new* header, as the KDF sees it: with the keyfile pool
    /// already mixed in, see [`Self::effective_password`].
    pub password: Vec<u8>,
    /// Keyfiles to mix into [`Self::password`].
    pub keyfiles: Vec<PathBuf>,
    /// PIM of the new header.
    pub pim: i32,
    /// The encryption algorithm the master key belongs to.
    ///
    /// The key's length narrows this down but cannot identify it (cascades of
    /// the same length look alike), so the caller has to say which one it is.
    pub ea: EncryptionAlgorithm,
    /// Header key derivation function for the new header.
    pub prf: Prf,
    /// Sector size the volume was created with (512 unless it was changed).
    pub sector_size: u32,
    /// Which header to rebuild.
    pub volume_type: VolumeType,
    /// Size of the volume's data area in bytes: `host_size - 262144` for an
    /// ordinary volume, the hidden volume's data size for a hidden one.
    pub data_size: u64,
}

impl RestoreHeaderOptions {
    /// The password bytes the KDF sees, i.e. with the keyfile pool mixed in.
    pub fn effective_password(&self, volume: Option<&Path>) -> Result<Vec<u8>> {
        apply_keyfiles(&self.password, &self.keyfiles, volume)
    }
}

/// Rebuild a container's header from its master key: VeraCrypt's "Restore
/// Volume Header" for the case where every header copy is gone.
///
/// The master key is what decrypts the data area, and the data area is not
/// touched by this -- only the two header slots of `options.volume_type` are
/// written, so the result is an ordinary container that opens with
/// `options.password`/`pim`/`prf` and still holds all the data. Without the
/// master key the data area itself cannot be recovered, so this is the last
/// resort.
pub fn restore_headers_from_master_key(
    path: &Path,
    master_key: &[u8],
    options: &RestoreHeaderOptions,
) -> Result<Volume> {
    validate_sector_size(options.sector_size)?;
    let layout = options.volume_type.creation_layout();
    let expected_key_len = options.ea.key_size() * 2;
    if master_key.len() != expected_key_len {
        return Err(Error::InvalidParameter(format!(
            "a {} master key is {expected_key_len} bytes, got {}",
            options.ea,
            master_key.len()
        )));
    }
    let unit = DATA_UNIT_SIZE as u64;
    if options.data_size == 0 || options.data_size % unit != 0 {
        return Err(Error::InvalidParameter(format!(
            "the data area size must be a non-zero multiple of {DATA_UNIT_SIZE}, got {}",
            options.data_size
        )));
    }
    let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let host_size = file.metadata()?.len();
    let data_offset = layout.creation_data_offset(host_size, options.data_size)?;
    if data_offset + options.data_size > host_size {
        return Err(Error::InvalidParameter(format!(
            "a {} data area of {} bytes does not fit in a {host_size} byte container",
            layout_var_name(options.volume_type),
            options.data_size
        )));
    }
    if options.volume_type == VolumeType::Normal {
        if let Some(natural) = layout.max_data_size(host_size) {
            if natural != options.data_size {
                log::warn!(
                    "an ordinary volume in a {host_size} byte container normally has a \
                     {natural} byte data area; building a {} byte one as requested",
                    options.data_size
                );
            }
        }
    }

    let header = VolumeHeader {
        version: VOLUME_HEADER_VERSION,
        required_min_version: TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION,
        volume_type: options.volume_type,
        creation_time: 0,
        modification_time: 0,
        hidden_volume_data_size: match options.volume_type {
            VolumeType::Hidden => options.data_size,
            VolumeType::Normal => 0,
        },
        volume_data_size: options.data_size,
        encrypted_area_start: data_offset,
        encrypted_area_length: options.data_size,
        flags: 0,
        sector_size: options.sector_size,
        ea: options.ea,
        prf: options.prf,
        salt: Vec::new(),
        master_key: master_key.to_vec(),
    };
    let password = options.effective_password(Some(path))?;
    let primary_salt = random_bytes(HEADER_SALT_SIZE)?;
    write_header_region_verified(
        &file,
        layout.header_offset(),
        &header,
        &password,
        options.pim,
        &primary_salt,
    )?;
    let backup_salt = random_bytes(HEADER_SALT_SIZE)?;
    write_header_region_verified(
        &file,
        backup_offset_of(host_size, layout)?,
        &header,
        &password,
        options.pim,
        &backup_salt,
    )?;
    // Every container VeraCrypt creates has random bytes in the hidden header
    // slots of a normal volume; rebuild those too when the slots are zeroes
    // (say a bare image that was never a container before).
    if options.volume_type == VolumeType::Normal {
        let fake = CreateOptions {
            ea: options.ea,
            prf: options.prf,
            password: options.password.clone(),
            keyfiles: options.keyfiles.clone(),
            pim: options.pim,
            sector_size: options.sector_size,
            full_format: false,
            sparse: false,
            random_source: None,
        };
        for offset in [HIDDEN_SLOT_OFFSET, host_size - VOLUME_HEADER_SIZE] {
            if region_is_zero(&file, offset, HEADER_SALT_SIZE)? {
                write_fake_hidden_region(
                    &file,
                    offset,
                    host_size,
                    host_size,
                    &fake,
                    &mut RandomSupply::system(),
                )?;
                log::info!("wrote a fake hidden header at offset {offset}");
            }
        }
    }
    file.sync_all()?;

    // Prove the result is a header a user can actually open.
    let volume = Volume::open(
        path,
        &OpenOptions {
            password: options.password.clone(),
            keyfiles: options.keyfiles.clone(),
            pim: options.pim,
            prf: Some(options.prf),
            ea: Some(options.ea),
            volume_type: Some(options.volume_type),
            use_backup_header: false,
            preserve_timestamps: false,
        },
    )?;
    log::info!(
        "rebuilt the {} header of {} from its master key ({}, {} byte data area)",
        layout_var_name(options.volume_type),
        path.display(),
        options.ea,
        options.data_size
    );
    Ok(volume)
}

fn layout_var_name(volume_type: VolumeType) -> &'static str {
    match volume_type {
        VolumeType::Normal => "normal volume's",
        VolumeType::Hidden => "hidden volume's",
    }
}

fn region_is_zero(file: &File, offset: u64, len: usize) -> Result<bool> {
    let mut buf = vec![0u8; len];
    read_exact_at(file, offset, &mut buf)?;
    Ok(buf.iter().all(|b| *b == 0))
}

/// Heuristic: does this container's data area look like it was never written
/// to?
///
/// VeraCrypt's quick format leaves the data area the way the host filesystem
/// reported it (zero bytes on NTFS/ext4), while a full format -- VeraCrypt's
/// default, and vcrs's -- fills it with ciphertext that has nothing to do with
/// zero bytes. A container whose unused space is still zeroes is recognisable
/// as a container, which is why VeraCrypt refuses to put a hidden volume into a
/// quickly formatted outer volume. Sampling the raw *ciphertext* needs no
/// password.
pub fn looks_quick_formatted(path: &Path) -> Result<bool> {
    const SAMPLES: u64 = 64;
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = VOLUME_HEADER_GROUP_SIZE;
    let end = match len.checked_sub(VOLUME_HEADER_GROUP_SIZE) {
        Some(end) => end,
        None => return Ok(false),
    };
    let unit = DATA_UNIT_SIZE as u64;
    if end <= start + unit {
        return Ok(false);
    }
    let span = end - start;
    let mut sector = vec![0u8; DATA_UNIT_SIZE];
    let mut zero = 0u64;
    let mut seen = 0u64;
    for i in 0..SAMPLES {
        let offset = (start + span * i / SAMPLES) & !(unit - 1);
        if offset + unit > end {
            continue;
        }
        read_exact_at(&file, offset, &mut sector)?;
        seen += 1;
        if sector.iter().all(|b| *b == 0) {
            zero += 1;
        }
    }
    Ok(seen > 0 && zero * 2 >= seen)
}

/// Read raw host bytes without decrypting them (diagnostics, tests, CLI).
pub fn read_region(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}
