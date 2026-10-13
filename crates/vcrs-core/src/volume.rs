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
use std::path::Path;

use crate::cipher::EncryptionAlgorithm;
use crate::header::{
    VolumeHeader, VolumeType, HEADER_SALT_SIZE, MAX_SECTOR_SIZE, MIN_SECTOR_SIZE,
    TOTAL_VOLUME_HEADERS_SIZE, TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION, VOLUME_HEADER_SIZE,
    VOLUME_HEADER_VERSION,
};
use crate::layout::{VolumeLayout, HIDDEN_RESERVED_END_AREA};
use crate::prf::{Prf, HEADER_KEY_SIZE};
use crate::xts::{Xts, DATA_UNIT_SIZE};
use crate::{Error, Result};

/// `TC_MIN_FAT_FS_SIZE`: 9 sectors of the largest size.
pub const MIN_FAT_FS_SIZE: u64 = 9 * MAX_SECTOR_SIZE as u64;
/// `TC_MIN_VOLUME_SIZE`.
pub const MIN_VOLUME_SIZE: u64 = TOTAL_VOLUME_HEADERS_SIZE + MIN_FAT_FS_SIZE;
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
            pim: 0,
            sector_size: MIN_SECTOR_SIZE,
            full_format: false,
        }
    }
}

/// How to open a volume.
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub password: Vec<u8>,
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
            &options.password,
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
        write_header_region(&file, backup_offset, &header, &options.password, options.pim, &backup_salt)?;
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
            &options.password,
            options.pim,
            &header.salt,
        )?;
        let backup_offset = backup_offset_of(host_size, layout)?;
        let backup_salt = random_bytes(HEADER_SALT_SIZE)?;
        write_header_region(&file, backup_offset, &header, &options.password, options.pim, &backup_salt)?;

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
                prf.derive(&options.password, &region[..HEADER_SALT_SIZE], options.pim, &mut header_key)?;

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
                            if header.encrypted_area_length == 0
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
        let data_offset = layout.data_offset(&header, host_size);
        let data_size = header.encrypted_area_length;
        Ok(Volume { file, header, layout, host_size, data_offset, data_size, xts })
    }

    /// Read and decrypt raw host bytes. `host_offset` and `buf.len()` must be
    /// multiples of 512, and the range must lie inside the data area.
    pub fn read_at(&self, host_offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check_range(host_offset, buf.len())?;
        read_exact_at(&self.file, host_offset, buf)?;
        self.xts.decrypt(buf, host_offset / DATA_UNIT_SIZE as u64)?;
        Ok(())
    }

    /// Encrypt and write raw host bytes.
    pub fn write_at(&self, host_offset: u64, buf: &[u8]) -> Result<()> {
        self.check_range(host_offset, buf.len())?;
        let mut enc = buf.to_vec();
        self.xts.encrypt(&mut enc, host_offset / DATA_UNIT_SIZE as u64)?;
        write_all_at(&self.file, host_offset, &enc)?;
        Ok(())
    }

    /// Read decrypted volume bytes at `offset` relative to the start of the
    /// volume data area.
    pub fn read_data(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_at(self.data_offset + offset, buf)
    }

    /// Write decrypted volume bytes at `offset` relative to the start of the
    /// volume data area.
    pub fn write_data(&self, offset: u64, buf: &[u8]) -> Result<()> {
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
