//! Present a decrypted volume as a real *block device* over iSCSI.
//!
//! A filesystem framework (Dokany, WinFsp) can only ever present a
//! **filesystem**, so using one meant implementing the filesystem in user mode
//! (we did: FAT via `fatfs`). That covers FAT containers, but not the
//! NTFS/exFAT/ReFS containers a VeraCrypt user is most likely to have -- which
//! is why the mount layer now exposes a block device instead.
//!
//! iSCSI solves that with no kernel driver of our own: this module serves the
//! decrypted sectors over a loopback TCP socket and Windows' built-in Microsoft
//! iSCSI Initiator attaches them as an ordinary disk, so **Windows' own signed
//! NTFS/exFAT drivers** do the filesystem work. Reading *and* writing NTFS, and
//! formatting the volume from Disk Management, come for free.
//!
//! ```text
//!   Windows (ntfs.sys / fastfat.sys)
//!        v
//!   disk.sys + Microsoft iSCSI Initiator (in-box, signed)
//!        v   iSCSI over 127.0.0.1:3260
//!   IscsiServer (iscsi-target crate) -> ScsiVolume (this module)
//!        v
//!   DataArea: Volume::read_data / write_data  (XTS decryption)
//! ```
//!
//! # The partition-table problem, and why it is solved with a synthetic MBR
//!
//! VeraCrypt file containers do not hold a disk image: the filesystem starts at
//! the very first byte of the encrypted data area (VeraCrypt presents a
//! *volume*, not a disk). Windows, however, only mounts a filesystem that sits
//! inside a **partition** of a fixed disk -- an unpartitioned disk is shown as
//! "not initialized" and cannot be mounted or formatted.
//!
//! [`DiskMode::Partitioned`] (the default) bridges the two: the SCSI device
//! reports a disk that is one MiB larger than the data area and serves a
//! **synthetic MBR** at LBA 0 which describes the data area as its single
//! primary partition. The MBR is generated on the fly and *never written to the
//! container*, so:
//!
//! * Windows sees a normal partitioned disk, finds the filesystem inside the
//!   partition (or lets the user format one) and uses its own drivers;
//! * the container keeps the VeraCrypt layout -- a bare filesystem at data
//!   offset 0 -- so real VeraCrypt mounts exactly the same volume;
//! * writes into the synthetic MiB (including a disk signature or partition
//!   table rewrite Windows may attempt) are absorbed in memory, so nothing can
//!   corrupt the container's header groups or shift the filesystem.
//!
//! [`DiskMode::Raw`] exposes the bare data area instead, which is what non
//! Windows initiators (and tests) want.
//!
//! # What the `iscsi-target` crate can and cannot do with the Microsoft initiator
//!
//! Verified against Windows 11 (initiator build 26300) with the target side
//! traced via `RUST_LOG=iscsi_target=debug`:
//!
//! * A **static target** works: `iscsicli AddTarget` + `iscsicli QLoginTarget`
//!   makes Windows perform the full three-PDU login sequence (`Free ->
//!   SecurityNegotiation -> LoginOperationalNegotiation -> FullFeaturePhase`)
//!   and then issue SCSI commands. This is the flow [`mount_iscsi`] documents.
//! * Discovery does **not** work: for `iscsicli QAddTargetPortal` Windows opens a
//!   `SessionType=Discovery` login, which the crate routes to
//!   `handle_discovery_session` -- and that function processes only the *first*
//!   login PDU before waiting for a `SendTargets` text request, so the
//!   initiator's next login PDU is answered with "Unexpected opcode during
//!   discovery: 0x03" and the portal scan fails with "Target Error".
//! * CRC32C digests are half-implemented: the multi-target server negotiates the
//!   initiator's `HeaderDigest`/`DataDigest` offer, but its write path calls the
//!   digest-less `write_pdu`, so an initiator that asks for CRC32C (the crate's
//!   own client does) sees a digest mismatch on the first response. Windows
//!   offers `None` unless the user turns digests on, and `iscsicli AddTarget ...
//!   0 0` keeps them off, which is why the static-target flow is unaffected.
//!
//! Both are upstream bugs, not ours, and they are why `vcrs-mount`'s tests drive
//! [`ScsiVolume`]'s SCSI interface directly instead of talking iSCSI to itself.

use std::{
    fmt, io,
    net::TcpStream,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use iscsi_target::{
    AuthConfig, ChapCredentials, IscsiError, IscsiServer, ScsiBlockDevice, ScsiResult,
};
use vcrs_core::volume::{OpenOptions, ProtectedRange, Volume};

use crate::device::{DataArea, SECTOR_SIZE};
use crate::{Error, Result};

/// The well-known iSCSI port.
pub const ISCSI_PORT: u16 = 3260;

/// Default target name (an IQN is required by the initiator).
pub const DEFAULT_TARGET_NAME: &str = "iqn.2025-12.io.vcrs:volume";

/// The prefix of every name this program generates itself.
pub const IQN_PREFIX: &str = "iqn.2025-12.io.vcrs:";

/// Bytes of randomness in a generated target name (48 bits, 12 hex digits).
pub const RANDOM_IQN_BYTES: usize = 6;

/// Start LBA of the synthetic partition: the conventional 1 MiB alignment, which
/// keeps every filesystem happy (and matches what Windows itself uses).
pub const DEFAULT_PARTITION_START_LBA: u64 = 2048;

/// How long a target keeps serving after the last initiator logged out, before
/// it stops on its own (see [`IscsiMountOptions::idle_timeout`]).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// How the volume's data area is presented to the initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiskMode {
    /// Present a synthetic MBR in front of the data area (default, Windows).
    #[default]
    Partitioned,
    /// Present the bare data area; LBA 0 is the container's first data sector.
    Raw,
}

impl DiskMode {
    /// Parse a `--disk-mode` value.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "partition" | "partitioned" | "mbr" | "disk" => Some(DiskMode::Partitioned),
            "raw" | "superfloppy" | "floppy" => Some(DiskMode::Raw),
            _ => None,
        }
    }

    /// Name as accepted by [`DiskMode::from_name`].
    pub fn name(self) -> &'static str {
        match self {
            DiskMode::Partitioned => "partition",
            DiskMode::Raw => "raw",
        }
    }
}

/// How [`mount_iscsi`] (and [`IscsiMount::start`]) serve the volume.
#[derive(Debug, Clone)]
pub struct IscsiMountOptions {
    /// Address to listen on. Keep it on the loopback interface: the target has
    /// no authentication and serves decrypted data.
    pub bind_addr: String,
    /// IQN of the served target, as typed into `iscsicli`.
    pub target_name: String,
    /// Refuse writes (the initiator sees a write-protected disk).
    pub read_only: bool,
    /// Report the disk as removable media (the INQUIRY RMB bit).
    ///
    /// Windows only offers exFAT in its format dialogs for removable media, so
    /// this is the way to get exFAT into that list. The container on disk is
    /// unaffected: the bit is purely cosmetic to the initiator.
    pub removable: bool,
    /// See [`DiskMode`].
    pub disk_mode: DiskMode,
    /// First LBA of the synthetic partition (1 MiB by default).
    pub partition_start_lba: u64,
    /// Preserve the container's modification timestamp (VeraCrypt's "Preserve
    /// modification timestamp of file containers", which is on by default
    /// there): writing through the mount must not reveal *when* the container
    /// was last used. The host's timestamps are frozen while the target runs and
    /// written back when it stops.
    pub preserve_timestamp: bool,
    /// How long the target keeps serving after the last initiator logged out.
    ///
    /// Windows occasionally logs out and logs back in (a rescan, a reboot, a
    /// driver reload), which is why the target does not stop the moment a
    /// session ends. `Duration::ZERO` keeps it serving until Ctrl-C.
    pub idle_timeout: Duration,
    /// VeraCrypt's *protect hidden volume* option.
    ///
    /// When set, the hidden volume inside this container is opened with these
    /// credentials and its data area becomes a protected range: every write
    /// that would land inside it fails instead of destroying the hidden volume.
    /// VeraCrypt does the same when you mount an outer volume with "protect
    /// hidden volume".
    pub protect_hidden: Option<OpenOptions>,
    /// Ask the initiator for CHAP authentication, with this secret and
    /// [`vcrs_core::CHAP_USER`].
    ///
    /// Require CHAP authentication (the initiator has to prove it knows a
    /// secret before it may log in).
    ///
    /// `false` (the default) serves the target to any initiator that knows the
    /// name, which is how it has always worked; the target is then only as
    /// private as its port and its name, which is why the bind address has to be
    /// on the loopback interface. With this set, a login without the right
    /// credentials is refused.
    ///
    /// The secret is never typed and never crosses a process boundary: both
    /// halves of the mount derive it from the volume's header salt and the
    /// random per-mount target name, see [`vcrs_core::chap_secret`].
    pub chap: bool,
}

impl Default for IscsiMountOptions {
    fn default() -> Self {
        IscsiMountOptions {
            bind_addr: format!("127.0.0.1:{ISCSI_PORT}"),
            target_name: DEFAULT_TARGET_NAME.to_string(),
            read_only: false,
            removable: false,
            disk_mode: DiskMode::default(),
            partition_start_lba: DEFAULT_PARTITION_START_LBA,
            preserve_timestamp: true,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            protect_hidden: None,
            chap: false,
        }
    }
}

impl IscsiMountOptions {
    /// The default options, with a target name that gives nothing away.
    ///
    /// The name used to be derived from the container's file name. An IQN is not
    /// private: it is registered as a *static* target with the Microsoft iSCSI
    /// Initiator (which requires elevation and keeps the list in the registry), it
    /// appears in the initiator's event log, in `iscsicli ListTargets`, in this
    /// program's output and in the `%TEMP%` log the mount leaves behind. A name
    /// taken from the file turned, for example, `divorce-settlement.vc` into
    /// `iqn.2025-12.io.vcrs:divorce-settlement`, written into the machine's
    /// registry where it outlives the container — and a *stable* name also meant
    /// that two mounts of the same container were linkable to each other.
    ///
    /// A name drawn at random per mount keeps the volume identifyable to the
    /// session using it and to nobody else. Nothing is derived from it and it is
    /// not a secret; it is only there to be unlinkable. If the system generator is
    /// unavailable the file name is used as a fallback, because a usable name beats
    /// failing the mount, and the host layer checks the name it is given either way.
    pub fn for_volume(path: &Path) -> Self {
        let mut opts = IscsiMountOptions::default();
        if let Some(name) = random_target_name() {
            opts.target_name = name;
            return opts;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            let sanitised: String = stem
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
                .collect();
            if !sanitised.is_empty() {
                opts.target_name = format!("{IQN_PREFIX}{sanitised}");
            }
        }
        opts
    }
}

/// A fresh `iqn.2025-12.io.vcrs:<48 random bits>` name, or `None` when the
/// system's random generator is not available.
fn random_target_name() -> Option<String> {
    use std::fmt::Write as _;

    let bytes = vcrs_core::random_bytes(RANDOM_IQN_BYTES).ok()?;
    debug_assert_eq!(bytes.len(), RANDOM_IQN_BYTES);
    let mut hex = String::with_capacity(RANDOM_IQN_BYTES * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    Some(format!("{IQN_PREFIX}{hex}"))
}

/// Turns an iSCSI layer failure into a `vcrs-core` error.
fn to_core(err: IscsiError) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::Other, format!("iSCSI: {err}")))
}

/// Turns a device failure into the error the SCSI layer expects. `read`/`write`
/// failures are reported to the initiator as a medium error.
fn dev_err(message: impl fmt::Display) -> IscsiError {
    IscsiError::Scsi(message.to_string())
}

/// A SCSI block device backed by a volume's decrypted data area.
///
/// All offsets are relative to the **start of the data area**, exactly like
/// [`DataArea`], so the SCSI layer, the FAT filesystem and future backends all
/// share one definition of "sector 0".
pub struct ScsiVolume<A: DataArea = Volume> {
    area: A,
    read_only: bool,
    removable: bool,
    block_size: u32,
    /// Synthetic bytes in front of the data area (`DiskMode::Partitioned`), i.e.
    /// the MBR and the padding up to the first partition. Never persisted.
    prefix: Vec<u8>,
    /// Capacity of the presented disk in blocks of `block_size`.
    capacity: u64,
    /// Whether a write into the synthetic region has been logged already.
    warned_prefix_write: bool,
    /// The CHAP secret this target requires, derived from the volume's header
    /// salt when it was opened (see [`IscsiMountOptions::chap`]).
    chap_secret: Option<String>,
}

impl ScsiVolume<Volume> {
    /// Open `path` and serve it according to `opts`.
    pub fn open(path: &Path, open: &OpenOptions, opts: &IscsiMountOptions) -> Result<Self> {
        // A mounted container must not look as if it had been used. The flag is
        // handed to `Volume::open`, which freezes the timestamps before it reads
        // anything -- doing it afterwards is too late for the access time, which
        // the filesystem has already recorded by then.
        let mut open = open.clone();
        open.preserve_timestamps = opts.preserve_timestamp;
        let volume = Volume::open(path, &open)?;
        if let Some(hidden_open) = &opts.protect_hidden {
            // VeraCrypt refuses to mount with hidden-volume protection unless the
            // hidden volume's own password is right, so failing here (instead of
            // serving the outer volume unprotected) is the safe behaviour.
            let hidden = Volume::open(path, hidden_open).map_err(|e| {
                Error::InvalidParameter(format!(
                    "hidden volume protection: the hidden volume of {} could not be opened \
                     ({e}); refusing to serve the outer volume without protection",
                    path.display()
                ))
            })?;
            let range = ProtectedRange::new(hidden.data_offset, hidden.data_size);
            log::info!(
                "hidden volume protection: writes into the hidden data area at host offsets \
                 {}..{} ({} bytes) will be refused",
                range.start,
                range.end(),
                range.length
            );
            volume.protect_hidden_volume(range);
        }
        // A stable, non-zero disk signature: Windows keeps track of disks by it,
        // and deriving it from the container's header salt means it does not
        // change between sessions (and differs between containers).
        let salt = &volume.header.salt;
        let signature = u32::from_le_bytes([salt[0], salt[1], salt[2], salt[3]]) | 0x8000_0000;
        let mut device = Self::with_signature(volume, opts, signature)?;
        device.chap_secret = chap_secret_for(path, opts)?;
        Ok(device)
    }
}

/// The CHAP secret for this mount, or `None` when CHAP is off.
///
/// Both halves of a mount derive it independently: the target, and the elevated
/// attach half that runs `iscsicli` reads the same 64 bytes from the same path.
/// The input is the salt of the volume's *primary* header region -- plaintext,
/// and at the same offset in every layout -- so neither half has to be told a
/// secret and neither has to know which header the other one opened. (Deriving
/// it from the header *this* side opened would not work for a hidden or
/// `--backup` mount: the salt of those headers sits somewhere else and the other
/// half would have to guess.)
fn chap_secret_for(path: &Path, opts: &IscsiMountOptions) -> Result<Option<String>> {
    if !opts.chap {
        return Ok(None);
    }
    // The field name in a `vcrs` mount is not an IQN, but it still goes into
    // the derivation here: the mount server is what turns it into one.
    vcrs_core::chap_secret_for_file(path, &opts.target_name).map(Some)
}

impl<A: DataArea> ScsiVolume<A> {
    /// Serve an arbitrary data area (used by the tests and by future backends).
    pub fn with_signature(area: A, opts: &IscsiMountOptions, disk_signature: u32) -> Result<Self> {
        let block_size = area.sector_size().max(SECTOR_SIZE as u32);
        if block_size as usize % SECTOR_SIZE != 0 {
            return Err(Error::InvalidParameter(format!(
                "the volume's {block_size}-byte sectors are not a multiple of {SECTOR_SIZE}"
            )));
        }
        let data_len = area.len();
        if data_len % block_size as u64 != 0 {
            return Err(Error::InvalidParameter(format!(
                "the data area ({data_len} bytes) is not a multiple of the {block_size}-byte sector size"
            )));
        }
        let blocks = data_len / block_size as u64;

        let (prefix, capacity) = match opts.disk_mode {
            DiskMode::Raw => (Vec::new(), blocks),
            DiskMode::Partitioned => {
                let start = opts.partition_start_lba.max(1);
                if start > u32::MAX as u64 {
                    return Err(Error::InvalidParameter(
                        "the synthetic partition start must fit in an MBR entry".to_string(),
                    ));
                }
                if blocks > u32::MAX as u64 {
                    return Err(Error::InvalidParameter(format!(
                        "the data area holds {blocks} sectors; MBR partitioning tops out at {}",
                        u32::MAX
                    )));
                }
                // What kind of filesystem is inside? It only decides the MBR
                // partition type byte, which Windows uses as a hint.
                let mut vbr = vec![0u8; block_size.min(512) as usize];
                let fs_type = match area.read_at(0, &mut vbr) {
                    Ok(()) => detect_partition_type(&vbr),
                    Err(_) => partition_type::NTFS,
                };
                // How much of the data area does the filesystem actually use?
                // After `vcrs expand` the filesystem is smaller than the data
                // area, and that is exactly the state in which the user is
                // supposed to grow it from Windows. If the MBR claimed the
                // whole data area, the extra space would live *inside* the
                // partition and Windows' "Extend Volume" would have nothing to
                // grow into, so describe only the filesystem and leave the rest
                // of the disk unallocated.
                let fs_blocks = filesystem_sectors(&vbr, block_size)
                    .unwrap_or(blocks)
                    .clamp(1, blocks);
                if fs_blocks < blocks {
                    log::info!(
                        "the filesystem inside the volume uses {fs_blocks} of the {blocks} sectors                          of the data area; the rest stays unallocated so Windows can extend it"
                    );
                }
                let mut prefix = vec![0u8; (start * block_size as u64) as usize];
                let mbr = build_mbr(fs_type, start, fs_blocks, disk_signature);
                prefix[..mbr.len()].copy_from_slice(&mbr);
                (prefix, start + blocks)
            }
        };

        Ok(ScsiVolume {
            area,
            read_only: opts.read_only,
            removable: opts.removable,
            block_size,
            prefix,
            capacity,
            warned_prefix_write: false,
            chap_secret: None,
        })
    }

    /// Size of the presented disk in bytes.
    pub fn disk_size(&self) -> u64 {
        self.capacity * self.block_size as u64
    }

    /// Length of the encrypted data area in bytes.
    pub fn data_size(&self) -> u64 {
        self.area.len()
    }

    /// First LBA that maps into the container's data area.
    pub fn data_start_lba(&self) -> u64 {
        self.prefix.len() as u64 / self.block_size as u64
    }

    /// Borrow the underlying data area.
    pub fn area(&self) -> &A {
        &self.area
    }

    /// Split `[offset, offset+len)` into the part that lands in the synthetic
    /// prefix and the part that maps into the data area.
    fn split(&self, offset: u64, len: usize) -> (usize, u64, usize) {
        let prefix_len = self.prefix.len() as u64;
        if offset >= prefix_len {
            (0, offset - prefix_len, len)
        } else {
            let in_prefix = (prefix_len - offset).min(len as u64) as usize;
            (in_prefix, 0, len - in_prefix)
        }
    }

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> ScsiResult<()> {
        let (prefix_part, data_offset, data_part) = self.split(offset, buf.len());
        if prefix_part > 0 {
            let begin = offset as usize;
            buf[..prefix_part].copy_from_slice(&self.prefix[begin..begin + prefix_part]);
        }
        if data_part > 0 {
            self.area
                .read_at(data_offset, &mut buf[prefix_part..])
                .map_err(|err| dev_err(format!("reading {data_part} bytes at offset {data_offset}: {err}")))?;
        }
        Ok(())
    }

    fn write_from(&mut self, offset: u64, data: &[u8]) -> ScsiResult<()> {
        let (prefix_part, data_offset, data_part) = self.split(offset, data.len());
        if prefix_part > 0 {
            // The synthetic region must never reach the container: Windows may
            // rewrite the disk signature or "initialize" the disk at any time.
            if !self.warned_prefix_write {
                self.warned_prefix_write = true;
                log::warn!(
                    "ignoring a write to the synthetic partition-table region at disk offset {offset} \
                     (it is generated on the fly and is not part of the container)"
                );
            }
            let begin = offset as usize;
            self.prefix[begin..begin + prefix_part].copy_from_slice(&data[..prefix_part]);
        }
        if data_part > 0 {
            self.area
                .write_at(data_offset, &data[prefix_part..])
                .map_err(|err| dev_err(format!("writing {data_part} bytes at offset {data_offset}: {err}")))?;
        }
        Ok(())
    }
}

impl<A: DataArea + Send + Sync> ScsiBlockDevice for ScsiVolume<A> {
    fn read(&self, lba: u64, blocks: u32, block_size: u32) -> ScsiResult<Vec<u8>> {
        let len = (blocks as usize)
            .checked_mul(block_size as usize)
            .ok_or_else(|| dev_err("block count overflow"))?;
        let offset = lba
            .checked_mul(block_size as u64)
            .ok_or_else(|| dev_err(format!("LBA {lba} overflows")))?;
        let mut buf = vec![0u8; len];
        self.read_into(offset, &mut buf)?;
        Ok(buf)
    }

    fn write(&mut self, lba: u64, data: &[u8], block_size: u32) -> ScsiResult<()> {
        if self.read_only {
            return Err(dev_err("the volume is mounted read-only"));
        }
        let offset = lba
            .checked_mul(block_size as u64)
            .ok_or_else(|| dev_err(format!("LBA {lba} overflows")))?;
        self.write_from(offset, data)
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn removable(&self) -> bool {
        self.removable
    }

    fn flush(&mut self) -> ScsiResult<()> {
        self.area
            .sync()
            .map_err(|err| dev_err(format!("flushing the container: {err}")))
    }

    fn vendor_id(&self) -> &str {
        "vc-rs"
    }

    fn product_id(&self) -> &str {
        "VeraCrypt volume"
    }

    fn product_rev(&self) -> &str {
        "1.0 "
    }
}

impl<A: DataArea + fmt::Debug> fmt::Debug for ScsiVolume<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScsiVolume")
            .field("data_size", &self.data_size())
            .field("disk_size", &self.disk_size())
            .field("block_size", &self.block_size)
            .field("read_only", &self.read_only)
            .field("data_start_lba", &self.data_start_lba())
            .finish()
    }
}

/// Standard MBR partition type bytes we use.
pub mod partition_type {
    /// NTFS / exFAT / anything Windows should recognise on its own.
    pub const NTFS: u8 = 0x07;
    /// FAT32 with LBA addressing.
    pub const FAT32_LBA: u8 = 0x0C;
    /// FAT16 with LBA addressing.
    pub const FAT16_LBA: u8 = 0x0E;
}

/// How many sectors (in `block_size` units) the filesystem inside the data area
/// occupies, read from its volume boot record.
///
/// `None` when the boot sector is not a filesystem we recognise -- a freshly
/// created, still unformatted container decrypts to noise -- or when the
/// filesystem does not say how big it is.
fn filesystem_sectors(vbr: &[u8], block_size: u32) -> Option<u64> {
    if vbr.len() < 512 || vbr[510] != 0x55 || vbr[511] != 0xAA {
        return None;
    }
    let bytes_per_sector = u16::from_le_bytes([vbr[0x0B], vbr[0x0C]]) as u64;
    if bytes_per_sector == 0 {
        return None;
    }
    let be32 = |at: usize| u32::from_le_bytes(vbr[at..at + 4].try_into().unwrap()) as u64;
    let total_sectors = match &vbr[3..11] {
        b"NTFS    " => u64::from_le_bytes(vbr[0x28..0x30].try_into().unwrap()),
        b"EXFAT   " => u64::from_le_bytes(vbr[0x48..0x50].try_into().unwrap()),
        _ if &vbr[0x52..0x5A] == b"FAT32   " => be32(0x20),
        _ if matches!(&vbr[0x36..0x3E], b"FAT16   " | b"FAT12   ") => {
            let small = u16::from_le_bytes([vbr[0x13], vbr[0x14]]) as u64;
            if small != 0 {
                small
            } else {
                be32(0x20)
            }
        }
        _ => return None,
    };
    let bytes = total_sectors.checked_mul(bytes_per_sector)?;
    if bytes == 0 {
        return None;
    }
    Some(bytes.div_ceil(block_size as u64))
}

/// Guess the MBR partition type from a volume boot record.
///
/// The type byte is only a hint -- Windows identifies the filesystem itself --
/// but a FAT volume marked as NTFS makes some tools refuse to mount it, so it is
/// worth reading the boot sector we are already decrypting anyway.
fn detect_partition_type(vbr: &[u8]) -> u8 {
    if vbr.len() < 512 {
        return partition_type::NTFS;
    }
    match &vbr[3..11] {
        b"NTFS    " | b"EXFAT   " => return partition_type::NTFS,
        _ => {}
    }
    if vbr[510] != 0x55 || vbr[511] != 0xAA {
        // Not a boot sector at all (a freshly created, still unformatted
        // quick-formatted volume decrypts to noise).
        return partition_type::NTFS;
    }
    if &vbr[0x52..0x5A] == b"FAT32   " {
        return partition_type::FAT32_LBA;
    }
    match &vbr[0x36..0x3E] {
        b"FAT16   " => partition_type::FAT16_LBA,
        _ => partition_type::NTFS,
    }
}

/// Build the synthetic MBR that makes the data area look like one partition.
fn build_mbr(fs_type: u8, start_lba: u64, sectors: u64, disk_signature: u32) -> Vec<u8> {
    let mut mbr = vec![0u8; SECTOR_SIZE];
    mbr[0x1B8..0x1BC].copy_from_slice(&disk_signature.to_le_bytes());
    let entry = 0x1BE;
    mbr[entry] = 0x00; // not bootable: this is a data partition
    mbr[entry + 1] = 0x20; // start CHS: unused by the OS, but keep it sane
    mbr[entry + 2] = 0x21;
    mbr[entry + 3] = 0x00;
    mbr[entry + 4] = fs_type;
    mbr[entry + 5] = 0xFE; // end CHS: "too large", i.e. use the LBA fields
    mbr[entry + 6] = 0xFF;
    mbr[entry + 7] = 0xFF;
    mbr[entry + 8..entry + 12].copy_from_slice(&(start_lba as u32).to_le_bytes());
    mbr[entry + 12..entry + 16].copy_from_slice(&(sectors as u32).to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    mbr
}

/// A running iSCSI target. Dropping it stops the listener.
pub struct IscsiMount {
    server: Arc<IscsiServer>,
    thread: Option<thread::JoinHandle<()>>,
    addr: String,
    target_name: String,
    read_only: bool,
    idle_timeout: Duration,
}

impl IscsiMount {
    /// Bind and serve `device` in a background thread.
    ///
    /// Served through the crate's *multi-target* server rather than its
    /// single-target one: only the former implements the discovery session
    /// (`SessionType=Discovery`, no `TargetName` in the login request), which is
    /// exactly what the Microsoft initiator opens for `iscsicli
    /// QAddTargetPortal`. The single-target server answers such a login with
    /// "Unsupported opcode 0x03 in full feature phase", the initiator times out
    /// and `QAddTargetPortal` fails with "Target Error".
    pub fn start(device: ScsiVolume, opts: &IscsiMountOptions) -> Result<Self> {
        let builder = IscsiServer::builder().bind_addr(&opts.bind_addr);
        let secret = device.chap_secret.clone();
        let builder = match &secret {
            Some(secret) => builder.add_target_with_auth(
                opts.target_name.clone(),
                Box::new(device),
                Some("vc-rs VeraCrypt volume".to_string()),
                AuthConfig::Chap {
                    credentials: ChapCredentials::new(vcrs_core::CHAP_USER, secret.as_str()),
                },
                None,
            ),
            None => builder.add_target(
                opts.target_name.clone(),
                Box::new(device),
                Some("vc-rs VeraCrypt volume".to_string()),
            ),
        };
        let server = Arc::new(
            builder
                .max_connections(8)
                .build()
                .map_err(to_core)?,
        );
        let running = Arc::clone(&server);
        let thread = thread::spawn(move || {
            if let Err(err) = running.run() {
                log::error!("the iSCSI server stopped: {err}");
            }
        });
        let mount = IscsiMount {
            server,
            thread: Some(thread),
            addr: opts.bind_addr.clone(),
            target_name: opts.target_name.clone(),
            read_only: opts.read_only,
            idle_timeout: opts.idle_timeout,
        };
        mount.wait_until_listening()?;
        log::info!(
            "iSCSI target {} listening on {}{}{}",
            mount.target_name,
            mount.addr,
            if mount.read_only { " (read-only)" } else { "" },
            if secret.is_some() { " (CHAP)" } else { "" }
        );
        Ok(mount)
    }

    /// How long the target keeps serving after the last initiator logged out.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// The address the target listens on.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The IQN an initiator logs into.
    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    /// Number of attached initiator sessions.
    pub fn session_count(&self) -> usize {
        self.server.active_session_count()
    }

    /// Whether the target is still accepting connections.
    pub fn is_running(&self) -> bool {
        self.server.is_running()
    }

    /// Stop accepting connections and shut the listener down.
    pub fn stop(&self) {
        if self.server.is_running() {
            log::info!("stopping the iSCSI target {}", self.target_name);
        }
        // `shutdown_gracefully` only rejects *new* logins; `stop` is the one that
        // makes `IscsiServer::run` leave its accept loop. Without it the serving
        // thread never returns and joining it (in `Drop`) hangs forever.
        self.server.shutdown_gracefully();
        self.server.stop();
    }

    /// Wait until the listener answers, so that a caller that prints
    /// `iscsicli` commands cannot race the socket setup.
    /// Wait until the serving thread has bound the socket *and* is accepting.
    ///
    /// `IscsiServer::run` reports a bind failure only by returning, so a plain
    /// "can I connect?" probe is not enough: if another process (or another
    /// test) already listens on that port, the probe would succeed against
    /// *its* listener while our own serving thread is dead. Checking
    /// `is_running` (set by `run` after a successful bind) tells the two apart.
    fn wait_until_listening(&self) -> Result<()> {
        let started = Instant::now();
        let mut ever_running = false;
        loop {
            if self.server.is_running() {
                ever_running = true;
                if let Ok(stream) = TcpStream::connect(&self.addr) {
                    // The probe connection is not a valid iSCSI session; the
                    // target logs it and drops it.
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return Ok(());
                }
            }
            // A target that never became running failed to bind (or died) —
            // report that quickly instead of waiting for the full timeout.
            let timeout = if ever_running {
                Duration::from_secs(10)
            } else {
                Duration::from_secs(2)
            };
            if started.elapsed() >= timeout {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "the iSCSI target did not come up on {} (is another target already \
                         listening on that port?)",
                        self.addr
                    ),
                )));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Block until the initiator logs out (or Ctrl-C is pressed).
    ///
    /// A logout is not always a dismount (a client may reconnect), so the target
    /// keeps running for a few seconds after the last session disappears before
    /// it gives up, and only when at least one session was seen at all.
    pub fn wait(&self) -> Result<()> {
        let mut seen_session = false;
        let mut idle_since: Option<Instant> = None;
        while self.server.is_running() && !shutdown_requested() {
            let sessions = self.server.active_session_count();
            if sessions > 0 {
                seen_session = true;
                idle_since = None;
            } else if seen_session && !self.idle_timeout.is_zero() {
                let since = *idle_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= self.idle_timeout {
                    log::info!(
                        "the initiator logged out; stopping the target after {} s of idleness",
                        self.idle_timeout.as_secs_f32(),
                    );
                    break;
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
        self.stop();
        Ok(())
    }
}

impl Drop for IscsiMount {
    fn drop(&mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Global "Ctrl-C was pressed" flag, set by the console handler below.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Ask a running [`IscsiMount::wait`] to return (used by the console handler).
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

#[cfg(windows)]
/// Install a Ctrl-C handler that only sets [`SHUTDOWN`], so that the target can
/// close its sessions instead of dying mid-request (which would look like a
/// surprise removal to the initiator).
fn install_ctrl_handler() {
    use std::sync::atomic::AtomicBool as Flag;
    static INSTALLED: Flag = Flag::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe extern "system" fn handler(_ctrl_type: u32) -> i32 {
        SHUTDOWN.store(true, Ordering::SeqCst);
        1 // handled: let the target shut down cleanly
    }
    unsafe {
        winapi::um::consoleapi::SetConsoleCtrlHandler(Some(handler), 1);
    }
}

#[cfg(not(windows))]
fn install_ctrl_handler() {}

/// Serve `volume_path` over iSCSI until the initiator logs out or Ctrl-C.
///
/// Prints the two `iscsicli` commands that attach the volume; both need an
/// elevated prompt (the Microsoft initiator requires administrator rights, just
/// like mounting with VeraCrypt does).
pub fn mount_iscsi(volume_path: &Path, open: &OpenOptions, opts: &IscsiMountOptions) -> Result<()> {
    mount_iscsi_with(volume_path, open, opts, None)
}

/// Serve `volume_path` over iSCSI, calling `on_ready` once the target is
/// listening and before blocking on it.
///
/// The callback is what lets a front-end attach the volume itself
/// (`vcrs mount --letter Y`) instead of printing the two `iscsicli` commands and
/// leaving the user to run them in an elevated prompt: it receives the running
/// [`IscsiMount`] and the size of the disk it presents, and is called on the
/// serving thread before [`IscsiMount::wait`]. When it is present the manual
/// instructions are not printed.  It cannot fail the mount: the target is up by
/// then, so a front-end that cannot attach the volume reports that itself and
/// leaves the process serving.
pub fn mount_iscsi_with(
    volume_path: &Path,
    open: &OpenOptions,
    opts: &IscsiMountOptions,
    on_ready: Option<&dyn Fn(&IscsiMount, u64)>,
) -> Result<()> {
    install_ctrl_handler();
    let device = ScsiVolume::open(volume_path, open, opts)?;
    let disk_size = device.disk_size();
    eprintln!(
        "serving {} ({} bytes of data area, {} byte sectors, {}) as a {} byte disk",
        volume_path.display(),
        device.data_size(),
        device.block_size(),
        if opts.read_only { "read-only" } else { "read/write" },
        device.disk_size(),
    );
    if opts.disk_mode == DiskMode::Partitioned {
        eprintln!(
            "the data area is presented as one partition starting at LBA {} (a synthetic MBR; \
             the container itself keeps its VeraCrypt layout)",
            device.data_start_lba(),
        );
    }
    let mount = IscsiMount::start(device, opts)?;
    eprintln!("iSCSI target ready: {} on {}", mount.target_name(), mount.addr());
    eprintln!();
    match on_ready {
        Some(on_ready) => on_ready(&mount, disk_size),
        None => {
            // The trap this wording exists for: `vcrs mount` without `--letter`
            // serves the volume but does not log the initiator in, so no drive
            // letter appears until something runs the two commands below. Say so
            // before printing them.
            eprintln!("nothing is attached yet, so no drive letter has appeared: this command only");
            eprintln!("serves the volume. `vcrs mount <volume> --letter Y` does the rest of the work");
            eprintln!("(it asks for one elevation prompt); by hand, from an ELEVATED prompt:");
            // The manual recipe has to match how the session was actually
            // started: with CHAP the two credential arguments carry the user
            // and the derived secret (see `vcrs_core::chap_secret`, and
            // `vcrs attach --chap-from <volume>` does this for you), and the
            // authentication type is 1 instead of 0.
            if opts.chap {
                eprintln!(
                    "    iscsicli AddTarget {} vcrs {} {} 0 0 0 0 0 8 0 0 {} <secret> 1 0",
                    mount.target_name(),
                    portal_host(&mount.addr()),
                    portal_port(&mount.addr()),
                    vcrs_core::CHAP_USER,
                );
            } else {
                eprintln!(
                    "    iscsicli AddTarget {} vcrs {} {} 0 0 0 0 0 8 0 0 \"\" \"\" 0 0",
                    mount.target_name(),
                    portal_host(&mount.addr()),
                    portal_port(&mount.addr()),
                );
            }
            eprintln!("    iscsicli QLoginTarget {}", mount.target_name());
            eprintln!();
            eprintln!("(a *static* target is registered because the target crate cannot complete the");
            eprintln!(" initiator's multi-PDU login during a portal *scan*)");
            if opts.chap {
                eprintln!("(this target asks for CHAP: the two arguments before the 1 are the user and");
                eprintln!(" the secret, which is derived from the container's header salt, so a hand-");
                eprintln!(" written command has to use `vcrs attach --chap-from <volume>` to get it right)");
            } else {
                eprintln!("(the two empty strings are the CHAP user/password and the trailing 0 means");
                eprintln!(" 'no authentication'; use `--chap` to require authentication instead)");
            }
            eprintln!();
            eprintln!("Windows then shows the volume as a partitioned disk: the data area appears as a");
            eprintln!("single partition (the container itself keeps its VeraCrypt layout).");
            eprintln!("detach it again with:");
            eprintln!("    iscsicli QLogoutTarget {}", mount.target_name());
            eprintln!("    iscsicli LogoutTarget <SessionId>      (see: iscsicli SessionList 1)");
            eprintln!("    iscsicli RemoveTarget {}", mount.target_name());
            eprintln!(
                "    (or: vcrs dismount --iscsi {} -- it also takes the disk offline first,",
                mount.target_name()
            );
            eprintln!("     because Windows refuses to log out a session whose disk is still in use)");
        }
    }
    eprintln!();
    if opts.idle_timeout.is_zero() {
        eprintln!("this process keeps serving the volume until you press Ctrl-C.");
    } else {
        eprintln!(
            "this process keeps serving the volume until you press Ctrl-C, and stops by itself\n\
             {} s after the last initiator logs out (pass --idle-timeout 0 to keep serving\n\
             through a logout, e.g. while Windows reboots).",
            opts.idle_timeout.as_secs_f32(),
        );
    }
    mount.wait()
}

/// The host part of a `host:port` address, as `iscsicli` expects it.
fn portal_host(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((host, _port)) => host,
        None => addr,
    }
}

/// The port part of a `host:port` address, as `iscsicli AddTarget` expects it.
fn portal_port(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((_host, port)) => port,
        None => "3260",
    }
}

/// Pick a free loopback port (handy for tests, which cannot guess the port).
pub fn free_loopback_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}
