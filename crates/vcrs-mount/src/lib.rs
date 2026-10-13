//! Mounting and formatting of VeraCrypt-compatible volumes.
//!
//! `vcrs-core` implements the VeraCrypt *volume format*: it creates and opens
//! `.vc` containers and reads/writes the decrypted data area of a volume. This
//! crate adds the two things a user needs on top of that:
//!
//! 1. [`format_volume`] creates a FAT12/16/32 filesystem inside the volume's
//!    data area (written through the encrypted volume), which is what VeraCrypt
//!    and Windows put into a small volume.
//! 2. [`iscsi`] serves the volume's data area as a **raw block device** over
//!    iSCSI, so the initiator's own filesystem drivers mount whatever lives
//!    inside the volume — NTFS, exFAT, or anything else. On Windows this is how
//!    a container becomes a drive letter.
//!
//! # Why iSCSI and not a filesystem framework
//!
//! Dokany/WinFsp are *filesystem* frameworks: they hand user-mode code file
//! operations, so using them would mean reimplementing NTFS. A VeraCrypt
//! container is a *raw disk* holding a bare filesystem, so the block device is
//! what has to be exposed; the iSCSI target does that in user mode, with no
//! kernel driver and no plaintext ever hitting the disk. [`VolumeDevice`]
//! (decrypted sectors) is the single backend both the FAT formatter and the
//! iSCSI device are built on.
//!
//! ```no_run
//! use vcrs_mount::{format_volume, FatKind};
//! use vcrs_core::volume::{CreateOptions, Volume};
//!
//! # fn main() -> vcrs_mount::Result<()> {
//! // Create a 4 MiB container and put a FAT16 filesystem inside its data area.
//! let mut create = CreateOptions::default();
//! create.password = b"secret".to_vec();
//! let mut volume = Volume::create("vault.vc".as_ref(), 4 * 1024 * 1024, &create)?;
//! format_volume(&mut volume, FatKind::Auto, "VAULT")?;
//! # Ok(())
//! # }
//! ```
//!
//! # Platform support
//!
//! Formatting works everywhere. Serving a volume over iSCSI works everywhere
//! too, but only Windows' iSCSI initiator is configured by [`iscsi::mount_iscsi`]
//! (on other systems, point an initiator at the target yourself).

mod device;
mod fat;

/// Present the volume as a raw block device over iSCSI (the initiator's own
/// NTFS/exFAT drivers then mount it).
pub mod iscsi;

pub use device::{DataArea, VolumeDevice, SECTOR_SIZE};
pub use iscsi::{mount_iscsi, DiskMode, IscsiMount, IscsiMountOptions, ScsiVolume, ISCSI_PORT};
pub use vcrs_core::error::{Error, Result};

/// The flavour of FAT filesystem created by [`format_volume`].
///
/// FAT has no on-disk "type" field: the type is a function of the number of
/// clusters, so `fatfs` (like Windows) derives it from the cluster count. This
/// enum therefore selects the cluster size, which in turn selects the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FatKind {
    /// Pick from the volume size: FAT16 for volumes up to ~2 GiB (which is what
    /// VeraCrypt does for typical containers), FAT32 above that, and let `fatfs`
    /// choose for volumes that are too small for FAT16 (FAT12).
    #[default]
    Auto,
    /// Force FAT16 (fails if the volume cannot be divided into a valid number of
    /// FAT16 clusters, i.e. roughly below 2 MiB or above 2 GiB).
    Fat16,
    /// Force FAT32 (fails for volumes below ~35 MiB or above ~2 TiB).
    Fat32,
}

/// Create a FAT filesystem inside `volume`'s data area.
///
/// The filesystem is written through the encrypted volume (every sector is
/// encrypted with the volume's XTS keys) and flushed to the host file before
/// returning. `label` is the FAT volume label (max. 11 ASCII characters, stored
/// upper-case); pass `""` for no label.
///
/// The volume must be opened read-write, must have a data area of at least a few
/// sectors and must be small enough for FAT (2 TiB with 512-byte sectors).
/// Existing data in the volume is overwritten.
pub fn format_volume(
    volume: &mut vcrs_core::volume::Volume,
    kind: FatKind,
    label: &str,
) -> Result<()> {
    fat::format_volume(volume, kind, label)
}
