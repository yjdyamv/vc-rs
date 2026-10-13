//! Windows mount layer for a VeraCrypt-compatible volume.
//!
//! `vcrs-core` implements the VeraCrypt *volume format*: it can create and open
//! `.vc` containers and read/write the decrypted data area of the volume. This
//! crate adds the two things a user needs on top of that:
//!
//! 1. [`format_volume`] creates a FAT12/16/32 filesystem inside the volume's
//!    data area (the filesystem VeraCrypt and Windows put into a small volume),
//!    written through the encrypted volume.
//! 2. [`mount`] opens the volume, mounts the FAT filesystem that lives inside it
//!    through [Dokan](https://github.com/dokan-dev/dokan-rust) at a drive letter
//!    or directory, and blocks until it is unmounted. [`unmount`] detaches it
//!    again from another process.
//!
//! Dokany is a *filesystem* framework — it cannot expose a raw block device — so
//! the design is: implement the filesystem that lives inside the volume (FAT) in
//! user mode with the [`fatfs`] crate, backed by the decrypted/encrypted volume
//! data area through [`VolumeDevice`], and expose that filesystem through Dokany.
//! Nothing here ever exposes the raw volume.
//!
//! ```no_run
//! use vcrs_mount::{format_volume, mount, FatKind, MountOptions};
//! use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
//!
//! # fn main() -> vcrs_mount::Result<()> {
//! // Create a 4 MiB container and put a FAT16 filesystem inside its data area.
//! let mut create = CreateOptions::default();
//! create.password = b"secret".to_vec();
//! let mut volume = Volume::create("vault.vc".as_ref(), 4 * 1024 * 1024, &create)?;
//! format_volume(&mut volume, FatKind::Auto, "VAULT")?;
//! drop(volume);
//!
//! // Mount it as Z: (needs an elevated process and the Dokan driver installed)
//! // and block until it is unmounted.
//! let mut open = OpenOptions::default();
//! open.password = b"secret".to_vec();
//! mount("vault.vc".as_ref(), "Z:", &open, &MountOptions::default())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Platform support
//!
//! The Dokany part of this crate is Windows-only. The crate still builds on
//! other platforms, where [`mount`]/[`unmount`] return
//! [`Error::Unsupported`](vcrs_core::error::Error::Unsupported).

mod device;
mod fat;

/// Present the volume as a raw block device over iSCSI (Windows' own NTFS/exFAT
/// drivers then mount it; see the module docs for why this exists).
pub mod iscsi;

#[cfg(windows)]
mod fs_main;

pub use device::{DataArea, VolumeDevice, SECTOR_SIZE};
#[cfg(windows)]
pub use fs_main::{FileContext, VolumeFsHandler};
pub use iscsi::{
    mount_iscsi, DiskMode, IscsiMount, IscsiMountOptions, ScsiVolume, ISCSI_PORT,
};

pub use vcrs_core::error::{Error, Result};

use std::path::Path;

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

/// Options for [`mount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountOptions {
    /// Mount the volume read-only.
    ///
    /// This sets Dokan's `WRITE_PROTECT` flag (so Windows itself rejects writes
    /// before they reach this crate) and makes every write path in the file
    /// system handler fail with `STATUS_MEDIA_WRITE_PROTECTED` /
    /// `ERROR_WRITE_PROTECT`.
    pub read_only: bool,

    /// Report the volume as removable media (Dokan's `REMOVABLE` flag).
    ///
    /// This only changes how Explorer presents the drive; driving is identical.
    pub removable: bool,
}

// Default in this crate has always been read-write + removable.
impl Default for MountOptions {
    fn default() -> Self {
        MountOptions { read_only: false, removable: true }
    }
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
pub fn format_volume(volume: &mut vcrs_core::volume::Volume, kind: FatKind, label: &str) -> Result<()> {
    fat::format_volume(volume, kind, label)
}

/// Open the volume at `volume_path` and mount the FAT filesystem inside it at
/// `mount_point`, blocking until the filesystem is unmounted.
///
/// `mount_point` is a drive letter (`"Z:"`, or just `"Z"`) or the path of an
/// existing, empty directory (`"C:\\mount\\vault"`). `open` carries the volume
/// password/PIM and any header overrides.
///
/// On Windows this requires an elevated process and the Dokan driver; the
/// function returns when the volume is unmounted (by [`unmount`], by Explorer's
/// "eject", or by Dokany itself on error). `opts.read_only` and the volume label
/// and free space reporting come from the FAT filesystem inside the volume.
pub fn mount(
    volume_path: &Path,
    mount_point: &str,
    open: &vcrs_core::volume::OpenOptions,
    opts: &MountOptions,
) -> Result<()> {
    #[cfg(windows)]
    {
        fs_main::mount(volume_path, mount_point, open, opts)
    }
    #[cfg(not(windows))]
    {
        let _ = (volume_path, mount_point, open, opts);
        Err(Error::Unsupported("mounting a volume requires Windows and the Dokan driver".into()))
    }
}

/// Unmount the volume mounted at `mount_point` (a drive letter like `"Z:"` or a
/// mount point directory).
///
/// This is the way to stop a blocking [`mount`] from another process. Dokany's
/// `DokanRemoveMountPoint` requires a process that can open the Dokan control
/// device, so this normally needs elevation as well.
///
/// This is an extension over the original stub API, provided so that a CLI can
/// offer an "unmount" command while `mount` blocks.
pub fn unmount(mount_point: &str) -> Result<()> {
    #[cfg(windows)]
    {
        fs_main::unmount(mount_point)
    }
    #[cfg(not(windows))]
    {
        let _ = mount_point;
        Err(Error::Unsupported("unmounting a volume requires Windows and the Dokan driver".into()))
    }
}
