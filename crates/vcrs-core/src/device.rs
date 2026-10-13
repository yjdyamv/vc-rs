//! Raw access to a partition or volume, for non-system in-place encryption.
//!
//! VeraCrypt restricts in-place encryption to partitions that hold a *mounted
//! NTFS* filesystem (src/Format/InPlace.c:127+), because making room for the
//! volume header requires shrinking the filesystem, and on Windows only NTFS
//! has an in-place shrink ioctl (`FSCTL_SHRINK_VOLUME`, plus
//! `FSCTL_MOVE_FILE` to relocate clusters that sit in the tail).
//!
//! The types here wrap a raw `File` handle on a device together with the
//! information the rest of the crate needs: the size, the sector size, the
//! partition geometry and (for NTFS) the volume data buffer. The in-place
//! loops in [`crate::volume`] can then run against a device exactly like they
//! run against a container file, with three differences: the size comes from
//! the device rather than from the file metadata, the file system has to be
//! shrunk first, and the first sectors are concealed (XORed) while the
//! transformation runs.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[cfg(windows)]
pub use windows::Device;

/// The volume header group: the primary header plus the space VeraCrypt keeps
/// for the (fake) hidden header.
pub const HEADER_GROUP_SIZE: u64 = crate::header::VOLUME_HEADER_GROUP_SIZE;
/// The primary and backup header groups together.
pub const TOTAL_HEADERS_SIZE: u64 = crate::header::TOTAL_VOLUME_HEADERS_SIZE;
/// `TC_NONSYS_INPLACE_ENC_MIN_VOL_SIZE` (src/Format/InPlace.c:63):
/// `TC_TOTAL_VOLUME_HEADERS_SIZE + TC_MIN_NTFS_FS_SIZE * 2` with
/// `TC_MIN_NTFS_FS_SIZE = 884 * TC_MAX_VOLUME_SECTOR_SIZE` (src/Common/Volumes.h:87).
pub const MIN_DEVICE_SIZE: u64 =
    TOTAL_HEADERS_SIZE + 2 * (884 * crate::header::MAX_SECTOR_SIZE as u64);
/// `TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE` (src/Format/InPlace.c:60).
pub const CONCEAL_PORTION_SIZE: usize = 2 * crate::header::MAX_SECTOR_SIZE as usize;
/// `TC_NTFS_CONCEAL_CONSTANT` (src/Format/InPlace.c:61).
pub const CONCEAL_CONSTANT: u8 = 0xFF;

/// What a raw device turned out to be.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// The path as it was given.
    pub path: PathBuf,
    /// The `\Device\HarddiskVolumeN` form, when the system could resolve it.
    pub volume_path: Option<PathBuf>,
    /// Size of the device in bytes.
    pub size: u64,
    /// Logical sector size of the device.
    pub sector_size: u32,
    /// "MBR" or "GPT", when the partition table could be queried.
    pub partition_style: Option<String>,
    /// Partition number on the disk (0 for an unpartitioned disk).
    pub partition_number: Option<u32>,
    /// Whether Windows marks this as a service partition.
    pub is_service_partition: bool,
    /// Whether this is the volume Windows itself runs from.
    pub is_system_volume: bool,
    /// The filesystem name read from the boot sector, when it is recognisable.
    pub boot_sector_fs: Option<String>,
    /// NTFS volume data, if the device holds an NTFS filesystem.
    pub ntfs: Option<NtfsData>,
}

/// The `NTFS_VOLUME_DATA_BUFFER` fields we care about.
#[derive(Debug, Clone, Copy)]
pub struct NtfsData {
    pub serial: u64,
    pub bytes_per_sector: u32,
    pub bytes_per_cluster: u32,
    pub number_sectors: u64,
    pub total_clusters: u64,
    pub free_clusters: u64,
}

impl NtfsData {
    /// Size of the NTFS filesystem in bytes.
    pub fn filesystem_size(&self) -> u64 {
        self.number_sectors.saturating_mul(self.bytes_per_sector as u64)
    }

    /// Free space inside the filesystem, in bytes.
    pub fn free_bytes(&self) -> u64 {
        self.free_clusters.saturating_mul(self.bytes_per_cluster as u64)
    }
}

impl DeviceInfo {
    /// The size of the data area that a VeraCrypt volume covering this device
    /// would have.
    pub fn data_area_size(&self) -> u64 {
        self.size.saturating_sub(TOTAL_HEADERS_SIZE)
    }

    /// Where the backup header group starts (VeraCrypt writes it at the end of
    /// the device, minus one header group).
    pub fn backup_header_offset(&self) -> u64 {
        self.size.saturating_sub(HEADER_GROUP_SIZE)
    }

    /// How much the filesystem has to shrink to leave room for the headers.
    pub fn shrink_bytes(&self) -> u64 {
        match &self.ntfs {
            Some(ntfs) => ntfs.filesystem_size().saturating_sub(self.data_area_size()),
            None => 0,
        }
    }

    /// The reason the device cannot be encrypted in place, if there is one.
    pub fn blocker(&self) -> Option<String> {
        if self.size < MIN_DEVICE_SIZE {
            return Some(format!(
                "the device is {} bytes; in-place encryption needs at least {MIN_DEVICE_SIZE}",
                self.size
            ));
        }
        if self.sector_size == 0 || self.sector_size > crate::header::MAX_SECTOR_SIZE {
            return Some(format!("unsupported sector size {}", self.sector_size));
        }
        if self.partition_number == Some(0) {
            return Some(
                "this is a whole disk; VeraCrypt only encrypts partitions in place".to_string(),
            );
        }
        if self.is_system_volume {
            return Some("this is the volume Windows runs from; system encryption is out of scope".to_string());
        }
        match &self.ntfs {
            None => Some(format!(
                "no NTFS filesystem was found (the boot sector says {}); Windows cannot shrink \
                 any other filesystem in place",
                self.boot_sector_fs.as_deref().unwrap_or("nothing recognisable")
            )),
            Some(ntfs) => {
                if ntfs.free_bytes() < TOTAL_HEADERS_SIZE {
                    return Some(format!(
                        "the filesystem has only {} bytes free; shrinking it needs {TOTAL_HEADERS_SIZE}",
                        ntfs.free_bytes()
                    ));
                }
                None
            }
        }
    }
}

/// What `FSCTL_SHRINK_VOLUME` said when asked whether the filesystem can give
/// up its tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShrinkProbe {
    /// The filesystem can be shrunk to the requested size as it is.
    Ready,
    /// Data is allocated in the tail; VeraCrypt would move those clusters down
    /// (or a defragmentation with free-space consolidation would).
    NeedsClusterMove,
}

#[cfg(windows)]
mod windows {
    use std::fs::{File, OpenOptions};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};

    use super::*;

    // ---- kernel32 -------------------------------------------------------

    type Handle = *mut std::ffi::c_void;

    const FILE_DEVICE_FILE_SYSTEM: u32 = 0x0009;
    const METHOD_BUFFERED: u32 = 0;
    const METHOD_NEITHER: u32 = 3;
    const FILE_ANY_ACCESS: u32 = 0;
    const FILE_READ_ACCESS: u32 = 1;
    const FILE_DEVICE_DISK: u32 = 0x0007;

    const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }

    /// `FSCTL_ALLOW_EXTENDED_DASD_IO` (src/Format/InPlace.c:457): without this
    /// the filesystem driver refuses raw access to the tail of the partition,
    /// where the volume headers live.
    const FSCTL_ALLOW_EXTENDED_DASD_IO: u32 =
        ctl_code(FILE_DEVICE_FILE_SYSTEM, 32, METHOD_NEITHER, FILE_ANY_ACCESS);
    /// `FSCTL_LOCK_VOLUME`.
    const FSCTL_LOCK_VOLUME: u32 =
        ctl_code(FILE_DEVICE_FILE_SYSTEM, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
    /// `FSCTL_DISMOUNT_VOLUME`.
    const FSCTL_DISMOUNT_VOLUME: u32 =
        ctl_code(FILE_DEVICE_FILE_SYSTEM, 8, METHOD_BUFFERED, FILE_ANY_ACCESS);
    /// `FSCTL_GET_NTFS_VOLUME_DATA`.
    const FSCTL_GET_NTFS_VOLUME_DATA: u32 =
        ctl_code(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED, FILE_ANY_ACCESS);
    /// `FSCTL_SHRINK_VOLUME`.
    const FSCTL_SHRINK_VOLUME: u32 =
        ctl_code(FILE_DEVICE_FILE_SYSTEM, 102, METHOD_BUFFERED, FILE_ANY_ACCESS);
    /// `IOCTL_DISK_GET_LENGTH_INFO`.
    const IOCTL_DISK_GET_LENGTH_INFO: u32 =
        ctl_code(FILE_DEVICE_DISK, 0x17, METHOD_BUFFERED, FILE_READ_ACCESS);
    /// `IOCTL_DISK_GET_DRIVE_GEOMETRY`.
    const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 =
        ctl_code(FILE_DEVICE_DISK, 0, METHOD_BUFFERED, FILE_ANY_ACCESS);
    /// `IOCTL_DISK_GET_PARTITION_INFO_EX`.
    const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048;

    #[link(name = "kernel32")]
    extern "system" {
        fn DeviceIoControl(
            handle: Handle,
            control_code: u32,
            in_buffer: *mut std::ffi::c_void,
            in_size: u32,
            out_buffer: *mut std::ffi::c_void,
            out_size: u32,
            bytes_returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
        ) -> i32;
        fn QueryDosDeviceW(device_name: *const u16, target_path: *mut u16, max: u32) -> u32;
        fn GetVolumeInformationW(
            root: *const u16,
            volume_name: *mut u16,
            volume_name_size: u32,
            serial: *mut u32,
            max_component_len: *mut u32,
            flags: *mut u32,
            fs_name: *mut u16,
            fs_name_size: u32,
        ) -> i32;
        fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    // ---- ioctl structures ----------------------------------------------

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct DiskGeometry {
        cylinders: i64,
        media_type: u32,
        tracks_per_cylinder: u32,
        sectors_per_track: u32,
        bytes_per_sector: u32,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct NtfsVolumeData {
        volume_serial_number: i64,
        number_sectors: i64,
        total_clusters: i64,
        free_clusters: i64,
        total_reserved: i64,
        bytes_per_sector: u32,
        bytes_per_cluster: u32,
        bytes_per_file_record_segment: u32,
        clusters_per_file_record_segment: u32,
        mft_valid_data_length: i64,
        mft_start_lcn: i64,
        mft2_start_lcn: i64,
        mft_zone_start: i64,
        mft_zone_end: i64,
    }

    const PARTITION_STYLE_MBR: u32 = 0;
    const PARTITION_STYLE_GPT: u32 = 1;

    #[repr(C)]
    struct PartitionInformationEx {
        partition_style: u32,
        _padding: u32,
        starting_offset: i64,
        partition_length: i64,
        partition_number: u32,
        rewrite_partition: u8,
        is_service_partition: u8,
        _padding2: [u8; 2],
        _rest: [u8; 112],
    }

    impl Default for PartitionInformationEx {
        fn default() -> Self {
            PartitionInformationEx {
                partition_style: 0,
                _padding: 0,
                starting_offset: 0,
                partition_length: 0,
                partition_number: 0,
                rewrite_partition: 0,
                is_service_partition: 0,
                _padding2: [0; 2],
                _rest: [0; 112],
            }
        }
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct GetLengthInformation {
        length: i64,
    }

    const SHRINK_PREPARE: u32 = 0;
    const SHRINK_COMMIT: u32 = 1;
    const SHRINK_ABORT: u32 = 2;

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct ShrinkVolumeInformation {
        shrink_request_type: u32,
        flags: u32,
        new_number_of_sectors: i64,
    }

    // `FSCTL_SHRINK_VOLUME` reports "the filesystem cannot be shrunk to that
    // size because clusters beyond it are allocated" as ERROR_ACCESS_DENIED
    // (VeraCrypt checks exactly that: src/Format/InPlace.c:516).
    const ERROR_ACCESS_DENIED: i32 = 5;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn io_error(what: &str, path: &Path) -> Error {
        Error::Io(std::io::Error::new(
            std::io::Error::last_os_error().kind(),
            format!("{what} failed for {}: {}", path.display(), std::io::Error::last_os_error()),
        ))
    }

    /// A raw device (partition or mounted volume) opened for sector access.
    pub struct Device {
        file: File,
        info: DeviceInfo,
    }

    /// Turn the path the user gave into a Win32 device path we can open.
    pub fn normalize_device_path(path: &Path) -> Result<PathBuf> {
        let text = path.to_string_lossy().to_string();
        let text = text.trim_end_matches('\\');
        if text.len() == 2 && text.ends_with(':') {
            // "E:" or "E:\" -> the volume object behind that mount point.
            return Ok(PathBuf::from(format!(r"\\.\{text}")));
        }
        if let Some(rest) = text.strip_prefix(r"\\.\") {
            if rest.is_empty() {
                return Err(Error::InvalidParameter(
                    "a device path cannot be just \\\\.\\".to_string(),
                ));
            }
            return Ok(PathBuf::from(format!(r"\\.\{rest}")));
        }
        Err(Error::InvalidParameter(format!(
            "'{text}' is not a device path; pass a drive letter (E:) or a device such as \
             \\\\.\\PhysicalDrive1\\Partition2"
        )))
    }

    impl Device {
        /// Open a partition or volume for raw access.
        pub fn open(path: &Path, writable: bool) -> Result<Device> {
            let device_path = normalize_device_path(path)?;
            let mut options = OpenOptions::new();
            options.read(true).write(writable);
            let file = options
                .open(&device_path)
                .map_err(|e| Error::Io(std::io::Error::new(e.kind(), format!("opening {}: {e}", device_path.display()))))?;

            let size = query_size(&file, &device_path)?;
            let sector_size = query_sector_size(&file, &device_path)?;
            if size == 0 {
                return Err(Error::InvalidParameter(format!(
                    "the device {} reports a size of 0 bytes",
                    device_path.display()
                )));
            }
            let partition = query_partition(&file);
            let boot = read_boot_sector(&file, &device_path)?;
            let ntfs = query_ntfs(&file);
            let volume_path = dos_device_path(&device_path);
            let is_system_volume = match &volume_path {
                Some(target) => match windows_volume_path() {
                    // Comparing the `\Device\HarddiskVolumeN` names is exact and does
                    // not depend on how the serial number is reported.
                    Some(system) => target
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&system.to_string_lossy())
                        || is_system_volume_by_serial(ntfs.as_ref()),
                    None => is_system_volume_by_serial(ntfs.as_ref()),
                },
                None => is_system_volume_by_serial(ntfs.as_ref()),
            };

            let info = DeviceInfo {
                path: device_path.clone(),
                volume_path,
                size,
                sector_size,
                partition_style: partition.as_ref().map(|p| {
                    if p.partition_style == PARTITION_STYLE_GPT {
                        "GPT".to_string()
                    } else if p.partition_style == PARTITION_STYLE_MBR {
                        "MBR".to_string()
                    } else {
                        format!("style {}", p.partition_style)
                    }
                }),
                partition_number: partition.as_ref().map(|p| p.partition_number),
                is_service_partition: partition.as_ref().is_some_and(|p| p.is_service_partition != 0),
                is_system_volume,
                boot_sector_fs: boot,
                ntfs,
            };

            Ok(Device { file, info })
        }

        /// What was found on the device.
        pub fn info(&self) -> &DeviceInfo {
            &self.info
        }

        /// The underlying handle, so the container code can read and write
        /// through it.
        pub fn file(&self) -> &File {
            &self.file
        }

        /// Hand over the handle, so `Volume` can own it.
        pub fn into_file(self) -> File {
            self.file
        }

        /// Size of the device in bytes.
        pub fn len(&self) -> u64 {
            self.info.size
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// Ask the filesystem driver for raw access to the whole partition,
        /// including the sectors it otherwise hides (the volume headers live
        /// there).
        pub fn allow_extended_dasd_io(&self) -> Result<()> {
            let mut returned = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    self.file.as_raw_handle() as Handle,
                    FSCTL_ALLOW_EXTENDED_DASD_IO,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(Error::Unsupported(format!(
                    "the filesystem driver refused raw access to {} (FSCTL_ALLOW_EXTENDED_DASD_IO): \
                     the volume has to be a mounted filesystem for in-place encryption",
                    self.info.path.display()
                )));
            }
            Ok(())
        }

        /// Ask NTFS whether it could give up everything after `new_size`
        /// bytes, without changing anything (`ShrinkPrepare` followed by
        /// `ShrinkAbort`).
        pub fn probe_shrink(&self, new_size: u64) -> Result<ShrinkProbe> {
            let sectors = new_size / self.info.sector_size as u64;
            match self.shrink_to_sectors(sectors, false) {
                Ok(()) => {
                    // The filesystem is prepared to shrink; undo the request.
                    let _ = self.shrink_request(SHRINK_ABORT, sectors);
                    Ok(ShrinkProbe::Ready)
                }
                Err(Error::Io(e)) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                    Ok(ShrinkProbe::NeedsClusterMove)
                }
                Err(e) => Err(e),
            }
        }

        /// Shrink the NTFS filesystem so that `TOTAL_HEADERS_SIZE` bytes of
        /// free space appear behind it.
        ///
        /// The target has to be computed from the *filesystem's* size, not the
        /// device's: NTFS keeps the device's last sector for its own backup boot
        /// sector, so asking for `device_size - 262144` lands one sector past
        /// what NTFS is willing to give up and the commit fails with
        /// `ERROR_ACCESS_DENIED` (VeraCrypt's `NewFileSysSizeAfterShrink` does
        /// the same arithmetic).
        pub fn shrink_ntfs_for_in_place(&self) -> Result<u64> {
            let ntfs = self.info.ntfs.as_ref().ok_or_else(|| {
                Error::Unsupported(format!(
                    "{} does not hold an NTFS filesystem, and only NTFS can be shrunk to make room \
                     for the volume header (VeraCrypt refuses other filesystems for the same \
                     reason)",
                    self.info.path.display()
                ))
            })?;
            let target = ntfs
                .filesystem_size()
                .saturating_sub(TOTAL_HEADERS_SIZE as u64);
            // NTFS wants the new size to be a multiple of its cluster size.
            let cluster = ntfs.bytes_per_cluster as u64;
            let target = if cluster > 0 { target / cluster * cluster } else { target };
            self.shrink_ntfs_to(target)?;
            Ok(target)
        }

        /// Shrink the NTFS filesystem to `new_size` bytes.
        pub fn shrink_ntfs_to(&self, new_size: u64) -> Result<()> {
            let sectors = new_size / self.info.sector_size as u64;
            match self.shrink_to_sectors(sectors, true) {
                Err(Error::Io(e)) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                    // ShrinkCommit refuses while clusters live beyond the new
                    // end. VeraCrypt moves them itself (FSCTL_MOVE_FILE) instead;
                    // Windows' own defragmenter does the same thing.
                    Err(Error::Unsupported(format!(
                        "NTFS is not willing to shrink {} to {} bytes yet because data is stored there; \
                         move it to the front of the volume first (VeraCrypt rewrites those files itself, \
                         Windows does it with `defrag <drive> /X`) and try again",
                        self.info.path.display(),
                        new_size
                    )))
                }
                other => other,
            }
        }

        fn shrink_to_sectors(&self, sectors: u64, commit: bool) -> Result<()> {
            self.shrink_request(SHRINK_PREPARE, sectors)?;
            if commit {
                // The commit (and the abort) ignore the size field; VeraCrypt
                // zeroes it, so do we.
                self.shrink_request(SHRINK_COMMIT, 0)?;
            }
            Ok(())
        }

        fn shrink_request(&self, request: u32, sectors: u64) -> Result<()> {
            let mut information = ShrinkVolumeInformation {
                shrink_request_type: request,
                flags: 0,
                new_number_of_sectors: sectors as i64,
            };
            let mut returned = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    self.file.as_raw_handle() as Handle,
                    FSCTL_SHRINK_VOLUME,
                    &mut information as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<ShrinkVolumeInformation>() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let which = match request {
                    SHRINK_PREPARE => "ShrinkPrepare",
                    SHRINK_COMMIT => "ShrinkCommit",
                    _ => "ShrinkAbort",
                };
                return Err(io_error(&format!("FSCTL_SHRINK_VOLUME ({which})"), &self.info.path));
            }
            Ok(())
        }

        /// Lock and dismount the filesystem so that everything we write goes
        /// straight to the device.
        pub fn lock_and_dismount(&self) -> Result<()> {
            let mut returned = 0u32;
            let handle = self.file.as_raw_handle() as Handle;
            let mut last = 0i32;
            for _ in 0..20 {
                let ok = unsafe {
                    DeviceIoControl(
                        handle,
                        FSCTL_LOCK_VOLUME,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        0,
                        &mut returned,
                        std::ptr::null_mut(),
                    )
                };
                if ok != 0 {
                    last = 0;
                    break;
                }
                last = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if last != 0 {
                return Err(io_error("FSCTL_LOCK_VOLUME", &self.info.path));
            }
            let ok = unsafe {
                DeviceIoControl(
                    self.file.as_raw_handle() as Handle,
                    FSCTL_DISMOUNT_VOLUME,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io_error("FSCTL_DISMOUNT_VOLUME", &self.info.path));
            }
            Ok(())
        }

        /// Apply (or undo) VeraCrypt's concealment of the filesystem's first
        /// sectors, so that Windows does not touch the volume while it is
        /// being transformed (`ConcealNTFS`, src/Format/InPlace.c:2058).
        pub fn conceal(&self, on: bool) -> Result<()> {
            let mut buffer = vec![0u8; CONCEAL_PORTION_SIZE];
            crate::volume::read_exact_at(&self.file, 0, &mut buffer).map_err(Error::Io)?;
            if on {
                for byte in buffer.iter_mut() {
                    *byte ^= CONCEAL_CONSTANT;
                }
            } else {
                // Undo: the concealment is its own inverse, but only if it is
                // still in place.
                for byte in buffer.iter_mut() {
                    *byte ^= CONCEAL_CONSTANT;
                }
            }
            crate::volume::write_all_at(&self.file, 0, &buffer).map_err(Error::Io)
        }
    }

    fn query_size(file: &File, path: &Path) -> Result<u64> {
        let mut information = GetLengthInformation::default();
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle() as Handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null_mut(),
                0,
                &mut information as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<GetLengthInformation>() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 && information.length > 0 {
            return Ok(information.length as u64);
        }
        // Some devices do not answer IOCTL_DISK_GET_LENGTH_INFO; fall back to
        // the size the handle reports.
        let length = file.metadata().map_err(Error::Io)?.len();
        if length > 0 {
            return Ok(length);
        }
        Err(Error::InvalidParameter(format!(
            "could not determine the size of {}",
            path.display()
        )))
    }

    fn query_sector_size(file: &File, path: &Path) -> Result<u32> {
        let mut geometry = DiskGeometry::default();
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle() as Handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                std::ptr::null_mut(),
                0,
                &mut geometry as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<DiskGeometry>() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || geometry.bytes_per_sector == 0 {
            return Err(Error::InvalidParameter(format!(
                "could not determine the sector size of {}",
                path.display()
            )));
        }
        Ok(geometry.bytes_per_sector)
    }

    fn query_partition(file: &File) -> Option<PartitionInformationEx> {
        let mut information = PartitionInformationEx::default();
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle() as Handle,
                IOCTL_DISK_GET_PARTITION_INFO_EX,
                std::ptr::null_mut(),
                0,
                &mut information as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<PartitionInformationEx>() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(information)
    }

    fn query_ntfs(file: &File) -> Option<NtfsData> {
        let mut data = NtfsVolumeData::default();
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle() as Handle,
                FSCTL_GET_NTFS_VOLUME_DATA,
                std::ptr::null_mut(),
                0,
                &mut data as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<NtfsVolumeData>() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return None;
        }
        Some(NtfsData {
            serial: data.volume_serial_number as u64,
            bytes_per_sector: data.bytes_per_sector,
            bytes_per_cluster: data.bytes_per_cluster,
            number_sectors: data.number_sectors.max(0) as u64,
            total_clusters: data.total_clusters.max(0) as u64,
            free_clusters: data.free_clusters.max(0) as u64,
        })
    }

    /// Read the first sector and name the filesystem in it.
    fn read_boot_sector(file: &File, path: &Path) -> Result<Option<String>> {
        let mut sector = [0u8; 512];
        match crate::volume::read_exact_at(file, 0, &mut sector) {
            Ok(()) => {}
            Err(e) => {
                log::warn!("could not read the boot sector of {}: {e}", path.display());
                return Ok(None);
            }
        }
        // Name the filesystem from the boot sector the way VeraCrypt's own
        // checks do (src/Format/InPlace.c).
        let name = if sector[3..11].starts_with(b"NTFS") {
            Some("NTFS")
        } else if sector[3..11] == *b"EXFAT   " {
            Some("exFAT")
        } else if sector[82..90] == *b"FAT32   " {
            Some("FAT32")
        } else if sector[3..11].starts_with(b"MSDOS") || sector[3..11].starts_with(b"MSWIN") {
            Some("FAT")
        } else {
            None
        };
        Ok(name.map(|name| name.to_string()))
    }

    /// The `\Device\HarddiskVolumeN` name behind a device path, when the
    /// system knows one.
    fn dos_device_path(device_path: &Path) -> Option<PathBuf> {
        let name = device_path.to_string_lossy();
        // \\.\E: -> the DOS device name is "E:".
        let name = name.strip_prefix(r"\\.\")?;
        let name = if name.len() == 2 && name.ends_with(':') {
            name.to_string()
        } else {
            return None;
        };
        let wide_name = wide(Path::new(&name));
        let mut buffer = vec![0u16; 1024];
        let len = unsafe { QueryDosDeviceW(wide_name.as_ptr(), buffer.as_mut_ptr(), 1024) };
        if len == 0 {
            return None;
        }
        Some(PathBuf::from(String::from_utf16_lossy(&buffer[..len as usize])))
    }

    /// Whether the device holds the NTFS volume Windows itself runs from, judged
    /// by its serial number. NTFS reports a 64-bit serial and
    /// `GetVolumeInformationW` only the low 32 bits, so both are compared.
    fn is_system_volume_by_serial(ntfs: Option<&NtfsData>) -> bool {
        let Some(ntfs) = ntfs else {
            return false;
        };
        let mut buffer = vec![0u16; 260];
        let len = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), 260) };
        if len == 0 || len >= 260 {
            return false;
        }
        let text = String::from_utf16_lossy(&buffer[..len as usize]);
        let Some(letter) = text.chars().next() else {
            return false;
        };
        if letter == '\\' {
            return false;
        }
        let root = wide(Path::new(&format!("{letter}:\\")));
        let mut serial = 0u32;
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };
        ok != 0 && (serial as u64 == ntfs.serial || serial as u64 == ntfs.serial & 0xFFFF_FFFF)
    }

    /// The `\Device\HarddiskVolumeN` name of the volume Windows itself runs from.
    fn windows_volume_path() -> Option<PathBuf> {
        let mut buffer = vec![0u16; 260];
        let len = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), 260) };
        if len == 0 || len >= 260 {
            return None;
        }
        let text = String::from_utf16_lossy(&buffer[..len as usize]);
        let letter = text.chars().next()?;
        if letter == '\\' || !text.contains(':') {
            return None;
        }
        dos_device_path(Path::new(&format!(r"\\.\{letter}:")))
    }
}

#[cfg(not(windows))]
pub struct Device {
    _private: (),
}

#[cfg(not(windows))]
impl Device {
    pub fn open(_path: &Path, _writable: bool) -> Result<Device> {
        Err(Error::Unsupported(
            "raw device access is only implemented on Windows".to_string(),
        ))
    }

    pub fn info(&self) -> &DeviceInfo {
        unreachable!()
    }

    pub fn file(&self) -> &std::fs::File {
        unreachable!()
    }

    pub fn len(&self) -> u64 {
        0
    }

    pub fn is_empty(&self) -> bool {
        true
    }

    pub fn allow_extended_dasd_io(&self) -> Result<()> {
        Ok(())
    }

    pub fn probe_shrink(&self, _new_size: u64) -> Result<ShrinkProbe> {
        Err(Error::Unsupported(
            "raw device access is only implemented on Windows".to_string(),
        ))
    }

    pub fn shrink_ntfs_to(&self, _new_size: u64) -> Result<()> {
        Err(Error::Unsupported(
            "raw device access is only implemented on Windows".to_string(),
        ))
    }

    pub fn lock_and_dismount(&self) -> Result<()> {
        Ok(())
    }

    pub fn conceal(&self, _on: bool) -> Result<()> {
        Ok(())
    }
}

/// Whether a path looks like a raw device rather than a file.
pub fn looks_like_device(path: &Path) -> bool {
    let text = path.to_string_lossy();
    if text.starts_with(r"\\.\") {
        return true;
    }
    let bytes = text.as_bytes();
    bytes.len() == 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

/// Open a device and describe it without changing anything.
pub fn describe(path: &Path) -> Result<(Device, DeviceInfo)> {
    let device = Device::open(path, false)?;
    let info = device.info().clone();
    Ok((device, info))
}
