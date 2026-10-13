//! VeraCrypt volume layouts: where headers and volume data live in the host
//! file (`src/Volume/VolumeLayout.cpp`).
//!
//! Only file-hosted volumes are implemented (sector size 512); system/partition
//! encryption layouts are out of scope.

use crate::header::{
    VolumeHeader, VolumeType, TOTAL_VOLUME_HEADERS_SIZE, VOLUME_HEADER_SIZE,
    VOLUME_HEADER_SIZE_LEGACY,
};
use crate::{Error, Result};

/// `TC_VOLUME_SMALL_SIZE_THRESHOLD`.
pub const SMALL_VOLUME_THRESHOLD: u64 = 2 * 1024 * 1024;
/// `TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE`.
pub const HIDDEN_RESERVED_END_AREA: u64 = 4096;
/// `TC_HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH`.
pub const HIDDEN_RESERVED_END_AREA_HIGH: u64 = 131_072;
/// Absolute offset of the hidden volume header in a V2 volume.
pub const HIDDEN_VOLUME_HEADER_OFFSET: u64 = VOLUME_HEADER_SIZE;

/// How a volume's headers are arranged inside the host file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeLayout {
    /// Current format: 64 KiB primary header at offset 0, 64 KiB backup header
    /// 128 KiB before the end of the host.
    V2Normal,
    /// Current hidden-volume format: 64 KiB header at offset 64 KiB, backup
    /// header 64 KiB before the end of the host.
    V2Hidden,
    /// Legacy format: 512-byte header at offset 0, data from offset 512, no
    /// backup header.
    V1Normal,
}

impl VolumeLayout {
    /// Layouts to try when opening a normal volume, in VeraCrypt's order.
    pub const NORMAL_TRIAL_ORDER: [VolumeLayout; 2] =
        [VolumeLayout::V2Normal, VolumeLayout::V1Normal];
    /// Layouts to try when opening a hidden volume.
    pub const HIDDEN_TRIAL_ORDER: [VolumeLayout; 1] = [VolumeLayout::V2Hidden];

    pub const fn volume_type(self) -> VolumeType {
        match self {
            VolumeLayout::V2Hidden => VolumeType::Hidden,
            _ => VolumeType::Normal,
        }
    }

    pub const fn is_hidden(self) -> bool {
        matches!(self, VolumeLayout::V2Hidden)
    }

    /// Offset of the primary header region.
    pub const fn header_offset(self) -> u64 {
        match self {
            VolumeLayout::V2Normal | VolumeLayout::V1Normal => 0,
            VolumeLayout::V2Hidden => HIDDEN_VOLUME_HEADER_OFFSET,
        }
    }

    /// Size of the header region to read/write (`VolumeLayout::GetHeaderSize`).
    pub const fn header_size(self) -> usize {
        match self {
            VolumeLayout::V2Normal | VolumeLayout::V2Hidden => VOLUME_HEADER_SIZE as usize,
            VolumeLayout::V1Normal => VOLUME_HEADER_SIZE_LEGACY as usize,
        }
    }

    /// Backup header offset, relative to the end of the host file (negative).
    pub const fn backup_header_offset(self) -> Option<i64> {
        match self {
            VolumeLayout::V2Normal => Some(-(2 * VOLUME_HEADER_SIZE as i64)),
            VolumeLayout::V2Hidden => Some(-(VOLUME_HEADER_SIZE as i64)),
            VolumeLayout::V1Normal => None,
        }
    }

    /// Largest volume data size this layout can hold in a host of `host_size`
    /// bytes (`VolumeLayout::GetMaxDataSize`).
    ///
    /// For hidden volumes the argument is the *hidden volume size*, matching
    /// `VolumeLayoutV2Hidden::GetMaxDataSize(volumeSize)`, which reserves a
    /// filesystem area at the end of the volume (VeraCrypt shrinks the hidden
    /// volume to keep it compatible with a filesystem that needs the last
    /// sector).
    pub fn max_data_size(self, host_size: u64) -> Option<u64> {
        match self {
            // Both header groups (primary at 0 and backup near the end) plus
            // the hidden header slots are reserved.
            VolumeLayout::V2Normal => host_size.checked_sub(TOTAL_VOLUME_HEADERS_SIZE),
            VolumeLayout::V2Hidden => {
                let reserved = if host_size < SMALL_VOLUME_THRESHOLD {
                    HIDDEN_RESERVED_END_AREA
                } else {
                    HIDDEN_RESERVED_END_AREA_HIGH
                };
                host_size.checked_sub(reserved)
            }
            VolumeLayout::V1Normal => host_size.checked_sub(VOLUME_HEADER_SIZE_LEGACY),
        }
    }

    /// Offset of the volume data area inside the host file, taken from the
    /// header (`VolumeLayout::GetDataOffset(hostSize)`).
    pub fn data_offset(self, header: &VolumeHeader, host_size: u64) -> u64 {
        match self {
            // For V1 the data always follows the 512-byte header.
            VolumeLayout::V1Normal => VOLUME_HEADER_SIZE_LEGACY,
            // V2 stores the offset in the header.
            _ => {
                let _ = host_size;
                header.encrypted_area_start
            }
        }
    }

    /// Where the data area of a *newly created* volume starts.
    ///
    /// `host_size` is the size of the whole host file and `volume_size` the
    /// size of the volume being created (for a hidden volume inside an existing
    /// container, `volume_size` is the hidden volume's size).
    pub fn creation_data_offset(self, host_size: u64, volume_size: u64) -> Result<u64> {
        match self {
            VolumeLayout::V2Normal => Ok(2 * VOLUME_HEADER_SIZE),
            VolumeLayout::V2Hidden => {
                let tail = 2 * VOLUME_HEADER_SIZE + volume_size;
                host_size.checked_sub(tail).ok_or_else(|| {
                    Error::InvalidParameter(format!(
                        "host of {host_size} bytes cannot hold a hidden volume of {volume_size} bytes"
                    ))
                })
            }
            VolumeLayout::V1Normal => Err(Error::Unsupported(
                "creating legacy V1 volumes is not supported".into(),
            )),
        }
    }
}

impl VolumeType {
    /// Layout used when creating a volume of this type.
    pub const fn creation_layout(self) -> VolumeLayout {
        match self {
            VolumeType::Normal => VolumeLayout::V2Normal,
            VolumeType::Hidden => VolumeLayout::V2Hidden,
        }
    }
}
