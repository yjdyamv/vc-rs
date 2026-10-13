//! Creating the FAT filesystem inside a volume's data area.
//!
//! `fatfs::format_volume` writes a BPB whose FAT type is *derived from the
//! cluster count* (`FatType::from_clusters`), not from the requested
//! `FormatVolumeOptions::fat_type` — that option only selects a default cluster
//! size. To honour [`FatKind`] we therefore pick the cluster size ourselves and
//! predict, with the same arithmetic `fatfs` uses, which FAT type it will
//! produce. [`predicted_fat_type`] reproduces `fatfs`'s internal
//! `determine_fs_geometry` search (it tries FAT32, then FAT16, then FAT12 and
//! takes the first geometry that self-consistently fits).

use std::io;

use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use vcrs_core::{
    error::Error,
    volume::Volume,
};

use crate::{
    device::{VolumeDevice, SECTOR_SIZE},
    FatKind, Result,
};

/// Root directory entries `fatfs` creates for FAT12/16 (its default).
const MAX_ROOT_DIR_ENTRIES: u32 = 512;
/// Size of a FAT directory entry.
const DIR_ENTRY_SIZE: u32 = 32;
/// Number of FAT copies `fatfs` creates.
const FATS: u32 = 2;
/// Reserved sectors `fatfs` uses for FAT32 (`fatfs` uses 1 for FAT12/16).
const FAT32_RESERVED_SECTORS: u32 = 8;

/// Smallest cluster size `fatfs` accepts.
const MIN_CLUSTER_SIZE: u32 = 512;
/// Largest cluster size `fatfs` accepts.
const MAX_CLUSTER_SIZE: u32 = 32 * 1024;

/// The FAT type `fatfs` derives from a cluster count (FAT16_MIN/FAT32_MIN).
fn fat_type_from_clusters(total_clusters: u32) -> FatType {
    if total_clusters < 4085 {
        FatType::Fat12
    } else if total_clusters < 65_525 {
        FatType::Fat16
    } else {
        FatType::Fat32
    }
}

/// Cluster limits per FAT type as enforced by `fatfs` (`max_clusters`).
fn max_clusters(fat_type: FatType) -> u32 {
    match fat_type {
        FatType::Fat12 => 4084,
        FatType::Fat16 => 65_524,
        FatType::Fat32 => 0x0FFF_FFF4,
    }
}

fn bits_per_fat_entry(fat_type: FatType) -> u32 {
    match fat_type {
        FatType::Fat12 => 12,
        FatType::Fat16 => 16,
        FatType::Fat32 => 32,
    }
}

/// The geometry `fatfs` computes for one candidate FAT type, or `None` if that
/// type cannot describe this volume.
fn predict_fat_type(total_sectors: u32, bytes_per_sector: u16, bytes_per_cluster: u32) -> Option<FatType> {
    let bytes_per_sector = u32::from(bytes_per_sector);
    if bytes_per_cluster < bytes_per_sector || bytes_per_cluster % bytes_per_sector != 0 {
        return None;
    }
    let sectors_per_cluster = bytes_per_cluster / bytes_per_sector;

    // `fatfs` tries FAT32 first, then FAT16, then FAT12.
    for fat_type in [FatType::Fat32, FatType::Fat16, FatType::Fat12] {
        let reserved_sectors = if fat_type == FatType::Fat32 { FAT32_RESERVED_SECTORS } else { 1 };
        let root_dir_sectors = if fat_type == FatType::Fat32 {
            0
        } else {
            (MAX_ROOT_DIR_ENTRIES * DIR_ENTRY_SIZE).div_ceil(bytes_per_sector)
        };
        if total_sectors <= reserved_sectors + root_dir_sectors + 8 {
            continue;
        }
        let data_and_fat = total_sectors - reserved_sectors - root_dir_sectors;
        // fatfs: t2 = bits_per_cluster / bits_per_fat_entry + fats
        let t2 = (u64::from(sectors_per_cluster) * u64::from(bytes_per_sector) * 8)
            / u64::from(bits_per_fat_entry(fat_type))
            + u64::from(FATS);
        let sectors_per_fat = (u64::from(data_and_fat) + u64::from(sectors_per_cluster) * 2).div_ceil(t2);
        let sectors_per_fat = match u32::try_from(sectors_per_fat) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let Some(data_sectors) = data_and_fat.checked_sub(sectors_per_fat * FATS) else {
            continue;
        };
        let total_clusters = data_sectors / sectors_per_cluster;
        // fatfs compares the derived type with the candidate and rejects an
        // over-large cluster count.
        if fat_type_from_clusters(total_clusters) == fat_type && total_clusters <= max_clusters(fat_type) {
            return Some(fat_type);
        }
    }
    None
}

/// `fatfs`'s automatic cluster size rule (`determine_bytes_per_cluster`), used
/// as the starting point of the search for a size that yields `fat_type`.
fn default_cluster_size(fat_type: FatType, total_bytes: u64, bytes_per_sector: u16) -> u32 {
    let mebibyte = 1024 * 1024;
    let gibibyte = 1024 * 1024 * 1024;
    let size = match fat_type {
        FatType::Fat12 => next_power_of_two(total_bytes) / mebibyte * 512,
        FatType::Fat16 => {
            if total_bytes <= 16 * mebibyte {
                1024
            } else if total_bytes <= 128 * mebibyte {
                2048
            } else {
                next_power_of_two(total_bytes) / (64 * mebibyte) * 1024
            }
        }
        FatType::Fat32 => {
            if total_bytes <= 260 * mebibyte {
                512
            } else if total_bytes <= 8 * gibibyte {
                4096
            } else {
                next_power_of_two(total_bytes) / (2 * gibibyte) * 1024
            }
        }
    };
    size.clamp(u64::from(bytes_per_sector), u64::from(MAX_CLUSTER_SIZE)) as u32
}

fn next_power_of_two(value: u64) -> u64 {
    if value <= 1 {
        1
    } else {
        1u64 << (64 - (value - 1).leading_zeros())
    }
}

/// Find a cluster size for which `fatfs` will create `fat_type`.
///
/// The natural (Windows-compatible) size is tried first, then larger sizes
/// (FAT12/16 clusters are capped by the number of clusters) and finally smaller
/// ones (FAT32 needs a small cluster size on small volumes).
fn cluster_size_for(fat_type: FatType, total_sectors: u32, bytes_per_sector: u16) -> Option<u32> {
    let total_bytes = u64::from(total_sectors) * u64::from(bytes_per_sector);
    let start = default_cluster_size(fat_type, total_bytes, bytes_per_sector);

    let mut candidates = Vec::new();
    let mut size = start;
    while size <= MAX_CLUSTER_SIZE {
        candidates.push(size);
        size *= 2;
    }
    let mut size = start / 2;
    while size >= MIN_CLUSTER_SIZE {
        candidates.push(size);
        size /= 2;
    }

    candidates.into_iter().find(|&bytes_per_cluster| {
        predict_fat_type(total_sectors, bytes_per_sector, bytes_per_cluster) == Some(fat_type)
    })
}

/// Convert a human readable volume label into the 11-byte FAT label field.
fn label_field(label: &str) -> Result<[u8; 11]> {
    let mut field = [b' '; 11];
    let label = label.trim();
    if label.is_empty() {
        return Ok(field);
    }
    let illegal = ['"', '*', '+', ',', '/', ':', ';', '<', '=', '>', '?', '[', '\\', ']', '|'];
    let characters: Vec<char> = label.chars().collect();
    if characters.len() > field.len() {
        return Err(Error::InvalidParameter(format!(
            "volume label {label:?} is longer than {} characters",
            field.len()
        )));
    }
    for (index, character) in characters.iter().enumerate() {
        if !character.is_ascii() || illegal.contains(character) {
            return Err(Error::InvalidParameter(format!(
                "volume label {label:?} contains a character that cannot be stored in a FAT label"
            )));
        }
        field[index] = character.to_ascii_uppercase() as u8;
    }
    Ok(field)
}

fn fatfs_error(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::InvalidInput => Error::InvalidParameter(format!("FAT filesystem: {error}")),
        _ => Error::Io(error),
    }
}

/// Implementation of [`crate::format_volume`].
pub fn format_volume(volume: &mut Volume, kind: FatKind, label: &str) -> Result<()> {
    let data_size = volume.data_size;
    if data_size < u64::from(SECTOR_SIZE as u32) {
        return Err(Error::InvalidParameter(format!(
            "volume data area is too small to hold a filesystem ({data_size} bytes)"
        )));
    }
    if data_size % u64::from(SECTOR_SIZE as u32) != 0 {
        return Err(Error::InvalidParameter(format!(
            "volume data area size {data_size} is not a multiple of the {SECTOR_SIZE} byte sector size"
        )));
    }
    let total_sectors = data_size / u64::from(SECTOR_SIZE as u32);
    let Ok(total_sectors) = u32::try_from(total_sectors) else {
        return Err(Error::InvalidParameter(format!(
            "volume data area ({data_size} bytes) has too many sectors for FAT"
        )));
    };

    let bytes_per_sector = SECTOR_SIZE as u16;
    let mut options = FormatVolumeOptions::new()
        .bytes_per_sector(bytes_per_sector)
        .total_sectors(total_sectors);
    let label = label_field(label)?;
    if label != [b' '; 11] {
        options = options.volume_label(label);
    }

    // Pick the cluster size that produces the requested FAT type. `Auto` prefers
    // FAT16 (what VeraCrypt uses for containers up to ~2 GiB) and falls back to
    // FAT32; for volumes too small for either we leave the choice to `fatfs`.
    let chosen = match kind {
        FatKind::Auto => cluster_size_for(FatType::Fat16, total_sectors, bytes_per_sector)
            .map(|size| (FatType::Fat16, size))
            .or_else(|| cluster_size_for(FatType::Fat32, total_sectors, bytes_per_sector).map(|size| (FatType::Fat32, size))),
        FatKind::Fat16 => Some((
            FatType::Fat16,
            cluster_size_for(FatType::Fat16, total_sectors, bytes_per_sector).ok_or_else(|| {
                Error::InvalidParameter(format!(
                    "a {data_size} byte volume cannot hold a FAT16 filesystem (needs 2 MiB..2 GiB)"
                ))
            })?,
        )),
        FatKind::Fat32 => Some((
            FatType::Fat32,
            cluster_size_for(FatType::Fat32, total_sectors, bytes_per_sector).ok_or_else(|| {
                Error::InvalidParameter(format!(
                    "a {data_size} byte volume cannot hold a FAT32 filesystem (needs ~35 MiB..2 TiB)"
                ))
            })?,
        )),
    };
    if let Some((fat_type, bytes_per_cluster)) = chosen {
        options = options.fat_type(fat_type).bytes_per_cluster(bytes_per_cluster);
    }

    // Everything below goes through the encrypted volume: `VolumeDevice` buffers
    // whole 512 byte sectors (fatfs issues arbitrary byte-granular I/O) and
    // encrypts them on the way out.
    let device = VolumeDevice::new(&mut *volume);
    fatfs::format_volume(device.clone(), options).map_err(fatfs_error)?;

    // Read the filesystem back to confirm (and report) what was really created.
    let filesystem = FileSystem::new(device.clone(), FsOptions::new()).map_err(fatfs_error)?;
    log::info!(
        "formatted a {} byte volume data area as {:?} with {} byte clusters ({} sectors)",
        data_size,
        filesystem.fat_type(),
        filesystem.cluster_size(),
        total_sectors
    );
    filesystem.unmount().map_err(fatfs_error)?;

    // Write the cached sectors through the encryption layer and fsync the host
    // file so the formatting is durable.
    device.sync().map_err(fatfs_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BPS: u16 = 512;

    fn sectors(bytes: u64) -> u32 {
        (bytes / u64::from(BPS)) as u32
    }

    #[test]
    fn a_4_mib_volume_becomes_fat16() {
        let total = sectors(4 * 1024 * 1024);
        let cluster_size = cluster_size_for(FatType::Fat16, total, BPS).unwrap();
        assert_eq!(cluster_size, 512);
        assert_eq!(predict_fat_type(total, BPS, cluster_size), Some(FatType::Fat16));
    }

    #[test]
    fn a_large_volume_cannot_be_fat16() {
        let total = sectors(8 * 1024 * 1024 * 1024);
        assert_eq!(cluster_size_for(FatType::Fat16, total, BPS), None);
    }

    #[test]
    fn a_40_mib_volume_can_be_fat32() {
        let total = sectors(40 * 1024 * 1024);
        let cluster_size = cluster_size_for(FatType::Fat32, total, BPS).unwrap();
        assert_eq!(predict_fat_type(total, BPS, cluster_size), Some(FatType::Fat32));
    }

    #[test]
    fn labels_are_upper_cased_and_validated() {
        assert_eq!(label_field("vault").unwrap(), *b"VAULT      ");
        assert_eq!(label_field("").unwrap(), *b"           ");
        assert!(label_field("twelve-chars").is_err());
        assert!(label_field("bad:label").is_err());
    }
}
