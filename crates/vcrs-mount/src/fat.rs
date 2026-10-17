//! Creating the FAT32 filesystem inside a volume's data area.
//!
//! FAT32 is the only filesystem vc-rs creates: it is the only FAT that is not
//! limited to a size nobody uses any more (FAT12 stops at 16 MiB, FAT16 at
//! 2 GiB), and Windows, macOS and Linux all read it. A volume whose data area is
//! too small for FAT32 is refused rather than silently given a lower FAT.
//!
//! `fatfs::format_volume` writes a BPB whose FAT type is *derived from the
//! cluster count* (`FatType::from_clusters`), not from the requested
//! `FormatVolumeOptions::fat_type` — that option only selects a default cluster
//! size. To be sure the result is FAT32, [`cluster_size_for_fat32`] picks a
//! cluster size for which `fatfs` derives FAT32, using the same arithmetic
//! `fatfs` uses internally (`determine_fs_geometry`), and `format_volume` reads
//! the filesystem back and fails if `fatfs` disagreed.

use std::io;

use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use vcrs_core::{error::Error, volume::Volume};

use crate::{
    device::{VolumeDevice, SECTOR_SIZE},
    Result,
};

/// Number of FAT copies `fatfs` creates.
const FATS: u32 = 2;
/// Reserved sectors `fatfs` uses for FAT32 (`fatfs` uses 1 for FAT12/16).
const FAT32_RESERVED_SECTORS: u32 = 8;
/// Bits per FAT entry for FAT32.
const FAT32_BITS_PER_ENTRY: u32 = 32;
/// The cluster count from which the FAT specification (and `fatfs`) calls a
/// filesystem FAT32.
const FAT32_MIN_CLUSTERS: u32 = 65_525;
/// The largest cluster count `fatfs` accepts for FAT32 (`max_clusters`).
const FAT32_MAX_CLUSTERS: u32 = 0x0FFF_FFF4;

/// Smallest cluster size `fatfs` accepts.
const MIN_CLUSTER_SIZE: u32 = 512;
/// Largest cluster size `fatfs` accepts.
const MAX_CLUSTER_SIZE: u32 = 32 * 1024;

/// Would `fatfs` create a FAT32 filesystem for this cluster size?
///
/// `fatfs` computes the geometry for the requested type and then *rejects it*
/// unless the cluster count it ends up with really is that type, so a cluster
/// size can only be used when the arithmetic below lands in the FAT32 range.
fn fits_fat32(total_sectors: u32, bytes_per_sector: u16, bytes_per_cluster: u32) -> bool {
    let bytes_per_sector = u32::from(bytes_per_sector);
    if bytes_per_cluster < bytes_per_sector || !bytes_per_cluster.is_multiple_of(bytes_per_sector) {
        return false;
    }
    let sectors_per_cluster = bytes_per_cluster / bytes_per_sector;
    if total_sectors <= FAT32_RESERVED_SECTORS + 8 {
        return false;
    }
    let data_and_fat = total_sectors - FAT32_RESERVED_SECTORS;
    // fatfs: t2 = bits_per_cluster / bits_per_fat_entry + fats
    let t2 = (u64::from(sectors_per_cluster) * u64::from(bytes_per_sector) * 8)
        / u64::from(FAT32_BITS_PER_ENTRY)
        + u64::from(FATS);
    let sectors_per_fat =
        (u64::from(data_and_fat) + u64::from(sectors_per_cluster) * 2).div_ceil(t2);
    let Ok(sectors_per_fat) = u32::try_from(sectors_per_fat) else {
        return false;
    };
    let Some(data_sectors) = data_and_fat.checked_sub(sectors_per_fat * FATS) else {
        return false;
    };
    let total_clusters = data_sectors / sectors_per_cluster;
    (FAT32_MIN_CLUSTERS..=FAT32_MAX_CLUSTERS).contains(&total_clusters)
}

/// `fatfs`'s automatic cluster size rule for FAT32
/// (`determine_bytes_per_cluster`), used as the starting point of the search for
/// a size that yields FAT32.
fn default_cluster_size(total_bytes: u64, bytes_per_sector: u16) -> u32 {
    let mebibyte = 1024 * 1024;
    let gibibyte = 1024 * 1024 * 1024;
    let size = if total_bytes <= 260 * mebibyte {
        512
    } else if total_bytes <= 8 * gibibyte {
        4096
    } else {
        next_power_of_two(total_bytes) / (2 * gibibyte) * 1024
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

/// Find a cluster size for which `fatfs` will create FAT32, or `None` when no
/// cluster size can (the volume is too small for 65 525 clusters).
///
/// The natural (Windows-compatible) size is tried first, then larger sizes (a
/// large volume needs big clusters to stay under FAT32's cluster limit) and
/// finally smaller ones (a small volume needs small clusters to reach the
/// minimum cluster count).
fn cluster_size_for_fat32(total_sectors: u32, bytes_per_sector: u16) -> Option<u32> {
    let total_bytes = u64::from(total_sectors) * u64::from(bytes_per_sector);
    let start = default_cluster_size(total_bytes, bytes_per_sector);

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

    candidates
        .into_iter()
        .find(|&bytes_per_cluster| fits_fat32(total_sectors, bytes_per_sector, bytes_per_cluster))
}

/// Convert a human readable volume label into the 11-byte FAT label field.
fn label_field(label: &str) -> Result<[u8; 11]> {
    let mut field = [b' '; 11];
    let label = label.trim();
    if label.is_empty() {
        return Ok(field);
    }
    let illegal = [
        '"', '*', '+', ',', '/', ':', ';', '<', '=', '>', '?', '[', '\\', ']', '|',
    ];
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
pub fn format_volume(volume: &mut Volume, label: &str) -> Result<()> {
    let data_size = volume.data_size;
    if data_size < u64::from(SECTOR_SIZE as u32) {
        return Err(Error::InvalidParameter(format!(
            "volume data area is too small to hold a filesystem ({data_size} bytes)"
        )));
    }
    if !data_size.is_multiple_of(u64::from(SECTOR_SIZE as u32)) {
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
    let Some(bytes_per_cluster) = cluster_size_for_fat32(total_sectors, bytes_per_sector) else {
        return Err(Error::InvalidParameter(format!(
            "a {data_size} byte volume data area is too small for FAT32: it needs at least \
             {FAT32_MIN_CLUSTERS} clusters, so with {MIN_CLUSTER_SIZE} byte clusters at least {} bytes",
            u64::from(FAT32_MIN_CLUSTERS) * u64::from(MIN_CLUSTER_SIZE)
        )));
    };

    let mut options = FormatVolumeOptions::new()
        .bytes_per_sector(bytes_per_sector)
        .total_sectors(total_sectors)
        .fat_type(FatType::Fat32)
        .bytes_per_cluster(bytes_per_cluster);
    let label = label_field(label)?;
    if label != [b' '; 11] {
        options = options.volume_label(label);
    }

    // Everything below goes through the encrypted volume: `VolumeDevice` buffers
    // whole 512 byte sectors (fatfs issues arbitrary byte-granular I/O) and
    // encrypts them on the way out.
    let device = VolumeDevice::new(&mut *volume);
    fatfs::format_volume(device.clone(), options).map_err(fatfs_error)?;

    // Read the filesystem back to confirm (and report) what was really created.
    let filesystem = FileSystem::new(device.clone(), FsOptions::new()).map_err(fatfs_error)?;
    let fat_type = filesystem.fat_type();
    let cluster_size = filesystem.cluster_size();
    filesystem.unmount().map_err(fatfs_error)?;

    // Write the cached sectors through the encryption layer and fsync the host
    // file so the formatting is durable.
    device.sync().map_err(fatfs_error)?;

    // `fatfs` derives the type from the cluster count, so a mismatch means the
    // search above and `fatfs` disagree: report it instead of handing back a
    // filesystem of a type vc-rs does not promise.
    if fat_type != FatType::Fat32 {
        return Err(Error::InvalidParameter(format!(
            "the filesystem created in a {data_size} byte volume data area is {fat_type:?}, \
             not FAT32 (the volume was left formatted)"
        )));
    }

    log::info!(
        "formatted a {data_size} byte volume data area as FAT32 with {cluster_size} byte clusters \
         ({total_sectors} sectors)"
    );
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
    fn fat32_needs_about_thirty_three_mebibytes() {
        // 65 525 clusters of 512 bytes is the specification's minimum, so
        // anything below ~33 MiB cannot be FAT32 with any cluster size.
        for mib in [1u64, 8, 16, 32] {
            assert_eq!(
                cluster_size_for_fat32(sectors(mib * 1024 * 1024), BPS),
                None,
                "{mib} MiB is too small for FAT32"
            );
        }
        for mib in [33u64, 40, 100, 512] {
            let cluster_size = cluster_size_for_fat32(sectors(mib * 1024 * 1024), BPS)
                .unwrap_or_else(|| panic!("{mib} MiB must be enough for FAT32"));
            assert!(
                fits_fat32(sectors(mib * 1024 * 1024), BPS, cluster_size),
                "{mib} MiB must be FAT32 with {cluster_size} byte clusters"
            );
        }
    }

    #[test]
    fn a_large_volume_gets_larger_clusters() {
        // 512 MiB is past the 260 MiB step of fatfs' automatic rule, so the
        // cluster size must grow rather than the cluster count run away.
        let total = sectors(512 * 1024 * 1024);
        let cluster_size = cluster_size_for_fat32(total, BPS).unwrap();
        assert!(
            cluster_size > 512,
            "a 512 MiB volume should use {cluster_size} byte clusters"
        );
        assert!(fits_fat32(total, BPS, cluster_size));
    }

    #[test]
    fn labels_are_upper_cased_and_validated() {
        assert_eq!(label_field("vault").unwrap(), *b"VAULT      ");
        assert_eq!(label_field("").unwrap(), *b"           ");
        assert!(label_field("twelve-chars").is_err());
        assert!(label_field("bad:label").is_err());
    }
}
