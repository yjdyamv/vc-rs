//! Integration test for the block device glue behind the mount layer.
//!
//! It never talks to a filesystem framework (which would need an elevated shell
//! and a driver): instead it drives `fatfs` directly over a [`VolumeDevice`]
//! backed by a real, encrypted VeraCrypt-compatible container and checks that
//! the bytes survive the round trip through format -> write -> reopen -> read.

use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use fatfs::{FatType, FileSystem, FsOptions};
use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_mount::{format_volume, FatKind, VolumeDevice, SECTOR_SIZE};

const PASSWORD: &[u8] = b"test-password";
const MARKER: &[u8] = b"VC-RS-FAT-ROUNDTRIP";

/// A container file in the system temp directory that is deleted on drop, even
/// when an assertion fails.
struct TempVolume {
    path: PathBuf,
}

impl TempVolume {
    fn new(tag: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("vcrs-mount-{tag}-{}-{unique}.vc", std::process::id()));
        let _ = fs::remove_file(&path);
        TempVolume { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempVolume {
    fn drop(&mut self) {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => eprintln!("could not delete {}: {error}", self.path.display()),
        }
    }
}

/// Deterministic, non-repeating test data (a xorshift stream, so a stale sector
/// or a broken offset shows up as a mismatch).
fn pattern(length: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut data = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.push((state >> 24) as u8);
    }
    data
}

fn create_options() -> CreateOptions {
    CreateOptions { password: PASSWORD.to_vec(), ..CreateOptions::default() }
}

fn open_options() -> OpenOptions {
    OpenOptions { password: PASSWORD.to_vec(), ..OpenOptions::default() }
}

/// The same numbers a mount handler would report as free space.
fn free_bytes(filesystem: &FileSystem<VolumeDevice<Volume>>) -> u64 {
    let stats = filesystem.stats().expect("stats");
    u64::from(stats.cluster_size()) * u64::from(stats.free_clusters())
}

fn read_whole_file(filesystem: &FileSystem<VolumeDevice<Volume>>, path: &str) -> Vec<u8> {
    let mut file = filesystem.root_dir().open_file(path).expect("open file");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("read file");
    data
}

/// Format a 4 MiB volume, write files through `fatfs`, then reopen the volume
/// from scratch and verify the contents.
#[test]
fn fat_filesystem_round_trips_through_the_encrypted_volume() {
    const VOLUME_SIZE: u64 = 4 * 1024 * 1024;

    let container = TempVolume::new("roundtrip");
    let mut volume = Volume::create(container.path(), VOLUME_SIZE, &create_options()).expect("create volume");
    assert_eq!(volume.data_size % SECTOR_SIZE as u64, 0, "the FAT region must be sector aligned");
    assert!(volume.data_size >= VOLUME_SIZE - 512 * 1024);

    format_volume(&mut volume, FatKind::Auto, "TESTVOL").expect("format the volume");
    volume.flush().expect("flush the volume");
    drop(volume);

    let payload = [MARKER, &pattern(4096 + 123)].concat();
    let inner_payload = pattern(4096 - 7);

    // --- first mount: write the files ------------------------------------
    let volume = Volume::open(container.path(), &open_options()).expect("reopen the volume");
    let device = VolumeDevice::new(volume);
    let filesystem = FileSystem::new(device.clone(), FsOptions::new()).expect("mount the FAT filesystem");

    assert_eq!(filesystem.fat_type(), FatType::Fat16, "a 4 MiB volume is FAT16");
    assert_eq!(filesystem.volume_label().trim(), "TESTVOL");
    let free_before = free_bytes(&filesystem);
    assert!(free_before > 3 * 1024 * 1024, "a fresh 4 MiB volume should be mostly free");

    let root = filesystem.root_dir();
    let mut file = root.create_file("roundtrip.bin").expect("create roundtrip.bin");
    file.write_all(&payload).expect("write roundtrip.bin");
    file.flush().expect("flush the file");
    drop(file);

    let subdir = root.create_dir("SUBDIR").expect("create SUBDIR");
    let mut nested = subdir.create_file("inner.bin").expect("create SUBDIR/inner.bin");
    nested.write_all(&inner_payload).expect("write SUBDIR/inner.bin");
    nested.flush().expect("flush the file");
    // Rewriting a byte at a non-zero, non-sector-aligned offset must not
    // corrupt the rest of the file.
    nested.seek(SeekFrom::Start(4096 - 8)).expect("seek");
    nested.write_all(b"tail").expect("overwrite the tail");
    nested.flush().expect("flush the file");
    drop(nested);
    drop(subdir);
    drop(root);

    let names: Vec<String> = filesystem
        .root_dir()
        .iter()
        .map(|entry| entry.expect("directory entry").file_name())
        .collect();
    assert!(names.iter().any(|name| name == "roundtrip.bin"), "listing: {names:?}");
    assert!(names.iter().any(|name| name == "SUBDIR"), "listing: {names:?}");
    let free_after_write = free_bytes(&filesystem);
    assert!(free_after_write < free_before, "writing data must reduce the free space");

    // Writing 4 bytes at offset 4088 of a 4089-byte file extends it to 4092.
    let mut expected_inner = inner_payload[..4096 - 8].to_vec();
    expected_inner.extend_from_slice(b"tail");

    // `FileSystem::unmount` (called by `Drop`) flushes the FAT and the directory
    // entries through the device; `sync` pushes the cached sectors into the
    // container file.
    drop(filesystem);
    device.sync().expect("sync the device");
    drop(device);

    // --- second mount: the bytes must come back ---------------------------
    let volume = Volume::open(container.path(), &open_options()).expect("reopen the volume");
    let device = VolumeDevice::new(volume);
    let filesystem = FileSystem::new(device.clone(), FsOptions::new()).expect("mount the FAT filesystem");

    assert_eq!(read_whole_file(&filesystem, "roundtrip.bin"), payload);
    assert_eq!(read_whole_file(&filesystem, "SUBDIR/inner.bin"), expected_inner);
    assert!(free_bytes(&filesystem) <= free_before);
    // Reading through the manifest-dependent path proves the sector cache and
    // the FAT are consistent for a second, independent `fatfs` instance.
    let mut file = filesystem.root_dir().open_file("roundtrip.bin").expect("open");
    let mut tail = Vec::new();
    file.seek(SeekFrom::Start(payload.len() as u64 - 32)).expect("seek");
    file.read_to_end(&mut tail).expect("read the tail");
    assert_eq!(tail, payload[payload.len() - 32..]);
    drop(file);
    drop(filesystem);
    device.sync().expect("sync the device");
    drop(device);

    // --- the container must not contain plaintext -------------------------
    let mut raw = Vec::new();
    File::open(container.path())
        .expect("open the container")
        .read_to_end(&mut raw)
        .expect("read the container");
    assert_eq!(raw.len() as u64, VOLUME_SIZE);
    assert!(
        !contains(&raw, MARKER),
        "the plaintext marker was found in the container: the volume is not encrypted"
    );
    assert!(
        !contains(&raw, &payload[..64]),
        "plaintext file data was found in the container"
    );
}

/// The `FatKind` request must be honoured for both FAT types the UI offers.
#[test]
fn fat16_and_fat32_are_both_formatted_on_request() {
    // 40 MiB of data area needs more than 65525 clusters, so it is FAT32 with
    // any cluster size; 4 MiB is FAT16.
    for (kind, size, expected) in [
        (FatKind::Fat16, 4 * 1024 * 1024u64, FatType::Fat16),
        (FatKind::Fat32, 40 * 1024 * 1024u64, FatType::Fat32),
    ] {
        let container = TempVolume::new("kind");
        let mut volume = Volume::create(container.path(), size, &create_options()).expect("create volume");
        format_volume(&mut volume, kind, "KINDTEST").expect("format the volume");
        volume.flush().expect("flush the volume");
        drop(volume);

        let volume = Volume::open(container.path(), &open_options()).expect("reopen the volume");
        let device = VolumeDevice::new(volume);
        let filesystem = FileSystem::new(device.clone(), FsOptions::new()).expect("mount the FAT filesystem");
        assert_eq!(filesystem.fat_type(), expected, "{kind:?} on a {size} byte volume");
        assert_eq!(filesystem.volume_label().trim(), "KINDTEST");

        // A write big enough to cross clusters must work for both types.
        let root = filesystem.root_dir();
        let mut file = root.create_file("data.bin").expect("create data.bin");
        let payload = pattern(200_000);
        file.write_all(&payload).expect("write data.bin");
        drop(file);
        drop(root);
        drop(filesystem);
        device.sync().expect("sync the device");
        drop(device);

        let volume = Volume::open(container.path(), &open_options()).expect("reopen the volume");
        let device = VolumeDevice::new(volume);
        let filesystem = FileSystem::new(device.clone(), FsOptions::new()).expect("mount the FAT filesystem");
        assert_eq!(read_whole_file(&filesystem, "data.bin"), payload);
        drop(filesystem);
        device.sync().expect("sync the device");
    }
}

/// A volume that was never formatted must be reported, not guessed at.
#[test]
fn mounting_an_unformatted_volume_fails() {
    let container = TempVolume::new("unformatted");
    let volume = Volume::create(container.path(), 4 * 1024 * 1024, &create_options()).expect("create volume");
    let device = VolumeDevice::new(volume);
    assert!(
        FileSystem::new(device, FsOptions::new()).is_err(),
        "an unformatted data area must not look like a FAT filesystem"
    );
}

/// Formatting with an unsupported label must not silently produce something
/// else (the label is optional, so it is simply dropped).
#[test]
fn labels_are_sanitised() {
    let container = TempVolume::new("label");
    let mut volume = Volume::create(container.path(), 4 * 1024 * 1024, &create_options()).expect("create volume");
    format_volume(&mut volume, FatKind::Auto, "").expect("format without a label");
    volume.flush().expect("flush the volume");
    drop(volume);

    let volume = Volume::open(container.path(), &open_options()).expect("reopen the volume");
    let device = VolumeDevice::new(volume);
    let filesystem = FileSystem::new(device.clone(), FsOptions::new()).expect("mount the FAT filesystem");
    // fatfs substitutes the FAT default name for a volume without a label.
    assert!(
        matches!(filesystem.volume_label().trim(), "" | "NO NAME"),
        "unexpected label {:?}",
        filesystem.volume_label()
    );
    drop(filesystem);
    device.sync().expect("sync the device");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}
