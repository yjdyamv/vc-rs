//! VeraCrypt's "Preserve modification timestamp of file containers": using a
//! container must not reveal *when* it was used, so `OpenOptions::preserve_timestamps`
//! freezes the host file's timestamps before the header is read and writes them
//! back when the volume (and with it the file handle) is closed.
//!
//! The freeze itself is the Windows `FILETIME` sentinel (`-1` = "do not update
//! this timestamp"), which is what VeraCrypt's driver uses in
//! `src/Driver/Ntvol.c`, so these tests are Windows-only.
//!
//! The order matters and is what these tests pin down: a filesystem records the
//! access when the first read happens, and no later "do not update" flag takes
//! that back -- so a container opened *without* the flag, then frozen, keeps a
//! fresh access time (measured on this machine before the flag was moved into
//! `Volume::open`).
#![cfg(windows)]

use std::fs::FileTimes;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, Prf};

const PASSWORD: &[u8] = b"timestamps-password";
const PIM: i32 = 1;
const HOST_SIZE: u64 = 1024 * 1024;

fn temp(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("vcrs-timestamps-{name}.vc"));
    let _ = std::fs::remove_file(&path);
    path
}

fn options() -> CreateOptions {
    CreateOptions {
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        password: PASSWORD.to_vec(),
        keyfiles: Vec::new(),
        pim: PIM,
        sector_size: 512,
        full_format: false,
        sparse: false,
        random_source: None,
    }
}

fn open_options() -> OpenOptions {
    OpenOptions {
        password: PASSWORD.to_vec(),
        pim: PIM,
        ..Default::default()
    }
}

/// The options the CLI and the iSCSI mount use.
fn preserving_options() -> OpenOptions {
    OpenOptions {
        preserve_timestamps: true,
        ..open_options()
    }
}

/// Something clearly in the past, so that a write's "now" is easy to tell apart.
fn the_past() -> SystemTime {
    SystemTime::now() - Duration::from_secs(30 * 24 * 3600)
}

fn set_times(path: &Path, when: SystemTime) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    let times = FileTimes::new().set_modified(when).set_accessed(when);
    file.set_times(times).unwrap();
}

/// The container's (modified, accessed) times.
fn times(path: &Path) -> (SystemTime, SystemTime) {
    let metadata = std::fs::metadata(path).unwrap();
    (
        metadata.modified().unwrap(),
        metadata.accessed().unwrap(),
    )
}

#[test]
fn a_container_opened_with_preserve_timestamps_keeps_both_times() {
    let path = temp("frozen");
    Volume::create(&path, HOST_SIZE, &options()).unwrap();
    let past = the_past();
    set_times(&path, past);
    assert_eq!(times(&path), (past, past));

    let volume = Volume::open(&path, &preserving_options()).unwrap();
    volume.write_data(0, &[0x42; 4096]).unwrap();
    volume.flush().unwrap();
    assert_eq!(
        times(&path).0,
        past,
        "a write to a preserved container must not move the modification time"
    );
    assert_eq!(
        times(&path).1,
        past,
        "and reading the header must not move the access time either"
    );

    drop(volume);
    assert_eq!(
        times(&path),
        (past, past),
        "closing the handle must not flush a queued access time"
    );

    // The write itself still has to be there.
    let volume = Volume::open(&path, &open_options()).unwrap();
    let mut read = vec![0u8; 4096];
    volume.read_data(0, &mut read).unwrap();
    assert_eq!(read, [0x42; 4096]);
    drop(volume);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn without_the_flag_a_write_moves_the_modification_time() {
    // The control case for the test above: if this ever stops holding, the
    // preservation test proves nothing.
    let path = temp("unfrozen");
    Volume::create(&path, HOST_SIZE, &options()).unwrap();
    let past = the_past();
    set_times(&path, past);

    let volume = Volume::open(&path, &open_options()).unwrap();
    volume.write_data(0, &[0x11; 4096]).unwrap();
    volume.flush().unwrap();
    drop(volume);

    assert_ne!(
        times(&path).0,
        past,
        "the filesystem records the write time when nothing preserves it"
    );
    let _ = std::fs::remove_file(&path);
}
