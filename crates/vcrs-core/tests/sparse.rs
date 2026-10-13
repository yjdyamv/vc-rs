//! Sparse ("dynamic") containers: `CreateOptions::sparse` marks the host file
//! as sparse, so a quick-formatted container only occupies the space that is
//! actually written -- VeraCrypt's "dynamic volume" checkbox.

use std::path::PathBuf;

use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, Error, Prf};

const PASSWORD: &[u8] = b"sparse-password";
const PIM: i32 = 1;
const HOST_SIZE: u64 = 4 * 1024 * 1024;

fn temp(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("vcrs-sparse-{name}.vc"));
    let _ = std::fs::remove_file(&path);
    path
}

fn options(sparse: bool) -> CreateOptions {
    CreateOptions {
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        password: PASSWORD.to_vec(),
        keyfiles: Vec::new(),
        pim: PIM,
        sector_size: 512,
        full_format: false,
        sparse,
    }
}

fn open_options() -> OpenOptions {
    OpenOptions {
        password: PASSWORD.to_vec(),
        pim: PIM,
        ..Default::default()
    }
}

#[test]
fn a_sparse_container_round_trips() {
    let path = temp("round-trip");
    let volume = Volume::create(&path, HOST_SIZE, &options(true)).unwrap();
    assert_eq!(volume.data_size, HOST_SIZE - 262144);

    // A write into a sparse container has to allocate that part of the file and
    // read back unchanged, like any other container.
    let data = [0x5au8; 4096];
    volume.write_data(0, &data).unwrap();
    volume.write_data(volume.data_size - 4096, &data).unwrap();
    volume.flush().unwrap();
    drop(volume);

    let volume = Volume::open(&path, &open_options()).unwrap();
    let mut read = vec![0u8; data.len()];
    volume.read_data(0, &mut read).unwrap();
    assert_eq!(read, data);
    volume.read_data(volume.data_size - 4096, &mut read).unwrap();
    assert_eq!(read, data);
    drop(volume);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_sparse_container_cannot_be_full_formatted() {
    let path = temp("full-format");
    let mut options = options(true);
    options.full_format = true;
    let error = Volume::create(&path, HOST_SIZE, &options).unwrap_err();
    assert!(matches!(error, Error::InvalidParameter(_)), "{error}");
    assert!(error.to_string().contains("quick-formatted"), "{error}");
    let _ = std::fs::remove_file(&path);
}

/// The point of a sparse container: the file's length is the full volume size,
/// but the space it really occupies stays down at the header regions.
#[cfg(windows)]
#[test]
fn a_sparse_container_uses_little_disk_space() {
    let path = temp("size-on-disk");
    let volume = Volume::create(&path, HOST_SIZE, &options(true)).unwrap();
    drop(volume);

    let length = std::fs::metadata(&path).unwrap().len();
    assert_eq!(length, HOST_SIZE, "the length is the volume's full size");
    let on_disk = size_on_disk(&path).unwrap();
    assert!(
        on_disk < HOST_SIZE / 4,
        "a 4 MiB sparse container should occupy far less than that, got {on_disk} bytes"
    );
    let _ = std::fs::remove_file(&path);
}

/// `GetCompressedFileSizeW` reports the disk space the file really uses, i.e.
/// whether the sparse flag was accepted.
#[cfg(windows)]
fn size_on_disk(path: &std::path::Path) -> std::io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCompressedFileSizeW(file: *const u16, high: *mut u32) -> u32;
    }

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut high = 0u32;
    let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
    if low == 0xFFFF_FFFF {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(0) {
            return Err(error);
        }
    }
    Ok(((high as u64) << 32) | low as u64)
}
