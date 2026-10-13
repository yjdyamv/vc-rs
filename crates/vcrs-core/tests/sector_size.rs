//! Volume sector size: VeraCrypt records it in the header (512..4096, a multiple of
//! 512) and the filesystem inside is expected to match it.  The *crypto* is
//! unaffected: XTS data units are always 512 bytes, so a 4096-byte-sector volume
//! is encrypted exactly like a 512-byte-sector one (verified by
//! `src/Volume/EncryptionModeXTS.cpp`: `sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE`).

use std::path::PathBuf;

use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, Prf};

const PASSWORD: &[u8] = b"sector-size-password";
const PIM: i32 = 1;
const HOST_SIZE: u64 = 2 * 1024 * 1024;

fn temp(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("vcrs-{name}.vc"));
    let _ = std::fs::remove_file(&path);
    path
}

fn options(sector_size: u32) -> CreateOptions {
    CreateOptions {
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        password: PASSWORD.to_vec(),
        keyfiles: Vec::new(),
        pim: PIM,
        sector_size,
        full_format: false,
        sparse: false,
    }
}

fn open_options() -> OpenOptions {
    OpenOptions {
        password: PASSWORD.to_vec(),
        pim: PIM,
        ..Default::default()
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u64 * 31 + seed as u64 * 7) % 251) as u8)
        .collect()
}

#[test]
fn a_4096_byte_sector_volume_round_trips() {
    let path = temp("sector-4096");
    let volume = Volume::create(&path, HOST_SIZE, &options(4096)).unwrap();
    assert_eq!(volume.header.sector_size, 4096);
    assert_eq!(volume.data_size, HOST_SIZE - 262144);

    // A whole 4096-byte sector and a single 512-byte data unit both work: the
    // alignment rule is the 512-byte data unit, not the volume sector size.
    let sector = pattern(4096, 3);
    let unit = pattern(512, 9);
    volume.write_data(0, &sector).unwrap();
    volume.write_data(4096, &unit).unwrap();
    volume.flush().unwrap();
    drop(volume);

    let volume = Volume::open(&path, &open_options()).unwrap();
    assert_eq!(volume.header.sector_size, 4096);
    let mut read = vec![0u8; 4096];
    volume.read_data(0, &mut read).unwrap();
    assert_eq!(read, sector);
    let mut read = vec![0u8; 512];
    volume.read_data(4096, &mut read).unwrap();
    assert_eq!(read, unit);

    std::fs::remove_file(path).ok();
}

#[test]
fn the_data_area_is_xts_at_512_byte_units_regardless_of_the_sector_size() {
    // VeraCrypt computes the XTS data-unit number as `offset / 512` even for a
    // 4096-byte-sector volume (EncryptionModeXTS.cpp), so the ciphertext on disk
    // has to be exactly what XTS produces for unit 256 over the data area.
    let path = temp("sector-units");
    let plaintext = pattern(8192, 5);
    let mut volume = Volume::create(&path, HOST_SIZE, &options(4096)).unwrap();
    let master_key = volume.header.data_key().to_vec();
    volume.write_data(0, &plaintext).unwrap();
    volume.flush().unwrap();
    drop(volume);

    let mut expected = plaintext.clone();
    vcrs_core::Xts::new(EncryptionAlgorithm::Aes, &master_key)
        .unwrap()
        .encrypt(&mut expected, 131072 / 512)
        .unwrap();
    let on_disk = vcrs_core::volume::read_region(&path, 131072, 8192).unwrap();
    assert_eq!(
        on_disk, expected,
        "the data unit number must not depend on the sector size"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn an_invalid_sector_size_is_refused() {
    for bad in [0u32, 256, 600, 4097, 8192] {
        let path = temp("sector-bad");
        let err = Volume::create(&path, HOST_SIZE, &options(bad))
            .expect_err("an invalid sector size must not be accepted");
        assert!(
            err.to_string().contains("sector size must be 512..4096"),
            "unexpected error for {bad}: {err}"
        );
        assert!(!path.exists(), "nothing may be created for an invalid sector size");
    }
}
