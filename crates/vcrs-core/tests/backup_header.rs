//! Backup header recovery test.
//!
//! Every V2 volume carries a second copy of its header at the end of the host file
//! (`host_size - 131072` for a normal volume), encrypted with a *fresh salt* so that
//! even the salt differs from the primary header. If the primary header is damaged,
//! `use_backup_header: true` must still open the volume and see the same data.

use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, Prf, VolumeType};

const HOST_SIZE: u64 = 1024 * 1024;
const BACKUP_HEADER_OFFSET: u64 = HOST_SIZE - 131072;

fn options() -> CreateOptions {
    CreateOptions {
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        password: b"backup-password".to_vec(),
        pim: 0,
        keyfiles: Vec::new(),
        sector_size: 512,
        full_format: false,
        sparse: false,
    }
}

fn open_password() -> OpenOptions {
    OpenOptions {
        password: b"backup-password".to_vec(),
        pim: 0,
        volume_type: None,
        use_backup_header: false,
        ..Default::default()
    }
}

#[test]
fn backup_header_recovers_a_damaged_volume() -> vcrs_core::Result<()> {
    let mut path = std::env::temp_dir();
    path.push("vcrs-backup-recovery.vc");
    let _ = std::fs::remove_file(&path);

    let volume = Volume::create(&path, HOST_SIZE, &options())?;
    assert_eq!(volume.header.volume_type, VolumeType::Normal);
    assert_eq!(volume.data_offset, 131072);
    assert_eq!(volume.data_size, HOST_SIZE - 262144);

    let marker = vec![0x3cu8; 4096];
    volume.write_data(0, &marker)?;
    volume.flush()?;
    let primary_salt = volume.header.salt.clone();
    let primary_key = volume.header.master_key.clone();
    drop(volume);

    // The backup header sits at the END of the file and uses its own random salt.
    let backup_salt = vcrs_core::volume::read_region(&path, BACKUP_HEADER_OFFSET, 64)?;
    assert_ne!(
        backup_salt.as_slice(),
        primary_salt.as_slice(),
        "the backup header must be encrypted with a freshly derived header key"
    );

    // Opening normally uses the primary header and still works.
    let opened = Volume::open(&path, &open_password())?;
    assert_eq!(opened.header.master_key, primary_key);

    // Now destroy the primary header (and the fake hidden header next to it) the way
    // a wiped sector or a stray write would.
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&path)?;
        use std::io::{Seek, SeekFrom, Write};
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&vec![0u8; 131072])?;
        f.flush()?;
    }

    // The primary header is gone: opening must fail...
    let err = Volume::open(&path, &open_password()).unwrap_err();
    assert!(
        matches!(err, vcrs_core::Error::PasswordIncorrect),
        "expected PasswordIncorrect for a wiped primary header, got {err:?}"
    );

    // ...but the backup header recovers the volume, data included.
    let mut opts = open_password();
    opts.use_backup_header = true;
    let recovered = Volume::open(&path, &opts)?;
    assert_eq!(recovered.header.master_key, primary_key, "backup header master key differs");
    assert_eq!(recovered.data_offset, 131072);
    assert_eq!(recovered.data_size, HOST_SIZE - 262144);
    let mut back = vec![0u8; marker.len()];
    recovered.read_data(0, &mut back)?;
    assert_eq!(back, marker, "data unreadable through the backup header");

    std::fs::remove_file(&path).ok();
    Ok(())
}
