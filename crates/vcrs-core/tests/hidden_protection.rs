//! Hidden-volume protection test.
//!
//! VeraCrypt can mount an *outer* volume while protecting a hidden volume that
//! lives inside it: writes that would land in the hidden volume's data area are
//! refused instead of silently destroying it (`src/Driver/EncryptedIoQueue.c`,
//! `bProtectHiddenVolume` / `bHiddenVolProtectionAction`).
//!
//! The rules verified here are VeraCrypt's:
//!   * the protected range is the hidden volume's data area, in host bytes
//!     (`hiddenVolumeOffset = hiddenHeader.EncryptedAreaStart`,
//!      `hiddenVolumeProtectedSize = hiddenHeader.VolumeDataSize`);
//!   * reads are never affected, only writes;
//!   * the first offending write fails, and from then on *every* write fails,
//!     so a filesystem that ignores the error cannot quietly corrupt the hidden
//!     volume (VeraCrypt deliberately fakes a failing device);
//!   * writes that do not overlap the range still work while no violation has
//!     happened.

use vcrs_core::volume::{CreateOptions, OpenOptions, ProtectedRange, Volume};
use vcrs_core::{EncryptionAlgorithm, Error, Prf, VolumeType};

const HOST_SIZE: u64 = 10 * 1024 * 1024;
const HIDDEN_SIZE: u64 = 4 * 1024 * 1024;
const SECTOR: u64 = 512;

fn dummy_path(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("vcrs-protect-{name}.vc"));
    p
}

fn options(password: &str) -> CreateOptions {
    CreateOptions {
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        password: password.as_bytes().to_vec(),
        pim: 0,
        keyfiles: Vec::new(),
        sector_size: 512,
        full_format: false,
        sparse: false,
        random_source: None,
    }
}

fn open_options(password: &str, hidden: bool) -> OpenOptions {
    OpenOptions {
        password: password.as_bytes().to_vec(),
        pim: 0,
        volume_type: if hidden { Some(VolumeType::Hidden) } else { None },
        ..Default::default()
    }
}

#[test]
fn writes_into_the_hidden_volume_are_refused() -> vcrs_core::Result<()> {
    let path = dummy_path("main");
    let _ = std::fs::remove_file(&path);

    // An outer volume with a marker, and a hidden volume with its own marker.
    let outer = Volume::create(&path, HOST_SIZE, &options("outer-password"))?;
    let outer_marker = [0xa5u8; 512];
    outer.write_data(0, &outer_marker)?;
    let hidden = Volume::create_hidden(&path, HIDDEN_SIZE, &options("hidden-password"))?;
    let hidden_marker = [0x5au8; 512];
    hidden.write_data(0, &hidden_marker)?;
    let hidden_range = ProtectedRange::new(hidden.data_offset, hidden.data_size);
    drop(hidden);

    // The outer volume is opened normally, with the hidden volume protected.
    let outer = Volume::open(&path, &open_options("outer-password", false))?;
    assert_eq!(outer.header.volume_type, VolumeType::Normal);
    assert!(!outer.protection_triggered());
    assert_eq!(outer.protected_range(), None);
    outer.protect_hidden_volume(hidden_range);
    assert_eq!(outer.protected_range(), Some(hidden_range));
    assert!(!outer.protection_triggered());

    // Reads of the protected area are allowed (VeraCrypt only guards writes).
    // The outer volume cannot decrypt the hidden volume's plaintext (different
    // master key, that is the point of a hidden volume), so what we check is
    // that the *host bytes* at the protected range never change.
    let mut before = vec![0u8; SECTOR as usize];
    outer.read_at(hidden_range.start, &mut before)?;
    assert_ne!(before, vec![0u8; SECTOR as usize], "the protected sector is not plaintext zeros");
    assert!(!outer.protection_triggered());

    // A write that stops right before the protected range is fine.
    outer.write_at(hidden_range.start - SECTOR, &[0x11u8; 512])?;
    assert!(!outer.protection_triggered());

    // A write that overlaps the protected range is refused ...
    let err = outer
        .write_at(hidden_range.start, &[0x22u8; 512])
        .expect_err("writing into the hidden volume must fail");
    match err {
        Error::HiddenVolumeProtected { offset, length, start, end } => {
            assert_eq!(offset, hidden_range.start);
            assert_eq!(length, SECTOR);
            assert_eq!(start, hidden_range.start);
            assert_eq!(end, hidden_range.start + hidden_range.length);
        }
        other => panic!("expected HiddenVolumeProtected, got {other:?}"),
    }
    assert!(outer.protection_triggered());

    // ... and from then on every write fails, even outside the protected range.
    let err = outer
        .write_at(outer.data_offset, &[0x33u8; 512])
        .expect_err("after a violation all writes must fail");
    assert!(matches!(err, Error::HiddenVolumeProtectionActive), "got {err:?}");

    // Even a write in the middle of the outer volume's own data area fails, and
    // the outer marker written before the violation is still there.
    let err = outer.write_data(1024 * 1024, &[0x44u8; 512]).expect_err("still protected");
    assert!(matches!(err, Error::HiddenVolumeProtectionActive), "got {err:?}");
    let mut marker = vec![0u8; SECTOR as usize];
    outer.read_data(0, &mut marker)?;
    assert_eq!(marker, outer_marker);

    // The data pages the failed writes targeted were not modified: the host
    // bytes at the protected range are byte-for-byte the ones from before.
    let mut after = vec![0u8; SECTOR as usize];
    outer.read_at(hidden_range.start, &mut after)?;
    assert_eq!(before, after, "the refused writes did not touch the hidden volume");
    drop(outer);

    // The hidden volume still opens normally and its marker is intact.
    let hidden = Volume::open(&path, &open_options("hidden-password", true))?;
    let mut marker = vec![0u8; SECTOR as usize];
    hidden.read_data(0, &mut marker)?;
    assert_eq!(marker, hidden_marker, "the hidden volume survived the refused writes");

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn a_partial_overlap_is_enough_to_trigger_protection() -> vcrs_core::Result<()> {
    let path = dummy_path("edge");
    let _ = std::fs::remove_file(&path);

    let outer = Volume::create(&path, HOST_SIZE, &options("outer-password"))?;
    let hidden = Volume::create_hidden(&path, HIDDEN_SIZE, &options("hidden-password"))?;
    let hidden_range = ProtectedRange::new(hidden.data_offset, hidden.data_size);
    drop(hidden);
    drop(outer);

    let outer = Volume::open(&path, &open_options("outer-password", false))?;
    outer.protect_hidden_volume(hidden_range);

    // Zero-length writes are always allowed: they cannot damage anything.
    assert!(outer.write_at(hidden_range.start - SECTOR, &[]).is_ok());
    assert!(!outer.protection_triggered());

    // A write that straddles the boundary (its last sector is the one before the
    // protected range, and it also covers the first protected sector) must
    // trigger protection, exactly like VeraCrypt's RegionsOverlap check.
    let err = outer
        .write_at(hidden_range.start - SECTOR, &[0x55u8; 1024])
        .expect_err("a straddling write must fail");
    assert!(matches!(err, Error::HiddenVolumeProtected { .. }), "got {err:?}");

    let _ = std::fs::remove_file(&path);
    Ok(())
}
