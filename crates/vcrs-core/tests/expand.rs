//! Container expansion test.
//!
//! VeraCrypt's Volume Expander (`src/ExpandVolume/ExpandVolume.c`) grows a
//! file-hosted *normal* volume in place:
//!
//!   * the host file is lengthened and the newly exposed area is filled with
//!     zeroes encrypted under a throwaway key (`FormatNoFs(bInitFreeSpace)`) so
//!     the free space looks like ciphertext;
//!   * the header's `VolumeDataSize`/`EncryptedAreaLength` are set to the new
//!     data area size, `EncryptedAreaStart` is unchanged, and the **master key
//!     stays the same** -- the existing data is never re-encrypted;
//!   * both the primary and the backup header are rewritten with *fresh* random
//!     salts, so the header key has to be derived from the password again;
//!   * the old backup header group, which is now in the middle of the data area,
//!     is overwritten.
//!
//! The filesystem itself is not touched: extending it is the operating system's
//! job, exactly as with VeraCrypt.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use vcrs_core::header::VOLUME_HEADER_GROUP_SIZE;
use vcrs_core::volume::{CreateOptions, OpenOptions, Volume, MIN_EXPAND_BYTES};
use vcrs_core::{EncryptionAlgorithm, Error, Prf, VolumeType};

const OLD_HOST: u64 = 10 * 1024 * 1024;
const NEW_HOST: u64 = 20 * 1024 * 1024;
const SALT: usize = 64;

fn dummy_path(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("vcrs-expand-{name}.vc"));
    p
}

fn options(password: &str) -> CreateOptions {
    CreateOptions {
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        password: password.as_bytes().to_vec(),
        pim: 1,
        keyfiles: Vec::new(),
        sector_size: 512,
        full_format: false,
        sparse: false,
        random_source: None,
    }
}

fn open_options(password: &str, backup: bool) -> OpenOptions {
    OpenOptions {
        password: password.as_bytes().to_vec(),
        pim: 1,
        use_backup_header: backup,
        ..Default::default()
    }
}

fn read_region(path: &std::path::Path, offset: u64, len: usize) -> vcrs_core::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn salt_of(region: &[u8]) -> Vec<u8> {
    region[..SALT].to_vec()
}

/// A run the user stops at a chunk boundary says `Interrupted` and leaves the
/// container describing its old size, so the same command can be run again. The
/// alternative would be a container that claims to be 20 MiB with most of it
/// still unwritten.
#[test]
fn a_stopped_expand_can_be_repeated() {
    let path = dummy_path("stopped");
    let mut volume = Volume::create(&path, OLD_HOST, &options("stopped")).expect("create");
    volume.flush().expect("flush");

    let mut calls = 0u32;
    let mut watcher = |_done: u64, _total: u64| {
        calls += 1;
        if calls == 1 {
            vcrs_core::Control::Continue
        } else {
            vcrs_core::Control::Stop
        }
    };
    let watch = vcrs_core::Watch::new(&mut watcher);
    let error = volume
        .expand_with_progress(NEW_HOST, b"stopped", 1, Some(watch))
        .expect_err("the watcher asked to stop");
    assert!(
        matches!(error, Error::Io(ref e) if e.kind() == std::io::ErrorKind::Interrupted),
        "{error}"
    );
    assert_eq!(
        volume.host_size, OLD_HOST,
        "the header still describes the old size"
    );

    // Nothing was torn: the same expand runs to the end now.
    volume.expand(NEW_HOST, b"stopped", 1).expect("expand");
    assert_eq!(volume.host_size, NEW_HOST);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn expanding_preserves_the_data_and_rewrites_both_headers() -> vcrs_core::Result<()> {
    let path = dummy_path("main");
    let _ = std::fs::remove_file(&path);

    let mut volume = Volume::create(&path, OLD_HOST, &options("expand-me"))?;
    let old_data_size = volume.data_size;
    let old_master_key = volume.header.master_key.clone();

    // A marker at the very start and one at the very end of the data area.
    let first = [0xa5u8; 512];
    let last = [0x5au8; 512];
    volume.write_data(0, &first)?;
    volume.write_data(old_data_size - 512, &last)?;
    volume.flush()?;

    let old_primary_salt = salt_of(&read_region(&path, 0, SALT)?);
    let old_backup_offset = OLD_HOST - VOLUME_HEADER_GROUP_SIZE;
    let old_backup_region = read_region(&path, old_backup_offset, 512)?;

    volume.expand(NEW_HOST, b"expand-me", 1)?;

    assert_eq!(volume.host_size, NEW_HOST);
    assert_eq!(volume.data_offset, 2 * 65536);
    assert_eq!(volume.data_size, NEW_HOST - 262144);
    assert_eq!(
        volume.header.master_key, old_master_key,
        "expanding must not change the master key"
    );
    assert_eq!(volume.header.encrypted_area_start, volume.data_offset);
    assert_eq!(volume.header.encrypted_area_length, volume.data_size);
    assert_eq!(volume.header.volume_data_size, volume.data_size);

    // The old data is still readable at the same data offsets.
    let mut buf = [0u8; 512];
    volume.read_data(0, &mut buf)?;
    assert_eq!(buf, first);
    volume.read_data(old_data_size - 512, &mut buf)?;
    assert_eq!(buf, last);

    // Both headers were re-encrypted with fresh salts.
    let new_primary_salt = salt_of(&read_region(&path, 0, SALT)?);
    let new_backup_offset = NEW_HOST - VOLUME_HEADER_GROUP_SIZE;
    let new_backup_salt = salt_of(&read_region(&path, new_backup_offset, SALT)?);
    assert_ne!(new_primary_salt, old_primary_salt);
    assert_ne!(new_backup_salt, new_primary_salt);
    assert_ne!(new_backup_salt, old_primary_salt);

    // The stale backup header group in the middle of the data area is gone.
    let wiped = read_region(&path, old_backup_offset, 512)?;
    assert_ne!(wiped, old_backup_region);
    assert_ne!(salt_of(&wiped), salt_of(&old_backup_region));

    // The newly exposed area is ciphertext, not zeroes (FormatNoFs).
    let tail = read_region(&path, NEW_HOST - 512, 512)?;
    assert!(tail.iter().any(|&b| b != 0), "the new area must not be plain zeroes");

    drop(volume);

    // A fresh open sees the new geometry, and so does the backup header.
    let reopened = Volume::open(&path, &open_options("expand-me", false))?;
    assert_eq!(reopened.host_size, NEW_HOST);
    assert_eq!(reopened.data_size, NEW_HOST - 262144);
    assert_eq!(reopened.header.master_key, old_master_key);
    let mut buf = [0u8; 512];
    reopened.read_data(old_data_size - 512, &mut buf)?;
    assert_eq!(buf, last);

    let via_backup = Volume::open(&path, &open_options("expand-me", true))?;
    assert_eq!(via_backup.data_size, NEW_HOST - 262144);
    assert_eq!(via_backup.header.master_key, old_master_key);

    std::fs::remove_file(&path).ok();
    Ok(())
}

#[test]
fn expanding_twice_keeps_every_marker() -> vcrs_core::Result<()> {
    let path = dummy_path("twice");
    let _ = std::fs::remove_file(&path);

    let mut volume = Volume::create(&path, OLD_HOST, &options("twice"))?;
    let marker = [0x11u8; 512];
    volume.write_data(4096, &marker)?;

    let mut seen_salts = Vec::new();
    let mut host = OLD_HOST;
    for _ in 0..2 {
        host += 4 * 1024 * 1024;
        volume.expand(host, b"twice", 1)?;
        assert_eq!(volume.host_size, host);
        let salt = salt_of(&read_region(&path, 0, SALT)?);
        assert!(!seen_salts.contains(&salt), "the primary salt must change on every expansion");
        seen_salts.push(salt);
        let mut buf = [0u8; 512];
        volume.read_data(4096, &mut buf)?;
        assert_eq!(buf, marker);
    }

    std::fs::remove_file(&path).ok();
    Ok(())
}

#[test]
fn expansion_is_refused_where_veracrypt_refuses_it() -> vcrs_core::Result<()> {
    let path = dummy_path("refuse");
    let _ = std::fs::remove_file(&path);

    // A hidden volume cannot be expanded.
    let outer = Volume::create(&path, OLD_HOST, &options("outer"))?;
    drop(outer);
    let hidden_size = 4 * 1024 * 1024;
    Volume::create_hidden(&path, hidden_size, &options("hidden"))?;

    let mut hidden = Volume::open(
        &path,
        &OpenOptions {
            password: b"hidden".to_vec(),
            pim: 1,
            volume_type: Some(VolumeType::Hidden),
            ..Default::default()
        },
    )?;
    hidden.write_data(0, &[7u8; 512])?;
    match hidden.expand(hidden.host_size + 4 * 1024 * 1024, b"hidden", 1) {
        Err(Error::Unsupported(message)) => assert!(
            message.to_lowercase().contains("hidden"),
            "unexpected message: {message}"
        ),
        other => panic!("expected Unsupported, got {other:?}"),
    }

    // ... but the outer volume may grow (VeraCrypt asks the user first, because
    // that destroys the hidden volume; `--force` in the CLI).
    let mut outer = Volume::open(&path, &open_options("outer", false))?;
    outer.expand(OLD_HOST + 4 * 1024 * 1024, b"outer", 1)?;
    assert_eq!(outer.host_size, OLD_HOST + 4 * 1024 * 1024);

    // Shrinking and too-small growth are refused.
    match outer.expand(OLD_HOST, b"outer", 1) {
        Err(Error::InvalidParameter(message)) => assert!(message.contains("smaller")),
        other => panic!("expected InvalidParameter for shrinking, got {other:?}"),
    }
    let barely = outer.host_size + 512;
    match outer.expand(barely, b"outer", 1) {
        Err(Error::InvalidParameter(message)) => assert!(
            message.contains(&MIN_EXPAND_BYTES.to_string()),
            "unexpected message: {message}"
        ),
        other => panic!("expected InvalidParameter for a {barely}-byte host, got {other:?}"),
    }
    // Unaligned sizes are refused too.
    match outer.expand(outer.host_size + 100 * 1024 + 1, b"outer", 1) {
        Err(Error::InvalidParameter(message)) => assert!(message.contains("sector size")),
        other => panic!("expected InvalidParameter for an unaligned size, got {other:?}"),
    }

    std::fs::remove_file(&path).ok();
    Ok(())
}
