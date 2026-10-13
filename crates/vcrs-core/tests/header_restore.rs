//! Header backup, restore, rebuild-from-master-key and credential-change tests.
//!
//! VeraCrypt's "Backup Volume Header" saves the container's *primary header
//! group* -- 128 KiB: the ordinary header at offset 0 and the hidden header (or
//! the random bytes standing in for it) at 64 KiB. Its restore writes the
//! header it found back over both slots, re-encrypted under a fresh salt. The
//! tests below pin all of that down, including the guarantee that a restore
//! never touches the other volume type's slots and that a wrong or damaged
//! backup leaves the container as it was.

use std::path::{Path, PathBuf};

use vcrs_core::volume::{CreateOptions, OpenOptions, RestoreHeaderOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, Prf, VolumeType};

const PASSWORD: &[u8] = b"header-password";
const NEW_PASSWORD: &[u8] = b"header-new-password";
const HIDDEN_PASSWORD: &[u8] = b"header-hidden-password";
const PIM: i32 = 1;
const HOST_SIZE: u64 = 2 * 1024 * 1024;
const GROUP: u64 = 131072;
const HIDDEN_HOST_SIZE: u64 = 8 * 1024 * 1024;
const HIDDEN_SIZE: u64 = 1024 * 1024;

fn temp(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("vcrs-{name}.vc"));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("hc"));
    path
}

fn create_options(password: &[u8]) -> CreateOptions {
    CreateOptions {
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        password: password.to_vec(),
        pim: PIM,
        keyfiles: Vec::new(),
        sector_size: 512,
        // Quick: none of these tests cares about the contents of the untouched
        // data area, and a full format would only make them slow.
        full_format: false,
    }
}

fn open_options(password: &[u8], prf: Option<Prf>, use_backup_header: bool) -> OpenOptions {
    OpenOptions {
        password: password.to_vec(),
        pim: PIM,
        prf,
        use_backup_header,
        ..Default::default()
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8) ^ seed).collect()
}

/// Overwrite `len` bytes at `offset` with zeroes, as a damaged header would be.
fn zero(path: &Path, offset: u64, len: u64) -> vcrs_core::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&vec![0u8; len as usize])?;
    file.sync_all()?;
    Ok(())
}

fn read_data(path: &Path, password: &[u8], offset: u64, len: usize) -> vcrs_core::Result<Vec<u8>> {
    let volume = Volume::open(path, &open_options(password, None, false))?;
    let mut buf = vec![0u8; len];
    volume.read_data(offset, &mut buf)?;
    Ok(buf)
}

#[test]
fn a_backup_file_holds_the_primary_header_group() -> vcrs_core::Result<()> {
    let path = temp("backup-group");
    let backup = path.with_extension("hc");
    Volume::create(&path, HOST_SIZE, &create_options(PASSWORD))?;

    let written = vcrs_core::backup_headers(&path, &backup)?;
    assert_eq!(written, GROUP);
    assert_eq!(std::fs::read(&backup)?.len(), GROUP as usize);

    // VeraCrypt's restore insists on exactly this: the container's own primary
    // header group, byte for byte.
    let container = std::fs::read(&path)?;
    assert_eq!(std::fs::read(&backup)?, container[..GROUP as usize].to_vec());
    Ok(())
}

#[test]
fn a_backup_file_restores_a_wiped_container() -> vcrs_core::Result<()> {
    let path = temp("restore-file");
    let backup = path.with_extension("hc");
    let volume = Volume::create(&path, HOST_SIZE, &create_options(PASSWORD))?;
    let marker = pattern(4096, 0x11);
    volume.write_data(512, &marker)?;
    volume.flush()?;
    drop(volume);

    vcrs_core::backup_headers(&path, &backup)?;

    // Destroy every header copy: the primary group and the backup group.
    zero(&path, 0, GROUP)?;
    zero(&path, HOST_SIZE - GROUP, GROUP)?;
    assert!(Volume::open(&path, &open_options(PASSWORD, None, false)).is_err());

    let restored =
        vcrs_core::restore_headers(&path, &backup, VolumeType::Normal, Some(&open_options(PASSWORD, None, false)))?;
    let restored = restored.expect("the backup opens with the password");
    assert_eq!(restored.header.volume_type, VolumeType::Normal);
    assert_eq!(restored.data_size, HOST_SIZE - 262144);
    drop(restored);

    // Both slots now hold a usable header: the primary one, and the copy at the
    // end of the container.
    for use_backup_header in [false, true] {
        let volume = Volume::open(&path, &open_options(PASSWORD, None, use_backup_header))?;
        let mut buf = vec![0u8; marker.len()];
        volume.read_data(512, &mut buf)?;
        assert_eq!(buf, marker, "use_backup_header = {use_backup_header}");
    }
    Ok(())
}

#[test]
fn the_embedded_copy_restores_a_destroyed_primary_header() -> vcrs_core::Result<()> {
    let path = temp("restore-embedded");
    let volume = Volume::create(&path, HOST_SIZE, &create_options(PASSWORD))?;
    let marker = pattern(1024, 0x22);
    volume.write_data(0, &marker)?;
    volume.flush()?;
    drop(volume);

    zero(&path, 0, GROUP)?;
    assert!(Volume::open(&path, &open_options(PASSWORD, None, false)).is_err());
    // The copy at the end of the container is still there, which is the whole
    // point of a backup header.
    assert!(Volume::open(&path, &open_options(PASSWORD, None, true)).is_ok());

    let restored =
        vcrs_core::restore_headers_from_embedded(&path, VolumeType::Normal, Some(&open_options(PASSWORD, None, false)))?;
    assert!(restored.is_some());

    // The primary header works again, without --backup.
    let volume = Volume::open(&path, &open_options(PASSWORD, None, false))?;
    let mut buf = vec![0u8; marker.len()];
    volume.read_data(0, &mut buf)?;
    assert_eq!(buf, marker);
    Ok(())
}

#[test]
fn a_master_key_rebuilds_every_header_copy() -> vcrs_core::Result<()> {
    let path = temp("restore-master-key");
    let volume = Volume::create(&path, HOST_SIZE, &create_options(PASSWORD))?;
    let marker = pattern(8192, 0x33);
    volume.write_data(0, &marker)?;
    volume.flush()?;
    let master_key = volume.header.master_key.clone();
    let data_size = volume.data_size;
    drop(volume);

    // Everything is gone: no header at the front, none at the back.
    zero(&path, 0, GROUP)?;
    zero(&path, HOST_SIZE - GROUP, GROUP)?;
    assert!(Volume::open(&path, &open_options(PASSWORD, None, false)).is_err());

    let options = RestoreHeaderOptions {
        password: PASSWORD.to_vec(),
        keyfiles: Vec::new(),
        pim: PIM,
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        sector_size: 512,
        volume_type: VolumeType::Normal,
        data_size,
    };
    let restored = vcrs_core::restore_headers_from_master_key(&path, &master_key, &options)?;
    assert_eq!(restored.header.master_key, master_key);
    assert_eq!(restored.data_offset, 131072);
    assert_eq!(restored.data_size, data_size);
    let mut buf = vec![0u8; marker.len()];
    restored.read_data(0, &mut buf)?;
    assert_eq!(buf, marker);
    drop(restored);

    // And the rebuilt header is an ordinary one: any later open finds it.
    assert_eq!(read_data(&path, PASSWORD, 0, marker.len())?, marker);
    Ok(())
}

#[test]
fn change_credentials_rewrites_both_copies() -> vcrs_core::Result<()> {
    let path = temp("change-credentials");
    let mut volume = Volume::create(&path, HOST_SIZE, &create_options(PASSWORD))?;
    let marker = pattern(2048, 0x44);
    volume.write_data(1024, &marker)?;
    volume.flush()?;
    let previous_salt = volume.header.salt.clone();

    volume.change_credentials(NEW_PASSWORD, PIM, Some(Prf::Sha256))?;
    assert_eq!(volume.header.prf, Prf::Sha256);
    assert_ne!(volume.header.salt, previous_salt, "the salt has to be fresh");
    assert_eq!(volume.header.master_key.len(), 64);
    drop(volume);

    // The old credentials are gone from both slots.
    assert!(Volume::open(&path, &open_options(PASSWORD, None, false)).is_err());
    assert!(Volume::open(&path, &open_options(PASSWORD, None, true)).is_err());

    for use_backup_header in [false, true] {
        let volume = Volume::open(&path, &open_options(NEW_PASSWORD, Some(Prf::Sha256), use_backup_header))?;
        assert_eq!(volume.header.prf, Prf::Sha256);
        let mut buf = vec![0u8; marker.len()];
        volume.read_data(1024, &mut buf)?;
        assert_eq!(buf, marker, "use_backup_header = {use_backup_header}");
    }
    Ok(())
}

#[test]
fn change_credentials_leaves_the_other_slots_alone() -> vcrs_core::Result<()> {
    let path = temp("change-outer-only");
    Volume::create(&path, HIDDEN_HOST_SIZE, &create_options(PASSWORD))?;
    let hidden = Volume::create_hidden(&path, HIDDEN_SIZE, &create_options(HIDDEN_PASSWORD))?;
    let marker = pattern(1024, 0x55);
    hidden.write_data(0, &marker)?;
    hidden.flush()?;
    drop(hidden);

    let before = std::fs::read(&path)?;

    let mut outer = Volume::open(&path, &open_options(PASSWORD, None, false))?;
    outer.change_credentials(NEW_PASSWORD, PIM, None)?;
    drop(outer);

    let after = std::fs::read(&path)?;
    // The ordinary header lives in [0, 64 KiB); the hidden header at 64 KiB and
    // its backup copy at the end of the container are none of its business.
    let hidden_primary = GROUP / 2;
    let hidden_backup = (HIDDEN_HOST_SIZE - GROUP + GROUP / 2) as usize;
    assert_ne!(&before[..hidden_primary as usize], &after[..hidden_primary as usize]);
    assert_eq!(
        &before[hidden_primary as usize..GROUP as usize],
        &after[hidden_primary as usize..GROUP as usize]
    );
    assert_eq!(&before[hidden_backup..], &after[hidden_backup..]);

    // The outer volume's new password works, the old one does not, ...
    assert!(Volume::open(&path, &open_options(PASSWORD, None, false)).is_err());
    assert!(Volume::open(&path, &open_options(NEW_PASSWORD, None, false)).is_ok());
    // ... and the hidden volume inside is untouched.
    let hidden = Volume::open(&path, &open_options(HIDDEN_PASSWORD, None, false))?;
    assert_eq!(hidden.header.volume_type, VolumeType::Hidden);
    let mut buf = vec![0u8; marker.len()];
    hidden.read_data(0, &mut buf)?;
    assert_eq!(buf, marker);
    Ok(())
}

#[test]
fn restoring_a_hidden_header_leaves_the_outer_volume_alone() -> vcrs_core::Result<()> {
    let path = temp("restore-hidden");
    let backup = path.with_extension("hc");
    Volume::create(&path, HIDDEN_HOST_SIZE, &create_options(PASSWORD))?;
    let hidden = Volume::create_hidden(&path, HIDDEN_SIZE, &create_options(HIDDEN_PASSWORD))?;
    let marker = pattern(1024, 0x66);
    hidden.write_data(0, &marker)?;
    hidden.flush()?;
    drop(hidden);
    vcrs_core::backup_headers(&path, &backup)?;

    let outer_before = std::fs::read(&path)?[..(GROUP / 2) as usize].to_vec();

    // Destroy the hidden header and its embedded copy.
    zero(&path, GROUP / 2, GROUP / 2)?;
    zero(&path, HIDDEN_HOST_SIZE - GROUP / 2, GROUP / 2)?;
    assert!(Volume::open(&path, &open_options(HIDDEN_PASSWORD, None, false)).is_err());
    let outer = Volume::open(&path, &open_options(PASSWORD, None, false))?;
    assert_eq!(outer.header.volume_type, VolumeType::Normal);
    drop(outer);

    let restored = vcrs_core::restore_headers(
        &path,
        &backup,
        VolumeType::Hidden,
        Some(&open_options(HIDDEN_PASSWORD, None, false)),
    )?;
    let restored = restored.expect("the hidden header in the backup opens");
    assert_eq!(restored.header.volume_type, VolumeType::Hidden);
    let mut buf = vec![0u8; marker.len()];
    restored.read_data(0, &mut buf)?;
    assert_eq!(buf, marker);
    drop(restored);

    // Nothing outside the hidden slots changed: the ordinary header at the
    // start and the ordinary volume itself are untouched.
    let after = std::fs::read(&path)?;
    assert_eq!(&after[..(GROUP / 2) as usize], &outer_before[..]);
    assert!(Volume::open(&path, &open_options(PASSWORD, None, false)).is_ok());
    assert!(Volume::open(&path, &open_options(HIDDEN_PASSWORD, None, false)).is_ok());
    Ok(())
}

#[test]
fn a_backup_file_of_the_wrong_size_is_refused() -> vcrs_core::Result<()> {
    let path = temp("restore-wrong-size");
    Volume::create(&path, HOST_SIZE, &create_options(PASSWORD))?;
    let wrong = path.with_extension("hc");
    std::fs::write(&wrong, vec![0u8; 256])?;

    // VeraCrypt rejects anything that is not exactly one header group, and so
    // do we: a truncated file must not be written into the container.
    let error = vcrs_core::restore_headers(&path, &wrong, VolumeType::Normal, None)
        .expect_err("a 256 byte file is not a header backup");
    let message = error.to_string();
    assert!(message.contains("a header backup is 131072 bytes"), "{message}");

    // The container is still perfectly fine.
    assert!(Volume::open(&path, &open_options(PASSWORD, None, false)).is_ok());
    Ok(())
}

#[test]
fn a_wrong_backup_leaves_the_container_alone() -> vcrs_core::Result<()> {
    // A backup of a *different* container has the right size but the wrong
    // header: the restore has to put the old header back.
    let path = temp("restore-wrong-volume");
    let backup = path.with_extension("hc");
    let other = temp("restore-other-volume");
    let volume = Volume::create(&path, HOST_SIZE, &create_options(PASSWORD))?;
    let marker = pattern(1024, 0x77);
    volume.write_data(0, &marker)?;
    volume.flush()?;
    drop(volume);
    Volume::create(&other, HOST_SIZE, &create_options(b"another-password"))?;
    vcrs_core::backup_headers(&other, &backup)?;

    let error = vcrs_core::restore_headers(
        &path,
        &backup,
        VolumeType::Normal,
        Some(&open_options(PASSWORD, None, false)),
    )
    .expect_err("the other container's header does not open with this password");
    let message = error.to_string();
    assert!(message.contains("does not open with those credentials"), "{message}");

    // Untouched: both the data and the header are still the originals.
    assert_eq!(read_data(&path, PASSWORD, 0, marker.len())?, marker);
    assert!(Volume::open(&path, &open_options(PASSWORD, None, true)).is_ok());
    Ok(())
}

#[test]
fn a_backup_file_holds_two_openable_header_slots() -> vcrs_core::Result<()> {
    let path = temp("two-slots");
    let backup = path.with_extension("hc");
    let outer = Volume::create(&path, HIDDEN_HOST_SIZE, &create_options(PASSWORD))?;
    let hidden = Volume::create_hidden(&path, HIDDEN_SIZE, &create_options(HIDDEN_PASSWORD))?;
    let outer_master_key = outer.header.master_key.clone();
    let hidden_master_key = hidden.header.master_key.clone();
    drop(outer);
    drop(hidden);

    vcrs_core::backup_headers(&path, &backup)?;
    let area = std::fs::read(&backup)?;
    assert_eq!(area.len(), GROUP as usize);

    // The first slot is the ordinary header and the second the hidden one,
    // each a self-contained encrypted header region -- the layout VeraCrypt's
    // restore reads (and writes back after re-encrypting it with a new salt).
    let outer_header = open_header_slot(&area[..(GROUP / 2) as usize], PASSWORD)?;
    assert_eq!(outer_header.volume_type, VolumeType::Normal);
    assert_eq!(outer_header.master_key, outer_master_key);

    let hidden_header = open_header_slot(&area[(GROUP / 2) as usize..], HIDDEN_PASSWORD)?;
    assert_eq!(hidden_header.volume_type, VolumeType::Hidden);
    assert_eq!(hidden_header.master_key, hidden_master_key);
    Ok(())
}

/// Decrypt one 64 KiB header region the way a VeraCrypt restore does: derive the
/// header key from the password and the salt stored in the region itself.
fn open_header_slot(region: &[u8], password: &[u8]) -> vcrs_core::Result<vcrs_core::VolumeHeader> {
    let (ea, prf) = (EncryptionAlgorithm::Aes, Prf::Sha512);
    let mut header_key = vec![0u8; vcrs_core::prf::HEADER_KEY_SIZE];
    prf.derive(password, &region[..vcrs_core::header::HEADER_SALT_SIZE], PIM, &mut header_key)?;
    assert!(vcrs_core::VolumeHeader::region_has_magic(region, &header_key, ea)?);
    vcrs_core::VolumeHeader::decrypt(region, &header_key, ea, prf)
}

#[test]
fn looks_quick_formatted_tells_the_two_apart() -> vcrs_core::Result<()> {
    let quick = temp("looks-quick");
    Volume::create(&quick, HOST_SIZE, &create_options(PASSWORD))?;
    assert!(vcrs_core::looks_quick_formatted(&quick)?);

    let full = temp("looks-full");
    let mut options = create_options(PASSWORD);
    options.full_format = true;
    Volume::create(&full, HOST_SIZE, &options)?;
    assert!(!vcrs_core::looks_quick_formatted(&full)?);
    Ok(())
}
