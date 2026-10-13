//! Hidden volume integration test.
//!
//! A hidden volume lives *inside* a normal (outer) volume: its header replaces the
//! fake hidden header at offset 65536 and its data area is a suffix of the outer
//! volume's data area.  VeraCrypt only looks for it when the user asks for a hidden
//! volume, so opening a hidden volume without `volume_type: Some(Hidden)` must fail.
//!
//! Layout arithmetic under test (10 MiB host, 4 MiB hidden volume):
//!   outer  : data offset 131072,                  data size 10 MiB - 262144
//!   hidden : data offset 10 MiB - 131072 - 4 MiB, data size 4 MiB - 131072
//! The hidden header goes to offset 65536 (inside the outer header group, which is
//! why VeraCrypt writes a *fake* hidden header there for every normal volume) and
//! its backup to 10 MiB - 65536.

use vcrs_core::header::VOLUME_HEADER_SIZE;
use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, Prf, VolumeType};

const HOST_SIZE: u64 = 10 * 1024 * 1024;
const HIDDEN_SIZE: u64 = 4 * 1024 * 1024;

fn dummy_path(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("vcrs-hidden-{name}.vc"));
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
fn hidden_volume_lives_inside_the_outer_volume() -> vcrs_core::Result<()> {
    let path = dummy_path("main");
    let _ = std::fs::remove_file(&path);

    // Outer volume with a recognisable marker at the very start of its data area.
    let outer = Volume::create(&path, HOST_SIZE, &options("outer-password"))?;
    assert_eq!(outer.header.volume_type, VolumeType::Normal);
    assert_eq!(outer.data_offset, 131072);
    assert_eq!(outer.data_size, HOST_SIZE - 262144);
    let marker = [0xa5u8; 512];
    outer.write_data(0, &marker)?;
    outer.flush()?;
    drop(outer);

    // The fake hidden header VeraCrypt writes for every normal volume must be
    // present at offset 65536 (it occupies the slot the real hidden header takes
    // over).  Its body is encrypted with a random key, so only the plaintext salt
    // (the first 64 bytes) can be inspected: it must be its own random value.
    let primary_salt = vcrs_core::volume::read_region(&path, 0, 64)?;
    let fake_hidden_salt = vcrs_core::volume::read_region(&path, 65536, 64)?;
    let real_backup_salt = vcrs_core::volume::read_region(&path, HOST_SIZE - 131072, 64)?;
    let fake_hidden_backup_salt =
        vcrs_core::volume::read_region(&path, HOST_SIZE - VOLUME_HEADER_SIZE, 64)?;
    assert_ne!(primary_salt, fake_hidden_salt, "no fake hidden header at 65536");
    assert!(
        fake_hidden_salt.iter().any(|b| *b != 0),
        "the fake hidden header must be random-looking, not zeros"
    );
    assert_ne!(
        real_backup_salt, primary_salt,
        "the backup header must be encrypted with a freshly derived header key (new salt)"
    );
    assert!(
        fake_hidden_backup_salt.iter().any(|b| *b != 0),
        "no fake hidden header in front of EOF"
    );
    assert_ne!(fake_hidden_backup_salt, real_backup_salt);

    // Put a hidden volume inside it.
    let hidden = Volume::create_hidden(&path, HIDDEN_SIZE, &options("hidden-password"))?;
    assert_eq!(hidden.header.volume_type, VolumeType::Hidden);
    assert_eq!(hidden.data_offset, HOST_SIZE - 131072 - HIDDEN_SIZE);
    assert_eq!(hidden.data_size, HIDDEN_SIZE - 131072);
    // VolumeType must be derived from the header field, not forced by the layout.
    assert_eq!(hidden.header.hidden_volume_data_size, HIDDEN_SIZE - 131072);
    let hidden_marker = [0x5au8; 512];
    hidden.write_data(0, &hidden_marker)?;
    hidden.flush()?;
    drop(hidden);

    // The hidden volume's own header is now at 65536 and its backup at EOF-65536;
    // both were written with their own random salt.
    let hidden_salt = vcrs_core::volume::read_region(&path, 65536, 64)?;
    let hidden_backup_salt =
        vcrs_core::volume::read_region(&path, HOST_SIZE - VOLUME_HEADER_SIZE, 64)?;
    assert_ne!(hidden_salt, hidden_backup_salt, "hidden backup header reused the salt");
    assert_ne!(hidden_salt, primary_salt, "hidden header reused the outer volume's salt");

    // Opening with the outer password still yields the outer volume, and the
    // marker at the start of its data area survived (the hidden data area is a
    // suffix, so only the tail of the outer data area is overwritten).
    let outer_again = Volume::open(&path, &open_options("outer-password", false))?;
    assert_eq!(outer_again.header.volume_type, VolumeType::Normal);
    assert_eq!(outer_again.data_offset, 131072);
    assert_eq!(outer_again.data_size, HOST_SIZE - 262144);
    let mut read_back = [0u8; 512];
    outer_again.read_data(0, &mut read_back)?;
    assert_eq!(read_back, marker, "outer data area start was clobbered");

    // The hidden volume opens only when a hidden volume is requested.
    let hidden_again = Volume::open(&path, &open_options("hidden-password", true))?;
    assert_eq!(hidden_again.header.volume_type, VolumeType::Hidden);
    assert_eq!(hidden_again.data_offset, HOST_SIZE - 131072 - HIDDEN_SIZE);
    assert_eq!(hidden_again.data_size, HIDDEN_SIZE - 131072);
    let mut read_back = [0u8; 512];
    hidden_again.read_data(0, &mut read_back)?;
    assert_eq!(read_back, hidden_marker, "hidden data area did not round trip");

    // Without asking for a hidden volume at all, VeraCrypt still tries the hidden
    // header (that is how the GUI mounts a hidden volume from its password alone),
    // so this must succeed and report the hidden geometry.
    let auto = Volume::open(&path, &open_options("hidden-password", false))?;
    assert_eq!(auto.header.volume_type, VolumeType::Hidden);
    assert_eq!(auto.data_offset, HOST_SIZE - 131072 - HIDDEN_SIZE);

    // The outer password does not open the hidden volume either.
    let err = Volume::open(&path, &open_options("outer-password", true)).unwrap_err();
    assert!(
        matches!(err, vcrs_core::Error::PasswordIncorrect),
        "expected PasswordIncorrect, got {err:?}"
    );

    std::fs::remove_file(&path).ok();
    Ok(())
}
