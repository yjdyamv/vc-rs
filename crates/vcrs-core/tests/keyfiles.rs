//! Keyfile end-to-end tests.
//!
//! VeraCrypt mixes a "keyfile pool" into the password before running the KDF, so
//! a container opened without its keyfiles must look like a wrong password.
//! See `docs/research/keyfiles.md` and `crates/vcrs-core/src/keyfile.rs`.

use std::path::{Path, PathBuf};

use vcrs_core::keyfile::{apply_keyfiles, pool_size, KEYFILE_POOL_LEGACY_SIZE, KEYFILE_POOL_SIZE};
use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_core::Error;

const VOLUME_SIZE: u64 = 320 * 1024; // just above the 262144-byte header area

fn sandbox(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vcrs-keyfiles-{}-{}", name, std::process::id()));
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    std::fs::create_dir_all(&dir).expect("create sandbox");
    dir
}

fn write_keyfile(path: &Path, seed: u8, len: usize) {
    let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect();
    std::fs::write(path, data).expect("write keyfile");
}

fn create_options(password: &[u8], keyfiles: Vec<PathBuf>) -> CreateOptions {
    CreateOptions {
        password: password.to_vec(),
        keyfiles,
        pim: 1, // keep the derivation cheap
        ..Default::default()
    }
}

fn open_options(password: &[u8], keyfiles: Vec<PathBuf>) -> OpenOptions {
    OpenOptions {
        password: password.to_vec(),
        keyfiles,
        pim: 1,
        ..Default::default()
    }
}

#[test]
fn a_container_made_with_a_keyfile_needs_that_keyfile() {
    let dir = sandbox("single");
    let key_a = dir.join("a.key");
    let key_b = dir.join("b.key");
    write_keyfile(&key_a, 0x11, 128);
    write_keyfile(&key_b, 0x77, 512);
    let volume_path = dir.join("volume.vc");

    let created = Volume::create(&volume_path, VOLUME_SIZE, &create_options(b"pw", vec![key_a.clone()]))
        .expect("create with a keyfile");
    let master_key = created.header.master_key.clone();
    drop(created);

    // The keyfile is required: without it the password does not fit the header.
    let err = Volume::open(&volume_path, &open_options(b"pw", Vec::new())).err();
    assert!(
        matches!(err, Some(Error::PasswordIncorrect)),
        "opening without the keyfile should fail, got {err:?}"
    );

    // A different keyfile is just as wrong, and so is a different password.
    let err = Volume::open(&volume_path, &open_options(b"pw", vec![key_b.clone()])).err();
    assert!(matches!(err, Some(Error::PasswordIncorrect)), "wrong keyfile: {err:?}");
    let err = Volume::open(&volume_path, &open_options(b"other", vec![key_a.clone()])).err();
    assert!(matches!(err, Some(Error::PasswordIncorrect)), "wrong password: {err:?}");

    // ... and with the keyfile it opens, the master key being the same one.
    let reopened = Volume::open(&volume_path, &open_options(b"pw", vec![key_a.clone()]))
        .expect("reopen with the keyfile");
    assert_eq!(reopened.header.master_key, master_key);
}

#[test]
fn a_directory_of_keyfiles_equals_the_explicit_list() {
    let dir = sandbox("directory");
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).expect("create keyfile dir");
    let a = keys.join("01.key");
    let b = keys.join("02.key");
    write_keyfile(&a, 0x22, 200);
    write_keyfile(&b, 0x33, 4096);

    let from_dir = apply_keyfiles(b"password", &[keys.clone()], None).expect("directory pool");
    let explicit = apply_keyfiles(b"password", &[a, b], None).expect("explicit pool");
    assert_eq!(from_dir, explicit, "a directory must hash like its sorted file list");

    // Same property through a real container.
    let volume_path = dir.join("volume.vc");
    Volume::create(&volume_path, VOLUME_SIZE, &create_options(b"password", vec![keys.clone()]))
        .expect("create from a directory of keyfiles");
    Volume::open(&volume_path, &open_options(b"password", vec![keys.clone()]))
        .expect("reopen from the directory");
}

#[test]
fn the_pool_layout_follows_the_password_length() {
    let dir = sandbox("pool");
    let key = dir.join("k.key");
    write_keyfile(&key, 0x55, 64);
    let keyfiles = vec![key];

    // Short passwords keep VeraCrypt's 64-byte legacy pool ...
    let short = apply_keyfiles(b"pw", &keyfiles, None).expect("short password");
    assert_eq!(short.len(), KEYFILE_POOL_LEGACY_SIZE);
    assert_eq!(pool_size(short.len()), KEYFILE_POOL_LEGACY_SIZE);
    // ... and the first password bytes are altered in place, so the result is
    // not the raw password followed by the pool.
    assert_ne!(&short[..2], b"pw");

    // Long passwords use the 128-byte pool, with the remainder appended.
    let long_password = vec![b'x'; 100];
    let long = apply_keyfiles(&long_password, &keyfiles, None).expect("long password");
    assert_eq!(long.len(), KEYFILE_POOL_SIZE);
    assert_eq!(pool_size(long_password.len()), KEYFILE_POOL_SIZE);
    assert_ne!(&long[..100], &long_password[..]);

    // 64 bytes is the boundary: still the legacy pool.
    let boundary = apply_keyfiles(&vec![b'y'; KEYFILE_POOL_LEGACY_SIZE], &keyfiles, None).expect("boundary");
    assert_eq!(boundary.len(), KEYFILE_POOL_LEGACY_SIZE);
}
