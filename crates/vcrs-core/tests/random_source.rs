//! `CreateOptions::random_source` (VeraCrypt's `--random-source` switch).
//!
//! The same source file has to build the same container byte for byte, which is
//! what makes an audit or a bug report reproducible; without the option the
//! containers differ run to run.

use std::path::{Path, PathBuf};

use vcrs_core::volume::{CreateOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, OpenOptions, Prf};

const PASSWORD: &[u8] = b"random-source-password";
const HIDDEN_PASSWORD: &[u8] = b"random-source-hidden";
const PIM: i32 = 1;
const HOST_SIZE: u64 = 2 * 1024 * 1024;
const HIDDEN_HOST_SIZE: u64 = 8 * 1024 * 1024;
const HIDDEN_SIZE: u64 = 1024 * 1024;

fn temp(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("vcrs-{name}.vc"));
    let _ = std::fs::remove_file(&path);
    path
}

fn source_file(name: &str, content: &[u8]) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("vcrs-{name}.seed"));
    std::fs::write(&path, content).unwrap();
    path
}

fn options(password: &[u8], source: Option<PathBuf>) -> CreateOptions {
    CreateOptions {
        ea: EncryptionAlgorithm::Aes,
        prf: Prf::Sha512,
        password: password.to_vec(),
        pim: PIM,
        full_format: false,
        random_source: source,
        ..Default::default()
    }
}

fn open_options(password: &[u8]) -> OpenOptions {
    OpenOptions {
        password: password.to_vec(),
        pim: PIM,
        ..Default::default()
    }
}

/// Create a normal container and return its bytes.
fn build(path: &Path, options: &CreateOptions) -> Vec<u8> {
    Volume::create(path, HOST_SIZE, options).unwrap();
    std::fs::read(path).unwrap()
}

#[test]
fn the_same_source_builds_the_same_container() {
    let seed = source_file("same", b"a seed for a deterministic container");
    let first_path = temp("same-one");
    let second_path = temp("same-two");

    let first = build(&first_path, &options(PASSWORD, Some(seed.clone())));
    let second = build(&second_path, &options(PASSWORD, Some(seed)));
    assert_eq!(first, second, "the same source file has to give the same bytes");
    assert_eq!(first.len() as u64, HOST_SIZE);

    // The deterministic container is an ordinary volume: it opens and its data
    // area is where a volume created from the system generator puts it.
    let volume = Volume::open(&first_path, &open_options(PASSWORD)).unwrap();
    assert_eq!(volume.data_size, HOST_SIZE - 262144);
    assert_eq!(volume.header.salt.len(), 64);
    assert!(volume.header.salt.iter().any(|b| *b != 0));

    for path in [first_path, second_path] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn the_same_source_builds_the_same_hidden_volume() {
    let seed = source_file("same-hidden", b"a seed for a hidden volume");
    let mut images = Vec::new();
    for name in ["hidden-one", "hidden-two"] {
        let path = temp(name);
        Volume::create(&path, HIDDEN_HOST_SIZE, &options(PASSWORD, Some(seed.clone()))).unwrap();
        Volume::create_hidden(
            &path,
            HIDDEN_SIZE,
            &options(HIDDEN_PASSWORD, Some(seed.clone())),
        )
        .unwrap();
        images.push(std::fs::read(&path).unwrap());
        let _ = std::fs::remove_file(path);
    }
    assert_eq!(
        images[0], images[1],
        "both the outer and the hidden header have to be reproducible"
    );
}

#[test]
fn a_different_source_builds_a_different_container() {
    let one = source_file("different-one", b"seed one");
    let two = source_file("different-two", b"seed two");
    let first_path = temp("different-a");
    let second_path = temp("different-b");

    let first = build(&first_path, &options(PASSWORD, Some(one)));
    let second = build(&second_path, &options(PASSWORD, Some(two)));
    assert_ne!(first, second);

    for path in [first_path, second_path] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn without_a_source_every_container_differs() {
    let first_path = temp("system-a");
    let second_path = temp("system-b");
    let first = build(&first_path, &options(PASSWORD, None));
    let second = build(&second_path, &options(PASSWORD, None));
    assert_ne!(
        first, second,
        "the operating system's generator must not repeat itself"
    );

    for path in [first_path, second_path] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn an_empty_source_is_refused() {
    let seed = source_file("empty", b"");
    let path = temp("empty-source");
    let err = Volume::create(&path, HOST_SIZE, &options(PASSWORD, Some(seed))).unwrap_err();
    assert!(err.to_string().contains("empty"), "{err}");
    assert!(!path.exists(), "nothing may be created");
    let _ = std::fs::remove_file(path);
}
