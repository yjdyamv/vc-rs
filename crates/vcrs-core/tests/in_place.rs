//! In-place encryption of a plaintext image.
//!
//! The volume ends up byte-for-byte the way VeraCrypt's "Encrypt a non-system
//! partition in place" leaves it: the data area moved 128 KiB forward, the
//! primary header group in the space that freed up, the backup header group at
//! the very end, `TC_HEADER_FLAG_NONSYS_INPLACE_ENC` set in the flags, and the
//! whole data area encrypted with a master key that only ever lived in the
//! backup header until the run finished.

use std::path::PathBuf;

use vcrs_core::header::HEADER_FLAG_NONSYS_INPLACE_ENC;
use vcrs_core::{
    decrypt_in_place, decrypt_in_place_stopping_after, encrypt_in_place,
    encrypt_in_place_stopping_after, EncryptionAlgorithm, OpenOptions, Prf, Volume,
};

const PASSWORD: &[u8] = b"in-place-password";
const PIM: i32 = 1;
/// Data area of the finished volume.
const DATA_SIZE: u64 = 1024 * 1024;
const HEADER_GROUP: u64 = 131072;
/// The plaintext that the image holds before the run: the (already shrunk)
/// filesystem. Its last 128 KiB get overwritten as the ciphertext moves up, and
/// the volume's data area is the first `DATA_SIZE` bytes of it.
const PLAINTEXT_SIZE: u64 = DATA_SIZE + HEADER_GROUP;
/// The whole image: plaintext plus the free space VeraCrypt leaves for the
/// backup header group.
const FILE_SIZE: u64 = PLAINTEXT_SIZE + HEADER_GROUP;

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32).wrapping_mul(2654435761).wrapping_add(seed) >> 8) as u8)
        .collect()
}

/// A plain image: `PLAINTEXT_SIZE` bytes of "filesystem" content followed by
/// `HEADER_GROUP` zeroed bytes, which is what in-place encryption turns into the
/// backup header group (VeraCrypt shrinks the filesystem by that much first).
fn plain_image(name: &str, seed: u32) -> (PathBuf, Vec<u8>) {
    let path = std::env::temp_dir().join(name);
    let mut image = pattern(FILE_SIZE as usize, seed);
    image[PLAINTEXT_SIZE as usize..].fill(0);
    std::fs::write(&path, &image).unwrap();
    (path, image)
}

fn open_options() -> OpenOptions {
    OpenOptions {
        password: PASSWORD.to_vec(),
        pim: PIM,
        prf: Some(Prf::Sha512),
        ea: Some(EncryptionAlgorithm::Aes),
        volume_type: None,
        use_backup_header: false,
        ..Default::default()
    }
}

/// What a finished in-place container decrypts back to: the filesystem (`DATA_SIZE`
/// bytes that the run moved, unchanged) followed by the 128 KiB that were freed for
/// the encryption -- VeraCrypt zeroes everything from the end of the data area
/// onwards, so those come back as zeros, not as the bytes they held before.
fn decrypted_image(image: &[u8]) -> Vec<u8> {
    let mut expected = image[..DATA_SIZE as usize].to_vec();
    expected.resize(PLAINTEXT_SIZE as usize, 0);
    expected
}

/// Index of the first differing byte, or `None` when the slices are equal (used
/// instead of `assert_eq!` on whole megabyte-sized images).
fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    if a.len() != b.len() {
        return Some(usize::MAX);
    }
    a.iter().zip(b).position(|(x, y)| x != y)
}

#[test]
fn a_plain_image_becomes_a_normal_volume() {
    let (path, image) = plain_image("vcrs-inplace-plain.hc", 1);
    let volume = encrypt_in_place(&path, PASSWORD, PIM, EncryptionAlgorithm::Aes, Prf::Sha512).unwrap();

    assert!(volume.in_place().is_none(), "the run has to finish");
    assert_eq!(volume.data_offset, HEADER_GROUP);
    assert_eq!(volume.data_size, DATA_SIZE);
    assert_eq!(volume.header.volume_data_size, DATA_SIZE);
    assert_eq!(volume.header.encrypted_area_start, HEADER_GROUP);
    assert_eq!(volume.header.encrypted_area_length, DATA_SIZE);
    assert_ne!(
        volume.header.flags & HEADER_FLAG_NONSYS_INPLACE_ENC,
        0,
        "VeraCrypt keeps the in-place flag set on a finished volume"
    );

    // The data survived the 128 KiB shift.
    let mut read = vec![0u8; DATA_SIZE as usize];
    volume.read_data(0, &mut read).unwrap();
    assert_eq!(read, image[..DATA_SIZE as usize]);

    // The plaintext is gone from the file: its first bytes now hold the primary
    // header and the shifted data area is ciphertext.
    let on_disk = std::fs::read(&path).unwrap();
    assert_eq!(on_disk.len() as u64, FILE_SIZE);
    // The header body is encrypted, so the "VERA" magic is not visible in the
    // file -- only the 64-byte salt in front of it is plaintext.
    assert!(on_disk[..64].iter().any(|b| *b != 0), "the header salt has to be random");
    assert_ne!(
        &on_disk[HEADER_GROUP as usize..HEADER_GROUP as usize + 512],
        &image[..512],
        "the data area has to be ciphertext now"
    );

    // A finished volume opens normally, from either header copy.
    let reopened = Volume::open(&path, &open_options()).unwrap();
    assert_eq!(reopened.header.master_key, volume.header.master_key);
    let backup = Volume::open(
        &path,
        &OpenOptions {
            use_backup_header: true,
            ..open_options()
        },
    )
    .unwrap();
    assert_eq!(backup.header.master_key, volume.header.master_key);

    std::fs::remove_file(path).ok();
}

#[test]
fn an_interrupted_run_resumes_where_it_stopped() {
    let (path, image) = plain_image("vcrs-inplace-resume.hc", 2);

    // Stop after a quarter of the data area.
    let partial = encrypt_in_place_stopping_after(
        &path,
        PASSWORD,
        PIM,
        EncryptionAlgorithm::Aes,
        Prf::Sha512,
        Some(DATA_SIZE / 4),
    )
    .unwrap();
    let state = partial.in_place().expect("the run has to be unfinished");
    assert_eq!(state.encrypted_length, DATA_SIZE / 4);
    assert_eq!(state.remaining, DATA_SIZE - DATA_SIZE / 4);
    assert_eq!(state.total(), DATA_SIZE);
    assert_eq!(partial.data_size, DATA_SIZE);

    // A partially encrypted volume can be read (its top quarter is ciphertext, the
    // rest is still plaintext where it always was) but not written.
    let mut read = vec![0u8; DATA_SIZE as usize];
    partial.read_data(0, &mut read).unwrap();
    assert_eq!(read, image[..DATA_SIZE as usize]);
    assert!(matches!(
        partial.write_data(0, &vec![0u8; 512]).unwrap_err(),
        vcrs_core::Error::InPlaceIncomplete { .. }
    ));
    drop(partial);

    // Only the backup header is valid while the run is unfinished, and that is
    // exactly where the resume starts from.
    let finished = encrypt_in_place(&path, PASSWORD, PIM, EncryptionAlgorithm::Aes, Prf::Sha512).unwrap();
    assert!(finished.in_place().is_none());
    let mut read = vec![0u8; DATA_SIZE as usize];
    finished.read_data(0, &mut read).unwrap();
    assert_eq!(read, image[..DATA_SIZE as usize], "the resume must not have damaged anything");
    assert_eq!(finished.header.volume_data_size, DATA_SIZE);
    assert_eq!(finished.header.encrypted_area_length, DATA_SIZE);

    std::fs::remove_file(path).ok();
}

#[test]
fn a_plain_image_is_not_decrypted() {
    let (path, image) = plain_image("vcrs-inplace-not.hc", 6);
    let err = decrypt_in_place(&path, PASSWORD, PIM).expect_err("there is nothing to decrypt");
    assert!(
        err.to_string().contains("not a VeraCrypt volume"),
        "unexpected error: {err}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), image);
    std::fs::remove_file(path).ok();
}

#[test]
fn a_container_survives_a_decryption_round_trip() {
    let (path, image) = plain_image("vcrs-inplace-roundtrip.hc", 7);
    encrypt_in_place(&path, PASSWORD, PIM, EncryptionAlgorithm::Aes, Prf::Sha512).unwrap();

    let outcome = decrypt_in_place(&path, PASSWORD, PIM).unwrap();
    assert!(outcome.finished);
    assert_eq!(outcome.decrypted, DATA_SIZE);
    assert_eq!(outcome.data_size, DATA_SIZE);

    // The file is the plaintext image it was made from -- and it has no header left
    // at all (VeraCrypt zeroes the tail and there is nothing to keep).
    let restored = std::fs::read(&path).unwrap();
    assert_eq!(restored.len() as u64, PLAINTEXT_SIZE);
    let expected = decrypted_image(&image);
    assert_eq!(
        first_difference(&restored, &expected),
        None,
        "the decrypted image differs from the original"
    );
    assert!(
        restored[PLAINTEXT_SIZE as usize - HEADER_GROUP as usize..]
            .iter()
            .all(|b| *b == 0),
        "the freed tail has to be zeros again"
    );
    std::fs::remove_file(path).ok();
}

#[test]
fn an_interrupted_decryption_resumes() {
    let (path, image) = plain_image("vcrs-inplace-dec-resume.hc", 8);
    encrypt_in_place(&path, PASSWORD, PIM, EncryptionAlgorithm::Aes, Prf::Sha512).unwrap();

    // A quarter of the data area, decrypted from the bottom up.
    let partial =
        decrypt_in_place_stopping_after(&path, PASSWORD, PIM, false, Some(DATA_SIZE / 4)).unwrap();
    assert!(!partial.finished);
    assert_eq!(partial.decrypted, DATA_SIZE / 4);
    assert_eq!(partial.data_size, DATA_SIZE);

    // VeraCrypt moves EncryptedAreaStart up and EncryptedAreaLength down while
    // decrypting, and the backup header carries that state (the primary header
    // group is gone -- the first chunk was written over it).
    let state = Volume::open(
        &path,
        &OpenOptions {
            use_backup_header: true,
            ..open_options()
        },
    )
    .unwrap();
    assert_eq!(state.header.encrypted_area_start, HEADER_GROUP + DATA_SIZE / 4);
    assert_eq!(state.header.encrypted_area_length, DATA_SIZE - DATA_SIZE / 4);

    // The bottom quarter of the image is back where it was ...
    let on_disk = std::fs::read(&path).unwrap();
    assert_eq!(&on_disk[..(DATA_SIZE / 4) as usize], &image[..(DATA_SIZE / 4) as usize]);

    // ... and a fresh (non-resumed) run is refused, because a half decrypted and a
    // half encrypted container look the same in the header: the caller has to say
    // which direction to continue in, exactly like VeraCrypt's switch does.
    let err = decrypt_in_place(&path, PASSWORD, PIM)
        .expect_err("only an explicit resume may continue a partial transformation");
    assert!(
        err.to_string().contains("unfinished in-place transformation"),
        "unexpected error: {err}"
    );

    let finished = decrypt_in_place_stopping_after(&path, PASSWORD, PIM, true, None).unwrap();
    assert!(finished.finished);
    assert_eq!(finished.decrypted, DATA_SIZE - DATA_SIZE / 4);
    let restored = std::fs::read(&path).unwrap();
    assert_eq!(
        first_difference(&restored, &decrypted_image(&image)),
        None,
        "the resumed decryption has to rebuild the whole image"
    );
    std::fs::remove_file(path).ok();
}

#[test]
fn a_non_empty_tail_is_refused() {
    let path = std::env::temp_dir().join("vcrs-inplace-tail.hc");
    // Every byte is non-zero, including the backup header slot.
    let image = pattern(FILE_SIZE as usize, 3);
    std::fs::write(&path, &image).unwrap();

    let err = encrypt_in_place(&path, PASSWORD, PIM, EncryptionAlgorithm::Aes, Prf::Sha512)
        .expect_err("a non-empty tail must not be silently overwritten");
    let message = err.to_string();
    assert!(
        message.contains("not a header this password opens") && message.contains("zero those bytes"),
        "unexpected error: {message}"
    );
    // Nothing was written.
    assert_eq!(std::fs::read(&path).unwrap(), image);

    std::fs::remove_file(path).ok();
}
