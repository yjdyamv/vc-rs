//! Create → write → re-open → read round trip for **every** combination of
//! encryption algorithm and header key derivation function.
//!
//! This is the test that would catch a wrong cascade key split (each cipher in a
//! cascade must consume its own 32-byte chunk of the derived key, in VeraCrypt's
//! application order) or a mis-wired KDF: each volume is written with one
//! (EA, PRF) pair and then opened from scratch, and opening must both find the
//! right combination and decrypt the data area back to the same bytes.
//!
//! `PIM = 1` keeps the derivation counts small (16 000 PBKDF2 iterations, 64 MiB
//! Argon2) so the whole matrix stays in the tens of seconds while still using the
//! real code paths.

use std::path::PathBuf;

use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, Prf};

/// `TC_MIN_VOLUME_SIZE` is 299 008 bytes; round up a little.
const VOLUME_SIZE: u64 = 320 * 1024;
const PASSWORD: &[u8] = b"matrix-password";
const PIM: i32 = 1;

fn tmp_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("vcrs-matrix-{}-{tag}.vc", std::process::id()));
    p
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8).collect()
}

#[test]
fn every_ea_and_prf_round_trips() {
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for ea in EncryptionAlgorithm::ALL {
        for prf in Prf::ALL {
            checked += 1;
            let path = tmp_path(&format!("{}-{}", ea.name().replace('-', ""), prf.name()));
            let _ = std::fs::remove_file(&path);

            let outcome = round_trip(&path, ea, prf);
            let _ = std::fs::remove_file(&path);

            if let Err(e) = outcome {
                failures.push(format!("{} / {}: {e}", ea.name(), prf.name()));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {checked} (EA, PRF) combinations failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

fn round_trip(path: &PathBuf, ea: EncryptionAlgorithm, prf: Prf) -> vcrs_core::Result<()> {
    let create = CreateOptions {
        ea,
        prf,
        password: PASSWORD.to_vec(),
        pim: PIM,
        keyfiles: Vec::new(),
        sector_size: 512,
        full_format: false,
    };
    let volume = Volume::create(path, VOLUME_SIZE, &create)?;

    // Write far enough into the data area to cross a 512-byte data unit boundary
    // and to make the offset mapping (host offset / 512) meaningful.
    let data = pattern(2048);
    volume.write_data(1024, &data)?;
    volume.flush()?;
    drop(volume);

    // Open from scratch: the trial decryption loop has to find the combination.
    let open = OpenOptions {
        password: PASSWORD.to_vec(),
        pim: PIM,
        ..Default::default()
    };
    let opened = Volume::open(path, &open)?;
    assert_eq!(opened.header.ea, ea, "trial decryption picked the wrong EA");
    assert_eq!(opened.header.prf, prf, "trial decryption picked the wrong PRF");
    assert_eq!(opened.data_size, VOLUME_SIZE - 262144);

    let mut back = vec![0u8; data.len()];
    opened.read_data(1024, &mut back)?;
    assert_eq!(back, data, "partial write at an unaligned-by-one-sector offset did not round trip");

    // A quick-formatted volume is zero-filled on disk (`SetLength`), exactly like
    // VeraCrypt, so the *decrypted* content of untouched data units is garbage —
    // there is no "zero plaintext" contract to assert here. Instead cover the
    // whole data area, which exercises every data unit and the sector mapping.
    let total = opened.data_size as usize;
    let full = pattern(total);
    opened.write_data(0, &full)?;
    opened.flush()?;
    drop(opened);

    let reopened = Volume::open(path, &open)?;
    let mut entire = vec![0u8; total];
    reopened.read_data(0, &mut entire)?;
    assert_eq!(entire, full, "full data area did not round trip");

    // The last byte of the data area must also be the last byte before the
    // backup header (offset/size mapping must not run past the data area).
    assert_eq!(reopened.data_offset + reopened.data_size, VOLUME_SIZE - 131072);

    Ok(())
}
