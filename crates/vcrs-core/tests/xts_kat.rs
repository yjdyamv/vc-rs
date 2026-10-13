//! Byte-exact XTS compatibility test against VeraCrypt's own test vectors.
//!
//! `xts_kat_vectors.rs` holds the IEEE 1619 XTS-AES-256 vectors that VeraCrypt
//! itself uses (`EncryptionTest::TestXtsAES`). Matching them proves that our
//! tweak encoding, GF(2^128) multiplication and cascade plumbing agree with
//! VeraCrypt for the AES path.
//!
//! VeraCrypt reads the stored 8 bytes with `memcpy` into a `uint64` and then
//! applies `Endian::Big`, so the stored bytes are the *big-endian* encoding of
//! the data unit number used for the tweak.

use vcrs_core::{EncryptionAlgorithm, Xts};

mod xts_kat_vectors;
use xts_kat_vectors::XTS_KAT;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in generated vectors")
}

#[test]
fn ieee1619_xts_aes256_known_answers() {
    for (i, (key1, key2, data_unit_no, plaintext, ciphertext)) in XTS_KAT.iter().enumerate() {
        let key1 = unhex(key1);
        let key2 = unhex(key2);
        let mut xts_key = key1.clone();
        xts_key.extend_from_slice(&key2);

        let plaintext = unhex(plaintext);
        let ciphertext = unhex(ciphertext);
        assert_eq!(plaintext.len(), 512);
        assert_eq!(ciphertext.len(), 512);

        let unit = u64::from_be_bytes(*data_unit_no);

        let xts = Xts::new(EncryptionAlgorithm::Aes, &xts_key).unwrap();

        let mut buf = plaintext.clone();
        xts.encrypt(&mut buf, unit).unwrap();
        assert_eq!(
            buf,
            ciphertext,
            "vector {i} (data unit {unit:#018x}): encryption does not match VeraCrypt/IEEE 1619"
        );

        xts.decrypt(&mut buf, unit).unwrap();
        assert_eq!(buf, plaintext, "vector {i}: decryption does not round-trip");
    }
}
