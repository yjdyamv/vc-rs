//! XTS (IEEE 1619) mode over one or more cascaded ciphers, byte-compatible
//! with `src/Volume/EncryptionModeXTS.cpp`.
//!
//! VeraCrypt's XTS has three properties that must be reproduced exactly:
//!
//! 1. **Data unit size 512** (`ENCRYPTION_DATA_UNIT_SIZE`). The data unit
//!    number is the *host* byte offset divided by 512, so it is an absolute
//!    property of the file, not of the encrypted area.
//! 2. The tweak is `E_secondary(LE64(data_unit_no) || 0^8)`, and the whitening
//!    value for block `j` is derived by multiplying by `x` in GF(2^128) with the
//!    reduction polynomial `x^128 + x^7 + x^2 + x + 1` (0x87 XORed into the
//!    lowest byte on overflow).
//! 3. **Cascades are applied as whole-buffer passes**, not block-by-block: for
//!    encryption the buffer is fully XTS-processed with cipher[0], then with
//!    cipher[1], and so on; decryption runs the passes in reverse order. Each
//!    pass uses its own secondary (tweak) cipher.
//!
//! There is no ciphertext stealing: the final, possibly short, data unit simply
//! processes its whole 16-byte blocks. The 448-byte effective header region is
//! therefore one partial data unit (28 blocks) starting at data unit 0.

use crate::cipher::{CipherId, EncryptionAlgorithm};
use crate::{Error, Result};
use botan::BlockCipher;

/// XTS data unit size used by VeraCrypt for file-hosted volumes.
pub const DATA_UNIT_SIZE: usize = 512;
/// XTS block size.
pub const BLOCK_SIZE: usize = 16;

struct Layer {
    data: BlockCipher,
    tweak: BlockCipher,
}

/// One cascaded XTS instance: either a single cipher or a VeraCrypt cascade.
pub struct Xts {
    /// In VeraCrypt's application (encryption) order.
    layers: Vec<Layer>,
    /// Added to every data unit number (system/partition encryption only;
    /// always 0 for file-hosted volumes).
    sector_offset: u64,
}

impl Xts {
    /// Build an XTS instance from a full XTS key, `primary || secondary`.
    ///
    /// `key` must be exactly `ea.key_size() * 2` bytes (or longer, in which
    /// case the surplus is ignored, which is how the 192-byte header key is
    /// used).
    pub fn new(ea: EncryptionAlgorithm, key: &[u8]) -> Result<Self> {
        let ks = ea.key_size();
        if key.len() < 2 * ks {
            return Err(Error::InvalidParameter(format!(
                "{ea} needs {} XTS key bytes, got {}",
                2 * ks,
                key.len()
            )));
        }
        let (primary, secondary) = key.split_at(ks);

        let mut layers = Vec::with_capacity(ea.ciphers().len());
        for (i, cipher) in ea.ciphers().iter().enumerate() {
            let mut data = BlockCipher::new(cipher.botan_name())?;
            data.set_key(&primary[i * CipherId::KEY_SIZE..(i + 1) * CipherId::KEY_SIZE])?;
            let mut tweak = BlockCipher::new(cipher.botan_name())?;
            tweak.set_key(&secondary[i * CipherId::KEY_SIZE..(i + 1) * CipherId::KEY_SIZE])?;
            if data.block_size()? != BLOCK_SIZE {
                return Err(Error::Unsupported(format!(
                    "cipher {} has block size {}",
                    cipher.name(),
                    data.block_size()?
                )));
            }
            layers.push(Layer { data, tweak });
        }
        Ok(Self { layers, sector_offset: 0 })
    }

    /// Set the data unit offset (system encryption only; 0 otherwise).
    pub fn set_sector_offset(&mut self, offset: u64) {
        self.sector_offset = offset;
    }

    /// Encrypt `buf` in place. `buf.len()` must be a multiple of 16, and
    /// `start_data_unit` is the data unit number of `buf[0]`
    /// (i.e. `host_byte_offset / 512`).
    pub fn encrypt(&self, buf: &mut [u8], start_data_unit: u64) -> Result<()> {
        for layer in &self.layers {
            self.pass(layer, buf, start_data_unit, true)?;
        }
        Ok(())
    }

    /// Decrypt `buf` in place; the exact inverse of [`Xts::encrypt`].
    pub fn decrypt(&self, buf: &mut [u8], start_data_unit: u64) -> Result<()> {
        for layer in self.layers.iter().rev() {
            self.pass(layer, buf, start_data_unit, false)?;
        }
        Ok(())
    }

    /// One full XTS pass with a single cipher/whitening pair over `buf`.
    fn pass(&self, layer: &Layer, buf: &mut [u8], start_data_unit: u64, encrypting: bool) -> Result<()> {
        if !buf.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::InvalidParameter(format!(
                "XTS input must be a multiple of {BLOCK_SIZE}, got {}",
                buf.len()
            )));
        }

        let mut data_unit = start_data_unit + self.sector_offset;
        let mut offset = 0usize;
        while offset < buf.len() {
            let unit_len = std::cmp::min(DATA_UNIT_SIZE, buf.len() - offset);
            debug_assert_eq!(unit_len % BLOCK_SIZE, 0);

            // T_0 = E_secondary(LE64(data_unit_no) || 0^8)
            let mut tweak = [0u8; BLOCK_SIZE];
            tweak[..8].copy_from_slice(&data_unit.to_le_bytes());
            layer.tweak.encrypt_in_place(&mut tweak)?;

            let mut block = offset;
            while block < offset + unit_len {
                let b = &mut buf[block..block + BLOCK_SIZE];
                xor_in_place(b, &tweak);
                if encrypting {
                    layer.data.encrypt_in_place(b)?;
                } else {
                    layer.data.decrypt_in_place(b)?;
                }
                xor_in_place(b, &tweak);
                multiply_by_x(&mut tweak);
                block += BLOCK_SIZE;
            }

            offset += unit_len;
            data_unit += 1;
        }
        Ok(())
    }
}

fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

/// Multiply the little-endian 128-bit whitening value by `x` in
/// GF(2^128) modulo `x^128 + x^7 + x^2 + x + 1`.
fn multiply_by_x(value: &mut [u8; BLOCK_SIZE]) {
    let mut carry_in = 0u8;
    for byte in value.iter_mut() {
        let carry_out = *byte >> 7;
        *byte = (*byte << 1) | carry_in;
        carry_in = carry_out;
    }
    if carry_in != 0 {
        value[0] ^= 0x87;
    }
}

impl std::fmt::Debug for Xts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xts")
            .field("ciphers", &self.layers.len())
            .field("sector_offset", &self.sector_offset)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::CipherId;

    #[test]
    fn multiply_by_x_reduction() {
        // The whitening value is a 128-bit little-endian integer: a low byte
        // shifts into the next byte without touching the reduction polynomial.
        let mut v = [0u8; 16];
        v[0] = 0x80;
        multiply_by_x(&mut v);
        assert_eq!(v[0], 0x00);
        assert_eq!(v[1], 0x01);
        assert!(v[2..].iter().all(|b| *b == 0));

        // Overflowing the top bit of the 128-bit value reduces modulo
        // x^128 + x^7 + x^2 + x + 1, i.e. XORs 0x87 into the lowest byte.
        let mut v = [0u8; 16];
        v[15] = 0x80;
        multiply_by_x(&mut v);
        assert_eq!(v[0], 0x87);
        assert!(v[1..].iter().all(|b| *b == 0));

        let mut v = [0u8; 16];
        v[0] = 0x01;
        v[15] = 0x80;
        multiply_by_x(&mut v);
        // 0x01 shifts up to 0x02, then the reduction XORs in 0x87.
        assert_eq!(v[0], 0x87 ^ 0x02);
        assert_eq!(v[1], 0x00);
        assert_eq!(v[15], 0x00);
    }

    #[test]
    fn xts_roundtrip_single_and_cascades() {
        let mut rng = botan::RandomNumberGenerator::new().unwrap();
        for ea in EncryptionAlgorithm::ALL {
            let key = rng.read(ea.key_size() * 2).unwrap();
            let xts = Xts::new(ea, &key).unwrap();
            // 3 full data units (including a partial one at the end).
            let plain = rng.read(512 * 3 + 448).unwrap();
            let mut buf = plain.clone();
            xts.encrypt(&mut buf, 1234).unwrap();
            assert_ne!(buf, plain, "{ea} did not encrypt");
            xts.decrypt(&mut buf, 1234).unwrap();
            assert_eq!(buf, plain, "{ea} roundtrip failed");
        }
    }

    #[test]
    fn xts_data_unit_number_matters() {
        let ea = EncryptionAlgorithm::Aes;
        let key = vec![0x42u8; 64];
        let xts = Xts::new(ea, &key).unwrap();
        let plain = vec![0u8; 512];
        let mut a = plain.clone();
        let mut b = plain.clone();
        xts.encrypt(&mut a, 0).unwrap();
        xts.encrypt(&mut b, 1).unwrap();
        assert_ne!(a, b);
        // Two XTS blocks of zeros with different data unit numbers must differ
        // in their first block as well.
        assert_ne!(a[..16], b[..16]);
    }

    /// Every cipher must be usable through Botan under the name we picked.
    #[test]
    fn cipher_names_exist() {
        for c in [CipherId::Aes, CipherId::Serpent, CipherId::Twofish, CipherId::Camellia, CipherId::Kuznyechik] {
            let mut bc = BlockCipher::new(c.botan_name())
                .unwrap_or_else(|e| panic!("botan has no {}: {e}", c.botan_name()));
            bc.set_key(&[0u8; 32]).unwrap();
            assert_eq!(bc.block_size().unwrap(), 16);
        }
    }

    #[test]
    fn cascade_order_is_reverse_of_display_name() {
        assert_eq!(
            EncryptionAlgorithm::from_name("AES-Twofish-Serpent").unwrap().ciphers(),
            &[CipherId::Serpent, CipherId::Twofish, CipherId::Aes]
        );
        assert_eq!(
            EncryptionAlgorithm::from_name("kuznyechik_serpent_camellia")
                .unwrap()
                .ciphers(),
            &[CipherId::Camellia, CipherId::Serpent, CipherId::Kuznyechik]
        );
    }
}
