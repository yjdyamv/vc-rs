//! VeraCrypt volume header: layout, serialization and (de)encryption.
//!
//! Layout of the 512-byte *effective* header (the first 512 bytes of the header
//! region; all multi-byte integers are big-endian):
//!
//! | absolute offset | size | field                                        |
//! |-----------------|------|----------------------------------------------|
//! | 0               | 64   | random salt (never encrypted)                |
//! | 64              | 4    | `"VERA"` magic                               |
//! | 68              | 2    | header version (5 for current volumes)       |
//! | 70              | 2    | required program version (`0x010b`)          |
//! | 72              | 4    | CRC-32 of the 256-byte master key area       |
//! | 76              | 8    | volume creation time (0 as written)          |
//! | 84              | 8    | header modification time (0 as written)      |
//! | 92              | 8    | hidden volume size                           |
//! | 100             | 8    | volume data size                             |
//! | 108             | 8    | encrypted area start                         |
//! | 116             | 8    | encrypted area length                        |
//! | 124             | 4    | flags                                        |
//! | 128             | 4    | sector size                                  |
//! | 132             | 120  | reserved, zero                               |
//! | 252             | 4    | CRC-32 of bytes 64..252 of the header        |
//! | 256             | 256  | XTS master key area (`key1 || key2`, zero pad)|
//!
//! Everything from offset 64 onwards is encrypted with the header key
//! (`Xts::encrypt(region[64..], data_unit_no = 0)`).

use crate::cipher::EncryptionAlgorithm;
use crate::prf::Prf;
use crate::xts::{Xts, BLOCK_SIZE, DATA_UNIT_SIZE};
use crate::{Error, Result};

/// Size of the header region for current (V2) volumes.
pub const VOLUME_HEADER_SIZE: u64 = 64 * 1024;
/// Size of the legacy (V1) header region.
pub const VOLUME_HEADER_SIZE_LEGACY: u64 = 512;
/// `TC_VOLUME_HEADER_GROUP_SIZE`.
pub const VOLUME_HEADER_GROUP_SIZE: u64 = 2 * VOLUME_HEADER_SIZE;
/// `TC_TOTAL_VOLUME_HEADERS_SIZE`: primary + backup header groups.
pub const TOTAL_VOLUME_HEADERS_SIZE: u64 = 2 * VOLUME_HEADER_GROUP_SIZE;

/// The salt occupies the first 64 bytes of the header region and is plaintext.
pub const HEADER_SALT_SIZE: usize = 64;
/// Offset of the first encrypted byte within the header region.
pub const HEADER_ENCRYPTED_DATA_OFFSET: usize = HEADER_SALT_SIZE;
/// Size of the encrypted part of the *effective* 512-byte header.
pub const HEADER_ENCRYPTED_DATA_SIZE: usize = 512 - HEADER_SALT_SIZE;
/// Size of the master key area (192 used for the largest cascade, 256 reserved).
pub const MASTER_KEY_AREA_SIZE: usize = 256;
/// Offset of the master key area inside the header region.
pub const MASTER_KEY_AREA_OFFSET: usize = 256;
/// Offset of the master key area inside the encrypted part of the header.
pub const MASTER_KEY_AREA_REL_OFFSET: usize = MASTER_KEY_AREA_OFFSET - HEADER_ENCRYPTED_DATA_OFFSET;

/// Current header version.
pub const VOLUME_HEADER_VERSION: u16 = 5;
/// Oldest header version we can read.
pub const MIN_ALLOWED_HEADER_VERSION: u16 = 1;
/// `TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION`, written by current VeraCrypt.
pub const TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION: u16 = 0x010b;

/// Highest `required_min_version` we can satisfy: the program version whose
/// on-disk format vc-rs implements (VeraCrypt 1.26.30 writes 0x010b headers, but
/// a volume may legitimately require up to the version that created it).
pub const MAX_SUPPORTED_PROGRAM_VERSION: u16 = 0x0126;

/// `TC_HEADER_FLAG_ENCRYPTED_SYSTEM`.
pub const HEADER_FLAG_ENCRYPTED_SYSTEM: u32 = 0x1;
/// `TC_HEADER_FLAG_NONSYS_INPLACE_ENC`.
pub const HEADER_FLAG_NONSYS_INPLACE_ENC: u32 = 0x2;

/// Magic at header offset 64.
pub const MAGIC: &[u8; 4] = b"VERA";
/// Smallest and largest legal sector size.
pub const MIN_SECTOR_SIZE: u32 = 512;
pub const MAX_SECTOR_SIZE: u32 = 4096;

// Field offsets (absolute, inside the header region). The salt occupies
// [0,64), these offsets are relative to the start of the region, i.e. the
// encoded fields live at `MASTER_KEY_AREA_OFFSET - 64 - 188 = 4` in the
// "encrypted header data" buffer whose first byte is the magic.
pub const OFF_MAGIC: usize = 64;
pub const OFF_VERSION: usize = 68;
pub const OFF_REQUIRED_VERSION: usize = 70;
pub const OFF_KEY_AREA_CRC: usize = 72;
pub const OFF_CREATION_TIME: usize = 76;
pub const OFF_MODIFICATION_TIME: usize = 84;
pub const OFF_HIDDEN_VOLUME_SIZE: usize = 92;
pub const OFF_VOLUME_SIZE: usize = 100;
pub const OFF_ENCRYPTED_AREA_START: usize = 108;
pub const OFF_ENCRYPTED_AREA_LENGTH: usize = 116;
pub const OFF_FLAGS: usize = 124;
pub const OFF_SECTOR_SIZE: usize = 128;
pub const OFF_HEADER_CRC: usize = 252;

/// Whether a header describes a normal or a hidden volume.
///
/// Not stored as its own field: it is implied by `hidden_volume_data_size`
/// (non-zero inside a hidden volume's header) and by which offset the header
/// was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeType {
    Normal,
    Hidden,
}

impl VolumeType {
    pub const fn name(self) -> &'static str {
        match self {
            VolumeType::Normal => "normal",
            VolumeType::Hidden => "hidden",
        }
    }
}

/// A parsed VeraCrypt volume header.
#[derive(Debug, Clone)]
pub struct VolumeHeader {
    pub version: u16,
    pub required_min_version: u16,
    /// Not serialized directly; derived from `hidden_volume_data_size`.
    pub volume_type: VolumeType,
    pub creation_time: u64,
    pub modification_time: u64,
    pub hidden_volume_data_size: u64,
    pub volume_data_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_length: u64,
    pub flags: u32,
    pub sector_size: u32,
    /// The encryption algorithm. Not stored in the header: it is discovered by
    /// trial decryption and remembered by the caller.
    pub ea: EncryptionAlgorithm,
    /// The PRF. Not stored in the header: discovered by trial decryption.
    pub prf: Prf,
    pub salt: Vec<u8>,
    /// `key1 || key2` for XTS, i.e. `ea.key_size() * 2` bytes.
    pub master_key: Vec<u8>,
}

impl VolumeHeader {
    /// Size of the master key area actually used by this header's algorithm.
    pub fn master_key_len(&self) -> usize {
        self.ea.key_size() * 2
    }

    pub fn is_encrypted_system(&self) -> bool {
        self.flags & HEADER_FLAG_ENCRYPTED_SYSTEM != 0
    }

    pub fn is_non_system_inplace_enc(&self) -> bool {
        self.flags & HEADER_FLAG_NONSYS_INPLACE_ENC != 0
    }

    /// Build the plaintext header region of `header_size` bytes.
    ///
    /// Everything that serialization does not write stays zero, matching
    /// `VolumeHeader::Serialize()` which is always called on a zeroed buffer.
    pub fn serialize(&self, header_size: usize) -> Result<Vec<u8>> {
        if header_size < 512 || header_size % DATA_UNIT_SIZE != 0 {
            return Err(Error::InvalidParameter(format!(
                "header region size must be a multiple of {DATA_UNIT_SIZE} and >= 512, got {header_size}"
            )));
        }
        if self.salt.len() != HEADER_SALT_SIZE {
            return Err(Error::InvalidParameter(format!(
                "salt must be {HEADER_SALT_SIZE} bytes, got {}",
                self.salt.len()
            )));
        }
        let key_len = self.master_key_len();
        if self.master_key.len() < key_len {
            return Err(Error::InvalidParameter(format!(
                "master key for {} must be {key_len} bytes, got {}",
                self.ea,
                self.master_key.len()
            )));
        }

        let mut buf = vec![0u8; header_size];
        buf[..HEADER_SALT_SIZE].copy_from_slice(&self.salt);

        buf[OFF_MAGIC..OFF_MAGIC + MAGIC.len()].copy_from_slice(MAGIC);
        // The master key must be in place before the key-area CRC is computed
        // (VeraCrypt's Serialize copies DataAreaKey first, then serializes).
        buf[MASTER_KEY_AREA_OFFSET..MASTER_KEY_AREA_OFFSET + key_len]
            .copy_from_slice(&self.master_key[..key_len]);
        buf[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&self.version.to_be_bytes());
        buf[OFF_REQUIRED_VERSION..OFF_REQUIRED_VERSION + 2]
            .copy_from_slice(&self.required_min_version.to_be_bytes());
        // CRC of the 256-byte master key area (which includes its zero padding).
        let key_area = &buf[MASTER_KEY_AREA_OFFSET..MASTER_KEY_AREA_OFFSET + MASTER_KEY_AREA_SIZE];
        let key_area_crc = crc32(key_area);
        buf[OFF_KEY_AREA_CRC..OFF_KEY_AREA_CRC + 4].copy_from_slice(&key_area_crc.to_be_bytes());
        buf[OFF_CREATION_TIME..OFF_CREATION_TIME + 8]
            .copy_from_slice(&self.creation_time.to_be_bytes());
        buf[OFF_MODIFICATION_TIME..OFF_MODIFICATION_TIME + 8]
            .copy_from_slice(&self.modification_time.to_be_bytes());
        buf[OFF_HIDDEN_VOLUME_SIZE..OFF_HIDDEN_VOLUME_SIZE + 8]
            .copy_from_slice(&self.hidden_volume_data_size.to_be_bytes());
        buf[OFF_VOLUME_SIZE..OFF_VOLUME_SIZE + 8]
            .copy_from_slice(&self.volume_data_size.to_be_bytes());
        buf[OFF_ENCRYPTED_AREA_START..OFF_ENCRYPTED_AREA_START + 8]
            .copy_from_slice(&self.encrypted_area_start.to_be_bytes());
        buf[OFF_ENCRYPTED_AREA_LENGTH..OFF_ENCRYPTED_AREA_LENGTH + 8]
            .copy_from_slice(&self.encrypted_area_length.to_be_bytes());
        buf[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&self.flags.to_be_bytes());
        buf[OFF_SECTOR_SIZE..OFF_SECTOR_SIZE + 4].copy_from_slice(&self.sector_size.to_be_bytes());
        // Header CRC over the 188 bytes that end at the CRC field itself.
        let header_crc = crc32(&buf[OFF_MAGIC..OFF_HEADER_CRC]);
        buf[OFF_HEADER_CRC..OFF_HEADER_CRC + 4].copy_from_slice(&header_crc.to_be_bytes());

        Ok(buf)
    }

    /// Serialize and encrypt the whole header region with `header_key`
    /// (the 192-byte derived key).
    pub fn encrypt(&self, header_size: usize, header_key: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_salt(header_size, header_key, &self.salt)
    }

    /// Like [`Self::encrypt`], but writes `salt` into the region's first 64 bytes
    /// and derives nothing — the caller must have derived `header_key` from that
    /// same salt.
    ///
    /// VeraCrypt encrypts the backup header with a *fresh* random salt
    /// (`VolumeCreator::CreateVolume`, `backupHeaderSalt`), so the backup region
    /// is not just a copy of the primary one.
    pub fn encrypt_with_salt(&self, header_size: usize, header_key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        let mut region = self.serialize(header_size)?;
        region[..HEADER_SALT_SIZE].copy_from_slice(salt);
        let xts = Xts::new(self.ea, header_key)?;
        xts.encrypt(&mut region[HEADER_ENCRYPTED_DATA_OFFSET..], 0)?;
        Ok(region)
    }

    /// Cheap trial-decryption probe: does `header_key` + `ea` decrypt the first
    /// 16-byte block of the header data area to the "VERA" magic?
    ///
    /// During trial decryption one 192-byte key serves every encryption
    /// algorithm (each EA only consumes a prefix), so this lets the caller test
    /// all EAs for a derived key while decrypting 16 bytes instead of 448.
    pub fn region_has_magic(region: &[u8], header_key: &[u8], ea: EncryptionAlgorithm) -> Result<bool> {
        if region.len() < HEADER_ENCRYPTED_DATA_OFFSET + BLOCK_SIZE {
            return Err(Error::InvalidParameter(format!(
                "header region too short to probe: {} bytes",
                region.len()
            )));
        }
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&region[HEADER_ENCRYPTED_DATA_OFFSET..HEADER_ENCRYPTED_DATA_OFFSET + BLOCK_SIZE]);
        let xts = Xts::new(ea, header_key)?;
        xts.decrypt(&mut block, 0)?;
        Ok(&block[..MAGIC.len()] == MAGIC)
    }

    /// Decrypt and parse a header region.
    ///
    /// Returns `Err(Error::InvalidHeader)` when the region does not hold a
    /// valid header for this key (which, during trial decryption, usually just
    /// means "wrong key"). `ea`/`prf` must be the ones used to derive
    /// `header_key`, and are stored in the returned header.
    pub fn decrypt(region: &[u8], header_key: &[u8], ea: EncryptionAlgorithm, prf: Prf) -> Result<VolumeHeader> {
        if region.len() < 512 || region.len() % DATA_UNIT_SIZE != 0 {
            return Err(Error::InvalidParameter(format!(
                "header region size must be a multiple of {DATA_UNIT_SIZE} and >= 512, got {}",
                region.len()
            )));
        }
        let xts = Xts::new(ea, header_key)?;
        let mut plain = region.to_vec();
        xts.decrypt(&mut plain[HEADER_ENCRYPTED_DATA_OFFSET..], 0)?;

        let salt = plain[..HEADER_SALT_SIZE].to_vec();

        if &plain[OFF_MAGIC..OFF_MAGIC + MAGIC.len()] != MAGIC {
            return Err(Error::InvalidHeader("magic mismatch".into()));
        }
        let version = u16::from_be_bytes(plain[OFF_VERSION..OFF_VERSION + 2].try_into().unwrap());
        if version < MIN_ALLOWED_HEADER_VERSION {
            return Err(Error::InvalidHeader(format!(
                "header version {version} is below the minimum {MIN_ALLOWED_HEADER_VERSION}"
            )));
        }
        if version > VOLUME_HEADER_VERSION {
            return Err(Error::HigherVersionRequired(version));
        }
        if version >= 4 {
            let expected =
                u32::from_be_bytes(plain[OFF_HEADER_CRC..OFF_HEADER_CRC + 4].try_into().unwrap());
            let actual = crc32(&plain[OFF_MAGIC..OFF_HEADER_CRC]);
            if expected != actual {
                return Err(Error::InvalidHeader("header CRC-32 mismatch".into()));
            }
        }
        let required_min_version =
            u16::from_be_bytes(plain[OFF_REQUIRED_VERSION..OFF_REQUIRED_VERSION + 2].try_into().unwrap());
        if required_min_version > MAX_SUPPORTED_PROGRAM_VERSION {
            return Err(Error::HigherVersionRequired(required_min_version));
        }
        let key_area_crc =
            u32::from_be_bytes(plain[OFF_KEY_AREA_CRC..OFF_KEY_AREA_CRC + 4].try_into().unwrap());
        let key_len = ea.key_size() * 2;
        let key_area =
            &plain[MASTER_KEY_AREA_OFFSET..MASTER_KEY_AREA_OFFSET + MASTER_KEY_AREA_SIZE];
        if version >= 5 {
            // The CRC covers the fixed 256-byte area, independent of key length.
            if key_area_crc != crc32(key_area) {
                return Err(Error::InvalidHeader("master key area CRC-32 mismatch".into()));
            }
        } else if key_area_crc != crc32(&key_area[..key_len]) {
            // Legacy (pre-5) headers only cover the key bytes in use.
            return Err(Error::InvalidHeader("master key area CRC-32 mismatch".into()));
        }

        let sector_size = if version < 5 {
            MIN_SECTOR_SIZE
        } else {
            u32::from_be_bytes(plain[OFF_SECTOR_SIZE..OFF_SECTOR_SIZE + 4].try_into().unwrap())
        };
        if !(MIN_SECTOR_SIZE..=MAX_SECTOR_SIZE).contains(&sector_size)
            || sector_size % MIN_SECTOR_SIZE != 0
        {
            return Err(Error::InvalidHeader(format!("invalid sector size {sector_size}")));
        }

        let master_key = key_area[..key_len].to_vec();
        let hidden_volume_data_size = u64::from_be_bytes(
            plain[OFF_HIDDEN_VOLUME_SIZE..OFF_HIDDEN_VOLUME_SIZE + 8].try_into().unwrap(),
        );

        Ok(VolumeHeader {
            version,
            required_min_version,
            // A hidden volume's header stores its own size here; a normal
            // header stores zero (VeraCrypt's Deserialize does the same).
            volume_type: if hidden_volume_data_size != 0 {
                VolumeType::Hidden
            } else {
                VolumeType::Normal
            },
            creation_time: u64::from_be_bytes(
                plain[OFF_CREATION_TIME..OFF_CREATION_TIME + 8].try_into().unwrap(),
            ),
            modification_time: u64::from_be_bytes(
                plain[OFF_MODIFICATION_TIME..OFF_MODIFICATION_TIME + 8].try_into().unwrap(),
            ),
            hidden_volume_data_size,
            volume_data_size: u64::from_be_bytes(
                plain[OFF_VOLUME_SIZE..OFF_VOLUME_SIZE + 8].try_into().unwrap(),
            ),
            encrypted_area_start: u64::from_be_bytes(
                plain[OFF_ENCRYPTED_AREA_START..OFF_ENCRYPTED_AREA_START + 8]
                    .try_into()
                    .unwrap(),
            ),
            encrypted_area_length: u64::from_be_bytes(
                plain[OFF_ENCRYPTED_AREA_LENGTH..OFF_ENCRYPTED_AREA_LENGTH + 8]
                    .try_into()
                    .unwrap(),
            ),
            flags: u32::from_be_bytes(plain[OFF_FLAGS..OFF_FLAGS + 4].try_into().unwrap()),
            sector_size,
            ea,
            prf,
            salt,
            master_key,
        })
    }

    /// XTS key for the data area: `master_key[..2*key_size]`.
    pub fn data_key(&self) -> &[u8] {
        let n = self.master_key_len();
        &self.master_key[..n.min(self.master_key.len())]
    }
}

/// CRC-32 as used by VeraCrypt (`src/Common/Crc.c`): reflected, polynomial
/// `0xEDB88320`, init `0xFFFFFFFF`, final XOR `0xFFFFFFFF`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut r: u32 = 0xFFFF_FFFF;
    for byte in data {
        r ^= u32::from(*byte);
        for _ in 0..8 {
            r = if r & 1 != 0 { (r >> 1) ^ 0xEDB8_8320 } else { r >> 1 };
        }
    }
    r ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    /// VeraCrypt's own CRC self-test (`crc32_selftests` in src/Common/Crc.c).
    #[test]
    fn crc32_matches_veracrypt_selftest() {
        let test_data: Vec<u8> = (0u8..32).collect();
        assert_eq!(crc32(&test_data), 0x9126_7E8A);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926); // standard check value
    }

    #[test]
    fn header_roundtrip() {
        let header = VolumeHeader {
            version: VOLUME_HEADER_VERSION,
            required_min_version: TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION,
            volume_type: VolumeType::Normal,
            creation_time: 0,
            modification_time: 0,
            hidden_volume_data_size: 0,
            volume_data_size: 1_000_000,
            encrypted_area_start: 131_072,
            encrypted_area_length: 1_000_000,
            flags: 0,
            sector_size: 512,
            ea: EncryptionAlgorithm::AesTwofishSerpent,
            prf: Prf::Sha512,
            salt: vec![0x5A; HEADER_SALT_SIZE],
            master_key: (0..192u8).collect(),
        };
        let key = vec![0x11u8; 192];
        let region = header.encrypt(64 * 1024, &key).unwrap();
        // Salt must be plaintext.
        assert_eq!(&region[..64], &[0x5Au8; 64]);
        let back = VolumeHeader::decrypt(&region, &key, header.ea, header.prf).unwrap();
        assert_eq!(back.volume_data_size, header.volume_data_size);
        assert_eq!(back.encrypted_area_start, header.encrypted_area_start);
        assert_eq!(back.master_key, header.master_key);
        assert_eq!(back.sector_size, 512);
        assert_eq!(back.ea, EncryptionAlgorithm::AesTwofishSerpent);

        // Wrong key must not parse.
        let other = vec![0x22u8; 192];
        assert!(VolumeHeader::decrypt(&region, &other, header.ea, header.prf).is_err());
    }
}
