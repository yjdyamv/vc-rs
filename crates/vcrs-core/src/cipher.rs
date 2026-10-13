//! VeraCrypt encryption algorithms (cascades) and their VeraCrypt-compatible
//! cipher ordering.
//!
//! # Ordering rule (verified against src/Volume/Cipher.cpp)
//!
//! A cascade's *display name* lists the ciphers in the reverse of the order in
//! which they are applied. `EncryptionAlgorithm::Ciphers` (the order used when
//! encrypting, and reversed when decrypting) is therefore
//! `display_name.split('-').rev()`.
//!
//! So `AES-Twofish-Serpent` encrypts as `Serpent(AES? no: Serpent, Twofish, AES)`
//! and decrypts as `AES`, `Twofish`, `Serpent`.
//!
//! The XTS key material is split over that same application order: cipher `i`
//! takes `key[i*32 .. (i+1)*32]` from the primary key, and likewise from the
//! secondary (tweak) key.

/// A 256-bit block cipher supported by VeraCrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherId {
    Aes,
    Serpent,
    Twofish,
    Camellia,
    Kuznyechik,
}

impl CipherId {
    /// VeraCrypt's numeric cipher id (`src/Common/Crypto.h`).
    pub const fn vc_id(self) -> u8 {
        match self {
            CipherId::Aes => 1,
            CipherId::Serpent => 2,
            CipherId::Twofish => 3,
            CipherId::Camellia => 4,
            CipherId::Kuznyechik => 5,
        }
    }

    /// Human readable cipher name as shown by VeraCrypt.
    pub const fn name(self) -> &'static str {
        match self {
            CipherId::Aes => "AES",
            CipherId::Serpent => "Serpent",
            CipherId::Twofish => "Twofish",
            CipherId::Camellia => "Camellia",
            CipherId::Kuznyechik => "Kuznyechik",
        }
    }

    /// Name to hand to `botan::BlockCipher::new`.
    ///
    /// All VeraCrypt ciphers use 256-bit keys. Note that Botan's Camellia
    /// requires the explicit key size in the name.
    pub const fn botan_name(self) -> &'static str {
        match self {
            CipherId::Aes => "AES-256",
            CipherId::Serpent => "Serpent",
            CipherId::Twofish => "Twofish",
            CipherId::Camellia => "Camellia-256",
            CipherId::Kuznyechik => "Kuznyechik",
        }
    }

    /// Every cipher has a 16-byte block and a 32-byte key in VeraCrypt.
    pub const BLOCK_SIZE: usize = 16;
    pub const KEY_SIZE: usize = 32;
}

/// A VeraCrypt encryption algorithm: either a single cipher or a cascade of up
/// to three, in VeraCrypt's *application* order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionAlgorithm {
    Aes,
    Serpent,
    Twofish,
    Camellia,
    Kuznyechik,
    AesTwofish,
    AesTwofishSerpent,
    CamelliaKuznyechik,
    CamelliaSerpent,
    KuznyechikAes,
    KuznyechikSerpentCamellia,
    KuznyechikTwofish,
    SerpentAes,
    SerpentTwofishAes,
    TwofishSerpent,
}

use CipherId::{Aes, Camellia, Kuznyechik, Serpent, Twofish};

impl EncryptionAlgorithm {
    /// All algorithms in VeraCrypt's `GetAvailableAlgorithms()` order.
    pub const ALL: [EncryptionAlgorithm; 15] = [
        EncryptionAlgorithm::Aes,
        EncryptionAlgorithm::Serpent,
        EncryptionAlgorithm::Twofish,
        EncryptionAlgorithm::Camellia,
        EncryptionAlgorithm::Kuznyechik,
        EncryptionAlgorithm::AesTwofish,
        EncryptionAlgorithm::AesTwofishSerpent,
        EncryptionAlgorithm::CamelliaKuznyechik,
        EncryptionAlgorithm::CamelliaSerpent,
        EncryptionAlgorithm::KuznyechikAes,
        EncryptionAlgorithm::KuznyechikSerpentCamellia,
        EncryptionAlgorithm::KuznyechikTwofish,
        EncryptionAlgorithm::SerpentAes,
        EncryptionAlgorithm::SerpentTwofishAes,
        EncryptionAlgorithm::TwofishSerpent,
    ];

    /// Ciphers in the order they are applied when *encrypting*.
    ///
    /// Verified against `src/Volume/Cipher.cpp` constructors.
    pub const fn ciphers(self) -> &'static [CipherId] {
        match self {
            EncryptionAlgorithm::Aes => &[Aes],
            EncryptionAlgorithm::Serpent => &[Serpent],
            EncryptionAlgorithm::Twofish => &[Twofish],
            EncryptionAlgorithm::Camellia => &[Camellia],
            EncryptionAlgorithm::Kuznyechik => &[Kuznyechik],
            EncryptionAlgorithm::AesTwofish => &[Twofish, Aes],
            EncryptionAlgorithm::AesTwofishSerpent => &[Serpent, Twofish, Aes],
            EncryptionAlgorithm::CamelliaKuznyechik => &[Kuznyechik, Camellia],
            EncryptionAlgorithm::CamelliaSerpent => &[Serpent, Camellia],
            EncryptionAlgorithm::KuznyechikAes => &[Aes, Kuznyechik],
            EncryptionAlgorithm::KuznyechikSerpentCamellia => &[Camellia, Serpent, Kuznyechik],
            EncryptionAlgorithm::KuznyechikTwofish => &[Twofish, Kuznyechik],
            EncryptionAlgorithm::SerpentAes => &[Aes, Serpent],
            EncryptionAlgorithm::SerpentTwofishAes => &[Aes, Twofish, Serpent],
            EncryptionAlgorithm::TwofishSerpent => &[Serpent, Twofish],
        }
    }

    /// VeraCrypt display name, i.e. the cipher names in reverse application
    /// order joined with `-` (e.g. `AES-Twofish-Serpent`).
    pub const fn name(self) -> &'static str {
        match self {
            EncryptionAlgorithm::Aes => "AES",
            EncryptionAlgorithm::Serpent => "Serpent",
            EncryptionAlgorithm::Twofish => "Twofish",
            EncryptionAlgorithm::Camellia => "Camellia",
            EncryptionAlgorithm::Kuznyechik => "Kuznyechik",
            EncryptionAlgorithm::AesTwofish => "AES-Twofish",
            EncryptionAlgorithm::AesTwofishSerpent => "AES-Twofish-Serpent",
            EncryptionAlgorithm::CamelliaKuznyechik => "Camellia-Kuznyechik",
            EncryptionAlgorithm::CamelliaSerpent => "Camellia-Serpent",
            EncryptionAlgorithm::KuznyechikAes => "Kuznyechik-AES",
            EncryptionAlgorithm::KuznyechikSerpentCamellia => "Kuznyechik-Serpent-Camellia",
            EncryptionAlgorithm::KuznyechikTwofish => "Kuznyechik-Twofish",
            EncryptionAlgorithm::SerpentAes => "Serpent-AES",
            EncryptionAlgorithm::SerpentTwofishAes => "Serpent-Twofish-AES",
            EncryptionAlgorithm::TwofishSerpent => "Twofish-Serpent",
        }
    }

    /// Number of XTS key bytes (primary or secondary) for this algorithm: 32
    /// per cipher in the cascade.
    pub const fn key_size(self) -> usize {
        self.ciphers().len() * CipherId::KEY_SIZE
    }

    /// Parse a VeraCrypt display name (case-insensitively, `-` or `_`).
    pub fn from_name(s: &str) -> Option<Self> {
        let norm = s.to_ascii_lowercase().replace('_', "-");
        EncryptionAlgorithm::ALL
            .into_iter()
            .find(|ea| ea.name().to_ascii_lowercase() == norm)
    }
}

impl std::fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
