//! Where the random bytes that build a volume come from.
//!
//! Salts, master keys, the throwaway keys of a full format and the fake hidden
//! headers all need randomness, and by default it comes from the operating
//! system's CSPRNG (Botan's system random number generator).
//!
//! [`RandomSupply::from_file`] replaces it with a stream derived from a file, so
//! that the same file always builds the same container byte for byte. That is
//! what VeraCrypt's `--random-source` switch is for on the command line, even
//! though VeraCrypt itself only *adds* the file's bytes to its entropy pool
//! (see `TextUserInterface::UserEnrichRandomPool`, which reads `PoolSize` bytes
//! of the file and calls `RandomNumberGenerator::AddToPool`): its goal is to run
//! a format without typing random characters, while ours is reproducibility, so
//! a test or an audit can rebuild a container. The result of the OS generator
//! stays unpredictable, which is why this is off by default.
//!
//! The stream is HMAC-SHA-512 in counter mode (the construction of NIST SP
//! 800-108): each 64-byte block is `HMAC-SHA-512(key, label || counter)`, with
//! `key` = `HMAC-SHA-512(seed_label, file bytes)`. Any file size works, and a
//! key derived this way does not repeat even for a one-byte source file.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Label used to derive the stream key from the file's bytes.
const SEED_LABEL: &[u8] = b"vcrs-random-source v1";
/// Label mixed into every block.
const BLOCK_LABEL: &[u8] = b"vcrs-random-source";
/// Digest size of HMAC-SHA-512, i.e. the block size of the stream.
const BLOCK_SIZE: usize = 64;

/// Where [`RandomSupply::bytes`] reads from.
#[derive(Debug, Clone)]
pub enum RandomSupply {
    /// The operating system's random generator (the default).
    System,
    /// A deterministic stream derived from `path`.
    File {
        /// The file the stream was derived from (for messages).
        path: PathBuf,
        /// Stream key derived from the file's contents.
        key: Vec<u8>,
        /// Counter of the next block to produce.
        counter: u64,
    },
}

impl RandomSupply {
    /// The operating system's random generator.
    pub fn system() -> Self {
        RandomSupply::System
    }

    /// A stream derived from `path`.
    ///
    /// Errors when the file cannot be read or is empty: an empty file would give
    /// a stream that is the same for every run, which is the opposite of a
    /// deliberate choice.
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("reading the random source {}: {e}", path.display()),
            ))
        })?;
        if data.is_empty() {
            return Err(Error::InvalidParameter(format!(
                "the random source {} is empty; it has to hold at least one byte",
                path.display()
            )));
        }
        let mut mac = botan::MsgAuthCode::new("HMAC(SHA-512)")?;
        mac.set_key(SEED_LABEL)?;
        mac.update(&data)?;
        let key = mac.finish()?;
        Ok(RandomSupply::File {
            path: path.to_path_buf(),
            key,
            counter: 0,
        })
    }

    /// Whether this supply is reproducible from a file.
    pub fn is_deterministic(&self) -> bool {
        matches!(self, RandomSupply::File { .. })
    }

    /// The file this supply was derived from, if any.
    pub fn path(&self) -> Option<&Path> {
        match self {
            RandomSupply::System => None,
            RandomSupply::File { path, .. } => Some(path),
        }
    }

    /// `len` random bytes.
    pub fn bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        match self {
            RandomSupply::System => {
                let mut rng = botan::RandomNumberGenerator::new()?;
                Ok(rng.read(len)?)
            }
            RandomSupply::File { key, counter, .. } => {
                let mut out = Vec::with_capacity(len + BLOCK_SIZE);
                while out.len() < len {
                    let mut mac = botan::MsgAuthCode::new("HMAC(SHA-512)")?;
                    mac.set_key(key)?;
                    let mut message = BLOCK_LABEL.to_vec();
                    message.extend_from_slice(&counter.to_be_bytes());
                    mac.update(&message)?;
                    out.extend_from_slice(&mac.finish()?);
                    *counter = counter.wrapping_add(1);
                }
                out.truncate(len);
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_supply_is_reproducible_and_different_files_differ() {
        let dir = std::env::temp_dir();
        let one = dir.join("vcrs-random-supply-one.bin");
        let two = dir.join("vcrs-random-supply-two.bin");
        std::fs::write(&one, b"seed one").unwrap();
        std::fs::write(&two, b"seed one!").unwrap();

        let mut a = RandomSupply::from_file(&one).unwrap();
        let mut b = RandomSupply::from_file(&one).unwrap();
        let mut c = RandomSupply::from_file(&two).unwrap();
        assert!(a.is_deterministic());

        // The stream has to be stable across instances and not repeat itself,
        // including when a request is not a multiple of the block size.
        let first = a.bytes(100).unwrap();
        assert_eq!(first.len(), 100);
        assert_eq!(first, b.bytes(100).unwrap());
        assert_ne!(first, c.bytes(100).unwrap());
        assert_ne!(first[..64], first[64..100]);
        // Two instances step through the same stream, and it moves on instead of
        // repeating a block.
        let next = a.bytes(64).unwrap();
        assert_eq!(next, b.bytes(64).unwrap());
        assert_ne!(next, first[..64].to_vec());

        // A one-byte source still gives a full-size key.
        let tiny = dir.join("vcrs-random-supply-tiny.bin");
        std::fs::write(&tiny, b"x").unwrap();
        let mut small = RandomSupply::from_file(&tiny).unwrap();
        assert_eq!(small.bytes(64).unwrap().len(), 64);

        for path in [one, two, tiny] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn an_empty_file_is_refused() {
        let path = std::env::temp_dir().join("vcrs-random-supply-empty.bin");
        std::fs::write(&path, b"").unwrap();
        let err = RandomSupply::from_file(&path).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_system_supply_is_not_deterministic() {
        let mut supply = RandomSupply::system();
        assert!(!supply.is_deterministic());
        assert_eq!(supply.path(), None);
        assert_ne!(supply.bytes(32).unwrap(), supply.bytes(32).unwrap());
    }
}
