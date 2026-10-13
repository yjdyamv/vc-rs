//! `vcrs-core` — a byte-level compatible reimplementation of the VeraCrypt
//! volume format on top of [Botan].
//!
//! The module layout mirrors the parts of the VeraCrypt source that define the
//! on-disk format:
//!
//! | module | VeraCrypt source |
//! |---|---|
//! | [`header`] | `src/Volume/VolumeHeader.cpp` |
//! | [`layout`] | `src/Volume/VolumeLayout.cpp` |
//! | [`prf`] | `src/Volume/Pkcs5Kdf.h`, `src/Common/Pkcs5.c` |
//! | [`cipher`] | `src/Volume/Cipher.cpp`, `src/Volume/EncryptionAlgorithm.cpp` |
//! | [`keyfile`] | `src/Common/Keyfiles.c` |
//! | [`xts`] | `src/Volume/EncryptionModeXTS.cpp` |
//! | [`volume`] | `src/Core/VolumeCreator.cpp`, `src/Volume/Volume.cpp` |
//!
//! ```
//! # fn main() -> vcrs_core::Result<()> {
//! use vcrs_core::{CreateOptions, Volume};
//!
//! let path = std::env::temp_dir().join("vcrs-doc-example.hc");
//! let opts = CreateOptions { password: b"secret".to_vec(), ..Default::default() };
//! let volume = Volume::create(&path, 300 * 1024, &opts)?;
//! drop(volume);
//!
//! let volume = Volume::open(&path, &vcrs_core::OpenOptions {
//!     password: b"secret".to_vec(),
//!     ..Default::default()
//! })?;
//! assert_eq!(volume.data_size, 300 * 1024 - 256 * 1024);
//! # std::fs::remove_file(path).ok();
//! # Ok(())
//! # }
//! ```
//!
//! [Botan]: https://botan.randombit.net/

pub mod cipher;
pub mod error;
pub mod header;
pub mod keyfile;
pub mod layout;
pub mod prf;
pub mod volume;
pub mod xts;

pub use cipher::{CipherId, EncryptionAlgorithm};
pub use error::{Error, Result};
pub use header::{VolumeHeader, VolumeType};
pub use keyfile::apply_keyfiles;
pub use layout::VolumeLayout;
pub use prf::Prf;
pub use volume::{
    backup_headers, decrypt_in_place, decrypt_in_place_stopping_after, encrypt_in_place,
    encrypt_in_place_stopping_after, looks_quick_formatted, read_header_area, read_header_group,
    restore_headers, restore_headers_from_embedded, restore_headers_from_master_key, CreateOptions,
    DecryptOutcome, InPlaceState, OpenOptions, ProtectedRange, RestoreHeaderOptions, Volume,
    IN_PLACE_CHUNK_SIZE, IN_PLACE_HEADER_UPDATE_INTERVAL, MIN_IN_PLACE_DATA_SIZE,
};
pub use xts::Xts;

/// Version of the VeraCrypt volume format this crate implements
/// (`VOLUME_HEADER_VERSION`).
pub const VOLUME_HEADER_VERSION: u16 = header::VOLUME_HEADER_VERSION;
