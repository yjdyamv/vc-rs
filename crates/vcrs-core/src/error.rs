//! Error type for the vc-rs core crate.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while creating, opening or using a volume.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A Botan operation failed (unsupported algorithm, bad key size, ...).
    Botan(botan::Error),
    /// Underlying host I/O failed.
    Io(std::io::Error),
    /// A raw Botan FFI call failed (see `botan_pwdhash` and friends).
    BotanFfi {
        /// The Botan C function that failed.
        function: &'static str,
        /// Botan's status code.
        code: std::ffi::c_int,
        /// Human readable description from `botan_error_description`.
        message: String,
    },
    /// No header could be decrypted: wrong password/PIM/PRF, or not a volume.
    PasswordIncorrect,
    /// The caller passed something the layout maths cannot accept.
    InvalidParameter(String),
    /// A header was decrypted but failed structural validation.
    InvalidHeader(String),
    /// The volume uses a feature vc-rs does not implement yet.
    Unsupported(String),
    /// The header needs a newer VeraCrypt than the format version supports.
    HigherVersionRequired(u16),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Botan(e) => write!(f, "botan: {e}"),
            Error::BotanFfi { function, code, message } => {
                write!(f, "botan: {function} failed ({code}): {message}")
            }
            Error::Io(e) => write!(f, "io: {e}"),
            Error::PasswordIncorrect => {
                write!(f, "incorrect password/PIM/PRF or not a VeraCrypt volume")
            }
            Error::InvalidParameter(m) => write!(f, "invalid parameter: {m}"),
            Error::InvalidHeader(m) => write!(f, "invalid volume header: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::HigherVersionRequired(v) => {
                write!(f, "volume requires a newer VeraCrypt (header requires program version 0x{v:04x})")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Botan(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<botan::Error> for Error {
    fn from(e: botan::Error) -> Self {
        Error::Botan(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
