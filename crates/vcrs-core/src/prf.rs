//! Password-based key derivation, byte-compatible with VeraCrypt.
//!
//! VeraCrypt derives a **192-byte** header key from the (UTF-8) password and
//! the 64-byte header salt. Two families exist:
//!
//! * PBKDF2 over HMAC-SHA512 / HMAC-SHA256 / HMAC-BLAKE2s / HMAC-Whirlpool /
//!   HMAC-Streebog-512, with `pim <= 0 ? 500000 : 15000 + pim*1000` iterations.
//! * Argon2id, parameterised from the PIM (see [`argon2_params`]).
//!
//! The salt is used as-is (no separator, no KDF-specific salt derivation).
//!
//! We implement PBKDF2 by hand over `botan::MsgAuthCode` rather than calling
//! `botan::pbkdf`, because Botan's safe wrapper takes the password as a `&str`
//! and passes length 0 (strlen semantics). VeraCrypt treats the password as an
//! opaque byte string, so the byte-exact path must stay byte-oriented.

use crate::{Error, Result};

/// Size of the derived header key. VeraCrypt always derives this many bytes:
/// the largest serialized encryption-algorithm key is 3*32 = 96 bytes for a
/// three-cipher cascade, doubled for XTS = 192.
pub const HEADER_KEY_SIZE: usize = 192;
/// Size of the random per-header salt.
pub const SALT_SIZE: usize = 64;

/// The largest PIM VeraCrypt's dialogs accept. Above it the count is refused
/// rather than clamped: a PIM out of range is a typo, and a typo here means a
/// key derivation weaker than the operator believes they asked for.
///
/// (VeraCrypt's own maximum, `MAX_PIM_VALUE` in `src/Common/Pkcs5.h`.)
pub const MAX_PIM: i32 = 2_147_468;

/// Whether a PIM is one this program will use.
pub const fn pim_is_valid(pim: i32) -> bool {
    pim >= 0 && pim <= MAX_PIM
}

/// The PBKDF2 iteration count for a given PIM.
///
/// Saturating, not wrapping: with `[profile.release]` leaving `overflow-checks`
/// off, `15_000 + pim * 1_000` would wrap for a large PIM and produce a count
/// *weaker* than the default 500 000 — `pim = 4_294_968` wrapped to 15 704, a
/// 32-times weaker derivation, with no error anywhere. Callers reject such a PIM
/// (see [`pim_is_valid`]); this is the second line of defence.
pub const fn pbkdf2_iterations(pim: i32) -> u32 {
    if pim <= 0 {
        500_000
    } else {
        let pim = pim as u32;
        15_000u32.saturating_add(pim.saturating_mul(1_000))
    }
}

/// Argon2id parameters derived from the PIM, exactly as
/// `get_argon2_params()` in `src/Common/Pkcs5.c` computes them.
///
/// Returns `(memory_kib, iterations, parallelism)`.
pub fn argon2_params(pim: i32) -> (u32, u32, u32) {
    // VeraCrypt clamps a negative PIM to 0 and then maps 0 to the default 12
    // (`get_argon2_params` in src/Common/Pkcs5.c).
    let pim = if pim <= 0 { 12 } else { pim.min(MAX_PIM) };
    // Saturating: the arithmetic here used to be the only thing standing between a
    // wild PIM and a nonsensical memory/time cost, and it stood on i32 overflow.
    let mem_mib = std::cmp::min(64i32.saturating_add((pim - 1).saturating_mul(32)), 1024);
    let t = if pim <= 31 {
        3 + (pim - 1) / 3
    } else {
        13 + (pim - 31)
    };
    ((mem_mib * 1024) as u32, t as u32, 1)
}

/// Password derivation function used by a volume header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prf {
    Sha512,
    Sha256,
    Blake2s,
    Whirlpool,
    Streebog,
    Argon2,
}

impl Prf {
    /// Trial order used when opening a volume without a PRF hint.
    ///
    /// This is VeraCrypt's own preferred/default order: the most common PRF
    /// (SHA-512) first, and the expensive Argon2 last.
    pub const TRIAL_ORDER: [Prf; 6] = [
        Prf::Sha512,
        Prf::Sha256,
        Prf::Blake2s,
        Prf::Whirlpool,
        Prf::Streebog,
        Prf::Argon2,
    ];

    /// Every PRF, ordered as [`Prf::TRIAL_ORDER`].
    pub const ALL: [Prf; 6] = Prf::TRIAL_ORDER;

    /// VeraCrypt's display name for this PRF.
    pub const fn name(self) -> &'static str {
        match self {
            Prf::Sha512 => "SHA-512",
            Prf::Sha256 => "SHA-256",
            Prf::Blake2s => "BLAKE2s",
            Prf::Whirlpool => "Whirlpool",
            Prf::Streebog => "Streebog",
            Prf::Argon2 => "Argon2",
        }
    }

    /// VeraCrypt's numeric PRF id (`src/Common/Crypto.h`).
    pub const fn vc_id(self) -> u8 {
        match self {
            Prf::Sha512 => 1,
            Prf::Sha256 => 3,
            Prf::Blake2s => 4,
            Prf::Whirlpool => 2,
            Prf::Streebog => 5,
            Prf::Argon2 => 6,
        }
    }

    /// `botan::MsgAuthCode` name implementing this PRF, or `None` for Argon2.
    pub const fn hmac_name(self) -> Option<&'static str> {
        match self {
            Prf::Sha512 => Some("HMAC(SHA-512)"),
            Prf::Sha256 => Some("HMAC(SHA-256)"),
            Prf::Blake2s => Some("HMAC(BLAKE2s(256))"),
            Prf::Whirlpool => Some("HMAC(Whirlpool)"),
            Prf::Streebog => Some("HMAC(Streebog-512)"),
            Prf::Argon2 => None,
        }
    }

    /// Botan password-hash name used with `pbkdf2()`, or `None` for Argon2.
    pub const fn pbkdf2_name(self) -> Option<&'static str> {
        match self {
            Prf::Sha512 => Some("PBKDF2(SHA-512)"),
            Prf::Sha256 => Some("PBKDF2(SHA-256)"),
            Prf::Blake2s => Some("PBKDF2(BLAKE2s(256))"),
            Prf::Whirlpool => Some("PBKDF2(Whirlpool)"),
            Prf::Streebog => Some("PBKDF2(Streebog-512)"),
            Prf::Argon2 => None,
        }
    }

    /// Digest size of the underlying HMAC, in bytes.
    pub const fn digest_size(self) -> usize {
        match self {
            Prf::Sha512 | Prf::Whirlpool | Prf::Streebog => 64,
            Prf::Sha256 | Prf::Blake2s => 32,
            Prf::Argon2 => 0,
        }
    }

    /// Is this Argon2id?
    pub const fn is_argon2(self) -> bool {
        matches!(self, Prf::Argon2)
    }

    /// Iterations this PRF will perform for the given PIM (Argon2 excluded).
    pub const fn iterations(self, pim: i32) -> u32 {
        pbkdf2_iterations(pim)
    }

    /// Parse a VeraCrypt PRF name (case-insensitive).
    pub fn from_name(s: &str) -> Option<Prf> {
        let n = s.to_ascii_lowercase().replace('_', "-");
        Prf::ALL.into_iter().find(|p| {
            let pn = p.name().to_ascii_lowercase();
            pn == n
                || (p == &Prf::Argon2 && (n == "argon2id" || n == "argon2-id"))
                || (p == &Prf::Blake2s && (n == "blake2s-256" || n == "blake2s256"))
        })
    }

    /// Derive `out.len()` key bytes from `password` and `salt`.
    ///
    /// `password` is the raw password byte string (VeraCrypt uses the UTF-8
    /// encoding of the password, optionally extended by the keyfile pool).
    pub fn derive(self, password: &[u8], salt: &[u8], pim: i32, out: &mut [u8]) -> Result<()> {
        match self {
            Prf::Argon2 => {
                let (mem_kib, t, p) = argon2_params(pim);
                pwdhash(
                    "Argon2id",
                    out,
                    password,
                    salt,
                    mem_kib as usize,
                    t as usize,
                    p as usize,
                )
            }
            _ => {
                let name = self
                    .pbkdf2_name()
                    .ok_or_else(|| Error::Unsupported(format!("PRF {}", self.name())))?;
                pbkdf2(name, password, salt, self.iterations(pim), out)
            }
        }
    }
}

impl std::fmt::Display for Prf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// PBKDF2 (RFC 2898) with a pluggable HMAC, as implemented in
/// `src/Common/Pkcs5.c`.
///
/// This is Botan's `botan_pwdhash` with `(iterations, 0, 0)`, which is how the
/// C++ `PKCS5_PBKDF2_HMAC*` functions VeraCrypt uses are implemented.
///
/// `algo_name` is a Botan password-hash name such as `"PBKDF2(SHA-512)"`. The
/// password is passed as an explicit pointer/length pair: the safe
/// `botan::pbkdf` wrapper passes a `&str` and lets Botan call `strlen`, which
/// would silently truncate a password at its first NUL byte (VeraCrypt
/// appends a keyfile pool of arbitrary bytes to the password, so this matters).
pub fn pbkdf2(
    algo_name: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<()> {
    if iterations == 0 {
        return Err(Error::InvalidParameter("PBKDF2 iterations must be > 0".into()));
    }
    pwdhash(algo_name, out, password, salt, iterations as usize, 0, 0)
}

/// Botan's generic password-hash FFI: `botan_pwdhash(algo, p1, p2, p3, ...)`.
///
/// Parameter meanings depend on `algo_name`; for `"Argon2id"` they are
/// `(memory in KiB, iterations, parallelism)`.
fn pwdhash(
    algo_name: &str,
    out: &mut [u8],
    password: &[u8],
    salt: &[u8],
    p1: usize,
    p2: usize,
    p3: usize,
) -> Result<()> {
    let algo = std::ffi::CString::new(algo_name)
        .map_err(|_| Error::InvalidParameter(format!("algorithm name {algo_name} contains a NUL")))?;
    let rc = unsafe {
        botan_sys::botan_pwdhash(
            algo.as_ptr(),
            p1,
            p2,
            p3,
            out.as_mut_ptr(),
            out.len(),
            password.as_ptr() as *const std::ffi::c_char,
            password.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(ffi_error("botan_pwdhash", rc))
    }
}

/// Turn a Botan FFI status code into an [`Error`].
fn ffi_error(function: &'static str, rc: std::ffi::c_int) -> Error {
    if rc == botan_sys::BOTAN_FFI_ERROR_FUNCTION_NOT_AVAILABLE {
        return Error::Unsupported(format!(
            "{function} is not available in the Botan library vc-rs is linked against"
        ));
    }
    let message = unsafe {
        let ptr = botan_sys::botan_error_description(rc);
        if ptr.is_null() {
            format!("error code {rc}")
        } else {
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    Error::BotanFfi { function, code: rc, message }
}

/// Reference PBKDF2 (RFC 2898) built from `botan::MsgAuthCode` calls.
///
/// Kept as an independent implementation so the tests can cross-check the FFI
/// path above; production code uses [`pbkdf2`].
#[cfg(test)]
pub(crate) fn pbkdf2_manual(
    mac_name: &str,
    digest_size: usize,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<()> {
    if iterations == 0 {
        return Err(Error::InvalidParameter("PBKDF2 iterations must be > 0".into()));
    }
    if digest_size == 0 {
        return Err(Error::InvalidParameter("PBKDF2 digest size must be > 0".into()));
    }
    let mut mac = botan::MsgAuthCode::new(mac_name)?;
    // Any key length is valid for HMAC (Botan hashes keys longer than the
    // block size and zero-pads shorter ones), which matches VeraCrypt.
    mac.set_key(password)?;
    if mac.output_length()? != digest_size {
        return Err(Error::InvalidParameter(format!(
            "{mac_name} digest size is {}, expected {digest_size}",
            mac.output_length()?
        )));
    }

    let mut block_index: u32 = 1;
    let mut written = 0usize;
    while written < out.len() {
        // U_1 = PRF(password, salt || INT_32_BE(block_index))
        mac.update(salt)?;
        mac.update(&block_index.to_be_bytes())?;
        let mut u = mac.finish()?;
        let mut t = u.clone();
        for _ in 1..iterations {
            mac.update(&u)?;
            u = mac.finish()?;
            xor_into(&mut t, &u);
        }
        let take = std::cmp::min(digest_size, out.len() - written);
        out[written..written + take].copy_from_slice(&t[..take]);
        written += take;
        block_index += 1;
    }
    Ok(())
}

#[cfg(test)]
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn botan_pbkdf2_name(prf: Prf) -> &'static str {
        match prf {
            Prf::Sha512 => "PBKDF2(SHA-512)",
            Prf::Sha256 => "PBKDF2(SHA-256)",
            Prf::Blake2s => "PBKDF2(BLAKE2s(256))",
            Prf::Whirlpool => "PBKDF2(Whirlpool)",
            Prf::Streebog => "PBKDF2(Streebog-512)",
            Prf::Argon2 => unreachable!(),
        }
    }

    /// Cross-check the FFI PBKDF2 against Botan's own safe wrapper, and
    /// against the reference implementation in this module.
    #[test]
    fn pbkdf2_matches_botan() {
        for prf in [Prf::Sha512, Prf::Sha256, Prf::Blake2s, Prf::Whirlpool, Prf::Streebog] {
            let salt = [0x11u8; SALT_SIZE];
            // pim = 1 -> 15000 + 1000 = 16000 iterations
            let mut ours = [0u8; HEADER_KEY_SIZE];
            prf.derive(b"password123", &salt, 1, &mut ours).unwrap();
            assert_eq!(pbkdf2_iterations(1), 16_000);
            let theirs = botan::pbkdf(
                botan_pbkdf2_name(prf),
                HEADER_KEY_SIZE,
                "password123",
                &salt,
                16_000,
            )
            .unwrap();
            assert_eq!(ours.to_vec(), theirs, "PRF {prf} mismatch");

            let mut manual = [0u8; HEADER_KEY_SIZE];
            pbkdf2_manual(
                prf.hmac_name().unwrap(),
                prf.digest_size(),
                b"password123",
                &salt,
                16_000,
                &mut manual,
            )
            .unwrap();
            assert_eq!(manual, ours, "reference PBKDF2 for {prf} disagrees");
        }
    }

    /// A password with interior NUL bytes must be hashed in full: `strlen`-based
    /// entry points would truncate it. (VeraCrypt appends raw keyfile bytes.)
    #[test]
    fn pbkdf2_handles_binary_passwords() {
        let password = [0x00u8, 0x01, 0xff, 0x00, 0x7f, 0x00];
        let salt = [0x5au8; SALT_SIZE];
        let mut via_ffi = [0u8; 64];
        pbkdf2("PBKDF2(SHA-256)", &password, &salt, 1000, &mut via_ffi).unwrap();
        let mut manual = [0u8; 64];
        pbkdf2_manual("HMAC(SHA-256)", 32, &password, &salt, 1000, &mut manual).unwrap();
        assert_eq!(via_ffi, manual);

        // ... and it must differ from the password truncated at the first NUL.
        let mut truncated = [0u8; 64];
        pbkdf2("PBKDF2(SHA-256)", &[0x00u8], &salt, 1000, &mut truncated).unwrap();
        assert_ne!(via_ffi, truncated);
    }

    #[test]
    fn argon2id_derives_192_bytes() {
        // pim = 1 -> 64 MiB, 3 iterations: still fast enough for a unit test.
        let mut out = [0u8; HEADER_KEY_SIZE];
        Prf::Argon2.derive(b"password", &[0x22u8; SALT_SIZE], 1, &mut out).unwrap();
        // Argon2 is deterministic for the same inputs.
        let mut again = [0u8; HEADER_KEY_SIZE];
        Prf::Argon2.derive(b"password", &[0x22u8; SALT_SIZE], 1, &mut again).unwrap();
        assert_eq!(out, again);
        assert_ne!(out, [0u8; HEADER_KEY_SIZE]);
    }

    #[test]
    fn argon2_parameters_match_veracrypt() {
        assert_eq!(argon2_params(0), (416 * 1024, 6, 1));
        assert_eq!(argon2_params(-1), (416 * 1024, 6, 1));
        assert_eq!(argon2_params(1), (64 * 1024, 3, 1));
        assert_eq!(argon2_params(12), (416 * 1024, 6, 1));
        assert_eq!(argon2_params(31), (1024 * 1024, 13, 1));
        assert_eq!(argon2_params(32), (1024 * 1024, 14, 1));
    }
}
