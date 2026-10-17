//! The CHAP credentials of the loopback iSCSI target.
//!
//! `vcrs mount` serves the *decrypted* volume over a TCP socket on the loopback
//! interface, and a target that does not ask for authentication can be logged
//! into by anything else running on the machine. The Windows initiator can do
//! one-way CHAP, so a mount made with `--chap` asks for it.
//!
//! Nobody types the secret and it is never passed from one process to another:
//! both halves of a mount derive it from the container itself.
//!
//! ```text
//! secret = base64(HMAC-SHA-512(key = header salt, message = label || IQN)[..12])
//! ```
//!
//! The header salt is plain data inside the container, so this is not a secret
//! in the cryptographic sense: whoever can read the container can derive it (and
//! could attack the container itself, which needs the password). What it does
//! give is that only a process that can read the container may log in — another
//! user's process cannot, even though it can reach the loopback port, and
//! neither can anything that merely guesses the portal. The target name is mixed
//! in because it is drawn at random for every mount, so the secret is not a
//! stable fingerprint of the container either.
//!
//! Sixteen characters, because the initiator takes 12 to 16 *bytes*: "Maximum
//! size of CHAP secret is 16 bytes. Minimum size is 12 bytes if IPSec is not
//! used".

use crate::error::{Error, Result};
use std::io::Read;
use std::path::Path;

/// The user name both halves send. CHAP would take anything, this one says who
/// is asking.
pub const CHAP_USER: &str = "vcrs";

/// Mixed into the derivation so the secret is not a bare chunk of the header.
const CHAP_LABEL: &[u8] = b"vcrs-chap v1";

/// Raw secret bytes: 12 is 96 bits, the RFC 3720 minimum, and exactly what
/// base64 renders in sixteen characters without padding.
const SECRET_BYTES: usize = 12;

/// base64, standard alphabet.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The CHAP secret for the header whose salt is `salt`, mounted as `target`.
pub fn chap_secret(salt: &[u8], target: &str) -> Result<String> {
    let mut mac = botan::MsgAuthCode::new("HMAC(SHA-512)")?;
    mac.set_key(salt)?;
    let mut message = CHAP_LABEL.to_vec();
    message.extend_from_slice(target.as_bytes());
    mac.update(&message)?;
    let digest = mac.finish()?;
    Ok(encode(&digest[..SECRET_BYTES]))
}

/// The CHAP secret for a mount of the volume at `path`, as `target`.
///
/// The salt is read from the first [`HEADER_SALT_SIZE`](crate::header::HEADER_SALT_SIZE)
/// bytes of the file or device: it is plaintext and sits at the same offset in
/// every layout, so the target and the elevated half that runs `iscsicli` can
/// both derive the secret from the volume alone. Neither has to be told a secret
/// and neither has to know which header the other one opened (a hidden or
/// `--backup` mount has its salt somewhere else, and guessing that is exactly
/// the kind of drift that would silently break a mount).
///
/// Both halves call *this* function, so there is only one derivation to get
/// wrong.
pub fn chap_secret_for_file(path: &Path, target: &str) -> Result<String> {
    let mut file = std::fs::File::open(path).map_err(|e| {
        Error::InvalidParameter(format!(
            "CHAP needs the header salt of {}, which could not be opened ({e})",
            path.display()
        ))
    })?;
    let mut salt = vec![0u8; crate::header::HEADER_SALT_SIZE];
    file.read_exact(&mut salt).map_err(|e| {
        Error::InvalidParameter(format!(
            "CHAP needs the first {} bytes of {} as the header salt ({e})",
            salt.len(),
            path.display()
        ))
    })?;
    chap_secret(&salt, target)
}

/// base64 without padding, for a length that is a multiple of three.
fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(bits >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(bits >> 12) as usize & 0x3f] as char);
        out.push(ALPHABET[(bits >> 6) as usize & 0x3f] as char);
        out.push(ALPHABET[bits as usize & 0x3f] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_is_sixteen_characters_the_initiator_accepts() {
        let secret = chap_secret(&[7u8; 64], "iqn.2025-12.io.vcrs:abc").unwrap();
        assert_eq!(secret.len(), 16, "{secret}");
        assert!(
            secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/'),
            "{secret}"
        );
    }

    #[test]
    fn the_secret_follows_both_the_salt_and_the_target() {
        let a = chap_secret(&[1u8; 64], "iqn.x").unwrap();
        assert_eq!(a, chap_secret(&[1u8; 64], "iqn.x").unwrap());
        assert_ne!(a, chap_secret(&[2u8; 64], "iqn.x").unwrap());
        assert_ne!(a, chap_secret(&[1u8; 64], "iqn.y").unwrap());
    }

    #[test]
    fn the_file_helper_reads_the_first_salt_and_refuses_a_short_file() {
        let path = std::env::temp_dir().join("vcrs-chap-core-test.vc");
        let salt = [3u8; 64];
        std::fs::write(&path, salt).unwrap();
        assert_eq!(
            chap_secret_for_file(&path, "iqn.x").unwrap(),
            chap_secret(&salt, "iqn.x").unwrap()
        );
        // The bytes after the salt do not matter: a real container is full of
        // them, and only the salt is hashed.
        let mut longer = salt.to_vec();
        longer.extend_from_slice(&[9u8; 4096]);
        std::fs::write(&path, &longer).unwrap();
        assert_eq!(
            chap_secret_for_file(&path, "iqn.x").unwrap(),
            chap_secret(&salt, "iqn.x").unwrap()
        );

        std::fs::write(&path, [1u8; 8]).unwrap();
        assert!(chap_secret_for_file(&path, "iqn.x").is_err());
        assert!(chap_secret_for_file(
            &std::env::temp_dir().join("vcrs-chap-does-not-exist.vc"),
            "iqn.x"
        )
        .is_err());
        let _ = std::fs::remove_file(&path);
    }
}
