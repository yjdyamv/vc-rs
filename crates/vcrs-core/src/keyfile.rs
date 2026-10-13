//! VeraCrypt keyfiles.
//!
//! VeraCrypt does not append a keyfile to the password. It builds a *keyfile
//! pool* out of all keyfiles and then mixes that pool into the password bytes
//! (`KeyFilesApply` / `KeyFileProcess` in `src/Common/Keyfiles.c`):
//!
//! ```text
//! keyPoolSize = password.len() <= 64 ? 64 : 128    // KEYFILE_POOL_LEGACY_SIZE / KEYFILE_POOL_SIZE
//! for each keyfile:                                // a file, or every file in a directory
//!     crc = 0xFFFFFFFF; writePos = 0
//!     for each byte b (at most 1 MiB is read):      // KEYFILE_MAX_READ_LEN
//!         crc = UPDC32(b, crc)                     // reflected CRC-32 step, no final inversion
//!         keyPool[writePos++] += (crc >> 24) as u8
//!         keyPool[writePos++] += (crc >> 16) as u8
//!         keyPool[writePos++] += (crc >>  8) as u8
//!         keyPool[writePos++] +=  crc        as u8
//!         writePos %= keyPoolSize
//! for i in 0..keyPoolSize:
//!     password[i] += keyPool[i]                    // password[i] = keyPool[i] when i >= password.len()
//! password.len() = max(password.len(), keyPoolSize)
//! ```
//!
//! Consequences worth remembering: the KDF therefore always sees at least 64
//! bytes when keyfiles are used (even for an empty password), a password of
//! more than 64 bytes switches to the 128-byte pool, and only the first 1 MiB
//! of each keyfile matters. Every file restarts `crc` and `writePos`, and the
//! pool update is a plain byte-wise addition, so the *order* of the keyfiles
//! does not influence the result.
//!
//! Directory entries are used exactly as VeraCrypt uses them: not recursive,
//! hidden files (Windows attribute) skipped, and the container file itself
//! skipped when it happens to live in that directory.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// `KEYFILE_POOL_LEGACY_SIZE`: pool size for passwords up to 64 bytes.
pub const KEYFILE_POOL_LEGACY_SIZE: usize = 64;
/// `KEYFILE_POOL_SIZE`: pool size for longer passwords.
pub const KEYFILE_POOL_SIZE: usize = 128;
/// `MAX_LEGACY_PASSWORD`.
pub const MAX_LEGACY_PASSWORD: usize = 64;
/// `KEYFILE_MAX_READ_LEN`: only this much of a keyfile is read.
pub const KEYFILE_MAX_READ_LEN: u64 = 1024 * 1024;

/// Pool size VeraCrypt uses for a password of `password_len` bytes.
pub const fn pool_size(password_len: usize) -> usize {
    if password_len <= MAX_LEGACY_PASSWORD {
        KEYFILE_POOL_LEGACY_SIZE
    } else {
        KEYFILE_POOL_SIZE
    }
}

/// Build the keyfile pool for `keyfiles`, sized for `password_len` password
/// bytes. `volume` is the container the keyfiles belong to; when it sits inside
/// one of the keyfile directories it is skipped (VeraCrypt does the same, so
/// that keeping the container next to its keyfiles still works).
pub fn keyfile_pool(
    keyfiles: &[PathBuf],
    password_len: usize,
    volume: Option<&Path>,
) -> Result<Vec<u8>> {
    let mut pool = vec![0u8; pool_size(password_len)];
    for path in keyfiles {
        let mut used = 0usize;
        process_path(&mut pool, path, volume, &mut used)?;
        if used == 0 {
            return Err(Error::InvalidParameter(format!(
                "no usable files in keyfile path {}",
                path.display()
            )));
        }
    }
    Ok(pool)
}

/// Apply `keyfiles` to `password` the way VeraCrypt does, returning the bytes
/// the KDF has to be fed with. Without keyfiles the password is returned
/// unchanged.
pub fn apply_keyfiles(
    password: &[u8],
    keyfiles: &[PathBuf],
    volume: Option<&Path>,
) -> Result<Vec<u8>> {
    if keyfiles.is_empty() {
        return Ok(password.to_vec());
    }

    let pool = keyfile_pool(keyfiles, password.len(), volume)?;
    let mut out = vec![0u8; password.len().max(pool.len())];
    out[..password.len()].copy_from_slice(password);
    for (byte, mask) in out[..pool.len()].iter_mut().zip(pool.iter()) {
        *byte = byte.wrapping_add(*mask);
    }
    Ok(out)
}

/// One reflected CRC-32 step — VeraCrypt's `UPDC32` macro — i.e. the CRC-32 of
/// `crate::header` without the initial and final inversion.
pub const fn crc32_step(crc: u32, byte: u8) -> u32 {
    let mut value = (crc ^ byte as u32) & 0xFF;
    let mut bit = 0;
    while bit < 8 {
        value = if value & 1 != 0 {
            (value >> 1) ^ 0xEDB8_8320
        } else {
            value >> 1
        };
        bit += 1;
    }
    (crc >> 8) ^ value
}

fn process_path(
    pool: &mut [u8],
    path: &Path,
    volume: Option<&Path>,
    used: &mut usize,
) -> Result<()> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        Error::InvalidParameter(format!("keyfile {}: {e}", path.display()))
    })?;

    if !metadata.is_dir() {
        process_file(pool, path)?;
        *used += 1;
        return Ok(());
    }

    let mut files = Vec::new();
    let entries = std::fs::read_dir(path).map_err(|e| {
        Error::InvalidParameter(format!("keyfile directory {}: {e}", path.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            Error::InvalidParameter(format!("keyfile directory {}: {e}", path.display()))
        })?;
        let candidate = entry.path();
        let Ok(metadata) = entry.metadata() else { continue };
        if metadata.is_dir() {
            continue; // VeraCrypt does not scan recursively
        }
        if is_hidden(&metadata) {
            continue;
        }
        if let Some(volume) = volume {
            if is_same_file(&candidate, volume) {
                continue; // the container itself is not a keyfile
            }
        }
        files.push(candidate);
    }

    // The pool is a sum of independent per-file contributions, so the order is
    // irrelevant; sorting only makes the behaviour reproducible.
    files.sort();
    for file in files {
        process_file(pool, &file)?;
        *used += 1;
    }
    Ok(())
}

fn process_file(pool: &mut [u8], path: &Path) -> Result<()> {
    let mut file = File::open(path).map_err(|e| {
        Error::InvalidParameter(format!("cannot open keyfile {}: {e}", path.display()))
    })?;

    let mut crc: u32 = 0xFFFF_FFFF;
    let mut write_pos = 0usize;
    let mut total: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];

    'read: loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        for byte in &buffer[..read] {
            crc = crc32_step(crc, *byte);
            for shift in [24u32, 16, 8, 0] {
                pool[write_pos] = pool[write_pos].wrapping_add((crc >> shift) as u8);
                write_pos += 1;
                if write_pos >= pool.len() {
                    write_pos = 0;
                }
            }
            total += 1;
            if total >= KEYFILE_MAX_READ_LEN {
                break 'read;
            }
        }
    }

    if total == 0 {
        return Err(Error::InvalidParameter(format!(
            "keyfile {} is empty",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn is_hidden(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x2 != 0 // FILE_ATTRIBUTE_HIDDEN
}

#[cfg(not(windows))]
fn is_hidden(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn is_same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vcrs-keyfile-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the test directory");
        dir
    }

    fn write_file(path: &Path, contents: &[u8]) {
        std::fs::write(path, contents).expect("write the test file");
    }

    #[test]
    fn crc32_step_matches_the_header_crc() {
        for data in [b"".as_slice(), b"a", b"123456789", b"the quick brown fox"] {
            let mut crc = 0xFFFF_FFFF;
            for byte in data {
                crc = crc32_step(crc, *byte);
            }
            assert_eq!(!crc, crate::header::crc32(data));
        }
    }

    #[test]
    fn pool_size_follows_the_password_length() {
        assert_eq!(pool_size(0), 64);
        assert_eq!(pool_size(64), 64);
        assert_eq!(pool_size(65), 128);
        assert_eq!(pool_size(128), 128);
    }

    #[test]
    fn keyfiles_are_mixed_into_the_password() {
        let dir = temp_dir("mix");
        let file = dir.join("kf.bin");
        write_file(&file, b"a keyfile");

        let pool = keyfile_pool(&[file.clone()], 3, None).expect("pool");
        assert_eq!(pool.len(), 64);
        assert!(pool.iter().any(|&b| b != 0), "the pool must not be empty");

        let mixed = apply_keyfiles(b"abc", &[file.clone()], None).expect("mixed");
        assert_eq!(mixed.len(), 64, "the KDF always sees at least the pool");
        assert_eq!(mixed[0], b'a'.wrapping_add(pool[0]));
        assert_eq!(mixed[1], b'b'.wrapping_add(pool[1]));
        assert_eq!(mixed[2], b'c'.wrapping_add(pool[2]));
        assert_eq!(&mixed[3..], &pool[3..]);

        // A password longer than 64 bytes switches to the 128-byte pool.
        let long = vec![b'x'; 65];
        let mixed_long = apply_keyfiles(&long, &[file.clone()], None).expect("mixed");
        assert_eq!(mixed_long.len(), 128);

        // No keyfiles: the password goes through untouched.
        assert_eq!(apply_keyfiles(b"abc", &[], None).unwrap(), b"abc");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_directory_of_keyfiles_sums_the_pool() {
        let dir = temp_dir("dir");
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        write_file(&a, b"first keyfile");
        write_file(&b, b"second keyfile");

        let pool_a = keyfile_pool(&[a.clone()], 64, None).expect("pool");
        let pool_b = keyfile_pool(&[b.clone()], 64, None).expect("pool");
        let pool_dir = keyfile_pool(&[dir.clone()], 64, None).expect("pool");
        let pool_both = keyfile_pool(&[a.clone(), b.clone()], 64, None).expect("pool");

        for i in 0..pool_dir.len() {
            assert_eq!(
                pool_dir[i],
                pool_a[i].wrapping_add(pool_b[i]),
                "a directory must be the sum of its files (byte {i})"
            );
            assert_eq!(pool_both[i], pool_dir[i], "and the order must not matter");
        }

        // The container living in the keyfile directory is skipped.
        let volume = dir.join("volume.hc");
        write_file(&volume, b"not a keyfile at all");
        let pool_with_volume = keyfile_pool(&[dir.clone()], 64, Some(&volume)).expect("pool");
        let pool_without = keyfile_pool(&[a.clone(), b.clone()], 64, None).expect("pool");
        assert_eq!(pool_with_volume, pool_without);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_the_first_mebibyte_of_a_keyfile_matters() {
        let dir = temp_dir("big");
        let big = dir.join("big.bin");
        let mut contents = vec![0u8; KEYFILE_MAX_READ_LEN as usize];
        for (i, byte) in contents.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        write_file(&big, &contents);
        let truncated = keyfile_pool(&[big.clone()], 64, None).expect("pool");

        contents.extend_from_slice(b"this tail must be ignored");
        write_file(&big, &contents);
        let with_tail = keyfile_pool(&[big.clone()], 64, None).expect("pool");

        assert_eq!(truncated, with_tail);
        assert!(truncated.iter().any(|&b| b != 0));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_and_missing_keyfiles_are_rejected() {
        let dir = temp_dir("bad");
        let empty = dir.join("empty.bin");
        write_file(&empty, b"");
        let error = keyfile_pool(&[empty], 64, None).unwrap_err();
        assert!(
            error.to_string().contains("is empty"),
            "unexpected error: {error}"
        );

        let missing = dir.join("does-not-exist");
        let error = keyfile_pool(&[missing], 64, None).unwrap_err();
        assert!(
            error.to_string().contains("keyfile"),
            "unexpected error: {error}"
        );

        let empty_dir = dir.join("empty-dir");
        std::fs::create_dir_all(&empty_dir).expect("create the empty directory");
        let error = keyfile_pool(&[empty_dir], 64, None).unwrap_err();
        assert!(
            error.to_string().contains("no usable files"),
            "unexpected error: {error}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
