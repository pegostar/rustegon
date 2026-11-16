// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! The key sealing cursor continuation tokens (PD-053 `DataPlaneConfig::token_key`, PD-054).
//!
//! Without a configured key the data plane draws a random key per process, so every token a
//! client holds becomes invalid at a restart. `rustegond` therefore keeps the key in a file:
//! `security.cursor_token_key_file`, default `<data_dir>/cursor-token.key`. On the first start
//! the file is created owner-only (0600 on Unix, directory ACL on Windows) with 32 bytes from
//! the OS CSPRNG; later starts read it. Copying the file to other nodes makes their tokens
//! interchangeable (needed once cursors are served cluster-wide, M5).
//!
//! File format: 64 lowercase or uppercase hex digits, optionally followed by one line ending.
//! Anything else refuses the start: silently replacing a damaged key would invalidate tokens,
//! and the operator should know the file was touched.

use std::{io, path::Path};

use rustegon_common::{Error, ErrorCode, Result};
use rustegon_sim_api::{FileSystem, OpenMode, Rng};
use zeroize::Zeroizing;

/// Default file name under the data directory.
pub const DEFAULT_FILE: &str = "cursor-token.key";

const KEY_LEN: usize = 32;
/// Hex digits plus the longest accepted line ending (`\r\n`).
const MAX_FILE_LEN: u64 = (KEY_LEN as u64) * 2 + 2;

fn io_error(path: &Path, e: &io::Error) -> Error {
    // The path is not secret; the key never appears in an error.
    Error::new(ErrorCode::Internal, format!("{}: {e}", path.display()))
}

fn invalid(path: &Path, reason: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!(
            "{}: {reason}; expected 64 hex digits (delete the file to generate a new key, which \
             invalidates outstanding cursor tokens)",
            path.display()
        ),
    )
}

/// Reads the key at `path`, creating it with a fresh random key when it does not exist.
/// Returns the key and whether it was created. Blocking (small file I/O at startup).
///
/// # Errors
/// I/O errors (`RGN-5001`), a malformed file (`RGN-1001`).
pub fn load_or_create(
    fs: &dyn FileSystem,
    rng: &dyn Rng,
    path: &Path,
) -> Result<(Zeroizing<[u8; KEY_LEN]>, bool)> {
    match fs.open(path, OpenMode::Read) {
        Ok(file) => {
            let size = file.size().map_err(|e| io_error(path, &e))?;
            if size > MAX_FILE_LEN {
                return Err(invalid(path, "file too long"));
            }
            let len = usize::try_from(size).map_err(|_| invalid(path, "file too long"))?;
            let mut raw = Zeroizing::new(vec![0u8; len]);
            file.read_exact_at(&mut raw, 0)
                .map_err(|e| io_error(path, &e))?;
            Ok((parse(path, &raw)?, false))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((create(fs, rng, path)?, true)),
        Err(e) => Err(io_error(path, &e)),
    }
}

fn parse(path: &Path, raw: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let text = raw
        .strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw);
    if text.len() != KEY_LEN * 2 {
        return Err(invalid(path, "wrong length"));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let (pairs, _) = text.as_chunks::<2>();
    for (out, [hi, lo]) in key.iter_mut().zip(pairs) {
        let hi = hex_digit(*hi).ok_or_else(|| invalid(path, "not hex"))?;
        let lo = hex_digit(*lo).ok_or_else(|| invalid(path, "not hex"))?;
        *out = (hi << 4) | lo;
    }
    Ok(key)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn create(fs: &dyn FileSystem, rng: &dyn Rng, path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rng.fill_bytes(key.as_mut());
    let mut text = Zeroizing::new(Vec::with_capacity(KEY_LEN * 2 + 1));
    for b in key.iter() {
        for nibble in [b >> 4, b & 0x0f] {
            text.push(b"0123456789abcdef"[usize::from(nibble)]);
        }
    }
    text.push(b'\n');
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(dir) = dir {
        fs.create_dir_all(dir).map_err(|e| io_error(dir, &e))?;
    }
    // `create_new_private` fails if a concurrent start created the file meanwhile, instead of
    // silently overwriting a key that may already have sealed tokens.
    let mut file = fs
        .create_new_private(path)
        .map_err(|e| io_error(path, &e))?;
    file.append(&text)
        .and_then(|()| file.sync_data())
        .map_err(|e| io_error(path, &e))?;
    if let Some(dir) = dir {
        fs.sync_dir(dir).map_err(|e| io_error(dir, &e))?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rustegon_sim_api::{OsRng, StdFileSystem};

    use super::*;

    #[test]
    fn pd_054_token_key_is_created_once_and_reread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join(DEFAULT_FILE);
        let (first, created) = load_or_create(&StdFileSystem, &OsRng, &path).unwrap();
        assert!(created);
        let (again, created) = load_or_create(&StdFileSystem, &OsRng, &path).unwrap();
        assert!(!created);
        assert_eq!(*first, *again, "the key survives a restart");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.len(), 65);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn pd_054_malformed_token_key_refuses_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEFAULT_FILE);
        for content in ["", "abc\n", &"zz".repeat(32), &"ab".repeat(40)] {
            std::fs::write(&path, content).unwrap();
            let err = load_or_create(&StdFileSystem, &OsRng, &path).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{content:?}");
            assert!(err.message().contains("64 hex digits"), "{err}");
        }
        std::fs::write(&path, format!("{}\r\n", "0A".repeat(32))).unwrap();
        let (key, created) = load_or_create(&StdFileSystem, &OsRng, &path).unwrap();
        assert!(!created);
        assert_eq!(*key, [0x0a; 32]);
    }
}
