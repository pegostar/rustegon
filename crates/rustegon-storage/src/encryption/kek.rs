// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! KEK providers (security.md §6): wrap and unwrap DEKs under a key-encryption key that never
//! enters the store.
//!
//! The storage crate's trait is synchronous because storage I/O runs on the dedicated I/O pool
//! (coding-standards.md §3.3); the async `KeyProvider` of security.md §6 (M4, network KMS
//! providers) adapts to it by blocking on that pool, never on an executor thread.
//!
//! Providers of M4 (FR-EAR-002, PD-057), both holding a local 256-bit key in memory:
//! - `file`: the key in a file, given as 32 raw bytes or 64 hex digits (optionally followed by a
//!   newline). On Unix a file readable or writable by group or others is refused (mode 0600 or
//!   0400 required, security.md §6); on Windows the ACL is not inspected and a warning is logged
//!   (the deployment restricts the directory ACL to the service account, security.md §7).
//! - `env`: the key in an environment variable as standard base64 (44 characters with padding,
//!   43 without). The value is never logged or echoed; errors name the variable only.
//!
//! Both use the same wrap scheme and the same KEK id (`file:` + key check value; the prefix is
//! kept from M1 because ids are persisted, DEC-016), so a key can move between a file and an
//! environment variable without rewrapping any DEK. KMS providers (M13) bring their own ids.

use std::{fmt, io, path::Path};

use aes_gcm::aes::{
    Aes256,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use rustegon_common::Redacted;
use rustegon_sim_api::{FileSystem, OpenMode, Rng};
use zeroize::Zeroize;

use super::{KEY_LEN, NONCE_LEN, SecretKey, TAG_LEN, open, seal};
use crate::error::{Result, StorageError};

/// Identifier of a KEK, stored next to every wrapped DEK so a mismatched key is reported as
/// such instead of as a failed decryption. Public: it reveals nothing about the key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KekId(String);

impl KekId {
    /// Upper bound on an id's length (it is length-prefixed by one byte on disk).
    pub const MAX_LEN: usize = 255;

    /// An id from its text.
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] if `id` is empty or longer than [`KekId::MAX_LEN`].
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > Self::MAX_LEN {
            return Err(StorageError::InvalidArgument(format!(
                "KEK id must be 1..={} bytes",
                Self::MAX_LEN
            )));
        }
        Ok(Self(id))
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KekId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A DEK encrypted under a KEK, plus the id of that KEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    /// The KEK that wrapped this key.
    pub kek_id: KekId,
    /// Provider-specific ciphertext (for the file provider: `nonce ‖ ciphertext ‖ tag`).
    pub bytes: Vec<u8>,
}

/// Source of the key-encryption key (security.md §6). Implementations must never log or print
/// key material and report every failure to produce a key as
/// [`StorageError::KeyUnavailable`] (`RGN-4006`).
pub trait KekProvider: Send + Sync + fmt::Debug {
    /// Id of the active KEK.
    fn key_id(&self) -> &KekId;

    /// Wraps `key` under the active KEK; `rng` supplies any nonce the scheme needs.
    ///
    /// # Errors
    /// [`StorageError::KeyUnavailable`] if the KEK cannot be used.
    fn wrap(&self, key: &SecretKey, rng: &dyn Rng) -> Result<WrappedKey>;

    /// Unwraps a key wrapped by [`KekProvider::wrap`].
    ///
    /// # Errors
    /// [`StorageError::KeyUnavailable`] if `wrapped` names another KEK or does not
    /// authenticate under this one.
    fn unwrap(&self, wrapped: &WrappedKey) -> Result<SecretKey>;
}

/// Associated data of a DEK wrap: binds the ciphertext to its purpose and scheme version.
const WRAP_AAD: &[u8] = b"rustegon.dek-wrap.v1";
/// Length of a key wrapped by the file provider: random nonce, encrypted key, tag.
const FILE_WRAP_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
/// Largest KEK file accepted: 64 hex digits plus a CRLF, with slack. Anything larger is not a
/// key file and is refused before reading it into memory.
const MAX_KEY_FILE_LEN: u64 = 128;
/// Bytes of the key check value used as id (64 bits: collisions between distinct KEKs of one
/// deployment are negligible, and the value reveals nothing usable about the key).
const KCV_LEN: usize = 8;
/// Plaintext block encrypted to derive the key check value; domain-separated so the KCV is not
/// the encryption of any block the store ever writes.
const KCV_BLOCK: [u8; 16] = *b"rustegon.kek.kcv";

/// Permission bits that must be clear on a Unix KEK file: any access by group or others.
const GROUP_OTHER_BITS: u32 = 0o077;
/// Longest accepted base64 text of the `env` provider (44 characters for 32 bytes, padded); a
/// longer value is refused without decoding it.
const MAX_BASE64_LEN: usize = 64;

/// The local-key KEK provider behind `file` and `env` (module docs): a 32-byte key obtained
/// once at startup and kept in memory.
///
/// Wrap scheme: AES-256-GCM under the KEK with a random 96-bit nonce from the store's `Rng`
/// (one wrap per encrypted file; far below the 2^32 random-nonce limit of NIST SP 800-38D
/// §8.3 for one KEK). Id: `file:` + hex of the first 8 bytes of `AES-256(KEK, KCV_BLOCK)`, a
/// standard key check value.
pub struct FileKekProvider {
    kek: SecretKey,
    id: KekId,
}

impl FileKekProvider {
    /// Reads the KEK from `path` (`file` provider).
    ///
    /// # Errors
    /// [`StorageError::KeyUnavailable`] if the file is missing, unreadable, accessible by group
    /// or others on Unix, or does not hold exactly one 256-bit key (32 raw bytes or 64 hex
    /// digits). Messages name the path, never the contents.
    pub fn open(fs: &dyn FileSystem, path: &Path) -> Result<Self> {
        let unavailable = |what: &str| {
            StorageError::key_unavailable(format!("KEK file {}: {what}", path.display()))
        };
        let io_err = |e: io::Error| match e.kind() {
            io::ErrorKind::NotFound => unavailable("not found"),
            _ => unavailable(&format!("cannot be read ({})", e.kind())),
        };
        // Checked before the key is read: a key that others could read must be assumed
        // compromised, and refusing (instead of warning) makes the operator fix it before any
        // data is written under it (security.md §6).
        match fs.permission_mode(path).map_err(io_err)? {
            Some(mode) if mode & GROUP_OTHER_BITS != 0 => {
                return Err(unavailable(&format!(
                    "mode {mode:04o} gives group or others access; restrict it to the owner \
                     (chmod 600)"
                )));
            }
            Some(_) => {}
            None => tracing::warn!(
                path = %path.display(),
                "KEK file permissions are not checked on this platform; restrict its ACL to \
                 the service account"
            ),
        }
        let file = fs.open(path, OpenMode::Read).map_err(io_err)?;
        let size = file.size().map_err(io_err)?;
        if size > MAX_KEY_FILE_LEN {
            return Err(unavailable("too large to be a 256-bit key"));
        }
        // Lossless: bounded by MAX_KEY_FILE_LEN.
        #[allow(clippy::cast_possible_truncation)]
        let mut contents = vec![0u8; size as usize];
        let read = file.read_exact_at(&mut contents, 0).map_err(io_err);
        let key = read.and_then(|()| {
            parse_key(&contents).ok_or_else(|| {
                unavailable("must hold exactly 32 raw bytes or 64 hex digits (256-bit key)")
            })
        });
        contents.zeroize();
        Ok(Self::from_key(key?))
    }

    /// The `env` provider: decodes the KEK from `value`, the text of environment variable
    /// `variable` (standard base64 of 32 bytes, padding optional, surrounding ASCII whitespace
    /// ignored). `None` means the variable is not set.
    ///
    /// # Errors
    /// [`StorageError::KeyUnavailable`] if the variable is unset, empty, not base64 or not
    /// exactly 32 bytes. Messages name the variable, never the value.
    pub fn from_env_value(variable: &str, value: Option<&str>) -> Result<Self> {
        use base64::{
            Engine as _, alphabet,
            engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
        };
        let unavailable = |what: &str| {
            StorageError::key_unavailable(format!("KEK environment variable {variable}: {what}"))
        };
        let Some(value) = value else {
            return Err(unavailable("not set"));
        };
        let text = value.trim_ascii();
        if text.is_empty() {
            return Err(unavailable("empty"));
        }
        let malformed = || unavailable("must hold the standard base64 encoding of a 256-bit key");
        if text.len() > MAX_BASE64_LEN {
            return Err(malformed());
        }
        let engine = GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
        );
        // One spare byte: a value that decodes to more than 32 bytes is detected by its length
        // instead of by a too-small buffer. Both copies are zeroized on every path.
        let mut raw = [0u8; KEY_LEN + 1];
        let decoded = engine.decode_slice(text, &mut raw);
        let key = match decoded {
            Ok(KEY_LEN) => {
                let mut bytes = [0u8; KEY_LEN];
                bytes.copy_from_slice(&raw[..KEY_LEN]);
                let key = SecretKey::from_bytes(bytes);
                bytes.zeroize();
                Some(key)
            }
            _ => None,
        };
        raw.zeroize();
        key.map(Self::from_key).ok_or_else(malformed)
    }

    /// A provider holding `kek` (tests, and providers that obtain the key elsewhere).
    #[must_use]
    pub fn from_key(kek: SecretKey) -> Self {
        let id = KekId(format!("file:{}", hex(&key_check_value(&kek))));
        Self { kek, id }
    }
}

impl fmt::Debug for FileKekProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileKekProvider")
            .field("id", &self.id)
            .field("kek", &Redacted::new(()))
            .finish()
    }
}

impl KekProvider for FileKekProvider {
    fn key_id(&self) -> &KekId {
        &self.id
    }

    fn wrap(&self, key: &SecretKey, rng: &dyn Rng) -> Result<WrappedKey> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let mut bytes = Vec::with_capacity(FILE_WRAP_LEN);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(key.expose());
        let sealed = seal(&self.kek.aead(), nonce, WRAP_AAD, &mut bytes, NONCE_LEN);
        if sealed.is_err() {
            bytes.zeroize();
        }
        sealed?;
        Ok(WrappedKey {
            kek_id: self.id.clone(),
            bytes,
        })
    }

    fn unwrap(&self, wrapped: &WrappedKey) -> Result<SecretKey> {
        if wrapped.kek_id != self.id {
            return Err(StorageError::key_unavailable(format!(
                "key wrapped under KEK {} but the provider holds KEK {}",
                wrapped.kek_id, self.id
            )));
        }
        let failed =
            || StorageError::key_unavailable(format!("DEK does not unwrap under KEK {}", self.id));
        if wrapped.bytes.len() != FILE_WRAP_LEN {
            return Err(failed());
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&wrapped.bytes[..NONCE_LEN]);
        let mut buf = wrapped.bytes[NONCE_LEN..].to_vec();
        let opened = open(&self.kek.aead(), nonce, WRAP_AAD, &mut buf);
        let key = opened.ok().and_then(|()| {
            let mut raw = [0u8; KEY_LEN];
            raw.copy_from_slice(buf.get(..KEY_LEN)?);
            let key = SecretKey::from_bytes(raw);
            raw.zeroize();
            Some(key)
        });
        buf.zeroize();
        key.ok_or_else(failed)
    }
}

/// `AES-256(kek, KCV_BLOCK)[..KCV_LEN]`.
fn key_check_value(kek: &SecretKey) -> [u8; KCV_LEN] {
    let aes = Aes256::new(&(*kek.expose()).into());
    let mut block = KCV_BLOCK.into();
    aes.encrypt_block(&mut block);
    let mut kcv = [0u8; KCV_LEN];
    kcv.copy_from_slice(&block[..KCV_LEN]);
    kcv
}

/// Parses 32 raw bytes, or 64 hex digits with an optional trailing `\n` / `\r\n`.
fn parse_key(contents: &[u8]) -> Option<SecretKey> {
    let mut raw = [0u8; KEY_LEN];
    let parsed = if contents.len() == KEY_LEN {
        raw.copy_from_slice(contents);
        true
    } else {
        let text = contents
            .strip_suffix(b"\n")
            .map_or(contents, |t| t.strip_suffix(b"\r").unwrap_or(t));
        text.len() == 2 * KEY_LEN
            && text
                .as_chunks::<2>()
                .0
                .iter()
                .zip(raw.iter_mut())
                .all(
                    |(pair, out)| match (hex_digit(pair[0]), hex_digit(pair[1])) {
                        (Some(hi), Some(lo)) => {
                            *out = (hi << 4) | lo;
                            true
                        }
                        _ => false,
                    },
                )
    };
    let key = parsed.then(|| SecretKey::from_bytes(raw));
    raw.zeroize();
    key
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        // Writing into a String cannot fail.
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use rustegon_sim_api::StdFileSystem;

    use super::*;
    use crate::encryption::tests::TestRng;

    fn write(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        // Owner-only, as a deployed key file must be (Unix refuses anything else).
        StdFileSystem
            .create_new_private(&path)
            .unwrap()
            .append(contents)
            .unwrap();
        path
    }

    #[test]
    fn file_provider_accepts_raw_and_hex_keys_with_the_same_id() {
        let dir = tempfile::tempdir().unwrap();
        let raw: Vec<u8> = (0u8..32).collect();
        let hex_text = hex(&raw);
        let a = FileKekProvider::open(&StdFileSystem, &write(dir.path(), "raw", &raw)).unwrap();
        let b = FileKekProvider::open(
            &StdFileSystem,
            &write(dir.path(), "hex", hex_text.as_bytes()),
        )
        .unwrap();
        let c = FileKekProvider::open(
            &StdFileSystem,
            &write(
                dir.path(),
                "crlf",
                format!("{}\r\n", hex_text.to_uppercase()).as_bytes(),
            ),
        )
        .unwrap();
        assert_eq!(a.key_id(), b.key_id());
        assert_eq!(a.key_id(), c.key_id());
        assert!(a.key_id().as_str().starts_with("file:"));
        assert_eq!(a.key_id().as_str().len(), "file:".len() + 2 * KCV_LEN);
        let other = FileKekProvider::from_key(SecretKey::from_bytes([9; KEY_LEN]));
        assert_ne!(a.key_id(), other.key_id());
    }

    #[test]
    fn file_provider_refuses_missing_and_malformed_key_files_as_key_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let cases: Vec<(PathBuf, &str)> = vec![
            (dir.path().join("missing"), "not found"),
            (write(dir.path(), "short", &[1; 31]), "256-bit"),
            (write(dir.path(), "long", &[1; 33]), "256-bit"),
            (write(dir.path(), "nothex", &[b'g'; 64]), "256-bit"),
            (write(dir.path(), "huge", &[b'0'; 200]), "too large"),
            (write(dir.path(), "empty", b""), "256-bit"),
        ];
        for (path, want) in cases {
            let err = FileKekProvider::open(&StdFileSystem, &path).unwrap_err();
            assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");
            assert!(err.to_string().contains(want), "{err}");
            assert_eq!(
                rustegon_common::Error::from(err).code(),
                rustegon_common::ErrorCode::KeyUnavailable
            );
        }
    }

    #[test]
    fn wrap_unwrap_round_trip_and_wrong_kek_is_key_unavailable() {
        let rng = TestRng::default();
        let kek = FileKekProvider::from_key(SecretKey::generate(&rng));
        let dek = SecretKey::generate(&rng);
        let wrapped = kek.wrap(&dek, &rng).unwrap();
        assert_eq!(wrapped.bytes.len(), FILE_WRAP_LEN);
        assert!(!wrapped.bytes.windows(KEY_LEN).any(|w| w == dek.expose()));
        assert_eq!(kek.unwrap(&wrapped).unwrap().expose(), dek.expose());
        // Two wraps of one key differ (fresh nonce).
        assert_ne!(kek.wrap(&dek, &rng).unwrap().bytes, wrapped.bytes);

        let other = FileKekProvider::from_key(SecretKey::generate(&rng));
        let err = other.unwrap(&wrapped).unwrap_err();
        assert!(matches!(err, StorageError::KeyUnavailable(_)));
        assert!(err.to_string().contains(kek.key_id().as_str()), "{err}");
        // Same id but damaged bytes, or wrong length: still KeyUnavailable.
        let mut damaged = wrapped.clone();
        damaged.bytes[NONCE_LEN] ^= 1;
        assert!(matches!(
            kek.unwrap(&damaged),
            Err(StorageError::KeyUnavailable(_))
        ));
        damaged.bytes.pop();
        assert!(matches!(
            kek.unwrap(&damaged),
            Err(StorageError::KeyUnavailable(_))
        ));
        let provider: Arc<dyn KekProvider> = Arc::new(kek);
        let printed = format!("{provider:?}");
        assert!(
            printed.contains(rustegon_common::redacted::REDACTED),
            "{printed}"
        );
    }

    /// TC-EAR-002 (PD-057): the `env` provider decodes base64 (padded or not, whitespace
    /// around it ignored), wraps/unwraps, and has the id of the same key in a file, so a key can
    /// move between the providers.
    #[test]
    fn tc_ear_002_env_provider_wraps_unwraps_and_shares_the_file_key_id() {
        use base64::Engine as _;
        let dir = tempfile::tempdir().unwrap();
        let raw: Vec<u8> = (100u8..132).collect();
        let file = FileKekProvider::open(&StdFileSystem, &write(dir.path(), "kek", &raw)).unwrap();
        let padded = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(padded.len(), 44);
        let unpadded = padded.trim_end_matches('=').to_owned();
        for text in [padded.clone(), unpadded, format!("  {padded}\n")] {
            let env = FileKekProvider::from_env_value("RUSTEGON_KEK", Some(&text)).unwrap();
            assert_eq!(env.key_id(), file.key_id());
            let rng = TestRng::default();
            let dek = SecretKey::generate(&rng);
            let wrapped = env.wrap(&dek, &rng).unwrap();
            assert_eq!(file.unwrap(&wrapped).unwrap().expose(), dek.expose());
            assert_eq!(env.unwrap(&wrapped).unwrap().expose(), dek.expose());
        }
    }

    /// TC-EAR-003 (PD-057): an unset, empty or malformed variable is `RGN-4006`; the message
    /// names the variable and never echoes the value.
    #[test]
    fn tc_ear_003_env_provider_refuses_missing_or_malformed_values_without_echoing_them() {
        use base64::Engine as _;
        let b64 = |n: usize| base64::engine::general_purpose::STANDARD.encode(vec![7u8; n]);
        let cases = [
            (None, "not set".to_owned()),
            (Some("   ".to_owned()), "empty".to_owned()),
            (Some(b64(31)), "base64".to_owned()),
            (Some(b64(33)), "base64".to_owned()),
            (Some("CANARY-not-base64-!!".to_owned()), "base64".to_owned()),
            (Some("Q".repeat(200)), "base64".to_owned()),
        ];
        for (value, want) in cases {
            let err = FileKekProvider::from_env_value("MY_KEK", value.as_deref()).unwrap_err();
            assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");
            let text = err.to_string();
            assert!(text.contains("MY_KEK") && text.contains(&want), "{text}");
            if let Some(v) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                assert!(!text.contains(v), "value echoed: {text}");
            }
            assert_eq!(
                rustegon_common::Error::from(err).code(),
                rustegon_common::ErrorCode::KeyUnavailable
            );
        }
    }

    /// TC-EAR-003 (security.md §6): on Unix a key file with any group/other permission bit is
    /// refused before it is read; 0600 and 0400 are accepted.
    #[cfg(unix)]
    #[test]
    fn tc_ear_003_file_provider_refuses_a_key_file_others_can_access() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "kek", &[5u8; 32]);
        for (mode, ok) in [(0o600, true), (0o400, true), (0o640, false), (0o604, false)] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let result = FileKekProvider::open(&StdFileSystem, &path);
            assert_eq!(result.is_ok(), ok, "mode {mode:o}");
            if let Err(err) = result {
                assert!(matches!(err, StorageError::KeyUnavailable(_)));
                assert!(err.to_string().contains("chmod 600"), "{err}");
            }
        }
    }

    #[test]
    fn kek_id_bounds() {
        assert!(KekId::new("").is_err());
        assert!(KekId::new("x".repeat(256)).is_err());
        assert_eq!(KekId::new("env:1").unwrap().to_string(), "env:1");
    }
}
