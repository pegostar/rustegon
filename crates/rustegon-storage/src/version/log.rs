// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Record log used by the MANIFEST: `len (u32 LE) ‖ XXH3-64 (u64 LE) ‖ payload`, the checksum
//! covering the length bytes and the payload. Every record is fsynced before it counts
//! (storage-engine.md §9).
//!
//! Torn tails: a crash during an append can leave the last record incomplete or, on file systems
//! that extend the size before the data lands, followed by zeros. An invalid record is therefore
//! accepted as a torn tail only if nothing meaningful follows it — it extends to or past the end
//! of the file, or everything after its length field is zero bytes (see [`is_torn_tail`] for why
//! the length field itself may be partly zeroed). An invalid record followed by other data is
//! corruption: silently dropping later edits could make orphan cleanup delete live files.
//!
//! Trade-off: a complete final record damaged by the medium is indistinguishable from a torn
//! write and is dropped too. Refusing to start after every torn write would be worse; the loss is
//! bounded to the last edit, and the store rewrites a fresh MANIFEST on every open.
//!
//! Encryption (storage-engine.md §7): with a [`FileCipher`] each payload is stored as
//! `ENCRYPTED_RECORD_MARKER ‖ AES-256-GCM(payload) ‖ tag`, the marker byte doubling as
//! associated data. The framing (length, checksum over the stored bytes) is unchanged, so torn
//! tails are handled exactly as for plaintext logs and a damaged record is a checksum failure
//! before the key is touched. Nonce: `log file number ‖ record index` — the §7 log scheme
//! `segment_id ‖ record_seq` with the MANIFEST number as segment id. Indices are unique per DEK
//! because a log is written once, front to back: recovery never appends to an existing MANIFEST
//! (it starts a new one, with a new DEK). The marker lets a reader without the key report
//! `KeyUnavailable` instead of garbage: plaintext payloads never start with it (MANIFEST edits
//! start with their format version 1, and the writer refuses a plaintext payload that would).

use std::{hash::Hasher as _, sync::Arc};

use rustegon_sim_api::File;
use twox_hash::XxHash3_64;

use crate::{
    encryption::FileCipher,
    error::{Result, StorageError},
};

const HEADER_LEN: usize = 12;
/// Upper bound for one record; a full snapshot of a large store is a few MiB.
const MAX_RECORD_LEN: usize = 64 << 20;
/// Upper bound for a whole MANIFEST read into memory at recovery.
const MAX_LOG_LEN: u64 = 1 << 30;
/// First byte of every encrypted record payload (module docs). Persisted; never change.
const ENCRYPTED_RECORD_MARKER: u8 = 0xE5;

fn checksum(len_bytes: [u8; 4], payload: &[u8]) -> u64 {
    let mut h = XxHash3_64::new();
    h.write(&len_bytes);
    h.write(payload);
    h.finish()
}

/// Appends records and syncs each one.
pub(crate) struct LogWriter {
    file: Box<dyn File>,
    buf: Vec<u8>,
    /// The log file's DEK context; `None` for a plaintext log.
    cipher: Option<Arc<FileCipher>>,
    /// Index of the next record (the nonce counter when encrypting).
    next_index: u64,
    /// Set after a failed append or sync: the file may hold a partial or complete copy of the
    /// failed record, so a retry would either corrupt the log or, encrypted, seal different
    /// bytes under the same nonce (GCM forbids reuse). The writer refuses further records.
    failed: bool,
}

impl LogWriter {
    /// A writer appending to the empty `file`, encrypting with `cipher` if given.
    pub(crate) fn new(file: Box<dyn File>, cipher: Option<Arc<FileCipher>>) -> Self {
        Self {
            file,
            buf: Vec::new(),
            cipher,
            next_index: 0,
            failed: false,
        }
    }

    /// Appends one record and makes it durable.
    ///
    /// # Errors
    /// [`StorageError::InvalidArgument`] for an oversized record; I/O errors (after a failed
    /// sync the log state is unknown and the caller must stop using the store).
    pub(crate) fn add_record(&mut self, payload: &[u8]) -> Result<()> {
        if self.failed {
            return Err(StorageError::InvalidArgument(
                "log writer is unusable after a failed write".into(),
            ));
        }
        self.buf.clear();
        // Header placeholder, filled once the stored payload (possibly encrypted) is known.
        self.buf.extend_from_slice(&[0u8; HEADER_LEN]);
        match &self.cipher {
            None => {
                if payload.first() == Some(&ENCRYPTED_RECORD_MARKER) {
                    return Err(StorageError::InvalidArgument(
                        "plaintext log payloads must not start with the encrypted-record marker"
                            .into(),
                    ));
                }
                self.buf.extend_from_slice(payload);
            }
            Some(cipher) => {
                let counter = u32::try_from(self.next_index).map_err(|_| {
                    StorageError::InvalidArgument("encrypted log exceeds 2^32 records".into())
                })?;
                self.buf.push(ENCRYPTED_RECORD_MARKER);
                self.buf.extend_from_slice(payload);
                cipher.seal_in_place(
                    counter,
                    &[ENCRYPTED_RECORD_MARKER],
                    &mut self.buf,
                    HEADER_LEN + 1,
                )?;
            }
        }
        let stored_len = self.buf.len() - HEADER_LEN;
        if stored_len > MAX_RECORD_LEN {
            return Err(StorageError::InvalidArgument(format!(
                "log record of {stored_len} bytes exceeds {MAX_RECORD_LEN}"
            )));
        }
        // Lossless: bounded by MAX_RECORD_LEN.
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (stored_len as u32).to_le_bytes();
        let sum = checksum(len_bytes, &self.buf[HEADER_LEN..]);
        self.buf[..4].copy_from_slice(&len_bytes);
        self.buf[4..HEADER_LEN].copy_from_slice(&sum.to_le_bytes());
        if let Err(e) = self
            .file
            .append(&self.buf)
            .and_then(|()| self.file.sync_data())
        {
            self.failed = true;
            return Err(e.into());
        }
        self.next_index += 1;
        Ok(())
    }
}

/// Records recovered from a log.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LogContents {
    pub(crate) records: Vec<Vec<u8>>,
    /// Whether an invalid final record was discarded.
    pub(crate) torn_tail: bool,
}

/// Reads all valid records, tolerating a torn tail, and decrypts them with `cipher` (see module
/// docs).
///
/// # Errors
/// [`StorageError::Corruption`] for an invalid record followed by data, a record that fails
/// authentication, or a plaintext record in an encrypted log;
/// [`StorageError::KeyUnavailable`] for an encrypted record without `cipher`; I/O errors.
pub(crate) fn read_log(file: &dyn File, cipher: Option<&FileCipher>) -> Result<LogContents> {
    let size = file.size()?;
    if size > MAX_LOG_LEN {
        return Err(StorageError::corruption(format!(
            "log of {size} bytes exceeds {MAX_LOG_LEN}"
        )));
    }
    // Lossless: bounded by MAX_LOG_LEN.
    #[allow(clippy::cast_possible_truncation)]
    let mut data = vec![0u8; size as usize];
    file.read_exact_at(&mut data, 0)?;
    let mut contents = parse_log(&data)?;
    for (index, record) in contents.records.iter_mut().enumerate() {
        decrypt_record(record, index, cipher)?;
    }
    Ok(contents)
}

/// Turns the stored payload of record `index` into its plaintext payload.
fn decrypt_record(record: &mut Vec<u8>, index: usize, cipher: Option<&FileCipher>) -> Result<()> {
    let encrypted = record.first() == Some(&ENCRYPTED_RECORD_MARKER);
    match (cipher, encrypted) {
        (None, false) => Ok(()),
        (None, true) => Err(StorageError::key_unavailable(format!(
            "log record {index} is encrypted but no DEK is available for the log"
        ))),
        (Some(cipher), false) => Err(StorageError::corruption(format!(
            "plaintext record {index} in encrypted log {}",
            cipher.file_number()
        ))),
        (Some(cipher), true) => {
            let counter = u32::try_from(index)
                .map_err(|_| StorageError::corruption("encrypted log exceeds 2^32 records"))?;
            record.remove(0);
            cipher.open_in_place(counter, &[ENCRYPTED_RECORD_MARKER], record)
        }
    }
}

fn parse_log(data: &[u8]) -> Result<LogContents> {
    let mut contents = LogContents::default();
    let mut pos = 0;
    while pos < data.len() {
        match parse_record(&data[pos..]) {
            Some(payload) => {
                pos += HEADER_LEN + payload.len();
                contents.records.push(payload.to_vec());
            }
            None if is_torn_tail(&data[pos..]) => {
                contents.torn_tail = true;
                break;
            }
            None => {
                return Err(StorageError::corruption(format!(
                    "log record at offset {pos} is invalid and followed by data"
                )));
            }
        }
    }
    Ok(contents)
}

/// The payload of a valid record at the start of `rest`, or `None`.
fn parse_record(rest: &[u8]) -> Option<&[u8]> {
    let header = rest.get(..HEADER_LEN)?;
    let len_bytes: [u8; 4] = header[..4].try_into().ok()?;
    let stored: [u8; 8] = header[4..].try_into().ok()?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_RECORD_LEN {
        return None;
    }
    let payload = rest.get(HEADER_LEN..HEADER_LEN + len)?;
    (u64::from_le_bytes(stored) == checksum(len_bytes, payload)).then_some(payload)
}

/// Whether the invalid record at the start of `rest` is a torn final write.
///
/// A torn write leaves a prefix of the record, possibly followed by zeros (module docs). If the
/// prefix covers the whole length field, the claimed length is the real one and the record
/// reaches to or past the end of the file. If the prefix ends *inside* the length field, the
/// zero fill clears its high bytes, so a record longer than 255 bytes claims a shorter length
/// that can end before the file does; then every byte after the length field is zero. Both
/// cases leave no later record behind, so accepting them never drops a durable edit; anything
/// else (non-zero bytes after the claimed end of an invalid record) is corruption.
fn is_torn_tail(rest: &[u8]) -> bool {
    let Some(len_bytes) = rest.get(..4) else {
        return true;
    };
    let mut raw = [0u8; 4];
    raw.copy_from_slice(len_bytes);
    let claimed_end = HEADER_LEN.saturating_add(u32::from_le_bytes(raw) as usize);
    claimed_end >= rest.len() || rest[4..].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn failed_append_poisons_the_writer_so_no_nonce_is_reused() {
        use rustegon_sim::SimFileSystem;
        use rustegon_sim_api::{FileSystem, OpenMode};
        let fs = SimFileSystem::new();
        fs.create_dir_all(std::path::Path::new("/log")).unwrap();
        let file = fs
            .open(
                std::path::Path::new("/log/MANIFEST-000001"),
                OpenMode::CreateNew,
            )
            .unwrap();
        let mut w = super::LogWriter::new(file, None);
        w.add_record(b"first").unwrap();
        fs.fail_next_appends(1);
        assert!(w.add_record(b"second").is_err());
        // The fault is gone, but the writer stays poisoned.
        assert!(matches!(
            w.add_record(b"third"),
            Err(crate::error::StorageError::InvalidArgument(_))
        ));
    }

    use super::*;

    fn encode(records: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in records {
            let len_bytes = u32::try_from(r.len()).unwrap().to_le_bytes();
            out.extend_from_slice(&len_bytes);
            out.extend_from_slice(&checksum(len_bytes, r).to_le_bytes());
            out.extend_from_slice(r);
        }
        out
    }

    #[test]
    fn log_round_trips_and_tolerates_every_truncation() {
        let records: [&[u8]; 3] = [b"first", b"", b"third record"];
        let data = encode(&records);
        let full = parse_log(&data).unwrap();
        assert_eq!(full.records, records.map(<[u8]>::to_vec));
        assert!(!full.torn_tail);
        let ends = [17, 29, data.len()];
        for cut in 0..=data.len() {
            let got = parse_log(&data[..cut]).unwrap();
            let complete = ends.iter().filter(|&&e| e <= cut).count();
            assert_eq!(got.records.len(), complete, "cut {cut}");
            assert_eq!(got.torn_tail, !ends.contains(&cut) && cut != 0, "cut {cut}");
        }
    }

    /// TC-STO-002 regression (found by the 2026-11-05 crash campaign after subcompactions made
    /// MANIFEST edits longer than 255 bytes): a torn final record whose surviving prefix ends
    /// inside the length field and is then zero-filled (size persisted before the data) has its
    /// high length bytes zeroed, so it claims a *shorter* length that ends before the file does.
    /// It is still a torn tail: nothing but zeros follows the length field.
    #[test]
    fn long_final_record_torn_in_its_length_field_and_zero_filled_is_a_torn_tail() {
        let long = vec![0xA5u8; 0x14E];
        let data = encode(&[b"first", &long]);
        let start = encode(&[b"first"]).len();
        for kept in 0..=data.len() - start {
            for total in kept..=data.len() - start {
                let mut torn = data[..start + kept].to_vec();
                torn.resize(start + total, 0);
                let got =
                    parse_log(&torn).unwrap_or_else(|e| panic!("kept {kept}, total {total}: {e}"));
                let complete = usize::from(kept == data.len() - start);
                assert_eq!(
                    got.records.len(),
                    1 + complete,
                    "kept {kept}, total {total}"
                );
                assert_eq!(got.torn_tail, complete == 0 && total > 0, "kept {kept}");
            }
        }
    }

    #[test]
    fn log_distinguishes_torn_tail_from_corruption() {
        // Zero fill after the last record: torn tail.
        let mut data = encode(&[b"a", b"b"]);
        data.extend_from_slice(&[0u8; 100]);
        let got = parse_log(&data).unwrap();
        assert_eq!((got.records.len(), got.torn_tail), (2, true));

        // Damage in a record followed by more records: corruption.
        let mut data = encode(&[b"aaaa", b"bbbb", b"cccc"]);
        data[HEADER_LEN] ^= 1;
        assert!(parse_log(&data).unwrap_err().is_corruption());

        // Damage in the complete final record: indistinguishable from a torn write, dropped
        // (module docs, "Trade-off").
        let mut data = encode(&[b"aaaa", b"bbbb"]);
        let last = data.len() - 1;
        data[last] ^= 1;
        let got = parse_log(&data).unwrap();
        assert_eq!((got.records.len(), got.torn_tail), (1, true));
    }

    mod encrypted {
        use rustegon_sim_api::{FileSystem as _, OpenMode, StdFileSystem};

        use super::*;
        use crate::encryption::{SecretKey, tests::TestRng};

        fn cipher(file_number: u64) -> Arc<FileCipher> {
            cipher_seeded(file_number, 0)
        }

        fn cipher_seeded(file_number: u64, seed: u64) -> Arc<FileCipher> {
            let dek = SecretKey::generate(&TestRng(seed.into()));
            Arc::new(FileCipher::new(file_number, &dek))
        }

        /// Writes `records` through a `LogWriter` and returns the file bytes.
        fn write(records: &[&[u8]], cipher: Option<Arc<FileCipher>>) -> Vec<u8> {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("log");
            let file = StdFileSystem.open(&path, OpenMode::CreateNew).unwrap();
            let mut w = LogWriter::new(file, cipher);
            for r in records {
                w.add_record(r).unwrap();
            }
            let f = StdFileSystem.open(&path, OpenMode::Read).unwrap();
            let mut data = vec![0u8; usize::try_from(f.size().unwrap()).unwrap()];
            f.read_exact_at(&mut data, 0).unwrap();
            data
        }

        fn read(data: &[u8], cipher: Option<&FileCipher>) -> Result<LogContents> {
            let mut contents = parse_log(data)?;
            for (i, r) in contents.records.iter_mut().enumerate() {
                decrypt_record(r, i, cipher)?;
            }
            Ok(contents)
        }

        #[test]
        fn plaintext_writer_output_is_the_v1_framing() {
            let records: [&[u8]; 3] = [b"\x01first", b"\x01", b"\x01third"];
            assert_eq!(write(&records, None), encode(&records));
            let dir = tempfile::tempdir().unwrap();
            let file = StdFileSystem
                .open(&dir.path().join("log"), OpenMode::CreateNew)
                .unwrap();
            let err = LogWriter::new(file, None)
                .add_record(&[ENCRYPTED_RECORD_MARKER, 1])
                .unwrap_err();
            assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
        }

        #[test]
        fn encrypted_log_round_trips_hides_payloads_and_tolerates_torn_tails() {
            let c = cipher(42);
            let records: [&[u8]; 3] = [b"\x01SECRET-one", b"\x01", b"\x01SECRET-three"];
            let data = write(&records, Some(Arc::clone(&c)));
            assert!(!data.windows(6).any(|w| w == b"SECRET"));
            let got = read(&data, Some(&c)).unwrap();
            assert_eq!(got.records, records.map(<[u8]>::to_vec));
            // Same prefix-of-records behaviour under every truncation as the plaintext log.
            for cut in 0..=data.len() {
                let got = read(&data[..cut], Some(&c)).unwrap();
                assert!(got.records.len() <= 3, "cut {cut}");
                for (r, want) in got.records.iter().zip(records) {
                    assert_eq!(r, want, "cut {cut}");
                }
            }
        }

        #[test]
        fn key_mismatch_and_tampering_are_reported() {
            let c = cipher(42);
            let data = write(&[b"\x01a", b"\x01b"], Some(Arc::clone(&c)));
            let err = read(&data, None).unwrap_err();
            assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");
            // Another DEK (or another file number) fails authentication: corruption.
            assert!(
                read(&data, Some(&cipher_seeded(42, 1)))
                    .unwrap_err()
                    .is_corruption()
            );
            assert!(read(&data, Some(&cipher(43))).unwrap_err().is_corruption());
            let plain = write(&[b"\x01a"], None);
            let err = read(&plain, Some(&c)).unwrap_err();
            assert!(err.to_string().contains("plaintext record"), "{err}");

            // Ciphertext flipped and the checksum recomputed, as an attacker would: the GCM tag
            // catches it.
            let mut forged = data.clone();
            forged[HEADER_LEN + 1] ^= 0x20;
            let len_bytes: [u8; 4] = forged[..4].try_into().unwrap();
            let len = u32::from_le_bytes(len_bytes) as usize;
            let sum = checksum(len_bytes, &forged[HEADER_LEN..HEADER_LEN + len]);
            forged[4..HEADER_LEN].copy_from_slice(&sum.to_le_bytes());
            let err = read(&forged, Some(&c)).unwrap_err();
            assert!(err.to_string().contains("authentication failed"), "{err}");

            // Records swapped (both valid on their own): the record index in the nonce
            // detects the reordering.
            let first_len = HEADER_LEN + len;
            let mut swapped = data[first_len..].to_vec();
            swapped.extend_from_slice(&data[..first_len]);
            assert!(read(&swapped, Some(&c)).unwrap_err().is_corruption());
        }
    }
}
