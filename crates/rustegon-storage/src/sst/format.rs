// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Physical framing of `rsst` v1 files: block handles, block trailers and the footer
//! (storage-engine.md §4).
//!
//! Every block on disk is `stored_bytes ‖ trailer`, trailer =
//! `compression (u8) ‖ encryption (u8) ‖ xxh3-64 (u64 LE)`. The checksum covers the stored bytes
//! *and* the two type bytes, so a flipped type byte is detected instead of misinterpreting the
//! block.
//!
//! Encryption (storage-engine.md §7): with a [`FileCipher`] the stored bytes are
//! `AES-256-GCM(compressed contents) ‖ tag (16 B)`, encrypted *after* compression (ciphertext
//! does not compress) under nonce `file_number ‖ block_offset / 16`, with the two type bytes as
//! associated data so a forged codec byte fails authentication even when the attacker also fixes
//! the checksum. The encryption byte is then 1 and the handle size includes the tag. The checksum
//! still covers the stored (encrypted) bytes, so damage is reported as a checksum mismatch
//! without touching the key; the GCM tag is verified on every read and a mismatch is corruption.
//! A plaintext file (no DEK in the registry) keeps byte-identical v1 framing (encryption byte 0).
//!
//! Footer (64 bytes, at the end of the file):
//! ```text
//! 0..8   metaindex offset (u64 LE)     8..16  metaindex size (u64 LE)
//! 16..20 format version (u32 LE)       20..48 reserved (zero)
//! 48..56 xxh3-64 of bytes 0..48        56..64 magic "RSTEGON\x01"
//! ```
//! The magic is last so a reader can recognise the file type from its final 8 bytes.

use std::hash::Hasher as _;

use bytes::Bytes;
use rustegon_sim_api::File;
use twox_hash::XxHash3_64;

use super::compression::{self, CompressionPolicy};
use crate::{
    coding::{Reader, put_varint},
    encryption::FileCipher,
    error::{Result, StorageError},
};

/// `rsst` format version written by this build.
pub const FORMAT_VERSION: u32 = 1;
/// File magic (last 8 bytes of every SST).
pub const MAGIC: [u8; 8] = *b"RSTEGON\x01";
/// Footer length in bytes.
pub const FOOTER_LEN: usize = 64;
/// Block trailer length: compression byte, encryption byte, 8-byte checksum.
pub const BLOCK_TRAILER_LEN: usize = 10;
/// Upper bound on a stored block, used to reject corrupt handles before allocating. A block holds
/// at most one oversized value beyond the target size and values are capped at 16 MiB (document
/// limit), so 256 MiB leaves ample room.
pub const MAX_BLOCK_LEN: u64 = 256 << 20;

const FOOTER_CHECKSUM_AT: usize = 48;

/// Block compression codec, as stored in the trailer. Values are persisted; never renumber.
/// Codecs 1 and 2 were added to v1 before its freeze at M1 exit (storage-engine.md §4,
/// "Format status"), so no version bump; after the freeze a new codec needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    /// Stored uncompressed.
    None = 0,
    /// LZ4 block format, prefixed by the raw length as a varint.
    Lz4 = 1,
    /// Zstd frame, prefixed by the raw length as a varint.
    Zstd = 2,
}

impl Compression {
    fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::None),
            1 => Some(Self::Lz4),
            2 => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// Block encryption marker in the trailer: plaintext. Values are persisted; never renumber.
const ENCRYPTION_NONE: u8 = 0;
/// Block encryption marker: AES-256-GCM under the file's DEK, 16-byte tag at the end of the
/// stored bytes (module docs).
const ENCRYPTION_AES_256_GCM: u8 = 1;
/// Divisor turning a block offset into its nonce counter (§7: `block_offset_div_16`).
const NONCE_OFFSET_UNIT: u64 = 16;

/// Nonce counter of the block at `offset`: `offset / 16`, refused when it does not fit the
/// nonce's 32 bits (an SST beyond 64 GiB) instead of wrapping into a repeated nonce.
pub(crate) fn nonce_counter(offset: u64) -> Result<u32> {
    u32::try_from(offset / NONCE_OFFSET_UNIT).map_err(|_| {
        StorageError::InvalidArgument(format!(
            "block offset {offset} exceeds the encrypted SST limit of {} bytes",
            (u64::from(u32::MAX) + 1) * NONCE_OFFSET_UNIT
        ))
    })
}

/// Location of a block inside an SST (size excludes the trailer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockHandle {
    /// Byte offset of the block.
    pub offset: u64,
    /// Stored size of the block without its trailer.
    pub size: u64,
}

impl BlockHandle {
    pub(crate) fn encode_to(self, buf: &mut Vec<u8>) {
        put_varint(buf, self.offset);
        put_varint(buf, self.size);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        match (r.varint(), r.varint()) {
            (Some(offset), Some(size)) if r.is_empty() => Ok(Self { offset, size }),
            _ => Err(StorageError::corruption("malformed block handle")),
        }
    }
}

fn block_checksum(stored: &[u8], compression: u8, encryption: u8) -> u64 {
    let mut h = XxHash3_64::new();
    h.write(stored);
    h.write(&[compression, encryption]);
    h.finish()
}

/// Appends `stored ‖ trailer` to `out` (a scratch buffer reused across blocks), compressing
/// `contents` per `policy` (storage-engine.md §6) and, with `cipher`, encrypting the result for
/// a block placed at file offset `offset` (module docs). Returns the stored size (the handle
/// size) and the codec actually used.
///
/// # Errors
/// [`StorageError::InvalidArgument`] when encrypting at an offset beyond the nonce range.
pub(crate) fn frame_block(
    out: &mut Vec<u8>,
    contents: &[u8],
    policy: CompressionPolicy,
    cipher: Option<&FileCipher>,
    offset: u64,
) -> Result<(u64, Compression)> {
    let start = out.len();
    let codec = compression::compress_into(out, contents, policy);
    let compression = codec as u8;
    let encryption = match cipher {
        None => ENCRYPTION_NONE,
        Some(cipher) => {
            let counter = nonce_counter(offset)?;
            cipher.seal_in_place(counter, &[compression, ENCRYPTION_AES_256_GCM], out, start)?;
            ENCRYPTION_AES_256_GCM
        }
    };
    let stored_len = out.len() - start;
    let checksum = block_checksum(&out[start..], compression, encryption);
    out.push(compression);
    out.push(encryption);
    out.extend_from_slice(&checksum.to_le_bytes());
    Ok((stored_len as u64, codec))
}

/// Reads and verifies the block at `handle`; `limit` is the end of the block area (start of
/// the footer), and returns the decrypted, decompressed contents. `cipher` is the file's DEK
/// context, `None` for a plaintext file. Checksum mismatch, a failed GCM tag, unknown codec or
/// encryption byte, a plaintext block in an encrypted file, undecodable payload or out-of-range
/// handles are corruption; an encrypted block in a file without a key is
/// [`StorageError::KeyUnavailable`].
pub(crate) fn read_block(
    file: &dyn File,
    handle: BlockHandle,
    limit: u64,
    cipher: Option<&FileCipher>,
) -> Result<Bytes> {
    let in_range = handle
        .size
        .checked_add(BLOCK_TRAILER_LEN as u64)
        .and_then(|t| handle.offset.checked_add(t))
        .is_some_and(|end| end <= limit);
    if !in_range || handle.size > MAX_BLOCK_LEN {
        return Err(StorageError::corruption(format!(
            "block handle {}+{} outside file data ({limit} bytes)",
            handle.offset, handle.size
        )));
    }
    // Lossless: bounded by MAX_BLOCK_LEN above.
    #[allow(clippy::cast_possible_truncation)]
    let size = handle.size as usize;
    let mut buf = vec![0u8; size + BLOCK_TRAILER_LEN];
    file.read_exact_at(&mut buf, handle.offset)?;
    let (compression, encryption) = (buf[size], buf[size + 1]);
    let mut stored_sum = [0u8; 8];
    stored_sum.copy_from_slice(&buf[size + 2..]);
    if u64::from_le_bytes(stored_sum) != block_checksum(&buf[..size], compression, encryption) {
        return Err(StorageError::corruption(format!(
            "block checksum mismatch at offset {}",
            handle.offset
        )));
    }
    match (encryption, cipher) {
        (ENCRYPTION_NONE, None) => buf.truncate(size),
        (ENCRYPTION_AES_256_GCM, Some(cipher)) => {
            buf.truncate(size);
            // Authenticated before anything is decoded: tampered bytes never reach the
            // decompressor.
            cipher.open_in_place(
                nonce_counter(handle.offset)?,
                &[compression, encryption],
                &mut buf,
            )?;
        }
        (ENCRYPTION_NONE, Some(_)) => {
            // A file with a DEK is encrypted throughout; a plaintext block in it was swapped in.
            return Err(StorageError::corruption(format!(
                "plaintext block at offset {} in an encrypted SST",
                handle.offset
            )));
        }
        (ENCRYPTION_AES_256_GCM, None) => {
            return Err(StorageError::key_unavailable(format!(
                "encrypted SST block at offset {} but no DEK is available for the file",
                handle.offset
            )));
        }
        _ => {
            return Err(StorageError::corruption(format!(
                "unsupported block encryption flag {encryption} at offset {}",
                handle.offset
            )));
        }
    }
    let Some(codec) = Compression::from_u8(compression) else {
        return Err(StorageError::corruption(format!(
            "unknown block compression codec {compression} at offset {} \
             (rsst v{FORMAT_VERSION} knows 0 none, 1 lz4, 2 zstd)",
            handle.offset
        )));
    };
    if codec == Compression::None {
        return Ok(Bytes::from(buf));
    }
    // Decompression runs only on checksum-verified bytes.
    compression::decompress(codec, &buf)
        .map(Bytes::from)
        .map_err(|e| StorageError::corruption(format!("{e} at offset {}", handle.offset)))
}

/// Decoded footer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Footer {
    pub(crate) metaindex: BlockHandle,
    pub(crate) format_version: u32,
}

impl Footer {
    pub(crate) fn encode(self) -> [u8; FOOTER_LEN] {
        let mut out = [0u8; FOOTER_LEN];
        out[0..8].copy_from_slice(&self.metaindex.offset.to_le_bytes());
        out[8..16].copy_from_slice(&self.metaindex.size.to_le_bytes());
        out[16..20].copy_from_slice(&self.format_version.to_le_bytes());
        let checksum = XxHash3_64::oneshot(&out[..FOOTER_CHECKSUM_AT]);
        out[FOOTER_CHECKSUM_AT..56].copy_from_slice(&checksum.to_le_bytes());
        out[56..].copy_from_slice(&MAGIC);
        out
    }

    pub(crate) fn decode(bytes: &[u8; FOOTER_LEN]) -> Result<Self> {
        if bytes[56..] != MAGIC {
            return Err(StorageError::corruption("not an rsst file (bad magic)"));
        }
        let corrupt = || StorageError::corruption("truncated footer");
        let mut r = Reader::new(bytes);
        let offset = r.u64().ok_or_else(corrupt)?;
        let size = r.u64().ok_or_else(corrupt)?;
        let format_version = r.u32().ok_or_else(corrupt)?;
        let stored = Reader::new(&bytes[FOOTER_CHECKSUM_AT..])
            .u64()
            .ok_or_else(corrupt)?;
        if stored != XxHash3_64::oneshot(&bytes[..FOOTER_CHECKSUM_AT]) {
            return Err(StorageError::corruption("footer checksum mismatch"));
        }
        if format_version != FORMAT_VERSION {
            return Err(StorageError::corruption(format!(
                "unsupported rsst format version {format_version}"
            )));
        }
        Ok(Self {
            metaindex: BlockHandle { offset, size },
            format_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_round_trips_and_detects_damage() {
        let footer = Footer {
            metaindex: BlockHandle {
                offset: 123_456,
                size: 789,
            },
            format_version: FORMAT_VERSION,
        };
        let bytes = footer.encode();
        assert_eq!(Footer::decode(&bytes).unwrap(), footer);
        for at in 0..FOOTER_LEN {
            let mut bad = bytes;
            bad[at] ^= 0x10;
            assert!(Footer::decode(&bad).is_err(), "flip at {at} undetected");
        }
    }

    /// The checksum is part of the persisted format: pin the algorithm (XXH3-64, seed 0) with
    /// the reference vector, independent of the crate that implements it.
    #[test]
    fn checksum_is_xxh3_64_reference() {
        assert_eq!(XxHash3_64::oneshot(b""), 0x2d06_8005_38d3_94c2);
        let data: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        assert_eq!(
            block_checksum(&data, 1, 0),
            XxHash3_64::oneshot(&[data.as_slice(), &[1, 0]].concat())
        );
    }

    /// TC-CMP-005: blocks of different codecs (and raw fallbacks) coexist in one file; the
    /// trailer codec byte alone selects the decoder.
    #[test]
    fn tc_cmp_005_mixed_codecs_in_one_file_read_back() {
        use rustegon_sim_api::{FileSystem as _, OpenMode, StdFileSystem};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed.sst");
        let mut file = StdFileSystem.open(&path, OpenMode::CreateNew).unwrap();
        let compressible = b"mixed codecs ".repeat(200);
        // xorshift64 noise: no codec saves 12.5 % on it.
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let incompressible: Vec<u8> = (0..2000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect();
        let blocks = [
            (CompressionPolicy::Lz4, &compressible, Compression::Lz4),
            (
                CompressionPolicy::Zstd { level: 3 },
                &compressible,
                Compression::Zstd,
            ),
            (CompressionPolicy::None, &compressible, Compression::None),
            (
                CompressionPolicy::Zstd { level: 19 },
                &incompressible,
                Compression::None,
            ),
            (CompressionPolicy::Lz4, &incompressible, Compression::None),
        ];
        let (mut offset, mut handles, mut buf) = (0u64, Vec::new(), Vec::new());
        for (policy, contents, want) in blocks {
            buf.clear();
            let (size, codec) = frame_block(&mut buf, contents, policy, None, offset).unwrap();
            assert_eq!(codec, want, "{policy:?}");
            handles.push(BlockHandle { offset, size });
            file.append(&buf).unwrap();
            offset += buf.len() as u64;
        }
        for (handle, (_, contents, _)) in handles.into_iter().zip(blocks) {
            assert_eq!(
                &read_block(file.as_ref(), handle, offset, None).unwrap()[..],
                &contents[..]
            );
        }
    }

    /// Writes `stored ‖ trailer` with a *valid* checksum for an arbitrary codec byte, as a
    /// writer bug or a future format would, and reads it back through `read_block`.
    fn read_forged(stored: &[u8], codec: u8) -> Result<Bytes> {
        use rustegon_sim_api::{FileSystem as _, OpenMode, StdFileSystem};

        let dir = tempfile::tempdir().unwrap();
        let mut file = StdFileSystem
            .open(&dir.path().join("forged.sst"), OpenMode::CreateNew)
            .unwrap();
        let mut buf = stored.to_vec();
        let checksum = block_checksum(stored, codec, ENCRYPTION_NONE);
        buf.extend_from_slice(&[codec, ENCRYPTION_NONE]);
        buf.extend_from_slice(&checksum.to_le_bytes());
        file.append(&buf).unwrap();
        let handle = BlockHandle {
            offset: 0,
            size: stored.len() as u64,
        };
        read_block(file.as_ref(), handle, buf.len() as u64, None)
    }

    /// Unknown codec bytes with a valid checksum are corruption naming the codec value.
    #[test]
    fn unknown_codec_byte_is_corruption_naming_the_codec() {
        for codec in [3u8, 0x7F, 0xFF] {
            let err = read_forged(b"payload", codec).unwrap_err();
            assert!(err.is_corruption());
            let msg = err.to_string();
            assert!(msg.contains(&format!("compression codec {codec}")), "{msg}");
        }
    }

    /// TC-CMP-003: a checksum-valid compressed block with a bogus payload is `StorageCorruption`
    /// through `read_block`, never a panic.
    #[test]
    fn tc_cmp_003_forged_compressed_block_is_corruption() {
        let mut lying = Vec::new();
        put_varint(&mut lying, MAX_BLOCK_LEN);
        lying.extend_from_slice(b"tiny");
        let mut garbage = Vec::new();
        put_varint(&mut garbage, 64);
        garbage.extend_from_slice(&[0xF7; 40]);
        for codec in [Compression::Lz4, Compression::Zstd] {
            for stored in [&lying[..], &garbage[..], &[0x80][..], &[][..]] {
                let err = read_forged(stored, codec as u8).unwrap_err();
                assert!(err.is_corruption(), "{codec:?}: {err}");
                assert!(err.to_string().contains("at offset 0"), "{err}");
            }
        }
    }

    // Test offsets are tiny; the casts cannot truncate.
    #[allow(clippy::cast_possible_truncation)]
    mod encrypted {
        use std::path::Path;

        use proptest::prelude::*;
        use rustegon_sim_api::{FileSystem as _, OpenMode, StdFileSystem};

        use super::*;
        use crate::encryption::{SecretKey, TAG_LEN, tests::TestRng};

        fn cipher(file_number: u64, seed: u64) -> FileCipher {
            FileCipher::new(file_number, &SecretKey::generate(&TestRng(seed.into())))
        }

        /// Frames `blocks` back to back into a new file; returns the file and the handles.
        fn write(
            dir: &Path,
            blocks: &[(&[u8], CompressionPolicy)],
            cipher: Option<&FileCipher>,
        ) -> (Box<dyn File>, Vec<BlockHandle>, Vec<u8>) {
            let mut file = StdFileSystem
                .open(&dir.join("enc.sst"), OpenMode::CreateNew)
                .unwrap();
            let (mut all, mut handles) = (Vec::new(), Vec::new());
            for (contents, policy) in blocks {
                let offset = all.len() as u64;
                let (size, _) = frame_block(&mut all, contents, *policy, cipher, offset).unwrap();
                handles.push(BlockHandle { offset, size });
            }
            file.append(&all).unwrap();
            (file, handles, all)
        }

        /// Rewrites block `h`'s trailer checksum after a forgery, as an attacker could.
        fn fix_checksum(bytes: &mut [u8], h: BlockHandle) {
            let (start, size) = (h.offset as usize, h.size as usize);
            let (codec, enc) = (bytes[start + size], bytes[start + size + 1]);
            let sum = block_checksum(&bytes[start..start + size], codec, enc);
            bytes[start + size + 2..start + size + 10].copy_from_slice(&sum.to_le_bytes());
        }

        fn reread(dir: &Path, bytes: &[u8]) -> Box<dyn File> {
            let path = dir.join("forged.sst");
            drop(StdFileSystem.remove_file(&path));
            let mut f = StdFileSystem.open(&path, OpenMode::CreateNew).unwrap();
            f.append(bytes).unwrap();
            f
        }

        /// SST blocks encrypted after compression round-trip; plaintext never reaches disk.
        #[test]
        fn encrypted_blocks_round_trip_after_compression() {
            let dir = tempfile::tempdir().unwrap();
            let text = b"CANARY plaintext that compresses well ".repeat(50);
            let blocks: [(&[u8], CompressionPolicy); 4] = [
                (&text, CompressionPolicy::Lz4),
                (&text, CompressionPolicy::Zstd { level: 3 }),
                (&text, CompressionPolicy::None),
                (b"", CompressionPolicy::None),
            ];
            let c = cipher(77, 1);
            let (file, handles, bytes) = write(dir.path(), &blocks, Some(&c));
            assert!(!bytes.windows(6).any(|w| w == b"CANARY"));
            let end = bytes.len() as u64;
            for (h, (contents, _)) in handles.iter().zip(blocks) {
                let at = (h.offset + h.size) as usize;
                assert_eq!(bytes[at + 1], ENCRYPTION_AES_256_GCM);
                assert!(h.size >= TAG_LEN as u64);
                let got = read_block(file.as_ref(), *h, end, Some(&c)).unwrap();
                assert_eq!(&got[..], contents);
            }
            // The compressed blocks are smaller than the raw text even with the tag: encryption
            // ran after compression.
            assert!(handles[0].size < text.len() as u64);
            assert_eq!(handles[2].size, (text.len() + TAG_LEN) as u64);
        }

        #[test]
        fn key_mismatches_and_forgeries_are_detected() {
            let dir = tempfile::tempdir().unwrap();
            let text = b"some block contents ".repeat(20);
            let blocks: [(&[u8], CompressionPolicy); 2] = [
                (&text, CompressionPolicy::Lz4),
                (&text, CompressionPolicy::None),
            ];
            let c = cipher(5, 1);
            let (file, handles, bytes) = write(dir.path(), &blocks, Some(&c));
            let end = bytes.len() as u64;
            let h = handles[0];

            let err = read_block(file.as_ref(), h, end, None).unwrap_err();
            assert!(matches!(err, StorageError::KeyUnavailable(_)), "{err}");
            for wrong in [cipher(5, 2), cipher(6, 1)] {
                let err = read_block(file.as_ref(), h, end, Some(&wrong)).unwrap_err();
                assert!(err.to_string().contains("authentication failed"), "{err}");
            }

            // Plain damage: checksum mismatch, before the key is used.
            let mut damaged = bytes.clone();
            damaged[h.offset as usize + 3] ^= 1;
            let f = reread(dir.path(), &damaged);
            let err = read_block(f.as_ref(), h, end, Some(&c)).unwrap_err();
            assert!(err.to_string().contains("checksum mismatch"), "{err}");

            // Forged ciphertext, tag and codec byte with a recomputed checksum: the GCM tag
            // (with the codec byte as associated data) rejects each.
            let size = h.size as usize;
            for at in [
                h.offset as usize,
                h.offset as usize + size - 1,
                h.offset as usize + size,
            ] {
                let mut forged = bytes.clone();
                forged[at] ^= if at == h.offset as usize + size {
                    0x03
                } else {
                    0x40
                };
                fix_checksum(&mut forged, h);
                let f = reread(dir.path(), &forged);
                let err = read_block(f.as_ref(), h, end, Some(&c)).unwrap_err();
                assert!(err.is_corruption(), "byte {at}: {err}");
                assert!(
                    err.to_string().contains("authentication failed"),
                    "byte {at}: {err}"
                );
            }

            // A block moved to another offset fails: the offset is part of the nonce.
            let h1 = handles[1];
            let mut moved = bytes[h1.offset as usize..].to_vec();
            moved.extend_from_slice(&bytes[h1.offset as usize..]);
            let f = reread(dir.path(), &moved);
            let relocated = BlockHandle {
                offset: moved.len() as u64 / 2,
                size: h1.size,
            };
            let err = read_block(f.as_ref(), relocated, moved.len() as u64, Some(&c)).unwrap_err();
            assert!(err.to_string().contains("authentication failed"), "{err}");

            // A plaintext block in an encrypted file is corruption; an unknown flag too.
            let mut mixed = Vec::new();
            frame_block(&mut mixed, b"plain", CompressionPolicy::None, None, 0).unwrap();
            let f = reread(dir.path(), &mixed);
            let ph = BlockHandle { offset: 0, size: 5 };
            let err = read_block(f.as_ref(), ph, mixed.len() as u64, Some(&c)).unwrap_err();
            assert!(err.to_string().contains("plaintext block"), "{err}");
            mixed[6] = 9;
            fix_checksum(&mut mixed, ph);
            let f = reread(dir.path(), &mixed);
            let err = read_block(f.as_ref(), ph, mixed.len() as u64, None).unwrap_err();
            assert!(err.to_string().contains("encryption flag 9"), "{err}");
        }

        #[test]
        fn nonce_counter_is_offset_div_16_and_refuses_overflow() {
            assert_eq!(nonce_counter(0).unwrap(), 0);
            assert_eq!(nonce_counter(31).unwrap(), 1);
            let limit = (u64::from(u32::MAX) + 1) * NONCE_OFFSET_UNIT;
            assert_eq!(nonce_counter(limit - 1).unwrap(), u32::MAX);
            assert!(matches!(
                nonce_counter(limit),
                Err(StorageError::InvalidArgument(_))
            ));
            let c = cipher(1, 1);
            let err = frame_block(
                &mut Vec::new(),
                b"x",
                CompressionPolicy::None,
                Some(&c),
                limit,
            )
            .unwrap_err();
            assert!(matches!(err, StorageError::InvalidArgument(_)), "{err}");
        }

        proptest! {
            /// Nonce uniqueness (storage-engine.md §7): blocks framed back to back, of any size
            /// including empty, get strictly increasing `offset / 16` counters, because each
            /// encrypted block occupies more than 16 bytes on disk.
            #[test]
            fn tc_ear_nonce_counters_strictly_increase(
                lens in proptest::collection::vec(0usize..300, 1..60),
                zstd in any::<bool>(),
            ) {
                let c = cipher(3, 9);
                let policy = if zstd {
                    CompressionPolicy::Zstd { level: 1 }
                } else {
                    CompressionPolicy::Lz4
                };
                let mut out = Vec::new();
                let mut last: Option<u32> = None;
                for len in lens {
                    let offset = out.len() as u64;
                    let contents = vec![b'z'; len];
                    frame_block(&mut out, &contents, policy, Some(&c), offset).unwrap();
                    let counter = nonce_counter(offset).unwrap();
                    prop_assert!(last.is_none_or(|l| counter > l), "{last:?} -> {counter}");
                    prop_assert!(out.len() as u64 - offset > NONCE_OFFSET_UNIT);
                    last = Some(counter);
                }
            }
        }
    }

    #[test]
    fn block_handle_round_trips_and_rejects_garbage() {
        let h = BlockHandle {
            offset: u64::MAX,
            size: 16 << 10,
        };
        let mut buf = Vec::new();
        h.encode_to(&mut buf);
        assert_eq!(BlockHandle::decode(&buf).unwrap(), h);
        buf.push(0);
        assert!(BlockHandle::decode(&buf).is_err());
        assert!(BlockHandle::decode(&[0x80]).is_err());
    }
}
