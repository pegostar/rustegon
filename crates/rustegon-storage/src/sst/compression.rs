// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Per-block compression (FR-CMP-001, storage-engine.md §6).
//!
//! Stored form of a compressed block: `raw length (varint) ‖ codec payload`. The raw length is
//! stored by us rather than taken from the codec because LZ4 block format does not record it and
//! because it lets the reader reject an absurd length *before* allocating: a corrupt or hostile
//! block yields [`StorageError::Corruption`], never an out-of-memory abort. The block checksum
//! (see [`super::format`]) covers this stored form, so decompression only ever runs on bytes
//! that passed verification; the length checks here guard against writer bugs and checksum
//! collisions.
//!
//! A block whose stored compressed form (varint length prefix included) is larger than 87.5 %
//! of its raw size is stored raw with [`Compression::None`]: decompressing it would cost CPU on
//! every read for little space saving (the same threshold `RocksDB` uses by default).
//!
//! Before allocating the output buffer the reader bounds the recorded raw length three ways: the
//! absolute block bound ([`MAX_BLOCK_LEN`]), the codec's maximum expansion ratio over the
//! payload size, and for Zstd the frame header's content size, which must match exactly. A
//! checksum-valid block with a lying length therefore cannot make a small payload allocate
//! 256 MiB.

use super::format::{Compression, MAX_BLOCK_LEN};
use crate::{
    coding::{get_varint, put_varint},
    error::{Result, StorageError},
};

/// Zstd level for L2+ (storage-engine.md §6).
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;
/// Zstd level for the bottommost level (storage-engine.md §6, tunable).
pub const DEFAULT_BOTTOMMOST_ZSTD_LEVEL: i32 = 6;
/// Lowest Zstd level accepted by configuration (`zstd(1..19)`, storage-engine.md §6).
pub const MIN_ZSTD_LEVEL: i32 = 1;
/// Highest Zstd level accepted by configuration; 20+ are "ultra" levels with large windows.
pub const MAX_ZSTD_LEVEL: i32 = 19;
/// Highest LSM level that defaults to LZ4 (flush output L0 and L1, storage-engine.md §6).
const LAST_LZ4_LEVEL: usize = 1;
/// The compressed form is kept only if `stored * KEEP_DEN <= raw * KEEP_NUM`, i.e. it saves at
/// least 12.5 % (storage-engine.md §6). `stored` includes the varint raw-length prefix.
const KEEP_NUM: u64 = 7;
/// Denominator of the 87.5 % keep threshold, see [`KEEP_NUM`].
const KEEP_DEN: u64 = 8;
/// Upper bound on LZ4 block-format expansion (raw bytes per payload byte): a match length is
/// extended by 0xFF bytes worth 255 raw bytes each, so no LZ4 payload decodes to more than
/// 255x its size (the LZ4 format's ~255:1 maximum ratio).
const LZ4_MAX_RATIO: u64 = 255;
/// Upper bound on Zstd expansion when the frame omits its content size: the densest Zstd block
/// is an RLE block, 3-byte header + 1 byte for at most 128 KiB (RFC 8878 §3.1.1.2), i.e.
/// 128 Ki / 4 = 32 768 raw bytes per payload byte. Our writer always records the content size,
/// so this only applies to foreign or damaged frames.
const ZSTD_MAX_RATIO: u64 = 32_768;

/// Which codec the writer tries for each data block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionPolicy {
    /// Store blocks raw.
    None,
    /// LZ4 block format (`lz4_flex`): the memtable-flush default.
    #[default]
    Lz4,
    /// Zstd at `level`; zstd clamps out-of-range levels, configuration validates 1..=19.
    Zstd {
        /// Compression level.
        level: i32,
    },
}

impl CompressionPolicy {
    /// Default policy for an output file at LSM `level` (storage-engine.md §6): LZ4 for L0/L1,
    /// Zstd 3 for L2+, `bottommost_zstd_level` when the file goes to the bottommost level.
    /// Called by flush and compaction when choosing writer options.
    #[must_use]
    pub fn for_level(level: usize, bottommost: bool, bottommost_zstd_level: i32) -> Self {
        if bottommost && level > LAST_LZ4_LEVEL {
            Self::Zstd {
                level: bottommost_zstd_level,
            }
        } else if level > LAST_LZ4_LEVEL {
            Self::Zstd {
                level: DEFAULT_ZSTD_LEVEL,
            }
        } else {
            Self::Lz4
        }
    }
}

/// Appends the stored form of `raw` to `out` and returns the codec recorded in the trailer.
/// Falls back to storing raw when the policy is `None`, the codec fails, or the saving is below
/// the 12.5 % threshold; compression is an optimisation and never fails a write.
pub(crate) fn compress_into(
    out: &mut Vec<u8>,
    raw: &[u8],
    policy: CompressionPolicy,
) -> Compression {
    let start = out.len();
    if policy != CompressionPolicy::None {
        put_varint(out, raw.len() as u64);
        let payload = out.len();
        let (codec, written) = match policy {
            CompressionPolicy::Lz4 => {
                out.resize(
                    payload + lz4_flex::block::get_maximum_output_size(raw.len()),
                    0,
                );
                (
                    Compression::Lz4,
                    lz4_flex::block::compress_into(raw, &mut out[payload..]).ok(),
                )
            }
            CompressionPolicy::Zstd { level } => {
                out.resize(payload + zstd::zstd_safe::compress_bound(raw.len()), 0);
                // shortcut: a fresh zstd context per block costs an allocation; keep one per
                // writer if storage benchmarks (BM-STO-*) show it.
                (
                    Compression::Zstd,
                    zstd::bulk::compress_to_buffer(raw, &mut out[payload..], level).ok(),
                )
            }
            CompressionPolicy::None => (Compression::None, None),
        };
        if let Some(n) = written {
            out.truncate(payload + n);
            // u64 products cannot overflow: both sides are below 2^40.
            if (out.len() - start) as u64 * KEEP_DEN <= raw.len() as u64 * KEEP_NUM {
                return codec;
            }
        }
        out.truncate(start);
    }
    out.extend_from_slice(raw);
    Compression::None
}

/// Decompresses a verified stored block. Any inconsistency is corruption.
pub(crate) fn decompress(codec: Compression, stored: &[u8]) -> Result<Vec<u8>> {
    let corrupt = |what: &str| StorageError::corruption(format!("{codec:?} block: {what}"));
    let (raw_len, prefix) = get_varint(stored).ok_or_else(|| corrupt("missing raw length"))?;
    let payload = &stored[prefix..];
    // Bounds before allocating: a lying length must not make a small payload allocate up to
    // MAX_BLOCK_LEN (see the module docs).
    if raw_len > MAX_BLOCK_LEN {
        return Err(corrupt(&format!(
            "raw length {raw_len} exceeds the block size limit"
        )));
    }
    let max_ratio = match codec {
        Compression::Lz4 => LZ4_MAX_RATIO,
        Compression::Zstd => {
            match zstd::zstd_safe::get_frame_content_size(payload) {
                Ok(Some(size)) if size != raw_len => {
                    return Err(corrupt(&format!(
                        "raw length {raw_len} differs from the Zstd frame content size {size}"
                    )));
                }
                Ok(_) => {}
                Err(_) => return Err(corrupt("malformed Zstd frame header")),
            }
            ZSTD_MAX_RATIO
        }
        Compression::None => return Err(corrupt("not a compressed block")),
    };
    // payload.len() <= MAX_BLOCK_LEN, so the product fits in u64.
    if raw_len > payload.len() as u64 * max_ratio {
        return Err(corrupt(&format!(
            "raw length {raw_len} exceeds {max_ratio}x the {}-byte payload",
            payload.len()
        )));
    }
    // Lossless: bounded by MAX_BLOCK_LEN above.
    #[allow(clippy::cast_possible_truncation)]
    let raw_len = raw_len as usize;
    let mut raw = vec![0u8; raw_len];
    let n = match codec {
        Compression::Lz4 => lz4_flex::block::decompress_into(payload, &mut raw)
            .map_err(|e| corrupt(&e.to_string()))?,
        Compression::Zstd => zstd::bulk::decompress_to_buffer(payload, &mut raw)
            .map_err(|e| corrupt(&e.to_string()))?,
        Compression::None => return Err(corrupt("not a compressed block")),
    };
    if n != raw_len {
        return Err(corrupt("decompressed length differs from the recorded one"));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const POLICIES: [CompressionPolicy; 3] = [
        CompressionPolicy::None,
        CompressionPolicy::Lz4,
        CompressionPolicy::Zstd {
            level: DEFAULT_ZSTD_LEVEL,
        },
    ];

    fn round_trip(raw: &[u8], policy: CompressionPolicy) -> (Compression, usize) {
        let mut out = vec![0xAA]; // pre-existing bytes must be preserved
        let codec = compress_into(&mut out, raw, policy);
        let stored = &out[1..];
        let back = if codec == Compression::None {
            stored.to_vec()
        } else {
            decompress(codec, stored).unwrap()
        };
        assert_eq!(back, raw);
        assert_eq!(out[0], 0xAA);
        (codec, stored.len())
    }

    proptest! {
        /// TC-CMP-001: every codec round-trips arbitrary and repetitive blocks.
        #[test]
        fn tc_cmp_001_round_trip_per_codec(
            raw in prop::collection::vec(any::<u8>(), 0..4096),
            repeat in 1usize..8,
        ) {
            let repetitive: Vec<u8> = raw.iter().copied().cycle().take(raw.len() * repeat).collect();
            for policy in POLICIES {
                round_trip(&raw, policy);
                round_trip(&repetitive, policy);
            }
        }
    }

    #[test]
    fn tc_cmp_001_compressible_block_uses_the_codec() {
        let raw: Vec<u8> = b"rustegon block ".repeat(1000);
        for (policy, codec) in [
            (CompressionPolicy::Lz4, Compression::Lz4),
            (CompressionPolicy::Zstd { level: 6 }, Compression::Zstd),
        ] {
            let (got, stored) = round_trip(&raw, policy);
            assert_eq!(got, codec);
            assert!(stored < raw.len() / 10, "{policy:?}: {stored} bytes");
        }
    }

    /// TC-CMP-002: incompressible data falls back to raw storage.
    #[test]
    fn tc_cmp_002_incompressible_block_stored_raw() {
        // xorshift noise: no codec can shrink it by 12.5 %.
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let raw: Vec<u8> = (0..16 << 10)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect();
        for policy in POLICIES {
            assert_eq!(round_trip(&raw, policy), (Compression::None, raw.len()));
        }
    }

    /// TC-CMP-003: corrupt compressed payloads are reported as corruption, not panics or OOM.
    #[test]
    fn tc_cmp_003_corrupt_payload_is_corruption() {
        let raw: Vec<u8> = b"abcdefgh".repeat(512);
        for policy in &POLICIES[1..] {
            let mut stored = Vec::new();
            let codec = compress_into(&mut stored, &raw, *policy);
            assert_ne!(codec, Compression::None);
            let prefix = varint_len(raw.len() as u64);
            // Lying raw length: huge, larger than real, smaller than real.
            for lie in [u64::MAX, MAX_BLOCK_LEN + 1, raw.len() as u64 + 1, 10] {
                let mut bad = Vec::new();
                put_varint(&mut bad, lie);
                bad.extend_from_slice(&stored[prefix..]);
                assert!(
                    decompress(codec, &bad).unwrap_err().is_corruption(),
                    "lie {lie}"
                );
            }
            // Truncated and garbled payloads.
            assert!(decompress(codec, &stored[..stored.len() / 2]).is_err());
            assert!(decompress(codec, &[]).is_err());
            let mut garbled = stored.clone();
            for b in &mut garbled[prefix..] {
                *b = b.wrapping_mul(31).wrapping_add(7);
            }
            assert!(decompress(codec, &garbled).unwrap_err().is_corruption());
        }
    }

    fn varint_len(v: u64) -> usize {
        let mut buf = Vec::new();
        put_varint(&mut buf, v);
        buf.len()
    }

    /// TC-CMP-003: a small payload claiming a large (but in-bound) raw length is rejected before
    /// the allocation, by the codec expansion bound or the Zstd frame content size.
    #[test]
    fn tc_cmp_003_lying_length_rejected_before_allocating() {
        let raw = vec![7u8; 1000];
        for policy in &POLICIES[1..] {
            let mut stored = Vec::new();
            let codec = compress_into(&mut stored, &raw, *policy);
            assert_ne!(codec, Compression::None);
            let payload = &stored[varint_len(raw.len() as u64)..];
            // Within MAX_BLOCK_LEN, but far beyond any real expansion of this tiny payload.
            let mut bad = Vec::new();
            put_varint(&mut bad, MAX_BLOCK_LEN);
            bad.extend_from_slice(payload);
            let err = decompress(codec, &bad).unwrap_err();
            assert!(err.is_corruption());
            let msg = err.to_string();
            assert!(
                msg.contains("payload") || msg.contains("content size"),
                "{policy:?}: {msg}"
            );
        }
        // Zstd: a lie that passes the ratio bound is still caught by the frame header.
        let mut stored = Vec::new();
        let codec = compress_into(&mut stored, &raw, POLICIES[2]);
        let mut bad = Vec::new();
        put_varint(&mut bad, raw.len() as u64 + 1);
        bad.extend_from_slice(&stored[varint_len(raw.len() as u64)..]);
        let msg = decompress(codec, &bad).unwrap_err().to_string();
        assert!(msg.contains("content size"), "{msg}");
    }

    /// The expansion bounds never reject legitimate output: maximally compressible blocks up to
    /// the 16 MiB document limit decode under both codecs.
    #[test]
    fn expansion_bounds_admit_real_blocks() {
        for len in [0usize, 1, 13, 4096, 1 << 20, 16 << 20] {
            let raw = vec![0u8; len];
            for policy in &POLICIES[1..] {
                let mut stored = Vec::new();
                let codec = compress_into(&mut stored, &raw, *policy);
                let back = if codec == Compression::None {
                    stored
                } else {
                    decompress(codec, &stored).unwrap()
                };
                assert_eq!(back.len(), len, "{policy:?}");
            }
        }
    }

    #[test]
    fn per_level_defaults_follow_the_spec() {
        let bottom = DEFAULT_BOTTOMMOST_ZSTD_LEVEL;
        assert_eq!(
            CompressionPolicy::for_level(0, false, bottom),
            CompressionPolicy::Lz4
        );
        assert_eq!(
            CompressionPolicy::for_level(1, true, bottom),
            CompressionPolicy::Lz4
        );
        assert_eq!(
            CompressionPolicy::for_level(2, false, bottom),
            CompressionPolicy::Zstd { level: 3 }
        );
        assert_eq!(
            CompressionPolicy::for_level(6, true, bottom),
            CompressionPolicy::Zstd { level: 6 }
        );
    }
}
