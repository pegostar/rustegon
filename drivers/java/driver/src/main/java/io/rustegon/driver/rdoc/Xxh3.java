// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.rdoc;

/**
 * XXH3-64 with seed 0 and the default secret, used for the RDoc field-name hash
 * (data-model.md §4: {@code name_hash16} = low 16 bits of {@code xxh3_64(name)}).
 *
 * <p>Hand port of the reference algorithm (xxHash 0.8, as implemented by the {@code twox-hash}
 * crate the server uses) instead of a dependency: the JDK has no XXH3, and the usual Java
 * library ({@code zero-allocation-hashing}) relies on {@code sun.misc.Unsafe}, which JDK 25 warns
 * about at run time. The port is verified against that library for every length 0..2048 and
 * against the server's RDoc fixtures (TC-DRV-JAVA-001). Field names are at most 1024 bytes, but
 * every length is supported.
 */
final class Xxh3 {
    private static final long PRIME32_1 = 0x9E3779B1L;
    private static final long PRIME32_2 = 0x85EBCA77L;
    private static final long PRIME32_3 = 0xC2B2AE3DL;
    private static final long PRIME64_1 = 0x9E3779B185EBCA87L;
    private static final long PRIME64_2 = 0xC2B2AE3D27D4EB4FL;
    private static final long PRIME64_3 = 0x165667B19E3779F9L;
    private static final long PRIME64_4 = 0x85EBCA77C2B2AE63L;
    private static final long PRIME64_5 = 0x27D4EB2F165667C5L;
    private static final long PRIME_MX1 = 0x165667919E3779F9L;
    private static final long PRIME_MX2 = 0x9FB21C651E98DF25L;

    /** Inputs up to this length take the short paths. */
    private static final int CUTOFF = 240;
    /** Stripe length of the long path. */
    private static final int STRIPE = 64;
    /** Stripes per block: (secret length - 64) / 8. */
    private static final int STRIPES_PER_BLOCK = (192 - STRIPE) / 8;
    private static final int BLOCK = STRIPE * STRIPES_PER_BLOCK;

    /** The 192-byte default secret of XXH3 (xxhash.h {@code XXH3_kSecret}). */
    private static final byte[] SECRET = bytes(
            0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21,
            0xad, 0x1c, 0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4,
            0xb7, 0xb3, 0x67, 0x1f, 0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a,
            0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21, 0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e,
            0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c, 0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3,
            0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3, 0x71, 0x64, 0x48, 0x97,
            0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8, 0xa8, 0xfa,
            0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
            0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78,
            0x73, 0x64, 0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff,
            0xfa, 0x13, 0x63, 0xeb, 0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16,
            0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e, 0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc,
            0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce, 0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16,
            0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e);

    private Xxh3() {}

    private static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }

    /** RDoc {@code name_hash16}: the low 16 bits of XXH3-64 of the UTF-8 name. */
    static int nameHash16(byte[] name) {
        return (int) (hash64(name, 0, name.length) & 0xFFFF);
    }

    /** XXH3-64 (seed 0) of {@code input[off, off + len)}. */
    static long hash64(byte[] input, int off, int len) {
        if (len > CUTOFF) {
            return hashLong(input, off, len);
        }
        if (len > 128) {
            return hash129To240(input, off, len);
        }
        if (len > 16) {
            return hash17To128(input, off, len);
        }
        if (len > 8) {
            return hash9To16(input, off, len);
        }
        if (len >= 4) {
            return hash4To8(input, off, len);
        }
        if (len > 0) {
            return hash1To3(input, off, len);
        }
        return avalancheXxh64(u64(SECRET, 56) ^ u64(SECRET, 64));
    }

    private static long u64(byte[] b, int at) {
        return (b[at] & 0xFFL)
                | (b[at + 1] & 0xFFL) << 8
                | (b[at + 2] & 0xFFL) << 16
                | (b[at + 3] & 0xFFL) << 24
                | (b[at + 4] & 0xFFL) << 32
                | (b[at + 5] & 0xFFL) << 40
                | (b[at + 6] & 0xFFL) << 48
                | (b[at + 7] & 0xFFL) << 56;
    }

    private static long u32(byte[] b, int at) {
        return (b[at] & 0xFFL)
                | (b[at + 1] & 0xFFL) << 8
                | (b[at + 2] & 0xFFL) << 16
                | (b[at + 3] & 0xFFL) << 24;
    }

    private static long avalanche(long x) {
        x ^= x >>> 37;
        x *= PRIME_MX1;
        x ^= x >>> 32;
        return x;
    }

    private static long avalancheXxh64(long x) {
        x ^= x >>> 33;
        x *= PRIME64_2;
        x ^= x >>> 29;
        x *= PRIME64_3;
        x ^= x >>> 32;
        return x;
    }

    /** Low half XOR high half of the 128-bit product of two unsigned 64-bit values. */
    private static long foldedMultiply(long a, long b) {
        return (a * b) ^ Math.unsignedMultiplyHigh(a, b);
    }

    private static long hash1To3(byte[] in, int off, int len) {
        long combined = (in[off + len - 1] & 0xFFL)
                | ((long) len << 8)
                | (in[off] & 0xFFL) << 16
                | (in[off + (len >> 1)] & 0xFFL) << 24;
        long secret = u32(SECRET, 0) ^ u32(SECRET, 4);
        return avalancheXxh64(secret ^ combined);
    }

    private static long hash4To8(byte[] in, int off, int len) {
        long first = u32(in, off);
        long last = u32(in, off + len - 4);
        long combined = last | (first << 32);
        long value = (u64(SECRET, 8) ^ u64(SECRET, 16)) ^ combined;
        value ^= Long.rotateLeft(value, 49) ^ Long.rotateLeft(value, 24);
        value *= PRIME_MX2;
        value ^= (value >>> 35) + len;
        value *= PRIME_MX2;
        value ^= value >>> 28;
        return value;
    }

    private static long hash9To16(byte[] in, int off, int len) {
        long low = (u64(SECRET, 24) ^ u64(SECRET, 32)) ^ u64(in, off);
        long high = (u64(SECRET, 40) ^ u64(SECRET, 48)) ^ u64(in, off + len - 8);
        long value = len + Long.reverseBytes(low) + high + foldedMultiply(low, high);
        return avalanche(value);
    }

    /** {@code mix_step}: 16 input bytes against 16 secret bytes. */
    private static long mix16(byte[] in, int at, int secretAt) {
        return foldedMultiply(u64(in, at) ^ u64(SECRET, secretAt),
                u64(in, at + 8) ^ u64(SECRET, secretAt + 8));
    }

    private static long hash17To128(byte[] in, int off, int len) {
        long acc = len * PRIME64_1;
        int pairs = (len - 1) / 32;
        // Pairs of 16-byte chunks from the front and the back, highest pair first; pair i
        // uses secret bytes [32i, 32i + 32).
        for (int i = pairs; i >= 0; i--) {
            acc += mix16(in, off + 16 * i, 32 * i);
            acc += mix16(in, off + len - 16 * (i + 1), 32 * i + 16);
        }
        return avalanche(acc);
    }

    private static long hash129To240(byte[] in, int off, int len) {
        long acc = len * PRIME64_1;
        for (int i = 0; i < 8; i++) {
            acc += mix16(in, off + 16 * i, 16 * i);
        }
        acc = avalanche(acc);
        int tailChunks = (len - 128) / 16;
        for (int i = 0; i < tailChunks; i++) {
            acc += mix16(in, off + 128 + 16 * i, 3 + 16 * i);
        }
        acc += mix16(in, off + len - 16, 119);
        return avalanche(acc);
    }

    private static void accumulate(long[] acc, byte[] in, int at, int secretAt) {
        for (int i = 0; i < 8; i++) {
            long data = u64(in, at + 8 * i);
            long value = data ^ u64(SECRET, secretAt + 8 * i);
            acc[i ^ 1] += data;
            acc[i] += (value & 0xFFFFFFFFL) * (value >>> 32);
        }
    }

    private static void scramble(long[] acc) {
        int secretAt = SECRET.length - STRIPE;
        for (int i = 0; i < 8; i++) {
            long a = acc[i];
            a ^= a >>> 47;
            a ^= u64(SECRET, secretAt + 8 * i);
            acc[i] = a * PRIME32_1;
        }
    }

    private static long hashLong(byte[] in, int off, int len) {
        long[] acc = {
            PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1
        };
        // Full blocks except the last block of the input (a remainder, or the last full block
        // when the length is a multiple of the block size), which the final round handles.
        int fullBlocks = len / BLOCK;
        int remainder = len % BLOCK;
        int roundBlocks = remainder == 0 ? fullBlocks - 1 : fullBlocks;
        for (int b = 0; b < roundBlocks; b++) {
            int blockAt = off + b * BLOCK;
            for (int s = 0; s < STRIPES_PER_BLOCK; s++) {
                accumulate(acc, in, blockAt + s * STRIPE, 8 * s);
            }
            scramble(acc);
        }
        int lastBlockAt = off + roundBlocks * BLOCK;
        int lastBlockLen = len - roundBlocks * BLOCK;
        // Stripes of the last block, excluding the last stripe (full or partial).
        int stripes = (lastBlockLen - 1) / STRIPE;
        for (int s = 0; s < stripes; s++) {
            accumulate(acc, in, lastBlockAt + s * STRIPE, 8 * s);
        }
        accumulate(acc, in, off + len - STRIPE, SECRET.length - 71);
        long result = len * PRIME64_1;
        for (int i = 0; i < 4; i++) {
            int secretAt = 11 + 16 * i;
            result += foldedMultiply(acc[2 * i] ^ u64(SECRET, secretAt),
                    acc[2 * i + 1] ^ u64(SECRET, secretAt + 8));
        }
        return avalanche(result);
    }
}
