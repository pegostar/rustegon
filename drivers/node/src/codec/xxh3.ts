// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * XXH3-64 with seed 0 (the RDoc `name_hash16` source, data-model.md §4), a scalar port of
 * xxhash-rust 0.8 `const_xxh3.rs` (the crate the server uses through twox-hash: same output).
 * BigInt arithmetic: field names are short (≤ 1024 bytes), so speed is not a concern here.
 */

const M64 = (1n << 64n) - 1n;

const SECRET = Uint8Array.from([
  0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
  0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
  0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
  0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
  0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
  0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
  0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
  0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
  0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
  0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
  0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
  0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
]);

const P32_1 = 0x9e3779b1n;
const P32_2 = 0x85ebca77n;
const P32_3 = 0xc2b2ae3dn;
const P64_1 = 0x9e3779b185ebca87n;
const P64_2 = 0xc2b2ae3d27d4eb4fn;
const P64_3 = 0x165667b19e3779f9n;
const P64_4 = 0x85ebca77c2b2ae63n;
const P64_5 = 0x27d4eb2f165667c5n;

const STRIPE_LEN = 64;
const SECRET_CONSUME_RATE = 8;
const SECRET_MERGEACCS_START = 11;
const SECRET_LASTACC_START = 7;
const SECRET_SIZE_MIN = 136;

function u32(b: Uint8Array, at: number): bigint {
  return BigInt(((b[at] ?? 0) | ((b[at + 1] ?? 0) << 8) | ((b[at + 2] ?? 0) << 16)) + (b[at + 3] ?? 0) * 0x1000000);
}

function u64(b: Uint8Array, at: number): bigint {
  return u32(b, at) | (u32(b, at + 4) << 32n);
}

const mul = (a: bigint, b: bigint): bigint => (a * b) & M64;
const add = (a: bigint, b: bigint): bigint => (a + b) & M64;
const rotl = (v: bigint, r: bigint): bigint => ((v << r) | (v >> (64n - r))) & M64;

function swap64(v: bigint): bigint {
  let r = 0n;
  for (let i = 0n; i < 64n; i += 8n) {
    r = (r << 8n) | ((v >> i) & 0xffn);
  }
  return r;
}

function fold64(a: bigint, b: bigint): bigint {
  const p = a * b;
  return (p & M64) ^ (p >> 64n);
}

function avalanche(v: bigint): bigint {
  v ^= v >> 37n;
  v = mul(v, 0x165667919e3779f9n);
  return v ^ (v >> 32n);
}

function xxh64Avalanche(v: bigint): bigint {
  v ^= v >> 33n;
  v = mul(v, P64_2);
  v ^= v >> 29n;
  v = mul(v, P64_3);
  return v ^ (v >> 32n);
}

function strongAvalanche(v: bigint, len: bigint): bigint {
  v ^= rotl(v, 49n) ^ rotl(v, 24n);
  v = mul(v, 0x9fb21c651e98df25n);
  v ^= add(v >> 35n, len);
  v = mul(v, 0x9fb21c651e98df25n);
  return v ^ (v >> 28n);
}

function mix16(input: Uint8Array, at: number, secretAt: number): bigint {
  return fold64(u64(input, at) ^ u64(SECRET, secretAt), u64(input, at + 8) ^ u64(SECRET, secretAt + 8));
}

function len1to3(input: Uint8Array): bigint {
  const n = input.length;
  const combo =
    (BigInt(input[0] ?? 0) << 16n) |
    (BigInt(input[n >> 1] ?? 0) << 24n) |
    BigInt(input[n - 1] ?? 0) |
    (BigInt(n) << 8n);
  return xxh64Avalanche(combo ^ (u32(SECRET, 0) ^ u32(SECRET, 4)));
}

function len4to8(input: Uint8Array): bigint {
  const n = input.length;
  const flip = u64(SECRET, 8) ^ u64(SECRET, 16);
  const input64 = add(u32(input, n - 4), u32(input, 0) << 32n);
  return strongAvalanche(input64 ^ flip, BigInt(n));
}

function len9to16(input: Uint8Array): bigint {
  const n = input.length;
  const lo = u64(input, 0) ^ (u64(SECRET, 24) ^ u64(SECRET, 32));
  const hi = u64(input, n - 8) ^ (u64(SECRET, 40) ^ u64(SECRET, 48));
  return avalanche(add(add(add(BigInt(n), swap64(lo)), hi), fold64(lo, hi)));
}

function len17to128(input: Uint8Array): bigint {
  const n = input.length;
  let acc = mul(BigInt(n), P64_1);
  if (n > 32) {
    if (n > 64) {
      if (n > 96) {
        acc = add(acc, mix16(input, 48, 96));
        acc = add(acc, mix16(input, n - 64, 112));
      }
      acc = add(acc, mix16(input, 32, 64));
      acc = add(acc, mix16(input, n - 48, 80));
    }
    acc = add(acc, mix16(input, 16, 32));
    acc = add(acc, mix16(input, n - 32, 48));
  }
  acc = add(acc, mix16(input, 0, 0));
  acc = add(acc, mix16(input, n - 16, 16));
  return avalanche(acc);
}

function len129to240(input: Uint8Array): bigint {
  const n = input.length;
  let acc = mul(BigInt(n), P64_1);
  const rounds = Math.floor(n / 16);
  let i = 0;
  for (; i < 8; i++) {
    acc = add(acc, mix16(input, 16 * i, 16 * i));
  }
  acc = avalanche(acc);
  for (; i < rounds; i++) {
    acc = add(acc, mix16(input, 16 * i, 16 * (i - 8) + 3));
  }
  acc = add(acc, mix16(input, n - 16, SECRET_SIZE_MIN - 17));
  return avalanche(acc);
}

function accumulate512(acc: bigint[], input: Uint8Array, at: number, secretAt: number): void {
  for (let i = 0; i < 8; i++) {
    const data = u64(input, at + 8 * i);
    const key = data ^ u64(SECRET, secretAt + 8 * i);
    acc[i ^ 1] = add(acc[i ^ 1] ?? 0n, data);
    acc[i] = add(acc[i] ?? 0n, (key & 0xffffffffn) * (key >> 32n));
  }
}

function scramble(acc: bigint[], secretAt: number): void {
  for (let i = 0; i < 8; i++) {
    const v = (acc[i] ?? 0n) ^ ((acc[i] ?? 0n) >> 47n) ^ u64(SECRET, secretAt + 8 * i);
    acc[i] = mul(v, P32_1);
  }
}

function long(input: Uint8Array): bigint {
  const n = input.length;
  const acc = [P32_3, P64_1, P64_2, P64_3, P64_4, P32_2, P64_5, P32_1];
  const stripes = (SECRET.length - STRIPE_LEN) / SECRET_CONSUME_RATE;
  const blockLen = STRIPE_LEN * stripes;
  const blocks = Math.floor((n - 1) / blockLen);
  for (let b = 0; b < blocks; b++) {
    for (let s = 0; s < stripes; s++) {
      accumulate512(acc, input, b * blockLen + s * STRIPE_LEN, s * SECRET_CONSUME_RATE);
    }
    scramble(acc, SECRET.length - STRIPE_LEN);
  }
  const lastStripes = Math.floor((n - 1 - blockLen * blocks) / STRIPE_LEN);
  for (let s = 0; s < lastStripes; s++) {
    accumulate512(acc, input, blocks * blockLen + s * STRIPE_LEN, s * SECRET_CONSUME_RATE);
  }
  accumulate512(acc, input, n - STRIPE_LEN, SECRET.length - STRIPE_LEN - SECRET_LASTACC_START);
  let result = mul(BigInt(n), P64_1);
  for (let i = 0; i < 4; i++) {
    result = add(
      result,
      fold64((acc[2 * i] ?? 0n) ^ u64(SECRET, SECRET_MERGEACCS_START + 16 * i), (acc[2 * i + 1] ?? 0n) ^ u64(SECRET, SECRET_MERGEACCS_START + 16 * i + 8)),
    );
  }
  return avalanche(result);
}

/** XXH3-64 of `input` with seed 0. */
export function xxh3_64(input: Uint8Array): bigint {
  const n = input.length;
  if (n === 0) {
    return xxh64Avalanche(u64(SECRET, 56) ^ u64(SECRET, 64));
  }
  if (n <= 3) {
    return len1to3(input);
  }
  if (n <= 8) {
    return len4to8(input);
  }
  if (n <= 16) {
    return len9to16(input);
  }
  if (n <= 128) {
    return len17to128(input);
  }
  if (n <= 240) {
    return len129to240(input);
  }
  return long(input);
}

