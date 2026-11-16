// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { xxh3_64 } from '../../src/codec/xxh3.ts';

// Reference values of twox-hash 2.1 (the server's hash crate) for inputs `i % 251`, one per
// length class of XXH3-64 (0, 1–3, 4–8, 9–16, 17–128, 129–240, 241+).
const REFERENCE: [number, bigint][] = [
  [0, 0x2d06800538d394c2n],
  [1, 0xc44bdff4074eecdbn],
  [2, 0xd6645fc3051a9457n],
  [3, 0x5f4299fc161c9cbbn],
  [4, 0x60dab036a58211f2n],
  [8, 0x3a1c2d7c85af88f8n],
  [9, 0xe9612598145bb9dcn],
  [15, 0x55ecedc2b87bb042n],
  [16, 0x8355e3a6f61770dbn],
  [17, 0x9ef341a99de37328n],
  [32, 0x3523581fe96e4c05n],
  [33, 0xe68c56ba88991e58n],
  [128, 0x85c6174c7ff4c46bn],
  [129, 0xec7642b431ba3e5an],
  [240, 0x375a384d957fe865n],
  [241, 0x02e8cd95421c6d02n],
  [244, 0xbc17c91ec3cf8d7fn],
  [1024, 0xe5d78bafa45b2aa5n],
  [10240, 0xbcd63266df6e2244n],
];

void test('TC-DRV-NODE-001 xxh3_64 matches the reference values of every length class', () => {
  for (const [n, expected] of REFERENCE) {
    const input = Uint8Array.from({ length: n }, (_, i) => i % 251);
    assert.equal(xxh3_64(input).toString(16), expected.toString(16), `length ${n}`);
  }
});
