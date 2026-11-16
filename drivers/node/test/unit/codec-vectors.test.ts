// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { codecVectors } from '../support/codec-checks.ts';

const FILES = ['codec/values.yaml', 'codec/documents.yaml', 'codec/invalid.yaml'];

void test('TC-DRV-NODE-001 conformance codec vector files are complete', () => {
  const ids = FILES.flatMap((f) => codecVectors(f).map((v) => v.id));
  // Sections named by the README; a renamed section must not silently drop its vectors.
  for (const section of [
    'values.yaml#values/',
    'values.yaml#noncanonical/',
    'documents.yaml#documents/',
    'documents.yaml#noncanonical/',
    'invalid.yaml#documents/',
    'invalid.yaml#values/',
    'invalid.yaml#json/',
  ]) {
    assert.ok(ids.some((id) => id.startsWith(section)), section);
  }
  assert.equal(new Set(ids).size, ids.length);
});

for (const file of FILES) {
  void test(`TC-DRV-NODE-001 conformance codec vectors ${file}`, async (t) => {
    for (const v of codecVectors(file)) {
      await t.test(v.id, () => {
        v.check();
      });
    }
  });
}
