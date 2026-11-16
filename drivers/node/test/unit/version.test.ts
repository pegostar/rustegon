// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { nodeDriverDir } from '../support/files.ts';
import { DRIVER_VERSION } from '../../src/index.ts';

// The login reports DRIVER_VERSION: it must not drift from the package that ships it.
void test('TC-DRV-NODE-027 DRIVER_VERSION equals the package.json version', () => {
  const pkg = JSON.parse(readFileSync(path.join(nodeDriverDir, 'package.json'), 'utf8')) as { version: string };
  assert.equal(DRIVER_VERSION, pkg.version);
});
