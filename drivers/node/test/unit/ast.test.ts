// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test } from 'node:test';
import { astCases, checkAstCase } from '../support/conformance/checks.ts';

for (const file of ['ast/filters.json', 'ast/updates.json', 'ast/statements.json']) {
  void test(`TC-DRV-NODE-011 conformance AST vectors ${file}`, async (t) => {
    for (const c of astCases(file)) {
      await t.test(c, () => checkAstCase(file, c));
    }
  });
}
