// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test } from 'node:test';
import { retryScenarioNames, runRetryScenario } from '../support/conformance/checks.ts';

const FILE = 'retry.yaml';

void test('TC-DRV-NODE-016 retry scenarios of retry.yaml on the in-process fake server (PD-073)', async (t) => {
  for (const name of retryScenarioNames(FILE)) {
    await t.test(name, () => runRetryScenario(FILE, name));
  }
});
