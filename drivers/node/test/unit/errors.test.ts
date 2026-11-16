// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import * as grpc from '@grpc/grpc-js';
import { nodeDriverDir } from '../support/files.ts';
import { checkErrorMappingCase, errorMappingCases } from '../support/conformance/checks.ts';
import { errorFromServiceError, errorDetailOf } from '../../src/transport/calls.ts';
import {
  AuthenticationError,
  CommitOutcomeUnknownError,
  PasswordChangeRequiredError,
  QuerySyntaxError,
  RustegonClientError,
  RustegonError,
  RustegonTimeoutError,
} from '../../src/index.ts';
import { classIdOf, clientInfo, errorFromInfo } from '../../src/errors/errors.ts';

const FILE = 'generated/errors.json';

void test('TC-DRV-NODE-006 the compiled table equals drivers/conformance/generated/errors.json', () => {
  execFileSync(process.execPath, [path.join(nodeDriverDir, 'scripts', 'generate-errors.mjs'), '--check'], { stdio: 'pipe' });
});

void test('TC-DRV-NODE-006 conformance error mapping (every code, unknown code, transport fallbacks, hierarchy)', async (t) => {
  for (const c of errorMappingCases(FILE)) {
    await t.test(c, () => checkErrorMappingCase(FILE, c));
  }
});

void test('TC-DRV-NODE-006 hierarchy details: syntax errors are client errors, password change is authentication', () => {
  assert.ok(errorFromInfo({ code: 1010, name: 'QuerySyntaxError', retryable: false }, 'x') instanceof RustegonClientError);
  assert.ok(errorFromInfo({ code: 1011, name: 'QueryTypeError', retryable: false }, 'x') instanceof QuerySyntaxError);
  const p = new PasswordChangeRequiredError(clientInfo(4002), 'x');
  assert.ok(p instanceof AuthenticationError);
  assert.equal(classIdOf(p), 'PasswordChangeRequired');
  assert.equal(classIdOf(errorFromInfo({ code: 2003, name: '', retryable: false }, 'x')), 'Timeout');
  assert.ok(errorFromInfo({ code: 5006, name: '', retryable: false }, 'x') instanceof RustegonTimeoutError);
  const unknown = errorFromInfo({ code: 9876, name: '', retryable: true }, 'x');
  assert.equal(unknown.constructor, RustegonError);
  assert.equal(unknown.code, 9876);
  assert.equal(unknown.retryable, true);
  assert.equal(unknown.name, 'RustegonError');
});

void test('TC-DRV-NODE-006 a corrupt or foreign status trailer falls back to the status code', () => {
  const md = new grpc.Metadata();
  md.set('grpc-status-details-bin', Buffer.from('not a status'));
  assert.equal(errorDetailOf(md), undefined);
  const e = errorFromServiceError(Object.assign(new Error('x'), { code: grpc.status.UNAVAILABLE, details: 'gone', metadata: md }));
  assert.equal(e.code, 3002);
  assert.equal(e.retryable, true);
});

void test('TC-DRV-NODE-006 resolve() outside a commit is refused', () => {
  const e = new CommitOutcomeUnknownError(clientInfo(2006), 'x');
  assert.throws(() => e.resolve(), /no transaction to resolve/);
});
