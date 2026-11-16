// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { TestServer } from '../support/server.ts';
import { RustegonClient, UnavailableError } from '../../src/index.ts';

const found = TestServer.findBinaries();
const server = found.dir === undefined ? undefined : await TestServer.start(found.dir, { tls: false });
after(async () => server?.stop());

// ADR-034: a bare `rustegon://user:pwd@host:port/db` string, with no TLS option, must reach a
// plain-text node — the default every DEC-014 user starts from.
void test('TC-DRV-NODE-010 ADR-034: a bare connection string logs in to a plain-text node', { skip: server === undefined ? `no server binaries: ${found.reason}` : false }, async () => {
  const s = server!;
  const uri = `rustegon://${TestServer.adminUser}:${s.adminPassword}@${s.grpcEndpoint}/admin`;
  await using client = await RustegonClient.connect(uri, { connectTimeoutMs: 10_000 });
  await client.ping();
  assert.match((await client.getServerInfo()).serverVersion, /^\d+\.\d+\.\d+/);
  // A TLS client against the plain-text port fails as a transport error, not a hang.
  await assert.rejects(
    RustegonClient.connect(`${uri}?tls=true`, { connectTimeoutMs: 3_000, maxRetries: 0 }),
    UnavailableError,
  );
});
