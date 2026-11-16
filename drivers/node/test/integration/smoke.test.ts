// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { sharedServer, skipReason } from '../support/server.ts';
import { Filter, Update, Sort, RustegonClient, AuthenticationError } from '../../src/index.ts';

const server = await sharedServer();
after(async () => server?.stop());

void test('TC-DRV-NODE-009 SCRAM login, ping, server info, wrong password', { skip: server === undefined ? skipReason() : false }, async () => {
  const s = server!;
  await using client = await s.admin();
  await client.ping();
  const info = await client.getServerInfo();
  assert.match(info.serverVersion, /^\d+\.\d+\.\d+/);
  assert.equal(info.protocolVersion.split('.')[0], '1');
  await assert.rejects(RustegonClient.connect(s.options({ user: 'admin', password: 'wrong-password' })), (e: unknown) => e instanceof AuthenticationError && e.code === 4001);
});

void test('TC-DRV-NODE-012 CRUD, find with sort/limit, by-id and statement writes', { skip: server === undefined ? skipReason() : false }, async () => {
  const s = server!;
  await using client = await s.admin();
  const dbName = `node_smoke_${Date.now()}`;
  await client.createDatabase(dbName);
  try {
    const items = client.db(dbName).collection('items');
    await items.insertMany([{ _id: 1n, n: 1n, s: 'a' }, { _id: 2n, n: 2n, s: 'b' }, { _id: 3n, n: 3n, s: 'a' }]);
    assert.deepEqual((await items.findById(2n))?.n, 2n);
    const found = await items.find(Filter.eq('s', 'a')).sort(Sort.descending('n')).limit(5).toArray();
    assert.deepEqual(found.map((d) => d._id), [3n, 1n]);
    assert.deepEqual(await items.updateOne(Filter.id(1n), Update.inc('n', 10n)), { matchedCount: 1, modifiedCount: 1 });
    assert.deepEqual(await items.updateMany(Filter.eq('s', 'a'), Update.set('t', true)), { matchedCount: 2, modifiedCount: 2 });
    assert.deepEqual(await items.deleteMany(Filter.empty), { deletedCount: 3 });
    const rows = await client.db(dbName).query('FROM items WHERE n > $min', { min: 0n }).toArray();
    assert.equal(rows.length, 0);
  } finally {
    await client.dropDatabase(dbName, { ifExists: true });
  }
});
