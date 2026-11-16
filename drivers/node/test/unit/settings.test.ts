// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkConnectionStringCase, connectionStringCases } from '../support/conformance/checks.ts';
import { InvalidArgumentError, InvalidSettingsError, RustegonClient, parseConnectionString, resolveSettings } from '../../src/index.ts';
import { inspect } from 'node:util';

const FILE = 'connstring.yaml';
const settings = (uri: string) => resolveSettings(parseConnectionString(uri));

void test('TC-DRV-NODE-008 conformance connection strings (connstring.yaml)', async (t) => {
  for (const c of connectionStringCases(FILE)) {
    await t.test(c, () => checkConnectionStringCase(FILE, c));
  }
});

void test('TC-DRV-NODE-008 ADR-034: TLS is off by default', () => {
  assert.equal(settings('rustegon://db1').tls, false);
  assert.equal(settings('rustegon://u:p@db1/shop').tls, false);
  assert.equal(resolveSettings({}).tls, false);
  assert.equal(settings('rustegon://db1/?apiKey=rgn_a_b').tls, false);
});

void test('TC-DRV-NODE-008 ADR-034: a tls* option or X.509 turns TLS on', () => {
  assert.equal(settings('rustegon://db1/?tlsCaFile=ca.crt').tls, true);
  assert.equal(settings('rustegon://db1/?tlsServerName=node1').tls, true);
  assert.equal(settings('rustegon://db1/?tlsCertificateFile=c.crt&tlsKeyFile=c.key').tls, true);
  assert.equal(settings('rustegon://db1/?authMechanism=X509').tls, true);
  assert.equal(resolveSettings({ tlsCaFile: 'ca.crt' }).tls, true);
  assert.equal(resolveSettings({ authMechanism: 'X509' }).tls, true);
  assert.equal(settings('rustegon://db1/?tls=true').tls, true);
  assert.equal(settings('rustegon://db1/?tls=TRUE&tlsCaFile=ca.crt').tls, true);
});

void test('TC-DRV-NODE-008 ADR-034: explicit tls=false with a tls* option or X.509 is an error', () => {
  for (const uri of [
    'rustegon://db1/?tls=false&tlsCaFile=ca.crt',
    'rustegon://db1/?tls=false&tlsServerName=n',
    'rustegon://db1/?tlsCertificateFile=c.crt&tlsKeyFile=c.key&tls=false',
    'rustegon://db1/?tls=false&authMechanism=X509',
  ]) {
    assert.throws(() => settings(uri), InvalidSettingsError, uri);
  }
  assert.throws(() => resolveSettings({ tls: false, tlsCaFile: 'ca.crt' }), InvalidSettingsError);
  // The options object overrides the string: tls=false from code meets the string's CA file.
  assert.throws(() => resolveSettings(parseConnectionString('rustegon://db1/?tlsCaFile=ca.crt'), { tls: false }), InvalidSettingsError);
});

void test('TC-DRV-NODE-008 options override the connection string; the password stays out of the string', () => {
  const s = resolveSettings(parseConnectionString('rustegon://app@db1:7701/shop?retryReads=false'), { password: 's3cret', maxRetries: 3 });
  assert.equal(s.user, 'app');
  assert.equal(s.password, 's3cret');
  assert.equal(s.authMechanism, 'SCRAM-SHA-256');
  assert.equal(s.retryReads, false);
  assert.equal(s.maxRetries, 3);
  assert.deepEqual(s.hosts, [{ host: 'db1', port: 7701 }]);
});

void test('TC-DRV-NODE-008 invalid option values from code are argument errors', () => {
  assert.throws(() => resolveSettings({ maxRetries: 11 }), InvalidArgumentError);
  assert.throws(() => resolveSettings({ connectionsPerEndpoint: 0 }), InvalidArgumentError);
  assert.throws(() => resolveSettings({ hosts: ['::1'] }), InvalidArgumentError);
  assert.throws(() => resolveSettings({ readConsistency: 'bounded_staleness' }), InvalidArgumentError);
  assert.throws(() => resolveSettings({ tlsCertificateFile: 'c.crt' }), InvalidArgumentError);
});

void test('TC-DRV-NODE-008 a user without password is refused by the client, secrets are never printed', () => {
  assert.throws(() => new RustegonClient('rustegon://app@db1/shop'), InvalidArgumentError);
  const client = new RustegonClient('rustegon://app:Sup3rSecret@db1/shop');
  try {
    assert.doesNotMatch(inspect(client), /Sup3rSecret/);
    assert.doesNotMatch(JSON.stringify(client), /Sup3rSecret/);
  } finally {
    void client.close();
  }
  try {
    settings('rustegon://u:Sup3r%zzSecret@db1');
    assert.fail('expected an error');
  } catch (e) {
    assert.ok(e instanceof InvalidSettingsError);
    assert.doesNotMatch(e.message, /Sup3r/);
  }
});
