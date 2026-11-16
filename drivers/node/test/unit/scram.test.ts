// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { saslPrep, SaslPrepError } from '../../src/auth/saslprep.ts';
import { ScramSha256Client } from '../../src/auth/scram.ts';
import { AuthenticationError } from '../../src/errors/errors.ts';
import { scramCases } from '../support/scram-checks.ts';

// RFC 7677 §3 test vector.
const CLIENT_NONCE = 'rOprNGfwEbeRWgbNEkqO';
const SERVER_FIRST = 'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096';
const CLIENT_FINAL = 'c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=';
const SERVER_FINAL = 'v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=';

const isAuthFailure = (e: unknown): boolean => e instanceof AuthenticationError && e.code === 4001;

void describe('TC-DRV-NODE-007 SCRAM-SHA-256 and SASLprep', () => {
  void test('TC-DRV-NODE-007 RFC 7677 test vector', async () => {
    const c = new ScramSha256Client('user', 'pencil', { clientNonce: CLIENT_NONCE });
    assert.equal(c.clientFirst, `n,,n=user,r=${CLIENT_NONCE}`);
    assert.equal(await c.processServerFirst(SERVER_FIRST), CLIENT_FINAL);
    c.verifyServerFinal(SERVER_FINAL);
  });

  void test('TC-DRV-NODE-007 wrong server signature fails mutual authentication', async () => {
    const c = new ScramSha256Client('user', 'pencil', { clientNonce: CLIENT_NONCE });
    await c.processServerFirst(SERVER_FIRST);
    assert.throws(() => c.verifyServerFinal('v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='), isAuthFailure);
    assert.throws(() => c.verifyServerFinal('e=invalid-proof'), isAuthFailure);
  });

  for (const [why, serverFirst] of [
    ['nonce does not extend ours', 'r=other%hvYDpWUa2RaTCAfuxFIlj,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096'],
    ['no server part', 'r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096'],
    ['downgrade', 'r=rOprNGfwEbeRWgbNEkqO%x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4095'],
    ['client DoS', 'r=rOprNGfwEbeRWgbNEkqO%x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=10000001'],
    ['empty salt', 'r=rOprNGfwEbeRWgbNEkqO%x,s=,i=4096'],
    ['invalid base64 salt', 'r=rOprNGfwEbeRWgbNEkqO%x,s=W22ZaJ0S*Y7soEsUEjb6gQ==,i=4096'],
    ['extension', 'r=rOprNGfwEbeRWgbNEkqO%x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=ext'],
    ['attribute order', 's=W22ZaJ0SNY7soEsUEjb6gQ==,r=rOprNGfwEbeRWgbNEkqO%x,i=4096'],
  ] as const) {
    void test(`TC-DRV-NODE-007 malformed server-first is rejected: ${why}`, async () => {
      const c = new ScramSha256Client('user', 'pencil', { clientNonce: CLIENT_NONCE });
      await assert.rejects(c.processServerFirst(serverFirst), isAuthFailure);
    });
  }

  void test('TC-DRV-NODE-007 user name is SASL-escaped and the nonce is random', () => {
    assert.equal(new ScramSha256Client('a=b,c', 'p', { clientNonce: 'xyz' }).clientFirst, 'n,,n=a=3Db=2Cc,r=xyz');
    const n1 = new ScramSha256Client('u', 'p').clientFirst;
    const n2 = new ScramSha256Client('u', 'p').clientFirst;
    assert.notEqual(n1, n2);
    assert.equal(n1.length, 'n,,n=u,r='.length + 24);
    assert.ok(!String(new ScramSha256Client('u', 'secret')).includes('secret'));
  });

  for (const [input, expected] of [
    ['I­X', 'IX'], // RFC 4013 §3: soft hyphen mapped to nothing
    ['user', 'user'],
    ['USER', 'USER'], // no case folding
    ['ª', 'a'], // NFKC
    ['Ⅸ', 'IX'], // NFKC
    ['a b', 'a b'], // non-ASCII space → SPACE
    ['a​b', 'a b'], // U+200B is in C.1.2 and mapped to SPACE first (as the Rust crate)
    ['a️b', 'ab'], // variation selector mapped to nothing
    ['אב', 'אב'], // RandALCat only
    ['café', 'café'],
    ['café', 'café'], // NFKC composes
    ['pass word 1', 'pass word 1'],
  ] as const) {
    void test(`TC-DRV-NODE-007 SASLprep maps and normalizes ${JSON.stringify(input)}`, () => {
      assert.equal(saslPrep(input), expected);
    });
  }

  for (const input of [
    '\u0007', // C.2.1
    'ا1', // RandALCat not last
    'אa', // RandALCat with LCat
    'a\u0080', // C.2.2
    '', // C.3 private use
    '﷐', // C.4
    '\ud800', // C.5 lone surrogate
    '�', // C.6
    '⿰', // C.7
    '‎', // C.8
    '\u{e0001}', // C.9
    'ȡ', // A.1 unassigned in Unicode 3.2
    'x \u0007',
  ]) {
    void test(`TC-DRV-NODE-007 SASLprep rejects prohibited output ${JSON.stringify(input)}`, () => {
      assert.throws(() => saslPrep(input), SaslPrepError);
    });
  }

  void test('TC-DRV-NODE-007 invalid SASLprep password fails before any proof, without the password in the message', async () => {
    const c = new ScramSha256Client('user', 'bad\u0007', { clientNonce: CLIENT_NONCE });
    await assert.rejects(c.processServerFirst(SERVER_FIRST), (e: unknown) => isAuthFailure(e) && !(e as Error).message.includes('bad'));
  });
});

void describe('TC-DRV-NODE-018 SCRAM conformance vectors (scram/vectors.yaml)', () => {
  for (const c of scramCases('scram/vectors.yaml')) {
    void test(`TC-DRV-NODE-018 ${c.id}`, () => c.check());
  }
});
