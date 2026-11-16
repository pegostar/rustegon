// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { saslPrep } from '../../src/auth/saslprep.ts';
import { ScramSha256Client } from '../../src/auth/scram.ts';
import { asList, asMap, asString, loadConformanceYaml, type YamlMap } from './files.ts';

/** One case of scram/vectors.yaml: `saslprep/<name>` or `exchange/<name>`. */
export interface ScramCase {
  readonly id: string;
  readonly check: () => Promise<void>;
}

/**
 * `checkScramVectors` (README §7, PD-074): every SASLprep input gives its output or is refused;
 * every exchange, with the client nonce forced, sends exactly `clientFirst` and `clientFinal`,
 * accepts `serverFinal` and rejects it with one character changed.
 */
export function scramCases(file: string): ScramCase[] {
  const root = asMap(loadConformanceYaml(file), file);
  const prep = asList(root['saslprep'], 'saslprep').map((v) => {
    const e = asMap(v);
    return { id: `saslprep/${asString(e['name'])}`, check: () => Promise.resolve(checkSaslPrep(e)) };
  });
  const exchanges = asList(root['exchanges'], 'exchanges').map((v) => {
    const e = asMap(v);
    return { id: `exchange/${asString(e['name'])}`, check: () => checkExchange(e) };
  });
  return [...prep, ...exchanges];
}

/** Runs every case; throws an Error naming the first failing one. */
export async function checkScramVectors(file: string): Promise<void> {
  for (const c of scramCases(file)) {
    try {
      await c.check();
    } catch (e) {
      throw new Error(`${file} ${c.id}: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
    }
  }
}

function checkSaslPrep(v: YamlMap): void {
  let prepared: string | undefined;
  try {
    prepared = saslPrep(asString(v['input']));
  } catch {
    prepared = undefined;
  }
  if (v['error'] === true) {
    if (prepared !== undefined) {
      throw new Error(`expected a refusal, got '${prepared}'`);
    }
  } else if (prepared !== asString(v['output'])) {
    throw new Error(prepared === undefined ? 'refused' : `got '${prepared}'`);
  }
}

async function checkExchange(v: YamlMap): Promise<void> {
  const make = (): ScramSha256Client =>
    new ScramSha256Client(asString(v['user']), asString(v['password']), { clientNonce: asString(v['clientNonce']) });
  const expect = (what: string, actual: string, expected: string): void => {
    if (actual !== expected) {
      throw new Error(`${what}: got '${actual}', expected '${expected}'`);
    }
  };
  const client = make();
  expect('clientFirst', client.clientFirst, asString(v['clientFirst']));
  expect('clientFinal', await client.processServerFirst(asString(v['serverFirst'])), asString(v['clientFinal']));
  const serverFinal = asString(v['serverFinal']);
  client.verifyServerFinal(serverFinal);

  // One character changed inside the signature must be rejected.
  const tampered = make();
  await tampered.processServerFirst(asString(v['serverFirst']));
  const i = 2;
  const changed = serverFinal.slice(0, i) + (serverFinal[i] === 'A' ? 'B' : 'A') + serverFinal.slice(i + 1);
  let rejected = false;
  try {
    tampered.verifyServerFinal(changed);
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error('a tampered serverFinal was accepted');
  }
}
