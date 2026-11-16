// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { spawn, execFile, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { randomInt } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { repoRoot } from './files.ts';
import { RustegonClient, type ClientOptions } from '../../src/index.ts';

const execFileAsync = promisify(execFile);
const READY = 'rustegond ready ';

/**
 * A single-node `rustegond` for integration tests (PD-072): `rustegon init` into a fresh temporary
 * directory (CA, node certificate, configuration, a client certificate for `conf_x509`), then
 * `rustegond --stop-on-stdin-eof`, which prints `rustegond ready grpc=… http=…` and stops
 * gracefully when stdin closes. Binaries come from `RUSTEGON_BIN_DIR` (default
 * `<repo>/target/debug`). `tls: false` starts the node in plain text (ADR-034 default).
 */
export class TestServer {
  static readonly adminUser = 'admin';
  static readonly clientCertificateUser = 'conf_x509';

  readonly root: string;
  readonly grpcEndpoint: string;
  readonly adminPassword: string;
  readonly tls: boolean;
  private process: ChildProcess;

  private constructor(root: string, process: ChildProcess, grpc: string, password: string, tls: boolean) {
    this.root = root;
    this.process = process;
    this.grpcEndpoint = grpc;
    this.adminPassword = password;
    this.tls = tls;
  }

  get host(): string {
    return this.grpcEndpoint.slice(0, this.grpcEndpoint.lastIndexOf(':'));
  }

  get port(): string {
    return this.grpcEndpoint.slice(this.grpcEndpoint.lastIndexOf(':') + 1);
  }

  get caFile(): string {
    return path.join(this.root, 'data', 'certs', 'ca.crt');
  }

  get clientCertFile(): string {
    return path.join(this.root, 'data', 'certs', `client-${TestServer.clientCertificateUser}`, 'client.crt');
  }

  get clientKeyFile(): string {
    return path.join(this.root, 'data', 'certs', `client-${TestServer.clientCertificateUser}`, 'client.key');
  }

  /** Client options for this node (TLS on its CA when the node runs TLS). */
  options(extra: ClientOptions = {}): ClientOptions {
    return {
      hosts: [this.grpcEndpoint],
      applicationName: 'rustegon-node-tests',
      ...(this.tls ? { tls: true, tlsCaFile: this.caFile } : { tls: false }),
      ...extra,
    };
  }

  /** A connected admin client. */
  admin(extra: ClientOptions = {}): Promise<RustegonClient> {
    return RustegonClient.connect(this.options({ user: TestServer.adminUser, password: this.adminPassword, ...extra }));
  }

  /** The binary directory, or a reason why there is none. */
  static findBinaries(): { dir?: string; reason: string } {
    const dir = process.env.RUSTEGON_BIN_DIR !== undefined && process.env.RUSTEGON_BIN_DIR.length > 0 ? process.env.RUSTEGON_BIN_DIR : path.join(repoRoot, 'target', 'debug');
    for (const name of ['rustegon', 'rustegond']) {
      if (!existsSync(path.join(dir, exe(name)))) {
        return { reason: `${exe(name)} not found in ${dir} (set RUSTEGON_BIN_DIR)` };
      }
    }
    return { dir, reason: '' };
  }

  static async start(binDir: string, options: { tls?: boolean } = {}): Promise<TestServer> {
    const tls = options.tls ?? true;
    const root = mkdtempSync(path.join(os.tmpdir(), 'rustegon-node-'));
    const passwordFile = path.join(root, 'admin.pw');
    // 24 uniform base62 characters pass the password policy (as the server's own generator).
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const password = Array.from({ length: 24 }, () => alphabet[randomInt(alphabet.length)]).join('');
    writeFileSync(passwordFile, password);
    const data = path.join(root, 'data');
    await execFileAsync(
      path.join(binDir, exe('rustegon')),
      // ADR-034: `init` writes a plain-text node unless `--tls` asks for the CA, node and client certificates.
      ['init', '--data-dir', data, '--grpc-port', '0', '--http-port', '0', '--admin-password-file', passwordFile, '--non-interactive',
        ...(tls ? ['--tls', '--client-user', TestServer.clientCertificateUser] : [])],
      { env: cleanEnv() },
    );
    const args = [
      '--config', path.join(data, 'rustegon.toml'), '--admin-password-file', passwordFile, '--stop-on-stdin-eof',
      // The smallest iteration count the configuration accepts: fast logins.
      '--set', 'auth.scram_iterations=100000', '--set', 'log.stderr=false',
      // The conformance suite logs in (and fails logins on purpose) far more often than the
      // default rate limits allow (PD-098). 0 = unlimited.
      '--set', 'rate_limit.auth_per_ip_per_min=0', '--set', 'rate_limit.auth_per_user_per_min=0',
      '--set', 'rate_limit.session_per_user_per_min=0', '--set', 'rate_limit.admin_per_user_per_min=0',
    ];
    if (tls) {
      // X.509 logins (conf_x509) need the client certificate to be accepted, not required.
      args.push('--set', 'tls.client_cert=optional');
    }
    const child = spawn(path.join(binDir, exe('rustegond')), args, { env: cleanEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (d: string) => (stderr += d));
    const line = await new Promise<string>((resolve, reject) => {
      let out = '';
      const timer = setTimeout(() => reject(new Error(`rustegond did not become ready; stderr:\n${stderr}`)), 120_000);
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (d: string) => {
        out += d;
        const i = out.indexOf(READY);
        const nl = out.indexOf('\n', i);
        if (i >= 0 && nl > i) {
          clearTimeout(timer);
          resolve(out.slice(i + READY.length, nl).trim());
        }
      });
      child.on('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`rustegond exited (${code}) before it was ready; stderr:\n${stderr}`));
      });
    });
    const grpc = /grpc=(\S+)/.exec(line)?.[1];
    if (grpc === undefined) {
      child.kill();
      throw new Error(`unexpected ready line: ${line}`);
    }
    return new TestServer(root, child, grpc, password, tls);
  }

  /** Stops the node (stdin closed = graceful; killed after 30 s) and deletes its directory. */
  async stop(): Promise<void> {
    const p = this.process;
    if (p.exitCode === null) {
      const exited = new Promise<void>((resolve) => p.once('exit', () => resolve()));
      p.stdin?.end();
      const timer = setTimeout(() => p.kill(), 30_000);
      await exited;
      clearTimeout(timer);
    }
    try {
      rmSync(this.root, { recursive: true, force: true, maxRetries: 5 });
    } catch {
      // A file still held open (antivirus, slow handle release) leaves a temp directory behind.
    }
  }
}

function exe(name: string): string {
  return process.platform === 'win32' ? `${name}.exe` : name;
}

/** The node must see only the flags given here, not an operator's RUSTEGON_* environment. */
function cleanEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!k.toUpperCase().startsWith('RUSTEGON_')) {
      env[k] = v;
    }
  }
  return env;
}

let shared: Promise<TestServer | undefined> | undefined;

/**
 * The run's shared TLS node (started on first use, stopped at exit), or undefined with the
 * reason printed when there are no binaries; under `CI=true` missing binaries are an error.
 */
export function sharedServer(): Promise<TestServer | undefined> {
  shared ??= (async () => {
    const found = TestServer.findBinaries();
    if (found.dir === undefined) {
      if (process.env.CI === 'true') {
        throw new Error(`CI=true but no server binaries: ${found.reason}`);
      }
      console.warn(`integration tests skipped: ${found.reason}`);
      return undefined;
    }
    return TestServer.start(found.dir);
  })();
  return shared;
}

export const skipReason = (): string => `no server binaries: ${TestServer.findBinaries().reason}`;
