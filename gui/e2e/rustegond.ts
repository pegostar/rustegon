import { ChildProcess, execFile, spawn } from 'node:child_process';
import { randomInt } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

/**
 * A single-node rustegond for the e2e suite, started like the driver tests do (PD-072,
 * drivers/dotnet RustegonTestServer): `rustegon init` into a fresh temporary directory, then
 * `rustegond --stop-on-stdin-eof`, which prints `rustegond ready grpc=… http=…`. No `--tls`:
 * the node serves plain http, the single-node default (ADR-034).
 */
export interface Rustegond {
  /** REST listener `127.0.0.1:port` (plain http). */
  http: string;
  adminPassword: string;
  stop(): Promise<void>;
}

const exe = (name: string) => (process.platform === 'win32' ? `${name}.exe` : name);

export function binDir(): string {
  const dir = process.env['RUSTEGON_BIN_DIR'] ?? resolve(__dirname, '../../target/release');
  for (const name of ['rustegon', 'rustegond']) {
    if (!existsSync(join(dir, exe(name)))) {
      throw new Error(
        `${exe(name)} not found in ${dir}: build with \`cargo build --release -p rustegond -p rustegon-cli\` or set RUSTEGON_BIN_DIR`,
      );
    }
  }
  return dir;
}

/** The node must see only our flags, not an operator's RUSTEGON_* environment. */
function cleanEnv(): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !k.toUpperCase().startsWith('RUSTEGON_')),
  );
}

/**
 * `turnkey`: `rustegon init --turnkey` (ADR-036, the MSI/DEB/RPM first install), so the first
 * start creates `admin` with the password `admin`, to be changed at first login.
 */
export async function startRustegond(
  extraArgs: string[] = [],
  options: { turnkey?: boolean } = {},
): Promise<Rustegond> {
  const turnkey = options.turnkey ?? false;
  const bin = binDir();
  const root = mkdtempSync(join(tmpdir(), 'rustegon-gui-e2e-'));
  const data = join(root, 'data');
  const pwFile = join(root, 'admin.pw');
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  // 24 uniform base62 characters pass the password policy (as the server's own generator).
  const adminPassword = Array.from({ length: 24 }, () => alphabet[randomInt(alphabet.length)]).join(
    '',
  );
  mkdirSync(root, { recursive: true });
  writeFileSync(pwFile, adminPassword);

  await promisify(execFile)(
    join(bin, exe('rustegon')),
    [
      'init',
      '--data-dir',
      data,
      '--grpc-port',
      '0',
      '--http-port',
      '0',
      ...(turnkey ? ['--turnkey'] : ['--admin-password-file', pwFile, '--non-interactive']),
    ],
    { env: cleanEnv() },
  );

  const child = spawn(
    join(bin, exe('rustegond')),
    [
      '--config',
      join(data, 'rustegon.toml'),
      ...(turnkey ? [] : ['--admin-password-file', pwFile]),
      '--stop-on-stdin-eof',
      '--set',
      'log.stderr=false',
      // One node serves the whole suite from one address: the lockout test fails logins on
      // purpose, which the per-IP/per-user rate limits would turn into RGN-4003. 0 = unlimited.
      '--set',
      'rate_limit.auth_per_ip_per_min=0',
      '--set',
      'rate_limit.auth_per_user_per_min=0',
      '--set',
      'rate_limit.session_per_user_per_min=0',
      '--set',
      'rate_limit.admin_per_user_per_min=0',
      ...extraArgs,
    ],
    { env: cleanEnv(), stdio: ['pipe', 'pipe', 'pipe'] },
  );
  let stderr = '';
  child.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
  const line = await readyLine(child, () => stderr);
  const http = /http=(\S+)/.exec(line)?.[1];
  if (!http) throw new Error(`no http address in ready line: ${line}`);

  return {
    http,
    adminPassword: turnkey ? 'admin' : adminPassword,
    async stop() {
      child.stdin?.end();
      const exited = new Promise((r) => child.once('exit', r));
      const timer = setTimeout(() => child.kill(), 30_000);
      await exited;
      clearTimeout(timer);
      try {
        rmSync(root, { recursive: true, force: true });
      } catch {
        // A file still held open leaves the temp directory behind.
      }
    },
  };
}

function readyLine(child: ChildProcess, stderr: () => string): Promise<string> {
  return new Promise((resolveLine, reject) => {
    let out = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`rustegond did not become ready in 120 s; stderr:\n${stderr()}`));
    }, 120_000);
    child.stdout?.on('data', (d: Buffer) => {
      out += d.toString();
      const line = out.split(/\r?\n/).find((l) => l.startsWith('rustegond ready '));
      if (line) {
        clearTimeout(timer);
        resolveLine(line);
      }
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`rustegond exited (${code}) before it was ready; stderr:\n${stderr()}`));
    });
  });
}
