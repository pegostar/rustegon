// Contract test (testing-strategy.md §GUI): the committed generated API types must match a
// fresh generation from the committed OpenAPI document, so the GUI never drifts from the server.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'rg-api-'));
const fresh = join(dir, 'schema.d.ts');
try {
  execFileSync(
    process.execPath,
    ['node_modules/openapi-typescript/bin/cli.js', '../api/openapi/rustegon-v1.yaml', '-o', fresh],
    { stdio: 'pipe' },
  );
  const norm = (f) => readFileSync(f, 'utf8').replace(/\r\n/g, '\n');
  if (norm(fresh) !== norm('src/app/api/schema.d.ts')) {
    console.error(
      'check-api: src/app/api/schema.d.ts differs from ../api/openapi/rustegon-v1.yaml; run `npm run api:gen` and commit.',
    );
    process.exit(1);
  }
  console.log('check-api: generated API types match the committed OpenAPI document');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
