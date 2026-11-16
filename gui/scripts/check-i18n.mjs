// i18n completeness (angular-gui.md §1: all strings externalized, locales en + it): extracts the
// source messages and fails when the Italian file misses an id.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'rg-i18n-'));
try {
  execFileSync(
    process.execPath,
    [
      'node_modules/@angular/cli/bin/ng.js',
      'extract-i18n',
      '--format',
      'json',
      '--output-path',
      dir,
    ],
    { stdio: 'pipe' },
  );
  const source = Object.keys(
    JSON.parse(readFileSync(join(dir, 'messages.json'), 'utf8')).translations,
  );
  const it = Object.keys(
    JSON.parse(readFileSync('src/locale/messages.it.json', 'utf8')).translations,
  );
  const missing = source.filter((id) => !it.includes(id));
  const stale = it.filter((id) => !source.includes(id));
  // Stale ids only warn: shared components carry translations before a screen uses them.
  if (stale.length) console.warn(`check-i18n: unused Italian ids ${JSON.stringify(stale)}`);
  if (missing.length) {
    console.error(`check-i18n: messages.it.json misses ${JSON.stringify(missing)}`);
    process.exit(1);
  }
  console.log(`check-i18n: ${source.length} messages, Italian complete`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
