// Performance budgets of angular-gui.md §1, measured gzip-compressed (Angular's own budgets
// measure raw bytes): initial JS ≤ 350 KB, every lazy chunk ≤ 200 KB, except the lazily loaded
// Monaco editor (PD-134), whose chunks and workers together have their own budget ≤ 1400 KB.
// A chunk counts as Monaco when most of its bytes come from node_modules/monaco-editor, read
// from the esbuild metafile that `ng build --stats-json` writes (removed here: it must not be
// embedded into rustegond and served under /ui).
import { existsSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

const DIST = 'dist';
const STATS = `${DIST}/browser-stats.json`;
const KB = 1024;
const LAZY_KB = 200;
const INITIAL_KB = 350;
const MONACO_KB = 1400;

if (!existsSync(STATS)) {
  console.error(`bundle-size: ${STATS} missing (build with ng build --stats-json)`);
  process.exit(1);
}
const outputs = JSON.parse(readFileSync(STATS, 'utf8')).outputs;
rmSync(STATS);
const monaco = new Set(
  Object.entries(outputs)
    .filter(([, o]) => {
      const from = Object.entries(o.inputs)
        .filter(([path]) => path.includes('node_modules/monaco-editor/'))
        .reduce((sum, [, i]) => sum + i.bytesInOutput, 0);
      return from * 2 > o.bytes;
    })
    .map(([file]) => file.replace(/^.*\//, ''))
    .filter((file) => file.endsWith('.js')),
);

const html = readFileSync(`${DIST}/index.html`, 'utf8');
const initial = new Set(
  [
    ...html.matchAll(
      /<(?:script[^>]*\ssrc|link[^>]*rel="modulepreload"[^>]*\shref)="([^"]+\.js)"/g,
    ),
  ].map((m) => m[1]),
);
const gz = (f) => gzipSync(readFileSync(`${DIST}/${f}`)).length;
const kb = (n) => `${(n / KB).toFixed(1)} KB`;
let initialBytes = 0;
let monacoBytes = 0;
let failed = false;
for (const f of readdirSync(DIST).filter((f) => f.endsWith('.js'))) {
  const size = gz(f);
  if (initial.has(f)) {
    initialBytes += size;
  } else if (monaco.has(f)) {
    monacoBytes += size;
    console.log(`bundle-size: Monaco chunk ${f} ${kb(size)} gzip`);
  } else if (size > LAZY_KB * KB) {
    console.error(`bundle-size: lazy chunk ${f} is ${kb(size)} gzip (> ${LAZY_KB} KB)`);
    failed = true;
  }
}
console.log(
  `bundle-size: initial JS ${kb(initialBytes)} gzip (budget ${INITIAL_KB} KB, ${initial.size} files)`,
);
console.log(
  `bundle-size: Monaco JS ${kb(monacoBytes)} gzip (budget ${MONACO_KB} KB, ${monaco.size} files, lazy)`,
);
if (initialBytes > INITIAL_KB * KB || monacoBytes > MONACO_KB * KB) failed = true;
process.exit(failed ? 1 : 0);
