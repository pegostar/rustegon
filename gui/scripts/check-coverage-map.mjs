// AC-GUI-001 (angular-gui.md §6): every operation of the committed OpenAPI document is either
// reached by a GUI route in e2e/coverage-map.json or excluded there with a reason (PD-146).
import { readFileSync } from 'node:fs';

const map = JSON.parse(readFileSync('e2e/coverage-map.json', 'utf8'));
// shortcut: line-based scan of the paths section (2-space path keys, 4-space methods) instead of
// a YAML parser; upgrade if the generator's layout changes (the check then reports every op).
const ops = new Set();
let path = null;
for (const line of readFileSync('../api/openapi/rustegon-v1.yaml', 'utf8').split(/\r?\n/)) {
  const p = /^ {2}"?(\/[^":]+)"?:\s*$/.exec(line);
  if (p) path = p[1];
  const m = /^ {4}(get|post|put|patch|delete):/.exec(line);
  if (m && path) ops.add(`${m[1].toUpperCase()} ${path}`);
}
const routed = new Set(Object.values(map.routes).flat());
const excluded = map.excluded ?? {};
const errors = [];
if (ops.size === 0) errors.push('no operations found in the OpenAPI document');
for (const op of ops)
  if (!routed.has(op) && !excluded[op]) errors.push(`not reachable and not excluded: ${op}`);
for (const op of [...routed, ...Object.keys(excluded)])
  if (!ops.has(op)) errors.push(`not in the OpenAPI document: ${op}`);
for (const op of Object.keys(excluded)) {
  if (routed.has(op)) errors.push(`both routed and excluded: ${op}`);
  if (!excluded[op]?.trim()) errors.push(`excluded without a reason: ${op}`);
}
if (errors.length) {
  console.error(`check-coverage-map (AC-GUI-001):\n  ${errors.join('\n  ')}`);
  process.exit(1);
}
console.log(
  `check-coverage-map: ${ops.size} operations, ${routed.size} reachable from the GUI, ${Object.keys(excluded).length} excluded with a reason`,
);
