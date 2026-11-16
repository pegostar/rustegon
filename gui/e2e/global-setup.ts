import { resolve } from 'node:path';
import { startGuiServer } from './gui-server';
import { startRustegond } from './rustegond';

/**
 * Starts a real rustegond (RUSTEGON_BIN_DIR, default ../target/release) and publishes for the
 * tests (process.env reaches the workers):
 * - RGN_E2E_BASE_URL: the console URL (ends with /ui/);
 * - RGN_E2E_API: rustegond's REST address (plain http, the single-node default, ADR-034) for
 *   setup calls;
 * - RGN_E2E_ADMIN_PASSWORD: the password of `admin`.
 *
 * RGN_E2E_SERVE selects who serves the GUI: `proxy` (default; gui-server.ts serves dist/ and
 * forwards /api) or `rustegond` (rustegond serves /ui itself, after lane SG).
 */
export default async function globalSetup(): Promise<() => Promise<void>> {
  const mode = process.env['RGN_E2E_SERVE'] ?? 'proxy';
  // `external`: a node that is already running (TC-INS-009 Docker variant, PD-156); the caller
  // sets RGN_E2E_BASE_URL, RGN_E2E_API and RGN_E2E_ADMIN_PASSWORD and stops the node itself.
  if (mode === 'external') return async () => undefined;
  const node = await startRustegond();
  let closeGui = async () => undefined;
  if (mode === 'rustegond') {
    process.env['RGN_E2E_BASE_URL'] = `http://127.0.0.1:${node.http.split(':').pop()}/ui/`;
  } else if (mode === 'proxy') {
    const gui = await startGuiServer(resolve(__dirname, '../dist'), node.http);
    process.env['RGN_E2E_BASE_URL'] = gui.url;
    closeGui = gui.close;
  } else {
    await node.stop();
    throw new Error(`RGN_E2E_SERVE must be proxy, rustegond or external, not ${mode}`);
  }
  process.env['RGN_E2E_API'] = node.http;
  process.env['RGN_E2E_ADMIN_PASSWORD'] = node.adminPassword;
  return async () => {
    await closeGui();
    await node.stop();
  };
}
