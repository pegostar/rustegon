import { createServer } from 'node:net';
import { resolve } from 'node:path';
import { startGuiServer } from './gui-server';
import { startRustegond } from './rustegond';
import { expect, signIn, test } from './fixtures';

/** A port free right now, so the node keeps one address across its restart. */
function freePort(): Promise<number> {
  return new Promise((done, fail) => {
    const server = createServer();
    server.once('error', fail);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => done(typeof address === 'object' && address ? address.port : 0));
    });
  });
}

// PD-230: a static setting edited in its tab is saved to rustegon.toml, waits for a restart, and
// "Restart the database" applies it without the process ending. Own node: the shared one listens
// on an ephemeral port that a restart would change.
test('tc_gui_017_static_setting_applies_after_restart_the_database', async ({ page }) => {
  test.setTimeout(240_000);
  const port = await freePort();
  const node = await startRustegond(['--set', `listen.http=127.0.0.1:${port}`]);
  const gui =
    process.env['RGN_E2E_SERVE'] === 'rustegond'
      ? { url: `http://127.0.0.1:${port}/ui/`, close: async () => undefined }
      : await startGuiServer(resolve(__dirname, '../dist'), node.http);
  try {
    await page.goto(new URL('login', gui.url).toString());
    await signIn(page, 'admin', node.adminPassword);
    await expect(page).toHaveURL(/dashboard$/);
    await page.goto(new URL('settings', gui.url).toString());

    await page.getByRole('tab', { name: 'Access and security' }).click();
    const field = page.getByLabel('Users tracked for lockout', { exact: true });
    await field.fill('50000');
    await page.getByRole('button', { name: 'Save changes (1)' }).click();
    const waiting = page.getByRole('region', { name: 'Changes waiting for a restart' });
    await expect(waiting).toContainText('lockout.max_tracked');
    // A listen address set by a --set option is shown but cannot be changed here.
    await page.getByRole('tab', { name: 'Network and TLS' }).click();
    await expect(page.getByLabel('REST address', { exact: true })).toHaveCount(0);
    await expect(page.getByText(/take precedence over the file/).first()).toBeVisible();

    await waiting.getByRole('button', { name: 'Restart the database' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Restart' }).click();
    await expect(waiting).toHaveCount(0, { timeout: 180_000 });
    await page.getByRole('tab', { name: 'Access and security' }).click();
    await expect(page.getByLabel('Users tracked for lockout', { exact: true })).toHaveValue(
      '50000',
    );
  } finally {
    await gui.close();
    await node.stop();
  }
});
