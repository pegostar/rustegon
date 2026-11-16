import { resolve } from 'node:path';
import { startGuiServer } from './gui-server';
import { startRustegond } from './rustegond';
import { expect, signIn, test } from './fixtures';

// TC-SEC-024 (ADR-036): on a turnkey node (`rustegon init --turnkey`, as the MSI/DEB/RPM first
// install leaves it), signing in as admin / admin lands on the change-password screen, nothing
// else is reachable before the change, and afterwards only the new password works.
test('tc_sec_024_turnkey_admin_admin_lands_on_change_password', async ({ page }) => {
  test.setTimeout(240_000);
  const node = await startRustegond([], { turnkey: true });
  const gui =
    process.env['RGN_E2E_SERVE'] === 'rustegond'
      ? { url: `http://127.0.0.1:${node.http.split(':').pop()}/ui/`, close: async () => undefined }
      : await startGuiServer(resolve(__dirname, '../dist'), node.http);
  try {
    await page.goto(new URL('dashboard', gui.url).toString());
    await expect(page).toHaveURL(/\/ui\/login\?returnUrl=%2Fdashboard$/);
    await signIn(page, 'admin', 'admin');
    await expect(page).toHaveURL(/\/ui\/change-password/);
    // Another page sends the user back until the password is changed.
    await page.goto(new URL('data', gui.url).toString());
    await expect(page).not.toHaveURL(/\/ui\/data$/);

    const next = 'Turnkey-Changed-Passw0rd-2026';
    if (!/change-password/.test(page.url())) {
      await signIn(page, 'admin', 'admin');
      await expect(page).toHaveURL(/\/ui\/change-password/);
    }
    await page.getByLabel('Current password').fill('admin');
    await page.getByLabel('New password', { exact: true }).fill(next);
    await page.getByLabel('Repeat the new password').fill(next);
    await page.getByRole('button', { name: 'Change password' }).click();
    // Back to the page that was asked for before the detour.
    await expect(page).toHaveURL(/\/ui\/data$/);

    await page.getByRole('button', { name: 'admin' }).click();
    await page.getByRole('menuitem', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/ui\/login$/);
    await signIn(page, 'admin', 'admin');
    await expect(page.getByRole('alert')).toHaveText('Invalid user name or password.');
    await signIn(page, 'admin', next);
    await expect(page).toHaveURL(/\/ui\/dashboard$/);
  } finally {
    await gui.close();
    await node.stop();
  }
});
