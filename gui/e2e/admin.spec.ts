import { Page, request } from '@playwright/test';
import { ADMIN, adminPassword, expect, go, signIn, test } from './fixtures';

// Lane A screens against a real rustegond: TC-GUI-006 (S14–S16 users, roles, API keys),
// TC-GUI-007 (S22 backup, S23 restore command), TC-GUI-017 (S17 settings). Names are unique
// per run; every test leaves users, roles, keys and settings as it found them.

const tag = () => Date.now().toString(36);

async function signInAsAdmin(page: Page, path: string): Promise<void> {
  await go(page, 'login');
  await signIn(page, ADMIN, adminPassword());
  await expect(page).toHaveURL(/dashboard$/);
  await go(page, path);
}

async function confirmTyped(page: Page, name: string, button: string): Promise<void> {
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(`Type "${name}" to confirm`).fill(name);
  await dialog.getByRole('button', { name: button }).click();
  await expect(dialog).toHaveCount(0);
}

test('tc_gui_006_create_user_grant_role_and_delete', async ({ page }) => {
  const name = `gui_a_${tag()}`;
  await signInAsAdmin(page, 'security/users');
  await expect(page.getByRole('heading', { name: 'Users', level: 1 })).toBeVisible();

  await page.getByRole('button', { name: 'New user' }).click();
  await page.getByLabel('User name').fill(name);
  await page.getByLabel('Initial password').fill('Gui-Lane-A-Passw0rd-2026');
  await page.getByLabel('Roles', { exact: true }).fill('read');
  await page.getByRole('button', { name: 'Create user' }).click();
  const row = page.getByRole('row').filter({ has: page.getByRole('rowheader', { name }) });
  await expect(row).toContainText('read');

  // Grant a scoped role.
  await page.getByRole('button', { name: `Edit ${name}` }).click();
  await page.getByLabel('Roles', { exact: true }).fill('read, read_write@shop_a');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(row).toContainText('read_write@shop_a');

  // The admin cannot delete itself (last root, self).
  await expect(page.getByRole('button', { name: `Delete ${ADMIN}` })).toBeDisabled();

  await page.getByRole('button', { name: `Delete ${name}` }).click();
  await confirmTyped(page, name, 'Delete');
  await expect(page.getByRole('rowheader', { name })).toHaveCount(0);
});

test('tc_gui_006_api_key_secret_shown_once_then_revoked', async ({ page }) => {
  await signInAsAdmin(page, 'security/api-keys');
  await page.getByRole('button', { name: 'New API key' }).click();
  await expect(page.getByLabel('Roles (scope)')).toHaveValue('root');
  await page.getByLabel('Description').fill(`gui lane A ${tag()}`);
  await page.getByRole('button', { name: 'Create key' }).click();

  const secretPanel = page.getByRole('region', { name: 'Copy the new API key now' });
  const secret = ((await secretPanel.locator('pre code').textContent()) ?? '').trim();
  expect(secret).toMatch(/^rgn_/);
  const keyId = secret.split('_')[1];

  // The key works, and the secret is in no browser storage or URL.
  const api = await request.newContext({
    baseURL: `http://${process.env['RGN_E2E_API']}`,
    extraHTTPHeaders: { authorization: `ApiKey ${secret}` },
  });
  expect((await api.get('/api/v1/auth/me')).status()).toBe(200);
  const stored = await page.evaluate(() =>
    JSON.stringify([{ ...localStorage }, { ...sessionStorage }]),
  );
  expect(stored).not.toContain(secret);
  expect(page.url()).not.toContain(secret);

  await page.getByRole('button', { name: 'I have stored the key' }).click();
  await expect(page.getByText(secret)).toHaveCount(0);
  await page.reload();
  await expect(page.getByRole('rowheader', { name: keyId })).toBeVisible();
  await expect(page.getByText(secret)).toHaveCount(0);

  await page.getByRole('button', { name: `Revoke ${keyId}` }).click();
  await confirmTyped(page, keyId, 'Revoke');
  await expect(page.getByRole('rowheader', { name: keyId })).toHaveCount(0);
  expect((await api.get('/api/v1/auth/me')).status()).toBe(401);
  await api.dispose();
});

test('tc_gui_006_custom_role_and_effective_privileges', async ({ page }) => {
  const role = `gui_a_role_${tag()}`;
  await signInAsAdmin(page, 'security/roles');
  await expect(page.getByRole('rowheader', { name: 'root' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Drop root' })).toHaveCount(0);

  await page.getByRole('button', { name: 'New role' }).click();
  await page.getByLabel('Role name').fill(role);
  await page.getByLabel('Privileges', { exact: true }).fill('database:shop_a: find');
  await page.getByLabel('Inherits', { exact: true }).fill('read@shop_b');
  await page.getByRole('button', { name: 'Save role' }).click();
  const row = page.getByRole('row').filter({ has: page.getByRole('rowheader', { name: role }) });
  await expect(row).toContainText('database:shop_a: find');

  await page.getByRole('button', { name: `Edit ${role}` }).click();
  await page.getByLabel('Privileges', { exact: true }).fill('database:shop_a: find, insert');
  await page.getByRole('button', { name: 'Save role' }).click();
  await expect(row).toContainText('find, insert');

  await page.getByLabel('User name').fill(ADMIN);
  await page.getByRole('button', { name: 'Show privileges' }).click();
  await expect(
    page.getByRole('table', { name: 'Effective privileges of a user' }).getByText('root').first(),
  ).toBeVisible();

  await page.getByRole('button', { name: `Drop ${role}` }).click();
  await confirmTyped(page, role, 'Drop');
  await expect(page.getByRole('rowheader', { name: role })).toHaveCount(0);
});

test('tc_gui_007_backup_verify_snapshot_and_restore_command', async ({ page }) => {
  test.setTimeout(180_000);
  const snapshot = `gui-a-${tag()}`;
  await signInAsAdmin(page, 'backup');
  const dest = page.getByLabel('Backup destination');
  // Prefilled from node.data_dir: <data_dir>/backups is always allowed.
  await expect(dest).toHaveValue(/backups$/);
  await page.getByRole('button', { name: 'Start backup' }).click();
  const backups = page.getByRole('table', { name: 'Backups' });
  await expect(backups.getByRole('row')).not.toHaveCount(0, { timeout: 120_000 });
  const first = backups.getByRole('row').nth(1);
  await first.getByRole('button', { name: 'Deep verify' }).click();
  await expect(page.getByRole('region', { name: 'Verification' })).toContainText('files checked', {
    timeout: 120_000,
  });
  await first.getByRole('button', { name: 'Files' }).click();
  await expect(page.getByRole('table', { name: 'Backup files' }).getByRole('row')).not.toHaveCount(
    0,
  );

  // S23: the restore command for that backup, built in the browser.
  const backupId = ((await first.getByRole('rowheader').textContent()) ?? '').trim();
  await first.getByRole('link', { name: 'Restore…' }).click();
  await expect(page).toHaveURL(/backup\/restore\?/);
  await expect(page.getByLabel('Backup id')).toHaveValue(backupId);
  await page.getByLabel('New data directory').fill('/srv/rustegon restored');
  await page.getByLabel('Shell').selectOption({ label: 'POSIX sh / bash' });
  await page.getByRole('button', { name: 'Generate command' }).click();
  const command = page.getByRole('region', { name: 'Restore command' }).locator('pre code');
  await expect(command).toContainText(`rustegon backup restore --from `);
  await expect(command).toContainText(`--id ${backupId} --into '/srv/rustegon restored'`);

  // Local snapshot: create, then delete with typed confirmation.
  await go(page, 'backup');
  await page.getByLabel('Snapshot name').fill(snapshot);
  await page.getByRole('button', { name: 'Create snapshot' }).click();
  await expect(page.getByRole('rowheader', { name: snapshot })).toBeVisible({ timeout: 60_000 });
  await page.getByRole('button', { name: `Delete snapshot ${snapshot}` }).click();
  await confirmTyped(page, snapshot, 'Delete');
  await expect(page.getByRole('rowheader', { name: snapshot })).toHaveCount(0);
});

test('tc_gui_017_change_a_setting_and_restore_it', async ({ page, admin }) => {
  const name = 'auth.session_idle_timeout_driver_secs';
  const read = async () => {
    const res = await admin.get(`/api/v1/settings?names=${name}`);
    return ((await res.json()) as { settings: { value: string }[] }).settings[0].value;
  };
  const original = await read();
  const changed = String(Number(original) + 60);
  try {
    await signInAsAdmin(page, 'settings');
    await page.getByLabel('Search settings').fill('session_idle_timeout_driver');
    const row = page.getByRole('row').filter({ has: page.getByRole('rowheader', { name }) });
    await expect(row).toHaveCount(1);
    await page.getByRole('button', { name: `Change ${name}` }).click();
    await page.getByLabel('Value').fill(changed);
    await page.getByRole('button', { name: 'Apply' }).click();
    await expect(row).toContainText(changed);
    expect(await read()).toBe(changed);

    await page.getByRole('button', { name: `Change ${name}` }).click();
    await page.getByLabel('Value').fill(original);
    await page.getByRole('button', { name: 'Apply' }).click();
    await expect(row).toContainText(original);
  } finally {
    // Leave the shared node as it was, whatever happened above.
    if ((await read()) !== original)
      await admin.patch('/api/v1/settings', { data: { values: { [name]: original } } });
  }
  expect(await read()).toBe(original);
});
