import { readFileSync } from 'node:fs';
import { ADMIN, adminPassword, createUser, expect, go, signIn, test } from './fixtures';

// TC-GUI-002 login/lockout (angular-gui.md §5, S01) against a real rustegond.

test('tc_gui_002_login_logout_and_return_url', async ({ page }) => {
  await go(page, 'data');
  await expect(page).toHaveURL(/\/ui\/login\?returnUrl=%2Fdata$/);
  await expect(page.getByLabel('User name')).toBeFocused();
  await signIn(page, ADMIN, adminPassword());
  await expect(page).toHaveURL(/\/ui\/data$/);
  await expect(page.getByRole('heading', { name: 'Data', level: 1 })).toBeVisible();

  await page.getByRole('link', { name: 'Dashboard' }).click();
  await expect(page.getByText('Ready', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: ADMIN }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/ui\/login$/);
  // The session cookie is gone: protected pages send the user back to the login page.
  await go(page, 'dashboard');
  await expect(page).toHaveURL(/\/ui\/login\?returnUrl=%2Fdashboard$/);
});

test('tc_gui_002_wrong_password_and_unknown_user_get_the_same_message', async ({ page }) => {
  await go(page, 'login');
  await signIn(page, ADMIN, 'not-the-password');
  await expect(page.getByRole('alert')).toHaveText('Invalid user name or password.');
  await signIn(page, 'no_such_user', 'whatever');
  await expect(page.getByRole('alert')).toHaveText('Invalid user name or password.');
});

test('tc_gui_002_lockout_after_repeated_failures', async ({ page, admin }) => {
  const password = 'Lockout-Test-Passw0rd-2026';
  await createUser(admin, 'gui_locky', password, [{ role: 'read', resource: '' }]);
  await go(page, 'login');
  // FR-SEC-006 default policy: 10 failures within 5 min lock the account.
  // Wait for each attempt's own response: the alert of the previous attempt is still shown, so
  // waiting on the alert let the next fill race the request in flight and attempts got lost.
  for (let i = 0; i < 10; i++) {
    const response = page.waitForResponse(
      (r) => r.url().endsWith('/api/v1/auth/login') && r.request().method() === 'POST',
    );
    await signIn(page, 'gui_locky', `wrong-${i}`);
    expect((await response).status()).toBe(401);
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeEnabled();
  }
  await signIn(page, 'gui_locky', password);
  await expect(page.getByRole('alert')).toContainText('temporarily locked');
  await expect(page).toHaveURL(/\/ui\/login/);
});

test('tc_gui_002_must_change_password_then_least_privilege', async ({ page, admin }) => {
  const first = 'First-Login-Passw0rd-2026';
  const second = 'Second-Login-Passw0rd-2026';
  await createUser(admin, 'gui_reader', first, [{ role: 'read', resource: '' }], true);
  await go(page, 'login');
  await signIn(page, 'gui_reader', first);
  await expect(page).toHaveURL(/\/ui\/change-password/);
  await page.getByLabel('Current password').fill(first);
  await page.getByLabel('New password', { exact: true }).fill(second);
  await page.getByLabel('Repeat the new password').fill(second);
  await page.getByRole('button', { name: 'Change password' }).click();
  await expect(page).toHaveURL(/\/ui\/dashboard$/);

  // A read-only user: Security is hidden, and its URL shows the 403 panel in place.
  await expect(page.getByRole('navigation').getByRole('link', { name: 'Security' })).toHaveCount(0);
  await go(page, 'security');
  await expect(page).toHaveURL(/\/ui\/security$/);
  await expect(page.getByRole('heading', { name: 'Insufficient privileges' })).toBeVisible();
});

test('tc_gui_002_login_page_in_italian', async ({ page }) => {
  await go(page, 'login');
  await page.evaluate(() => localStorage.setItem('rg.locale', 'it'));
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Accedi a Rustegon' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'it');
  await page.evaluate(() => localStorage.removeItem('rg.locale'));
});

test('tc_gui_002_login_page_in_german_spanish_and_french', async ({ page }) => {
  // PD-231: each locale file is served and applied at bootstrap.
  await go(page, 'login');
  for (const locale of ['de', 'es', 'fr']) {
    const heading = (
      JSON.parse(readFileSync(`src/locale/messages.${locale}.json`, 'utf8')) as {
        translations: Record<string, string>;
      }
    ).translations['login.heading'];
    await page.evaluate((l) => localStorage.setItem('rg.locale', l), locale);
    await page.reload();
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('lang', locale);
  }
  await page.evaluate(() => localStorage.removeItem('rg.locale'));
});
