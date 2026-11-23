import AxeBuilder from '@axe-core/playwright';
import { Locator, Page } from '@playwright/test';
import { ADMIN, adminPassword, expect, go, signIn, test } from './fixtures';

// AC-GUI-002 (FR-GUI-002): axe on every existing route in light and dark, zero critical or
// serious violations. Extend ROUTES when a screen is added.
const ROUTES = [
  'dashboard',
  'data',
  'db/shop/c/orders/doc/1',
  'db/shop',
  'db/shop/c/orders',
  'db/shop/c/orders/new',
  'query',
  'indexes',
  'security',
  'security/users',
  'security/roles',
  'security/api-keys',
  'backup',
  'backup/restore',
  'backup/databases',
  'backup/database-restore',
  'settings',
  'change-password',
  'no-such-page',
];

async function audit(page: Page, what: string): Promise<void> {
  const result = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  const bad = result.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious');
  expect(
    bad.map(
      (v) => `${what}: ${v.id} (${v.impact}) ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`,
    ),
  ).toEqual([]);
}

for (const scheme of ['light', 'dark'] as const) {
  test(`tc_gui_a11y_every_route_${scheme}`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await go(page, 'login');
    await expect(page.getByLabel('User name')).toBeVisible();
    await audit(page, `login/${scheme}`);
    await signIn(page, ADMIN, adminPassword());
    await expect(page).toHaveURL(/dashboard$/);
    for (const route of ROUTES) {
      await go(page, route);
      await expect(page.locator('main h1')).toBeVisible();
      // Audit the settled page: the side nav's links get their names once it initializes.
      if (route !== 'change-password') {
        await expect(
          page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Dashboard' }),
        ).toBeVisible();
      }
      await audit(page, `${route}/${scheme}`);
    }
  });
}

test('tc_gui_a11y_skip_link_and_landmarks', async ({ page }) => {
  await go(page, 'login');
  await signIn(page, ADMIN, adminPassword());
  await expect(page).toHaveURL(/dashboard$/);
  await page.keyboard.press('Tab');
  const skip = page.getByRole('link', { name: 'Skip to main content' });
  await expect(skip).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('main#main')).toBeFocused();
  await expect(page.getByRole('banner')).toHaveCount(1);
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
});

/** Presses Tab until `target` holds the focus; fails after `max` presses (unreachable). */
async function tabTo(page: Page, target: Locator, max = 60): Promise<void> {
  for (let i = 0; i < max; i++) {
    if (await target.evaluate((el) => el.contains(document.activeElement))) return;
    await page.keyboard.press('Tab');
  }
  throw new Error(`not reachable with Tab in ${max} presses: ${target}`);
}

// AC-GUI-002 keyboard journey: sign in, reach a screen through the side nav, pick a database
// and run a query without the mouse.
test('tc_gui_a11y_keyboard_only_query_journey', async ({ page, admin }) => {
  const db = `kb_${Date.now()}`;
  for (const [path, data] of [
    ['/api/v1/databases', { name: db }],
    [`/api/v1/databases/${db}/collections`, { name: 'items' }],
    [`/api/v1/databases/${db}/collections/items/documents`, { documents: [{ _id: 1, n: 1 }] }],
  ] as const) {
    const res = await admin.post(path, { data });
    expect(res.ok(), await res.text()).toBe(true);
  }
  await go(page, 'login');
  await tabTo(page, page.getByLabel('User name'));
  await page.keyboard.type(ADMIN);
  await tabTo(page, page.getByLabel('Password', { exact: true }));
  await page.keyboard.type(adminPassword());
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/dashboard$/);

  await tabTo(
    page,
    page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Query' }),
  );
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/query$/);

  const database = page.getByRole('combobox', { name: 'Database' });
  await tabTo(page, database);
  await page.keyboard.type(db); // native <select> typeahead picks the option while closed
  await expect(database).toHaveValue(db);

  await tabTo(page, page.locator('.monaco-editor'));
  await page.keyboard.type('FROM items');
  await page.keyboard.press('Escape'); // closes the suggestion widget
  await page.keyboard.press('ControlOrMeta+Enter');
  await expect(page.locator('p.status')).toContainText('1 rows in');
});
