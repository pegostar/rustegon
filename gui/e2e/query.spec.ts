import { APIRequestContext, Page } from '@playwright/test';
import { ADMIN, adminPassword, expect, go, signIn, test } from './fixtures';

// TC-GUI-004 query editor + explain + create suggested index (angular-gui.md §5, S09–S11).

async function seed(admin: APIRequestContext, db: string): Promise<void> {
  for (const [path, data] of [
    ['/api/v1/databases', { name: db }],
    [`/api/v1/databases/${db}/collections`, { name: 'items' }],
    [
      `/api/v1/databases/${db}/collections/items/documents`,
      { documents: [1, 2, 3, 4].map((n) => ({ _id: n, n, tag: n % 2 ? 'odd' : 'even' })) },
    ],
  ] as const) {
    const res = await admin.post(path, { data });
    expect(res.ok(), await res.text()).toBe(true);
  }
}

async function openQuery(page: Page, db: string): Promise<void> {
  await go(page, 'login');
  await signIn(page, ADMIN, adminPassword());
  await expect(page).toHaveURL(/dashboard$/);
  await go(page, 'query');
  await page.getByRole('combobox', { name: 'Database' }).selectOption(db);
  await expect(page.locator('.monaco-editor')).toBeVisible();
}

/** Replaces the editor text through the keyboard (Monaco owns its input element). */
async function typeQuery(page: Page, text: string): Promise<void> {
  await page.locator('.monaco-editor .view-lines').click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.press('Delete');
  await page.keyboard.type(text);
  await page.keyboard.press('Escape'); // closes the suggestion widget
}

test('tc_gui_004_run_a_query_and_see_results', async ({ page, admin }) => {
  const db = `q_run_${Date.now()}`;
  await seed(admin, db);
  await openQuery(page, db);
  await typeQuery(page, 'FROM items WHERE n >= 2 ORDER BY n DESC');
  await page.keyboard.press('ControlOrMeta+Enter');
  await expect(page.locator('p.status')).toContainText('3 rows in');
  const grid = page.getByRole('grid', { name: 'Query results' });
  await expect(grid.getByRole('gridcell', { name: 'even' }).first()).toBeVisible();
  await page.getByRole('radio', { name: 'JSON' }).click();
  await expect(page.locator('rg-code-block')).toContainText('"tag": "odd"');

  // A syntax error is marked and offers its position.
  await typeQuery(page, 'FROM items WHERE');
  await page.getByRole('button', { name: 'Run', exact: true }).click();
  await expect(page.getByText('RGN-1010')).toBeVisible();
  await page.getByRole('button', { name: /Go to line 1, column/ }).click();
  await expect(page.locator('.monaco-editor .squiggly-error')).toHaveCount(1);
});

test('tc_gui_004_explain_create_suggested_index_and_drop_it', async ({ page, admin }) => {
  const db = `q_ix_${Date.now()}`;
  await seed(admin, db);
  await openQuery(page, db);
  await typeQuery(page, 'FROM items WHERE n = 3');
  await page.getByRole('button', { name: 'Explain', exact: true }).click();
  await expect(page.getByText('Collection scan: every document is read')).toBeVisible();
  await page.getByRole('button', { name: 'Explain analyze' }).click();
  await expect(page.getByText('Rows returned')).toBeVisible();

  await page.getByRole('link', { name: 'Create suggested index' }).click();
  await expect(page).toHaveURL(new RegExp(`/indexes[?]db=${db}&coll=items&fields=n$`));
  await expect(page.getByLabel('Name')).toHaveValue('ix_n');
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  const grid = page.getByRole('grid', { name: 'Indexes' });
  await expect(grid.getByRole('gridcell', { name: 'ix_n' })).toBeVisible();

  // The plan now reads the index.
  await go(page, 'query');
  await page.getByRole('combobox', { name: 'Database' }).selectOption(db);
  await page.getByRole('button', { name: 'Explain', exact: true }).click();
  await expect(page.locator('rg-explain-plan')).toContainText('IndexScan');

  await go(page, `indexes?db=${db}&coll=items`);
  await page.getByRole('grid', { name: 'Indexes' }).getByRole('gridcell', { name: 'ix_n' }).click();
  await expect(page.locator('rg-code-block')).toContainText('"ix_n"');
  await page.getByRole('button', { name: 'Drop index' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Drop' }).click();
  await expect(page.getByText('No secondary indexes')).toBeVisible();
});
