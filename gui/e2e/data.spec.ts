import AxeBuilder from '@axe-core/playwright';
import { Page } from '@playwright/test';
import { ADMIN, adminPassword, expect, go, signIn, test } from './fixtures';

// TC-GUI-003 (angular-gui.md §5): S05 databases → S06 collections → S07 documents → S08 editor
// against a real rustegond, including the RGN-2009 conflict flow and Monaco under the CSP of
// PD-131. Revisions are not exercised: R1 has no revision API (PD-133).

const unique = () => `gui_${Date.now().toString(36)}`;

/** Console errors and CSP violations of the page, collected from the start of the test. */
function watchConsole(page: Page): string[] {
  const errors: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  page.on('pageerror', (e) => errors.push(e.message));
  return errors;
}

async function noSeriousViolations(page: Page, what: string): Promise<void> {
  const result = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  const bad = result.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious');
  expect(bad.map((v) => `${what}: ${v.id} ${v.nodes.map((n) => n.target.join(' '))}`)).toEqual([]);
}

async function plainText(page: Page): Promise<import('@playwright/test').Locator> {
  const toggle = page.getByRole('button', { name: 'Plain text editor' });
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-pressed', 'true');
  // Monaco's own input is also a textbox named "Document (JSON)" (a div) until the textarea
  // renders: match the textarea only, or toHaveValue fails at once on the div.
  return page.getByRole('textbox', { name: 'Document (JSON)' }).and(page.locator('textarea'));
}

/** Runs `click` and waits until the PUT it sends is answered and the editor is idle again. */
async function saved(page: Page, click: () => Promise<void>): Promise<void> {
  const put = page.waitForResponse(
    (r) => r.request().method() === 'PUT' && r.url().includes('/documents/'),
  );
  await click();
  await put;
  await expect(page.getByRole('button', { name: 'Save document' })).toBeEnabled();
}

test('tc_gui_003_database_collection_document_crud', async ({ page, admin }) => {
  const errors = watchConsole(page);
  const db = unique();
  await go(page, 'login');
  await signIn(page, ADMIN, adminPassword());
  await expect(page).toHaveURL(/dashboard$/);

  // S05: create a database.
  await go(page, 'data');
  await expect(page.getByRole('heading', { name: 'Databases', level: 1 })).toBeVisible();
  await page.getByRole('button', { name: 'Create database' }).first().click();
  await page.getByLabel('Database name').fill(db);
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/ui/db/${db}$`));

  // S06: create a collection.
  await expect(page.getByText('No collections yet')).toBeVisible();
  await page.getByRole('button', { name: 'Create collection' }).first().click();
  await page.getByLabel('Collection name').fill('orders');
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/ui/db/${db}/c/orders$`));

  // S07 empty, then S08 insert.
  await expect(page.getByText('No documents match')).toBeVisible();
  await page.getByRole('link', { name: 'New document' }).click();
  const text = await plainText(page);
  await text.fill('{"_id": "o1", "total": 5}');
  await page.getByRole('button', { name: 'Insert document' }).click();
  await expect(page).toHaveURL(/\/doc\/%22o1%22$/);
  await expect(page.getByRole('heading', { name: 'Document "o1"' })).toBeVisible();
  await expect(page.getByText('_rev', { exact: true })).toBeVisible();

  // Replace with If-Match; then a concurrent change makes the next save fail with RGN-2009.
  const editor = await plainText(page);
  await expect(editor).toHaveValue(/"total": 5/);
  await editor.fill('{"_id": "o1", "total": 6}');
  // Wait for the save to finish: its answer replaces the editor text, so filling the next
  // version before it arrives would be overwritten (the "stored 6, expected 7" flake).
  await saved(page, () => page.getByRole('button', { name: 'Save document' }).click());
  await expect(editor).toHaveValue(/"total": 6/);
  const res = await admin.put(`/api/v1/databases/${db}/collections/orders/documents/"o1"`, {
    data: { _id: 'o1', total: 100 },
  });
  expect(res.ok(), await res.text()).toBe(true);
  await editor.fill('{"_id": "o1", "total": 7}');
  await page.getByRole('button', { name: 'Save document' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'RGN-2009' })).toBeVisible();
  await saved(page, () => page.getByRole('button', { name: 'Overwrite' }).click());
  await expect(page.getByRole('alert').filter({ hasText: 'RGN-2009' })).toHaveCount(0);
  const stored = await admin.get(`/api/v1/databases/${db}/collections/orders/documents/"o1"`);
  expect(((await stored.json()) as { document: { total: unknown } }).document.total).toBe(7);

  // S07: the grid lists it, a filter that excludes it shows the empty state.
  await page.getByRole('link', { name: 'orders' }).click();
  const grid = page.getByRole('grid', { name: 'Documents' });
  await expect(grid.getByRole('gridcell', { name: 'o1' })).toBeVisible();
  await page.getByLabel('Filter (RGQL expression)').fill('total > 100');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page.getByText('No documents match')).toBeVisible();
  await page.getByRole('button', { name: 'Clear filter' }).first().click();
  await grid.getByRole('gridcell', { name: 'o1' }).click();

  // S08 delete, S07 drop collection, S06 drop database (typed confirmations).
  await page.getByRole('button', { name: 'Delete document' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete document' }).click();
  await expect(page).toHaveURL(new RegExp(`/ui/db/${db}/c/orders$`));
  await expect(page.getByText('No documents match')).toBeVisible();
  await page.getByRole('button', { name: 'Drop collection' }).click();
  const dropColl = page.getByRole('dialog');
  await expect(dropColl.getByRole('button', { name: 'Drop collection' })).toBeDisabled();
  await dropColl.getByLabel('Type "orders" to confirm').fill('orders');
  await dropColl.getByRole('button', { name: 'Drop collection' }).click();
  await expect(page).toHaveURL(new RegExp(`/ui/db/${db}$`));
  await page.getByRole('button', { name: 'Drop database' }).click();
  const dropDb = page.getByRole('dialog');
  await dropDb.getByLabel(`Type "${db}" to confirm`).fill(db);
  await dropDb.getByRole('button', { name: 'Drop database' }).click();
  await expect(page).toHaveURL(/\/ui\/data$/);
  await expect(page.getByRole('gridcell', { name: db })).toHaveCount(0);
  // The browser logs the deliberate RGN-2009 response (412) as a failed resource.
  expect(errors.filter((e) => !e.includes('status of 412'))).toEqual([]);
});

test('tc_gui_003_monaco_loads_under_the_csp_and_edits_json', async ({ page, admin }) => {
  const errors = watchConsole(page);
  const workers: string[] = [];
  page.on('worker', (w) => workers.push(w.url()));
  const db = unique();
  expect((await admin.post('/api/v1/databases', { data: { name: db } })).ok()).toBe(true);
  expect(
    (await admin.post(`/api/v1/databases/${db}/collections`, { data: { name: 'items' } })).ok(),
  ).toBe(true);
  await go(page, 'login');
  await signIn(page, ADMIN, adminPassword());
  await expect(page).toHaveURL(/dashboard$/);
  await go(page, `db/${db}/c/items/new`);

  // The editor, its stylesheet and its JSON worker load from /ui under the server's CSP.
  const monaco = page.locator('.monaco-editor');
  await expect(monaco).toBeVisible();
  await expect(page.locator('link[data-rg-monaco]')).toHaveCount(1);
  await monaco.click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.press('Delete');
  await expect(page.getByText('Invalid JSON', { exact: false })).toBeVisible();
  await page.keyboard.insertText('{"name": "widget"}');
  await expect(page.getByText('Invalid JSON', { exact: false })).toHaveCount(0);
  await expect.poll(() => workers.some((u) => u.includes('/ui/worker-'))).toBe(true);
  await noSeriousViolations(page, 'S08 with Monaco');
  await page.getByRole('button', { name: 'Insert document' }).click();
  await expect(page).toHaveURL(/\/doc\/%7B%22\$oid%22/);
  await expect(page.locator('.monaco-editor')).toContainText('widget');

  // axe on the populated S05–S07 screens.
  await go(page, 'data');
  await expect(page.getByRole('gridcell', { name: db })).toBeVisible();
  await noSeriousViolations(page, 'S05');
  await go(page, `db/${db}`);
  await expect(page.getByRole('gridcell', { name: 'items' })).toBeVisible();
  await noSeriousViolations(page, 'S06');
  await go(page, `db/${db}/c/items`);
  await expect(page.getByRole('gridcell', { name: 'widget' })).toBeVisible();
  await noSeriousViolations(page, 'S07');
  await page.getByRole('button', { name: 'Validator' }).click();
  await expect(page.getByRole('dialog').locator('.monaco-editor')).toBeVisible();
  await noSeriousViolations(page, 'S06 validator');
  expect(errors).toEqual([]);
});
