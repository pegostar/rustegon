import { ADMIN, adminPassword, expect, go, signIn, test } from './fixtures';

// TC-INS-009 (NFR-USE-001, AC-INS-004): the last step of the scripted walk-through from a
// release archive. scripts/walkthrough.sh unpacks the archive, points RUSTEGON_BIN_DIR at it
// (global setup runs its `rustegon init` and `rustegond`) and times the whole run.
test('tc_ins_009_admin_signs_in_to_the_console_of_the_archive', async ({ page }) => {
  test.skip(!process.env['RGN_E2E_WALKTHROUGH'], 'run by scripts/walkthrough.sh');
  await go(page, '');
  await expect(page).toHaveURL(/\/ui\/login/);
  await signIn(page, ADMIN, adminPassword());
  await expect(page.getByRole('button', { name: ADMIN })).toBeVisible();
  await expect(page).not.toHaveURL(/\/ui\/login/);
});
