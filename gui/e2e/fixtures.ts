import { APIRequestContext, expect, Page, request, test as base } from '@playwright/test';

export const ADMIN = 'admin';

function env(name: string): string {
  const v = process.env[name];
  if (!v)
    throw new Error(
      `${name} is not set: run the suite through playwright.config.ts (global setup)`,
    );
  return v;
}

export const adminPassword = () => env('RGN_E2E_ADMIN_PASSWORD');

/** Navigates within the console: `go(page, 'dashboard')` → <base>/ui/dashboard. */
export async function go(page: Page, path: string): Promise<void> {
  await page.goto(new URL(path, env('RGN_E2E_BASE_URL')).toString());
}

/** Signs in through the S01 form. */
export async function signIn(page: Page, user: string, password: string): Promise<void> {
  await page.getByLabel('User name').fill(user);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

export const test = base.extend<{ admin: APIRequestContext }>({
  // eslint-disable-next-line no-empty-pattern
  baseURL: async ({}, use) => use(env('RGN_E2E_BASE_URL')),
  // Plain http: the single-node default (ADR-034).
  // eslint-disable-next-line no-empty-pattern
  admin: async ({}, use) => {
    const api = `http://${env('RGN_E2E_API')}`;
    const anon = await request.newContext({ baseURL: api });
    const res = await anon.post('/api/v1/auth/login', {
      data: { user: ADMIN, password: adminPassword(), delivery: 'token' },
    });
    expect(res.ok(), await res.text()).toBe(true);
    const { sessionToken } = (await res.json()) as { sessionToken: string };
    await anon.dispose();
    const ctx = await request.newContext({
      baseURL: api,
      extraHTTPHeaders: { authorization: `Bearer ${sessionToken}` },
    });
    await use(ctx);
    await ctx.dispose();
  },
});

/** Creates a password user through the REST API (POST /users). */
export async function createUser(
  admin: APIRequestContext,
  name: string,
  password: string,
  roles: { role: string; resource?: string }[],
  mustChangePassword = false,
): Promise<void> {
  const res = await admin.post('/api/v1/users', {
    data: { name, password, roles, mustChangePassword },
  });
  expect(res.ok(), await res.text()).toBe(true);
}

export { expect };
