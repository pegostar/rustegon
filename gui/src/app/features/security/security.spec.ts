import { ApplicationRef, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { render, screen } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { Me, SessionStore } from '../../core/session-store';
import { ApiKeysPage } from './api-keys.page';
import { formatGrant, generatePassword, parseGrants } from './common';
import {
  closesCycle,
  effectivePrivileges,
  formatPrivileges,
  parsePrivileges,
  RolesPage,
} from './roles.page';
import { UsersPage } from './users.page';

const ADMIN: Me = {
  user: 'admin',
  roles: [{ role: 'root', resource: 'cluster' }],
  mechanism: 'scram',
  expiresAtUnixMs: 0,
};
const unavailable = () => new ApiError(503, 3002, 'Unavailable', 'down', true, {}, 'tr-1');
const never = () => new Promise<never>(() => undefined);

/** `get` answers per path; `request` records mutations. */
function mockApi(get: (path: string) => Promise<unknown>) {
  return {
    get: vi.fn((path: string) => get(path)),
    request: vi.fn<(...args: unknown[]) => Promise<unknown>>(() =>
      Promise.resolve({ secret: 'rgn_k1_s3cr3t' }),
    ),
  };
}

async function renderPage(component: unknown, api: ReturnType<typeof mockApi>) {
  return render(component as typeof UsersPage, {
    providers: [
      provideRouter([]),
      { provide: ApiClient, useValue: api },
      { provide: SessionStore, useValue: { user: signal(ADMIN) } },
    ],
  });
}

/** Types into the typed-confirmation dialog and confirms (plain DOM events, see shared.spec). */
async function confirmTyped(name: string, label: string) {
  const ok = (await screen.findByRole('button', { name: label })) as HTMLButtonElement;
  const input = screen.getByRole('textbox', {
    name: `Type "${name}" to confirm`,
  }) as HTMLInputElement;
  expect(ok.disabled).toBe(true);
  input.value = name;
  input.dispatchEvent(new Event('input'));
  await TestBed.inject(ApplicationRef).whenStable();
  expect(ok.disabled).toBe(false);
  ok.click();
}

describe('S14–S16 helpers', () => {
  it('tc_gui_006_role_references_round_trip', () => {
    expect(parseGrants('root, read@shop read_write@shop.orders')).toEqual([
      { role: 'root', resource: '' },
      { role: 'read', resource: 'database:shop' },
      { role: 'read_write', resource: 'collection:shop.orders' },
    ]);
    expect(parseGrants('read@')).toBeNull();
    expect(parseGrants('a b@c@d')).toBeNull();
    expect(parseGrants('')).toEqual([]);
    expect(formatGrant({ role: 'root', resource: 'cluster' })).toBe('root');
    expect(formatGrant({ role: 'read', resource: 'database:*' })).toBe('read');
    expect(formatGrant({ role: 'read', resource: 'database:shop' })).toBe('read@shop');
    expect(formatGrant({ role: 'read', resource: 'collection:shop.o' })).toBe('read@shop.o');
  });

  it('tc_gui_006_generated_passwords_are_random_and_long', () => {
    const a = generatePassword();
    expect(a).toHaveLength(24);
    expect(generatePassword()).not.toBe(a);
  });

  it('tc_gui_006_privileges_text_round_trips_and_rejects_unknown_actions', () => {
    const ps = parsePrivileges('database:shop: find, insert\n\ncluster: cluster_view');
    expect(ps).toEqual([
      { resource: 'database:shop', actions: ['find', 'insert'] },
      { resource: 'cluster', actions: ['cluster_view'] },
    ]);
    expect(formatPrivileges(ps ?? [])).toBe('database:shop: find, insert\ncluster: cluster_view');
    expect(parsePrivileges('cluster: fly')).toBeNull();
    expect(parsePrivileges('no actions')).toBeNull();
  });

  it('tc_gui_006_inheritance_cycles_are_detected', () => {
    const roles = [
      { name: 'a', inherits: ['b'] },
      { name: 'b', inherits: ['c@shop'] },
      { name: 'c', inherits: [] },
    ];
    expect(closesCycle('c', ['a'], roles)).toBe(true);
    expect(closesCycle('c', ['c'], roles)).toBe(true);
    expect(closesCycle('d', ['a'], roles)).toBe(false);
  });

  it('tc_gui_006_effective_privileges_follow_inheritance', () => {
    const rows = effectivePrivileges(
      [{ role: 'app', resource: '' }],
      [
        {
          name: 'app',
          inherits: ['read@shop'],
          privileges: [{ resource: 'cluster', actions: ['backup'] }],
        },
        {
          name: 'read',
          builtIn: true,
          privileges: [{ resource: 'database:*', actions: ['find'] }],
        },
      ],
    );
    expect(rows).toEqual([
      { grant: 'app', via: 'app', resource: 'cluster', actions: 'backup' },
      { grant: 'app', via: 'app → read@shop', resource: 'database:*', actions: 'find' },
    ]);
  });
});

describe('S14 users page', () => {
  const users = [
    {
      name: 'admin',
      roles: [{ role: 'root', resource: 'cluster' }],
      disabled: false,
      mustChangePassword: false,
      createdAtUnixMs: 0,
    },
    {
      name: 'bob',
      roles: [{ role: 'read', resource: 'database:shop' }],
      disabled: true,
      mustChangePassword: true,
      createdAtUnixMs: 0,
    },
  ];

  it('tc_gui_006_users_loading', async () => {
    await renderPage(UsersPage, mockApi(never));
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_006_users_empty', async () => {
    await renderPage(
      UsersPage,
      mockApi(() => Promise.resolve({ users: [] })),
    );
    expect(await screen.findByText('No users')).toBeTruthy();
  });

  it('tc_gui_006_users_error', async () => {
    await renderPage(
      UsersPage,
      mockApi(() => Promise.reject(unavailable())),
    );
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeTruthy();
  });

  it('tc_gui_006_users_data_protects_self_and_last_root', async () => {
    await renderPage(
      UsersPage,
      mockApi(() => Promise.resolve({ users })),
    );
    expect(await screen.findByRole('rowheader', { name: 'bob' })).toBeTruthy();
    expect(screen.getByText('read@shop')).toBeTruthy();
    expect(screen.getByText('Must change password')).toBeTruthy();
    const del = (n: string) =>
      screen.getByRole('button', { name: `Delete ${n}` }) as HTMLButtonElement;
    expect(del('admin').disabled).toBe(true);
    expect(del('bob').disabled).toBe(false);
  });

  it('tc_gui_006_create_user_with_generated_password', async () => {
    const api = mockApi(() => Promise.resolve({ users }));
    await renderPage(UsersPage, api);
    await userEvent.click(await screen.findByRole('button', { name: 'New user' }));
    await userEvent.type(screen.getByLabelText('User name'), 'carol');
    await userEvent.click(screen.getByRole('button', { name: 'Generate password' }));
    const pw = screen.getByLabelText('Initial password') as HTMLInputElement;
    expect(pw.type).toBe('text');
    expect(pw.value).toHaveLength(24);
    const secret = pw.value;
    await userEvent.type(screen.getByLabelText('Roles'), 'read@shop');
    await userEvent.click(screen.getByRole('button', { name: 'Create user' }));
    expect(api.request).toHaveBeenCalledWith('post', '/api/v1/users', {
      body: {
        name: 'carol',
        password: secret,
        mustChangePassword: true,
        roles: [{ role: 'read', resource: 'database:shop' }],
      },
    });
    // The form and the secret are gone after saving.
    expect(screen.queryByLabelText('Initial password')).toBeNull();
    expect(document.body.innerHTML).not.toContain(secret);
  });

  it('tc_gui_006_delete_user_requires_typed_name', async () => {
    const api = mockApi(() => Promise.resolve({ users }));
    await renderPage(UsersPage, api);
    (await screen.findByRole('button', { name: 'Delete bob' })).click();
    await confirmTyped('bob', 'Delete');
    await vi.waitFor(() =>
      expect(api.request).toHaveBeenCalledWith('delete', '/api/v1/users/{name}', {
        path: { name: 'bob' },
      }),
    );
  });
});

describe('S15 roles page', () => {
  const roles = [
    { name: 'read', builtIn: true, privileges: [{ resource: 'database:*', actions: ['find'] }] },
    { name: 'app', builtIn: false, inherits: ['read@shop'], privileges: [] },
  ];

  it('tc_gui_006_roles_loading', async () => {
    await renderPage(RolesPage, mockApi(never));
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_006_roles_empty', async () => {
    await renderPage(
      RolesPage,
      mockApi(() => Promise.resolve({ roles: [] })),
    );
    expect(await screen.findByText('No roles')).toBeTruthy();
  });

  it('tc_gui_006_roles_error', async () => {
    await renderPage(
      RolesPage,
      mockApi(() => Promise.reject(unavailable())),
    );
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
  });

  it('tc_gui_006_roles_data_built_in_read_only', async () => {
    await renderPage(
      RolesPage,
      mockApi(() => Promise.resolve({ roles })),
    );
    expect(await screen.findByRole('rowheader', { name: 'app' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Drop app' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Drop read' })).toBeNull();
    expect(screen.getByText('Built-in')).toBeTruthy();
  });

  it('tc_gui_006_create_role', async () => {
    const api = mockApi(() => Promise.resolve({ roles }));
    await renderPage(RolesPage, api);
    await userEvent.click(await screen.findByRole('button', { name: 'New role' }));
    await userEvent.type(screen.getByLabelText('Role name'), 'auditor');
    await userEvent.type(screen.getByLabelText('Privileges'), 'cluster: audit_view');
    await userEvent.type(screen.getByLabelText('Inherits'), 'app');
    await userEvent.click(screen.getByRole('button', { name: 'Save role' }));
    expect(api.request).toHaveBeenCalledWith('post', '/api/v1/roles', {
      body: {
        name: 'auditor',
        privileges: [{ resource: 'cluster', actions: ['audit_view'] }],
        inherits: ['app'],
      },
    });
  });
});

describe('S16 API keys page', () => {
  const key = {
    keyId: 'k1',
    description: 'reporting',
    user: 'admin',
    roles: [{ role: 'read', resource: 'database:shop' }],
    ipAllowlist: [],
    createdAtUnixMs: 0,
  };

  it('tc_gui_006_keys_loading', async () => {
    await renderPage(ApiKeysPage, mockApi(never));
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_006_keys_empty', async () => {
    await renderPage(
      ApiKeysPage,
      mockApi(() => Promise.resolve({ keys: [] })),
    );
    expect(await screen.findByText('No API keys')).toBeTruthy();
  });

  it('tc_gui_006_keys_error', async () => {
    await renderPage(
      ApiKeysPage,
      mockApi(() => Promise.reject(unavailable())),
    );
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
  });

  it('tc_gui_006_keys_data_and_secret_shown_once', async () => {
    const api = mockApi(() => Promise.resolve({ keys: [key] }));
    await renderPage(ApiKeysPage, api);
    expect(await screen.findByText('k1')).toBeTruthy();
    expect(api.get).toHaveBeenCalledWith('/api/v1/api-keys', { query: { user: 'admin' } });
    await userEvent.click(screen.getByRole('button', { name: 'New API key' }));
    expect((screen.getByLabelText('Roles (scope)') as HTMLInputElement).value).toBe('root');
    await userEvent.type(screen.getByLabelText('Description'), 'ci');
    await userEvent.click(screen.getByRole('button', { name: 'Create key' }));
    expect(api.request).toHaveBeenCalledWith('post', '/api/v1/api-keys', {
      body: {
        description: 'ci',
        roles: [{ role: 'root', resource: '' }],
        ipAllowlist: [],
        expiresAtUnixMs: null,
        user: null,
      },
    });
    expect(await screen.findByText('rgn_k1_s3cr3t')).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: 'I have stored the key' }));
    expect(screen.queryByText('rgn_k1_s3cr3t')).toBeNull();
    expect(JSON.stringify(localStorage)).not.toContain('s3cr3t');
    expect(JSON.stringify(sessionStorage)).not.toContain('s3cr3t');
  });

  it('tc_gui_006_revoke_requires_typed_key_id', async () => {
    const api = mockApi(() => Promise.resolve({ keys: [key] }));
    await renderPage(ApiKeysPage, api);
    (await screen.findByRole('button', { name: 'Revoke k1' })).click();
    await confirmTyped('k1', 'Revoke');
    await vi.waitFor(() =>
      expect(api.request).toHaveBeenCalledWith('delete', '/api/v1/api-keys/{key_id}', {
        path: { key_id: 'k1' },
      }),
    );
  });
});
