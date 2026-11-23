import { signal } from '@angular/core';
import { render, screen, within } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { SessionStore } from '../../core/session-store';
import {
  fromToml,
  isSecret,
  RESTART_POLL_WAIT,
  SettingsPage,
  tabOf,
  toToml,
  tomlItems,
} from './settings.page';

const SETTINGS = [
  {
    name: 'auth.scram_iterations',
    value: '600000',
    defaultValue: '600000',
    description: 'PBKDF2 iterations.',
    runtimeMutable: true,
    kind: 'integer',
    min: 100000,
    max: 10000000,
  },
  {
    name: 'lockout.max_failures',
    value: '10',
    defaultValue: '10',
    description: 'Failures before a lock.',
    runtimeMutable: false,
    kind: 'integer',
    min: 1,
    max: 1000,
  },
  {
    name: 'log.level',
    value: '"info"',
    defaultValue: '"info"',
    description: 'Log level.',
    runtimeMutable: false,
    kind: 'enum',
    choices: ['debug', 'info', 'warn'],
  },
  {
    name: 'node.data_dir',
    value: "'C:\\data'",
    defaultValue: '"data"',
    description: 'Data directory.',
    runtimeMutable: false,
    kind: 'path',
    locked: 'manual',
  },
  {
    name: 'storage.encryption_key_env',
    value: '"‹redacted›"',
    defaultValue: '""',
    description: 'KEK variable.',
    runtimeMutable: false,
    kind: 'string',
    locked: 'secret',
  },
];

function setup(
  list: () => Promise<unknown>,
  roles = [{ role: 'root', resource: 'cluster' }],
  ready: () => Promise<unknown> = () => Promise.resolve({}),
) {
  const api = {
    get: vi.fn((path: string) => (path === '/api/v1/health/ready' ? ready() : list())),
    request: vi.fn<(...args: unknown[]) => Promise<unknown>>(() =>
      Promise.resolve({ settings: [] }),
    ),
  };
  const user = { user: 'admin', roles, mechanism: 'scram', expiresAtUnixMs: 0 };
  return render(SettingsPage, {
    providers: [
      { provide: ApiClient, useValue: api },
      { provide: SessionStore, useValue: { user: signal(user) } },
      { provide: RESTART_POLL_WAIT, useValue: () => Promise.resolve() },
    ],
  }).then(() => api);
}

describe('S17 settings page (PD-230)', () => {
  it('tc_gui_017_settings_helpers', () => {
    expect(tabOf('auth.scram_iterations')).toBe('access');
    expect(tabOf('listen.http')).toBe('network');
    expect(tabOf('backup.allowed_destinations')).toBe('backup');
    expect(tabOf('future.thing')).toBe('other');
    expect(toToml('string', 'a "b"')).toBe('"a \\"b\\""');
    expect(fromToml('string', '"a \\"b\\""')).toBe('a "b"');
    expect(fromToml('path', "'C:\\data'")).toBe('C:\\data');
    expect(toToml('path', 'C:\\data')).toBe('"C:\\\\data"');
    expect(toToml('integer', ' 7 ')).toBe('7');
    expect(tomlItems(`['/a', "/b"]`)).toEqual(['/a', '/b']);
    expect(fromToml('string_list', `['/a', "/b"]`)).toBe('/a, /b');
    expect(toToml('string_list', '/a, ,/b')).toBe('["/a", "/b"]');
    expect(isSecret(SETTINGS[4] as never)).toBe(true);
    expect(isSecret(SETTINGS[0] as never)).toBe(false);
  });

  it('tc_gui_017_settings_loading', async () => {
    await setup(() => new Promise(() => undefined));
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_017_settings_error', async () => {
    await setup(() => Promise.reject(new ApiError(403, 4002, 'PermissionDenied', 'no', false)));
    expect(await screen.findByText('Insufficient privileges')).toBeTruthy();
  });

  it('tc_gui_017_settings_are_grouped_in_tabs_with_locked_ones_explained', async () => {
    await setup(() => Promise.resolve({ settings: SETTINGS }));
    const tabs = await screen.findAllByRole('tab');
    expect(tabs.map((t) => t.textContent?.trim())).toEqual([
      'General',
      'Access and security',
      'Storage',
    ]);
    // General: the log level is a choice; the data directory is locked with its reason.
    expect((screen.getByLabelText('Log level') as HTMLSelectElement).value).toBe('info');
    expect(screen.queryByLabelText('Data directory')).toBeNull();
    expect(screen.getByText(/Change it in rustegon.toml by hand/)).toBeTruthy();
    await userEvent.click(screen.getByRole('tab', { name: 'Storage' }));
    expect(await screen.findByText(/Secret: hidden/)).toBeTruthy();
    expect(document.body.textContent).not.toContain('‹redacted›');
  });

  it('tc_gui_017_settings_show_a_localized_label_and_fall_back_to_the_server_text', async () => {
    const future = { ...SETTINGS[0], name: 'future.thing', description: 'From the server.' };
    await setup(() => Promise.resolve({ settings: [SETTINGS[2], future] }));
    // Known setting: the console's label and description, with the key beside them (PD-231).
    expect(await screen.findByLabelText('Log level')).toBeTruthy();
    expect(screen.getByText('log.level')).toBeTruthy();
    expect(screen.getByText(/Log filter, for example/)).toBeTruthy();
    // A setting the console does not know yet: its key and the server's description.
    await userEvent.click(screen.getByRole('tab', { name: 'Other' }));
    expect(await screen.findByLabelText('future.thing')).toBeTruthy();
    expect(screen.getByText('From the server.')).toBeTruthy();
  });

  it('tc_gui_017_changes_are_saved_together_and_validated', async () => {
    const api = await setup(() => Promise.resolve({ settings: SETTINGS }));
    await userEvent.click(await screen.findByRole('tab', { name: 'Access and security' }));
    const save = screen.getByRole('button', { name: /^Save changes/ });
    expect((save as HTMLButtonElement).disabled).toBe(true);
    const iterations = screen.getByLabelText('Password hashing iterations');
    await userEvent.clear(iterations);
    await userEvent.type(iterations, '5');
    expect(screen.getByText(/Enter a whole number from 100000 to 10000000/)).toBeTruthy();
    expect((save as HTMLButtonElement).disabled).toBe(true);
    await userEvent.clear(iterations);
    await userEvent.type(iterations, '700000');
    const failures = screen.getByLabelText('Failed logins before lockout');
    await userEvent.clear(failures);
    await userEvent.type(failures, '4');
    await userEvent.click(screen.getByRole('button', { name: 'Save changes (2)' }));
    expect(api.request).toHaveBeenCalledWith('patch', '/api/v1/settings', {
      body: { values: { 'auth.scram_iterations': '700000', 'lockout.max_failures': '4' } },
    });
  });

  it('tc_gui_017_pending_settings_offer_a_restart_that_waits_for_the_node', async () => {
    let down = true;
    const pending = SETTINGS.map((s) =>
      s.name === 'lockout.max_failures' ? { ...s, pendingValue: '4' } : s,
    );
    const api = await setup(
      () => Promise.resolve({ settings: pending }),
      undefined,
      () => {
        // Not ready once (stopping), then ready again.
        const was = down;
        down = false;
        return was ? Promise.reject(new Error('down')) : Promise.resolve({});
      },
    );
    const panel = await screen.findByRole('region', { name: 'Changes waiting for a restart' });
    expect(within(panel).getByText('lockout.max_failures')).toBeTruthy();
    await userEvent.click(within(panel).getByRole('button', { name: 'Restart the database' }));
    const dialog = await screen.findByRole('dialog');
    within(dialog).getByRole('button', { name: 'Restart' }).click();
    await vi.waitFor(() =>
      expect(api.request).toHaveBeenCalledWith('post', '/api/v1/node/restart', {}),
    );
    await vi.waitFor(() =>
      expect(api.get).toHaveBeenCalledWith('/api/v1/health/ready', { skipAuthRedirect: true }),
    );
    // Reloaded after the node answered again.
    await vi.waitFor(() =>
      expect(api.get.mock.calls.filter((c) => c[0] === '/api/v1/settings').length).toBe(2),
    );
  });

  it('tc_gui_017_failed_restart_is_reported', async () => {
    await setup(() =>
      Promise.resolve({ settings: SETTINGS, lastRestartError: 'audit I/O error on /x' }),
    );
    expect((await screen.findByRole('alert')).textContent).toContain('audit I/O error on /x');
  });

  it('tc_gui_017_read_only_without_cluster_manage', async () => {
    await setup(
      () => Promise.resolve({ settings: SETTINGS }),
      [{ role: 'monitor', resource: 'cluster' }],
    );
    await screen.findAllByRole('tab');
    expect(screen.queryByLabelText('Log level')).toBeNull();
    expect(screen.queryByRole('button', { name: /^Save changes/ })).toBeNull();
    expect(screen.getAllByText(/Read only for your role/).length).toBeGreaterThan(0);
  });
});
