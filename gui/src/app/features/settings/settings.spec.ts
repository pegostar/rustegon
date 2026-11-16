import { signal } from '@angular/core';
import { render, screen } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { SessionStore } from '../../core/session-store';
import { fromToml, isSecret, kindOf, SettingsPage, toToml } from './settings.page';

const SETTINGS = [
  {
    name: 'auth.scram_iterations',
    value: '600000',
    defaultValue: '600000',
    description: 'PBKDF2 iterations.',
    runtimeMutable: true,
  },
  {
    name: 'storage.encryption_key_env',
    value: '"‹redacted›"',
    defaultValue: '""',
    description: 'KEK variable.',
    runtimeMutable: false,
  },
  {
    name: 'log.format',
    value: '"json"',
    defaultValue: '"text"',
    description: 'Log format.',
    runtimeMutable: false,
  },
];

function setup(get: () => Promise<unknown>, roles = [{ role: 'root', resource: 'cluster' }]) {
  const api = { get: vi.fn(get), request: vi.fn(() => Promise.resolve({})) };
  const user = { user: 'admin', roles, mechanism: 'scram', expiresAtUnixMs: 0 };
  return render(SettingsPage, {
    providers: [
      { provide: ApiClient, useValue: api },
      { provide: SessionStore, useValue: { user: signal(user) } },
    ],
  }).then(() => api);
}

describe('S17 settings page', () => {
  it('tc_gui_017_settings_helpers', () => {
    expect(kindOf('true')).toBe('bool');
    expect(kindOf('600000')).toBe('int');
    expect(kindOf('0.5')).toBe('float');
    expect(kindOf('"text"')).toBe('string');
    expect(kindOf('[1, 2]')).toBe('toml');
    expect(toToml('string', 'a "b"')).toBe('"a \\"b\\""');
    expect(fromToml('string', '"a \\"b\\""')).toBe('a "b"');
    expect(toToml('int', ' 7 ')).toBe('7');
    expect(isSecret(SETTINGS[1])).toBe(true);
    expect(isSecret(SETTINGS[0])).toBe(false);
  });

  it('tc_gui_017_settings_loading', async () => {
    await setup(() => new Promise(() => undefined));
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_017_settings_empty_search', async () => {
    await setup(() => Promise.resolve({ settings: SETTINGS }));
    await screen.findByText('auth.scram_iterations');
    await userEvent.type(screen.getByLabelText('Search settings'), 'nothing-matches');
    expect(await screen.findByText('No matching settings')).toBeTruthy();
  });

  it('tc_gui_017_settings_error', async () => {
    await setup(() => Promise.reject(new ApiError(403, 4002, 'PermissionDenied', 'no', false)));
    expect(await screen.findByText('Insufficient privileges')).toBeTruthy();
  });

  it('tc_gui_017_settings_data_hides_secrets', async () => {
    await setup(() => Promise.resolve({ settings: SETTINGS }));
    expect(await screen.findByText('Secret (hidden)')).toBeTruthy();
    expect(document.body.textContent).not.toContain('‹redacted›');
    expect(screen.getAllByText('Restart required')).toHaveLength(2);
    expect(screen.getByText('Changed')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Change storage.encryption_key_env' })).toBeNull();
  });

  it('tc_gui_017_change_setting', async () => {
    const api = await setup(() => Promise.resolve({ settings: SETTINGS }));
    await userEvent.click(
      await screen.findByRole('button', { name: 'Change auth.scram_iterations' }),
    );
    const input = screen.getByLabelText('Value');
    await userEvent.clear(input);
    await userEvent.type(input, '700000');
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }));
    expect(api.request).toHaveBeenCalledWith('patch', '/api/v1/settings', {
      body: { values: { 'auth.scram_iterations': '700000' } },
    });
  });

  it('tc_gui_017_read_only_without_cluster_manage', async () => {
    await setup(
      () => Promise.resolve({ settings: SETTINGS }),
      [{ role: 'monitor', resource: 'cluster' }],
    );
    await screen.findByText('auth.scram_iterations');
    expect(screen.queryByRole('button', { name: /^Change / })).toBeNull();
  });
});
