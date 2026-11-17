import { ApplicationRef } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { render, screen, within } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { BackupsPage } from './backups.page';
import { tomlStrings } from './common';
import { quote, RESTORE_POLL_WAIT, RestorePage, restoreCommand, RestoreSpec } from './restore.page';

const unavailable = () => new ApiError(503, 3002, 'Unavailable', 'down', true, {}, 'tr-1');
const never = () => new Promise<never>(() => undefined);
const backup = {
  backupId: 'b-20261113',
  createdAtUnixMs: 0,
  encryption: 'plaintext',
  fileCount: 3,
  formatVersion: 1,
  sourceClusterId: 'c',
  sourceNodeId: 'n1',
  sourceServerVersion: '0.1.0',
  totalBytes: 2048,
  consistency: {
    appliedIndex: 1,
    appliedTerm: 1,
    storageSeqno: 1,
    timestamp: { wallNs: '1', logical: 0 },
  },
};

function mockApi(
  routes: Partial<Record<string, () => Promise<unknown>>>,
  fallback: () => Promise<unknown> = () => Promise.resolve({}),
) {
  return {
    get: vi.fn((path: string) => (routes[path] ?? fallback)()),
    request: vi.fn<(...args: unknown[]) => Promise<unknown>>(() =>
      Promise.resolve({ warnings: [] }),
    ),
  };
}

const renderWith = (
  component: typeof BackupsPage | typeof RestorePage,
  api: ReturnType<typeof mockApi>,
  inputs = {},
  wait: () => Promise<void> = () => Promise.resolve(),
) =>
  render(component as typeof BackupsPage, {
    providers: [
      provideRouter([]),
      { provide: ApiClient, useValue: api },
      { provide: RESTORE_POLL_WAIT, useValue: wait },
    ],
    inputs,
  });

const settings = () =>
  Promise.resolve({
    settings: [
      {
        name: 'node.data_dir',
        value: '"/var/lib/rustegon"',
        defaultValue: '""',
        description: '',
        runtimeMutable: false,
      },
      {
        name: 'backup.allowed_destinations',
        value: '["s3://bkp/prod"]',
        defaultValue: '[]',
        description: '',
        runtimeMutable: false,
      },
    ],
  });

describe('S22 backups page', () => {
  it('tc_gui_007_backups_loading', async () => {
    await renderWith(BackupsPage, mockApi({ '/api/v1/settings': settings }, never));
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_007_backups_empty_with_suggested_destination', async () => {
    const api = mockApi({
      '/api/v1/settings': settings,
      '/api/v1/snapshots': () => Promise.resolve({ snapshots: [] }),
      '/api/v1/backups': () => Promise.resolve({ backups: [], unreadable: [] }),
    });
    await renderWith(BackupsPage, api);
    expect(await screen.findByText('No snapshots')).toBeTruthy();
    const dest = screen.getByLabelText('Backup destination') as HTMLInputElement;
    await vi.waitFor(() => expect(dest.value).toBe('/var/lib/rustegon/backups'));
    await userEvent.click(screen.getByRole('button', { name: 'Show backups' }));
    expect(await screen.findByText('No backups at this destination')).toBeTruthy();
    expect(api.get).toHaveBeenCalledWith('/api/v1/backups', {
      query: { destination: '/var/lib/rustegon/backups' },
    });
  });

  it('tc_gui_007_backups_error', async () => {
    await renderWith(
      BackupsPage,
      mockApi({
        '/api/v1/settings': settings,
        '/api/v1/snapshots': () => Promise.reject(unavailable()),
      }),
    );
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
  });

  it('tc_gui_007_backups_data_start_and_verify', async () => {
    const api = mockApi({
      '/api/v1/settings': settings,
      '/api/v1/snapshots': () =>
        Promise.resolve({
          snapshots: [
            {
              name: 'before-upgrade',
              createdAtUnixMs: 0,
              fileCount: 2,
              totalBytes: 10,
              consistency: backup.consistency,
            },
          ],
        }),
      '/api/v1/backups': () => Promise.resolve({ backups: [backup], unreadable: [] }),
    });
    await renderWith(BackupsPage, api);
    expect(await screen.findByText('before-upgrade')).toBeTruthy();
    const dest = screen.getByLabelText('Backup destination') as HTMLInputElement;
    await vi.waitFor(() => expect(dest.value).not.toBe(''));
    await userEvent.click(screen.getByRole('button', { name: 'Start backup' }));
    expect(api.request).toHaveBeenCalledWith('post', '/api/v1/backups', {
      body: { destination: '/var/lib/rustegon/backups' },
      timeoutMs: 3_600_000,
    });
    expect(await screen.findByText('b-20261113')).toBeTruthy();
    api.request.mockResolvedValueOnce({ backup, filesChecked: 3, bytesHashed: 2048 });
    await userEvent.click(screen.getByRole('button', { name: 'Deep verify' }));
    expect(await screen.findByText(/3 files checked, 2048 bytes hashed/)).toBeTruthy();
  });

  it('tc_gui_007_delete_snapshot_requires_typed_name', async () => {
    const api = mockApi({
      '/api/v1/settings': settings,
      '/api/v1/snapshots': () =>
        Promise.resolve({
          snapshots: [
            {
              name: 's1',
              createdAtUnixMs: 0,
              fileCount: 2,
              totalBytes: 10,
              consistency: backup.consistency,
            },
          ],
        }),
    });
    await renderWith(BackupsPage, api);
    (await screen.findByRole('button', { name: 'Delete snapshot s1' })).click();
    const ok = (await screen.findByRole('button', { name: 'Delete' })) as HTMLButtonElement;
    expect(ok.disabled).toBe(true);
    const input = screen.getByRole('textbox', { name: 'Type "s1" to confirm' }) as HTMLInputElement;
    input.value = 's1';
    input.dispatchEvent(new Event('input'));
    await TestBed.inject(ApplicationRef).whenStable();
    ok.click();
    await vi.waitFor(() =>
      expect(api.request).toHaveBeenCalledWith('delete', '/api/v1/snapshots/{name}', {
        path: { name: 's1' },
      }),
    );
  });

  it('tc_gui_007_reads_toml_destinations', () => {
    expect(tomlStrings('"C:\\\\data"')).toEqual(['C:\\data']);
    expect(tomlStrings("'/srv/x'")).toEqual(['/srv/x']);
    expect(tomlStrings('["a", "b"]')).toEqual(['a', 'b']);
    expect(tomlStrings('42')).toEqual([]);
    expect(tomlStrings('{ bad')).toEqual([]);
  });
});

describe('S23 restore command', () => {
  const base: RestoreSpec = {
    source: 'backup',
    shell: 'posix',
    from: '/srv/backups',
    id: 'b-1',
    into: '/srv/restored',
    toTime: '',
    archive: '',
    snapshot: '',
    dataDir: '',
    kek: 'none',
    kekValue: '',
    s3Credentials: '',
  };

  it('tc_gui_007_quotes_arguments_for_each_shell', () => {
    expect(quote('/srv/a', 'posix')).toBe('/srv/a');
    expect(quote("it's $HOME; rm -rf /", 'posix')).toBe(`'it'\\''s $HOME; rm -rf /'`);
    expect(quote("it's $env:X `n", 'powershell')).toBe(`'it''s $env:X \`n'`);
    expect(quote('a\u2019b', 'powershell')).toBe(`'a\u2019\u2019b'`);
    expect(quote('-x', 'posix')).toBe(`'-x'`);
    expect(quote('@args', 'powershell')).toBe(`'@args'`);
    expect(quote('C:\\Program Files\\data', 'powershell')).toBe(`'C:\\Program Files\\data'`);
  });

  it('tc_gui_007_backup_restore_command', () => {
    expect(restoreCommand(base)).toBe(
      'rustegon backup restore --from /srv/backups --id b-1 --into /srv/restored',
    );
    const pitr = restoreCommand({
      ...base,
      from: 's3://bkp/prod',
      id: '',
      toTime: '2026-11-10T09:30:00Z',
      kek: 'env',
      kekValue: 'RGN_KEK',
      s3Credentials: '/etc/rustegon/s3 creds.json',
    });
    expect(pitr).toBe(
      "rustegon backup restore --from s3://bkp/prod --into /srv/restored --to-time 2026-11-10T09:30:00.000Z --s3-credentials-file '/etc/rustegon/s3 creds.json' --encryption-key-env RGN_KEK",
    );
  });

  it('tc_gui_007_snapshot_restore_command_references_the_key_file', () => {
    expect(
      restoreCommand({
        ...base,
        source: 'snapshot',
        snapshot: 's1',
        dataDir: '/var/lib/rustegon',
        kek: 'file',
        kekValue: '/etc/kek',
      }),
    ).toBe(
      'rustegon snapshot restore --data-dir /var/lib/rustegon --name s1 --encryption-key-file /etc/kek',
    );
  });
});

describe('S23 restore page', () => {
  it('tc_gui_007_restore_page_prefills_and_generates_the_command', async () => {
    const api = mockApi({ '/api/v1/backups': () => Promise.resolve({ backups: [backup] }) });
    await renderWith(RestorePage, api, { from: '/srv/backups', id: 'b-1' });
    await userEvent.selectOptions(screen.getByLabelText('Restore from'), 'backup');
    expect(screen.queryByRole('heading', { name: 'Restore command' })).toBeNull();
    await userEvent.type(screen.getByLabelText('New data directory'), '/srv/new');
    await userEvent.click(screen.getByRole('button', { name: 'Generate command' }));
    const code = await screen.findByText(/rustegon backup restore/);
    expect(code.textContent).toContain('--from /srv/backups --id b-1 --into /srv/new');
    // Offline: nothing is sent to the server to restore.
    expect(api.request).not.toHaveBeenCalled();
  });

  it('tc_gui_007_restore_page_lists_backups_and_shows_errors', async () => {
    const api = mockApi({ '/api/v1/backups': () => Promise.reject(unavailable()) });
    await renderWith(RestorePage, api, { from: '/srv/backups' });
    await userEvent.click(screen.getByRole('button', { name: 'List backups at this destination' }));
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
    await userEvent.selectOptions(screen.getByLabelText('Restore from'), 'backup');
    await userEvent.click(screen.getByRole('button', { name: 'Generate command' }));
    expect(screen.getByText('Enter a backup id or a point in time.')).toBeTruthy();
  });

  it('tc_gui_007_restore_online_is_the_default_and_hides_offline_fields', async () => {
    const api = mockApi({
      '/api/v1/settings': settings,
      '/api/v1/backups': () => Promise.resolve({ backups: [backup], unreadable: [] }),
    });
    await renderWith(RestorePage, api);
    expect((screen.getByLabelText('Restore from') as HTMLSelectElement).value).toBe('online');
    const dest = screen.getByLabelText('Backup destination') as HTMLInputElement;
    await vi.waitFor(() => expect(dest.value).toBe('/var/lib/rustegon/backups'));
    await vi.waitFor(() =>
      expect(api.get).toHaveBeenCalledWith('/api/v1/backups', {
        query: { destination: '/var/lib/rustegon/backups' },
      }),
    );
    for (const label of [
      'New data directory',
      'Point in time (optional)',
      'Encryption key (encrypted backups)',
      'Shell',
    ])
      expect(screen.queryByLabelText(label)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Generate command' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Restore' })).toBeTruthy();
  });

  it('tc_gui_007_restore_online_prefills_the_backup_from_the_link', async () => {
    const api = mockApi({
      '/api/v1/backups': () => Promise.resolve({ backups: [backup], unreadable: [] }),
    });
    await renderWith(RestorePage, api, { from: '/srv/backups', id: 'b-20261113' });
    const choice = screen.getByLabelText('Backup to restore') as HTMLSelectElement;
    await vi.waitFor(() => expect(choice.value).toBe('b-20261113'));
    expect(within(choice).getByRole('option', { name: /b-20261113 .* 2.0 KiB/ })).toBeTruthy();
  });

  it('tc_gui_007_restore_online_confirms_restores_and_follows_the_node', async () => {
    let up = false;
    const api = mockApi({
      '/api/v1/backups': () => Promise.resolve({ backups: [backup], unreadable: [] }),
      '/api/v1/health/ready': () =>
        up ? Promise.resolve({ status: 'ready' }) : Promise.reject(unavailable()),
    });
    const gates: (() => void)[] = [];
    const wait = () => new Promise<void>((resolve) => gates.push(resolve));
    const tick = async () => {
      await vi.waitFor(() => expect(gates.length).toBe(1));
      gates.shift()?.();
    };
    await renderWith(RestorePage, api, { from: '/srv/backups' }, wait);
    const choice = screen.getByLabelText('Backup to restore');
    await screen.findByRole('option', { name: /b-20261113/ });
    await userEvent.selectOptions(choice, 'b-20261113');
    await userEvent.click(screen.getByRole('button', { name: 'Restore' }));

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('store.pre-restore-');
    // A plain confirmation: nothing to type (owner decision).
    expect(within(dialog).queryByRole('textbox')).toBeNull();
    const ok = within(dialog).getByRole('button', { name: 'Restore' }) as HTMLButtonElement;
    expect(ok.disabled).toBe(false);
    ok.click();
    await vi.waitFor(() =>
      expect(api.request).toHaveBeenCalledWith('post', '/api/v1/backups/{backup_id}/restore', {
        path: { backup_id: 'b-20261113' },
        body: { destination: '/srv/backups' },
        timeoutMs: 3_600_000,
      }),
    );
    expect(
      await screen.findByText(
        'Restore in progress: the node stops serving and restores the backup.',
      ),
    ).toBeTruthy();

    // Ready before it went down does not count; then down; then ready again.
    up = true;
    await tick();
    up = false;
    await tick();
    expect(screen.queryByText(/Restore completed/)).toBeNull();
    up = true;
    await tick();
    expect(
      await screen.findByText(
        'Restore completed. Sign in again with the credentials of the backup.',
      ),
    ).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Sign in' }).getAttribute('href')).toBe('/login');
    expect(api.get).toHaveBeenCalledWith('/api/v1/health/ready', { skipAuthRedirect: true });
    expect(api.request).toHaveBeenCalledWith('post', '/api/v1/auth/logout', {
      skipAuthRedirect: true,
    });
  });

  it('tc_gui_007_restore_online_requires_a_backup', async () => {
    const api = mockApi({
      '/api/v1/backups': () => Promise.resolve({ backups: [], unreadable: [] }),
    });
    await renderWith(RestorePage, api, { from: '/srv/backups' });
    await userEvent.click(screen.getByRole('button', { name: 'Restore' }));
    expect(await screen.findByText('Choose a backup.')).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('tc_gui_007_restore_shows_the_last_completed_restore', async () => {
    const api = mockApi({
      '/api/v1/restore-status': () =>
        Promise.resolve({
          state: 'completed',
          backupId: 'b-old',
          finishedAt: 0,
          previousStore: 'store.pre-restore-20261117T100000Z',
        }),
    });
    await renderWith(RestorePage, api);
    expect(await screen.findByText(/backup b-old completed on/)).toBeTruthy();
    expect(
      screen.getByText(/kept on the server as store.pre-restore-20261117T100000Z/),
    ).toBeTruthy();
  });

  it('tc_gui_007_restore_shows_the_last_failed_restore', async () => {
    const api = mockApi({
      '/api/v1/restore-status': () =>
        Promise.resolve({
          state: 'failed',
          backupId: 'b-bad',
          finishedAt: 0,
          error: {
            code: 5002,
            name: 'DataCorruption',
            message: 'checksum mismatch',
            retryable: false,
            details: {},
            traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
          },
        }),
    });
    await renderWith(RestorePage, api);
    expect(await screen.findByText(/backup b-bad failed on/)).toBeTruthy();
    expect(screen.getByText('RGN-5002')).toBeTruthy();
    expect(screen.getByText('checksum mismatch')).toBeTruthy();
  });

  it('tc_gui_007_restore_status_error_does_not_break_the_page', async () => {
    const api = mockApi({ '/api/v1/restore-status': () => Promise.reject(unavailable()) });
    await renderWith(RestorePage, api);
    expect(await screen.findByRole('button', { name: 'Restore' })).toBeTruthy();
    expect(screen.queryByText('RGN-3002')).toBeNull();
  });
});
