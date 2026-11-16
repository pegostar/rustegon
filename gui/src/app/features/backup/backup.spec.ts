import { ApplicationRef } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { render, screen } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { BackupsPage } from './backups.page';
import { tomlStrings } from './common';
import { quote, RestorePage, restoreCommand, RestoreSpec } from './restore.page';

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
) =>
  render(component as typeof BackupsPage, {
    providers: [provideRouter([]), { provide: ApiClient, useValue: api }],
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
    expect(screen.queryByRole('heading', { name: 'Restore command' })).toBeNull();
    await userEvent.type(screen.getByLabelText('New data directory'), '/srv/new');
    await userEvent.click(screen.getByRole('button', { name: 'Generate command' }));
    const code = await screen.findByText(/rustegon backup restore/);
    expect(code.textContent).toContain('--from /srv/backups --id b-1 --into /srv/new');
    expect(api.get).not.toHaveBeenCalled();
  });

  it('tc_gui_007_restore_page_lists_backups_and_shows_errors', async () => {
    const api = mockApi({ '/api/v1/backups': () => Promise.reject(unavailable()) });
    await renderWith(RestorePage, api, { from: '/srv/backups' });
    await userEvent.click(screen.getByRole('button', { name: 'List backups at this destination' }));
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: 'Generate command' }));
    expect(screen.getByText('Enter a backup id or a point in time.')).toBeTruthy();
  });
});
