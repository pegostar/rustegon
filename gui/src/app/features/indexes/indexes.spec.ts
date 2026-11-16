import { provideRouter } from '@angular/router';
import { render, screen, waitFor } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { SessionStore } from '../../core/session-store';
import { indexDefinition, IndexesPage } from './indexes.page';
import { Dialogs } from '../../shared/dialog';

const def = (name: string, unique = false) => ({
  index_type: unique ? 'unique' : 'standard',
  name,
  on: { database: 'shop', name: 'orders' },
  keys: [{ path: ['status'] }, { path: ['createdAt'], descending: true }],
  options: [{ name: 'sparse', value: { kind: 'literal', value: true } }],
});

describe('S11 index definition', () => {
  it('tc_gui_004_builds_the_create_index_ast', () => {
    expect(
      indexDefinition('shop', 'orders', {
        name: ' by_status ',
        fields: 'status, -createdAt, items.0.sku DESC',
        unique: true,
        sparse: true,
        partial: 'total > 0',
      }),
    ).toEqual({
      index_type: 'unique',
      name: 'by_status',
      on: { database: 'shop', name: 'orders' },
      keys: [
        { path: ['status'] },
        { path: ['createdAt'], descending: true },
        { path: ['items', 0, 'sku'], descending: true },
      ],
      options: [
        { name: 'sparse', value: { kind: 'literal', value: true } },
        { name: 'partial', value: { kind: 'literal', value: 'total > 0' } },
      ],
    });
    expect(
      indexDefinition('d', 'c', {
        name: 'x',
        fields: 'a',
        unique: false,
        sparse: false,
        partial: '',
      }),
    ).toEqual({
      index_type: 'standard',
      name: 'x',
      on: { database: 'd', name: 'c' },
      keys: [{ path: ['a'] }],
    });
  });
});

describe('S11 indexes page', () => {
  let api: { get: ReturnType<typeof vi.fn>; request: ReturnType<typeof vi.fn> };

  async function setup(
    indexes: () => Promise<unknown>,
    inputs: Record<string, string> = {},
    roles = [{ role: 'root' }],
  ) {
    api = {
      get: vi.fn((path: string) => {
        if (path === '/api/v1/databases') return Promise.resolve({ databases: [{ name: 'shop' }] });
        if (path === '/api/v1/databases/{db}/collections')
          return Promise.resolve({ collections: [{ name: 'orders' }] });
        if (path.endsWith('/progress'))
          return Promise.resolve({ state: 'building', docsProcessed: 50, docsTotal: 200 });
        if (path.endsWith('/{name}'))
          return Promise.resolve({ definition: def('by_status'), state: 'ready' });
        return indexes();
      }),
      request: vi.fn().mockResolvedValue({}),
    };
    const r = await render(IndexesPage, {
      providers: [
        provideRouter([]),
        { provide: ApiClient, useValue: api },
        { provide: Dialogs, useValue: { open: () => Promise.resolve(true) } },
      ],
      inputs,
    });
    r.fixture.debugElement.injector
      .get(SessionStore)
      .user.set({ user: 'u', roles, mechanism: 'password', expiresAtUnixMs: 0 } as never);
    return r;
  }

  it('tc_gui_004_shows_loading', async () => {
    await setup(() => new Promise(() => undefined));
    expect(await screen.findByText('Indexes of orders')).toBeTruthy();
    expect(screen.getByText('Loading…')).toBeTruthy();
  });

  it('tc_gui_004_shows_the_error_panel', async () => {
    await setup(() => Promise.reject(new ApiError(404, 1030, 'NotFound', 'gone', false, {}, 'tr')));
    expect(await screen.findByText('RGN-1030')).toBeTruthy();
  });

  it('tc_gui_004_shows_the_empty_state', async () => {
    await setup(() => Promise.resolve({ indexes: [] }));
    expect(await screen.findByText('No secondary indexes')).toBeTruthy();
  });

  it('tc_gui_004_lists_indexes_with_build_progress_and_drops_one', async () => {
    await setup(() =>
      Promise.resolve({
        indexes: [
          { definition: def('by_status'), state: 'ready' },
          { definition: def('ux', true), state: 'building' },
        ],
      }),
    );
    expect(await screen.findByText('by_status')).toBeTruthy();
    expect(screen.getAllByText('status, createdAt DESC')).toHaveLength(2);
    expect(await screen.findByText('building 25 %')).toBeTruthy();
    await userEvent.click(screen.getByText('by_status'));
    expect(await screen.findByText('Index by_status')).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: 'Drop index' }));
    await waitFor(() =>
      expect(api.request).toHaveBeenCalledWith(
        'delete',
        '/api/v1/databases/{db}/collections/{coll}/indexes/{name}',
        { path: { db: 'shop', coll: 'orders', name: 'by_status' } },
      ),
    );
  });

  it('tc_gui_004_suggested_index_opens_the_prefilled_form_and_creates_it', async () => {
    await setup(() => Promise.resolve({ indexes: [] }), {
      db: 'shop',
      coll: 'orders',
      fields: 'tag,n',
    });
    expect((await screen.findByLabelText('Name')) as HTMLInputElement).toHaveProperty(
      'value',
      'ix_tag_n',
    );
    expect(screen.getByLabelText('Fields')).toHaveProperty('value', 'tag, n');
    await userEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(api.request).toHaveBeenCalledWith(
      'post',
      '/api/v1/databases/{db}/collections/{coll}/indexes',
      {
        path: { db: 'shop', coll: 'orders' },
        body: {
          definition: {
            index_type: 'standard',
            name: 'ix_tag_n',
            on: { database: 'shop', name: 'orders' },
            keys: [{ path: ['tag'] }, { path: ['n'] }],
          },
        },
      },
    );
  });

  it('tc_gui_004_validates_the_create_form', async () => {
    await setup(() => Promise.resolve({ indexes: [] }));
    await userEvent.click(await screen.findByRole('button', { name: 'Create index' }));
    await userEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(screen.getByText('Enter at least one field.')).toBeTruthy();
    expect(api.request).not.toHaveBeenCalled();
  });

  it('tc_gui_004_read_only_user_cannot_create', async () => {
    await setup(() => Promise.resolve({ indexes: [] }), {}, [{ role: 'read' }]);
    expect(await screen.findByText('No secondary indexes')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Create index' })).toBeNull();
  });
});
