import { ApplicationRef, Type } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { render, screen, waitFor, within } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { PermissionsService } from '../../core/permissions.service';
import { MONACO_LOADER } from '../../shared/json-editor';
import { CollectionsPage } from './collections.page';
import { DatabasesPage } from './databases.page';
import { DocumentPage, splitDocument } from './document.page';
import { DocumentsPage, inferColumns } from './documents.page';

// S05–S08 component tests (angular-gui.md §5: loading, empty, error, data) with a mocked
// ApiClient; FR-GUI-001, TC-GUI-003 (document CRUD with optimistic concurrency).

// jsdom has no layout: scrolling is a no-op there.
Element.prototype.scrollTo ??= () => undefined;

const never = () => new Promise<never>(() => undefined);
const unavailable = () =>
  new ApiError(503, 3002, 'Unavailable', 'range unavailable', true, {}, 'tr');

// Dialogs: plain DOM events, since Testing Library's per-event detectChanges would re-enter the
// application tick the dialog schedules (as in shared.spec.ts).
const settle = () => TestBed.inject(ApplicationRef).whenStable();
async function press(el: HTMLElement): Promise<void> {
  el.click();
  await settle();
}
async function fill(el: HTMLElement, value: string): Promise<void> {
  const input = el as HTMLInputElement;
  input.value = value;
  input.dispatchEvent(new Event('input'));
  input.dispatchEvent(new Event('blur'));
  await settle();
}

interface Api {
  get: ReturnType<typeof vi.fn>;
  request: ReturnType<typeof vi.fn>;
}

function api(
  get: (path: string, opts?: { path?: Record<string, string> }) => Promise<unknown>,
): Api {
  return { get: vi.fn(get), request: vi.fn().mockResolvedValue({}) };
}

async function setup<T>(component: Type<T>, a: Api, inputs: Record<string, unknown> = {}) {
  const r = await render(component, {
    providers: [
      provideRouter([]),
      { provide: ApiClient, useValue: a },
      { provide: PermissionsService, useValue: { can: () => true } },
      { provide: MONACO_LOADER, useValue: never },
    ],
    inputs: inputs as never,
  });
  const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
  return { ...r, navigate };
}

describe('S05 databases page', () => {
  it('tc_gui_003_loading_shows_a_status', async () => {
    await setup(DatabasesPage, api(never));
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_003_empty_offers_create', async () => {
    await setup(
      DatabasesPage,
      api(() => Promise.resolve({ databases: [] })),
    );
    expect(await screen.findByText('No databases yet')).toBeTruthy();
    expect(screen.getAllByRole('button', { name: 'Create database' }).length).toBe(2);
  });

  it('tc_gui_003_error_shows_the_panel', async () => {
    await setup(
      DatabasesPage,
      api(() => Promise.reject(unavailable())),
    );
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeTruthy();
  });

  it('tc_gui_003_data_lists_databases_and_opens_one', async () => {
    const { navigate } = await setup(
      DatabasesPage,
      api((path) =>
        Promise.resolve(
          path === '/api/v1/databases'
            ? { databases: [{ name: 'shop', options: { implicit_collection_creation: false } }] }
            : { collections: [{ name: 'a' }, { name: 'b' }] },
        ),
      ),
    );
    const grid = await screen.findByRole('grid', { name: 'Databases' });
    expect(await within(grid).findByText('shop')).toBeTruthy();
    expect(within(grid).getByText('2')).toBeTruthy();
    expect(within(grid).getByText('No')).toBeTruthy();
    await userEvent.click(within(grid).getByText('shop'));
    expect(navigate).toHaveBeenCalledWith(['/db', 'shop']);
  });

  it('tc_gui_003_create_validates_the_name_and_posts', async () => {
    const a = api(() => Promise.resolve({ databases: [] }));
    const { navigate } = await setup(DatabasesPage, a);
    await press((await screen.findAllByRole('button', { name: 'Create database' }))[0]);
    const name = await screen.findByLabelText('Database name');
    await fill(name, '_system');
    await press(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('Enter a name that follows the rule.')).toBeTruthy();
    expect(a.request).not.toHaveBeenCalled();
    await fill(name, 'shop');
    await press(screen.getByRole('checkbox', { name: 'Create collections on first write' }));
    await press(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith(['/db', 'shop']));
    expect(a.request).toHaveBeenCalledWith('post', '/api/v1/databases', {
      body: { name: 'shop', options: { implicit_collection_creation: false } },
    });
  });

  it('tc_gui_003_create_shows_a_server_error_in_the_dialog', async () => {
    const a = api(() => Promise.resolve({ databases: [] }));
    a.request.mockRejectedValue(
      new ApiError(409, 1031, 'AlreadyExists', 'database shop exists', false),
    );
    await setup(DatabasesPage, a);
    await press((await screen.findAllByRole('button', { name: 'Create database' }))[0]);
    await fill(await screen.findByLabelText('Database name'), 'shop');
    await press(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(screen.getByText('RGN-1031 database shop exists')).toBeTruthy());
  });
});

describe('S06 collections page', () => {
  const inputs = { db: 'shop' };

  it('tc_gui_003_loading_state', async () => {
    await setup(CollectionsPage, api(never), inputs);
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_003_s06_empty_state', async () => {
    await setup(
      CollectionsPage,
      api(() => Promise.resolve({ collections: [] })),
      inputs,
    );
    expect(await screen.findByText('No collections yet')).toBeTruthy();
  });

  it('tc_gui_003_s06_error_state', async () => {
    await setup(
      CollectionsPage,
      api(() => Promise.reject(unavailable())),
      inputs,
    );
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
  });

  it('tc_gui_003_data_lists_collections_and_opens_one', async () => {
    const { navigate } = await setup(
      CollectionsPage,
      api(() =>
        Promise.resolve({
          collections: [
            {
              name: 'orders',
              options: {},
              validator: { definition: {}, level: 'moderate', action: 'warn' },
            },
            { name: 'users', options: {} },
          ],
        }),
      ),
      inputs,
    );
    const grid = await screen.findByRole('grid', { name: 'Collections' });
    expect(await within(grid).findByText('moderate / warn')).toBeTruthy();
    expect(within(grid).getByText('None')).toBeTruthy();
    await userEvent.click(within(grid).getByText('users'));
    expect(navigate).toHaveBeenCalledWith(['/db', 'shop', 'c', 'users']);
  });

  it('tc_gui_003_drop_database_needs_the_typed_name', async () => {
    const a = api(() => Promise.resolve({ collections: [] }));
    await setup(CollectionsPage, a, inputs);
    const nav = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    await press(await screen.findByRole('button', { name: 'Drop database' }));
    const dialog = await screen.findByRole('dialog');
    const confirmButton = within(dialog).getByRole('button', { name: 'Drop database' });
    expect((confirmButton as HTMLButtonElement).disabled).toBe(true);
    await fill(within(dialog).getByLabelText('Type "shop" to confirm'), 'shop');
    await press(confirmButton);
    await waitFor(() =>
      expect(a.request).toHaveBeenCalledWith('delete', '/api/v1/databases/{db}', {
        path: { db: 'shop' },
      }),
    );
    expect(nav).toHaveBeenCalledWith('/data');
  });
});

describe('S07 documents page', () => {
  const inputs = { db: 'shop', coll: 'orders' };

  it('tc_gui_003_infers_columns_id_first', () => {
    const cols = inferColumns([
      { total: 3, _id: 1, _rev: 'r' },
      { tags: ['a'], _id: 2 },
    ]);
    expect(cols.map((c) => c.key)).toEqual(['_id', 'total', 'tags']);
    expect(cols[2].cell?.({ tags: ['a'] })).toBe('["a"]');
  });

  it('tc_gui_003_loading_state', async () => {
    await setup(DocumentsPage, api(never), inputs);
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_003_s07_empty_state', async () => {
    await setup(
      DocumentsPage,
      api(() => Promise.resolve({ documents: [] })),
      inputs,
    );
    expect(await screen.findByText('No documents match')).toBeTruthy();
  });

  it('tc_gui_003_s07_error_state', async () => {
    await setup(
      DocumentsPage,
      api(() =>
        Promise.reject(new ApiError(400, 1001, 'InvalidArgument', 'syntax error at 1:5', false)),
      ),
      inputs,
    );
    expect(await screen.findByText('syntax error at 1:5')).toBeTruthy();
  });

  it('tc_gui_003_filters_pages_and_opens_a_document', async () => {
    const a = api((_p, opts) =>
      Promise.resolve(
        (opts as { query: { continuationToken?: string } }).query.continuationToken
          ? { documents: [{ _id: 'b', total: 2 }] }
          : { documents: [{ _id: 'a', total: 1 }], continuationToken: 'tok1' },
      ),
    );
    const { navigate } = await setup(DocumentsPage, a, inputs);
    expect(await screen.findByRole('grid', { name: 'Documents' })).toBeTruthy();
    await userEvent.type(screen.getByLabelText('Filter (RGQL expression)'), 'total > 0');
    await userEvent.type(screen.getByLabelText('Sort'), '-total');
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }));
    await waitFor(() =>
      expect(a.get).toHaveBeenLastCalledWith(
        '/api/v1/databases/{db}/collections/{coll}/documents',
        {
          path: inputs,
          query: { filter: 'total > 0', sort: '-total', limit: 100, continuationToken: undefined },
        },
      ),
    );
    await userEvent.click(await screen.findByRole('button', { name: 'Next page' }));
    expect(await screen.findByText('Page 2, 1 documents')).toBeTruthy();
    await userEvent.click(await screen.findByText('b'));
    expect(navigate).toHaveBeenCalledWith(['/db', 'shop', 'c', 'orders', 'doc', '"b"']);
    await userEvent.click(screen.getByRole('button', { name: 'Previous page' }));
    expect(await screen.findByText('Page 1, 1 documents')).toBeTruthy();
  });

  it('tc_gui_003_json_view_shows_the_page', async () => {
    await setup(
      DocumentsPage,
      api(() => Promise.resolve({ documents: [{ _id: 7 }] })),
      inputs,
    );
    await screen.findByRole('grid');
    await userEvent.click(screen.getByRole('radio', { name: 'JSON' }));
    expect(screen.getByText(/"_id": 7/)).toBeTruthy();
  });
});

describe('S08 document page', () => {
  const stored = { _id: 'a1', _rev: 'r1', _createdAt: { $date: '2026-01-01T00:00:00Z' }, total: 5 };
  const inputs = { db: 'shop', coll: 'orders', id: '"a1"' };

  async function plainText(): Promise<HTMLTextAreaElement> {
    await userEvent.click(await screen.findByRole('button', { name: 'Plain text editor' }));
    return screen.getByRole('textbox', { name: 'Document (JSON)' }) as HTMLTextAreaElement;
  }

  it('tc_gui_003_splits_server_fields', () => {
    expect(splitDocument(stored)).toEqual({
      body: { _id: 'a1', total: 5 },
      meta: { _rev: 'r1', _createdAt: { $date: '2026-01-01T00:00:00Z' } },
    });
  });

  it('tc_gui_003_loading_state', async () => {
    await setup(DocumentPage, api(never), inputs);
    expect(screen.getByRole('status').textContent).toContain('Loading');
  });

  it('tc_gui_003_s08_error_state', async () => {
    await setup(
      DocumentPage,
      api(() => Promise.reject(new ApiError(404, 1030, 'NotFound', 'no document a1', false))),
      inputs,
    );
    expect(await screen.findByText('no document a1')).toBeTruthy();
  });

  it('tc_gui_003_edits_with_if_match_and_resolves_a_conflict', async () => {
    const a = api(() => Promise.resolve({ document: stored }));
    await setup(DocumentPage, a, inputs);
    const text = await plainText();
    await waitFor(() => expect(JSON.parse(text.value)).toEqual({ _id: 'a1', total: 5 }));
    expect(screen.getByText('r1')).toBeTruthy();
    a.request.mockRejectedValueOnce(new ApiError(412, 2009, 'PreconditionFailed', 'rev', false));
    await userEvent.clear(text);
    await userEvent.type(text, '{{"_id": "a1", "total": 6}');
    await userEvent.click(screen.getByRole('button', { name: 'Save document' }));
    const path = { db: 'shop', coll: 'orders', id: '"a1"' };
    expect(a.request).toHaveBeenLastCalledWith(
      'put',
      '/api/v1/databases/{db}/collections/{coll}/documents/{id}',
      {
        path,
        query: { returnDocument: 'after' },
        body: { _id: 'a1', total: 6 },
        headers: { 'If-Match': '"r1"' },
      },
    );
    expect(await screen.findByText(/The document changed since you opened it/)).toBeTruthy();
    a.request.mockResolvedValueOnce({ document: { ...stored, _rev: 'r2', total: 6 } });
    await userEvent.click(screen.getByRole('button', { name: 'Overwrite' }));
    expect(a.request).toHaveBeenLastCalledWith(
      'put',
      '/api/v1/databases/{db}/collections/{coll}/documents/{id}',
      {
        path,
        query: { returnDocument: 'after' },
        body: { _id: 'a1', total: 6 },
        headers: {},
      },
    );
    expect(await screen.findByText('r2')).toBeTruthy();
  });

  it('tc_gui_003_rejects_invalid_json_and_a_changed_id', async () => {
    const a = api(() => Promise.resolve({ document: stored }));
    await setup(DocumentPage, a, inputs);
    const text = await plainText();
    await waitFor(() => expect(text.value).toContain('a1'));
    await userEvent.type(text, ',');
    expect(screen.getByText(/Invalid JSON/)).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Save document' }) as HTMLButtonElement).disabled,
    ).toBe(true);
    await userEvent.clear(text);
    await userEvent.type(text, '{{"_id": "other"}');
    await userEvent.click(screen.getByRole('button', { name: 'Save document' }));
    expect(await screen.findByText(/cannot change/)).toBeTruthy();
    expect(a.request).not.toHaveBeenCalled();
  });

  it('tc_gui_003_shows_the_validator_path_of_rgn_1006', async () => {
    const a = api(() => Promise.resolve({ document: stored }));
    a.request.mockRejectedValue(
      new ApiError(422, 1006, 'SchemaValidationFailed', 'fails the validator', false, {
        path: '/total',
      }),
    );
    await setup(DocumentPage, a, inputs);
    await plainText();
    await userEvent.click(await screen.findByRole('button', { name: 'Save document' }));
    expect(await screen.findByText('Field that failed validation: /total')).toBeTruthy();
  });

  it('tc_gui_003_inserts_a_new_document_and_opens_it', async () => {
    const a = api(never);
    a.request.mockResolvedValue({
      results: [{ id: { $oid: '0123456789abcdef01234567' } }],
      warnings: [],
    });
    const { navigate } = await setup(DocumentPage, a, { db: 'shop', coll: 'orders' });
    expect(screen.getByRole('heading', { name: 'New document in orders' })).toBeTruthy();
    const text = await plainText();
    await userEvent.clear(text);
    await userEvent.type(text, '{{"total": 1}');
    await userEvent.click(screen.getByRole('button', { name: 'Insert document' }));
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith(
        ['/db', 'shop', 'c', 'orders', 'doc', '{"$oid":"0123456789abcdef01234567"}'],
        { replaceUrl: true },
      ),
    );
    expect(a.request).toHaveBeenCalledWith(
      'post',
      '/api/v1/databases/{db}/collections/{coll}/documents',
      {
        path: { db: 'shop', coll: 'orders' },
        body: { documents: [{ total: 1 }] },
      },
    );
    expect(a.get).not.toHaveBeenCalled();
  });

  it('tc_gui_003_deletes_after_confirmation', async () => {
    const a = api(() => Promise.resolve({ document: stored }));
    const { navigate } = await setup(DocumentPage, a, inputs);
    await screen.findByText('r1');
    await press(screen.getByRole('button', { name: 'Delete document' }));
    const dialog = await screen.findByRole('dialog');
    await press(within(dialog).getByRole('button', { name: 'Delete document' }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith(['/db', 'shop', 'c', 'orders']));
    expect(a.request).toHaveBeenCalledWith(
      'delete',
      '/api/v1/databases/{db}/collections/{coll}/documents/{id}',
      {
        path: { db: 'shop', coll: 'orders', id: '"a1"' },
        headers: { 'If-Match': '"r1"' },
      },
    );
  });
});
