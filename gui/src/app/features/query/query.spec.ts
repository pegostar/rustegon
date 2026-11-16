import { provideRouter } from '@angular/router';
import { render, screen, waitFor } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { ExplainRow, suggestIndex } from './explain-plan';
import { QueryPage } from './query.page';
import { MONACO_LOADER } from './rgql-editor';
import { columnsOf, isDangerous, quoteIdent, syntaxPosition, toCsv } from './rgql';
import { Dialogs } from '../../shared/dialog';

const PLAN: ExplainRow = {
  explain_format: 1,
  statement: 'query',
  analyze: false,
  indexes_used: [],
  est_cost: null,
  execution: null,
  plan: {
    op: 'Filter',
    detail: "(tag = 't1' AND n >= 3)",
    index: null,
    est_rows: null,
    children: [
      {
        op: 'CollectionScan',
        detail: 'CollectionScan shop.t',
        index: null,
        est_rows: null,
        children: [],
      },
    ],
  },
};

describe('S09/S10 RGQL helpers', () => {
  it('tc_gui_004_dangerous_statements_need_confirmation', () => {
    expect(isDangerous('DROP INDEX shop.t.ix')).toBe(true);
    expect(isDangerous('DELETE FROM t')).toBe(true);
    expect(isDangerous("-- note\nUPDATE t SET a = 'where'")).toBe(true);
    expect(isDangerous('DELETE FROM t WHERE a = 1')).toBe(false);
    expect(isDangerous('FROM t')).toBe(false);
  });

  it('tc_gui_004_syntax_position_and_csv', () => {
    expect(syntaxPosition({ line: '2', column: '7' })).toEqual({ line: 2, column: 7 });
    expect(syntaxPosition({})).toBeNull();
    expect(columnsOf([{ a: 1 }, { b: 'x' }, 3])).toEqual(['a', 'b', 'value']);
    expect(toCsv(['a', 'b'], [{ a: 'x,y', b: { c: 1 } }, 2])).toBe('a,b\r\n"x,y","{""c"":1}"\r\n,');
    expect(quoteIdent('orders')).toBe('orders');
    expect(quoteIdent('a.b')).toBe('`a.b`');
  });

  it('tc_gui_004_suggests_an_index_for_a_collection_scan', () => {
    expect(suggestIndex(PLAN.plan.children[0], PLAN.plan)).toEqual({
      db: 'shop',
      coll: 't',
      fields: ['tag', 'n'],
    });
    expect(suggestIndex(PLAN.plan, undefined)).toBeNull();
  });
});

describe('S09 query page', () => {
  let api: { get: ReturnType<typeof vi.fn>; request: ReturnType<typeof vi.fn> };
  let confirmed = true;

  async function setup(databases: Promise<unknown>) {
    localStorage.clear();
    api = {
      get: vi.fn((path: string) =>
        path === '/api/v1/databases' ? databases : Promise.resolve({ collections: [] }),
      ),
      request: vi.fn(),
    };
    await render(QueryPage, {
      providers: [
        provideRouter([]),
        { provide: ApiClient, useValue: api },
        // No Monaco under jsdom: the editor keeps its textarea.
        { provide: MONACO_LOADER, useValue: () => new Promise(() => undefined) },
        { provide: Dialogs, useValue: { open: () => Promise.resolve(confirmed) } },
      ],
    });
  }

  // The live announcer repeats the text, so read the visible status line.
  const status = (text: string) =>
    waitFor(() => expect(document.querySelector('p.status')?.textContent).toContain(text));
  const ready = () => setup(Promise.resolve({ databases: [{ name: 'shop' }] }));
  async function type(text: string) {
    const editor = await screen.findByRole('textbox', { name: 'RGQL query' });
    await userEvent.clear(editor);
    // userEvent treats braces as key names.
    await userEvent.type(editor, text.replaceAll('{', '{{').replaceAll('[', '[['));
  }

  it('tc_gui_004_shows_loading_while_databases_load', async () => {
    await setup(new Promise(() => undefined));
    expect(screen.getByText('Loading…')).toBeTruthy();
  });

  it('tc_gui_004_shows_the_error_panel', async () => {
    await setup(Promise.reject(new ApiError(503, 3002, 'Unavailable', 'down', true, {}, 'tr')));
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
  });

  it('tc_gui_004_offers_to_create_a_database_when_there_is_none', async () => {
    await setup(Promise.resolve({ databases: [] }));
    expect(await screen.findByRole('link', { name: 'Create a database' })).toBeTruthy();
  });

  it('tc_gui_004_runs_a_query_and_announces_the_rows', async () => {
    await ready();
    expect(await screen.findByText('No results yet')).toBeTruthy();
    api.request.mockResolvedValue({
      rows: [
        { _id: 1, n: 'a' },
        { _id: 2, n: 'b' },
      ],
      cursorId: 'c1',
      stats: { docsReturned: 2, docsAffected: 0, executionTimeUs: 1500 },
      warnings: [],
    });
    await type('FROM items WHERE n = $n');
    await userEvent.type(screen.getByLabelText('Parameters (JSON object)'), '{{"n": "a"}');
    await userEvent.click(screen.getByRole('button', { name: 'Run' }));
    expect(api.request).toHaveBeenCalledWith('post', '/api/v1/databases/{db}/query', {
      path: { db: 'shop' },
      body: {
        rgql: 'FROM items WHERE n = $n',
        params: { n: 'a' },
        options: { consistency: null, maxTimeMs: null },
      },
    });
    await status('2 rows in 1.5 ms.');
    expect(await screen.findByText('b')).toBeTruthy();
    // Load more continues the cursor.
    api.request.mockResolvedValue({ rows: [{ _id: 3, n: 'c' }], cursorId: null, warnings: [] });
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(api.request).toHaveBeenLastCalledWith('post', '/api/v1/cursors/{cursor_id}/next', {
      path: { cursor_id: 'c1' },
    });
    await status('3 rows loaded.');
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull();
    // The history keeps the text, never the parameter values.
    const stored = Object.entries({ ...localStorage })
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');
    expect(stored).toContain('FROM items WHERE n = $n');
    expect(stored).not.toContain('"n":"a"');
  });

  it('tc_gui_004_rejects_invalid_parameters', async () => {
    await ready();
    await type('FROM items');
    await userEvent.type(screen.getByLabelText('Parameters (JSON object)'), '[[1]');
    await userEvent.click(screen.getByRole('button', { name: 'Run' }));
    expect(screen.getByText(/Parameters must be a JSON object/)).toBeTruthy();
    expect(api.request).not.toHaveBeenCalled();
  });

  it('tc_gui_004_syntax_error_offers_the_position', async () => {
    await ready();
    api.request.mockRejectedValue(
      new ApiError(400, 1010, 'QuerySyntaxError', 'unexpected end', false, {
        line: '1',
        column: '6',
      }),
    );
    await type('FROM ');
    await userEvent.click(screen.getByRole('button', { name: 'Run' }));
    expect(await screen.findByRole('button', { name: 'Go to line 1, column 6' })).toBeTruthy();
    expect(screen.getByText('RGN-1010')).toBeTruthy();
  });

  it('tc_gui_004_dangerous_statement_is_not_run_without_confirmation', async () => {
    await ready();
    confirmed = false;
    await type('DELETE FROM items');
    await userEvent.click(screen.getByRole('button', { name: 'Run' }));
    expect(api.request).not.toHaveBeenCalled();
    confirmed = true;
  });

  it('tc_gui_004_explain_shows_the_plan_and_suggests_an_index', async () => {
    await ready();
    api.request.mockResolvedValue({ plan: PLAN });
    await type("FROM t WHERE tag = 't1'");
    await userEvent.click(screen.getByRole('button', { name: 'Explain' }));
    expect(await screen.findByText('Collection scan: every document is read')).toBeTruthy();
    expect(api.request.mock.calls[0][2].body.analyze).toBe(false);
    const link = screen.getByRole('link', { name: 'Create suggested index' });
    expect(link.getAttribute('href')).toBe('/indexes?db=shop&coll=t&fields=tag,n');
  });

  it('tc_gui_004_empty_result', async () => {
    await ready();
    api.request.mockResolvedValue({ rows: [], warnings: [] });
    await type('FROM t');
    await userEvent.click(screen.getByRole('button', { name: 'Run' }));
    await waitFor(() => expect(screen.getByText('No rows')).toBeTruthy());
  });
});
