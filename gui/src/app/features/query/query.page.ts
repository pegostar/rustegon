import { DecimalPipe } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  resource,
  signal,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import type { components } from '../../api/schema';
import { NotificationService } from '../../core/notification.service';
import { SessionStore } from '../../core/session-store';
import { CodeBlock } from '../../shared/code-block';
import { confirm } from '../../shared/confirm-dialog';
import { DataGrid, GridColumn } from '../../shared/data-grid';
import { EmptyState } from '../../shared/empty-state';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { fitGrid } from '../data/documents.page';
import { Skeleton } from '../../shared/skeleton';
import { ExplainPlan, ExplainRow } from './explain-plan';
import { RgqlEditor } from './rgql-editor';
import { catalog, cellText, columnsOf, field, isDangerous, syntaxPosition, toCsv } from './rgql';
import { FIELD } from '../../shared/field';
import { Dialogs } from '../../shared/dialog';

type Stats = components['schemas']['QueryStatsJson'];
type Warning = components['schemas']['WarningJson'];
type Level = components['schemas']['ConsistencyLevel'];

/** A query document; `params` stays in memory (values may be sensitive, PD-137). */
interface QueryTab {
  id: number;
  db: string;
  text: string;
  params: string;
}
interface HistoryEntry {
  db: string;
  text: string;
  at: number;
}
interface Result {
  rows: unknown[];
  cursorId: string | null;
  stats: Stats | null;
  warnings: Warning[];
  elapsedMs: number;
}

const HISTORY_MAX = 200;

/**
 * S09 query editor & results and S10 explain viewer (angular-gui.md §4; R1 scope PD-126,
 * omissions PD-137). Tabs and history live in this browser per user (no server-side prefs).
 */
@Component({
  selector: 'rg-query-page',
  imports: [
    ...FIELD,
    DecimalPipe,
    FormsModule,
    RouterLink,
    CodeBlock,
    DataGrid,
    EmptyState,
    ErrorPanel,
    ExplainPlan,
    Icon,
    RgqlEditor,
    Skeleton,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './query.page.html',
  host: { '(keydown.escape)': 'running() && cancel()' },
})
export class QueryPage {
  protected readonly fitGrid = fitGrid;
  private readonly api = inject(ApiClient);
  private readonly notify = inject(NotificationService);
  private readonly dialog = inject(Dialogs);
  private readonly user = inject(SessionStore).user()?.user ?? 'anonymous';
  private readonly editor = viewChild(RgqlEditor);

  protected readonly databases = resource({
    loader: async () => (await this.api.get('/api/v1/databases')).databases.map((d) => d.name),
  });

  protected readonly tabs = signal<QueryTab[]>(this.loadTabs());
  protected readonly activeId = signal(this.tabs()[0].id);
  protected readonly tab = computed(
    () => this.tabs().find((t) => t.id === this.activeId()) ?? this.tabs()[0],
  );
  protected readonly collections = resource({
    params: () => this.tab().db || undefined,
    loader: async ({ params: db }) =>
      (await this.api.get('/api/v1/databases/{db}/collections', { path: { db } })).collections.map(
        (c) => c.name,
      ),
  });

  // Options (§4 S09).
  protected readonly consistency = signal<Level | ''>('');
  protected readonly maxTimeMs = signal<number | null>(null);
  protected readonly allowDiskUse = signal(false);

  protected readonly history = signal<HistoryEntry[]>(this.load('history', []));
  protected readonly historyFilter = signal('');
  protected readonly filteredHistory = computed(() => {
    const f = this.historyFilter().toLowerCase();
    return this.history().filter((h) => !f || h.text.toLowerCase().includes(f));
  });

  protected readonly running = signal(false);
  protected readonly paramsError = signal('');
  protected readonly error = signal<ApiError | null>(null);
  protected readonly errorAt = computed(() => {
    const e = this.error();
    return e?.code === 1010 ? syntaxPosition(e.details) : null;
  });
  protected readonly result = signal<Result | null>(null);
  protected readonly plan = signal<ExplainRow | null>(null);
  protected readonly status = signal('');
  protected readonly view = signal<'grid' | 'json'>('grid');
  protected readonly columns = computed<GridColumn<unknown>[]>(() =>
    columnsOf(this.result()?.rows ?? []).map((key) => ({
      key,
      header: key,
      cell: (r: unknown) => cellText(field(r, key)),
    })),
  );
  // The grid shows objects; `SELECT VALUE` rows become `{value}` (column `value`, see `field`).
  protected readonly gridRows = computed(() =>
    (this.result()?.rows ?? []).map((r) =>
      r !== null && typeof r === 'object' && !Array.isArray(r) ? r : { value: r },
    ),
  );
  protected readonly json = computed(() => JSON.stringify(this.result()?.rows ?? [], null, 2));

  /** Requests are numbered so a cancelled or superseded answer is ignored. */
  private seq = 0;

  constructor() {
    effect(() => {
      const dbs = this.databases.hasValue() ? this.databases.value() : [];
      catalog.databases = dbs;
      // A new tab (or a stored tab whose database is gone) gets the first database.
      const t = this.tab();
      if (dbs.length && !dbs.includes(t.db)) this.patchTab({ db: dbs[0] });
    });
    effect(() => {
      catalog.collections = this.collections.hasValue() ? this.collections.value() : [];
    });
    effect(() => {
      this.save(
        'tabs',
        this.tabs().map(({ id, db, text }) => ({ id, db, text })),
      );
    });
    effect(() => this.save('history', this.history()));
  }

  protected tabTitle(t: QueryTab, i: number): string {
    const first = t.text.trim().split('\n')[0];
    return first ? first.slice(0, 24) : $localize`:@@query.untitled:Query ${i + 1}:n:`;
  }

  protected patchTab(patch: Partial<QueryTab>): void {
    const id = this.tab().id;
    this.tabs.update((ts) => ts.map((t) => (t.id === id ? { ...t, ...patch } : t)));
  }

  protected addTab(): void {
    const id = Math.max(...this.tabs().map((t) => t.id)) + 1;
    this.tabs.update((ts) => [...ts, { id, db: this.tab().db, text: '', params: '' }]);
    this.activeId.set(id);
  }

  /** Accessible name of a tab's close button (the interpolated i18n-aria-label was not rendered). */
  protected closeLabel(i: number): string {
    return $localize`:@@query.closeTab:Close tab ${i + 1}:INTERPOLATION:`;
  }

  protected closeTab(id: number): void {
    const rest = this.tabs().filter((t) => t.id !== id);
    this.tabs.set(rest.length ? rest : [{ id: 1, db: this.tab().db, text: '', params: '' }]);
    if (this.activeId() === id) this.activeId.set(this.tabs()[0].id);
  }

  protected useHistory(h: HistoryEntry): void {
    this.patchTab({ db: h.db, text: h.text });
  }

  protected run(mode: 'all' | 'selection' = 'all'): Promise<void> {
    const text =
      mode === 'selection' ? this.editor()?.selection() || this.tab().text : this.tab().text;
    return this.execute(text, null);
  }

  protected explain(analyze: boolean): Promise<void> {
    return this.execute(this.tab().text, analyze);
  }

  protected cancel(): void {
    this.seq++;
    this.running.set(false);
    this.setStatus($localize`:@@query.cancelled:Query cancelled.`);
  }

  protected async loadMore(): Promise<void> {
    const r = this.result();
    if (!r?.cursorId) return;
    const seq = ++this.seq;
    this.running.set(true);
    try {
      const next = await this.api.request('post', '/api/v1/cursors/{cursor_id}/next', {
        path: { cursor_id: r.cursorId },
      });
      if (seq !== this.seq) return this.kill(next.cursorId);
      const rows = [...r.rows, ...next.rows];
      this.result.set({ ...r, rows, cursorId: next.cursorId ?? null, warnings: next.warnings });
      this.setStatus($localize`:@@query.loadedMore:${rows.length}:n: rows loaded.`);
    } catch (e) {
      if (seq === this.seq) this.error.set(ApiError.from(e));
    } finally {
      if (seq === this.seq) this.running.set(false);
    }
  }

  protected goToError(): void {
    const at = this.errorAt();
    if (at) this.editor()?.goTo(at.line, at.column);
  }

  protected export(format: 'json' | 'ndjson' | 'csv'): void {
    const rows = this.result()?.rows ?? [];
    const body =
      format === 'json'
        ? JSON.stringify(rows, null, 2)
        : format === 'ndjson'
          ? rows.map((r) => JSON.stringify(r)).join('\n')
          : toCsv(columnsOf(rows), rows);
    const type = format === 'csv' ? 'text/csv' : 'application/json';
    const url = URL.createObjectURL(new Blob([body], { type }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `query-result.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  /** `analyze` null: execute; else explain (with ANALYZE when true). */
  private async execute(text: string, analyze: boolean | null): Promise<void> {
    const db = this.tab().db;
    if (!text.trim() || !db) return;
    const params = this.parseParams();
    if (params === undefined) return;
    if (
      analyze === null &&
      isDangerous(text) &&
      !(await confirm(this.dialog, {
        title: $localize`:@@query.dangerTitle:Run this statement?`,
        message: $localize`:@@query.dangerMessage:It drops an object or changes every document of a collection.`,
        confirmLabel: $localize`:@@query.dangerConfirm:Run`,
      }))
    )
      return;
    const previous = this.result()?.cursorId;
    if (previous) void this.kill(previous);
    const seq = ++this.seq;
    this.running.set(true);
    this.error.set(null);
    this.editor()?.setError(null);
    this.remember(db, text);
    const options = {
      consistency: this.consistency() ? { level: this.consistency() as Level } : null,
      maxTimeMs: this.maxTimeMs() || null,
      ...(this.allowDiskUse() ? { allowDiskUse: true } : {}),
    };
    const started = performance.now();
    try {
      if (analyze === null) {
        const r = await this.api.request('post', '/api/v1/databases/{db}/query', {
          path: { db },
          body: { rgql: text, params: params as Record<string, never>, options },
        });
        if (seq !== this.seq) return this.kill(r.cursorId);
        const elapsedMs = r.stats
          ? r.stats.executionTimeUs / 1000
          : Math.round(performance.now() - started);
        this.plan.set(null);
        this.result.set({
          rows: r.rows,
          cursorId: r.cursorId ?? null,
          stats: r.stats ?? null,
          warnings: r.warnings,
          elapsedMs,
        });
        this.setStatus(
          r.stats && r.stats.docsAffected > 0
            ? $localize`:@@query.affected:${r.stats.docsAffected}:n: documents written in ${elapsedMs.toFixed(1)}:ms: ms.`
            : $localize`:@@query.rows:${r.rows.length}:n: rows in ${elapsedMs.toFixed(1)}:ms: ms.`,
        );
      } else {
        const r = await this.api.request('post', '/api/v1/databases/{db}/explain', {
          path: { db },
          body: { rgql: text, params: params as Record<string, never>, options, analyze },
        });
        if (seq !== this.seq) return;
        this.result.set(null);
        this.plan.set(r.plan as unknown as ExplainRow);
        this.setStatus($localize`:@@query.explained:Plan ready.`);
      }
    } catch (e) {
      if (seq !== this.seq) return;
      const err = ApiError.from(e);
      this.error.set(err);
      const at = err.code === 1010 ? syntaxPosition(err.details) : null;
      if (at) this.editor()?.setError({ ...at, message: err.message });
      this.setStatus($localize`:@@query.failed:The query failed: ${err.message}:message:`);
    } finally {
      if (seq === this.seq) this.running.set(false);
    }
  }

  private parseParams(): Record<string, unknown> | undefined {
    const raw = this.tab().params.trim();
    this.paramsError.set('');
    if (!raw) return {};
    try {
      const v: unknown = JSON.parse(raw);
      if (v !== null && typeof v === 'object' && !Array.isArray(v))
        return v as Record<string, unknown>;
    } catch {
      // Reported below.
    }
    this.paramsError.set(
      $localize`:@@query.paramsInvalid:Parameters must be a JSON object, e.g. {"min": 10}.`,
    );
    return undefined;
  }

  private async kill(cursorId: string | null | undefined): Promise<void> {
    if (!cursorId) return;
    try {
      await this.api.request('delete', '/api/v1/cursors/{cursor_id}', {
        path: { cursor_id: cursorId },
      });
    } catch {
      // Best effort: the server closes idle cursors after 10 min (protocol.md §5).
    }
  }

  private setStatus(message: string): void {
    this.status.set(message);
    void this.notify.announce(message);
  }

  private remember(db: string, text: string): void {
    this.history.update((h) =>
      [{ db, text, at: Date.now() }, ...h.filter((e) => e.text !== text || e.db !== db)].slice(
        0,
        HISTORY_MAX,
      ),
    );
  }

  private loadTabs(): QueryTab[] {
    const stored = this.load<Omit<QueryTab, 'params'>[]>('tabs', []);
    const tabs = stored
      .filter((t) => typeof t?.id === 'number' && typeof t.text === 'string')
      .map((t) => ({ id: t.id, db: String(t.db ?? ''), text: t.text, params: '' }));
    return tabs.length ? tabs : [{ id: 1, db: '', text: '', params: '' }];
  }

  // Query text only: no session data and no parameter values in browser storage (§1 security).
  private load<T>(what: string, fallback: T): T {
    try {
      const raw = localStorage.getItem(`rg.query.${what}.${this.user}`);
      return raw ? (JSON.parse(raw) as T) : fallback;
    } catch {
      return fallback;
    }
  }

  private save(what: string, value: unknown): void {
    try {
      localStorage.setItem(`rg.query.${what}.${this.user}`, JSON.stringify(value));
    } catch {
      // Storage blocked or full: tabs and history last for this page.
    }
  }
}
