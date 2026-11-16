import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  resource,
  signal,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ApiClient } from '../../api/api-client';
import { NotificationService } from '../../core/notification.service';
import { Action, PermissionsService } from '../../core/permissions.service';
import { CodeBlock } from '../../shared/code-block';
import { confirm } from '../../shared/confirm-dialog';
import { DataGrid, GridColumn } from '../../shared/data-grid';
import { EmptyState } from '../../shared/empty-state';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { Skeleton } from '../../shared/skeleton';
import { ValidatorDialog } from './validator-dialog';
import { FIELD } from '../../shared/field';
import { Dialogs } from '../../shared/dialog';

export type Doc = Record<string, unknown>;

/** Deep link of a document (angular-gui.md §1): the id segment is its extended-JSON text (PD-135). */
export function docLink(db: string, coll: string, id: unknown): string[] {
  return ['/db', db, 'c', coll, 'doc', JSON.stringify(id)];
}

const MAX_COLUMNS = 8;

/** Viewport height of an `rg-data-grid` (40 px rows) that fits `rows` rows, at most `max` px. */
export function fitGrid(rows: number, max = 400): number {
  return Math.min(max, Math.max(rows, 1) * 40);
}

/** Columns inferred from the page's documents: `_id` first, then fields by first appearance. */
export function inferColumns(docs: readonly Doc[]): GridColumn<Doc>[] {
  const keys = new Set<string>(['_id']);
  for (const d of docs) for (const k of Object.keys(d)) if (k !== '_rev') keys.add(k);
  return [...keys].slice(0, MAX_COLUMNS).map((key) => ({
    key,
    header: key,
    cell: (d: Doc) => {
      const v = d[key];
      return v === undefined ? '' : typeof v === 'string' ? v : JSON.stringify(v);
    },
  }));
}

interface Query {
  filter: string;
  sort: string;
  limit: number;
}

/**
 * S07 Document explorer (PD-126, PD-133): RGQL filter expression, sort, page size and keyset
 * pagination over `GET …/documents`, as a grid with inferred columns or raw JSON. The filter is
 * validated by the server (the list call answers RGN-1001 with the parser's message).
 */
@Component({
  selector: 'rg-documents-page',
  imports: [...FIELD, CodeBlock, DataGrid, EmptyState, ErrorPanel, Icon, Skeleton, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './documents.page.html',
})
export class DocumentsPage {
  protected readonly fitGrid = fitGrid;
  readonly db = input.required<string>();
  readonly coll = input.required<string>();
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  private readonly router = inject(Router);
  private readonly notify = inject(NotificationService);
  private readonly perms = inject(PermissionsService);

  protected readonly sizes = [25, 100, 500];
  protected readonly query = signal<Query>({ filter: '', sort: '', limit: 100 });
  /** Continuation token of each visited page (keyset pagination); reset by a new query. */
  protected readonly tokens = linkedSignal<unknown, (string | undefined)[]>({
    source: () => [this.db(), this.coll(), this.query()],
    computation: () => [undefined],
  });
  protected readonly view = signal<'grid' | 'json'>('grid');
  protected readonly failure = signal<unknown>(undefined);

  protected readonly page = resource({
    params: () => ({
      db: this.db(),
      coll: this.coll(),
      ...this.query(),
      token: this.tokens().at(-1),
    }),
    loader: async ({ params: p }) => {
      const r = await this.api.get('/api/v1/databases/{db}/collections/{coll}/documents', {
        path: { db: p.db, coll: p.coll },
        query: {
          filter: p.filter || undefined,
          sort: p.sort || undefined,
          limit: p.limit,
          continuationToken: p.token,
        },
      });
      return { documents: r.documents as Doc[], continuationToken: r.continuationToken };
    },
  });

  protected readonly columns = computed(() => inferColumns(this.page.value()?.documents ?? []));
  protected readonly json = computed(() =>
    JSON.stringify(this.page.value()?.documents ?? [], null, 2),
  );

  protected can(action: Action): boolean {
    return this.perms.can(action, { db: this.db() });
  }

  protected apply(filter: string, sort: string): void {
    this.query.update((q) => ({ ...q, filter: filter.trim(), sort: sort.trim() }));
  }

  protected setLimit(limit: number): void {
    this.query.update((q) => ({ ...q, limit }));
  }

  protected next(token: string | null | undefined): void {
    if (token) this.tokens.update((t) => [...t, token]);
  }

  protected previous(): void {
    this.tokens.update((t) => t.slice(0, -1));
  }

  protected open(d: Doc): void {
    void this.router.navigate(docLink(this.db(), this.coll(), d['_id']));
  }

  protected validator(): void {
    void this.dialog
      .open<boolean>(ValidatorDialog, { db: this.db(), coll: this.coll() }, { size: 'lg' })
      .then((saved) => {
        if (saved) void this.notify.announce($localize`:@@data.validator.saved:Validator saved.`);
      });
  }

  protected async drop(): Promise<void> {
    const db = this.db();
    const coll = this.coll();
    const ok = await confirm(this.dialog, {
      title: $localize`:@@data.collections.dropTitle:Drop collection`,
      message: $localize`:@@data.collections.dropMessage:This permanently deletes collection ${coll}:coll: with all its documents and indexes.`,
      confirmLabel: $localize`:@@data.collections.dropTitle:Drop collection`,
      typedConfirmation: coll,
    });
    if (!ok) return;
    this.failure.set(undefined);
    try {
      await this.api.request('delete', '/api/v1/databases/{db}/collections/{coll}', {
        path: { db, coll },
      });
      this.notify.toast($localize`:@@data.collections.dropped:Collection ${coll}:coll: dropped.`);
      void this.router.navigate(['/db', db]);
    } catch (e) {
      this.failure.set(e);
    }
  }
}
