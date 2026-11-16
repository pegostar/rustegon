import { JsonPipe } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  input,
  resource,
  signal,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import type { components } from '../../api/schema';
import { NotificationService } from '../../core/notification.service';
import { PermissionsService } from '../../core/permissions.service';
import { CodeBlock } from '../../shared/code-block';
import { confirm } from '../../shared/confirm-dialog';
import { DataGrid, GridColumn } from '../../shared/data-grid';
import { EmptyState } from '../../shared/empty-state';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { fitGrid } from '../data/documents.page';
import { Skeleton } from '../../shared/skeleton';
import { FIELD } from '../../shared/field';
import { Dialogs } from '../../shared/dialog';

type IndexJson = components['schemas']['IndexJson'];
type Progress = components['schemas']['IndexProgressResponse'];

/** The parts of the `CREATE INDEX` AST (query-language.md §13) the console reads and writes. */
interface IndexDefinition {
  index_type: string;
  name: string;
  on: { database?: string; name: string };
  keys: { path: (string | number)[]; descending?: boolean }[];
  options?: { name: string; value: { kind: string; value?: unknown } }[];
}

export interface IndexRow {
  name: string;
  kind: string;
  fields: string;
  options: string;
  state: string;
  error: string;
}

export interface IndexForm {
  name: string;
  fields: string;
  unique: boolean;
  sparse: boolean;
  partial: string;
}

/**
 * `CREATE INDEX` in the AST JSON form (`definition` of `POST …/indexes`). Fields are
 * comma-separated paths, `-path` or `path DESC` for descending. The server accepts only the
 * canonical AST, which is what the parser yields for these inputs.
 */
export function indexDefinition(db: string, coll: string, f: IndexForm): IndexDefinition {
  const keys = f.fields
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const descending = s.startsWith('-') || /\s+desc$/i.test(s);
      const path = s
        .replace(/^-/, '')
        .replace(/\s+(asc|desc)$/i, '')
        .split('.')
        .map((seg) => (/^\d+$/.test(seg) ? Number(seg) : seg));
      return descending ? { path, descending } : { path };
    });
  const options: NonNullable<IndexDefinition['options']> = [];
  if (f.sparse) options.push({ name: 'sparse', value: { kind: 'literal', value: true } });
  if (f.partial.trim())
    options.push({ name: 'partial', value: { kind: 'literal', value: f.partial.trim() } });
  return {
    index_type: f.unique ? 'unique' : 'standard',
    name: f.name.trim(),
    on: { database: db, name: coll },
    keys,
    ...(options.length ? { options } : {}),
  };
}

function toRow(ix: IndexJson, progress?: Progress): IndexRow {
  const d = ix.definition as unknown as IndexDefinition;
  const opts = (d.options ?? []).map((o) =>
    o.value.value === true ? o.name : `${o.name} = ${JSON.stringify(o.value.value)}`,
  );
  let state: string = ix.state;
  if (ix.state === 'building' && progress && progress.docsTotal > 0)
    state = `building ${Math.min(100, Math.floor((progress.docsProcessed / progress.docsTotal) * 100))} %`;
  return {
    name: d.name,
    kind: d.index_type,
    fields: d.keys.map((k) => k.path.join('.') + (k.descending ? ' DESC' : '')).join(', '),
    options: opts.join(', '),
    state,
    error: ix.error ?? '',
  };
}

/**
 * S11 indexes (angular-gui.md §4; R1 scope PD-126, omissions PD-138): list per collection with
 * build progress, create (standard/unique), details and drop. `db`, `coll` and `fields` come from
 * the URL (deep links, "Create suggested index" of S10).
 */
@Component({
  selector: 'rg-indexes-page',
  imports: [
    ...FIELD,
    JsonPipe,
    RouterLink,
    CodeBlock,
    DataGrid,
    EmptyState,
    ErrorPanel,
    Icon,
    Skeleton,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './indexes.page.html',
})
export class IndexesPage {
  protected readonly fitGrid = fitGrid;
  private readonly api = inject(ApiClient);
  private readonly router = inject(Router);
  private readonly dialog = inject(Dialogs);
  private readonly notify = inject(NotificationService);
  private readonly perms = inject(PermissionsService);

  /** Query parameters (withComponentInputBinding). */
  readonly db = input<string>();
  readonly coll = input<string>();
  readonly fields = input<string>();

  protected readonly databases = resource({
    loader: async () => (await this.api.get('/api/v1/databases')).databases.map((d) => d.name),
  });
  protected readonly selectedDb = computed(
    () => this.db() || (this.databases.hasValue() && this.databases.value()[0]) || '',
  );
  protected readonly collections = resource({
    params: () => this.selectedDb() || undefined,
    loader: async ({ params: db }) =>
      (await this.api.get('/api/v1/databases/{db}/collections', { path: { db } })).collections.map(
        (c) => c.name,
      ),
  });
  protected readonly selectedColl = computed(
    () => this.coll() || (this.collections.hasValue() && this.collections.value()[0]) || '',
  );
  protected readonly indexes = resource({
    params: () =>
      this.selectedDb() && this.selectedColl()
        ? { db: this.selectedDb(), coll: this.selectedColl() }
        : undefined,
    loader: async ({ params: { db, coll } }) => {
      const { indexes } = await this.api.get('/api/v1/databases/{db}/collections/{coll}/indexes', {
        path: { db, coll },
      });
      return Promise.all(
        indexes.map(async (ix) => {
          if (ix.state !== 'building') return toRow(ix);
          const name = (ix.definition as unknown as IndexDefinition).name;
          const p = await this.api
            .get('/api/v1/databases/{db}/collections/{coll}/indexes/{name}/progress', {
              path: { db, coll, name },
            })
            .catch(() => undefined);
          return toRow(ix, p);
        }),
      );
    },
  });

  protected readonly canCreate = computed(() =>
    this.perms.can('create_index', { db: this.selectedDb() }),
  );
  protected readonly canDrop = computed(() =>
    this.perms.can('drop_index', { db: this.selectedDb() }),
  );

  protected readonly columns: GridColumn<IndexRow>[] = [
    { key: 'name', header: $localize`:@@indexes.colName:Name` },
    { key: 'kind', header: $localize`:@@indexes.colKind:Kind`, width: '120px' },
    { key: 'fields', header: $localize`:@@indexes.colFields:Fields` },
    { key: 'options', header: $localize`:@@indexes.colOptions:Options` },
    { key: 'state', header: $localize`:@@indexes.colState:State`, width: '140px' },
    { key: 'error', header: $localize`:@@indexes.colError:Error` },
  ];

  // Details of the activated row (GET …/indexes/{name}).
  protected readonly selected = signal<string | null>(null);
  protected readonly detail = resource({
    params: () => {
      const name = this.selected();
      return name ? { db: this.selectedDb(), coll: this.selectedColl(), name } : undefined;
    },
    loader: ({ params: { db, coll, name } }) =>
      this.api.get('/api/v1/databases/{db}/collections/{coll}/indexes/{name}', {
        path: { db, coll, name },
      }),
  });

  // Create form.
  protected readonly creating = signal(false);
  protected readonly form = signal<IndexForm>({
    name: '',
    fields: '',
    unique: false,
    sparse: false,
    partial: '',
  });
  protected readonly submitted = signal(false);
  protected readonly nameError = computed(() =>
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(this.form().name.trim())
      ? ''
      : $localize`:@@indexes.nameInvalid:Use letters, digits and _ (not starting with a digit).`,
  );
  protected readonly fieldsError = computed(() =>
    this.form().fields.trim() ? '' : $localize`:@@indexes.fieldsRequired:Enter at least one field.`,
  );
  protected readonly createError = signal<ApiError | null>(null);
  protected readonly busy = signal(false);

  constructor() {
    // A suggestion from S10 opens the form prefilled.
    effect(() => {
      const f = this.fields();
      if (!f) return;
      const keys = f.split(',').filter(Boolean);
      this.form.set({
        name: `ix_${keys.map((k) => k.replace(/\W/g, '_')).join('_')}`.slice(0, 64),
        fields: keys.join(', '),
        unique: false,
        sparse: false,
        partial: '',
      });
      this.creating.set(true);
    });
  }

  protected select(db: string, coll?: string): void {
    this.selected.set(null);
    void this.router.navigate([], {
      queryParams: { db, coll: coll ?? null, fields: null },
      replaceUrl: true,
    });
  }

  protected patch(p: Partial<IndexForm>): void {
    this.form.update((f) => ({ ...f, ...p }));
  }

  protected openCreate(): void {
    this.form.set({ name: '', fields: '', unique: false, sparse: false, partial: '' });
    this.submitted.set(false);
    this.createError.set(null);
    this.creating.set(true);
  }

  protected async create(): Promise<void> {
    this.submitted.set(true);
    if (this.nameError() || this.fieldsError()) return;
    const db = this.selectedDb();
    const coll = this.selectedColl();
    this.busy.set(true);
    this.createError.set(null);
    try {
      await this.api.request('post', '/api/v1/databases/{db}/collections/{coll}/indexes', {
        path: { db, coll },
        body: {
          definition: indexDefinition(db, coll, this.form()) as unknown as Record<string, never>,
        },
      });
      this.creating.set(false);
      this.notify.announce($localize`:@@indexes.created:Index ${this.form().name}:name: created.`);
      this.indexes.reload();
    } catch (e) {
      this.createError.set(ApiError.from(e));
    } finally {
      this.busy.set(false);
    }
  }

  protected async drop(name: string): Promise<void> {
    const ok = await confirm(this.dialog, {
      title: $localize`:@@indexes.dropTitle:Drop index ${name}:name:?`,
      message: $localize`:@@indexes.dropMessage:Queries that use this index fall back to other indexes or a collection scan and may become much slower.`,
      confirmLabel: $localize`:@@indexes.dropConfirm:Drop`,
    });
    if (!ok) return;
    try {
      await this.api.request('delete', '/api/v1/databases/{db}/collections/{coll}/indexes/{name}', {
        path: { db: this.selectedDb(), coll: this.selectedColl(), name },
      });
      this.selected.set(null);
      this.notify.announce($localize`:@@indexes.dropped:Index ${name}:name: dropped.`);
    } catch (e) {
      this.notify.toast(ApiError.from(e).message);
    }
    this.indexes.reload();
  }
}
