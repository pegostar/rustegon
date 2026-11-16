import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  resource,
  signal,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { NotificationService } from '../../core/notification.service';
import { PermissionsService } from '../../core/permissions.service';
import { confirm } from '../../shared/confirm-dialog';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { JsonEditor } from '../../shared/json-editor';
import { Skeleton } from '../../shared/skeleton';
import { Doc, docLink } from './documents.page';
import { Dialogs } from '../../shared/dialog';

/** Fields the server maintains and rejects as input (data-model.md §2.2, FR-DOC-005). */
export const SERVER_FIELDS = ['_rev', '_createdAt', '_updatedAt', '_conflict', '_origin'];
/** Document size limit (system-overview.md §9). */
export const MAX_DOC_BYTES = 16 * 1024 * 1024;

/** Splits a stored document into the editable part and the server-maintained metadata. */
export function splitDocument(doc: Doc): { body: Doc; meta: Doc } {
  const body: Doc = {};
  const meta: Doc = {};
  for (const [k, v] of Object.entries(doc)) (SERVER_FIELDS.includes(k) ? meta : body)[k] = v;
  return { body, meta };
}

/**
 * S08 Document editor (PD-126, PD-133): insert, replace with optimistic concurrency
 * (`If-Match: "<_rev>"`; on RGN-2009 reload or overwrite), delete, duplicate. The JSON text
 * excludes the server-maintained fields, which the metadata panel shows. `_id` cannot change
 * on edit (the URL names the document).
 */
@Component({
  selector: 'rg-document-page',
  imports: [ErrorPanel, Icon, JsonEditor, Skeleton, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './document.page.html',
})
export class DocumentPage {
  readonly db = input.required<string>();
  readonly coll = input.required<string>();
  /** The `_id` as extended-JSON text (PD-135); absent for a new document. */
  readonly id = input<string>();
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  private readonly router = inject(Router);
  private readonly notify = inject(NotificationService);
  protected readonly perms = inject(PermissionsService);

  protected readonly isNew = computed(() => this.id() === undefined);
  protected readonly text = signal(
    (this.router.currentNavigation()?.extras.state?.['draft'] as string | undefined) ?? '{\n  \n}',
  );
  protected readonly meta = signal<Doc>({});
  private readonly loadedId = signal<unknown>(undefined);
  protected readonly failure = signal<unknown>(undefined);
  /** The save or delete met RGN-2009: someone else changed the document. */
  protected readonly conflict = signal(false);
  protected readonly busy = signal(false);

  protected readonly doc = resource({
    params: () => {
      const id = this.id();
      return id === undefined ? undefined : { db: this.db(), coll: this.coll(), id };
    },
    loader: async ({ params }) => {
      const { document } = await this.api.get(
        '/api/v1/databases/{db}/collections/{coll}/documents/{id}',
        { path: params },
      );
      this.show(document as Doc);
      return true;
    },
  });

  protected readonly bytes = computed(() => new TextEncoder().encode(this.text()).length);
  protected readonly syntaxError = computed(() => {
    try {
      const v: unknown = JSON.parse(this.text());
      return v !== null && typeof v === 'object' && !Array.isArray(v)
        ? ''
        : $localize`:@@data.doc.notObject:A document is a JSON object.`;
    } catch (e) {
      return $localize`:@@data.json.syntax:Invalid JSON: ${(e as Error).message}:message:`;
    }
  });
  protected readonly metaRows = computed(() =>
    Object.entries({ _id: this.loadedId(), ...this.meta() })
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => ({ k, v: typeof v === 'string' ? v : JSON.stringify(v) })),
  );
  protected readonly canWrite = computed(() =>
    this.perms.can(this.isNew() ? 'insert' : 'update', { db: this.db() }),
  );
  protected readonly canDelete = computed(() => this.perms.can('delete', { db: this.db() }));
  protected readonly tooBig = computed(() => this.bytes() > MAX_DOC_BYTES);
  protected readonly maxBytes = MAX_DOC_BYTES;

  private show(document: Doc): void {
    const { body, meta } = splitDocument(document);
    this.text.set(JSON.stringify(body, null, 2));
    this.meta.set(meta);
    this.loadedId.set(body['_id']);
    this.conflict.set(false);
  }

  private rev(): string | undefined {
    const r = this.meta()['_rev'];
    return typeof r === 'string' ? r : undefined;
  }

  protected reload(): void {
    this.conflict.set(false);
    this.failure.set(undefined);
    this.doc.reload();
  }

  protected async save(overwrite = false): Promise<void> {
    if (this.syntaxError() || this.tooBig()) return;
    const body = JSON.parse(this.text()) as Doc;
    const { db, coll } = { db: this.db(), coll: this.coll() };
    const id = this.id();
    if (id !== undefined && '_id' in body) {
      if (JSON.stringify(body['_id']) !== JSON.stringify(this.loadedId())) {
        this.failure.set(
          new ApiError(
            0,
            0,
            'Client',
            $localize`:@@data.doc.idImmutable:The _id of a stored document cannot change; use Duplicate to store a copy under a new _id.`,
            false,
          ),
        );
        return;
      }
    }
    await this.run(async () => {
      if (id === undefined) {
        const r = await this.api.request(
          'post',
          '/api/v1/databases/{db}/collections/{coll}/documents',
          {
            path: { db, coll },
            body: { documents: [body as Record<string, never>] },
          },
        );
        void this.notify.announce($localize`:@@data.doc.inserted:Document inserted.`);
        await this.router.navigate(docLink(db, coll, r.results[0]?.id), { replaceUrl: true });
        return;
      }
      const rev = this.rev();
      const r = await this.api.request(
        'put',
        '/api/v1/databases/{db}/collections/{coll}/documents/{id}',
        {
          path: { db, coll, id },
          query: { returnDocument: 'after' },
          body: body as Record<string, never>,
          headers: rev && !overwrite ? { 'If-Match': `"${rev}"` } : {},
        },
      );
      if (r.document) this.show(r.document as Doc);
      void this.notify.announce($localize`:@@data.doc.saved:Document saved.`);
    });
  }

  protected async remove(): Promise<void> {
    const id = this.id();
    if (id === undefined) return;
    const ok = await confirm(this.dialog, {
      title: $localize`:@@data.doc.deleteTitle:Delete document`,
      message: $localize`:@@data.doc.deleteMessage:This permanently deletes the document with _id ${id}:id:.`,
      confirmLabel: $localize`:@@data.doc.deleteTitle:Delete document`,
    });
    if (!ok) return;
    const { db, coll } = { db: this.db(), coll: this.coll() };
    const rev = this.rev();
    await this.run(async () => {
      await this.api.request('delete', '/api/v1/databases/{db}/collections/{coll}/documents/{id}', {
        path: { db, coll, id },
        headers: rev ? { 'If-Match': `"${rev}"` } : {},
      });
      this.notify.toast($localize`:@@data.doc.deleted:Document deleted.`);
      await this.router.navigate(['/db', db, 'c', coll]);
    });
  }

  protected duplicate(): void {
    if (this.syntaxError()) return;
    const body = JSON.parse(this.text()) as Doc;
    delete body['_id'];
    void this.router.navigate(['/db', this.db(), 'c', this.coll(), 'new'], {
      state: { draft: JSON.stringify(body, null, 2) },
    });
  }

  private async run(call: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.failure.set(undefined);
    this.conflict.set(false);
    try {
      await call();
    } catch (e) {
      const err = ApiError.from(e);
      if (err.code === 2009) this.conflict.set(true);
      else this.failure.set(err);
    } finally {
      this.busy.set(false);
    }
  }

  /** JSON pointer of the first validator violation (RGN-1006 `details.path`). */
  protected readonly failedPath = computed(() => {
    const f = this.failure();
    return f instanceof ApiError && f.code === 1006 ? (f.details['path'] ?? '') : '';
  });
}
