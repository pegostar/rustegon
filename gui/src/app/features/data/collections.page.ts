import { ChangeDetectionStrategy, Component, inject, input, resource, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ApiClient } from '../../api/api-client';
import type { components } from '../../api/schema';
import { NotificationService } from '../../core/notification.service';
import { PermissionsService } from '../../core/permissions.service';
import { confirm } from '../../shared/confirm-dialog';
import { DataGrid, GridColumn } from '../../shared/data-grid';
import { EmptyState } from '../../shared/empty-state';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { Skeleton } from '../../shared/skeleton';
import { CreateData, CreateDialog } from './create-dialog';
import { fitGrid } from './documents.page';
import { Dialogs } from '../../shared/dialog';

type Collection = components['schemas']['CollectionJson'];

/**
 * S06 Collections of one database (PD-126, PD-133): name and validator. R1 collections are
 * document collections without alterable options, so kind, shard key, compression, TTL,
 * revisions, CDC images, statistics and split points are not shown; the validator is edited on
 * the collection page (S07). Dropping the database needs its name typed (§2).
 */
@Component({
  selector: 'rg-collections-page',
  imports: [DataGrid, EmptyState, ErrorPanel, Icon, Skeleton, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="rg-page-header">
      <div>
        <nav class="rg-crumbs" i18n-aria-label="@@data.breadcrumb" aria-label="Breadcrumb">
          <ol>
            <li>
              <a routerLink="/data"
                ><rg-icon name="data" [size]="16" /><span i18n="@@data.databases.heading"
                  >Databases</span
                ></a
              >
            </li>
            <li>
              <a [routerLink]="['/db', db()]" aria-current="page">{{ db() }}</a>
            </li>
          </ol>
        </nav>
        <div class="rg-title">
          <span class="rg-title-icon"><rg-icon name="folder" [size]="22" /></span>
          <h1 i18n="@@data.collections.heading">Collections of {{ db() }}</h1>
          @if (colls.hasValue()) {
            <span class="rg-count" aria-hidden="true">{{ colls.value().length }}</span>
          }
        </div>
      </div>
      <div class="rg-actions">
        <button class="btn btn-glass" type="button" (click)="colls.reload()">
          <rg-icon name="refresh" /><span i18n="@@data.refresh">Refresh</span>
        </button>
        @if (can('drop_database')) {
          <button class="btn btn-outline-danger" type="button" (click)="drop()">
            <rg-icon name="delete" /><span i18n="@@data.databases.drop">Drop database</span>
          </button>
        }
        @if (can('create_collection')) {
          <button class="btn btn-primary" type="button" (click)="create()">
            <rg-icon name="add" /><span i18n="@@data.collections.create">Create collection</span>
          </button>
        }
      </div>
    </header>
    @if (failure(); as f) {
      <rg-error-panel class="mb-3" [error]="f" (retry)="drop()" />
    }
    <rg-skeleton [loading]="colls.isLoading()">
      @if (colls.error(); as e) {
        <rg-error-panel [error]="e" (retry)="colls.reload()" />
      } @else if (colls.value(); as rows) {
        @if (rows.length === 0) {
          <rg-empty-state
            class="rg-panel rg-empty-card rg-glide"
            icon="folder"
            i18n-heading="@@data.collections.empty"
            heading="No collections yet"
            i18n-message="@@data.collections.emptyMessage"
            message="Collections hold the documents of a database."
          >
            @if (can('create_collection')) {
              <button class="btn btn-primary" type="button" (click)="create()">
                <rg-icon name="add" /><span i18n="@@data.collections.create"
                  >Create collection</span
                >
              </button>
            }
          </rg-empty-state>
        } @else {
          <div class="rg-grid-frame rg-glide">
            <rg-data-grid
              [columns]="columns"
              [rows]="rows"
              [height]="fitGrid(rows.length)"
              i18n-label="@@data.collections.label"
              label="Collections"
              (rowActivate)="open($event)"
            />
          </div>
        }
      }
    </rg-skeleton>
  `,
})
export class CollectionsPage {
  protected readonly fitGrid = fitGrid;
  readonly db = input.required<string>();
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  private readonly router = inject(Router);
  private readonly notify = inject(NotificationService);
  private readonly perms = inject(PermissionsService);
  /** A failed drop, shown inline (§2: toasts only for background operations). */
  protected readonly failure = signal<unknown>(undefined);

  protected readonly columns: GridColumn<Collection>[] = [
    { key: 'name', header: $localize`:@@data.col.name:Name` },
    {
      key: 'validator',
      header: $localize`:@@data.col.validator:Validator`,
      cell: (c) =>
        c.validator
          ? `${c.validator.level ?? 'strict'} / ${c.validator.action ?? 'error'}`
          : $localize`:@@data.none:None`,
    },
  ];

  protected readonly colls = resource({
    params: () => ({ db: this.db() }),
    loader: async ({ params }) =>
      (await this.api.get('/api/v1/databases/{db}/collections', { path: params })).collections,
  });

  protected readonly can = (action: 'create_collection' | 'drop_database') =>
    this.perms.can(action, { db: this.db() });

  protected open(c: Collection): void {
    void this.router.navigate(['/db', this.db(), 'c', c.name]);
  }

  protected async create(): Promise<void> {
    const db = this.db();
    const data: CreateData = {
      title: $localize`:@@data.collections.createTitle:Create collection`,
      label: $localize`:@@data.collections.name:Collection name`,
      hint: $localize`:@@data.collections.rule:1–120 characters A–Z, a–z, 0–9, _, . and -, not starting with system.`,
      pattern: /^(?!system\.)[A-Za-z0-9_.-]{1,120}$/,
      submit: (name) =>
        this.api.request('post', '/api/v1/databases/{db}/collections', {
          path: { db },
          body: { name },
        }),
    };
    const name = await this.dialog.open<string>(CreateDialog, data);
    if (name) void this.router.navigate(['/db', db, 'c', name]);
  }

  protected async drop(): Promise<void> {
    const db = this.db();
    const ok = await confirm(this.dialog, {
      title: $localize`:@@data.databases.dropTitle:Drop database`,
      message: $localize`:@@data.databases.dropMessage:This permanently deletes database ${db}:db: with all its collections, documents and indexes.`,
      confirmLabel: $localize`:@@data.databases.dropTitle:Drop database`,
      typedConfirmation: db,
    });
    if (!ok) return;
    this.failure.set(undefined);
    try {
      await this.api.request('delete', '/api/v1/databases/{db}', { path: { db } });
      this.notify.toast($localize`:@@data.databases.dropped:Database ${db}:db: dropped.`);
      void this.router.navigateByUrl('/data');
    } catch (e) {
      this.failure.set(e);
    }
  }
}
