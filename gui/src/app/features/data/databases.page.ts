import { ChangeDetectionStrategy, Component, inject, resource } from '@angular/core';
import { Router } from '@angular/router';
import { ApiClient } from '../../api/api-client';
import { PermissionsService } from '../../core/permissions.service';
import { DataGrid, GridColumn } from '../../shared/data-grid';
import { EmptyState } from '../../shared/empty-state';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { Skeleton } from '../../shared/skeleton';
import { CreateData, CreateDialog } from './create-dialog';
import { fitGrid } from './documents.page';
import { Dialogs } from '../../shared/dialog';

export const IMPLICIT = 'implicit_collection_creation';

interface DbRow {
  name: string;
  collections: number;
  implicit: boolean;
}

/**
 * S05 Databases (PD-126 R1 scope, PD-133): name, collection count and the one database option
 * the server has; size, ranges, replication, survival goal and auto-index mode have no API yet.
 * Drop is on the database's own page (S06) behind a typed confirmation.
 */
@Component({
  selector: 'rg-databases-page',
  imports: [DataGrid, EmptyState, ErrorPanel, Icon, Skeleton],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <header class="rg-page-header">
      <div class="rg-title">
        <span class="rg-title-icon"><rg-icon name="data" [size]="22" /></span>
        <h1 i18n="@@data.databases.heading">Databases</h1>
      </div>
      <div class="rg-actions">
        <button class="btn btn-glass" type="button" (click)="dbs.reload()">
          <rg-icon name="refresh" /><span i18n="@@data.refresh">Refresh</span>
        </button>
        @if (canCreate) {
          <button class="btn btn-primary" type="button" (click)="create()">
            <rg-icon name="add" /><span i18n="@@data.databases.create">Create database</span>
          </button>
        }
      </div>
    </header>
    <rg-skeleton [loading]="dbs.isLoading()">
      @if (dbs.error(); as e) {
        <rg-error-panel [error]="e" (retry)="dbs.reload()" />
      } @else if (dbs.value(); as rows) {
        @if (rows.length === 0) {
          <rg-empty-state
            class="rg-panel rg-empty-card rg-glide"
            icon="data"
            i18n-heading="@@data.databases.empty"
            heading="No databases yet"
            i18n-message="@@data.databases.emptyMessage"
            message="A database groups collections; create one to start storing documents."
          >
            @if (canCreate) {
              <button class="btn btn-primary" type="button" (click)="create()">
                <rg-icon name="add" /><span i18n="@@data.databases.create">Create database</span>
              </button>
            }
          </rg-empty-state>
        } @else {
          <div class="rg-stack rg-stagger">
            <div class="rg-tiles">
              <section class="rg-panel rg-stat rg-lift">
                <p class="rg-stat-label" i18n="@@data.databases.heading">Databases</p>
                <p class="rg-stat-value rg-gradient-text">{{ rows.length }}</p>
                <span class="rg-stat-icon"><rg-icon name="data" /></span>
              </section>
              <section class="rg-panel rg-stat rg-lift">
                <p class="rg-stat-label" i18n="@@data.col.collections">Collections</p>
                <p class="rg-stat-value rg-gradient-text">{{ collectionCount(rows) }}</p>
                <span class="rg-stat-icon"><rg-icon name="folder" /></span>
              </section>
            </div>
            <div class="rg-grid-frame">
              <rg-data-grid
                [columns]="columns"
                [rows]="rows"
                [height]="fitGrid(rows.length)"
                i18n-label="@@data.databases.heading"
                label="Databases"
                (rowActivate)="open($event)"
              />
            </div>
          </div>
        }
      }
    </rg-skeleton>
  `,
})
export class DatabasesPage {
  protected readonly fitGrid = fitGrid;
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  private readonly router = inject(Router);
  protected readonly canCreate = inject(PermissionsService).can('create_database');

  protected readonly columns: GridColumn<DbRow>[] = [
    { key: 'name', header: $localize`:@@data.col.name:Name` },
    { key: 'collections', header: $localize`:@@data.col.collections:Collections`, width: '140px' },
    {
      key: 'implicit',
      header: $localize`:@@data.col.implicit:Collections on first write`,
      cell: (r) => (r.implicit ? $localize`:@@data.yes:Yes` : $localize`:@@data.no:No`),
    },
  ];

  protected readonly dbs = resource({
    loader: async (): Promise<DbRow[]> => {
      const { databases } = await this.api.get('/api/v1/databases');
      return Promise.all(
        databases.map(async (d) => ({
          name: d.name,
          collections: (
            await this.api.get('/api/v1/databases/{db}/collections', { path: { db: d.name } })
          ).collections.length,
          implicit: (d.options as Record<string, unknown>)[IMPLICIT] !== false,
        })),
      );
    },
  });

  protected collectionCount(rows: DbRow[]): number {
    return rows.reduce((n, r) => n + r.collections, 0);
  }

  protected open(row: DbRow): void {
    void this.router.navigate(['/db', row.name]);
  }

  protected async create(): Promise<void> {
    const data: CreateData = {
      title: $localize`:@@data.databases.createTitle:Create database`,
      label: $localize`:@@data.databases.name:Database name`,
      hint: $localize`:@@data.databases.rule:1–64 characters a–z, 0–9, _ and -, not starting with _`,
      pattern: /^[a-z0-9-][a-z0-9_-]{0,63}$/,
      implicitOption: true,
      submit: (name, implicit) =>
        this.api.request('post', '/api/v1/databases', {
          body: { name, options: { [IMPLICIT]: implicit } as unknown as Record<string, never> },
        }),
    };
    const name = await this.dialog.open<string>(CreateDialog, data);
    if (name) void this.router.navigate(['/db', name]);
  }
}
