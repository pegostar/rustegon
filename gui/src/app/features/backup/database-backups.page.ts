import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject, resource, signal } from '@angular/core';
import { FormControl, ReactiveFormsModule, Validators } from '@angular/forms';
import { ApiClient } from '../../api/api-client';
import type { components } from '../../api/schema';
import { confirm } from '../../shared/confirm-dialog';
import { Dialogs } from '../../shared/dialog';
import { EmptyState } from '../../shared/empty-state';
import { ErrorPanel } from '../../shared/error-panel';
import { FIELD } from '../../shared/field';
import { Icon } from '../../shared/icon';
import { Skeleton } from '../../shared/skeleton';
import { StatusBadge } from '../../shared/status-badge';
import { Mutation } from '../security/common';
import { BackupNav, destinationSuggestions, LONG_OP_MS } from './common';

type Dump = components['schemas']['DumpJson'];
type Restored = components['schemas']['RestoreDumpResponse'];

/** Documents of a dump, all collections of all its databases. */
export function dumpDocuments(d: Dump): number {
  return d.databases.reduce((n, db) => n + db.collections.reduce((m, c) => m + c.documents, 0), 0);
}

/**
 * Backup and restore of one database (FR-BKP-007, PD-226): the server writes a logical dump of
 * the database (documents, collection options, validators, indexes; never users, roles or
 * settings) to `dumps/<id>/` at a destination it allows, and restores it from there online.
 * The restore replaces the dumped collections of that database only; everything else on the
 * node is untouched.
 */
@Component({
  selector: 'rg-database-backups-page',
  imports: [
    ...FIELD,
    DatePipe,
    ReactiveFormsModule,
    EmptyState,
    ErrorPanel,
    Icon,
    Skeleton,
    StatusBadge,
    BackupNav,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: '../security/page.scss',
  template: `
    <header class="rg-page-header rg-hero">
      <div class="rg-hero-title">
        <span class="rg-page-icon"><rg-icon name="backup" /></span>
        <h1 i18n="@@dbBackups.heading">Database backups</h1>
      </div>
    </header>
    <rg-backup-nav />

    <p class="hint" i18n="@@dbBackups.intro">
      Back up a single database while it stays online: its documents, collection options, validators
      and indexes. Users, roles and settings are not included. Restoring replaces only the
      collections of that database; the rest of the node is not touched. Each backup is one
      compressed .dbck file in the destination.
    </p>

    @if (mutation.error(); as e) {
      <rg-error-panel [error]="e" />
    }
    @if (mutation.busy()) {
      <p class="rg-note" role="status" i18n="@@dbBackups.working">
        Working… this can take a while for a large database.
      </p>
    }

    <section class="panel wide rg-panel" aria-labelledby="dbb-heading">
      <h2 id="dbb-heading" i18n="@@dbBackups.formHeading">Back up a database</h2>
      <form class="inline-form" (submit)="$event.preventDefault(); show()">
        <rg-field>
          <label rgLabel i18n="@@dbBackups.database">Database</label>
          <select rgControl [formControl]="database">
            @for (name of databases.value() ?? []; track name) {
              <option [value]="name">{{ name }}</option>
            }
          </select>
        </rg-field>
        <rg-field>
          <label rgLabel i18n="@@backups.destinationLabel">Backup destination</label>
          <input rgControl [formControl]="dest" list="rg-dbb-suggestions" autocomplete="off" />
          <datalist id="rg-dbb-suggestions">
            @for (s of suggestions.value() ?? []; track s) {
              <option [value]="s"></option>
            }
          </datalist>
          <rg-hint i18n="@@backups.destinationHint"
            >Absolute path on the server, file:// or s3:// URL, allowed by
            backup.allowed_destinations.</rg-hint
          >
        </rg-field>
        <button class="btn btn-glass" type="submit" i18n="@@dbBackups.show">
          Show database backups
        </button>
        <button
          class="btn btn-primary"
          type="button"
          [disabled]="mutation.busy() || !database.value"
          (click)="start()"
          i18n="@@dbBackups.start"
        >
          Back up database
        </button>
      </form>
    </section>

    @if (restored(); as r) {
      <section class="panel wide rg-panel" aria-labelledby="dbb-restored-heading">
        <h2 id="dbb-restored-heading" i18n="@@dbBackups.restoredHeading">Restored</h2>
        <ul>
          @for (c of r.collections; track c.database + '.' + c.collection) {
            <li i18n="@@dbBackups.restoredLine">
              {{ c.database }}.{{ c.collection }}: {{ c.documents }} documents,
              {{ c.indexes }} indexes
            </li>
          }
        </ul>
      </section>
    }

    @if (destination()) {
      <rg-skeleton [loading]="dumps.isLoading()">
        @if (dumps.error(); as e) {
          <rg-error-panel [error]="e" (retry)="dumps.reload()" />
        } @else if (dumps.value(); as list) {
          @if (list.dumps.length === 0 && list.unreadable.length === 0) {
            <rg-empty-state
              class="rg-panel"
              icon="backup"
              i18n-heading="@@dbBackups.empty"
              heading="No database backups at this destination"
              i18n-message="@@dbBackups.emptyMessage"
              message="Choose a database and back it up to write a copy of it here."
            />
          } @else {
            <div class="rg-table">
              <table class="table table-hover">
                <caption class="cdk-visually-hidden" i18n="@@dbBackups.caption">
                  Database backups
                </caption>
                <thead>
                  <tr>
                    <th scope="col" i18n="@@dbBackups.colId">Backup id</th>
                    <th scope="col" i18n="@@dbBackups.colCreated">Taken at</th>
                    <th scope="col" i18n="@@dbBackups.colDatabases">Databases</th>
                    <th scope="col" i18n="@@dbBackups.colDocuments">Documents</th>
                    <th scope="col" i18n="@@dbBackups.colActions">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  @for (d of list.dumps; track d.dumpId) {
                    <tr>
                      <th scope="row">
                        <code>{{ d.dumpId }}</code>
                      </th>
                      <td>
                        <span [title]="d.createdAtUnixMs | date: 'yyyy-MM-dd HH:mm:ss' : 'UTC'">{{
                          d.createdAtUnixMs | date: 'medium'
                        }}</span>
                      </td>
                      <td>{{ names(d) }}</td>
                      <td>{{ documents(d) }}</td>
                      <td>
                        <button
                          class="btn btn-ghost btn-sm"
                          type="button"
                          [disabled]="mutation.busy()"
                          (click)="restore(d)"
                          [attr.aria-label]="restoreLabel(d)"
                          i18n="@@dbBackups.restore"
                        >
                          Restore…
                        </button>
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
            @for (u of list.unreadable; track u.dumpId) {
              <p class="rg-note">
                <rg-status-badge
                  status="error"
                  i18n-label="@@backups.unreadable"
                  label="Unreadable"
                />
                <code>{{ u.dumpId }}</code>: {{ u.error.message }} (RGN-{{ u.error.code }})
              </p>
            }
          }
        }
      </rg-skeleton>
    }
  `,
})
export class DatabaseBackupsPage {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  protected readonly mutation = new Mutation();
  protected readonly dest = new FormControl('', {
    nonNullable: true,
    validators: [Validators.required],
  });
  protected readonly database = new FormControl('', { nonNullable: true });
  protected readonly destination = signal<string | undefined>(undefined);
  protected readonly restored = signal<Restored | null>(null);

  protected readonly suggestions = resource({
    loader: async () => {
      const out = await destinationSuggestions(this.api);
      if (out.length && !this.dest.value) this.dest.setValue(out[0]);
      return out;
    },
  });

  /** User databases (names starting with `_` are internal and never dumped). */
  protected readonly databases = resource({
    loader: async () => {
      const { databases } = await this.api.get('/api/v1/databases');
      const names = databases.map((d) => d.name).filter((n) => !n.startsWith('_'));
      if (names.length && !this.database.value) this.database.setValue(names[0]);
      return names;
    },
  });

  protected readonly dumps = resource({
    params: () => this.destination(),
    loader: ({ params: destination }) => this.api.get('/api/v1/dumps', { query: { destination } }),
  });

  protected names(d: Dump): string {
    return d.databases.map((db) => db.name).join(', ');
  }

  protected documents(d: Dump): number {
    return dumpDocuments(d);
  }

  protected restoreLabel(d: Dump): string {
    return $localize`:@@dbBackups.restoreLabel:Restore ${this.names(d)}:databases: from ${d.dumpId}:id:`;
  }

  protected show(): void {
    const d = this.dest.value.trim();
    if (!d) return;
    if (d === this.destination()) this.dumps.reload();
    else this.destination.set(d);
  }

  protected async start(): Promise<void> {
    const destination = this.dest.value.trim();
    const database = this.database.value;
    if (!destination) {
      this.dest.markAsTouched();
      return;
    }
    if (!database) return;
    this.restored.set(null);
    const ok = await this.mutation.run(
      () =>
        this.api.request('post', '/api/v1/dumps', {
          body: { destination, databases: [database] },
          timeoutMs: LONG_OP_MS,
        }),
      $localize`:@@dbBackups.done:Database backup complete.`,
    );
    if (ok) {
      if (destination === this.destination()) this.dumps.reload();
      else this.destination.set(destination);
    }
  }

  protected async restore(d: Dump): Promise<void> {
    const destination = this.destination();
    if (!destination) return;
    const names = this.names(d);
    if (
      !(await confirm(this.dialog, {
        title: $localize`:@@dbBackups.restoreTitle:Restore ${names}:databases:?`,
        message: $localize`:@@dbBackups.restoreMessage:Every collection in this backup replaces the collection of the same name in ${names}:databases:; changes made after the backup are lost. Collections that are not in the backup and other databases are not touched.`,
        confirmLabel: $localize`:@@dbBackups.restoreConfirm:Restore`,
      }))
    )
      return;
    this.restored.set(null);
    await this.mutation.run(
      async () => {
        this.restored.set(
          await this.api.request('post', '/api/v1/dumps/{dump_id}/restore', {
            path: { dump_id: d.dumpId },
            body: {
              destination,
              databases: d.databases.map((db) => db.name),
              dropExisting: true,
            },
            timeoutMs: LONG_OP_MS,
          }),
        );
      },
      $localize`:@@dbBackups.restored:Database restored.`,
    );
  }
}
