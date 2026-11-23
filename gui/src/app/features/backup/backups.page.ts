import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject, resource, signal } from '@angular/core';
import { FormControl, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiClient } from '../../api/api-client';
import type { components } from '../../api/schema';
import { confirm } from '../../shared/confirm-dialog';
import { EmptyState } from '../../shared/empty-state';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { Bytes } from '../../shared/format';
import { Skeleton } from '../../shared/skeleton';
import { StatusBadge } from '../../shared/status-badge';
import { Mutation } from '../security/common';
import { BackupNav, destinationSuggestions, LONG_OP_MS } from './common';
import { FIELD } from '../../shared/field';
import { Dialogs } from '../../shared/dialog';

type Backup = components['schemas']['BackupJson'];
type Warning = components['schemas']['WarningJson'];
type Verified = components['schemas']['VerifyBackupResponse'];

/** Snapshot name rule of the server (`SnapshotName`). */
const SNAPSHOT_NAME = /^(?!\.)[A-Za-z0-9._-]{1,64}$/;

/**
 * S22 Backups (PD-126 scope): online backup of the node to a destination the server allows
 * (`backup.allowed_destinations`, default `<data_dir>/backups`), list and inspect the backups
 * at a destination, verify (shallow or deep), and the node's local snapshots (create, delete).
 * Not in R1's API, so omitted (PD-142): schedules and retention, scope (always the whole node),
 * encryption/compression choices (server configuration), incremental backups, progress with ETA
 * (the call returns when the backup is complete), destination probe, deleting a backup.
 */
@Component({
  selector: 'rg-backups-page',
  imports: [
    ...FIELD,
    DatePipe,
    ReactiveFormsModule,
    RouterLink,
    Bytes,
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
        <h1 i18n="@@backups.heading">Backups</h1>
      </div>
    </header>
    <rg-backup-nav />

    @if (mutation.error(); as e) {
      <rg-error-panel [error]="e" />
    }
    @if (mutation.busy()) {
      <p class="rg-note" role="status" i18n="@@backups.working">
        Working… a backup can take a while.
      </p>
    }

    <section class="panel wide rg-panel" aria-labelledby="dest-heading">
      <h2 id="dest-heading" i18n="@@backups.destination">Destination</h2>
      <p class="hint" i18n="@@backups.formatHint">
        Each backup of the whole node is one compressed .nbck file in the destination.
      </p>
      <form class="inline-form" (submit)="$event.preventDefault(); show()">
        <rg-field>
          <label rgLabel i18n="@@backups.destinationLabel">Backup destination</label>
          <input rgControl [formControl]="dest" list="rg-dest-suggestions" autocomplete="off" />
          <datalist id="rg-dest-suggestions">
            @for (s of suggestions.value() ?? []; track s) {
              <option [value]="s"></option>
            }
          </datalist>
          <rg-hint i18n="@@backups.destinationHint"
            >Absolute path on the server, file:// or s3:// URL, allowed by
            backup.allowed_destinations.</rg-hint
          >
        </rg-field>
        <button class="btn btn-glass" type="submit" i18n="@@backups.show">Show backups</button>
        <button
          class="btn btn-primary"
          type="button"
          [disabled]="mutation.busy()"
          (click)="start()"
          i18n="@@backups.start"
        >
          Start backup
        </button>
      </form>
    </section>

    @if (warnings().length) {
      <section class="panel wide rg-panel" aria-labelledby="warn-heading">
        <h2 id="warn-heading" i18n="@@backups.warnings">Backup warnings</h2>
        <ul>
          @for (w of warnings(); track $index) {
            <li>{{ w.kind }}: {{ w.message }}</li>
          }
        </ul>
      </section>
    }

    @if (verified(); as v) {
      <section class="panel wide rg-panel" aria-labelledby="verify-heading">
        <h2 id="verify-heading" i18n="@@backups.verifiedHeading">Verification</h2>
        <p>
          <rg-status-badge status="ok" i18n-label="@@backups.verifiedOk" label="Verified" />
          <span i18n="@@backups.verifiedText"
            >Backup {{ v.backup.backupId }}: {{ v.filesChecked }} files checked,
            {{ v.bytesHashed }} bytes hashed.</span
          >
        </p>
      </section>
    }

    @if (destination()) {
      <rg-skeleton [loading]="backups.isLoading()">
        @if (backups.error(); as e) {
          <rg-error-panel [error]="e" (retry)="backups.reload()" />
        } @else if (backups.value(); as list) {
          @if (list.backups.length === 0 && list.unreadable.length === 0) {
            <rg-empty-state
              class="rg-panel"
              icon="backup"
              i18n-heading="@@backups.empty"
              heading="No backups at this destination"
              i18n-message="@@backups.emptyMessage"
              message="Start a backup to write a consistent copy of the node here."
            />
          } @else {
            <div class="rg-table">
              <table class="table table-hover">
                <caption class="cdk-visually-hidden" i18n="@@backups.caption">
                  Backups
                </caption>
                <thead>
                  <tr>
                    <th scope="col" i18n="@@backups.colId">Backup id</th>
                    <th scope="col" i18n="@@backups.colCreated">Created</th>
                    <th scope="col" i18n="@@backups.colSize">Size</th>
                    <th scope="col" i18n="@@backups.colFiles">Files</th>
                    <th scope="col" i18n="@@backups.colEncryption">Encryption</th>
                    <th scope="col" i18n="@@backups.colSource">Source</th>
                    <th scope="col" i18n="@@backups.colActions">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  @for (b of list.backups; track b.backupId) {
                    <tr>
                      <th scope="row">
                        <code>{{ b.backupId }}</code>
                      </th>
                      <td>
                        <span [title]="b.createdAtUnixMs | date: 'yyyy-MM-dd HH:mm:ss' : 'UTC'">{{
                          b.createdAtUnixMs | date: 'medium'
                        }}</span>
                      </td>
                      <td><rg-bytes [value]="b.totalBytes" /></td>
                      <td>{{ b.fileCount }}</td>
                      <td>{{ b.encryption }}</td>
                      <td>{{ b.sourceNodeId }} · {{ b.sourceServerVersion }}</td>
                      <td>
                        <div class="row-actions">
                          <button
                            class="btn btn-ghost btn-sm"
                            type="button"
                            (click)="details.set(b.backupId)"
                            i18n="@@backups.files"
                          >
                            Files
                          </button>
                          <button
                            class="btn btn-ghost btn-sm"
                            type="button"
                            [disabled]="mutation.busy()"
                            (click)="verify(b, false)"
                            i18n="@@backups.verify"
                          >
                            Verify
                          </button>
                          <button
                            class="btn btn-ghost btn-sm"
                            type="button"
                            [disabled]="mutation.busy()"
                            (click)="verify(b, true)"
                            i18n="@@backups.verifyDeep"
                          >
                            Deep verify
                          </button>
                          <a
                            class="btn btn-ghost btn-sm"
                            routerLink="/backup/restore"
                            [queryParams]="{ from: destination(), id: b.backupId }"
                            i18n="@@backups.restoreLink"
                            >Restore…</a
                          >
                        </div>
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
            @for (u of list.unreadable; track u.backupId) {
              <p class="rg-note">
                <rg-status-badge
                  status="error"
                  i18n-label="@@backups.unreadable"
                  label="Unreadable"
                />
                <code>{{ u.backupId }}</code>: {{ u.error.message }} (RGN-{{ u.error.code }})
              </p>
            }
          }
        }
      </rg-skeleton>
    }

    @if (details()) {
      <section class="panel wide rg-panel" aria-labelledby="files-heading">
        <h2 id="files-heading" i18n="@@backups.filesHeading">Files of {{ details() }}</h2>
        @if (files.error(); as e) {
          <rg-error-panel [error]="e" (retry)="files.reload()" />
        } @else if (files.value(); as f) {
          <div class="table-wrap">
            <table class="table table-hover">
              <caption class="cdk-visually-hidden" i18n="@@backups.filesCaption">
                Backup files
              </caption>
              <thead>
                <tr>
                  <th scope="col" i18n="@@backups.colPath">Path</th>
                  <th scope="col" i18n="@@backups.colSize">Size</th>
                  <th scope="col" i18n="@@backups.colHash">BLAKE3</th>
                </tr>
              </thead>
              <tbody>
                @for (x of f.files; track x.path) {
                  <tr>
                    <td>{{ x.path }}</td>
                    <td><rg-bytes [value]="x.size" /></td>
                    <td>
                      <code>{{ x.blake3 }}</code>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
        <div class="form-actions">
          <button
            class="btn btn-ghost"
            type="button"
            (click)="details.set(undefined)"
            i18n="@@backups.close"
          >
            Close
          </button>
        </div>
      </section>
    }

    <section class="panel wide rg-panel" aria-labelledby="snap-heading">
      <h2 id="snap-heading" i18n="@@snapshots.heading">Local snapshots</h2>
      <p class="hint" i18n="@@snapshots.hint">
        Hard-link checkpoints of the node's store in its data directory: fast, but not a copy on
        another disk.
      </p>
      <form class="inline-form" (submit)="$event.preventDefault(); createSnapshot()">
        <rg-field>
          <label rgLabel i18n="@@snapshots.name">Snapshot name</label>
          <input rgControl [formControl]="snapshotName" autocomplete="off" />
          @if (snapshotName.invalid && snapshotName.touched) {
            <rg-error i18n="@@snapshots.nameInvalid"
              >1 to 64 characters A–Z a–z 0–9 . _ -, not starting with a dot.</rg-error
            >
          }
        </rg-field>
        <button
          class="btn btn-glass"
          type="submit"
          [disabled]="mutation.busy()"
          i18n="@@snapshots.create"
        >
          Create snapshot
        </button>
      </form>
      <rg-skeleton [loading]="snapshots.isLoading()">
        @if (snapshots.error(); as e) {
          <rg-error-panel [error]="e" (retry)="snapshots.reload()" />
        } @else if (snapshots.value(); as list) {
          @if (list.length === 0) {
            <rg-empty-state
              icon="history"
              i18n-heading="@@snapshots.empty"
              heading="No snapshots"
              i18n-message="@@snapshots.emptyMessage"
              message="Create a snapshot before a risky change to roll the node back quickly."
            />
          } @else {
            <div class="table-wrap">
              <table class="table table-hover">
                <caption class="cdk-visually-hidden" i18n="@@snapshots.caption">
                  Snapshots
                </caption>
                <thead>
                  <tr>
                    <th scope="col" i18n="@@snapshots.colName">Name</th>
                    <th scope="col" i18n="@@snapshots.colCreated">Created</th>
                    <th scope="col" i18n="@@snapshots.colSize">Size</th>
                    <th scope="col" i18n="@@snapshots.colFiles">Files</th>
                    <th scope="col" i18n="@@snapshots.colActions">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  @for (s of list; track s.name) {
                    <tr>
                      <th scope="row">{{ s.name }}</th>
                      <td>
                        <span [title]="s.createdAtUnixMs | date: 'yyyy-MM-dd HH:mm:ss' : 'UTC'">{{
                          s.createdAtUnixMs | date: 'medium'
                        }}</span>
                      </td>
                      <td><rg-bytes [value]="s.totalBytes" /></td>
                      <td>{{ s.fileCount }}</td>
                      <td>
                        <div class="row-actions">
                          <a
                            class="btn btn-ghost btn-sm"
                            routerLink="/backup/restore"
                            [queryParams]="{ snapshot: s.name }"
                            i18n="@@snapshots.restoreLink"
                            >Restore…</a
                          >
                          <button
                            class="btn btn-ghost btn-sm danger"
                            type="button"
                            (click)="deleteSnapshot(s.name)"
                            [attr.aria-label]="deleteLabel(s.name)"
                            i18n="@@snapshots.delete"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        }
      </rg-skeleton>
    </section>
  `,
})
export class BackupsPage {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  protected readonly mutation = new Mutation();
  protected readonly dest = new FormControl('', {
    nonNullable: true,
    validators: [Validators.required],
  });
  protected readonly destination = signal<string | undefined>(undefined);
  protected readonly details = signal<string | undefined>(undefined);
  protected readonly warnings = signal<Warning[]>([]);
  protected readonly verified = signal<Verified | null>(null);
  protected readonly snapshotName = new FormControl('', {
    nonNullable: true,
    validators: [Validators.required, Validators.pattern(SNAPSHOT_NAME)],
  });

  /** `<data_dir>/backups` and the allowed destinations; none when settings are not readable. */
  protected readonly suggestions = resource({
    loader: async () => {
      const out = await destinationSuggestions(this.api);
      if (out.length && !this.dest.value) this.dest.setValue(out[0]);
      return out;
    },
  });

  protected readonly backups = resource({
    params: () => this.destination(),
    loader: ({ params: destination }) =>
      this.api.get('/api/v1/backups', { query: { destination } }),
  });

  protected readonly files = resource({
    params: () => {
      const id = this.details();
      const destination = this.destination();
      return id && destination ? { id, destination } : undefined;
    },
    loader: ({ params: { id, destination } }) =>
      this.api.get('/api/v1/backups/{backup_id}', {
        path: { backup_id: id },
        query: { destination },
      }),
  });

  protected readonly snapshots = resource({
    loader: async () => (await this.api.get('/api/v1/snapshots')).snapshots,
  });

  protected show(): void {
    const d = this.dest.value.trim();
    if (!d) return;
    this.details.set(undefined);
    if (d === this.destination()) this.backups.reload();
    else this.destination.set(d);
  }

  protected async start(): Promise<void> {
    const destination = this.dest.value.trim();
    if (!destination) {
      this.dest.markAsTouched();
      return;
    }
    this.warnings.set([]);
    this.verified.set(null);
    const ok = await this.mutation.run(
      async () => {
        const res = await this.api.request('post', '/api/v1/backups', {
          body: { destination },
          timeoutMs: LONG_OP_MS,
        });
        this.warnings.set(res.warnings);
      },
      $localize`:@@backups.done:Backup complete.`,
    );
    if (ok) {
      if (destination === this.destination()) this.backups.reload();
      else this.destination.set(destination);
    }
  }

  protected async verify(b: Backup, deep: boolean): Promise<void> {
    const destination = this.destination();
    if (!destination) return;
    this.verified.set(null);
    await this.mutation.run(
      async () => {
        this.verified.set(
          await this.api.request('post', '/api/v1/backups/{backup_id}/verify', {
            path: { backup_id: b.backupId },
            body: { destination, deep },
            timeoutMs: LONG_OP_MS,
          }),
        );
      },
      $localize`:@@backups.verifiedDone:Backup verified.`,
    );
  }

  protected async createSnapshot(): Promise<void> {
    if (this.snapshotName.invalid) {
      this.snapshotName.markAsTouched();
      return;
    }
    const name = this.snapshotName.value;
    const ok = await this.mutation.run(
      () =>
        this.api.request('post', '/api/v1/snapshots', { body: { name }, timeoutMs: LONG_OP_MS }),
      $localize`:@@snapshots.created:Snapshot created.`,
    );
    if (ok) {
      this.snapshotName.reset();
      this.snapshots.reload();
    }
  }

  protected async deleteSnapshot(name: string): Promise<void> {
    if (
      !(await confirm(this.dialog, {
        title: $localize`:@@snapshots.deleteTitle:Delete snapshot ${name}:name:?`,
        message: $localize`:@@snapshots.deleteMessage:The node can no longer be restored to this snapshot. This cannot be undone.`,
        confirmLabel: $localize`:@@snapshots.deleteConfirm:Delete`,
        typedConfirmation: name,
      }))
    )
      return;
    const ok = await this.mutation.run(
      () => this.api.request('delete', '/api/v1/snapshots/{name}', { path: { name } }),
      $localize`:@@snapshots.deleted:Snapshot deleted.`,
    );
    if (ok) this.snapshots.reload();
  }

  protected deleteLabel(name: string): string {
    return $localize`:@@snapshots.deleteLabel:Delete snapshot ${name}:name:`;
  }
}
