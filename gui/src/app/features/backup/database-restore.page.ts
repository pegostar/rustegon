import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { ApiClient } from '../../api/api-client';
import type { components } from '../../api/schema';
import { confirm } from '../../shared/confirm-dialog';
import { Dialogs } from '../../shared/dialog';
import { ErrorPanel } from '../../shared/error-panel';
import { FIELD } from '../../shared/field';
import { formatBytes } from '../../shared/format';
import { Icon } from '../../shared/icon';
import { Mutation } from '../security/common';
import { BackupNav, LONG_OP_MS } from './common';

type Restored = components['schemas']['RestoreDumpResponse'];

/**
 * Restore one database from a `.dbck` file on the user's computer (FR-BKP-007, PD-229): the file
 * is sent as is to `POST /dumps/restore-file`, which restores every collection it holds, dropping
 * the existing ones of the same name first. Other databases and collections are not touched.
 */
@Component({
  selector: 'rg-database-restore-page',
  imports: [...FIELD, ErrorPanel, Icon, BackupNav],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: '../security/page.scss',
  template: `
    <header class="rg-page-header rg-hero">
      <div class="rg-hero-title">
        <span class="rg-page-icon"><rg-icon name="history" /></span>
        <h1 i18n="@@dbRestore.heading">Restore a database</h1>
      </div>
    </header>
    <rg-backup-nav />

    <p class="hint" i18n="@@dbRestore.intro">
      Choose a database backup file (.dbck) on your computer: it is sent to the node, which replaces
      every collection in the file with its copy from the backup. Collections that are not in the
      file and other databases are not touched.
    </p>

    @if (mutation.error(); as e) {
      <rg-error-panel [error]="e" />
    }
    @if (mutation.busy()) {
      <p class="rg-note" role="status" i18n="@@dbRestore.working">
        Uploading and restoring… this can take a while for a large file.
      </p>
    }

    <section class="panel wide rg-panel" aria-labelledby="dbr-heading">
      <h2 id="dbr-heading" i18n="@@dbRestore.formHeading">Restore from a file</h2>
      <form class="inline-form" (submit)="$event.preventDefault(); restore()">
        <rg-field>
          <label rgLabel i18n="@@dbRestore.file">Database backup file (.dbck)</label>
          <input
            rgControl
            type="file"
            accept=".dbck"
            [disabled]="mutation.busy()"
            (change)="choose($event)"
          />
          @if (file(); as f) {
            <rg-hint i18n="@@dbRestore.chosen">{{ f.name }} · {{ size(f.size) }}</rg-hint>
          }
        </rg-field>
        <button class="btn btn-primary" type="submit" [disabled]="mutation.busy() || !file()">
          <rg-icon name="history" /><span i18n="@@dbRestore.restore">Restore</span>
        </button>
      </form>
    </section>

    @if (restored(); as r) {
      <section class="panel wide rg-panel" aria-labelledby="dbr-restored-heading">
        <h2 id="dbr-restored-heading" i18n="@@dbBackups.restoredHeading">Restored</h2>
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
  `,
})
export class DatabaseRestorePage {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  protected readonly mutation = new Mutation();
  protected readonly file = signal<File | null>(null);
  protected readonly restored = signal<Restored | null>(null);

  protected size(bytes: number): string {
    return formatBytes(bytes);
  }

  protected choose(event: Event): void {
    this.restored.set(null);
    this.file.set((event.target as HTMLInputElement).files?.[0] ?? null);
  }

  protected async restore(): Promise<void> {
    const file = this.file();
    if (!file) return;
    if (
      !(await confirm(this.dialog, {
        title: $localize`:@@dbRestore.confirmTitle:Restore from ${file.name}:file:?`,
        message: $localize`:@@dbRestore.confirmMessage:Every collection in this file replaces the collection of the same name on the node; changes made after the backup are lost. Collections that are not in the file and other databases are not touched.`,
        confirmLabel: $localize`:@@dbRestore.confirm:Restore`,
      }))
    )
      return;
    this.restored.set(null);
    await this.mutation.run(
      async () => {
        this.restored.set(
          await this.api.request('post', '/api/v1/dumps/restore-file', {
            query: { dropExisting: true },
            body: file,
            headers: { 'content-type': 'application/octet-stream' },
            timeoutMs: LONG_OP_MS,
          }),
        );
      },
      $localize`:@@dbBackups.restored:Database restored.`,
    );
  }
}
