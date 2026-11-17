import { DatePipe } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  DestroyRef,
  inject,
  InjectionToken,
  input,
  OnInit,
  resource,
  signal,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import {
  AbstractControl,
  FormControl,
  FormGroup,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { RouterLink } from '@angular/router';
import { map } from 'rxjs';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import type { components } from '../../api/schema';
import { SessionService } from '../../core/session.service';
import { CodeBlock } from '../../shared/code-block';
import { confirm } from '../../shared/confirm-dialog';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { formatBytes } from '../../shared/format';
import { Mutation } from '../security/common';
import { BackupNav, destinationSuggestions, LONG_OP_MS } from './common';
import { FIELD } from '../../shared/field';
import { Dialogs } from '../../shared/dialog';

type ErrorInfo = components['schemas']['ErrorInfo'];

export type Shell = 'posix' | 'powershell';
type Kek = 'none' | 'file' | 'env';
type Source = 'online' | RestoreSpec['source'];

/** Pause between readiness probes while the node restores; tests swap it for an immediate one. */
export const RESTORE_POLL_WAIT = new InjectionToken<() => Promise<void>>('RESTORE_POLL_WAIT', {
  providedIn: 'root',
  factory: () => () => new Promise((resolve) => setTimeout(resolve, 1500)),
});

/** Arguments that need no quoting in either shell (no leading `-`/`@`: options, splatting). */
const SAFE = /^[A-Za-z0-9_/.:=+,][A-Za-z0-9_/.:=+,@%-]*$/;

/**
 * Quotes one argument for the shell. POSIX: single quotes, `'` as `'\''`. PowerShell: single
 * quotes (no `$` or backtick expansion), quotes doubled, including the typographic ones
 * PowerShell also treats as quotes.
 */
export function quote(arg: string, shell: Shell): string {
  if (SAFE.test(arg)) return arg;
  if (shell === 'posix') return `'${arg.replace(/'/g, `'\\''`)}'`;
  return `'${arg.replace(/['‘’‚‛]/g, (q) => q + q)}'`;
}

export interface RestoreSpec {
  source: 'backup' | 'snapshot';
  shell: Shell;
  from: string;
  id: string;
  into: string;
  toTime: string;
  archive: string;
  snapshot: string;
  dataDir: string;
  kek: Kek;
  kekValue: string;
  s3Credentials: string;
}

/**
 * The offline restore command (bins/rustegon-cli `backup restore`, `snapshot restore`). Never a
 * secret in argv: the KEK comes from a file or names an environment variable, S3 credentials
 * from a file or the AWS_* variables.
 */
export function restoreCommand(s: RestoreSpec): string {
  const args: string[] = ['rustegon'];
  const opt = (name: string, value: string) => {
    if (value) args.push(`--${name}`, quote(value, s.shell));
  };
  if (s.source === 'backup') {
    args.push('backup', 'restore');
    opt('from', s.from);
    opt('id', s.id);
    opt('into', s.into);
    if (s.toTime) {
      opt('to-time', new Date(s.toTime).toISOString());
      opt('archive', s.archive);
    }
    if (s.from.startsWith('s3://')) opt('s3-credentials-file', s.s3Credentials);
  } else {
    args.push('snapshot', 'restore');
    opt('data-dir', s.dataDir);
    opt('name', s.snapshot);
  }
  if (s.kek === 'file') opt('encryption-key-file', s.kekValue);
  if (s.kek === 'env') opt('encryption-key-env', s.kekValue);
  return args.join(' ');
}

/** Paths and names typed here end up in a shell command: no control characters. */
function noControl(c: AbstractControl): ValidationErrors | null {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u001f\u007f]/.test(String(c.value ?? '')) ? { control: true } : null;
}

const text = (required = false) =>
  new FormControl('', {
    nonNullable: true,
    validators: required ? [Validators.required, noControl] : [noControl],
  });

/**
 * S23 Restore. The default is the online restore of ADR-037, as simple as a "restore database"
 * dialog: pick a destination, list its backups, choose one, confirm by typing its id. The server
 * deep-verifies the backup, answers, stops serving, swaps its store for the backup (the replaced
 * store stays in the data directory as `store.pre-restore-<timestamp>`) and serves again in the
 * same process; the page follows that through `/health/ready` and then sends the user to sign in
 * again, because users, roles and passwords now come from the backup. `/restore-status` shows how
 * the last restore ended. The offline restores (a backup into a new data directory, a local
 * snapshot) stay as secondary choices that build the `rustegon` CLI command to run on the server
 * host (PD-126). Omitted (PD-143): collection subset and renaming (physical restores take the
 * whole node; `rustegon dump`/`restore` handle logical subsets).
 */
@Component({
  selector: 'rg-restore-page',
  imports: [
    ...FIELD,
    DatePipe,
    ReactiveFormsModule,
    RouterLink,
    CodeBlock,
    ErrorPanel,
    Icon,
    BackupNav,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: '../security/page.scss',
  template: `
    <header class="rg-page-header rg-hero">
      <div class="rg-hero-title">
        <span class="rg-page-icon"><rg-icon name="history" /></span>
        <div>
          <h1 i18n="@@restore.heading">Restore</h1>
          <p class="rg-subtitle" i18n="@@restore.subtitle">
            Restore a backup online: the node replaces all its data with the backup and serves
            again. Restoring into a new data directory or from a local snapshot happens offline with
            the rustegon command-line tool.
          </p>
        </div>
      </div>
    </header>
    <rg-backup-nav />

    @if (v().source === 'online') {
      @if (lastRestore.value(); as s) {
        @if (s.state === 'completed') {
          <p class="rg-note" i18n="@@restore.lastCompleted">
            Last restore: backup {{ s.backupId }} completed on {{ s.finishedAt | date: 'medium' }}.
            The replaced data is kept on the server as {{ s.previousStore }}.
          </p>
        } @else if (s.state === 'failed') {
          <p class="rg-note" i18n="@@restore.lastFailed">
            Last restore: backup {{ s.backupId }} failed on {{ s.finishedAt | date: 'medium' }}; the
            node kept its data.
          </p>
          @if (s.error; as e) {
            <rg-error-panel [error]="asError(e)" />
          }
        }
      }
      @if (mutation.error(); as e) {
        <rg-error-panel [error]="e" />
      }
    }

    <div class="split">
      <form class="panel rg-panel" [formGroup]="form" (ngSubmit)="submit()" novalidate>
        <rg-field>
          <label rgLabel i18n="@@restore.source">Restore from</label>
          <select rgControl formControlName="source">
            <option value="online" i18n="@@restore.fromOnline">
              A backup, replacing the node's data (online)
            </option>
            <option value="backup" i18n="@@restore.fromBackup">
              A backup (into a new data directory)
            </option>
            <option value="snapshot" i18n="@@restore.fromSnapshot">
              A local snapshot (replaces the node's store)
            </option>
          </select>
        </rg-field>

        @if (v().source !== 'snapshot') {
          <rg-field>
            <label rgLabel i18n="@@restore.destination">Backup destination</label>
            <input rgControl formControlName="from" list="rg-restore-dests" autocomplete="off" />
            <datalist id="rg-restore-dests">
              @for (s of suggestions.value() ?? []; track s) {
                <option [value]="s"></option>
              }
            </datalist>
            @if (form.controls.from.invalid) {
              <rg-error i18n="@@restore.required">Required, without control characters.</rg-error>
            }
          </rg-field>
          <div class="form-actions">
            <button
              class="btn btn-glass"
              type="button"
              (click)="listBackups()"
              i18n="@@restore.list"
            >
              List backups at this destination
            </button>
          </div>
          @if (backups.error(); as e) {
            <rg-error-panel [error]="e" />
          }
        }

        @if (v().source === 'online') {
          <rg-field>
            <label rgLabel i18n="@@restore.choose">Backup to restore</label>
            <select rgControl formControlName="id">
              <option value="" disabled i18n="@@restore.choosePlaceholder">
                List the backups, then choose one
              </option>
              @for (b of backups.hasValue() ? backups.value() : []; track b.backupId) {
                <option [value]="b.backupId">
                  {{ b.backupId }} · {{ b.createdAtUnixMs | date: 'medium' }} ·
                  {{ size(b.totalBytes) }}
                </option>
              }
            </select>
            @if (form.controls.id.invalid) {
              <rg-error i18n="@@restore.chooseRequired">Choose a backup.</rg-error>
            }
          </rg-field>
          <div class="form-actions">
            <button
              class="btn btn-primary"
              type="submit"
              [disabled]="mutation.busy() || phase() !== 'idle'"
            >
              <rg-icon name="history" /><span i18n="@@restore.restore">Restore</span>
            </button>
          </div>
        } @else if (v().source === 'backup') {
          <rg-field>
            <label rgLabel i18n="@@restore.backupId">Backup id</label>
            <input rgControl formControlName="id" list="rg-backup-ids" autocomplete="off" />
            <datalist id="rg-backup-ids">
              @for (b of backups.hasValue() ? backups.value() : []; track b.backupId) {
                <option [value]="b.backupId"></option>
              }
            </datalist>
            <rg-hint i18n="@@restore.backupIdHint"
              >Optional with a point in time: the newest backup taken before it is used.</rg-hint
            >
            @if (form.controls.id.invalid) {
              <rg-error i18n="@@restore.idRequired">Enter a backup id or a point in time.</rg-error>
            }
          </rg-field>
          <rg-field>
            <label rgLabel i18n="@@restore.into">New data directory</label>
            <input rgControl formControlName="into" autocomplete="off" />
            <rg-hint i18n="@@restore.intoHint"
              >Must be empty or absent; start rustegond on it afterwards.</rg-hint
            >
            @if (form.controls.into.invalid) {
              <rg-error i18n="@@restore.required">Required, without control characters.</rg-error>
            }
          </rg-field>
          <rg-field>
            <label rgLabel i18n="@@restore.toTime">Point in time (optional)</label>
            <input rgControl type="datetime-local" step="1" formControlName="toTime" />
            <rg-hint i18n="@@restore.toTimeHint"
              >Your local time; needs the PITR log archive (backup.pitr).</rg-hint
            >
          </rg-field>
          @if (v().toTime) {
            <rg-field>
              <label rgLabel i18n="@@restore.archive">PITR archive destination (optional)</label>
              <input rgControl formControlName="archive" autocomplete="off" />
            </rg-field>
          }
          @if (v().from.startsWith('s3://')) {
            <rg-field>
              <label rgLabel i18n="@@restore.s3Credentials">S3 credentials file (optional)</label>
              <input rgControl formControlName="s3Credentials" autocomplete="off" />
              <rg-hint i18n="@@restore.s3Hint"
                >JSON file with the keys; else the AWS_* environment variables are used.</rg-hint
              >
            </rg-field>
          }
        } @else {
          <rg-field>
            <label rgLabel i18n="@@restore.snapshot">Snapshot name</label>
            <input rgControl formControlName="snapshot" autocomplete="off" />
            @if (form.controls.snapshot.invalid) {
              <rg-error i18n="@@restore.required">Required, without control characters.</rg-error>
            }
          </rg-field>
          <rg-field>
            <label rgLabel i18n="@@restore.dataDir">Data directory of the stopped node</label>
            <input rgControl formControlName="dataDir" autocomplete="off" />
            @if (form.controls.dataDir.invalid) {
              <rg-error i18n="@@restore.required">Required, without control characters.</rg-error>
            }
          </rg-field>
        }

        @if (v().source !== 'online') {
          <rg-field>
            <label rgLabel i18n="@@restore.kek">Encryption key (encrypted backups)</label>
            <select rgControl formControlName="kek">
              <option value="none" i18n="@@restore.kekNone">Not encrypted</option>
              <option value="file" i18n="@@restore.kekFile">Key file on the server host</option>
              <option value="env" i18n="@@restore.kekEnv">Environment variable name</option>
            </select>
          </rg-field>
          @if (v().kek !== 'none') {
            <rg-field>
              <label rgLabel i18n="@@restore.kekValue">Key file path or variable name</label>
              <input rgControl formControlName="kekValue" autocomplete="off" />
              <rg-hint i18n="@@restore.kekHint"
                >Never the key itself: the command only references it.</rg-hint
              >
              @if (form.controls.kekValue.invalid) {
                <rg-error i18n="@@restore.kekInvalid"
                  >Enter a path, or a variable name of letters, digits and _.</rg-error
                >
              }
            </rg-field>
          }

          <rg-field>
            <label rgLabel i18n="@@restore.shell">Shell</label>
            <select rgControl formControlName="shell">
              <option value="posix">POSIX sh / bash</option>
              <option value="powershell">PowerShell</option>
            </select>
          </rg-field>
          <div class="form-actions">
            <button class="btn btn-primary" type="submit">
              <rg-icon name="play" /><span i18n="@@restore.generate">Generate command</span>
            </button>
          </div>
        }
      </form>

      @if (v().source === 'online') {
        <!-- Always present so screen readers announce the phases as they change. -->
        <div aria-live="polite">
          @switch (phase()) {
            @case ('restoring') {
              <section class="panel rg-panel rg-callout" aria-labelledby="progress-heading">
                <div class="rg-callout-head">
                  <span class="rg-page-icon sm"><rg-icon name="history" /></span>
                  <h2 id="progress-heading" i18n="@@restore.progressHeading">
                    Restore in progress…
                  </h2>
                </div>
                <p i18n="@@restore.progress">
                  Restore in progress: the node stops serving and restores the backup.
                </p>
              </section>
            }
            @case ('done') {
              <section class="panel rg-panel rg-callout" aria-labelledby="progress-heading">
                <div class="rg-callout-head">
                  <span class="rg-page-icon sm"><rg-icon name="history" /></span>
                  <h2 id="progress-heading" i18n="@@restore.doneHeading">Node serving again</h2>
                </div>
                <p i18n="@@restore.done">
                  Restore completed. Sign in again with the credentials of the backup.
                </p>
                <a class="btn btn-primary" routerLink="/login" i18n="@@restore.signIn">Sign in</a>
              </section>
            }
          }
        </div>
      } @else if (command(); as c) {
        <section
          class="panel rg-panel rg-callout command"
          aria-labelledby="cmd-heading"
          aria-live="polite"
        >
          <div class="rg-callout-head">
            <span class="rg-page-icon sm"><rg-icon name="play" /></span>
            <h2 id="cmd-heading" i18n="@@restore.commandHeading">Restore command</h2>
          </div>
          <ol>
            @if (v().source === 'snapshot') {
              <li i18n="@@restore.stepStop">Stop the node (rustegond) on the server host.</li>
            }
            <li i18n="@@restore.stepRun">Run the command on the server host:</li>
          </ol>
          <rg-code-block [code]="c" [language]="v().shell === 'posix' ? 'sh' : 'PowerShell'" />
          <ol start="3">
            @if (v().source === 'backup') {
              <li i18n="@@restore.stepStartNew">
                Point node.data_dir at the new directory and start rustegond.
              </li>
            } @else {
              <li i18n="@@restore.stepStart">Start rustegond again.</li>
            }
            <li i18n="@@restore.stepCheck">Sign in and check the databases and collections.</li>
          </ol>
        </section>
      }
    </div>
  `,
})
export class RestorePage implements OnInit {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  private readonly session = inject(SessionService);
  private readonly wait = inject(RESTORE_POLL_WAIT);
  private destroyed = false;
  protected readonly mutation = new Mutation();
  /** Online restore lifecycle: `restoring` from the server's 200 until it serves again. */
  protected readonly phase = signal<'idle' | 'restoring' | 'done'>('idle');
  /** Query parameters from the backups screen (`?from=&id=`, `?snapshot=`). */
  readonly from = input<string>();
  readonly id = input<string>();
  readonly snapshot = input<string>();

  protected readonly form = new FormGroup({
    source: new FormControl<Source>('online', { nonNullable: true }),
    shell: new FormControl<Shell>(
      navigator.userAgent.includes('Windows') ? 'powershell' : 'posix',
      { nonNullable: true },
    ),
    from: text(true),
    id: text(),
    into: text(true),
    toTime: text(),
    archive: text(),
    snapshot: text(true),
    dataDir: text(true),
    kek: new FormControl<Kek>('none', { nonNullable: true }),
    kekValue: text(true),
    s3Credentials: text(),
  });
  protected readonly v = toSignal(this.form.valueChanges.pipe(map(() => this.form.getRawValue())), {
    initialValue: this.form.getRawValue(),
  });
  /** The spec the command was generated from; editing the form hides a stale command. */
  private readonly generated = signal<RestoreSpec | null>(null);
  protected readonly command = computed(() => {
    const g = this.generated();
    return g && JSON.stringify(g) === JSON.stringify(this.v()) ? restoreCommand(g) : null;
  });

  private readonly listed = signal<string | undefined>(undefined);
  protected readonly backups = resource({
    params: () => this.listed(),
    loader: async ({ params: destination }) =>
      (await this.api.get('/api/v1/backups', { query: { destination } })).backups,
  });

  /** `<data_dir>/backups` first; prefills (and lists) an empty destination. */
  protected readonly suggestions = resource({
    loader: async () => {
      const out = await destinationSuggestions(this.api);
      if (out.length && !this.form.controls.from.value) {
        this.form.patchValue({ from: out[0] });
        this.listBackups();
      }
      return out;
    },
  });

  /** Outcome of the last online restore; unreadable (privileges, network) means "nothing to show". */
  protected readonly lastRestore = resource({
    loader: async () => {
      try {
        return await this.api.get('/api/v1/restore-status');
      } catch {
        return undefined;
      }
    },
  });

  constructor() {
    inject(DestroyRef).onDestroy(() => (this.destroyed = true));
  }

  ngOnInit(): void {
    if (this.snapshot()) this.form.patchValue({ source: 'snapshot', snapshot: this.snapshot() });
    else {
      this.form.patchValue({ from: this.from() ?? '', id: this.id() ?? '' });
      this.listBackups();
    }
  }

  protected listBackups(): void {
    const d = this.form.controls.from.value.trim();
    if (d) this.listed.set(d);
  }

  protected size(bytes: number): string {
    return formatBytes(bytes);
  }

  /** `/restore-status` carries the wire `ErrorInfo`; the error panel renders an `ApiError`. */
  protected asError(e: ErrorInfo): ApiError {
    return new ApiError(0, e.code, e.name, e.message, false, e.details, e.traceId);
  }

  protected submit(): Promise<void> {
    return this.form.controls.source.value === 'online' ? this.restore() : this.reveal();
  }

  /** Only the fields of the chosen source and options take part in validation. */
  private activeControls(): AbstractControl[] {
    const c = this.form.controls;
    const v = this.form.getRawValue();
    const out: AbstractControl[] =
      v.source === 'backup' ? [c.from, c.into, c.id, c.toTime, c.archive] : [c.snapshot, c.dataDir];
    if (v.kek !== 'none') out.push(c.kekValue);
    return out;
  }

  /** Online restore (ADR-037): a plain confirmation (nothing to type), then the call, then follow the node. */
  private async restore(): Promise<void> {
    const c = this.form.controls;
    c.from.markAsTouched();
    const destination = c.from.value.trim();
    const id = c.id.value.trim();
    if (!id) c.id.setErrors({ required: true });
    if (c.from.invalid || !destination || !id) return;
    if (
      !(await confirm(this.dialog, {
        title: $localize`:@@restore.onlineConfirmTitle:Restore backup ${id}:id: on this node?`,
        message: $localize`:@@restore.onlineConfirmMessage:Every database, user and role of the node is replaced by the backup's, and all open sessions end. The replaced data is kept on the server as store.pre-restore-<timestamp>.`,
        confirmLabel: $localize`:@@restore.onlineConfirmOk:Restore`,
      }))
    )
      return;
    const ok = await this.mutation.run(
      () =>
        this.api.request('post', '/api/v1/backups/{backup_id}/restore', {
          path: { backup_id: id },
          body: { destination },
          // The server deep-verifies the backup before answering.
          timeoutMs: LONG_OP_MS,
        }),
      $localize`:@@restore.scheduled:Restore started.`,
    );
    if (ok) {
      this.phase.set('restoring');
      void this.watch();
    }
  }

  /**
   * The node answers before it stops serving, so "ready" only means "restored" after it has been
   * seen not ready (503 draining, or connections refused) at least once.
   */
  private async watch(): Promise<void> {
    let wentDown = false;
    while (!this.destroyed) {
      await this.wait();
      if (this.destroyed) return;
      let ready: boolean;
      try {
        await this.api.get('/api/v1/health/ready', { skipAuthRedirect: true });
        ready = true;
      } catch {
        ready = false;
      }
      if (!ready) wentDown = true;
      else if (wentDown) {
        // The restore ended every session: forget the local one (logout tolerates a dead session).
        await this.session.logout();
        this.phase.set('done');
        return;
      }
    }
  }

  protected async reveal(): Promise<void> {
    const active = this.activeControls();
    active.forEach((c) => c.markAsTouched());
    const v = this.form.getRawValue();
    if (v.source === 'online') return;
    const kekOk = v.kek !== 'env' || /^[A-Za-z_][A-Za-z0-9_]*$/.test(v.kekValue);
    if (!kekOk) this.form.controls.kekValue.setErrors({ variable: true });
    const backup = v.source === 'backup';
    // The CLI needs --id unless --to-time picks the backup.
    const idOk = !backup || !!v.id.trim() || !!v.toTime;
    if (!idOk) this.form.controls.id.setErrors({ required: true });
    const timeOk = !backup || !v.toTime || !Number.isNaN(new Date(v.toTime).getTime());
    if (!timeOk) this.form.controls.toTime.setErrors({ time: true });
    if (active.some((c) => c.invalid) || !kekOk || !idOk || !timeOk) return;
    // A snapshot restore overwrites the node's store: a plain confirmation (owner decision).
    if (
      v.source === 'snapshot' &&
      !(await confirm(this.dialog, {
        title: $localize`:@@restore.confirmTitle:Replace the node's store with ${v.snapshot}:name:?`,
        message: $localize`:@@restore.confirmMessage:Running this command discards every change made after the snapshot.`,
        confirmLabel: $localize`:@@restore.confirmOk:Show the command`,
      }))
    )
      return;
    this.generated.set({ ...v, source: v.source });
  }
}
