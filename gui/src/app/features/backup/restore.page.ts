import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
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
import { map } from 'rxjs';
import { ApiClient } from '../../api/api-client';
import { CodeBlock } from '../../shared/code-block';
import { confirm } from '../../shared/confirm-dialog';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { BackupNav } from './common';
import { FIELD } from '../../shared/field';
import { Dialogs } from '../../shared/dialog';

export type Shell = 'posix' | 'powershell';
type Kek = 'none' | 'file' | 'env';

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
 * S23 Restore. A single-node restore is offline (the node must not serve the target data
 * directory), so the screen does not call the server to restore: it builds the `rustegon` CLI
 * command to run on the server host (PD-126). Backups can be listed through the node to pick
 * an id. Omitted (PD-143): collection subset and renaming (physical restores take the whole
 * node; `rustegon dump`/`restore` handle logical subsets), progress and the post-restore
 * verification summary (they happen in the CLI).
 */
@Component({
  selector: 'rg-restore-page',
  imports: [...FIELD, ReactiveFormsModule, CodeBlock, ErrorPanel, Icon, BackupNav],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: '../security/page.scss',
  template: `
    <header class="rg-page-header rg-hero">
      <div class="rg-hero-title">
        <span class="rg-page-icon"><rg-icon name="history" /></span>
        <div>
          <h1 i18n="@@restore.heading">Restore</h1>
          <p class="rg-subtitle" i18n="@@restore.offline">
            Restoring a single node happens offline with the rustegon command-line tool on the
            server host. Fill in the form to get the command; nothing is sent to the server.
          </p>
        </div>
      </div>
    </header>
    <rg-backup-nav />

    <div class="split">
      <form class="panel rg-panel" [formGroup]="form" (ngSubmit)="reveal()" novalidate>
        <rg-field>
          <label rgLabel i18n="@@restore.source">Restore from</label>
          <select rgControl formControlName="source">
            <option value="backup" i18n="@@restore.fromBackup">
              A backup (into a new data directory)
            </option>
            <option value="snapshot" i18n="@@restore.fromSnapshot">
              A local snapshot (replaces the node's store)
            </option>
          </select>
        </rg-field>

        @if (v().source === 'backup') {
          <rg-field>
            <label rgLabel i18n="@@restore.destination">Backup destination</label>
            <input rgControl formControlName="from" autocomplete="off" />
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
      </form>

      @if (command(); as c) {
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
  /** Query parameters from the backups screen (`?from=&id=`, `?snapshot=`). */
  readonly from = input<string>();
  readonly id = input<string>();
  readonly snapshot = input<string>();

  protected readonly form = new FormGroup({
    source: new FormControl<'backup' | 'snapshot'>('backup', { nonNullable: true }),
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

  ngOnInit(): void {
    if (this.snapshot()) this.form.patchValue({ source: 'snapshot', snapshot: this.snapshot() });
    else this.form.patchValue({ from: this.from() ?? '', id: this.id() ?? '' });
  }

  protected listBackups(): void {
    const d = this.form.controls.from.value.trim();
    if (d) this.listed.set(d);
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

  protected async reveal(): Promise<void> {
    const active = this.activeControls();
    active.forEach((c) => c.markAsTouched());
    const v = this.form.getRawValue();
    const kekOk = v.kek !== 'env' || /^[A-Za-z_][A-Za-z0-9_]*$/.test(v.kekValue);
    if (!kekOk) this.form.controls.kekValue.setErrors({ variable: true });
    const backup = v.source === 'backup';
    // The CLI needs --id unless --to-time picks the backup.
    const idOk = !backup || !!v.id.trim() || !!v.toTime;
    if (!idOk) this.form.controls.id.setErrors({ required: true });
    const timeOk = !backup || !v.toTime || !Number.isNaN(new Date(v.toTime).getTime());
    if (!timeOk) this.form.controls.toTime.setErrors({ time: true });
    if (active.some((c) => c.invalid) || !kekOk || !idOk || !timeOk) return;
    // A snapshot restore overwrites the node's store: typed confirmation (§2).
    if (
      v.source === 'snapshot' &&
      !(await confirm(this.dialog, {
        title: $localize`:@@restore.confirmTitle:Replace the node's store with ${v.snapshot}:name:?`,
        message: $localize`:@@restore.confirmMessage:Running this command discards every change made after the snapshot.`,
        confirmLabel: $localize`:@@restore.confirmOk:Show the command`,
        typedConfirmation: v.snapshot,
      }))
    )
      return;
    this.generated.set(v);
  }
}
