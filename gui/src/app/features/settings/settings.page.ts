import {
  ChangeDetectionStrategy,
  Component,
  computed,
  DestroyRef,
  inject,
  InjectionToken,
  resource,
  signal,
} from '@angular/core';
import { ApiClient } from '../../api/api-client';
import type { components } from '../../api/schema';
import { PermissionsService } from '../../core/permissions.service';
import { NotificationService } from '../../core/notification.service';
import { confirm } from '../../shared/confirm-dialog';
import { Dialogs } from '../../shared/dialog';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { Skeleton } from '../../shared/skeleton';
import { StatusBadge } from '../../shared/status-badge';
import { Mutation } from '../security/common';
import { settingText } from './setting-text';

type Setting = components['schemas']['SettingJson'];
export type Kind = 'bool' | 'integer' | 'string' | 'path' | 'enum' | 'string_list' | 'table';
export type TabId =
  'general' | 'network' | 'access' | 'limits' | 'audit' | 'storage' | 'backup' | 'other';

/** rustegon-common `redacted::REDACTED`: what the server returns for a secret setting. */
const REDACTED = '‹redacted›';

/** Secret settings (`Sensitivity::Secret`) arrive redacted and are never shown or edited. */
export const isSecret = (s: Setting): boolean =>
  s.locked === 'secret' || s.value.includes(REDACTED) || s.defaultValue.includes(REDACTED);

/** Pause between readiness probes while the node restarts; tests swap it for an immediate one. */
export const RESTART_POLL_WAIT = new InjectionToken<() => Promise<void>>('RESTART_POLL_WAIT', {
  providedIn: 'root',
  factory: () => () => new Promise((resolve) => setTimeout(resolve, 1500)),
});
/** Probes before the page stops waiting (about two minutes with the default pause). */
const RESTART_POLLS = 80;

/** Configuration sections of each tab; a section not listed goes to "other". */
const TABS: { id: TabId; sections: string[] }[] = [
  { id: 'general', sections: ['node', 'gui', 'log', 'dev'] },
  { id: 'network', sections: ['listen', 'tls', 'security'] },
  { id: 'access', sections: ['auth', 'lockout'] },
  { id: 'limits', sections: ['rate_limit'] },
  { id: 'audit', sections: ['audit'] },
  { id: 'storage', sections: ['storage', 'txn', 'query', 'index'] },
  { id: 'backup', sections: ['backup'] },
];

export function tabOf(name: string): TabId {
  const section = name.split('.')[0];
  return TABS.find((t) => t.sections.includes(section))?.id ?? 'other';
}

function unquote(t: string): string {
  if (t.length >= 2 && t.startsWith("'") && t.endsWith("'")) return t.slice(1, -1);
  try {
    const v: unknown = JSON.parse(t);
    return typeof v === 'string' ? v : t;
  } catch {
    return t;
  }
}

/** The strings of a TOML array of basic or literal strings. */
export function tomlItems(t: string): string[] {
  const out: string[] = [];
  for (const m of t.matchAll(/'([^']*)'|"((?:[^"\\]|\\.)*)"/g))
    out.push(m[1] ?? (JSON.parse(`"${m[2]}"`) as string));
  return out;
}

/** TOML text → form text (strings unquoted, lists comma-separated). */
export function fromToml(kind: Kind, toml: string): string {
  const t = toml.trim();
  switch (kind) {
    case 'string':
    case 'path':
    case 'enum':
      return unquote(t);
    case 'string_list':
      return tomlItems(t).join(', ');
    default:
      return t;
  }
}

/** Form text → TOML text (JSON string syntax is a valid TOML basic string). */
export function toToml(kind: Kind, text: string): string {
  switch (kind) {
    case 'string':
    case 'path':
    case 'enum':
      return JSON.stringify(text);
    case 'string_list':
      return `[${text
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => JSON.stringify(s))
        .join(', ')}]`;
    default:
      return text.trim();
  }
}

/** The value a change starts from: the configured one (pending restart) or the running one. */
const configured = (s: Setting): string => s.pendingValue ?? s.value;
const same = (s: Setting, a: string, b: string): boolean =>
  toToml(s.kind as Kind, fromToml(s.kind as Kind, a)) ===
  toToml(s.kind as Kind, fromToml(s.kind as Kind, b));

/**
 * S17 Settings (PD-126, PD-230): the node's settings grouped in tabs by topic and edited in
 * place with a type-aware input. Runtime settings apply at once; static ones are written to
 * rustegon.toml and apply when the node restarts, from the "Restart the database" button at
 * the end of the page, shown when changes are waiting. Settings the console may not change
 * (secrets, tables, set by the environment or a --set option, the data directory and store
 * encryption, or no configuration file) are shown read-only with the reason.
 */
@Component({
  selector: 'rg-settings-page',
  imports: [ErrorPanel, Icon, Skeleton, StatusBadge],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: '../security/page.scss',
  template: `
    <header class="rg-page-header rg-hero">
      <div class="rg-hero-title">
        <span class="rg-page-icon"><rg-icon name="settings" /></span>
        <div>
          <h1 i18n="@@settings.heading">Settings</h1>
          <p class="rg-subtitle" i18n="@@settings.intro2">
            Runtime settings apply at once. The others are saved in the configuration file and apply
            when the database restarts.
          </p>
        </div>
      </div>
      <div class="rg-actions">
        <button class="btn btn-glass" type="button" (click)="settings.reload()">
          <rg-icon name="refresh" /><span i18n="@@settings.refresh">Refresh</span>
        </button>
      </div>
    </header>

    @if (lastRestartError(); as e) {
      <p class="alert alert-danger" role="alert" i18n="@@settings.restartFailed">
        The last restart could not use the changed settings, so the database runs with the previous
        ones: {{ e }}
      </p>
    }

    <rg-skeleton [loading]="settings.isLoading()">
      @if (settings.error(); as e) {
        <rg-error-panel [error]="e" (retry)="settings.reload()" />
      } @else if (settings.hasValue()) {
        <div
          class="nav nav-tabs rg-subnav"
          role="tablist"
          i18n-aria-label="@@settings.tabs"
          aria-label="Setting groups"
        >
          @for (t of tabs(); track t) {
            <button
              class="nav-link"
              type="button"
              role="tab"
              [id]="'tab-' + t"
              [class.active]="t === tab()"
              [attr.aria-selected]="t === tab()"
              [attr.aria-controls]="'panel-' + t"
              (click)="tab.set(t)"
            >
              {{ tabLabel(t) }}
            </button>
          }
        </div>

        <form
          class="panel wide rg-panel"
          role="tabpanel"
          [id]="'panel-' + tab()"
          [attr.aria-labelledby]="'tab-' + tab()"
          (submit)="$event.preventDefault(); save()"
          novalidate
        >
          @for (s of visible(); track s.name) {
            <div class="setting">
              <div class="head">
                <label class="fw-semibold" [attr.for]="fieldId(s)">{{ label(s) }}</label>
                <code class="small">{{ s.name }}</code>
                @if (!s.runtimeMutable) {
                  <rg-status-badge
                    status="neutral"
                    i18n-label="@@settings.restartOnly"
                    label="Restart required"
                  />
                }
                @if (s.pendingValue !== undefined && s.pendingValue !== null) {
                  <rg-status-badge
                    status="warn"
                    i18n-label="@@settings.pending"
                    label="Waiting for restart"
                  />
                } @else if (!secret(s) && s.value !== s.defaultValue) {
                  <rg-status-badge status="info" i18n-label="@@settings.changed" label="Changed" />
                }
              </div>
              <p class="hint" [id]="fieldId(s) + '-d'">{{ doc(s) }}</p>
              @if (secret(s)) {
                <p class="rg-muted" i18n="@@settings.secretHidden">
                  Secret: hidden, set by reference in rustegon.toml.
                </p>
              } @else if (!editable(s)) {
                <p>
                  <code>{{ configuredValue(s) }}</code>
                  <span class="rg-muted"> · {{ lockReason(s) }}</span>
                </p>
              } @else {
                @switch (s.kind) {
                  @case ('bool') {
                    <div class="form-check form-switch">
                      <input
                        class="form-check-input"
                        type="checkbox"
                        role="switch"
                        [id]="fieldId(s)"
                        [attr.aria-describedby]="fieldId(s) + '-d'"
                        [checked]="text(s) === 'true'"
                        (change)="setText(s, $any($event.target).checked ? 'true' : 'false')"
                      />
                    </div>
                  }
                  @case ('enum') {
                    <select
                      class="form-select"
                      [id]="fieldId(s)"
                      [attr.aria-describedby]="fieldId(s) + '-d'"
                      (change)="setText(s, $any($event.target).value)"
                    >
                      @for (c of s.choices ?? []; track c) {
                        <option [value]="c" [selected]="c === text(s)">{{ c }}</option>
                      }
                    </select>
                  }
                  @case ('integer') {
                    <input
                      class="form-control"
                      type="number"
                      step="1"
                      [id]="fieldId(s)"
                      [attr.min]="s.min"
                      [attr.max]="s.max"
                      [attr.aria-describedby]="fieldId(s) + '-d'"
                      [attr.aria-invalid]="invalid(s)"
                      [value]="text(s)"
                      (input)="setText(s, $any($event.target).value)"
                    />
                    @if (invalid(s)) {
                      <p class="invalid" i18n="@@settings.range">
                        Enter a whole number from {{ s.min }} to {{ s.max }}.
                      </p>
                    }
                  }
                  @default {
                    <input
                      class="form-control"
                      autocomplete="off"
                      [id]="fieldId(s)"
                      [attr.aria-describedby]="fieldId(s) + '-d'"
                      [value]="text(s)"
                      (input)="setText(s, $any($event.target).value)"
                    />
                    @if (s.kind === 'string_list') {
                      <p class="rg-muted small" i18n="@@settings.listHint">Comma-separated.</p>
                    }
                  }
                }
              }
              <p class="rg-muted small">
                <span class="me-1" i18n="@@settings.defaultIs">Default:</span>
                <code>{{ secret(s) ? '—' : s.defaultValue || '""' }}</code>
                @if (s.pendingValue !== undefined && s.pendingValue !== null) {
                  · <span class="me-1" i18n="@@settings.runningIs">In use until the restart:</span>
                  <code>{{ s.value }}</code>
                }
                @if (editable(s) && !same(s, toTomlOf(s), s.defaultValue)) {
                  ·
                  <button
                    class="btn btn-link btn-sm p-0"
                    type="button"
                    (click)="setText(s, defaultText(s))"
                    [attr.aria-label]="resetLabel(s.name)"
                    i18n="@@settings.useDefault"
                  >
                    Use the default
                  </button>
                }
              </p>
            </div>
          }
          @if (canEdit) {
            @if (mutation.error(); as e) {
              <rg-error-panel [error]="e" />
            }
            <div class="form-actions">
              <button
                class="btn btn-primary"
                type="submit"
                [disabled]="mutation.busy() || dirtyNames().length === 0 || anyInvalid()"
              >
                <span i18n="@@settings.saveChanges">Save changes</span>
                @if (dirtyNames().length) {
                  ({{ dirtyNames().length }})
                }
              </button>
              <button
                class="btn btn-glass"
                type="button"
                [disabled]="mutation.busy() || dirtyNames().length === 0"
                (click)="discard()"
                i18n="@@settings.discard"
              >
                Discard changes
              </button>
            </div>
          }
        </form>

        @if (pending().length || phase() !== 'idle') {
          <section class="panel wide rg-panel" aria-labelledby="restart-heading">
            <h2 id="restart-heading" i18n="@@settings.restartHeading">
              Changes waiting for a restart
            </h2>
            <ul>
              @for (s of pending(); track s.name) {
                <li>
                  {{ label(s) }} (<code>{{ s.name }}</code
                  >): <code>{{ s.value }}</code> →
                  <code>{{ s.pendingValue }}</code>
                </li>
              }
            </ul>
            <p class="hint" i18n="@@settings.restartHint">
              Restarting stops the database for a few seconds; open sessions stay signed in. If you
              changed a listen address, open the console at the new address afterwards.
            </p>
            <p role="status">
              @switch (phase()) {
                @case ('restarting') {
                  <span i18n="@@settings.restarting">Restarting the database…</span>
                }
                @case ('lost') {
                  <span i18n="@@settings.restartLost">
                    The database does not answer at this address yet. If you changed a listen
                    address, open the console at the new one.
                  </span>
                }
              }
            </p>
            @if (canEdit) {
              <button
                class="btn btn-primary"
                type="button"
                [disabled]="phase() === 'restarting' || dirtyNames().length > 0"
                (click)="restart()"
              >
                <rg-icon name="refresh" /><span i18n="@@settings.restartButton"
                  >Restart the database</span
                >
              </button>
            }
          </section>
        }
      }
    </rg-skeleton>
  `,
  styles: `
    .setting {
      padding: 0.85rem 0;
      border-bottom: 1px solid var(--rg-hairline);
    }
    .setting:last-of-type {
      border-bottom: 0;
    }
    .head {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    .hint {
      margin: 0.25rem 0 0.5rem;
    }
    .invalid {
      color: var(--bs-danger-text-emphasis, #b02a37);
      margin: 0.25rem 0 0;
    }
    code {
      overflow-wrap: anywhere;
    }
    .form-control,
    .form-select {
      max-width: 36rem;
    }
  `,
})
export class SettingsPage {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  private readonly notify = inject(NotificationService);
  private readonly wait = inject(RESTART_POLL_WAIT);
  protected readonly canEdit = inject(PermissionsService).can('cluster_manage', 'cluster');
  protected readonly mutation = new Mutation();
  protected readonly tab = signal<TabId>('general');
  /** Form text of the fields changed and not saved yet, by setting name. */
  protected readonly drafts = signal<Record<string, string>>({});
  protected readonly phase = signal<'idle' | 'restarting' | 'lost'>('idle');
  private destroyed = false;

  protected readonly settings = resource({
    loader: () => this.api.get('/api/v1/settings'),
  });

  private readonly all = computed(() =>
    this.settings.hasValue() ? (this.settings.value()?.settings ?? []) : [],
  );
  protected readonly lastRestartError = computed(() =>
    this.settings.hasValue() ? this.settings.value()?.lastRestartError : undefined,
  );
  protected readonly tabs = computed(() => {
    const used = new Set(this.all().map((s) => tabOf(s.name)));
    return [...TABS.map((t) => t.id), 'other' as const].filter((t) => used.has(t));
  });
  protected readonly visible = computed(() =>
    this.all().filter((s) => tabOf(s.name) === this.tab()),
  );
  protected readonly pending = computed(() =>
    this.all().filter((s) => s.pendingValue !== undefined && s.pendingValue !== null),
  );
  protected readonly dirtyNames = computed(() => {
    const drafts = this.drafts();
    return this.all()
      .filter(
        (s) => s.name in drafts && !same(s, toToml(s.kind as Kind, drafts[s.name]), configured(s)),
      )
      .map((s) => s.name);
  });
  protected readonly anyInvalid = computed(() =>
    this.all().some((s) => s.name in this.drafts() && this.invalid(s)),
  );

  constructor() {
    inject(DestroyRef).onDestroy(() => (this.destroyed = true));
  }

  protected tabLabel(t: TabId): string {
    switch (t) {
      case 'general':
        return $localize`:@@settings.tabGeneral:General`;
      case 'network':
        return $localize`:@@settings.tabNetwork:Network and TLS`;
      case 'access':
        return $localize`:@@settings.tabAccess:Access and security`;
      case 'limits':
        return $localize`:@@settings.tabLimits:Request limits`;
      case 'audit':
        return $localize`:@@settings.tabAudit:Audit`;
      case 'storage':
        return $localize`:@@settings.tabStorage:Storage`;
      case 'backup':
        return $localize`:@@settings.tabBackup:Backup`;
      default:
        return $localize`:@@settings.tabOther:Other`;
    }
  }

  protected lockReason(s: Setting): string {
    if (!this.canEdit) return $localize`:@@settings.lockedRole:Read only for your role.`;
    switch (s.locked) {
      case 'table':
        return $localize`:@@settings.lockedTable:Set it in rustegon.toml.`;
      case 'no_config_file':
        return $localize`:@@settings.lockedNoFile:The database has no configuration file the console may change.`;
      case 'environment':
        return $localize`:@@settings.lockedEnv:Set by an environment variable or a --set option, which take precedence over the file.`;
      case 'manual':
        return $localize`:@@settings.lockedManual:Change it in rustegon.toml by hand: it needs files moved or re-encrypted.`;
      default:
        return '';
    }
  }

  protected secret(s: Setting): boolean {
    return isSecret(s);
  }

  protected editable(s: Setting): boolean {
    return this.canEdit && !s.locked && !isSecret(s);
  }

  protected same(s: Setting, a: string, b: string): boolean {
    return same(s, a, b);
  }

  protected fieldId(s: Setting): string {
    return `set-${s.name.replace(/[^a-z0-9_-]/gi, '-')}`;
  }

  protected configuredValue(s: Setting): string {
    return configured(s);
  }

  /** The form text of `s`: its draft, else its configured value. */
  protected text(s: Setting): string {
    return this.drafts()[s.name] ?? fromToml(s.kind as Kind, configured(s));
  }

  protected toTomlOf(s: Setting): string {
    return toToml(s.kind as Kind, this.text(s));
  }

  protected defaultText(s: Setting): string {
    return fromToml(s.kind as Kind, s.defaultValue);
  }

  protected setText(s: Setting, text: string): void {
    this.drafts.update((d) => ({ ...d, [s.name]: text }));
  }

  protected invalid(s: Setting): boolean {
    if (s.kind !== 'integer') return false;
    const t = this.text(s).trim();
    if (!/^-?\d+$/.test(t)) return true;
    const n = Number(t);
    return (s.min != null && n < s.min) || (s.max != null && n > s.max);
  }

  protected resetLabel(name: string): string {
    name = settingText(name)?.label ?? name;
    return $localize`:@@settings.useDefaultLabel:Use the default of ${name}:name:`;
  }

  protected label(s: Setting): string {
    return settingText(s.name)?.label ?? s.name;
  }

  protected doc(s: Setting): string {
    return settingText(s.name)?.doc ?? s.description;
  }

  protected discard(): void {
    this.drafts.set({});
    this.mutation.error.set(null);
  }

  protected async save(): Promise<void> {
    const names = this.dirtyNames();
    if (names.length === 0 || this.anyInvalid()) return;
    const byName = new Map(this.all().map((s) => [s.name, s]));
    const sent = this.drafts();
    const values: Record<string, string> = {};
    for (const n of names) {
      const s = byName.get(n);
      if (s) values[n] = toToml(s.kind as Kind, this.drafts()[n]);
    }
    const needsRestart = names.some((n) => byName.get(n)?.runtimeMutable === false);
    const ok = await this.mutation.run(
      () => this.api.request('patch', '/api/v1/settings', { body: { values } }),
      needsRestart
        ? $localize`:@@settings.savedRestart:Settings saved. Some apply after the database restarts.`
        : $localize`:@@settings.saved:Settings saved.`,
    );
    if (ok) {
      // Keep what was typed while the save was under way.
      this.drafts.update((d) =>
        Object.fromEntries(Object.entries(d).filter(([k, v]) => sent[k] !== v)),
      );
      this.settings.reload();
    }
  }

  protected async restart(): Promise<void> {
    if (
      !(await confirm(this.dialog, {
        title: $localize`:@@settings.restartTitle:Restart the database?`,
        message: $localize`:@@settings.restartMessage:The database stops for a few seconds and starts again with the saved settings. Requests in progress are completed first.`,
        confirmLabel: $localize`:@@settings.restartConfirm:Restart`,
      }))
    )
      return;
    const ok = await this.mutation.run(
      () => this.api.request('post', '/api/v1/node/restart', {}),
      $localize`:@@settings.restartStarted:Restarting the database.`,
    );
    if (!ok) return;
    this.phase.set('restarting');
    // The node answers before it stops: "ready" means restarted only after a "not ready".
    let wentDown = false;
    for (let i = 0; i < RESTART_POLLS && !this.destroyed; i++) {
      await this.wait();
      let ready: boolean;
      try {
        await this.api.get('/api/v1/health/ready', { skipAuthRedirect: true });
        ready = true;
      } catch {
        ready = false;
      }
      if (!ready) wentDown = true;
      else if (wentDown) {
        this.phase.set('idle');
        this.settings.reload();
        void this.notify.announce($localize`:@@settings.restarted:The database restarted.`);
        return;
      }
    }
    if (!this.destroyed) this.phase.set('lost');
  }
}
