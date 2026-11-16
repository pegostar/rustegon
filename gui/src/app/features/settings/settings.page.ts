import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  resource,
  signal,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormControl, ReactiveFormsModule, Validators } from '@angular/forms';
import { ApiClient } from '../../api/api-client';
import type { components } from '../../api/schema';
import { PermissionsService } from '../../core/permissions.service';
import { EmptyState } from '../../shared/empty-state';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { Skeleton } from '../../shared/skeleton';
import { StatusBadge } from '../../shared/status-badge';
import { Mutation } from '../security/common';
import { FIELD } from '../../shared/field';

type Setting = components['schemas']['SettingJson'];
export type Kind = 'bool' | 'int' | 'float' | 'string' | 'toml';

/** rustegon-common `redacted::REDACTED`: what the server returns for a secret setting. */
const REDACTED = '‹redacted›';

/** Secret settings (`Sensitivity::Secret`) arrive redacted and are never shown or edited. */
export const isSecret = (s: Setting): boolean =>
  s.value.includes(REDACTED) || s.defaultValue.includes(REDACTED);

/** The input type for a setting, from its TOML default (the API carries no type). */
export function kindOf(toml: string): Kind {
  const t = toml.trim();
  if (t === 'true' || t === 'false') return 'bool';
  if (/^-?\d+$/.test(t)) return 'int';
  if (/^-?\d+\.\d+([eE][-+]?\d+)?$/.test(t)) return 'float';
  if (/^"([^"\\]|\\.)*"$/.test(t)) return 'string';
  return 'toml';
}

/** Form text → TOML text (strings quoted; other kinds are already TOML). */
export function toToml(kind: Kind, text: string): string {
  return kind === 'string' ? JSON.stringify(text) : text.trim();
}

/** TOML text → form text (a basic string unquoted). */
export function fromToml(kind: Kind, toml: string): string {
  if (kind !== 'string') return toml;
  try {
    return String(JSON.parse(toml));
  } catch {
    return toml;
  }
}

/**
 * S17 Settings (PD-126 scope): searchable list of the node's settings with value, default and
 * description; runtime-mutable ones are edited with a type-aware input, a before/after diff and
 * reset to default; the server validates ranges and answers RGN-1001 inline. Secret settings
 * stay hidden. Not in R1's API, so omitted (PD-144): scope, last changed by/at, zone
 * configuration editor, static settings per node of a cluster.
 */
@Component({
  selector: 'rg-settings-page',
  imports: [...FIELD, ReactiveFormsModule, EmptyState, ErrorPanel, Icon, Skeleton, StatusBadge],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: '../security/page.scss',
  template: `
    <header class="rg-page-header rg-hero">
      <div class="rg-hero-title">
        <span class="rg-page-icon"><rg-icon name="settings" /></span>
        <div>
          <h1 i18n="@@settings.heading">Settings</h1>
          <p class="rg-subtitle" i18n="@@settings.intro">
            Runtime changes persist and take precedence over the configuration file. Other settings
            need a configuration change and a restart.
          </p>
        </div>
      </div>
      <div class="rg-actions">
        <button class="btn btn-glass" type="button" (click)="settings.reload()">
          <rg-icon name="refresh" /><span i18n="@@settings.refresh">Refresh</span>
        </button>
      </div>
    </header>

    <div class="inline-form rg-panel">
      <rg-field>
        <label rgLabel i18n="@@settings.search">Search settings</label>
        <input rgControl type="search" [formControl]="search" autocomplete="off" />
      </rg-field>
    </div>

    @if (editing(); as s) {
      <form class="panel rg-panel" (submit)="$event.preventDefault(); save(s)" novalidate>
        <h2 i18n="@@settings.editHeading">Change {{ s.name }}</h2>
        <p class="hint">{{ s.description }}</p>
        @switch (editKind()) {
          @case ('bool') {
            <rg-field>
              <label rgLabel i18n="@@settings.value">Value</label>
              <select rgControl [formControl]="value">
                <option value="true">true</option>
                <option value="false">false</option>
              </select>
            </rg-field>
          }
          @case ('int') {
            <rg-field>
              <label rgLabel i18n="@@settings.value">Value</label>
              <input rgControl type="number" step="1" [formControl]="value" />
              @if (value.invalid) {
                <rg-error i18n="@@settings.intInvalid">Enter a whole number.</rg-error>
              }
            </rg-field>
          }
          @default {
            <rg-field>
              <label rgLabel i18n="@@settings.value">Value</label>
              <input rgControl [formControl]="value" autocomplete="off" />
              @if (editKind() === 'toml') {
                <rg-hint i18n="@@settings.tomlHint">TOML value, for example [1, 2].</rg-hint>
              }
            </rg-field>
          }
        }
        <dl class="diff">
          <dt i18n="@@settings.current">Current</dt>
          <dd>
            <code>{{ s.value }}</code>
          </dd>
          <dt i18n="@@settings.new">New</dt>
          <dd>
            <code>{{ newToml() }}</code>
          </dd>
          <dt i18n="@@settings.default">Default</dt>
          <dd>
            <code>{{ s.defaultValue }}</code>
          </dd>
        </dl>
        @if (mutation.error(); as e) {
          <rg-error-panel [error]="e" />
        }
        <div class="form-actions">
          <button
            class="btn btn-primary"
            type="submit"
            [disabled]="mutation.busy() || newToml() === s.value"
            i18n="@@settings.save"
          >
            Apply
          </button>
          <button
            class="btn btn-glass"
            type="button"
            [disabled]="mutation.busy() || s.value === s.defaultValue"
            (click)="reset(s)"
            i18n="@@settings.reset"
          >
            Reset to default
          </button>
          <button
            class="btn btn-ghost"
            type="button"
            (click)="editing.set(null)"
            i18n="@@settings.cancel"
          >
            Cancel
          </button>
        </div>
      </form>
    }

    <rg-skeleton [loading]="settings.isLoading()">
      @if (settings.error(); as e) {
        <rg-error-panel [error]="e" (retry)="settings.reload()" />
      } @else if (settings.hasValue()) {
        @if (filtered().length === 0) {
          <rg-empty-state
            class="rg-panel"
            icon="query"
            i18n-heading="@@settings.empty"
            heading="No matching settings"
            i18n-message="@@settings.emptyMessage"
            message="No setting name or description contains the search text."
          />
        } @else {
          <div class="rg-table">
            <table class="table table-hover">
              <caption class="cdk-visually-hidden" i18n="@@settings.caption">
                Settings
              </caption>
              <thead>
                <tr>
                  <th scope="col" i18n="@@settings.colName">Name</th>
                  <th scope="col" i18n="@@settings.colValue">Value</th>
                  <th scope="col" i18n="@@settings.colDefault">Default</th>
                  <th scope="col" i18n="@@settings.colDescription">Description</th>
                  <th scope="col" i18n="@@settings.colActions">Actions</th>
                </tr>
              </thead>
              <tbody>
                @for (s of filtered(); track s.name) {
                  <tr>
                    <th scope="row">
                      <code>{{ s.name }}</code>
                    </th>
                    <td>
                      @if (secret(s)) {
                        <rg-status-badge
                          status="neutral"
                          i18n-label="@@settings.secret"
                          label="Secret (hidden)"
                        />
                      } @else {
                        <code>{{ s.value }}</code>
                        @if (s.value !== s.defaultValue) {
                          <rg-status-badge
                            status="info"
                            i18n-label="@@settings.changed"
                            label="Changed"
                          />
                        }
                      }
                    </td>
                    <td>
                      @if (!secret(s)) {
                        <code>{{ s.defaultValue }}</code>
                      }
                    </td>
                    <td>{{ s.description }}</td>
                    <td>
                      @if (!s.runtimeMutable) {
                        <span class="rg-muted nowrap" i18n="@@settings.restartOnly"
                          >Restart required</span
                        >
                      } @else if (canEdit && !secret(s)) {
                        <button
                          class="btn btn-ghost btn-sm"
                          type="button"
                          (click)="edit(s)"
                          [attr.aria-label]="editLabel(s.name)"
                          i18n="@@settings.edit"
                        >
                          Change
                        </button>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      }
    </rg-skeleton>
  `,
  styles: `
    .diff {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 0.4rem 1.25rem;
      margin: 0.25rem 0 1rem;
      padding: 0.85rem 1rem;
      border: 1px solid var(--rg-hairline);
      border-radius: var(--rg-radius);
      background: var(--rg-accent-softer);
    }
    dt {
      font-weight: 600;
      color: var(--rg-text-muted);
    }
    dd {
      margin: 0;
    }
    /* Long names and values wrap anywhere, but each column keeps a readable minimum. */
    code {
      overflow-wrap: anywhere;
    }
    th[scope='row'] {
      min-width: 15rem;
    }
    td:nth-child(2),
    td:nth-child(3) {
      min-width: 9rem;
    }
    td:nth-child(4) {
      min-width: 16rem;
    }
  `,
})
export class SettingsPage {
  private readonly api = inject(ApiClient);
  protected readonly canEdit = inject(PermissionsService).can('cluster_manage', 'cluster');
  protected readonly mutation = new Mutation();
  protected readonly search = new FormControl('', { nonNullable: true });
  private readonly query = toSignal(this.search.valueChanges, { initialValue: '' });
  protected readonly editing = signal<Setting | null>(null);
  protected readonly editKind = computed(() => kindOf(this.editing()?.defaultValue ?? ''));
  protected readonly value = new FormControl('', { nonNullable: true });
  private readonly valueText = toSignal(this.value.valueChanges, { initialValue: '' });
  protected readonly newToml = computed(() => toToml(this.editKind(), String(this.valueText())));

  protected readonly settings = resource({
    loader: async () => (await this.api.get('/api/v1/settings')).settings,
  });

  protected readonly filtered = computed(() => {
    const q = this.query().trim().toLowerCase();
    const all = this.settings.hasValue() ? this.settings.value() : [];
    return q
      ? all.filter(
          (s) => s.name.toLowerCase().includes(q) || s.description.toLowerCase().includes(q),
        )
      : all;
  });

  protected secret(s: Setting): boolean {
    return isSecret(s);
  }

  protected edit(s: Setting): void {
    this.mutation.error.set(null);
    this.editing.set(s);
    const kind = kindOf(s.defaultValue);
    this.value.setValidators(kind === 'int' ? [Validators.pattern(/^-?\d+$/)] : []);
    this.value.setValue(fromToml(kind, s.value));
  }

  protected save(s: Setting): Promise<void> {
    if (this.value.invalid) return Promise.resolve();
    return this.apply(s, this.newToml());
  }

  protected reset(s: Setting): Promise<void> {
    return this.apply(s, s.defaultValue);
  }

  private async apply(s: Setting, toml: string): Promise<void> {
    const ok = await this.mutation.run(
      () => this.api.request('patch', '/api/v1/settings', { body: { values: { [s.name]: toml } } }),
      $localize`:@@settings.applied:Setting changed.`,
    );
    if (ok) {
      this.editing.set(null);
      this.settings.reload();
    }
  }

  protected editLabel(name: string): string {
    return $localize`:@@settings.editLabel:Change ${name}:name:`;
  }
}
