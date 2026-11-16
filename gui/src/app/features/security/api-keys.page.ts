import { DatePipe } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  resource,
  signal,
} from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ApiClient } from '../../api/api-client';
import type { components } from '../../api/schema';
import { PermissionsService } from '../../core/permissions.service';
import { SessionStore } from '../../core/session-store';
import { CodeBlock } from '../../shared/code-block';
import { confirm } from '../../shared/confirm-dialog';
import { EmptyState } from '../../shared/empty-state';
import { Icon } from '../../shared/icon';
import { ErrorPanel } from '../../shared/error-panel';
import { Skeleton } from '../../shared/skeleton';
import { formatGrants, grantsValidator, Mutation, parseGrants, SecurityNav } from './common';
import { FIELD } from '../../shared/field';
import { Dialogs } from '../../shared/dialog';

type ApiKey = components['schemas']['ApiKeyJson'];

/** `10.0.0.0/8, 192.168.1.7` → list; the server parses and validates each CIDR. */
const splitList = (text: string): string[] =>
  text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

/**
 * S16 API keys: list a user's keys, create one (description, scope, expiry, IP allowlist) and
 * show its secret exactly once, revoke. The secret lives only in a signal of this page, cleared
 * on "Done" and when the page goes away; it is never stored or logged. "Last used" is not in
 * R1's API (PD-141).
 */
@Component({
  selector: 'rg-api-keys-page',
  imports: [
    ...FIELD,
    DatePipe,
    ReactiveFormsModule,
    CodeBlock,
    EmptyState,
    ErrorPanel,
    Icon,
    Skeleton,
    SecurityNav,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: './page.scss',
  template: `
    <header class="rg-page-header rg-hero">
      <div class="rg-hero-title">
        <span class="rg-page-icon"><rg-icon name="key" /></span>
        <h1 i18n="@@keys.heading">API keys</h1>
      </div>
      <div class="rg-actions">
        <button class="btn btn-glass" type="button" (click)="keys.reload()">
          <rg-icon name="refresh" /><span i18n="@@keys.refresh">Refresh</span>
        </button>
        <button class="btn btn-primary" type="button" (click)="openCreate()">
          <rg-icon name="add" /><span i18n="@@keys.new">New API key</span>
        </button>
      </div>
    </header>
    <rg-security-nav />

    @if (secret(); as s) {
      <section class="panel wide rg-panel rg-callout" aria-labelledby="secret-heading">
        <div class="rg-callout-head">
          <span class="rg-page-icon sm"><rg-icon name="key" /></span>
          <h2 id="secret-heading" i18n="@@keys.secretHeading">Copy the new API key now</h2>
        </div>
        <p i18n="@@keys.secretMessage">
          This is the only time the key is shown. Store it in a secret manager; send it as
          Authorization: ApiKey &lt;key&gt;.
        </p>
        <rg-code-block [code]="s" i18n-language="@@keys.secretLanguage" language="API key" />
        <div class="form-actions">
          <button class="btn btn-primary" type="button" (click)="secret.set(null)">
            <rg-icon name="check" /><span i18n="@@keys.done">I have stored the key</span>
          </button>
        </div>
      </section>
    }

    @if (mutation.error(); as e) {
      <rg-error-panel [error]="e" />
    }

    @if (canManageUsers) {
      <form
        class="inline-form rg-panel"
        (submit)="$event.preventDefault(); owner.set(ownerInput.value.trim() || me())"
      >
        <rg-field>
          <label rgLabel i18n="@@keys.owner">Keys of user</label>
          <input rgControl [formControl]="ownerInput" autocomplete="off" />
        </rg-field>
        <button class="btn btn-glass" type="submit" i18n="@@keys.show">Show keys</button>
      </form>
    }

    @if (creating()) {
      <form class="panel rg-panel" [formGroup]="form" (ngSubmit)="create()" novalidate>
        <h2 i18n="@@keys.createHeading">New API key for {{ owner() }}</h2>
        <rg-field>
          <label rgLabel i18n="@@keys.description">Description</label>
          <input rgControl formControlName="description" autocomplete="off" />
          @if (form.controls.description.invalid) {
            <rg-error i18n="@@keys.descriptionInvalid">Describe what the key is for.</rg-error>
          }
        </rg-field>
        <rg-field>
          <label rgLabel i18n="@@keys.scope">Roles (scope)</label>
          <input rgControl formControlName="roles" autocomplete="off" />
          <rg-hint i18n="@@keys.scopeHint"
            >A subset of the owner's roles: role, role&#64;db or role&#64;db.coll.</rg-hint
          >
          @if (form.controls.roles.invalid) {
            <rg-error i18n="@@keys.scopeInvalid">Enter at least one role reference.</rg-error>
          }
        </rg-field>
        <rg-field>
          <label rgLabel i18n="@@keys.expiry">Expires on (optional)</label>
          <input rgControl type="date" formControlName="expires" [min]="today" />
        </rg-field>
        <rg-field>
          <label rgLabel i18n="@@keys.allowlist">IP allowlist (optional)</label>
          <input rgControl formControlName="allowlist" autocomplete="off" />
          <rg-hint i18n="@@keys.allowlistHint"
            >Comma-separated addresses or CIDRs; empty allows any address.</rg-hint
          >
        </rg-field>
        <div class="form-actions">
          <button
            class="btn btn-primary"
            type="submit"
            [disabled]="mutation.busy()"
            i18n="@@keys.create"
          >
            Create key
          </button>
          <button
            class="btn btn-ghost"
            type="button"
            (click)="creating.set(false)"
            i18n="@@keys.cancel"
          >
            Cancel
          </button>
        </div>
      </form>
    }

    <rg-skeleton [loading]="keys.isLoading()">
      @if (keys.error(); as e) {
        <rg-error-panel [error]="e" (retry)="keys.reload()" />
      } @else if (keys.value(); as list) {
        @if (list.length === 0) {
          <rg-empty-state
            class="rg-panel"
            icon="key"
            i18n-heading="@@keys.empty"
            heading="No API keys"
            i18n-message="@@keys.emptyMessage"
            message="API keys let applications connect without a password, with a reduced scope."
          />
        } @else {
          <div class="rg-table">
            <table class="table table-hover">
              <caption class="cdk-visually-hidden" i18n="@@keys.caption">
                API keys
              </caption>
              <thead>
                <tr>
                  <th scope="col" i18n="@@keys.colId">Key id</th>
                  <th scope="col" i18n="@@keys.colDescription">Description</th>
                  <th scope="col" i18n="@@keys.colScope">Scope</th>
                  <th scope="col" i18n="@@keys.colCreated">Created</th>
                  <th scope="col" i18n="@@keys.colExpires">Expires</th>
                  <th scope="col" i18n="@@keys.colAllowlist">IP allowlist</th>
                  <th scope="col" i18n="@@keys.colActions">Actions</th>
                </tr>
              </thead>
              <tbody>
                @for (k of list; track k.keyId) {
                  <tr>
                    <th scope="row">
                      <code>{{ k.keyId }}</code>
                    </th>
                    <td>{{ k.description }}</td>
                    <td>{{ scope(k) }}</td>
                    <td>
                      <span [title]="k.createdAtUnixMs | date: 'yyyy-MM-dd HH:mm:ss' : 'UTC'">{{
                        k.createdAtUnixMs | date: 'medium'
                      }}</span>
                    </td>
                    <td>
                      @if (k.expiresAtUnixMs) {
                        <span [title]="k.expiresAtUnixMs | date: 'yyyy-MM-dd HH:mm:ss' : 'UTC'">{{
                          k.expiresAtUnixMs | date: 'medium'
                        }}</span>
                      } @else {
                        <ng-container i18n="@@keys.never">Never</ng-container>
                      }
                    </td>
                    <td>{{ k.ipAllowlist.join(', ') }}</td>
                    <td>
                      <button
                        class="btn btn-ghost btn-sm danger"
                        type="button"
                        (click)="revoke(k)"
                        [attr.aria-label]="revokeLabel(k.keyId)"
                        i18n="@@keys.revoke"
                      >
                        Revoke
                      </button>
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
})
export class ApiKeysPage {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  private readonly store = inject(SessionStore);
  protected readonly canManageUsers = inject(PermissionsService).can('user_manage', 'cluster');
  protected readonly mutation = new Mutation();
  protected readonly me = computed(() => this.store.user()?.user ?? '');
  protected readonly owner = signal(this.me());
  protected readonly ownerInput = new FormControl(this.me(), { nonNullable: true });
  protected readonly creating = signal(false);
  /** The full key, shown once (CreateApiKeyResponse.secret). */
  protected readonly secret = signal<string | null>(null);
  protected readonly today = new Date().toISOString().slice(0, 10);

  protected readonly keys = resource({
    params: () => this.owner(),
    loader: async ({ params: user }) =>
      (await this.api.get('/api/v1/api-keys', { query: { user } })).keys,
  });

  protected readonly form = new FormGroup({
    description: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    roles: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, grantsValidator],
    }),
    expires: new FormControl('', { nonNullable: true }),
    allowlist: new FormControl('', { nonNullable: true }),
  });

  protected scope(k: ApiKey): string {
    return formatGrants(k.roles);
  }

  /** The scope defaults to the owner's whole role set (the server needs a non-empty subset). */
  protected async openCreate(): Promise<void> {
    this.secret.set(null);
    const owner = this.owner();
    this.form.reset();
    this.creating.set(true);
    try {
      const roles =
        owner === this.me()
          ? (this.store.user()?.roles ?? [])
          : (await this.api.get('/api/v1/users/{name}', { path: { name: owner } })).user.roles;
      this.form.controls.roles.setValue(formatGrants(roles));
    } catch (e) {
      this.mutation.error.set(e);
    }
  }

  protected async create(): Promise<void> {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    const v = this.form.getRawValue();
    const owner = this.owner();
    const body: components['schemas']['CreateApiKeyRequest'] = {
      description: v.description,
      roles: parseGrants(v.roles) ?? [],
      ipAllowlist: splitList(v.allowlist),
      // End of the chosen day in the user's timezone.
      expiresAtUnixMs: v.expires ? new Date(`${v.expires}T23:59:59`).getTime() : null,
      user: owner === this.me() ? null : owner,
    };
    let full: string | null = null;
    const ok = await this.mutation.run(
      async () => {
        full = (await this.api.request('post', '/api/v1/api-keys', { body })).secret;
      },
      $localize`:@@keys.created:API key created. Copy it now: it is shown only once.`,
    );
    if (ok) {
      this.creating.set(false);
      this.form.reset();
      this.secret.set(full);
      this.keys.reload();
    }
  }

  protected async revoke(k: ApiKey): Promise<void> {
    if (
      !(await confirm(this.dialog, {
        title: $localize`:@@keys.revokeTitle:Revoke API key ${k.keyId}:id:?`,
        message: $localize`:@@keys.revokeMessage:Applications using this key are refused from now on. This cannot be undone.`,
        confirmLabel: $localize`:@@keys.revokeConfirm:Revoke`,
        typedConfirmation: k.keyId,
      }))
    )
      return;
    const ok = await this.mutation.run(
      () => this.api.request('delete', '/api/v1/api-keys/{key_id}', { path: { key_id: k.keyId } }),
      $localize`:@@keys.revoked:API key revoked.`,
    );
    if (ok) this.keys.reload();
  }

  protected revokeLabel(name: string): string {
    return $localize`:@@keys.revokeLabel:Revoke ${name}:name:`;
  }
}
