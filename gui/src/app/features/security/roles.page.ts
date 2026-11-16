import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  resource,
  signal,
} from '@angular/core';
import {
  AbstractControl,
  FormControl,
  FormGroup,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { ApiClient } from '../../api/api-client';
import type { components } from '../../api/schema';
import { Action } from '../../core/permissions.service';
import { confirm } from '../../shared/confirm-dialog';
import { EmptyState } from '../../shared/empty-state';
import { Icon } from '../../shared/icon';
import { ErrorPanel } from '../../shared/error-panel';
import { Skeleton } from '../../shared/skeleton';
import { formatGrant, Grant, grantsValidator, Mutation, parseGrants, SecurityNav } from './common';
import { FIELD } from '../../shared/field';
import { Dialogs } from '../../shared/dialog';

type Role = components['schemas']['RoleJson'];
type Privilege = components['schemas']['PrivilegeJson'];

// security.md §3.2 action names; the server validates them too (RGN-1001).
const ACTIONS: readonly Action[] = [
  'find',
  'insert',
  'update',
  'delete',
  'bulk_write',
  'aggregate_write',
  'change_stream',
  'subscription_manage',
  'create_collection',
  'drop_collection',
  'alter_collection',
  'create_index',
  'drop_index',
  'create_database',
  'drop_database',
  'txn_kill',
  'query_kill',
  'query_stats_view',
  'user_manage',
  'role_manage',
  'cluster_view',
  'cluster_manage',
  'backup',
  'restore',
  'audit_view',
  'diagnostics',
  'xdc_manage',
  'key_manage',
];

/** `resource: action, action` per line. */
export function formatPrivileges(ps: readonly Privilege[] = []): string {
  return ps.map((p) => `${p.resource}: ${p.actions.join(', ')}`).join('\n');
}

/** Parses the privileges text; `null` when a line is malformed or names an unknown action. */
export function parsePrivileges(text: string): Privilege[] | null {
  const out: Privilege[] = [];
  for (const line of text.split('\n').map((l) => l.trim())) {
    if (!line) continue;
    const i = line.lastIndexOf(':');
    // `resource` itself may contain ':' (`database:shop`): the actions follow the last one.
    if (i <= 0) return null;
    const actions = line
      .slice(i + 1)
      .split(',')
      .map((a) => a.trim())
      .filter(Boolean);
    if (!actions.length || !actions.every((a) => a === '*' || ACTIONS.includes(a as Action)))
      return null;
    out.push({ resource: line.slice(0, i).trim(), actions });
  }
  return out;
}

/**
 * True when `name` inheriting `inherits` would close a cycle: some inherited role reaches
 * `name` again through the current inheritance graph (the server rejects cycles as well).
 */
export function closesCycle(name: string, inherits: string[], roles: readonly Role[]): boolean {
  const byName = new Map(roles.map((r) => [r.name, r]));
  const seen = new Set<string>();
  const stack = inherits.map((r) => r.split('@')[0]);
  while (stack.length) {
    const r = stack.pop() as string;
    if (r === name) return true;
    if (seen.has(r)) continue;
    seen.add(r);
    stack.push(...(byName.get(r)?.inherits ?? []).map((x) => x.split('@')[0]));
  }
  return false;
}

export interface EffectiveRow {
  grant: string;
  via: string;
  resource: string;
  actions: string;
}

/** Which role grants what to a user (S15 viewer), following inheritance. */
export function effectivePrivileges(
  grants: readonly Grant[],
  roles: readonly Role[],
): EffectiveRow[] {
  const byName = new Map(roles.map((r) => [r.name, r]));
  const rows: EffectiveRow[] = [];
  for (const g of grants) {
    const seen = new Set<string>();
    const walk = (role: string, via: string) => {
      if (seen.has(role)) return;
      seen.add(role);
      const r = byName.get(role);
      for (const p of r?.privileges ?? [])
        rows.push({
          grant: formatGrant(g),
          via,
          resource: p.resource,
          actions: p.actions.join(', '),
        });
      for (const i of r?.inherits ?? []) {
        const base = i.split('@')[0];
        walk(base, `${via} → ${i}`);
      }
    };
    walk(g.role, g.role);
  }
  return rows;
}

function privilegesValidator(c: AbstractControl): ValidationErrors | null {
  return parsePrivileges(String(c.value ?? '')) ? null : { privileges: true };
}

/**
 * S15 Roles & permissions: built-in roles read-only, custom roles created, edited (privileges
 * and inheritance as text, PD-141) and dropped; an effective-privileges viewer per user built
 * from `GET /users/{name}` and `GET /roles` (no server endpoint for it, PD-128).
 */
@Component({
  selector: 'rg-roles-page',
  imports: [...FIELD, ReactiveFormsModule, EmptyState, ErrorPanel, Icon, Skeleton, SecurityNav],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: './page.scss',
  template: `
    <header class="rg-page-header rg-hero">
      <div class="rg-hero-title">
        <span class="rg-page-icon"><rg-icon name="security" /></span>
        <h1 i18n="@@roles.heading">Roles</h1>
      </div>
      <div class="rg-actions">
        <button class="btn btn-glass" type="button" (click)="roles.reload()">
          <rg-icon name="refresh" /><span i18n="@@roles.refresh">Refresh</span>
        </button>
        <button class="btn btn-primary" type="button" (click)="openCreate()">
          <rg-icon name="add" /><span i18n="@@roles.new">New role</span>
        </button>
      </div>
    </header>
    <rg-security-nav />

    @if (mutation.error(); as e) {
      <rg-error-panel [error]="e" />
    }

    @if (editing(); as ed) {
      <form class="panel rg-panel" [formGroup]="form" (ngSubmit)="save()" novalidate>
        @if (ed.isNew) {
          <h2 i18n="@@roles.createHeading">New role</h2>
          <rg-field>
            <label rgLabel i18n="@@roles.name">Role name</label>
            <input rgControl formControlName="name" autocomplete="off" />
            @if (form.controls.name.invalid) {
              <rg-error i18n="@@roles.nameInvalid">Enter a new role name.</rg-error>
            }
          </rg-field>
        } @else {
          <h2 i18n="@@roles.editHeading">Edit {{ ed.name }}</h2>
        }
        <rg-field>
          <label rgLabel i18n="@@roles.privileges">Privileges</label>
          <textarea rgControl rows="4" formControlName="privileges"></textarea>
          <rg-hint i18n="@@roles.privilegesHint"
            >One per line: resource: action, action (resource cluster, database:db, database:*,
            collection:db.coll).</rg-hint
          >
          @if (form.controls.privileges.invalid) {
            <rg-error i18n="@@roles.privilegesInvalid"
              >Use resource: action, action with known action names.</rg-error
            >
          }
        </rg-field>
        <rg-field>
          <label rgLabel i18n="@@roles.inherits">Inherits</label>
          <input rgControl formControlName="inherits" autocomplete="off" />
          <rg-hint i18n="@@roles.inheritsHint">Comma-separated role references.</rg-hint>
          @if (form.controls.inherits.hasError('cycle')) {
            <rg-error i18n="@@roles.cycle">This inheritance would form a cycle.</rg-error>
          } @else if (form.controls.inherits.invalid) {
            <rg-error i18n="@@roles.inheritsInvalid">Use role or role&#64;db.</rg-error>
          }
        </rg-field>
        <div class="form-actions">
          <button
            class="btn btn-primary"
            type="submit"
            [disabled]="mutation.busy()"
            i18n="@@roles.save"
          >
            Save role
          </button>
          <button class="btn btn-ghost" type="button" (click)="close()" i18n="@@roles.cancel">
            Cancel
          </button>
        </div>
      </form>
    }

    <rg-skeleton [loading]="roles.isLoading()">
      @if (roles.error(); as e) {
        <rg-error-panel [error]="e" (retry)="roles.reload()" />
      } @else if (roles.value(); as list) {
        @if (list.length === 0) {
          <rg-empty-state
            class="rg-panel"
            icon="security"
            i18n-heading="@@roles.empty"
            heading="No roles"
            i18n-message="@@roles.emptyMessage"
            message="Create a custom role to grant a precise set of privileges."
          />
        } @else {
          <div class="rg-table">
            <table class="table table-hover">
              <caption class="cdk-visually-hidden" i18n="@@roles.caption">
                Roles
              </caption>
              <thead>
                <tr>
                  <th scope="col" i18n="@@roles.colName">Name</th>
                  <th scope="col" i18n="@@roles.colType">Type</th>
                  <th scope="col" i18n="@@roles.colPrivileges">Privileges</th>
                  <th scope="col" i18n="@@roles.colInherits">Inherits</th>
                  <th scope="col" i18n="@@roles.colActions">Actions</th>
                </tr>
              </thead>
              <tbody>
                @for (r of list; track r.name) {
                  <tr>
                    <th scope="row">{{ r.name }}</th>
                    <td>
                      @if (r.builtIn) {
                        <span class="badge badge-glass"
                          ><ng-container i18n="@@roles.builtIn">Built-in</ng-container></span
                        >
                      } @else {
                        <span class="badge badge-glass"
                          ><ng-container i18n="@@roles.custom">Custom</ng-container></span
                        >
                      }
                    </td>
                    <td class="pre">{{ privileges(r) }}</td>
                    <td>{{ (r.inherits ?? []).join(', ') }}</td>
                    <td>
                      @if (!r.builtIn) {
                        <div class="row-actions">
                          <button
                            class="btn btn-ghost btn-sm"
                            type="button"
                            (click)="openEdit(r)"
                            [attr.aria-label]="editLabel(r.name)"
                            i18n="@@roles.edit"
                          >
                            Edit
                          </button>
                          <button
                            class="btn btn-ghost btn-sm danger"
                            type="button"
                            (click)="drop(r)"
                            [attr.aria-label]="dropLabel(r.name)"
                            i18n="@@roles.drop"
                          >
                            Drop
                          </button>
                        </div>
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

    <section class="panel wide rg-panel" aria-labelledby="eff-heading">
      <h2 id="eff-heading" i18n="@@roles.effective">Effective privileges of a user</h2>
      <p class="hint" i18n="@@roles.effectiveHint">
        Computed in the console from the user's role grants and the role definitions; the server
        stays the authority.
      </p>
      <form class="inline-form" (submit)="$event.preventDefault(); explain()">
        <rg-field>
          <label rgLabel i18n="@@roles.effectiveUser">User name</label>
          <input rgControl [formControl]="effectiveUser" autocomplete="off" />
        </rg-field>
        <button class="btn btn-glass" type="submit" i18n="@@roles.explain">Show privileges</button>
      </form>
      @if (effective.error(); as e) {
        <rg-error-panel [error]="e" />
      } @else if (effective.value(); as rows) {
        @if (rows.length === 0) {
          <p i18n="@@roles.noPrivileges">This user has no privileges.</p>
        } @else {
          <div class="table-wrap">
            <table class="table table-hover">
              <caption class="cdk-visually-hidden" i18n="@@roles.effectiveCaption">
                Effective privileges of a user
              </caption>
              <thead>
                <tr>
                  <th scope="col" i18n="@@roles.colGrant">Grant</th>
                  <th scope="col" i18n="@@roles.colVia">Through role</th>
                  <th scope="col" i18n="@@roles.colResource">Resource</th>
                  <th scope="col" i18n="@@roles.colPrivileges">Privileges</th>
                </tr>
              </thead>
              <tbody>
                @for (row of rows; track $index) {
                  <tr>
                    <td>{{ row.grant }}</td>
                    <td>{{ row.via }}</td>
                    <td>{{ row.resource }}</td>
                    <td>{{ row.actions }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      }
    </section>
  `,
  styles: `
    .pre {
      white-space: pre-line;
    }
  `,
})
export class RolesPage {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  protected readonly mutation = new Mutation();
  protected readonly editing = signal<{ isNew: boolean; name: string } | null>(null);

  protected readonly roles = resource({
    loader: async () => (await this.api.get('/api/v1/roles')).roles,
  });

  private readonly rolesOrEmpty = computed(() => (this.roles.hasValue() ? this.roles.value() : []));
  private readonly roleNames = computed(() => this.rolesOrEmpty().map((r) => r.name));

  private readonly nameCtl = new FormControl('', {
    nonNullable: true,
    validators: [
      Validators.required,
      Validators.pattern(/^[A-Za-z0-9_.-]{1,128}$/),
      (c: AbstractControl): ValidationErrors | null =>
        this.roleNames().includes(c.value) ? { exists: true } : null,
    ],
  });

  protected readonly form = new FormGroup({
    name: this.nameCtl,
    privileges: new FormControl('', { nonNullable: true, validators: [privilegesValidator] }),
    inherits: new FormControl('', {
      nonNullable: true,
      validators: [
        grantsValidator,
        (c: AbstractControl): ValidationErrors | null => {
          const ed = this.editing();
          const name = ed && !ed.isNew ? ed.name : this.nameCtl.value;
          const refs = String(c.value ?? '')
            .split(/[\s,]+/)
            .filter(Boolean);
          return name && closesCycle(name, refs, this.rolesOrEmpty()) ? { cycle: true } : null;
        },
      ],
    }),
  });

  protected readonly effectiveUser = new FormControl('', { nonNullable: true });
  private readonly explained = signal<string | undefined>(undefined);
  protected readonly effective = resource({
    params: () => this.explained(),
    loader: async ({ params: name }) => {
      const [{ user }, { roles }] = await Promise.all([
        this.api.get('/api/v1/users/{name}', { path: { name } }),
        this.api.get('/api/v1/roles'),
      ]);
      return effectivePrivileges(user.roles, roles);
    },
  });

  protected privileges(r: Role): string {
    return formatPrivileges(r.privileges);
  }

  protected openCreate(): void {
    this.form.reset();
    this.form.controls.name.enable();
    this.editing.set({ isNew: true, name: '' });
  }

  /** Edits the current definition (`GET /roles/{name}`), not the possibly stale list row. */
  protected async openEdit(listed: Role): Promise<void> {
    this.mutation.error.set(null);
    let r: Role;
    try {
      r = (await this.api.get('/api/v1/roles/{name}', { path: { name: listed.name } })).role;
    } catch (e) {
      this.mutation.error.set(e);
      return;
    }
    this.editing.set({ isNew: false, name: r.name });
    this.form.reset({
      name: r.name,
      privileges: formatPrivileges(r.privileges),
      inherits: (r.inherits ?? []).join(', '),
    });
    this.form.controls.name.disable();
  }

  protected close(): void {
    this.editing.set(null);
    this.form.reset();
  }

  protected explain(): void {
    const name = this.effectiveUser.value.trim();
    if (name === this.explained()) this.effective.reload();
    else this.explained.set(name || undefined);
  }

  protected async save(): Promise<void> {
    const ed = this.editing();
    this.form.controls.inherits.updateValueAndValidity();
    if (!ed || this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    const v = this.form.getRawValue();
    const privileges = parsePrivileges(v.privileges) ?? [];
    const inherits = (parseGrants(v.inherits) ?? []).map(formatGrant);
    const ok = await this.mutation.run(
      () =>
        ed.isNew
          ? this.api.request('post', '/api/v1/roles', {
              body: { name: v.name, privileges, inherits },
            })
          : this.api.request('patch', '/api/v1/roles/{name}', {
              path: { name: ed.name },
              body: { privileges, inherits },
            }),
      $localize`:@@roles.saved:Role saved.`,
    );
    if (ok) {
      this.close();
      this.roles.reload();
    }
  }

  protected async drop(r: Role): Promise<void> {
    if (
      !(await confirm(this.dialog, {
        title: $localize`:@@roles.dropTitle:Drop role ${r.name}:name:?`,
        message: $localize`:@@roles.dropMessage:Users and API keys granted this role lose its privileges. This cannot be undone.`,
        confirmLabel: $localize`:@@roles.dropConfirm:Drop`,
        typedConfirmation: r.name,
      }))
    )
      return;
    const ok = await this.mutation.run(
      () => this.api.request('delete', '/api/v1/roles/{name}', { path: { name: r.name } }),
      $localize`:@@roles.dropped:Role dropped.`,
    );
    if (ok) this.roles.reload();
  }

  protected editLabel(name: string): string {
    return $localize`:@@roles.editLabel:Edit ${name}:name:`;
  }

  protected dropLabel(name: string): string {
    return $localize`:@@roles.dropLabel:Drop ${name}:name:`;
  }
}
