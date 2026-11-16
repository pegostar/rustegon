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
import { confirm } from '../../shared/confirm-dialog';
import { EmptyState } from '../../shared/empty-state';
import { Icon } from '../../shared/icon';
import { ErrorPanel } from '../../shared/error-panel';
import { Skeleton } from '../../shared/skeleton';
import { StatusBadge } from '../../shared/status-badge';
import {
  formatGrants,
  generatePassword,
  grantsValidator,
  Mutation,
  parseGrants,
  SecurityNav,
  USERNAME,
} from './common';
import { FIELD } from '../../shared/field';
import { Dialogs } from '../../shared/dialog';

type User = components['schemas']['UserJson'];

/**
 * S14 Users (PD-126 scope): list, create (password or X.509), change roles and password,
 * disable/enable, drop. Not in R1's API, so omitted (PD-141): last login, locked state and
 * unlock, explicit session revocation (a password or role change revokes the sessions).
 */
@Component({
  selector: 'rg-users-page',
  imports: [
    ...FIELD,
    DatePipe,
    ReactiveFormsModule,
    EmptyState,
    ErrorPanel,
    Icon,
    Skeleton,
    StatusBadge,
    SecurityNav,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: './page.scss',
  template: `
    <header class="rg-page-header rg-hero">
      <div class="rg-hero-title">
        <span class="rg-page-icon"><rg-icon name="users" /></span>
        <h1 i18n="@@users.heading">Users</h1>
      </div>
      <div class="rg-actions">
        <button class="btn btn-glass" type="button" (click)="users.reload()">
          <rg-icon name="refresh" /><span i18n="@@users.refresh">Refresh</span>
        </button>
        @if (canManage) {
          <button class="btn btn-primary" type="button" (click)="openCreate()">
            <rg-icon name="add" /><span i18n="@@users.new">New user</span>
          </button>
        }
      </div>
    </header>
    <rg-security-nav />

    @if (mutation.error(); as e) {
      <rg-error-panel [error]="e" />
    }

    @if (creating()) {
      <form class="panel rg-panel" [formGroup]="createForm" (ngSubmit)="create()" novalidate>
        <h2 i18n="@@users.createHeading">New user</h2>
        <rg-field>
          <label rgLabel i18n="@@users.auth">Authentication</label>
          <select rgControl formControlName="kind">
            <option value="password" i18n="@@users.authPassword">Password</option>
            <option value="x509" i18n="@@users.authX509">X.509 certificate</option>
          </select>
        </rg-field>
        @if (createForm.controls.kind.value === 'password') {
          <rg-field>
            <label rgLabel i18n="@@users.name">User name</label>
            <input rgControl formControlName="name" autocomplete="off" />
            <rg-hint i18n="@@users.nameHint"
              >Letters, digits and _ . &#64; -, up to 128 characters.</rg-hint
            >
            @if (createForm.controls.name.invalid) {
              <rg-error i18n="@@users.nameInvalid">Enter a valid user name.</rg-error>
            }
          </rg-field>
          <rg-field>
            <label rgLabel i18n="@@users.password">Initial password</label>
            <input
              rgControl
              [type]="showPassword() ? 'text' : 'password'"
              formControlName="password"
              autocomplete="new-password"
            />
            <rg-hint i18n="@@users.passwordHint"
              >At least 12 characters; the server rejects guessable passwords.</rg-hint
            >
            @if (createForm.controls.password.invalid) {
              <rg-error i18n="@@users.passwordInvalid">Enter at least 12 characters.</rg-error>
            }
          </rg-field>
          <div class="form-actions">
            <button
              class="btn btn-glass"
              type="button"
              (click)="generate(createForm.controls.password)"
              i18n="@@users.generate"
            >
              Generate password
            </button>
          </div>
          @if (showPassword()) {
            <p class="hint" i18n="@@users.generatedHint">
              Copy the generated password now and hand it over securely: it is not shown again.
            </p>
          }
          <div class="form-check mb-3">
            <input
              class="form-check-input"
              type="checkbox"
              id="users-create-must-change"
              formControlName="mustChange"
            />
            <label class="form-check-label" for="users-create-must-change" i18n="@@users.mustChange"
              >Require a password change at first sign-in</label
            >
          </div>
        } @else {
          <rg-field>
            <label rgLabel i18n="@@users.subject">Certificate subject</label>
            <input rgControl formControlName="subject" autocomplete="off" />
            <rg-hint i18n="@@users.subjectHint"
              >For example CN=reporting,O=Example. The user is named x509:&lt;subject&gt;.</rg-hint
            >
            @if (createForm.controls.subject.invalid) {
              <rg-error i18n="@@users.subjectInvalid">Enter the certificate subject.</rg-error>
            }
          </rg-field>
        }
        <rg-field>
          <label rgLabel i18n="@@users.roles">Roles</label>
          <input rgControl formControlName="roles" autocomplete="off" />
          <rg-hint i18n="@@users.rolesHint"
            >Comma-separated: role, role&#64;database or role&#64;database.collection.</rg-hint
          >
          @if (createForm.controls.roles.invalid) {
            <rg-error i18n="@@users.rolesInvalid"
              >Use role, role&#64;db or role&#64;db.coll.</rg-error
            >
          }
        </rg-field>
        <div class="form-actions">
          <button
            class="btn btn-primary"
            type="submit"
            [disabled]="mutation.busy()"
            i18n="@@users.create"
          >
            Create user
          </button>
          <button class="btn btn-ghost" type="button" (click)="closeForms()" i18n="@@users.cancel">
            Cancel
          </button>
        </div>
      </form>
    }

    @if (editing(); as u) {
      <form class="panel rg-panel" [formGroup]="editForm" (ngSubmit)="save(u)" novalidate>
        <h2 i18n="@@users.editHeading">Edit {{ u.name }}</h2>
        <rg-field>
          <label rgLabel i18n="@@users.roles">Roles</label>
          <input rgControl formControlName="roles" autocomplete="off" />
          @if (editForm.controls.roles.invalid) {
            <rg-error i18n="@@users.rolesInvalid"
              >Use role, role&#64;db or role&#64;db.coll.</rg-error
            >
          }
        </rg-field>
        @if (!u.x509Subject) {
          <rg-field>
            <label rgLabel i18n="@@users.newPassword">New password (optional)</label>
            <input
              rgControl
              [type]="showPassword() ? 'text' : 'password'"
              formControlName="password"
              autocomplete="new-password"
            />
            @if (editForm.controls.password.invalid) {
              <rg-error i18n="@@users.passwordInvalid">Enter at least 12 characters.</rg-error>
            }
          </rg-field>
          <div class="form-actions">
            <button
              class="btn btn-glass"
              type="button"
              (click)="generate(editForm.controls.password)"
              i18n="@@users.generate"
            >
              Generate password
            </button>
          </div>
          @if (showPassword()) {
            <p class="hint" i18n="@@users.generatedHint">
              Copy the generated password now and hand it over securely: it is not shown again.
            </p>
          }
          <div class="form-check mb-3">
            <input
              class="form-check-input"
              type="checkbox"
              id="users-edit-must-change"
              formControlName="mustChange"
            />
            <label class="form-check-label" for="users-edit-must-change" i18n="@@users.mustChange"
              >Require a password change at first sign-in</label
            >
          </div>
        }
        <p class="hint" i18n="@@users.revokeHint">
          Changing the roles or the password signs the user out everywhere.
        </p>
        <div class="form-actions">
          <button
            class="btn btn-primary"
            type="submit"
            [disabled]="mutation.busy()"
            i18n="@@users.save"
          >
            Save
          </button>
          <button class="btn btn-ghost" type="button" (click)="closeForms()" i18n="@@users.cancel">
            Cancel
          </button>
        </div>
      </form>
    }

    <rg-skeleton [loading]="users.isLoading()">
      @if (users.error(); as e) {
        <rg-error-panel [error]="e" (retry)="users.reload()" />
      } @else if (users.value(); as list) {
        @if (list.length === 0) {
          <rg-empty-state
            class="rg-panel"
            icon="users"
            i18n-heading="@@users.empty"
            heading="No users"
            i18n-message="@@users.emptyMessage"
            message="Create a user for every person and application that connects."
          />
        } @else {
          <div class="rg-table">
            <table class="table table-hover">
              <caption class="cdk-visually-hidden" i18n="@@users.caption">
                Users
              </caption>
              <thead>
                <tr>
                  <th scope="col" i18n="@@users.colName">Name</th>
                  <th scope="col" i18n="@@users.colAuth">Authentication</th>
                  <th scope="col" i18n="@@users.colRoles">Roles</th>
                  <th scope="col" i18n="@@users.colStatus">Status</th>
                  <th scope="col" i18n="@@users.colCreated">Created</th>
                  <th scope="col" i18n="@@users.colActions">Actions</th>
                </tr>
              </thead>
              <tbody>
                @for (u of list; track u.name) {
                  <tr>
                    <th scope="row">{{ u.name }}</th>
                    <td>
                      @if (u.x509Subject) {
                        <ng-container i18n="@@users.authX509">X.509 certificate</ng-container>
                      } @else {
                        <ng-container i18n="@@users.authPassword">Password</ng-container>
                      }
                    </td>
                    <td>{{ grants(u) }}</td>
                    <td>
                      @if (u.disabled) {
                        <rg-status-badge
                          status="error"
                          i18n-label="@@users.disabled"
                          label="Disabled"
                        />
                      } @else {
                        <rg-status-badge status="ok" i18n-label="@@users.active" label="Active" />
                      }
                      @if (u.mustChangePassword) {
                        <rg-status-badge
                          status="warn"
                          i18n-label="@@users.mustChangeBadge"
                          label="Must change password"
                        />
                      }
                    </td>
                    <td>
                      <span [title]="u.createdAtUnixMs | date: 'yyyy-MM-dd HH:mm:ss' : 'UTC'">{{
                        u.createdAtUnixMs | date: 'medium'
                      }}</span>
                    </td>
                    <td>
                      @if (canManage) {
                        <div class="row-actions">
                          <button
                            class="btn btn-ghost btn-sm"
                            type="button"
                            (click)="openEdit(u)"
                            [attr.aria-label]="editLabel(u.name)"
                            i18n="@@users.edit"
                          >
                            Edit
                          </button>
                          <button
                            class="btn btn-ghost btn-sm"
                            type="button"
                            [disabled]="u.name === me()"
                            (click)="toggleDisabled(u)"
                          >
                            @if (u.disabled) {
                              <ng-container i18n="@@users.enable">Enable</ng-container>
                            } @else {
                              <ng-container i18n="@@users.disable">Disable</ng-container>
                            }
                          </button>
                          <button
                            class="btn btn-ghost btn-sm danger"
                            type="button"
                            [disabled]="!canDrop(u, list)"
                            (click)="drop(u)"
                            [attr.aria-label]="deleteLabel(u.name)"
                            i18n="@@users.delete"
                          >
                            Delete
                          </button>
                        </div>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
          <p class="hint" i18n="@@users.selfHint">
            You cannot disable or delete yourself, nor delete the last user holding the root role.
          </p>
        }
      }
    </rg-skeleton>
  `,
})
export class UsersPage {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(Dialogs);
  private readonly store = inject(SessionStore);
  protected readonly canManage = inject(PermissionsService).can('user_manage', 'cluster');
  protected readonly mutation = new Mutation();
  protected readonly me = computed(() => this.store.user()?.user);
  protected readonly creating = signal(false);
  protected readonly editing = signal<User | null>(null);
  protected readonly showPassword = signal(false);

  protected readonly users = resource({
    loader: async () => (await this.api.get('/api/v1/users')).users,
  });

  protected readonly createForm = new FormGroup({
    kind: new FormControl<'password' | 'x509'>('password', { nonNullable: true }),
    name: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.pattern(USERNAME)],
    }),
    password: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.minLength(12)],
    }),
    mustChange: new FormControl(true, { nonNullable: true }),
    subject: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    roles: new FormControl('', { nonNullable: true, validators: [grantsValidator] }),
  });

  protected readonly editForm = new FormGroup({
    roles: new FormControl('', { nonNullable: true, validators: [grantsValidator] }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.minLength(12)] }),
    mustChange: new FormControl(false, { nonNullable: true }),
  });

  constructor() {
    // Only the fields of the chosen mechanism take part in validation.
    this.createForm.controls.kind.valueChanges.subscribe((k) => this.applyKind(k));
    this.applyKind('password');
  }

  private applyKind(kind: 'password' | 'x509'): void {
    const c = this.createForm.controls;
    for (const ctl of kind === 'password' ? [c.name, c.password] : [c.subject]) ctl.enable();
    for (const ctl of kind === 'password' ? [c.subject] : [c.name, c.password]) ctl.disable();
  }

  protected grants(u: User): string {
    return formatGrants(u.roles);
  }

  /** Never the caller itself, never the last user holding `root` (S14). */
  protected canDrop(u: User, all: User[]): boolean {
    if (u.name === this.me()) return false;
    const isRoot = (x: User) => x.roles.some((g) => g.role === 'root');
    return !isRoot(u) || all.filter(isRoot).length > 1;
  }

  protected generate(ctl: FormControl<string>): void {
    ctl.setValue(generatePassword());
    ctl.markAsTouched();
    this.showPassword.set(true);
  }

  protected openCreate(): void {
    this.closeForms();
    this.creating.set(true);
  }

  protected openEdit(u: User): void {
    this.closeForms();
    this.editForm.reset({ roles: formatGrants(u.roles), password: '', mustChange: false });
    this.editing.set(u);
  }

  /** Drops every typed secret with the form. */
  protected closeForms(): void {
    this.creating.set(false);
    this.editing.set(null);
    this.showPassword.set(false);
    this.createForm.reset({ kind: 'password', mustChange: true });
    this.editForm.reset();
  }

  protected async create(): Promise<void> {
    if (this.createForm.invalid) {
      this.createForm.markAllAsTouched();
      return;
    }
    const v = this.createForm.getRawValue();
    const roles = parseGrants(v.roles) ?? [];
    const body =
      v.kind === 'password'
        ? { name: v.name, password: v.password, mustChangePassword: v.mustChange, roles }
        : { name: `x509:${v.subject}`, x509Subject: v.subject, roles };
    const ok = await this.mutation.run(
      () => this.api.request('post', '/api/v1/users', { body }),
      $localize`:@@users.created:User created.`,
    );
    if (ok) {
      this.closeForms();
      this.users.reload();
    }
  }

  protected async save(u: User): Promise<void> {
    if (this.editForm.invalid) {
      this.editForm.markAllAsTouched();
      return;
    }
    const v = this.editForm.getRawValue();
    const roles = parseGrants(v.roles) ?? [];
    const body: components['schemas']['UpdateUserRequest'] = {};
    if (formatGrants(roles) !== formatGrants(u.roles)) body.roles = roles;
    if (v.password) body.password = v.password;
    if (!u.x509Subject && v.mustChange !== u.mustChangePassword)
      body.mustChangePassword = v.mustChange;
    const ok = await this.mutation.run(
      () => this.api.request('patch', '/api/v1/users/{name}', { path: { name: u.name }, body }),
      $localize`:@@users.saved:User saved.`,
    );
    if (ok) {
      this.closeForms();
      this.users.reload();
    }
  }

  protected async toggleDisabled(u: User): Promise<void> {
    const disabled = !u.disabled;
    if (
      disabled &&
      !(await confirm(this.dialog, {
        title: $localize`:@@users.disableTitle:Disable ${u.name}:name:?`,
        message: $localize`:@@users.disableMessage:The user can no longer sign in until it is enabled again.`,
        confirmLabel: $localize`:@@users.disableConfirm:Disable`,
      }))
    )
      return;
    const ok = await this.mutation.run(
      () =>
        this.api.request('patch', '/api/v1/users/{name}', {
          path: { name: u.name },
          body: { disabled },
        }),
      disabled
        ? $localize`:@@users.disabledDone:User disabled.`
        : $localize`:@@users.enabledDone:User enabled.`,
    );
    if (ok) this.users.reload();
  }

  protected async drop(u: User): Promise<void> {
    if (
      !(await confirm(this.dialog, {
        title: $localize`:@@users.deleteTitle:Delete user ${u.name}:name:?`,
        message: $localize`:@@users.deleteMessage:The user is removed and can no longer sign in. This cannot be undone.`,
        confirmLabel: $localize`:@@users.deleteConfirm:Delete`,
        typedConfirmation: u.name,
      }))
    )
      return;
    const ok = await this.mutation.run(
      () => this.api.request('delete', '/api/v1/users/{name}', { path: { name: u.name } }),
      $localize`:@@users.deleted:User deleted.`,
    );
    if (ok) {
      if (this.editing()?.name === u.name) this.closeForms();
      this.users.reload();
    }
  }

  protected editLabel(name: string): string {
    return $localize`:@@users.editLabel:Edit ${name}:name:`;
  }

  protected deleteLabel(name: string): string {
    return $localize`:@@users.deleteLabel:Delete ${name}:name:`;
  }
}
