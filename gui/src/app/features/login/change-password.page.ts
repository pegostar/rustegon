import { ChangeDetectionStrategy, Component, inject, input, signal } from '@angular/core';
import {
  AbstractControl,
  FormControl,
  FormGroup,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { Router } from '@angular/router';
import { ApiError } from '../../api/api-error';
import { SessionService } from '../../core/session.service';
import { safeReturnUrl } from './login.page';
import { FIELD } from '../../shared/field';
import { Icon } from '../../shared/icon';

function sameAsNew(c: AbstractControl): ValidationErrors | null {
  return c.value === c.parent?.get('newPassword')?.value ? null : { mismatch: true };
}

/** Own password change (`POST /auth/password`), mandatory when the login said so (S01). */
@Component({
  selector: 'rg-change-password-page',
  imports: [...FIELD, Icon, ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main id="main" tabindex="-1">
      <section class="rg-login-card rg-glass-strong">
        <span class="rg-page-icon"><rg-icon name="key" /></span>
        <h1 i18n="@@changePassword.heading">Change your password</h1>
        @if (session.mustChangePassword()) {
          <p i18n="@@changePassword.required">
            Your administrator requires a new password before you continue.
          </p>
        }
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          <rg-field>
            <label rgLabel i18n="@@changePassword.current">Current password</label>
            <input
              rgControl
              type="password"
              formControlName="current"
              autocomplete="current-password"
            />
          </rg-field>
          <rg-field>
            <label rgLabel i18n="@@changePassword.new">New password</label>
            <input
              rgControl
              type="password"
              formControlName="newPassword"
              autocomplete="new-password"
            />
          </rg-field>
          <rg-field>
            <label rgLabel i18n="@@changePassword.confirm">Repeat the new password</label>
            <input
              rgControl
              type="password"
              formControlName="confirm"
              autocomplete="new-password"
            />
            @if (form.controls.confirm.hasError('mismatch')) {
              <rg-error i18n="@@changePassword.mismatch">The passwords differ.</rg-error>
            }
          </rg-field>
          <div class="rg-error" role="alert">{{ error() }}</div>
          <button
            class="btn btn-primary w-100"
            type="submit"
            [disabled]="busy()"
            i18n="@@changePassword.submit"
          >
            Change password
          </button>
        </form>
      </section>
    </main>
  `,
  styles: `
    main {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1rem;
      outline: none;
    }
    .rg-login-card {
      width: min(28rem, 100%);
      padding: 2.25rem 2rem 2rem;
      border-radius: var(--rg-radius-xl);
      box-shadow:
        inset 0 1px 0 var(--rg-glass-highlight),
        var(--rg-shadow-lg);
      animation: rg-rise var(--rg-dur-slow) var(--rg-ease) both;
    }
    .rg-page-icon {
      margin: 0 auto 1rem;
    }
    h1 {
      margin-bottom: 1rem;
      text-align: center;
    }
    form {
      display: flex;
      flex-direction: column;
    }
    .rg-error {
      min-height: 1.5em;
      margin-bottom: 0.75rem;
    }
  `,
})
export class ChangePasswordPage {
  readonly returnUrl = input<string>();
  protected readonly session = inject(SessionService);
  private readonly router = inject(Router);
  protected readonly form = new FormGroup({
    current: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    newPassword: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    confirm: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, sameAsNew],
    }),
  });
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  constructor() {
    this.form.controls.newPassword.valueChanges.subscribe(() =>
      this.form.controls.confirm.updateValueAndValidity(),
    );
  }

  protected async submit(): Promise<void> {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    try {
      const { current, newPassword } = this.form.getRawValue();
      await this.session.changePassword(current, newPassword);
      await this.router.navigateByUrl(safeReturnUrl(this.returnUrl()));
    } catch (e) {
      const err = ApiError.from(e);
      this.error.set(
        err.code === 4001
          ? $localize`:@@changePassword.wrongCurrent:The current password is wrong.`
          : err.label
            ? `${err.message} (${err.label})`
            : err.message,
      );
    } finally {
      this.busy.set(false);
    }
  }
}
