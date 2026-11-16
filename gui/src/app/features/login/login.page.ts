import {
  afterNextRender,
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  inject,
  input,
  resource,
  signal,
  viewChild,
} from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { SessionService } from '../../core/session.service';
import { Logo } from '../../shared/logo';
import { FIELD } from '../../shared/field';

/** Only same-app paths: an attacker-chosen returnUrl must not leave the console. */
export function safeReturnUrl(url: string | undefined): string {
  return url && url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\')
    ? url
    : '/dashboard';
}

/** S01 Login (angular-gui.md §4): password login over TLS; SCRAM runs server side (protocol.md §4). */
@Component({
  selector: 'rg-login-page',
  imports: [...FIELD, Logo, ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './login.page.html',
  styleUrl: './login.page.scss',
})
export class LoginPage {
  readonly returnUrl = input<string>();
  private readonly session = inject(SessionService);
  private readonly router = inject(Router);
  private readonly api = inject(ApiClient);

  protected readonly form = new FormGroup({
    user: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  });
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  /** Seconds left of an RGN-4003 rate limit; the form is disabled meanwhile. */
  protected readonly countdown = signal(0);
  protected readonly serverInfo = resource({
    loader: () => this.api.get('/api/v1/server-info', { skipAuthRedirect: true }),
  });
  private readonly userInput = viewChild<ElementRef<HTMLInputElement>>('userInput');
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor() {
    afterNextRender(() => this.userInput()?.nativeElement.focus());
    inject(DestroyRef).onDestroy(() => clearInterval(this.timer));
  }

  protected async submit(): Promise<void> {
    if (this.form.invalid || this.busy() || this.countdown() > 0) {
      this.form.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    const { user, password } = this.form.getRawValue();
    try {
      await this.session.login(user, password);
      const target = safeReturnUrl(this.returnUrl());
      await this.router.navigateByUrl(
        this.session.mustChangePassword()
          ? this.router.createUrlTree(['/change-password'], { queryParams: { returnUrl: target } })
          : target,
      );
    } catch (e) {
      this.form.controls.password.reset();
      this.showError(ApiError.from(e));
    } finally {
      this.busy.set(false);
    }
  }

  private showError(e: ApiError): void {
    switch (e.code) {
      case 4001:
        // Generic on purpose: no user enumeration (S01).
        this.error.set($localize`:@@login.invalid:Invalid user name or password.`);
        return;
      case 4007:
        this.error.set(
          $localize`:@@login.locked:This account is temporarily locked after too many failed sign-ins. Try again later or ask an administrator to unlock it.`,
        );
        return;
      case 4003:
        this.startCountdown(Math.ceil(Number(e.details['retry_after_ms'] ?? 1000) / 1000));
        return;
      case 4004:
        this.error.set(
          $localize`:@@login.tls:The server requires TLS. Open the console over https.`,
        );
        return;
      default:
        this.error.set(e.label ? `${e.message} (${e.label})` : e.message);
    }
  }

  private startCountdown(seconds: number): void {
    clearInterval(this.timer);
    this.countdown.set(seconds);
    this.error.set(
      $localize`:@@login.rateLimited:Too many sign-in attempts. Try again in ${seconds}:seconds: s.`,
    );
    this.timer = setInterval(() => {
      const left = this.countdown() - 1;
      this.countdown.set(Math.max(0, left));
      if (left <= 0) {
        clearInterval(this.timer);
        this.error.set(null);
      }
    }, 1000);
  }
}
