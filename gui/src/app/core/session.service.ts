import { inject, Injectable } from '@angular/core';
import { ApiClient } from '../api/api-client';
import { ApiError } from '../api/api-error';
import { SessionStore } from './session-store';

/** Login, logout, `/auth/me` and the own-password change (protocol.md §4, PD-055). */
@Injectable({ providedIn: 'root' })
export class SessionService {
  private readonly api = inject(ApiClient);
  private readonly store = inject(SessionStore);
  readonly user = this.store.user.asReadonly();
  readonly mustChangePassword = this.store.mustChangePassword.asReadonly();
  private probe: Promise<void> | null = null;

  /** Loads `/auth/me` once per page (and after login); a 401 means "not signed in". */
  ensure(): Promise<void> {
    this.probe ??= this.reload();
    return this.probe;
  }

  private async reload(): Promise<void> {
    try {
      this.store.user.set(await this.api.get('/api/v1/auth/me', { skipAuthRedirect: true }));
    } catch (e) {
      const err = ApiError.from(e);
      if (err.status !== 401) {
        this.probe = null;
        throw err;
      }
      this.store.clear();
    }
  }

  async login(user: string, password: string): Promise<void> {
    const res = await this.api.request('post', '/api/v1/auth/login', {
      body: { user, password, delivery: 'cookie', clientInfo: { application: 'rustegon-console' } },
      skipAuthRedirect: true,
    });
    this.store.setMustChange(res.mustChangePassword);
    this.probe = this.reload();
    await this.probe;
  }

  async logout(): Promise<void> {
    try {
      await this.api.request('post', '/api/v1/auth/logout', { skipAuthRedirect: true });
    } catch {
      // The server clears the cookies even for a dead session; local state is cleared anyway.
    }
    this.store.clear();
    this.probe = Promise.resolve();
  }

  /** A 401 here means a wrong current password, so it never redirects to the login page. */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    const user = this.store.user()?.user;
    await this.api.request('post', '/api/v1/auth/password', {
      body: { currentPassword, newPassword },
      skipAuthRedirect: true,
    });
    this.store.setMustChange(false);
    // The change bumps the credential epoch, which ends the user's sessions: sign in again.
    if (user) await this.login(user, newPassword);
  }
}
