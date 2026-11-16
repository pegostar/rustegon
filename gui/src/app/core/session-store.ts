import { Injectable, signal } from '@angular/core';
import type { components } from '../api/schema';

export type Me = components['schemas']['MeResponse'];
const MUST_CHANGE = 'rg.mustChangePassword';

/** Session state shared by the HTTP layer and SessionService (no tokens: the cookie is HttpOnly). */
@Injectable({ providedIn: 'root' })
export class SessionStore {
  readonly user = signal<Me | null>(null);
  /** Only the login response says it, so it survives a reload in sessionStorage. */
  readonly mustChangePassword = signal(read());

  setMustChange(v: boolean): void {
    this.mustChangePassword.set(v);
    try {
      if (v) sessionStorage.setItem(MUST_CHANGE, '1');
      else sessionStorage.removeItem(MUST_CHANGE);
    } catch {
      // Storage blocked: the flag lives for this page only.
    }
  }

  clear(): void {
    this.user.set(null);
    this.setMustChange(false);
  }
}

function read(): boolean {
  try {
    return sessionStorage.getItem(MUST_CHANGE) === '1';
  } catch {
    return false;
  }
}
