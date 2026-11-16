import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { AbstractControl, ValidationErrors } from '@angular/forms';
import { RouterLink, RouterLinkActive } from '@angular/router';
import type { components } from '../../api/schema';
import { NotificationService } from '../../core/notification.service';
import { PermissionsService } from '../../core/permissions.service';
import { Icon } from '../../shared/icon';

export type Grant = components['schemas']['RoleGrantJson'];

/** Role reference text of protocol.md §8: `r`, `r@db`, `r@db.c`. */
export function formatGrant(g: Grant): string {
  const res = g.resource ?? '';
  if (res.startsWith('database:') && res !== 'database:*') return `${g.role}@${res.slice(9)}`;
  if (res.startsWith('collection:')) return `${g.role}@${res.slice(11)}`;
  return g.role;
}

export const formatGrants = (grants: readonly Grant[]): string =>
  grants.map(formatGrant).join(', ');

const GRANT = /^[A-Za-z0-9_.-]+(@[A-Za-z0-9_.-]+)?$/;

/** `"read@shop, root"` → grants; `null` when an entry is malformed. */
export function parseGrants(text: string): Grant[] | null {
  const items = text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (!items.every((s) => GRANT.test(s))) return null;
  return items.map((s) => {
    const [role, scope] = s.split('@');
    if (!scope) return { role, resource: '' };
    return { role, resource: scope.includes('.') ? `collection:${scope}` : `database:${scope}` };
  });
}

/** Form validator for a grant list (`required` decides whether it may be empty). */
export function grantsValidator(c: AbstractControl): ValidationErrors | null {
  return parseGrants(String(c.value ?? '')) ? null : { grants: true };
}

/** S14 username rule. */
export const USERNAME = /^[a-zA-Z0-9_.@-]{1,128}$/;

/**
 * 24 random characters from the Web Crypto CSPRNG (≈ 143 bits). Shown once in the form and
 * never stored: the caller keeps it only in a form control that is reset after saving.
 */
export function generatePassword(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!';
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  // 61 symbols: the modulo bias (256 % 61) is negligible against 143 bits of entropy.
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
}

/** A mutation in flight: busy flag, inline error, screen-reader announcement on success. */
export class Mutation {
  readonly busy = signal(false);
  readonly error = signal<unknown>(null);
  private readonly notify = inject(NotificationService);

  async run(fn: () => Promise<unknown>, done: string): Promise<boolean> {
    this.busy.set(true);
    this.error.set(null);
    try {
      await fn();
      void this.notify.announce(done);
      return true;
    } catch (e) {
      this.error.set(e);
      return false;
    } finally {
      this.busy.set(false);
    }
  }
}

/** Second-level navigation of the Security group (S14–S16). */
@Component({
  selector: 'rg-security-nav',
  imports: [Icon, RouterLink, RouterLinkActive],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <nav
      class="nav nav-tabs rg-subnav"
      i18n-aria-label="@@security.nav"
      aria-label="Security sections"
    >
      <a
        class="nav-link"
        routerLink="/security/users"
        routerLinkActive="active"
        ariaCurrentWhenActive="page"
        ><rg-icon name="users" /><span i18n="@@security.users">Users</span></a
      >
      @if (perms.can('role_manage', 'cluster')) {
        <a
          class="nav-link"
          routerLink="/security/roles"
          routerLinkActive="active"
          ariaCurrentWhenActive="page"
          ><rg-icon name="security" /><span i18n="@@security.roles">Roles</span></a
        >
      }
      <a
        class="nav-link"
        routerLink="/security/api-keys"
        routerLinkActive="active"
        ariaCurrentWhenActive="page"
        ><rg-icon name="key" /><span i18n="@@security.apiKeys">API keys</span></a
      >
    </nav>
  `,
})
export class SecurityNav {
  protected readonly perms = inject(PermissionsService);
}
