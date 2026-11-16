import { TestBed } from '@angular/core/testing';
import {
  provideRouter,
  RedirectCommand,
  Router,
  RouterStateSnapshot,
  UrlTree,
} from '@angular/router';
import { ApiClient } from '../api/api-client';
import { ApiError } from '../api/api-error';
import { authGuard, privilegeGuard } from './guards';
import { PermissionsService } from './permissions.service';
import { Me, SessionStore } from './session-store';
import { SessionService } from './session.service';
import { ThemeService } from './theme.service';

const me = (roles: Me['roles']): Me => ({
  user: 'u',
  roles,
  mechanism: 'scram',
  expiresAtUnixMs: 0,
});
const unauthorized = new ApiError(401, 4001, 'Unauthenticated', 'no', false);

describe('core', () => {
  let api: { get: ReturnType<typeof vi.fn>; request: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    sessionStorage.clear();
    api = { get: vi.fn(), request: vi.fn() };
    TestBed.configureTestingModule({
      providers: [provideRouter([]), { provide: ApiClient, useValue: api }],
    });
  });

  describe('PermissionsService (built-in roles, security.md §3.3)', () => {
    const can = (roles: Me['roles'], ...args: Parameters<PermissionsService['can']>) => {
      TestBed.inject(SessionStore).user.set(me(roles));
      return TestBed.inject(PermissionsService).can(...args);
    };

    it('root may do everything', () => {
      expect(can([{ role: 'root', resource: '' }], 'backup', 'cluster')).toBe(true);
    });
    it('database roles never grant cluster actions', () => {
      expect(can([{ role: 'db_owner', resource: 'database:shop' }], 'user_manage', 'cluster')).toBe(
        false,
      );
      expect(
        can([{ role: 'db_owner', resource: 'database:shop' }], 'user_manage', { db: 'shop' }),
      ).toBe(true);
    });
    it('database roles apply to their scope', () => {
      const roles = [{ role: 'read', resource: 'collection:shop.orders' }];
      expect(can(roles, 'find', { db: 'shop' })).toBe(true);
      expect(can(roles, 'find', { db: 'crm' })).toBe(false);
      expect(can(roles, 'insert', { db: 'shop' })).toBe(false);
      expect(can([{ role: 'read_write', resource: '' }], 'insert', { db: 'crm' })).toBe(true);
    });
    it('cluster roles grant only their actions', () => {
      expect(can([{ role: 'backup_operator', resource: 'cluster' }], 'backup', 'cluster')).toBe(
        true,
      );
      expect(
        can([{ role: 'backup_operator', resource: 'cluster' }], 'user_manage', 'cluster'),
      ).toBe(false);
    });
    it('custom roles count as "may" (the server decides)', () => {
      expect(can([{ role: 'auditors', resource: '' }], 'audit_view', 'cluster')).toBe(true);
      expect(can([], 'find')).toBe(false);
    });
  });

  describe('SessionService', () => {
    it('login stores the must-change-password flag and loads /auth/me', async () => {
      api.request.mockResolvedValue({ user: 'u', expiresAtUnixMs: 1, mustChangePassword: true });
      api.get.mockResolvedValue(me([]));
      const s = TestBed.inject(SessionService);
      await s.login('u', 'p');
      expect(api.request).toHaveBeenCalledWith('post', '/api/v1/auth/login', {
        body: {
          user: 'u',
          password: 'p',
          delivery: 'cookie',
          clientInfo: { application: 'rustegon-console' },
        },
        skipAuthRedirect: true,
      });
      expect(s.user()?.user).toBe('u');
      expect(s.mustChangePassword()).toBe(true);
      expect(sessionStorage.getItem('rg.mustChangePassword')).toBe('1');

      api.request.mockResolvedValue({ user: 'u', expiresAtUnixMs: 1, mustChangePassword: false });
      await s.changePassword('p', 'q');
      expect(api.request).toHaveBeenCalledWith('post', '/api/v1/auth/password', {
        body: { currentPassword: 'p', newPassword: 'q' },
        skipAuthRedirect: true,
      });
      // The password change ends the session: a new login with the new password follows.
      expect(api.request).toHaveBeenLastCalledWith(
        'post',
        '/api/v1/auth/login',
        expect.objectContaining({ body: expect.objectContaining({ user: 'u', password: 'q' }) }),
      );
      expect(s.mustChangePassword()).toBe(false);
    });

    it('a 401 from /auth/me means signed out; other errors propagate', async () => {
      api.get.mockRejectedValueOnce(unauthorized);
      const s = TestBed.inject(SessionService);
      await s.ensure();
      expect(s.user()).toBeNull();

      api.get.mockRejectedValueOnce(new ApiError(503, 3002, 'Unavailable', 'down', true));
      const fresh = TestBed.runInInjectionContext(() => new SessionService());
      await expect(fresh.ensure()).rejects.toMatchObject({ code: 3002 });
    });

    it('logout clears the session even when the server call fails', async () => {
      TestBed.inject(SessionStore).user.set(me([]));
      api.request.mockRejectedValue(unauthorized);
      const s = TestBed.inject(SessionService);
      await s.logout();
      expect(s.user()).toBeNull();
    });
  });

  describe('guards', () => {
    const state = { url: '/data' } as RouterStateSnapshot;
    const run = (guard: ReturnType<typeof privilegeGuard>) =>
      TestBed.runInInjectionContext(() => guard({} as never, state));

    it('authGuard sends signed-out users to the login page with the return URL', async () => {
      api.get.mockRejectedValue(unauthorized);
      const r = (await run(authGuard)) as UrlTree;
      expect(TestBed.inject(Router).serializeUrl(r)).toBe('/login?returnUrl=%2Fdata');
    });

    it('authGuard sends a pending password change to its page first', async () => {
      api.get.mockResolvedValue(me([]));
      TestBed.inject(SessionStore).setMustChange(true);
      const r = (await run(authGuard)) as UrlTree;
      expect(TestBed.inject(Router).serializeUrl(r)).toBe('/change-password?returnUrl=%2Fdata');
    });

    it('privilegeGuard shows the 403 page in place', () => {
      TestBed.inject(SessionStore).user.set(me([{ role: 'read', resource: '' }]));
      const r = run(privilegeGuard('user_manage', 'cluster'));
      expect(r).toBeInstanceOf(RedirectCommand);
      expect((r as RedirectCommand).navigationBehaviorOptions?.skipLocationChange).toBe(true);
      TestBed.inject(SessionStore).user.set(me([{ role: 'user_admin', resource: 'cluster' }]));
      expect(run(privilegeGuard('user_manage', 'cluster'))).toBe(true);
    });
  });

  it('ThemeService applies the Bootstrap color mode and density to <html>', () => {
    const theme = TestBed.inject(ThemeService);
    theme.mode.set('dark');
    theme.density.set('compact');
    TestBed.tick();
    expect(document.documentElement.getAttribute('data-bs-theme')).toBe('dark');
    expect(document.documentElement.classList.contains('rg-compact')).toBe(true);
    expect(localStorage.getItem('rg.theme')).toBe('dark');
  });
});
