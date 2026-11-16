import { inject } from '@angular/core';
import { CanActivateFn, RedirectCommand, Router } from '@angular/router';
import { Action, On, PermissionsService } from './permissions.service';
import { SessionService } from './session.service';

/** Signed-in users only; a pending password change comes first (security.md §2.2). */
export const authGuard: CanActivateFn = async (_route, state) => {
  const session = inject(SessionService);
  const router = inject(Router);
  await session.ensure();
  if (!session.user())
    return router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
  if (session.mustChangePassword() && !state.url.startsWith('/change-password')) {
    return router.createUrlTree(['/change-password'], { queryParams: { returnUrl: state.url } });
  }
  return true;
};

/** Shows the 403 panel in place (URL kept) when the user surely lacks `action`. */
export function privilegeGuard(action: Action, on: On = 'any'): CanActivateFn {
  return () => {
    if (inject(PermissionsService).can(action, on)) return true;
    const router = inject(Router);
    return new RedirectCommand(router.parseUrl('/forbidden'), { skipLocationChange: true });
  };
}
