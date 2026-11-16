import { Routes } from '@angular/router';
import { privilegeGuard } from '../../core/guards';

// S14–S16 (the parent route already requires user_manage on the cluster).
export const SECURITY_ROUTES: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'users' },
  {
    path: 'users',
    title: () => $localize`:@@title.users:Users · Rustegon`,
    loadComponent: () => import('./users.page').then((m) => m.UsersPage),
  },
  {
    path: 'roles',
    title: () => $localize`:@@title.roles:Roles · Rustegon`,
    canActivate: [privilegeGuard('role_manage', 'cluster')],
    loadComponent: () => import('./roles.page').then((m) => m.RolesPage),
  },
  {
    path: 'api-keys',
    title: () => $localize`:@@title.apiKeys:API keys · Rustegon`,
    loadComponent: () => import('./api-keys.page').then((m) => m.ApiKeysPage),
  },
];
