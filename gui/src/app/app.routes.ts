import { Routes } from '@angular/router';
import { authGuard, privilegeGuard } from './core/guards';

/**
 * Feature groups load their own route files (features/<group>/<group>.routes.ts) so that each
 * wave-2 lane edits only its own file. Titles are functions: $localize must not run at import.
 */
export const routes: Routes = [
  {
    path: 'login',
    title: () => $localize`:@@title.login:Sign in · Rustegon`,
    loadComponent: () => import('./features/login/login.page').then((m) => m.LoginPage),
  },
  {
    path: 'change-password',
    title: () => $localize`:@@title.changePassword:Change password · Rustegon`,
    canActivate: [authGuard],
    loadComponent: () =>
      import('./features/login/change-password.page').then((m) => m.ChangePasswordPage),
  },
  {
    path: '',
    canActivate: [authGuard],
    canActivateChild: [authGuard],
    loadComponent: () => import('./shell/shell').then((m) => m.Shell),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      {
        path: 'dashboard',
        title: () => $localize`:@@title.dashboard:Dashboard · Rustegon`,
        loadComponent: () =>
          import('./features/dashboard/dashboard.page').then((m) => m.DashboardPage),
      },
      // S05–S08; the deep link /db/:db/c/:coll/doc/:id is reserved for the document editor.
      {
        path: 'data',
        loadChildren: () => import('./features/data/data.routes').then((m) => m.DATA_ROUTES),
      },
      {
        path: 'db',
        loadChildren: () => import('./features/data/data.routes').then((m) => m.DB_ROUTES),
      },
      {
        path: 'query',
        loadChildren: () => import('./features/query/query.routes').then((m) => m.QUERY_ROUTES),
      },
      {
        path: 'indexes',
        loadChildren: () =>
          import('./features/indexes/indexes.routes').then((m) => m.INDEXES_ROUTES),
      },
      {
        path: 'security',
        canActivate: [privilegeGuard('user_manage', 'cluster')],
        loadChildren: () =>
          import('./features/security/security.routes').then((m) => m.SECURITY_ROUTES),
      },
      {
        path: 'backup',
        canActivate: [privilegeGuard('backup', 'cluster')],
        loadChildren: () => import('./features/backup/backup.routes').then((m) => m.BACKUP_ROUTES),
      },
      {
        path: 'settings',
        canActivate: [privilegeGuard('cluster_view', 'cluster')],
        loadChildren: () =>
          import('./features/settings/settings.routes').then((m) => m.SETTINGS_ROUTES),
      },
      {
        path: 'forbidden',
        title: () => $localize`:@@title.forbidden:Insufficient privileges · Rustegon`,
        loadComponent: () =>
          import('./features/errors/forbidden.page').then((m) => m.ForbiddenPage),
      },
      {
        path: '**',
        title: () => $localize`:@@title.notFound:Not found · Rustegon`,
        loadComponent: () => import('./features/errors/not-found.page').then((m) => m.NotFoundPage),
      },
    ],
  },
];
