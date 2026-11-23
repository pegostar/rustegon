import { Routes } from '@angular/router';

// S22 Backups and snapshots, S23 Restore (the parent route requires backup on the cluster).
export const BACKUP_ROUTES: Routes = [
  {
    path: '',
    pathMatch: 'full',
    title: () => $localize`:@@title.backups:Backups · Rustegon`,
    loadComponent: () => import('./backups.page').then((m) => m.BackupsPage),
  },
  {
    path: 'databases',
    title: () => $localize`:@@title.dbBackups:Database backups · Rustegon`,
    loadComponent: () => import('./database-backups.page').then((m) => m.DatabaseBackupsPage),
  },
  {
    path: 'database-restore',
    title: () => $localize`:@@title.dbRestore:Restore a database · Rustegon`,
    loadComponent: () => import('./database-restore.page').then((m) => m.DatabaseRestorePage),
  },
  {
    path: 'restore',
    title: () => $localize`:@@title.restore:Restore · Rustegon`,
    loadComponent: () => import('./restore.page').then((m) => m.RestorePage),
  },
];
