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
    path: 'restore',
    title: () => $localize`:@@title.restore:Restore · Rustegon`,
    loadComponent: () => import('./restore.page').then((m) => m.RestorePage),
  },
];
