import { Routes } from '@angular/router';

// S17 (the parent route requires cluster_view; changes need cluster_manage).
export const SETTINGS_ROUTES: Routes = [
  {
    path: '',
    title: () => $localize`:@@title.settings:Settings · Rustegon`,
    loadComponent: () => import('./settings.page').then((m) => m.SettingsPage),
  },
];
