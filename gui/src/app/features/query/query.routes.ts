import { Routes } from '@angular/router';

export const QUERY_ROUTES: Routes = [
  {
    path: '',
    title: () => $localize`:@@title.query:Query · Rustegon`,
    loadComponent: () => import('./query.page').then((m) => m.QueryPage),
  },
];
