import { Routes } from '@angular/router';

export const INDEXES_ROUTES: Routes = [
  {
    path: '',
    title: () => $localize`:@@title.indexes:Indexes · Rustegon`,
    loadComponent: () => import('./indexes.page').then((m) => m.IndexesPage),
  },
];
