import { Routes } from '@angular/router';

// S05–S08 (angular-gui.md §4). `/data` lists databases; every entity has a deep link under
// `/db`: `/db/:db` (collections), `/db/:db/c/:coll` (documents), `/db/:db/c/:coll/new` and
// `/db/:db/c/:coll/doc/:id` (editor; `:id` is the `_id` as extended-JSON text, PD-135).
export const DATA_ROUTES: Routes = [
  {
    path: '',
    title: () => $localize`:@@title.databases:Databases · Rustegon`,
    loadComponent: () => import('./databases.page').then((m) => m.DatabasesPage),
  },
];

export const DB_ROUTES: Routes = [
  { path: '', pathMatch: 'full', redirectTo: '/data' },
  {
    path: ':db',
    title: () => $localize`:@@title.collections:Collections · Rustegon`,
    loadComponent: () => import('./collections.page').then((m) => m.CollectionsPage),
  },
  {
    path: ':db/c/:coll',
    title: () => $localize`:@@title.documents:Documents · Rustegon`,
    loadComponent: () => import('./documents.page').then((m) => m.DocumentsPage),
  },
  {
    path: ':db/c/:coll/new',
    title: () => $localize`:@@title.newDocument:New document · Rustegon`,
    loadComponent: () => import('./document.page').then((m) => m.DocumentPage),
  },
  {
    path: ':db/c/:coll/doc/:id',
    title: () => $localize`:@@title.document:Document · Rustegon`,
    loadComponent: () => import('./document.page').then((m) => m.DocumentPage),
  },
];
