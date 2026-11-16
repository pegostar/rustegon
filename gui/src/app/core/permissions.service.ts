import { inject, Injectable } from '@angular/core';
import { SessionStore } from './session-store';

/** RBAC actions of security.md §3.2 (rustegon-security `rbac::action`). */
export type Action =
  | 'find'
  | 'insert'
  | 'update'
  | 'delete'
  | 'bulk_write'
  | 'aggregate_write'
  | 'change_stream'
  | 'subscription_manage'
  | 'create_collection'
  | 'drop_collection'
  | 'alter_collection'
  | 'create_index'
  | 'drop_index'
  | 'create_database'
  | 'drop_database'
  | 'txn_kill'
  | 'query_kill'
  | 'query_stats_view'
  | 'user_manage'
  | 'role_manage'
  | 'cluster_view'
  | 'cluster_manage'
  | 'backup'
  | 'restore'
  | 'audit_view'
  | 'diagnostics'
  | 'xdc_manage'
  | 'key_manage';

const READ: Action[] = ['find', 'change_stream'];
const READ_WRITE: Action[] = [
  ...READ,
  'insert',
  'update',
  'delete',
  'bulk_write',
  'aggregate_write',
];
const DB_ADMIN: Action[] = [
  'create_collection',
  'drop_collection',
  'alter_collection',
  'create_index',
  'drop_index',
  'create_database',
  'drop_database',
  'txn_kill',
  'query_kill',
  'query_stats_view',
];

// Mirror of the built-in roles (rustegon-security `rbac::role::BuiltinRole::actions`).
// Database roles apply to their scope; cluster roles to everything.
const DB_ROLES: Record<string, Action[]> = {
  read: READ,
  read_write: READ_WRITE,
  db_admin: DB_ADMIN,
  db_owner: [...DB_ADMIN, ...READ_WRITE, 'user_manage', 'role_manage'],
};
const CLUSTER_ROLES: Record<string, Action[] | 'all'> = {
  user_admin: ['user_manage', 'role_manage'],
  monitor: ['cluster_view', 'query_stats_view'],
  backup_operator: ['backup', 'cluster_view'],
  restore_operator: ['restore'],
  cluster_admin: [
    'cluster_view',
    'cluster_manage',
    'audit_view',
    'diagnostics',
    'xdc_manage',
    'key_manage',
    'query_stats_view',
    'query_kill',
    'txn_kill',
  ],
  root: 'all',
};

/** `'cluster'`: the action on the cluster resource; `'any'`: on any resource; else a database. */
export type On = 'cluster' | 'any' | { db: string };

/**
 * Privilege-driven UI (angular-gui.md §1): hides or disables what the user surely cannot do.
 * Custom roles are not resolved here, so they count as "may": the server stays the authority.
 */
@Injectable({ providedIn: 'root' })
export class PermissionsService {
  private readonly store = inject(SessionStore);

  can(action: Action, on: On = 'any'): boolean {
    return (this.store.user()?.roles ?? []).some(({ role, resource }) => {
      const cluster = CLUSTER_ROLES[role];
      if (cluster) return cluster === 'all' || cluster.includes(action);
      const db = DB_ROLES[role];
      if (!db) return role !== 'node';
      if (!db.includes(action) || on === 'cluster') return false;
      if (on === 'any' || !resource || resource === 'cluster' || resource === 'database:*')
        return true;
      return (
        resource === `database:${on.db}` || (resource ?? '').startsWith(`collection:${on.db}.`)
      );
    });
  }
}
