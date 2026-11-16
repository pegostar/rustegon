import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { Icon } from '../../shared/icon';

/** Long operations (backup, deep verify) get a 1 h server deadline instead of the default. */
export const LONG_OP_MS = 3_600_000;

/**
 * A TOML scalar as `GET /settings` returns it (`"text"`, `'text'`, `["a", "b"]`) → strings.
 * Only what the destination suggestions need; anything else yields `[]`.
 */
export function tomlStrings(text: string): string[] {
  const t = text.trim();
  if (t.startsWith("'") && t.endsWith("'") && t.length >= 2) return [t.slice(1, -1)];
  try {
    // TOML basic strings and arrays of them are JSON for every path the server writes.
    const v: unknown = JSON.parse(t);
    if (typeof v === 'string') return [v];
    if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string');
  } catch {
    // Not JSON-compatible TOML: no suggestion.
  }
  return [];
}

/** Second-level navigation of Backup & restore (S22, S23). */
@Component({
  selector: 'rg-backup-nav',
  imports: [Icon, RouterLink, RouterLinkActive],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <nav class="nav nav-tabs rg-subnav" i18n-aria-label="@@backup.nav" aria-label="Backup sections">
      <a
        class="nav-link"
        routerLink="/backup"
        routerLinkActive="active"
        [routerLinkActiveOptions]="{ exact: true }"
        ariaCurrentWhenActive="page"
        ><rg-icon name="backup" /><span i18n="@@backup.backups">Backups and snapshots</span></a
      >
      <a
        class="nav-link"
        routerLink="/backup/restore"
        routerLinkActive="active"
        ariaCurrentWhenActive="page"
        ><rg-icon name="history" /><span i18n="@@backup.restore">Restore</span></a
      >
    </nav>
  `,
})
export class BackupNav {}
