import { Component, computed, input } from '@angular/core';
import { Route } from '@angular/router';
import { EmptyState } from '../../shared/empty-state';
import { Icon } from '../../shared/icon';

export type Group = 'data' | 'query' | 'indexes' | 'security' | 'backup' | 'settings';

export function groupLabel(group: Group): string {
  switch (group) {
    case 'data':
      return $localize`:@@nav.data:Data`;
    case 'query':
      return $localize`:@@nav.query:Query`;
    case 'indexes':
      return $localize`:@@nav.indexes:Indexes`;
    case 'security':
      return $localize`:@@nav.security:Security`;
    case 'backup':
      return $localize`:@@nav.backup:Backup & restore`;
    case 'settings':
      return $localize`:@@nav.settings:Settings`;
  }
}

export function placeholderRoute(group: Group): Route {
  return {
    path: '',
    title: () => `${groupLabel(group)} · Rustegon`,
    data: { group },
    loadComponent: () => Promise.resolve(PlaceholderPage),
  };
}

/** A screen group whose screens are not built yet. */
@Component({
  selector: 'rg-placeholder-page',
  imports: [EmptyState, Icon],
  template: `
    <div class="rg-stack rg-stagger">
      <header class="rg-page-header rg-hero">
        <div class="rg-hero-title">
          <span class="rg-page-icon"><rg-icon [name]="group()" /></span>
          <h1>{{ label() }}</h1>
        </div>
      </header>
      <rg-empty-state
        class="rg-panel"
        i18n-heading="@@placeholder.heading"
        heading="Not available yet"
        i18n-message="@@placeholder.message"
        message="These screens are part of the console but are not built yet. The server API is available to drivers and the CLI."
      />
    </div>
  `,
})
export class PlaceholderPage {
  readonly group = input.required<Group>();
  protected readonly label = computed(() => groupLabel(this.group()));
}
