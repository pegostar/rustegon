import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { Icon, IconName } from './icon';

/** Empty state (§2): icon, one-sentence explanation, projected primary action, docs link. */
@Component({
  selector: 'rg-empty-state',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rg-empty-state' },
  template: `
    <span class="rg-empty-icon"><rg-icon [name]="icon()" /></span>
    <h2>{{ heading() }}</h2>
    @if (message()) {
      <p>{{ message() }}</p>
    }
    <div class="rg-actions justify-content-center"><ng-content /></div>
    @if (docsUrl(); as url) {
      <a [href]="url" target="_blank" rel="noopener" i18n="@@emptyState.docs">Documentation</a>
    }
  `,
})
export class EmptyState {
  readonly heading = input.required<string>();
  readonly message = input('');
  readonly icon = input<IconName>('info');
  readonly docsUrl = input<string>();
}
