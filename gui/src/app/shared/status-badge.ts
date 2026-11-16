import { ChangeDetectionStrategy, Component, input } from '@angular/core';

export type Status = 'ok' | 'warn' | 'error' | 'info' | 'neutral';

/** Status label: the text carries the meaning, the color only reinforces it (WCAG 1.4.1). */
@Component({
  selector: 'rg-status-badge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { '[class]': '"rg-status " + status()' },
  template: `<span class="rg-status-dot" aria-hidden="true"></span>{{ label() }}`,
})
export class StatusBadge {
  readonly status = input<Status>('neutral');
  readonly label = input.required<string>();
}
