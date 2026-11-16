import { ChangeDetectionStrategy, Component, computed, effect, input, signal } from '@angular/core';

/** Shows its content, or while `loading` a skeleton that appears only after 200 ms (§2). */
@Component({
  selector: 'rg-skeleton',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (loading()) {
      <div aria-busy="true" role="status">
        <span class="cdk-visually-hidden" i18n="@@skeleton.loading">Loading…</span>
        @if (visible()) {
          @for (l of rows(); track $index) {
            <div class="line" aria-hidden="true"></div>
          }
        }
      </div>
    } @else {
      <ng-content />
    }
  `,
})
export class Skeleton {
  readonly loading = input.required<boolean>();
  readonly lines = input(3);
  protected readonly visible = signal(false);
  protected readonly rows = computed(() => Array.from({ length: this.lines() }));

  constructor() {
    effect((onCleanup) => {
      if (!this.loading()) {
        this.visible.set(false);
        return;
      }
      const t = setTimeout(() => this.visible.set(true), 200);
      onCleanup(() => clearTimeout(t));
    });
  }
}
