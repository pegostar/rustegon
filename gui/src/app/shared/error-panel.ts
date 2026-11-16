import { Clipboard } from '@angular/cdk/clipboard';
import { ChangeDetectionStrategy, Component, computed, inject, input, output } from '@angular/core';
import { ApiError } from '../api/api-error';
import { Icon } from './icon';

/** Inline error (§2): message, RGN code, copyable trace id, retry for retryable errors. */
@Component({
  selector: 'rg-error-panel',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @let e = err();
    <div class="rg-error-panel" role="alert">
      <span class="rg-error-icon"><rg-icon name="error" /></span>
      <div>
        <h2>
          @if (e.code === 4002) {
            <ng-container i18n="@@errorPanel.forbidden">Insufficient privileges</ng-container>
          } @else {
            <ng-container i18n="@@errorPanel.heading">Something went wrong</ng-container>
          }
        </h2>
        <p>{{ e.message }}</p>
        <p class="rg-error-meta">
          @if (e.label) {
            <code>{{ e.label }}</code> <span>{{ e.rgnName }}</span>
          }
          @if (e.traceId; as trace) {
            <span i18n="@@errorPanel.trace">Trace id</span> <code>{{ trace }}</code>
            <button
              type="button"
              class="btn btn-ghost btn-sm"
              (click)="copy(trace)"
              i18n="@@errorPanel.copyTrace"
            >
              Copy trace id
            </button>
          }
        </p>
        @if (e.retryable) {
          <button
            type="button"
            class="btn btn-glass btn-sm"
            (click)="retry.emit()"
            i18n="@@errorPanel.retry"
          >
            Retry
          </button>
        }
      </div>
    </div>
  `,
})
export class ErrorPanel {
  readonly error = input.required<unknown>();
  readonly retry = output();
  protected readonly err = computed(() => ApiError.from(this.error()));
  private readonly clipboard = inject(Clipboard);

  protected copy(text: string): void {
    this.clipboard.copy(text);
  }
}
