import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { NgbToast } from '@ng-bootstrap/ng-bootstrap/toast';
import { NotificationService } from '../core/notification.service';

/** Glass toast stack of NotificationService (polite live regions, auto-hide after 6 s). */
@Component({
  selector: 'rg-toasts',
  imports: [NgbToast],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rg-toasts' },
  template: `
    @for (t of notify.toasts(); track t.id) {
      <ngb-toast
        aria-live="polite"
        [autohide]="true"
        [delay]="6000"
        (hidden)="notify.dismiss(t.id)"
      >
        <span class="flex-grow-1">{{ t.message }}</span>
        <button type="button" class="btn btn-ghost btn-sm" (click)="notify.dismiss(t.id)">
          {{ t.action }}
        </button>
      </ngb-toast>
    }
  `,
})
export class Toasts {
  protected readonly notify = inject(NotificationService);
}
