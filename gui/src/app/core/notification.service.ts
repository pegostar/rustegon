import { LiveAnnouncer } from '@angular/cdk/a11y';
import { inject, Injectable, signal } from '@angular/core';

export interface Toast {
  id: number;
  message: string;
  action: string;
}

let nextId = 0;

/**
 * Toasts for background operations and screen-reader announcements for async results (§2).
 * The toasts are rendered by `rg-toasts` (shared/toasts.ts, mounted once in the root component)
 * as polite live regions.
 */
@Injectable({ providedIn: 'root' })
export class NotificationService {
  private readonly announcer = inject(LiveAnnouncer);
  readonly toasts = signal<readonly Toast[]>([]);

  toast(message: string, action?: string): void {
    const t = { id: nextId++, message, action: action ?? $localize`:@@notify.dismiss:Dismiss` };
    this.toasts.update((list) => [...list, t]);
  }

  dismiss(id: number): void {
    this.toasts.update((list) => list.filter((t) => t.id !== id));
  }

  announce(message: string): Promise<void> {
    return this.announcer.announce(message, 'polite');
  }
}
