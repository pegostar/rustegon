import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap/modal';
import { Dialog, DIALOG_DATA, Dialogs } from './dialog';
import { FIELD } from './field';

export interface ConfirmData {
  title: string;
  message: string;
  confirmLabel?: string;
  /** Destructive actions on named objects: the user must type this name (§2). */
  typedConfirmation?: string;
}

/** Confirmation dialog; open it with `confirm(dialogs, data)`. */
@Component({
  selector: 'rg-confirm-dialog',
  imports: [Dialog, ...FIELD],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <rg-dialog [heading]="data.title">
      <p>{{ data.message }}</p>
      @if (data.typedConfirmation; as name) {
        <rg-field>
          <label rgLabel i18n="@@confirm.typeName">Type "{{ name }}" to confirm</label>
          <input
            rgControl
            ngbAutofocus
            autocomplete="off"
            spellcheck="false"
            (input)="typed.set($any($event.target).value)"
          />
        </rg-field>
      }
      <ng-container rgDialogActions>
        <button
          type="button"
          class="btn btn-glass"
          (click)="modal.close(false)"
          i18n="@@confirm.cancel"
        >
          Cancel
        </button>
        <button
          type="button"
          class="btn"
          [class.btn-danger]="!!data.typedConfirmation"
          [class.btn-primary]="!data.typedConfirmation"
          [disabled]="!ok()"
          (click)="modal.close(true)"
        >
          {{ data.confirmLabel || confirmText }}
        </button>
      </ng-container>
    </rg-dialog>
  `,
})
export class ConfirmDialog {
  protected readonly data = inject(DIALOG_DATA) as ConfirmData;
  protected readonly modal = inject(NgbActiveModal);
  protected readonly typed = signal('');
  protected readonly ok = computed(
    () => !this.data.typedConfirmation || this.typed() === this.data.typedConfirmation,
  );
  protected readonly confirmText = $localize`:@@confirm.ok:Confirm`;
}

/** Resolves true only when the user confirmed. */
export async function confirm(dialogs: Dialogs, data: ConfirmData): Promise<boolean> {
  return (await dialogs.open<boolean, ConfirmData>(ConfirmDialog, data)) === true;
}
