import {
  ChangeDetectionStrategy,
  Component,
  inject,
  Injectable,
  InjectionToken,
  Injector,
  input,
  Type,
} from '@angular/core';
import { NgbActiveModal, NgbModal, NgbModalOptions } from '@ng-bootstrap/ng-bootstrap/modal';

/** Data passed to a dialog component by `Dialogs.open(component, data)`. */
export const DIALOG_DATA = new InjectionToken<unknown>('DIALOG_DATA');
const DIALOG_TITLE_ID = new InjectionToken<string>('DIALOG_TITLE_ID');

let nextId = 0;

/**
 * Opens glass modal dialogs (NgbModal; ADR-033). The dialog component injects `DIALOG_DATA`
 * and closes with `inject(NgbActiveModal).close(result)`; the promise resolves with that result,
 * or `undefined` when dismissed (Escape, backdrop, close button).
 */
@Injectable({ providedIn: 'root' })
export class Dialogs {
  private readonly modal = inject(NgbModal);
  private readonly injector = inject(Injector);

  open<R, D = unknown>(
    component: Type<unknown>,
    data?: D,
    options: NgbModalOptions = {},
  ): Promise<R | undefined> {
    const titleId = `rg-dialog-title-${nextId++}`;
    const ref = this.modal.open(component, {
      ariaLabelledBy: titleId,
      centered: true,
      scrollable: true,
      ...options,
      injector: Injector.create({
        parent: this.injector,
        providers: [
          { provide: DIALOG_DATA, useValue: data },
          { provide: DIALOG_TITLE_ID, useValue: titleId },
        ],
      }),
    });
    return ref.result.then(
      (r: R) => r,
      () => undefined,
    );
  }
}

/**
 * Dialog chrome: title (the dialog's accessible name), close button, body and an actions row.
 *
 *   <rg-dialog heading="Create database" i18n-heading="@@x.title">
 *     …body…
 *     <ng-container rgDialogActions>
 *       <button class="btn btn-glass" (click)="modal.dismiss()">Cancel</button>
 *       <button class="btn btn-primary">Create</button>
 *     </ng-container>
 *   </rg-dialog>
 *
 * A dialog form wraps rg-dialog in `<form class="rg-contents">` so the layout is unchanged.
 */
@Component({
  selector: 'rg-dialog',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rg-contents' },
  template: `
    <div class="modal-header">
      <h2 class="modal-title" [id]="titleId">{{ heading() }}</h2>
      <button
        type="button"
        class="btn-close"
        i18n-aria-label="@@dialog.close"
        aria-label="Close"
        (click)="modal.dismiss()"
      ></button>
    </div>
    <div class="modal-body"><ng-content /></div>
    <div class="modal-footer"><ng-content select="[rgDialogActions]" /></div>
  `,
})
export class Dialog {
  readonly heading = input.required<string>();
  protected readonly modal = inject(NgbActiveModal);
  protected readonly titleId = inject(DIALOG_TITLE_ID, { optional: true }) ?? '';
}
