import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap/modal';
import { ApiError } from '../../api/api-error';
import { Dialog, DIALOG_DATA } from '../../shared/dialog';
import { FIELD } from '../../shared/field';

export interface CreateData {
  title: string;
  label: string;
  hint: string;
  /** Name rule of system-overview.md §9. */
  pattern: RegExp;
  /** Shows the database option `implicitCollectionCreation` (S05). */
  implicitOption?: boolean;
  submit: (name: string, implicit: boolean) => Promise<unknown>;
}

/** Create dialog of S05/S06: a name (validated on blur and submit), server errors inline. */
@Component({
  selector: 'rg-create-dialog',
  imports: [...FIELD, Dialog, ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <form class="rg-contents" [formGroup]="form" (ngSubmit)="submit()" novalidate>
      <rg-dialog [heading]="data.title">
        <rg-field>
          <label rgLabel>{{ data.label }}</label>
          <input rgControl formControlName="name" autocomplete="off" ngbAutofocus />
          <rg-hint>{{ data.hint }}</rg-hint>
          @if (name.invalid) {
            <rg-error i18n="@@data.create.invalid">Enter a name that follows the rule.</rg-error>
          }
        </rg-field>
        @if (data.implicitOption) {
          <div class="form-check">
            <input
              class="form-check-input"
              type="checkbox"
              id="rg-create-implicit"
              formControlName="implicit"
            />
            <label class="form-check-label" for="rg-create-implicit" i18n="@@data.create.implicit"
              >Create collections on first write</label
            >
          </div>
        }
        <div role="alert" class="rg-error">{{ error() }}</div>
        <ng-container rgDialogActions>
          <button
            class="btn btn-glass"
            type="button"
            (click)="modal.dismiss()"
            i18n="@@data.create.cancel"
          >
            Cancel
          </button>
          <button
            class="btn btn-primary"
            type="submit"
            [disabled]="busy()"
            i18n="@@data.create.submit"
          >
            Create
          </button>
        </ng-container>
      </rg-dialog>
    </form>
  `,
})
export class CreateDialog {
  protected readonly data = inject(DIALOG_DATA) as CreateData;
  protected readonly modal = inject(NgbActiveModal);
  protected readonly form = new FormGroup({
    name: new FormControl('', {
      nonNullable: true,
      updateOn: 'blur',
      validators: [Validators.required, Validators.pattern(this.data.pattern)],
    }),
    implicit: new FormControl(true, { nonNullable: true }),
  });
  protected readonly name = this.form.controls.name;
  protected readonly busy = signal(false);
  protected readonly error = signal('');

  protected async submit(): Promise<void> {
    this.name.markAsTouched();
    if (this.name.invalid) return;
    this.busy.set(true);
    this.error.set('');
    try {
      await this.data.submit(this.name.value, this.form.controls.implicit.value);
      this.modal.close(this.name.value);
    } catch (e) {
      const err = ApiError.from(e);
      this.error.set(`${err.label} ${err.message}`.trim());
    } finally {
      this.busy.set(false);
    }
  }
}
