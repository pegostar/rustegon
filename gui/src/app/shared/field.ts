import {
  AfterContentInit,
  ChangeDetectionStrategy,
  Component,
  computed,
  contentChild,
  contentChildren,
  DestroyRef,
  Directive,
  ElementRef,
  inject,
  input,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormGroupDirective, NgControl, Validators } from '@angular/forms';

let nextId = 0;

/**
 * Labelled form field (ADR-033; replaces mat-form-field). It links the label, the control, the
 * hint and the error texts (`for`, `aria-describedby`, `aria-invalid`, `aria-required`) and,
 * for reactive-forms controls, shows the errors only once the control was touched or its form
 * submitted ("inline validation on blur and submit", angular-gui.md §2):
 *
 *   <rg-field>
 *     <label rgLabel i18n="@@x.name">Name</label>
 *     <input rgControl formControlName="name" />        (or <select rgControl>, <textarea rgControl>)
 *     <rg-hint i18n="@@x.nameHint">Letters and digits.</rg-hint>
 *     @if (form.controls.name.hasError('required')) { <rg-error i18n="@@x.nameRequired">…</rg-error> }
 *   </rg-field>
 */
@Component({
  selector: 'rg-field',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rg-field', '[class.rg-required]': 'control()?.required()' },
  template: `<ng-content select="[rgLabel]" /><ng-content /><ng-content
      select="rg-hint"
    /><ng-content select="rg-error" />`,
})
export class Field {
  readonly controlId = signal(`rg-field-${nextId++}`);
  protected readonly control = contentChild(FieldControl);
  private readonly hints = contentChildren(Hint);
  private readonly errors = contentChildren(FieldError);

  /** Errors are shown when present and, for form controls, the control is in error state. */
  readonly showErrors = computed(
    () => this.errors().length > 0 && (this.control()?.errorState() ?? true),
  );
  readonly describedBy = computed(() =>
    (this.showErrors() ? this.errors() : this.hints()).map((e) => e.id).join(' '),
  );
}

/** The control of an `rg-field`: an `<input>`, `<select>` or `<textarea>`. */
@Directive({
  selector: '[rgControl]',
  host: {
    '[id]': 'field.controlId()',
    '[class.form-control]': '!select',
    '[class.form-select]': 'select',
    '[attr.aria-describedby]': 'describedBy()',
    '[attr.aria-invalid]': 'field.showErrors() || null',
    '[attr.aria-required]': 'required() || null',
  },
})
export class FieldControl implements AfterContentInit {
  protected readonly field = inject(Field);
  /** Extra ids for `aria-describedby` (e.g. a page-level error message). */
  readonly rgDescribedBy = input<string | null | undefined>(null);
  protected readonly select: boolean;
  private readonly el = inject<ElementRef<HTMLElement>>(ElementRef).nativeElement;
  private readonly ngControl = inject(NgControl, { optional: true, self: true });
  private readonly form = inject(FormGroupDirective, { optional: true });
  private readonly destroyRef = inject(DestroyRef);
  // Reactive-forms state is not a signal: control events bump this counter.
  private readonly changes = signal(0);
  private readonly submitted = signal(false);

  readonly errorState = computed(() => {
    this.changes();
    const c = this.ngControl?.control;
    return c ? c.invalid && (c.touched || this.submitted()) : true;
  });
  readonly required = computed(() => {
    this.changes();
    return (
      this.el.hasAttribute('required') ||
      !!this.ngControl?.control?.hasValidator(Validators.required)
    );
  });
  protected readonly describedBy = computed(
    () => [this.field.describedBy(), this.rgDescribedBy()].filter(Boolean).join(' ') || null,
  );

  constructor() {
    this.select = this.el.tagName === 'SELECT';
    if (this.el.id) this.field.controlId.set(this.el.id);
  }

  ngAfterContentInit(): void {
    // FormControlName creates its control in its own ngOnChanges, so subscribe only now.
    this.ngControl?.control?.events
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => this.changes.update((n) => n + 1));
    this.form?.ngSubmit
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => this.submitted.set(true));
    this.changes.update((n) => n + 1);
  }
}

/** The visible label of an `rg-field`. */
@Directive({
  selector: '[rgLabel]',
  host: { class: 'form-label', '[attr.for]': 'field.controlId()' },
})
export class FieldLabel {
  protected readonly field = inject(Field);
}

/** Help text under the control; hidden while errors are shown. */
@Component({
  selector: 'rg-hint',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rg-hint', '[id]': 'id', '[hidden]': 'field.showErrors()' },
  template: '<ng-content />',
})
export class Hint {
  readonly id = `rg-hint-${nextId++}`;
  protected readonly field = inject(Field);
}

/** Error text of an `rg-field`, rendered by the caller only when the error applies. */
@Component({
  selector: 'rg-error',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rg-error', '[id]': 'id', '[hidden]': '!field.showErrors()' },
  template: '<ng-content />',
})
export class FieldError {
  readonly id = `rg-error-${nextId++}`;
  protected readonly field = inject(Field);
}

/** Everything a template needs for form fields: `imports: [...FIELD]`. */
export const FIELD = [Field, FieldControl, FieldLabel, Hint, FieldError] as const;
