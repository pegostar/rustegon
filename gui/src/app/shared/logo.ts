import { ChangeDetectionStrategy, Component, input } from '@angular/core';

/** Brand mark: a faceted copper gem (decorative; pair it with the product name as text). */
@Component({
  selector: 'rg-logo',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rg-logo' },
  template: `<svg
    viewBox="0 0 32 32"
    [attr.width]="size()"
    [attr.height]="size()"
    aria-hidden="true"
    focusable="false"
  >
    <path class="f1" d="M16 2 3.5 9 16 16z" />
    <path class="f2" d="M16 2 28.5 9 16 16z" />
    <path class="f3" d="M28.5 9v14L16 16z" />
    <path class="f4" d="M28.5 23 16 30V16z" />
    <path class="f3" d="M16 30 3.5 23 16 16z" />
    <path class="f2" d="M3.5 23V9L16 16z" />
    <path
      class="r"
      d="M12 22V10h5.2a3.6 3.6 0 0 1 .9 7.1L21 22h-2.9l-2.6-4.7H14.4V22zm2.4-6.8h2.6a1.5 1.5 0 0 0 0-3h-2.6z"
    />
  </svg>`,
})
export class Logo {
  readonly size = input(32);
}
