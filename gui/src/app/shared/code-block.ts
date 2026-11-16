import { Clipboard } from '@angular/cdk/clipboard';
import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';

/** Read-only code (CLI commands, JSON) rendered as text, with a copy button. */
@Component({
  selector: 'rg-code-block',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rg-code-block' },
  template: `
    <div class="rg-code-bar">
      <span>{{ language() }}</span>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        (click)="clipboard.copy(code())"
        i18n="@@codeBlock.copy"
      >
        Copy
      </button>
    </div>
    <pre tabindex="0"><code>{{ code() }}</code></pre>
  `,
})
export class CodeBlock {
  readonly code = input.required<string>();
  readonly language = input('');
  protected readonly clipboard = inject(Clipboard);
}
