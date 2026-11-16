import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  effect,
  ElementRef,
  inject,
  InjectionToken,
  input,
  model,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import type * as Monaco from 'monaco-editor';
import { ThemeService } from '../core/theme.service';
import { loadMonaco } from './monaco';

/** The Monaco loader; component tests replace it (jsdom cannot run Monaco). */
export const MONACO_LOADER = new InjectionToken<typeof loadMonaco>('MONACO_LOADER', {
  factory: () => loadMonaco,
});

let nextId = 0;

/**
 * JSON editor (angular-gui.md §1 `rg-json-editor`, S08): Monaco in accessible mode
 * (`accessibilitySupport: 'on'`; Ctrl+M toggles Tab between indenting and moving focus) with a
 * plain-text alternative, a native labelled textarea that screen readers and voice control
 * handle best. The plain text mode is also the fallback when the editor chunk cannot load.
 */
@Component({
  selector: 'rg-json-editor',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rg-json-editor' },
  template: `
    <div class="rg-json-bar">
      <span [id]="labelId">{{ label() }}</span>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        [attr.aria-pressed]="plain()"
        (click)="plain.set(!plain())"
      >
        <ng-container i18n="@@jsonEditor.plain">Plain text editor</ng-container>
      </button>
    </div>
    @if (plain()) {
      <textarea
        class="rg-json-plain"
        spellcheck="false"
        autocomplete="off"
        [attr.aria-labelledby]="labelId"
        [attr.aria-describedby]="describedBy() || null"
        [attr.aria-invalid]="invalid() || null"
        [readOnly]="readOnly()"
        [style.height.px]="height()"
        [value]="value()"
        (input)="value.set($any($event.target).value)"
      ></textarea>
    } @else {
      <div #host class="rg-json-monaco" [style.height.px]="height()"></div>
      @if (loading()) {
        <p class="rg-hint" role="status" i18n="@@jsonEditor.loading">Loading the editor…</p>
      }
      <p class="rg-hint" i18n="@@jsonEditor.tabHint">
        Press Ctrl+M to switch the Tab key between indenting and moving focus.
      </p>
    }
    @if (failed()) {
      <p class="rg-hint" role="alert" i18n="@@jsonEditor.failed">
        The code editor could not be loaded; the plain text editor is shown instead.
      </p>
    }
  `,
})
export class JsonEditor {
  /** The JSON text (two-way). */
  readonly value = model('');
  /** Visible label; also the editor's accessible name. */
  readonly label = input.required<string>();
  readonly readOnly = input(false);
  readonly height = input(360);
  /** Id of the element with the current error text (`aria-describedby`). */
  readonly describedBy = input<string>();
  readonly invalid = input(false);
  /** Plain text mode (two-way). */
  readonly plain = model(false);

  protected readonly labelId = `rg-json-editor-${nextId++}`;
  protected readonly loading = signal(false);
  protected readonly failed = signal(false);
  private readonly host = viewChild<ElementRef<HTMLElement>>('host');
  private readonly loader = inject(MONACO_LOADER);
  private readonly theme = inject(ThemeService);
  private editor?: Monaco.editor.IStandaloneCodeEditor;
  private monaco?: typeof Monaco;

  constructor() {
    // Create the editor whenever its host element appears (Monaco mode), dispose it otherwise.
    effect(() => {
      const host = this.host()?.nativeElement;
      if (!host) return this.dispose();
      untracked(() => void this.create(host));
    });
    effect(() => {
      const v = this.value();
      if (this.editor && this.editor.getValue() !== v) this.editor.setValue(v);
    });
    effect(() => this.editor?.updateOptions({ readOnly: this.readOnly() }));
    effect(() => {
      const theme = this.themeName();
      this.monaco?.editor.setTheme(theme);
    });
    inject(DestroyRef).onDestroy(() => this.dispose());
  }

  private async create(host: HTMLElement): Promise<void> {
    this.loading.set(true);
    try {
      const monaco = await this.loader();
      if (this.host()?.nativeElement !== host || this.editor) return;
      this.monaco = monaco;
      this.editor = monaco.editor.create(host, {
        value: this.value(),
        language: 'json',
        theme: this.themeName(),
        accessibilitySupport: 'on',
        ariaLabel: this.label(),
        readOnly: this.readOnly(),
        automaticLayout: true,
        minimap: { enabled: false },
        scrollBeyondLastLine: false,
        tabSize: 2,
      });
      this.editor.onDidChangeModelContent(() => this.value.set(this.editor?.getValue() ?? ''));
    } catch {
      this.failed.set(true);
      this.plain.set(true);
    } finally {
      this.loading.set(false);
    }
  }

  private themeName(): string {
    return this.theme.dark() ? 'vs-dark' : 'vs';
  }

  private dispose(): void {
    this.editor?.dispose();
    this.editor = undefined;
  }
}
