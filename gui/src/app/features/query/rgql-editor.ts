import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  effect,
  ElementRef,
  inject,
  InjectionToken,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';
import type * as monaco from 'monaco-editor';
import { ThemeService } from '../../core/theme.service';
import { loadMonaco } from '../../shared/monaco';
import { registerRgql } from './rgql';

/** Injected so component tests can keep the plain-text fallback (no Monaco under jsdom). */
export const MONACO_LOADER = new InjectionToken<typeof loadMonaco>('MONACO_LOADER', {
  factory: () => loadMonaco,
});

export interface EditorError {
  line: number;
  column: number;
  message: string;
}

const themeName = (dark: boolean) => (dark ? 'rg-glass-dark' : 'rg-glass-light');

/**
 * Monaco themes for the glass well (ADR-033): the editor background is transparent so the
 * frame's glass shows through; token colors keep ≥ 4.5:1 on the frame fill of each mode.
 */
function defineGlassThemes(m: typeof monaco): void {
  const clear = '#00000000';
  m.editor.defineTheme('rg-glass-light', {
    base: 'vs',
    inherit: true,
    rules: [
      { token: 'keyword', foreground: '4338ca', fontStyle: 'bold' },
      { token: 'predefined', foreground: '6d28d9' },
      { token: 'string', foreground: '9d174d' },
      { token: 'number', foreground: '0e7490' },
      { token: 'variable', foreground: '0e7490', fontStyle: 'italic' },
      { token: 'comment', foreground: '4b5563', fontStyle: 'italic' },
      { token: 'operator', foreground: '7c2d12' },
    ],
    colors: {
      'editor.background': clear,
      'editorGutter.background': clear,
      'editor.lineHighlightBackground': '#4f46e50f',
      'editor.lineHighlightBorder': clear,
      'editorLineNumber.foreground': '#64748b',
      'editorLineNumber.activeForeground': '#3730a3',
      'editor.selectionBackground': '#7c3aed33',
      'editorCursor.foreground': '#4338ca',
    },
  });
  m.editor.defineTheme('rg-glass-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [
      { token: 'keyword', foreground: 'a5b4fc', fontStyle: 'bold' },
      { token: 'predefined', foreground: 'c4b5fd' },
      { token: 'string', foreground: 'f9a8d4' },
      { token: 'number', foreground: '67e8f9' },
      { token: 'variable', foreground: '5eead4', fontStyle: 'italic' },
      { token: 'comment', foreground: '9ca3af', fontStyle: 'italic' },
      { token: 'operator', foreground: 'fdba74' },
    ],
    colors: {
      'editor.background': clear,
      'editorGutter.background': clear,
      'editor.lineHighlightBackground': '#818cf814',
      'editor.lineHighlightBorder': clear,
      'editorLineNumber.foreground': '#8b93b8',
      'editorLineNumber.activeForeground': '#c7d2fe',
      'editor.selectionBackground': '#a78bfa40',
      'editorCursor.foreground': '#a5b4fc',
    },
  });
}

/**
 * RGQL editor (§4 S09): Monaco with the `rgql` language, `accessibilitySupport: 'on'` and Tab
 * moving focus (no keyboard trap; Ctrl+M toggles). Until Monaco loads, or if it cannot, a
 * labelled textarea is the editor (the "form alternative" of §2).
 */
@Component({
  selector: 'rg-rgql-editor',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (!ready()) {
      <textarea
        #fallback
        class="fallback"
        spellcheck="false"
        [attr.aria-label]="label()"
        [value]="value()"
        (input)="valueChange.emit($any($event.target).value)"
        (keydown)="onKey($event)"
      ></textarea>
    }
    <div #host class="host" [hidden]="!ready()"></div>
  `,
  styles: `
    :host {
      display: block;
    }
    .host,
    .fallback {
      width: 100%;
      height: 260px;
      box-sizing: border-box;
    }
    .fallback {
      display: block;
      border: 0;
      padding: 12px 16px;
      font: 14px/1.6 var(--bs-font-monospace);
      resize: vertical;
      background: transparent;
      color: var(--rg-text);
    }
  `,
})
export class RgqlEditor {
  readonly value = input('');
  readonly label = input.required<string>();
  readonly valueChange = output<string>();
  /** Ctrl/Cmd+Enter. */
  readonly run = output();

  protected readonly ready = signal(false);
  private readonly host = viewChild.required<ElementRef<HTMLElement>>('host');
  private readonly fallback = viewChild<ElementRef<HTMLTextAreaElement>>('fallback');
  private readonly theme = inject(ThemeService);
  private monaco?: typeof monaco;
  private editor?: monaco.editor.IStandaloneCodeEditor;

  constructor() {
    const destroyRef = inject(DestroyRef);
    let destroyed = false;
    destroyRef.onDestroy(() => {
      destroyed = true;
      this.editor?.getModel()?.dispose();
      this.editor?.dispose();
    });
    inject(MONACO_LOADER)()
      .then((m) => {
        if (destroyed) return;
        this.monaco = m;
        registerRgql(m);
        defineGlassThemes(m);
        this.editor = m.editor.create(this.host().nativeElement, {
          value: this.value(),
          language: 'rgql',
          ariaLabel: this.label(),
          accessibilitySupport: 'on',
          tabFocusMode: true,
          automaticLayout: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          fixedOverflowWidgets: true,
          theme: themeName(this.dark()),
          fontSize: 14,
          lineHeight: 22,
          renderLineHighlight: 'all',
          roundedSelection: true,
          smoothScrolling: true,
          cursorBlinking: 'smooth',
          cursorSmoothCaretAnimation: 'on',
          overviewRulerLanes: 0,
          padding: { top: 12, bottom: 12 },
          scrollbar: { verticalScrollbarSize: 10, horizontalScrollbarSize: 10 },
        });
        this.editor.onDidChangeModelContent(() => {
          const v = this.editor?.getValue() ?? '';
          if (v !== this.value()) this.valueChange.emit(v);
        });
        this.editor.addCommand(m.KeyMod.CtrlCmd | m.KeyCode.Enter, () => this.run.emit());
        this.ready.set(true);
      })
      // Monaco failed to load: the textarea stays the editor.
      .catch(() => undefined);
    // External value changes (tab switch, history) replace the model text.
    effect(() => {
      const v = this.value();
      if (this.editor && this.editor.getValue() !== v) this.editor.setValue(v);
    });
    effect(() => {
      const dark = this.dark();
      this.monaco?.editor.setTheme(themeName(dark));
    });
  }

  /** The selected text (empty without a selection). */
  selection(): string {
    if (this.editor) {
      const sel = this.editor.getSelection();
      return sel ? (this.editor.getModel()?.getValueInRange(sel) ?? '') : '';
    }
    const t = this.fallback()?.nativeElement;
    return t ? t.value.slice(t.selectionStart, t.selectionEnd) : '';
  }

  /** Shows a server parse error as a marker (error squiggle), or clears it. */
  setError(err: EditorError | null): void {
    const model = this.editor?.getModel();
    if (!model || !this.monaco) return;
    this.monaco.editor.setModelMarkers(
      model,
      'rgql',
      err
        ? [
            {
              severity: this.monaco.MarkerSeverity.Error,
              message: err.message,
              startLineNumber: err.line,
              startColumn: err.column,
              endLineNumber: err.line,
              endColumn: err.column + 1,
            },
          ]
        : [],
    );
  }

  /** Moves the caret to a 1-based position and focuses the editor. */
  goTo(line: number, column: number): void {
    if (this.editor) {
      this.editor.setPosition({ lineNumber: line, column });
      this.editor.revealPositionInCenter({ lineNumber: line, column });
      this.editor.focus();
      return;
    }
    const t = this.fallback()?.nativeElement;
    if (!t) return;
    const lines = t.value.split('\n');
    const offset =
      lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0) + Math.max(0, column - 1);
    t.focus();
    t.setSelectionRange(offset, offset);
  }

  protected onKey(e: KeyboardEvent): void {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      this.run.emit();
    }
  }

  private dark(): boolean {
    return this.theme.dark();
  }
}
