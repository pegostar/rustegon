// The editor contributions of `editor.main` (find, suggest, hover, folding, Ctrl+M Tab focus
// toggle, …), registered before the first editor is created (monaco.ts). Monaco's language
// modes import this same module, so a smaller hand-picked subset would not load less.
import 'monaco-editor/internal/common/workers';
