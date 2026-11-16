/**
 * Lazy Monaco loader (angular-gui.md §1: Monaco is lazy-loaded; CSP of PD-131; budget PD-134).
 * The first call adds Monaco's stylesheet (`monaco.css`, a non-injected global style of
 * angular.json), imports the editor chunk and installs `MonacoEnvironment`; later calls share
 * the same promise. Workers are bundled same-origin (`new Worker(new URL(...))`), so they fit
 * `script-src 'self'; worker-src 'self' blob:` without `eval` or inline scripts.
 */
let monaco: Promise<typeof import('monaco-editor')> | undefined;

export function loadMonaco(): Promise<typeof import('monaco-editor')> {
  monaco ??= load().catch((e: unknown) => {
    monaco = undefined; // a failed chunk download may succeed on the next attempt
    throw e;
  });
  return monaco;
}

async function load(): Promise<typeof import('monaco-editor')> {
  (globalThis as { MonacoEnvironment?: object }).MonacoEnvironment = {
    getWorker: (_id: string, label: string) =>
      label === 'json'
        ? new Worker(new URL('./monaco-json.worker', import.meta.url), { type: 'module' })
        : new Worker(new URL('./monaco-editor.worker', import.meta.url), { type: 'module' }),
  };
  await stylesheet('monaco.css');
  // The ESM build's own `import '….css'` statements are emptied (angular.json `loader`), since
  // the application builder would emit them as files nobody loads; monaco.css replaces them.
  // Not the full `monaco-editor` entry, which also registers ~80 languages, TypeScript and an
  // LSP client (PD-134): the editor API, its contributions and the JSON language only.
  const [api, json] = await Promise.all([
    import('./monaco-contributions').then(() => import('monaco-editor/editor/editor.api')),
    import('monaco-editor/languages/features/json/register'),
  ]);
  return { ...api, json } as unknown as typeof import('monaco-editor');
}

function stylesheet(href: string): Promise<void> {
  if (document.querySelector(`link[data-rg-monaco]`)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const link = Object.assign(document.createElement('link'), { rel: 'stylesheet', href });
    link.dataset['rgMonaco'] = '';
    link.onload = () => resolve();
    link.onerror = () => {
      link.remove();
      reject(new Error(`${href} could not be loaded`));
    };
    document.head.append(link);
  });
}
