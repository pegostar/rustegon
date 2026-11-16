export type Locale = 'en' | 'it';
export const LOCALES: readonly Locale[] = ['en', 'it'];
const KEY = 'rg.locale';

/** The stored choice, else the browser language, else English. */
export function pickLocale(): Locale {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(KEY);
  } catch {
    // Storage blocked: fall back to the browser language.
  }
  if (stored === 'en' || stored === 'it') return stored;
  return navigator.language.toLowerCase().startsWith('it') ? 'it' : 'en';
}

/** Stores the choice and reloads, since translations are applied at bootstrap. */
export function switchLocale(locale: Locale): void {
  try {
    localStorage.setItem(KEY, locale);
  } catch {
    return;
  }
  location.reload();
}
