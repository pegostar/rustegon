export type Locale = 'en' | 'it' | 'de' | 'es' | 'fr';
export const LOCALES: readonly Locale[] = ['en', 'it', 'de', 'es', 'fr'];
const KEY = 'rg.locale';

const isLocale = (s: string | null): s is Locale => LOCALES.includes(s as Locale);

/** The stored choice, else the browser language, else English. */
export function pickLocale(): Locale {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(KEY);
  } catch {
    // Storage blocked: fall back to the browser language.
  }
  if (isLocale(stored)) return stored;
  const browser = navigator.language.toLowerCase().slice(0, 2);
  return isLocale(browser) ? browser : 'en';
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
