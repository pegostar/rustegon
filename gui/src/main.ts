import { registerLocaleData } from '@angular/common';
import localeDe from '@angular/common/locales/de';
import localeEs from '@angular/common/locales/es';
import localeFr from '@angular/common/locales/fr';
import localeIt from '@angular/common/locales/it';
import { LOCALE_ID } from '@angular/core';
import { loadTranslations } from '@angular/localize';
import { bootstrapApplication } from '@angular/platform-browser';
import { App } from './app/app';
import { appConfig } from './app/app.config';
import { pickLocale } from './app/core/i18n';

const LOCALE_DATA = { it: localeIt, de: localeDe, es: localeEs, fr: localeFr };

// Runtime i18n (PD-127, PD-231): one build served under /ui/, translations loaded before
// bootstrap. Templates evaluate $localize at render time; never call $localize at module top level.
async function main(): Promise<void> {
  const locale = pickLocale();
  if (locale !== 'en') {
    registerLocaleData(LOCALE_DATA[locale]);
    const res = await fetch(`locale/messages.${locale}.json`);
    if (res.ok) loadTranslations((await res.json()).translations);
  }
  document.documentElement.lang = locale;
  await bootstrapApplication(App, {
    ...appConfig,
    providers: [...appConfig.providers, { provide: LOCALE_ID, useValue: locale }],
  });
}

main().catch((err: unknown) => console.error(err));
