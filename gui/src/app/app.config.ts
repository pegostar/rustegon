import {
  provideHttpClient,
  withFetch,
  withInterceptors,
  withXsrfConfiguration,
} from '@angular/common/http';
import {
  ApplicationConfig,
  provideBrowserGlobalErrorListeners,
  provideZonelessChangeDetection,
} from '@angular/core';
import { provideRouter, withComponentInputBinding, withViewTransitions } from '@angular/router';
import { routes } from './app.routes';
import { apiInterceptor } from './core/http';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZonelessChangeDetection(),
    // View transitions: route changes cross-fade the main area (styles/_base.scss; skipped under
    // prefers-reduced-motion by the CSS).
    provideRouter(
      routes,
      withComponentInputBinding(),
      withViewTransitions({ skipInitialTransition: true }),
    ),
    provideHttpClient(
      withFetch(),
      // Signed double-submit CSRF (protocol.md §4): the readable rgn_csrf cookie echoed in
      // X-RGN-CSRF on every state-changing same-origin request.
      withXsrfConfiguration({ cookieName: 'rgn_csrf', headerName: 'X-RGN-CSRF' }),
      withInterceptors([apiInterceptor]),
    ),
  ],
};
