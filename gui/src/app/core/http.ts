import { HttpContextToken, HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { ApiError } from '../api/api-error';
import { SessionStore } from './session-store';

export const TIMEOUT_MS = new HttpContextToken<number | null>(() => null);
export const SKIP_AUTH_REDIRECT = new HttpContextToken<boolean>(() => false);

/**
 * Every API call: optional `X-RGN-Timeout-Ms`, errors mapped to `ApiError` (RGN code + trace
 * id), and a 401 sends the user to the login page with the current URL preserved
 * (angular-gui.md §2). CSRF is Angular's XSRF support configured in app.config.
 */
export const apiInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const store = inject(SessionStore);
  const timeout = req.context.get(TIMEOUT_MS);
  if (timeout !== null) req = req.clone({ setHeaders: { 'X-RGN-Timeout-Ms': String(timeout) } });
  return next(req).pipe(
    catchError((e: unknown) => {
      const err = ApiError.from(e);
      if (
        e instanceof HttpErrorResponse &&
        e.status === 401 &&
        !req.context.get(SKIP_AUTH_REDIRECT)
      ) {
        store.clear();
        const returnUrl = router.url;
        void router.navigate(['/login'], {
          queryParams: returnUrl.startsWith('/login') ? {} : { returnUrl },
        });
      }
      return throwError(() => err);
    }),
  );
};
