import { HttpErrorResponse } from '@angular/common/http';
import type { components } from './schema';

type ErrorBody = components['schemas']['ErrorBody']['error'];

/** A failed API call as protocol.md §7 describes it (`code` 0 = no answer from the server). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: number,
    readonly rgnName: string,
    message: string,
    readonly retryable: boolean,
    readonly details: Readonly<Record<string, string>> = {},
    readonly traceId?: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /** `RGN-4001` style label, empty for network failures. */
  get label(): string {
    return this.code ? `RGN-${this.code}` : '';
  }

  static from(e: unknown): ApiError {
    if (e instanceof ApiError) return e;
    if (e instanceof HttpErrorResponse) {
      const body = (e.error as { error?: ErrorBody } | null)?.error;
      if (body && typeof body.code === 'number') {
        return new ApiError(
          e.status,
          body.code,
          body.name,
          body.message,
          body.retryable,
          body.details ?? {},
          body.traceId,
        );
      }
      if (e.status === 0) {
        return new ApiError(
          0,
          0,
          'Network',
          $localize`:@@error.network:The server could not be reached. Check the network connection and the server's TLS certificate.`,
          true,
        );
      }
      return new ApiError(e.status, 0, 'Http', `HTTP ${e.status} ${e.statusText}`, e.status >= 500);
    }
    return new ApiError(0, 0, 'Client', e instanceof Error ? e.message : String(e), false);
  }
}
