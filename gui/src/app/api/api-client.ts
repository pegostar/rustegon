import { HttpClient, HttpContext, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { SKIP_AUTH_REDIRECT, TIMEOUT_MS } from '../core/http';
import type { paths } from './schema';

export type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';
/** Paths that define `M`. */
export type PathWith<M extends Method> = {
  [P in keyof paths]: paths[P][M] extends undefined | never ? never : P;
}[keyof paths];
type Op<P extends keyof paths, M extends Method> = NonNullable<paths[P][M]>;
type Params<O, K extends string> = O extends { parameters: infer P }
  ? K extends keyof P
    ? P[K]
    : never
  : never;
export type RequestBody<O> = O extends {
  requestBody?: { content: { 'application/json': infer B } };
}
  ? B
  : O extends { requestBody?: { content: { 'application/octet-stream': unknown } } }
    ? Blob
    : never;
export type Ok<O> = O extends { responses: { 200: { content: { 'application/json': infer R } } } }
  ? R
  : unknown;

export interface RequestOptions<O> {
  path?: Params<O, 'path'>;
  query?: Params<O, 'query'>;
  body?: RequestBody<O>;
  headers?: Record<string, string>;
  /** Sent as `X-RGN-Timeout-Ms` (protocol.md §4). */
  timeoutMs?: number;
  /** 401 is the caller's business (login, session probe): no redirect to the login page. */
  skipAuthRedirect?: boolean;
}

/** Builds `/api/v1/...` with path parameters substituted (also for `httpResource`). */
export function apiUrl(path: string, params?: object): string {
  return path.replace(/\{(\w+)\}/g, (_, k: string) => {
    const v = (params as Record<string, unknown> | undefined)?.[k];
    if (v === undefined) throw new Error(`missing path parameter ${k}`);
    return encodeURIComponent(String(v));
  });
}

/**
 * Thin typed client over the generated OpenAPI types; errors arrive as `ApiError` (core/http).
 * Example: `await api.request('get', '/api/v1/databases/{db}/collections', { path: { db } })`.
 */
@Injectable({ providedIn: 'root' })
export class ApiClient {
  private readonly http = inject(HttpClient);

  request<M extends Method, P extends PathWith<M>>(
    method: M,
    path: P,
    opts: RequestOptions<Op<P, M>> = {},
  ): Promise<Ok<Op<P, M>>> {
    let params = new HttpParams();
    for (const [k, v] of Object.entries((opts.query ?? {}) as Record<string, unknown>)) {
      if (v !== undefined && v !== null) params = params.set(k, String(v));
    }
    const context = new HttpContext()
      .set(TIMEOUT_MS, opts.timeoutMs ?? null)
      .set(SKIP_AUTH_REDIRECT, opts.skipAuthRedirect ?? false);
    return firstValueFrom(
      this.http.request<Ok<Op<P, M>>>(method.toUpperCase(), apiUrl(path, opts.path), {
        params,
        body: opts.body,
        headers: opts.headers,
        context,
      }),
    );
  }

  get<P extends PathWith<'get'>>(
    path: P,
    opts?: RequestOptions<Op<P, 'get'>>,
  ): Promise<Ok<Op<P, 'get'>>> {
    return this.request('get', path, opts);
  }
}
