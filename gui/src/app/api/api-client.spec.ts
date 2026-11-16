import {
  HttpErrorResponse,
  provideHttpClient,
  withInterceptors,
  withXsrfConfiguration,
} from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { apiInterceptor } from '../core/http';
import { SessionStore } from '../core/session-store';
import { ApiClient, apiUrl } from './api-client';
import { ApiError } from './api-error';

describe('ApiClient and the HTTP layer', () => {
  let api: ApiClient;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(
          withXsrfConfiguration({ cookieName: 'rgn_csrf', headerName: 'X-RGN-CSRF' }),
          withInterceptors([apiInterceptor]),
        ),
        provideHttpClientTesting(),
      ],
    });
    api = TestBed.inject(ApiClient);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    http.verify();
    document.cookie = 'rgn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  });

  it('substitutes and encodes path parameters', () => {
    expect(apiUrl('/api/v1/databases/{db}/collections/{coll}', { db: 'a b', coll: 'x/y' })).toBe(
      '/api/v1/databases/a%20b/collections/x%2Fy',
    );
    expect(() => apiUrl('/api/v1/databases/{db}', {})).toThrow(/db/);
  });

  it('sends query parameters and the timeout header', async () => {
    const p = api.get('/api/v1/databases/{db}/collections/{coll}/documents', {
      path: { db: 'shop', coll: 'orders' },
      query: { limit: 10, filter: undefined },
      timeoutMs: 5000,
    });
    const req = http.expectOne(
      (r) => r.url === '/api/v1/databases/shop/collections/orders/documents',
    );
    expect(req.request.params.get('limit')).toBe('10');
    expect(req.request.params.has('filter')).toBe(false);
    expect(req.request.headers.get('X-RGN-Timeout-Ms')).toBe('5000');
    req.flush({ documents: [] });
    await expect(p).resolves.toEqual({ documents: [] });
  });

  it('echoes the rgn_csrf cookie in X-RGN-CSRF on state-changing calls only (protocol.md §4)', async () => {
    document.cookie = 'rgn_csrf=abc123';
    const post = api.request('post', '/api/v1/databases', { body: { name: 'shop' } });
    const req = http.expectOne('/api/v1/databases');
    expect(req.request.headers.get('X-RGN-CSRF')).toBe('abc123');
    req.flush({});
    await post;
    const get = api.get('/api/v1/databases');
    const getReq = http.expectOne('/api/v1/databases');
    expect(getReq.request.headers.has('X-RGN-CSRF')).toBe(false);
    getReq.flush({ databases: [] });
    await get;
  });

  it('maps the error body to ApiError with code and trace id', async () => {
    const p = api.get('/api/v1/databases');
    http.expectOne('/api/v1/databases').flush(
      {
        error: {
          code: 1031,
          name: 'AlreadyExists',
          message: 'database exists',
          retryable: false,
          details: { db: 'shop' },
          traceId: 'tr-1',
        },
      },
      { status: 409, statusText: 'Conflict' },
    );
    const err = await p.catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ code: 1031, label: 'RGN-1031', traceId: 'tr-1', status: 409 });
  });

  it('redirects to the login page on 401, preserving the URL, unless skipped', async () => {
    const router = TestBed.inject(Router);
    const nav = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    vi.spyOn(router, 'url', 'get').mockReturnValue('/data?x=1');
    TestBed.inject(SessionStore).user.set({
      user: 'u',
      roles: [],
      mechanism: 'scram',
      expiresAtUnixMs: 0,
    });
    const unauthorized = {
      error: {
        code: 4001,
        name: 'Unauthenticated',
        message: 'no',
        retryable: false,
        details: {},
        traceId: 't',
      },
    };

    const p = api.get('/api/v1/databases');
    http
      .expectOne('/api/v1/databases')
      .flush(unauthorized, { status: 401, statusText: 'Unauthorized' });
    await expect(p).rejects.toBeInstanceOf(ApiError);
    expect(nav).toHaveBeenCalledWith(['/login'], { queryParams: { returnUrl: '/data?x=1' } });
    expect(TestBed.inject(SessionStore).user()).toBeNull();

    nav.mockClear();
    const q = api.get('/api/v1/auth/me', { skipAuthRedirect: true });
    http
      .expectOne('/api/v1/auth/me')
      .flush(unauthorized, { status: 401, statusText: 'Unauthorized' });
    await expect(q).rejects.toMatchObject({ code: 4001 });
    expect(nav).not.toHaveBeenCalled();
  });

  it('reports a network failure without an RGN code', () => {
    const err = ApiError.from(new HttpErrorResponse({ status: 0 }));
    expect(err).toMatchObject({ code: 0, label: '', retryable: true });
  });
});
