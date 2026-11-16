import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { render, screen } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiClient } from '../api/api-client';
import { ApiError } from '../api/api-error';
import { SessionService } from '../core/session.service';
import { DashboardPage } from './dashboard/dashboard.page';
import { LoginPage, safeReturnUrl } from './login/login.page';

const failure = (status: number, code: number, details: Record<string, string> = {}) =>
  new ApiError(status, code, 'X', 'server message', false, details, 'tr');

describe('S01 login page', () => {
  let session: { login: ReturnType<typeof vi.fn>; mustChangePassword: () => boolean };

  async function setup() {
    session = { login: vi.fn(), mustChangePassword: () => false };
    const api = { get: vi.fn().mockResolvedValue({ serverVersion: '0.1.0' }) };
    const r = await render(LoginPage, {
      providers: [
        provideRouter([]),
        { provide: SessionService, useValue: session },
        { provide: ApiClient, useValue: api },
      ],
      inputs: { returnUrl: '/data' },
    });
    return r;
  }

  async function signIn(user = 'alice', password = 'pw') {
    await userEvent.type(screen.getByLabelText('User name'), user);
    await userEvent.type(screen.getByLabelText('Password'), password);
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  }

  it('has autocomplete attributes, autofocus and the server version', async () => {
    await setup();
    expect(screen.getByLabelText('User name').getAttribute('autocomplete')).toBe('username');
    expect(screen.getByLabelText('Password').getAttribute('autocomplete')).toBe('current-password');
    expect(document.activeElement).toBe(screen.getByLabelText('User name'));
    expect(await screen.findByText('Rustegon 0.1.0')).toBeTruthy();
  });

  it('does not submit empty fields', async () => {
    await setup();
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(session.login).not.toHaveBeenCalled();
    expect(screen.getByText('Enter your user name.')).toBeTruthy();
  });

  it('navigates to the return URL after a successful login', async () => {
    await setup();
    const nav = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    session.login.mockResolvedValue(undefined);
    await signIn();
    expect(session.login).toHaveBeenCalledWith('alice', 'pw');
    expect(nav).toHaveBeenCalledWith('/data');
  });

  it('announces a generic message for RGN-4001 (no user enumeration)', async () => {
    await setup();
    session.login.mockRejectedValue(failure(401, 4001));
    await signIn();
    expect(screen.getByRole('alert').textContent).toContain('Invalid user name or password.');
    expect(screen.getByRole('alert').textContent).not.toContain('server message');
  });

  it('explains a lockout for RGN-4007', async () => {
    await setup();
    session.login.mockRejectedValue(failure(423, 4007));
    await signIn();
    expect(screen.getByRole('alert').textContent).toContain('temporarily locked');
  });

  it('counts down an RGN-4003 rate limit with the form disabled', async () => {
    await setup();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      session.login.mockRejectedValue(failure(429, 4003, { retry_after_ms: '2500' }));
      await signIn();
      expect(screen.getByRole('alert').textContent).toContain('Try again in 3 s');
      const button = screen.getByRole('button', { name: /Wait 3 s/ }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      await vi.advanceTimersByTimeAsync(3100);
      expect(screen.getByRole('button', { name: 'Sign in' })).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps the return URL inside the console', () => {
    expect(safeReturnUrl('/db/a/c/b/doc/1')).toBe('/db/a/c/b/doc/1');
    expect(safeReturnUrl('//evil.example')).toBe('/dashboard');
    expect(safeReturnUrl('https://evil.example')).toBe('/dashboard');
    expect(safeReturnUrl(undefined)).toBe('/dashboard');
  });
});

describe('S03 dashboard page', () => {
  function api(databases: { name: string }[], fail?: ApiError) {
    return {
      get: vi.fn((path: string) => {
        if (path === '/api/v1/server-info')
          return Promise.resolve({
            serverVersion: '0.1.0',
            protocolVersion: 1,
            features: [],
            nodeAddresses: ['a'],
          });
        if (path === '/api/v1/health/ready') return Promise.resolve({ status: 'ready' });
        if (fail) return Promise.reject(fail);
        if (path === '/api/v1/databases') return Promise.resolve({ databases });
        return Promise.resolve({ collections: [{}, {}] });
      }),
    };
  }

  const renderWith = (a: ReturnType<typeof api>) =>
    render(DashboardPage, { providers: [provideRouter([]), { provide: ApiClient, useValue: a }] });

  it('shows readiness, server info and data counts', async () => {
    await renderWith(api([{ name: 'a' }, { name: 'b' }]));
    expect(await screen.findByText('Ready')).toBeTruthy();
    expect(await screen.findByText('0.1.0')).toBeTruthy();
    expect(await screen.findByText('4')).toBeTruthy();
    expect(screen.getByText('Metrics are not available yet')).toBeTruthy();
  });

  it('offers to create the first database on an empty server', async () => {
    await renderWith(api([]));
    expect(await screen.findByRole('link', { name: 'Create your first database' })).toBeTruthy();
  });

  it('shows the error panel when the data cannot be loaded', async () => {
    await renderWith(api([], new ApiError(503, 3002, 'Unavailable', 'down', true, {}, 'tr-5')));
    expect(await screen.findByText('RGN-3002')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeTruthy();
  });
});
