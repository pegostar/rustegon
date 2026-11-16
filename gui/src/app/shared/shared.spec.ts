import { ApplicationRef } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { render, screen } from '@testing-library/angular';
import userEvent from '@testing-library/user-event';
import { ApiError } from '../api/api-error';
import { CodeBlock } from './code-block';
import { confirm } from './confirm-dialog';
import { DataGrid, GridColumn } from './data-grid';
import { Dialogs } from './dialog';
import { EmptyState } from './empty-state';
import { ErrorPanel } from './error-panel';
import { Bytes, Duration, formatBytes, formatDuration } from './format';
import { Skeleton } from './skeleton';
import { StatusBadge } from './status-badge';

// jsdom has no layout: scrolling is a no-op there.
Element.prototype.scrollTo ??= () => undefined;

describe('shared UI kit', () => {
  it('rg-empty-state shows heading, message, projected action and docs link', async () => {
    await render(
      `<rg-empty-state heading="No databases" message="Create one." docsUrl="https://docs">
        <button>Create</button></rg-empty-state>`,
      { imports: [EmptyState] },
    );
    expect(screen.getByRole('heading', { name: 'No databases' })).toBeTruthy();
    expect(screen.getByText('Create one.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Create' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Documentation' }).getAttribute('href')).toBe(
      'https://docs',
    );
  });

  describe('rg-error-panel', () => {
    it('shows message, RGN code and trace id, and retry for retryable errors', async () => {
      const retry = vi.fn();
      await render(ErrorPanel, {
        inputs: {
          error: new ApiError(503, 3002, 'Unavailable', 'range unavailable', true, {}, 'tr-9'),
        },
        on: { retry },
      });
      expect(screen.getByRole('alert').textContent).toContain('range unavailable');
      expect(screen.getByText('RGN-3002')).toBeTruthy();
      expect(screen.getByText('tr-9')).toBeTruthy();
      expect(screen.getByRole('button', { name: 'Copy trace id' })).toBeTruthy();
      await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
      expect(retry).toHaveBeenCalled();
    });

    it('names a 403 as insufficient privileges and offers no retry for non-retryable errors', async () => {
      await render(ErrorPanel, {
        inputs: { error: new ApiError(403, 4002, 'PermissionDenied', 'denied', false) },
      });
      expect(screen.getByRole('heading', { name: 'Insufficient privileges' })).toBeTruthy();
      expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
    });
  });

  describe('rg-skeleton', () => {
    afterEach(() => vi.useRealTimers());

    it('shows lines only after 200 ms of loading, then the content', async () => {
      vi.useFakeTimers();
      const { fixture, rerender } = await render(
        `<rg-skeleton [loading]="loading" [lines]="2"><p>data</p></rg-skeleton>`,
        { imports: [Skeleton], componentProperties: { loading: true } },
      );
      expect(screen.getByRole('status').getAttribute('aria-busy')).toBe('true');
      expect(fixture.nativeElement.querySelectorAll('.line').length).toBe(0);
      await vi.advanceTimersByTimeAsync(250);
      fixture.detectChanges();
      expect(fixture.nativeElement.querySelectorAll('.line').length).toBe(2);
      await rerender({ componentProperties: { loading: false } });
      expect(screen.getByText('data')).toBeTruthy();
    });
  });

  it('rg-confirm-dialog with typed confirmation enables confirm only on the exact name', async () => {
    await render('', {});
    const result = confirm(TestBed.inject(Dialogs), {
      title: 'Drop database',
      message: 'This deletes everything.',
      typedConfirmation: 'shop',
    });
    // Plain DOM events: the dialog lives outside the rendered fixture, and Testing Library's
    // per-event detectChanges would re-enter the application tick the dialog itself schedules.
    const ok = (await screen.findByRole('button', { name: 'Confirm' })) as HTMLButtonElement;
    const input = screen.getByRole('textbox') as HTMLInputElement;
    const type = async (v: string) => {
      input.value = v;
      input.dispatchEvent(new Event('input'));
      await TestBed.inject(ApplicationRef).whenStable();
    };
    expect(ok.disabled).toBe(true);
    await type('sho');
    expect(ok.disabled).toBe(true);
    await type('shop');
    expect(ok.disabled).toBe(false);
    ok.click();
    await expect(result).resolves.toBe(true);
  });

  it('rg-confirm-dialog resolves false on cancel', async () => {
    await render('', {});
    const result = confirm(TestBed.inject(Dialogs), { title: 'Sure?', message: 'm' });
    (await screen.findByRole('button', { name: 'Cancel' })).click();
    await expect(result).resolves.toBe(false);
  });

  it('rg-status-badge carries the meaning in text', async () => {
    const { fixture } = await render(StatusBadge, {
      inputs: { status: 'error', label: 'Unhealthy' },
    });
    expect(screen.getByText('Unhealthy')).toBeTruthy();
    expect(fixture.nativeElement.classList.contains('error')).toBe(true);
  });

  it('formats bytes and durations', async () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1536)).toBe('1.5 KiB');
    expect(formatBytes(16 * 1024 * 1024)).toBe('16.0 MiB');
    expect(formatBytes(200 * 1024)).toBe('200 KiB');
    expect(formatDuration(35)).toBe('35 ms');
    expect(formatDuration(1250)).toBe('1.3 s');
    expect(formatDuration(125_000)).toBe('2 min 5 s');
    expect(formatDuration(7_260_000)).toBe('2 h 1 min');
    await render(`<rg-bytes [value]="2048" /> <rg-duration [ms]="35" />`, {
      imports: [Bytes, Duration],
    });
    expect(screen.getByTitle('2048 B').textContent).toBe('2.0 KiB');
    expect(screen.getByTitle('35 ms').textContent).toBe('35 ms');
  });

  it('rg-code-block renders code as text', async () => {
    await render(CodeBlock, { inputs: { code: '<b>rustegon restore</b>', language: 'shell' } });
    expect(screen.getByText('<b>rustegon restore</b>')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Copy' })).toBeTruthy();
  });

  describe('rg-data-grid', () => {
    interface Row {
      name: string;
      size: number;
    }
    const columns: GridColumn<Row>[] = [
      { key: 'name', header: 'Name' },
      { key: 'size', header: 'Size', cell: (r) => formatBytes(r.size) },
    ];
    const rows: Row[] = Array.from({ length: 5 }, (_, i) => ({ name: `c${i}`, size: i * 1024 }));

    it('renders a grid with headers and rows', async () => {
      await render(DataGrid<Row>, { inputs: { columns, rows, label: 'Collections' } });
      const grid = screen.getByRole('grid', { name: 'Collections' });
      expect(grid.getAttribute('aria-rowcount')).toBe('6');
      expect(screen.getAllByRole('columnheader').map((h) => h.textContent)).toEqual([
        'Name',
        'Size',
      ]);
      expect(await screen.findByText('c1')).toBeTruthy();
      expect(screen.getByText('1.0 KiB')).toBeTruthy();
    });

    it('moves the active row with arrow keys and activates it with Enter', async () => {
      const activate = vi.fn();
      await render(DataGrid<Row>, {
        inputs: { columns, rows, label: 'Collections' },
        on: { rowActivate: activate },
      });
      const grid = screen.getByRole('grid');
      grid.focus();
      await userEvent.keyboard('{ArrowDown}{ArrowDown}');
      const active = grid.getAttribute('aria-activedescendant');
      expect(active).toMatch(/-r2$/);
      await userEvent.keyboard('{End}{Enter}');
      expect(activate).toHaveBeenCalledWith(rows[4]);
      await userEvent.keyboard('{Home}{ArrowUp}');
      expect(grid.getAttribute('aria-activedescendant')).toMatch(/-r0$/);
    });

    it('shows the empty message without rows', async () => {
      await render(DataGrid<Row>, {
        inputs: { columns, rows: [], label: 'Collections', emptyMessage: 'No collections' },
      });
      expect(screen.getByRole('gridcell', { name: 'No collections' })).toBeTruthy();
    });
  });
});
