import { CdkVirtualScrollViewport, ScrollingModule } from '@angular/cdk/scrolling';
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';

export interface GridColumn<T> {
  key: string;
  header: string;
  /** Text of the cell; default `String(row[key])`. Always rendered as text. */
  cell?: (row: T) => string;
  /** CSS grid track, default `minmax(120px, 1fr)`. */
  width?: string;
}

let nextId = 0;

/**
 * Virtualized grid (§2 accessibility: `role=grid`, arrow-key row navigation). Focus stays on the
 * grid element and `aria-activedescendant` names the active row, so virtual scrolling can
 * recycle row elements without losing focus. Enter or click emits `rowActivate`.
 */
@Component({
  selector: 'rg-data-grid',
  imports: [ScrollingModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div
      class="rg-grid"
      role="grid"
      tabindex="0"
      [attr.aria-label]="label()"
      [attr.aria-rowcount]="rows().length + 1"
      [attr.aria-colcount]="columns().length"
      [attr.aria-activedescendant]="active() < 0 ? null : rowId(active())"
      [style.--rg-grid-cols]="template()"
      (keydown)="onKey($event)"
      (focus)="onFocus()"
      (click)="onClick($event)"
    >
      <div role="row" class="rg-grid-row rg-grid-head" aria-rowindex="1">
        @for (c of columns(); track c.key) {
          <div role="columnheader">{{ c.header }}</div>
        }
      </div>
      @if (rows().length === 0) {
        <div role="row" class="rg-grid-row" aria-rowindex="2">
          <div role="gridcell" class="rg-grid-empty" [attr.aria-colspan]="columns().length">
            {{ emptyMessage() || noRowsText }}
          </div>
        </div>
      } @else {
        <cdk-virtual-scroll-viewport
          role="rowgroup"
          [itemSize]="rowHeight()"
          [minBufferPx]="rowHeight() * 10"
          [maxBufferPx]="rowHeight() * 20"
          [style.height.px]="height()"
        >
          <div
            *cdkVirtualFor="let row of rows(); let i = index"
            role="row"
            class="rg-grid-row"
            [id]="rowId(i)"
            [attr.data-i]="i"
            [attr.aria-rowindex]="i + 2"
            [class.active]="i === active()"
            [style.height.px]="rowHeight()"
          >
            @for (c of columns(); track c.key) {
              <div role="gridcell">{{ text(row, c) }}</div>
            }
          </div>
        </cdk-virtual-scroll-viewport>
      }
    </div>
  `,
})
export class DataGrid<T extends object> {
  readonly columns = input.required<GridColumn<T>[]>();
  readonly rows = input.required<readonly T[]>();
  /** Accessible name of the grid. */
  readonly label = input.required<string>();
  readonly rowHeight = input(40);
  readonly height = input(400);
  readonly emptyMessage = input('');
  readonly rowActivate = output<T>();

  protected readonly active = signal(-1);
  protected readonly noRowsText = $localize`:@@grid.empty:No rows`;
  protected readonly template = computed(() =>
    this.columns()
      .map((c) => c.width ?? 'minmax(120px, 1fr)')
      .join(' '),
  );
  private readonly viewport = viewChild(CdkVirtualScrollViewport);
  private readonly id = `rg-grid-${nextId++}`;

  protected rowId(i: number): string {
    return `${this.id}-r${i}`;
  }

  protected text(row: T, c: GridColumn<T>): string {
    if (c.cell) return c.cell(row);
    const v = (row as Record<string, unknown>)[c.key];
    return v === undefined || v === null
      ? ''
      : typeof v === 'object'
        ? JSON.stringify(v)
        : String(v);
  }

  protected onFocus(): void {
    if (this.active() < 0 && this.rows().length > 0) this.active.set(0);
  }

  protected onClick(e: MouseEvent): void {
    const row = (e.target as HTMLElement).closest<HTMLElement>('[data-i]');
    if (row) this.activate(Number(row.dataset['i']));
  }

  protected activate(i: number): void {
    this.active.set(i);
    this.rowActivate.emit(this.rows()[i]);
  }

  protected onKey(e: KeyboardEvent): void {
    const n = this.rows().length;
    if (n === 0) return;
    const page = Math.max(1, Math.floor(this.height() / this.rowHeight()) - 1);
    const cur = Math.max(0, this.active());
    const target: Record<string, number> = {
      ArrowDown: cur + 1,
      ArrowUp: cur - 1,
      PageDown: cur + page,
      PageUp: cur - page,
      Home: 0,
      End: n - 1,
    };
    if (e.key === 'Enter' && this.active() >= 0) {
      e.preventDefault();
      this.activate(this.active());
      return;
    }
    const next = target[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const i = Math.min(n - 1, Math.max(0, next));
    this.active.set(i);
    this.viewport()?.scrollToIndex(i);
  }
}
