import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];

/** 1536 → "1.5 KiB" (binary units, as the server's limits are stated). */
export function formatBytes(bytes: number): string {
  let v = Math.abs(bytes);
  let u = 0;
  while (v >= 1024 && u < UNITS.length - 1) {
    v /= 1024;
    u++;
  }
  const n = u === 0 || v >= 100 ? Math.round(v).toString() : v.toFixed(1);
  return `${bytes < 0 ? '-' : ''}${n} ${UNITS[u]}`;
}

/** 35 → "35 ms", 1250 → "1.3 s", 125000 → "2 min 5 s", 7_200_000 → "2 h 0 min". */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  const s = Math.round(ms / 1000);
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
}

/** Byte count, exact value in the tooltip. */
@Component({
  selector: 'rg-bytes',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<span [title]="value() + ' B'">{{ text() }}</span>`,
})
export class Bytes {
  readonly value = input.required<number>();
  protected readonly text = computed(() => formatBytes(this.value()));
}

/** Duration given in milliseconds. */
@Component({
  selector: 'rg-duration',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<span [title]="ms() + ' ms'">{{ text() }}</span>`,
})
export class Duration {
  readonly ms = input.required<number>();
  protected readonly text = computed(() => formatDuration(this.ms()));
}
