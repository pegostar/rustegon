import { DOCUMENT } from '@angular/common';
import { computed, DestroyRef, effect, inject, Injectable, signal } from '@angular/core';

export type ThemeMode = 'light' | 'dark' | 'system';
export type Density = 'comfortable' | 'compact';

/**
 * Light/dark/system and density (angular-gui.md §1, ADR-033); a per-browser preference.
 * Applies Bootstrap's color mode (`data-bs-theme` on <html>) and the `rg-compact` class.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  readonly mode = signal<ThemeMode>(load('rg.theme', ['light', 'dark', 'system'], 'system'));
  readonly density = signal<Density>(load('rg.density', ['comfortable', 'compact'], 'comfortable'));
  private readonly systemDark = signal(false);
  /** The scheme in effect: `system` follows prefers-color-scheme live. */
  readonly dark = computed(() =>
    this.mode() === 'system' ? this.systemDark() : this.mode() === 'dark',
  );

  constructor() {
    const root = inject(DOCUMENT).documentElement;
    const query = globalThis.matchMedia?.('(prefers-color-scheme: dark)');
    if (query) {
      this.systemDark.set(query.matches);
      const onChange = (e: MediaQueryListEvent) => this.systemDark.set(e.matches);
      query.addEventListener('change', onChange);
      inject(DestroyRef).onDestroy(() => query.removeEventListener('change', onChange));
    }
    effect(() => {
      root.setAttribute('data-bs-theme', this.dark() ? 'dark' : 'light');
      root.classList.toggle('rg-compact', this.density() === 'compact');
      save('rg.theme', this.mode());
      save('rg.density', this.density());
    });
  }
}

function load<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const v = localStorage.getItem(key) as T | null;
    return v && allowed.includes(v) ? v : fallback;
  } catch {
    return fallback;
  }
}

function save(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage blocked: the preference lasts for this page.
  }
}
