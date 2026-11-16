import { BreakpointObserver } from '@angular/cdk/layout';
import { NgTemplateOutlet } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  signal,
  TemplateRef,
  viewChild,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import {
  NgbDropdown,
  NgbDropdownItem,
  NgbDropdownMenu,
  NgbDropdownToggle,
} from '@ng-bootstrap/ng-bootstrap/dropdown';
import { NgbOffcanvas, NgbOffcanvasRef } from '@ng-bootstrap/ng-bootstrap/offcanvas';
import { NgbTooltip } from '@ng-bootstrap/ng-bootstrap/tooltip';
import { map } from 'rxjs';
import { LOCALES, Locale, pickLocale, switchLocale } from '../core/i18n';
import { Action, PermissionsService } from '../core/permissions.service';
import { SessionService } from '../core/session.service';
import { Density, ThemeMode, ThemeService } from '../core/theme.service';
import { groupLabel } from '../features/placeholder/placeholder.page';
import { Icon, IconName } from '../shared/icon';
import { Logo } from '../shared/logo';

interface NavItem {
  path: string;
  label: string;
  icon: IconName;
  /** Hidden when the user surely lacks it on the cluster (PermissionsService). */
  needs?: Action;
}

/** ≥ 1280 px expanded side nav, 960–1279 rail, < 960 drawer (offcanvas; angular-gui.md §2). */
type Layout = 'full' | 'rail' | 'drawer';

@Component({
  selector: 'rg-shell',
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    NgTemplateOutlet,
    NgbDropdown,
    NgbDropdownToggle,
    NgbDropdownMenu,
    NgbDropdownItem,
    NgbTooltip,
    Icon,
    Logo,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './shell.html',
  styleUrl: './shell.scss',
})
export class Shell {
  protected readonly session = inject(SessionService);
  protected readonly theme = inject(ThemeService);
  private readonly perms = inject(PermissionsService);
  private readonly router = inject(Router);
  private readonly offcanvas = inject(NgbOffcanvas);
  private readonly drawerTpl = viewChild.required<TemplateRef<unknown>>('drawer');
  private drawerRef?: NgbOffcanvasRef;

  protected readonly layout = toSignal(
    inject(BreakpointObserver)
      .observe(['(min-width: 1280px)', '(min-width: 960px)'])
      .pipe(
        map((s): Layout =>
          s.breakpoints['(min-width: 1280px)']
            ? 'full'
            : s.breakpoints['(min-width: 960px)']
              ? 'rail'
              : 'drawer',
        ),
      ),
    { initialValue: 'full' as Layout },
  );
  protected readonly drawerOpen = signal(false);
  protected readonly initial = computed(() =>
    (this.session.user()?.user ?? '?').charAt(0).toUpperCase(),
  );
  protected readonly locale = pickLocale();
  protected readonly locales = LOCALES;
  protected readonly localeNames: Record<Locale, string> = { en: 'English', it: 'Italiano' };

  protected readonly nav = computed<NavItem[]>(() =>
    (
      [
        { path: '/dashboard', label: $localize`:@@nav.dashboard:Dashboard`, icon: 'dashboard' },
        { path: '/data', label: groupLabel('data'), icon: 'data' },
        { path: '/query', label: groupLabel('query'), icon: 'query' },
        { path: '/indexes', label: groupLabel('indexes'), icon: 'indexes' },
        {
          path: '/security',
          label: groupLabel('security'),
          icon: 'security',
          needs: 'user_manage',
        },
        { path: '/backup', label: groupLabel('backup'), icon: 'backup', needs: 'backup' },
        {
          path: '/settings',
          label: groupLabel('settings'),
          icon: 'settings',
          needs: 'cluster_view',
        },
      ] satisfies NavItem[]
    ).filter((i) => !i.needs || this.perms.can(i.needs, 'cluster')),
  );

  protected readonly themes: { value: ThemeMode; label: string; icon: IconName }[] = [
    { value: 'system', label: $localize`:@@theme.system:System theme`, icon: 'monitor' },
    { value: 'light', label: $localize`:@@theme.light:Light theme`, icon: 'sun' },
    { value: 'dark', label: $localize`:@@theme.dark:Dark theme`, icon: 'moon' },
  ];
  protected readonly densities: { value: Density; label: string }[] = [
    { value: 'comfortable', label: $localize`:@@theme.comfortable:Comfortable density` },
    { value: 'compact', label: $localize`:@@theme.compact:Compact density` },
  ];

  protected setLocale(l: Locale): void {
    if (l !== this.locale) switchLocale(l);
  }

  constructor() {
    // Leaving the drawer layout (window widened) closes the drawer.
    effect(() => {
      if (this.layout() !== 'drawer') this.drawerRef?.dismiss();
    });
  }

  protected openDrawer(): void {
    this.drawerRef = this.offcanvas.open(this.drawerTpl(), {
      ariaLabelledBy: 'rg-drawer-title',
      panelClass: 'rg-drawer',
    });
    this.drawerOpen.set(true);
    const closed = () => this.drawerOpen.set(false);
    this.drawerRef.result.then(closed, closed);
  }

  protected navigated(): void {
    this.drawerRef?.dismiss();
  }

  protected focusMain(e: Event): void {
    e.preventDefault();
    document.getElementById('main')?.focus();
  }

  protected async logout(): Promise<void> {
    await this.session.logout();
    await this.router.navigate(['/login']);
  }
}
