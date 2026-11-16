import { ChangeDetectionStrategy, Component } from '@angular/core';
import { ApiError } from '../../api/api-error';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';

/** Shown in place of a route the user lacks the privilege for (privilegeGuard, §2 403). */
@Component({
  selector: 'rg-forbidden-page',
  imports: [ErrorPanel, Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="rg-stack rg-stagger">
      <header class="rg-page-header rg-hero">
        <div class="rg-hero-title">
          <span class="rg-page-icon danger"><rg-icon name="security" /></span>
          <h1 i18n="@@forbidden.heading">Access denied</h1>
        </div>
      </header>
      <rg-error-panel [error]="error" />
    </div>
  `,
})
export class ForbiddenPage {
  protected readonly error = new ApiError(
    403,
    4002,
    'PermissionDenied',
    $localize`:@@forbidden.message:Your roles do not grant the privilege this page needs. Ask an administrator for access.`,
    false,
  );
}
