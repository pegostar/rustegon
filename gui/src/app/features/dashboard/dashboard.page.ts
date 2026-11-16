import { ChangeDetectionStrategy, Component, inject, resource } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import { EmptyState } from '../../shared/empty-state';
import { ErrorPanel } from '../../shared/error-panel';
import { Icon } from '../../shared/icon';
import { Logo } from '../../shared/logo';
import { Skeleton } from '../../shared/skeleton';
import { StatusBadge } from '../../shared/status-badge';

/**
 * S03 Dashboard, minimal (PD-126): only what the server exposes today (server info, readiness,
 * databases and collections). There is no metrics endpoint yet, so no KPI tiles or charts.
 */
@Component({
  selector: 'rg-dashboard-page',
  imports: [EmptyState, ErrorPanel, Icon, Logo, Skeleton, StatusBadge, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard.page.html',
  styleUrl: './dashboard.page.scss',
})
export class DashboardPage {
  private readonly api = inject(ApiClient);

  protected readonly info = resource({ loader: () => this.api.get('/api/v1/server-info') });
  /** `/health/ready` answers 503 with a status body while not ready: that is data, not an error. */
  protected readonly ready = resource({
    loader: async () => {
      try {
        return (await this.api.get('/api/v1/health/ready')).status;
      } catch (e) {
        const err = ApiError.from(e);
        if (err.status === 503) return 'not_ready';
        throw err;
      }
    },
  });
  protected readonly data = resource({
    loader: async () => {
      const { databases } = await this.api.get('/api/v1/databases');
      const counts = await Promise.all(
        databases.map((d) =>
          this.api
            .get('/api/v1/databases/{db}/collections', { path: { db: d.name } })
            .then((r) => r.collections.length),
        ),
      );
      return { databases: databases.length, collections: counts.reduce((a, b) => a + b, 0) };
    },
  });

  protected refresh(): void {
    this.info.reload();
    this.ready.reload();
    this.data.reload();
  }
}
