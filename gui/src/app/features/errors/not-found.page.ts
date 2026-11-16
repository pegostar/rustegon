import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { EmptyState } from '../../shared/empty-state';
import { Icon } from '../../shared/icon';

@Component({
  selector: 'rg-not-found-page',
  imports: [EmptyState, Icon, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="rg-stack rg-stagger">
      <header class="rg-page-header rg-hero">
        <div class="rg-hero-title">
          <span class="rg-page-icon"><rg-icon name="query" /></span>
          <h1 i18n="@@notFound.heading">Page not found</h1>
        </div>
      </header>
      <rg-empty-state
        class="rg-panel"
        icon="warning"
        i18n-heading="@@notFound.title"
        heading="This page does not exist"
        i18n-message="@@notFound.message"
        message="The address may be mistyped or the page was moved."
      >
        <a class="btn btn-primary" routerLink="/dashboard" i18n="@@notFound.home"
          >Go to the dashboard</a
        >
      </rg-empty-state>
    </div>
  `,
})
export class NotFoundPage {}
