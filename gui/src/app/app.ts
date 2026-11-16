import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { ThemeService } from './core/theme.service';
import { Toasts } from './shared/toasts';

@Component({
  selector: 'rg-root',
  imports: [RouterOutlet, Toasts],
  template: '<router-outlet /><rg-toasts />',
})
export class App {
  // Instantiated at start so the stored theme applies to the login page too.
  protected readonly theme = inject(ThemeService);
}
