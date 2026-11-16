import { provideZonelessChangeDetection } from '@angular/core';
import { NgbConfig } from '@ng-bootstrap/ng-bootstrap/config';

// ng-bootstrap animations off: jsdom has no CSS transitions, and a modal's delayed removal would
// outlive the test that opened it.
export default [
  provideZonelessChangeDetection(),
  { provide: NgbConfig, useValue: Object.assign(new NgbConfig(), { animation: false }) },
];
