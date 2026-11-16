import { ChangeDetectionStrategy, Component, inject, resource, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap/modal';
import { ApiClient } from '../../api/api-client';
import { ApiError } from '../../api/api-error';
import type { components } from '../../api/schema';
import { Dialog, DIALOG_DATA } from '../../shared/dialog';
import { ErrorPanel } from '../../shared/error-panel';
import { JsonEditor } from '../../shared/json-editor';
import { Skeleton } from '../../shared/skeleton';
import { FIELD } from '../../shared/field';

type Level = components['schemas']['ValidationLevelName'];
type ActionName = components['schemas']['ValidationActionName'];

const EXAMPLE = '{\n  "$jsonSchema": {\n    "type": "object",\n    "required": []\n  }\n}';

/** Collection validator (S06 "validator editor"; `GET/PUT/DELETE …/validator`). */
@Component({
  selector: 'rg-validator-dialog',
  imports: [...FIELD, Dialog, FormsModule, ErrorPanel, JsonEditor, Skeleton],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <rg-dialog i18n-heading="@@data.validator.title" heading="Validator of {{ data.coll }}">
      <rg-skeleton [loading]="current.isLoading()">
        @if (current.error(); as e) {
          <rg-error-panel [error]="e" (retry)="current.reload()" />
        } @else {
          <rg-json-editor
            [(value)]="text"
            i18n-label="@@data.validator.definition"
            label="JSON Schema definition"
            [height]="260"
            describedBy="rg-validator-error"
            [invalid]="!!error()"
          />
          <div class="rg-form-grid mt-3">
            <rg-field>
              <label rgLabel i18n="@@data.validator.level">Validation level</label>
              <select rgControl [(ngModel)]="level">
                <option value="strict">strict</option>
                <option value="moderate">moderate</option>
                <option value="off">off</option>
              </select>
            </rg-field>
            <rg-field>
              <label rgLabel i18n="@@data.validator.action">Validation action</label>
              <select rgControl [(ngModel)]="action">
                <option value="error">error</option>
                <option value="warn">warn</option>
              </select>
            </rg-field>
          </div>
        }
      </rg-skeleton>
      <div id="rg-validator-error" role="alert" class="rg-error">{{ error() }}</div>
      <ng-container rgDialogActions>
        <button
          class="btn btn-glass"
          type="button"
          (click)="modal.dismiss()"
          i18n="@@data.create.cancel"
        >
          Cancel
        </button>
        @if (current.value()) {
          <button
            class="btn btn-outline-danger"
            type="button"
            [disabled]="busy()"
            (click)="remove()"
            i18n="@@data.validator.remove"
          >
            Remove validator
          </button>
        }
        <button
          class="btn btn-primary"
          type="button"
          [disabled]="busy()"
          (click)="save()"
          i18n="@@data.validator.save"
        >
          Save validator
        </button>
      </ng-container>
    </rg-dialog>
  `,
})
export class ValidatorDialog {
  protected readonly data = inject(DIALOG_DATA) as { db: string; coll: string };
  protected readonly modal = inject(NgbActiveModal);
  private readonly api = inject(ApiClient);
  protected readonly text = signal(EXAMPLE);
  protected level: Level = 'strict';
  protected action: ActionName = 'error';
  protected readonly busy = signal(false);
  protected readonly error = signal('');

  protected readonly current = resource({
    loader: async () => {
      const { validator } = await this.api.get(
        '/api/v1/databases/{db}/collections/{coll}/validator',
        {
          path: this.data,
        },
      );
      if (validator) {
        this.text.set(JSON.stringify(validator.definition, null, 2));
        this.level = validator.level ?? 'strict';
        this.action = validator.action ?? 'error';
      }
      return validator ?? null;
    },
  });

  protected async save(): Promise<void> {
    let definition: Record<string, never>;
    try {
      definition = JSON.parse(this.text()) as Record<string, never>;
    } catch (e) {
      this.error.set($localize`:@@data.json.syntax:Invalid JSON: ${(e as Error).message}:message:`);
      return;
    }
    await this.run(() =>
      this.api.request('put', '/api/v1/databases/{db}/collections/{coll}/validator', {
        path: this.data,
        body: { definition, level: this.level, action: this.action },
      }),
    );
  }

  protected remove(): Promise<void> {
    return this.run(() =>
      this.api.request('delete', '/api/v1/databases/{db}/collections/{coll}/validator', {
        path: this.data,
      }),
    );
  }

  private async run(call: () => Promise<unknown>): Promise<void> {
    this.busy.set(true);
    this.error.set('');
    try {
      await call();
      this.modal.close(true);
    } catch (e) {
      const err = ApiError.from(e);
      this.error.set(`${err.label} ${err.message}`.trim());
    } finally {
      this.busy.set(false);
    }
  }
}
