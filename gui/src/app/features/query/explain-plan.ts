import { DecimalPipe, NgTemplateOutlet } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Icon, IconName } from '../../shared/icon';

/** A node of explain format 1 (query-language.md §5.1). */
export interface PlanNode {
  op: string;
  detail: string;
  index: string | null;
  est_rows: number | null;
  actual_rows?: number;
  batches?: number;
  time_ms?: number | null;
  children: PlanNode[];
}

/** The explain row (query-language.md §5.1). */
export interface ExplainRow {
  explain_format: number;
  statement: string;
  analyze: boolean;
  indexes_used: string[];
  est_cost: number | null;
  plan: PlanNode;
  execution: { rows: number; affected: number; time_ms: number; warnings: number } | null;
}

export interface IndexSuggestion {
  db: string;
  coll: string;
  fields: string[];
}

/**
 * "Create suggested index" for a collection scan (§4 S10): the scanned collection (detail
 * `CollectionScan db.coll`) and the fields compared in the nearest `Filter` above it.
 * shortcut: a text heuristic over `detail`; replace with the advisor endpoint when it exists (PD-126).
 */
export function suggestIndex(scan: PlanNode, filter: PlanNode | undefined): IndexSuggestion | null {
  const m = /^CollectionScan\s+([^.\s]+)\.(\S+)/.exec(scan.detail);
  if (!m) return null;
  const fields = new Set<string>();
  const text = (filter?.detail ?? '').replace(/'(?:[^']|'')*'/g, "''");
  for (const f of text.matchAll(
    /([A-Za-z_][A-Za-z0-9_.]*)\s*(?:==?|!=|<=?|>=?|\bIN\b|\bLIKE\b|\bBETWEEN\b|\bCONTAINS\b)/gi,
  ))
    fields.add(f[1]);
  return { db: m[1], coll: m[2], fields: [...fields] };
}

interface Row {
  node: PlanNode;
  suggestion: IndexSuggestion | null;
  /** Share of the slowest stage's time, 0–100 (EXPLAIN ANALYZE only). */
  share: number | null;
}

/** Glyph of an operator (decorative; the operator name is always shown as text). */
function glyph(op: string): IconName {
  if (op === 'CollectionScan') return 'warning';
  if (op.includes('Index')) return 'key';
  if (op === 'Filter') return 'settings';
  if (op === 'Sort') return 'indexes';
  return 'chevronRight';
}

/** S10 explain viewer: summary tiles and the operator pipeline (outermost first), scans flagged. */
@Component({
  selector: 'rg-explain-plan',
  imports: [DecimalPipe, Icon, NgTemplateOutlet, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @let p = plan();
    <dl class="rg-plan-summary">
      <div class="rg-plan-wide">
        <dt i18n="@@explain.statement">Statement</dt>
        <dd>{{ p.statement }}</dd>
      </div>
      <div class="rg-plan-span">
        <dt i18n="@@explain.indexes">Indexes used</dt>
        <dd>
          @if (p.indexes_used.length) {
            {{ p.indexes_used.join(', ') }}
          } @else {
            <ng-container i18n="@@explain.noIndexes">none</ng-container>
          }
        </dd>
      </div>
      <div>
        <dt i18n="@@explain.cost">Estimated cost</dt>
        <dd>{{ p.est_cost === null ? '–' : (p.est_cost | number: '1.0-2') }}</dd>
      </div>
      @if (p.execution; as x) {
        <div>
          <dt i18n="@@explain.rows">Rows returned</dt>
          <dd>{{ x.rows | number }}</dd>
        </div>
        <div>
          <dt i18n="@@explain.affected">Documents written</dt>
          <dd>{{ x.affected | number }}</dd>
        </div>
        <div>
          <dt i18n="@@explain.time">Time</dt>
          <dd>{{ x.time_ms | number: '1.0-3' }} ms</dd>
        </div>
        <div>
          <dt i18n="@@explain.warnings">Warnings</dt>
          <dd>{{ x.warnings | number }}</dd>
        </div>
      }
    </dl>
    <ul class="rg-plan-tree" i18n-aria-label="@@explain.tree" aria-label="Plan operators">
      <ng-container *ngTemplateOutlet="nodeTpl; context: { $implicit: root() }" />
    </ul>
    <ng-template #nodeTpl let-row>
      <li>
        <div
          class="rg-plan-node"
          [class.rg-scan]="row.node.op === 'CollectionScan'"
          [class.rg-indexed]="row.node.index"
        >
          <span class="rg-plan-glyph"><rg-icon [name]="glyph(row.node.op)" [size]="18" /></span>
          <div class="rg-plan-body">
            <div class="rg-plan-head">
              <strong>{{ row.node.op }}</strong>
              <code>{{ row.node.detail }}</code>
            </div>
            <div class="rg-plan-badges">
              @if (row.node.index) {
                <span
                  ><ng-container i18n="@@explain.index">index</ng-container>
                  {{ row.node.index }}</span
                >
              }
              <span
                ><ng-container i18n="@@explain.estRows">est. rows</ng-container>
                {{ row.node.est_rows === null ? '–' : (row.node.est_rows | number: '1.0-1') }}</span
              >
              @if (row.node.actual_rows !== undefined) {
                <span
                  ><ng-container i18n="@@explain.actualRows">actual rows</ng-container>
                  {{ row.node.actual_rows | number }}</span
                >
                <span>{{ row.node.time_ms ?? 0 | number: '1.0-3' }} ms</span>
              }
            </div>
            @if (row.share !== null) {
              <div class="rg-plan-bar" aria-hidden="true">
                <span [style.width.%]="row.share"></span>
              </div>
            }
            @if (row.node.op === 'CollectionScan') {
              <div class="rg-plan-warn">
                <rg-icon name="warning" [size]="18" />
                <span i18n="@@explain.collScan">Collection scan: every document is read</span>
                @if (row.suggestion; as s) {
                  <a
                    class="btn btn-glass btn-sm"
                    routerLink="/indexes"
                    [queryParams]="{ db: s.db, coll: s.coll, fields: s.fields.join(',') || null }"
                    ><rg-icon name="add" [size]="16" /><span i18n="@@explain.suggest"
                      >Create suggested index</span
                    ></a
                  >
                }
              </div>
            }
          </div>
        </div>
        @if (row.children.length) {
          <ul>
            @for (c of row.children; track $index) {
              <ng-container *ngTemplateOutlet="nodeTpl; context: { $implicit: c }" />
            }
          </ul>
        }
      </li>
    </ng-template>
  `,
})
export class ExplainPlan {
  readonly plan = input.required<ExplainRow>();

  /** The tree with the suggestion of each collection scan precomputed. */
  protected readonly root = computed(() => {
    const plan = this.plan().plan;
    return build(plan, undefined, maxTime(plan));
  });
  protected readonly glyph = glyph;
}

function maxTime(node: PlanNode): number {
  return Math.max(node.time_ms ?? 0, ...(node.children ?? []).map(maxTime));
}

type TreeRow = Row & { children: TreeRow[] };

function build(node: PlanNode, filter: PlanNode | undefined, max: number): TreeRow {
  const f = node.op === 'Filter' ? node : filter;
  return {
    node,
    suggestion: node.op === 'CollectionScan' ? suggestIndex(node, f) : null,
    share: node.time_ms != null && max > 0 ? (node.time_ms / max) * 100 : null,
    children: (node.children ?? []).map((c) => build(c, f, max)),
  };
}
