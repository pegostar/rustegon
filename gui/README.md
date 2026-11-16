# Rustegon Console (GUI)

Angular 22 console of Rustegon (F30, FR-GUI-001/002; spec `docs/specifications/angular-gui.md`,
stack ADR-027, component library and theming ADR-033): standalone components, Signals, zoneless,
ng-bootstrap 21 + Bootstrap 5.3 (SCSS) + CDK, "liquid glass" design system. Built to
`dist/` with base href `/ui/`, embedded into `rustegond` and served under `/ui`.

## Commands (Node 24, npm 11)

| Command                | What                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------ |
| `npm ci`               | install from `package-lock.json`                                                           |
| `npm run lint`         | ESLint (angular-eslint, template a11y), stylelint, Prettier, Italian translations complete |
| `npm test`             | API contract check (`scripts/check-api.mjs`) + Vitest unit/component tests                 |
| `npm run build`        | production build into `dist/` + gzip budgets (initial ≤ 350 KB, lazy ≤ 200 KB; PD-134)     |
| `npm run e2e`          | Playwright against a real `rustegond` (needs `npm run build` first)                        |
| `npm run api:gen`      | regenerate `src/app/api/schema.d.ts` from `../api/openapi/rustegon-v1.yaml` (commit it)    |
| `npm run i18n:extract` | write the source messages to `src/locale/messages.json` (for translators; not committed)   |
| `npm start`            | dev server (no API proxy: use the e2e harness or rustegond for a backend)                  |

## E2E harness (`e2e/`)

`global-setup.ts` runs `rustegon init` in a temp directory and starts `rustegond`
(`--stop-on-stdin-eof`, rate limits off) as the driver tests do, then publishes
`RGN_E2E_BASE_URL`, `RGN_E2E_API` and `RGN_E2E_ADMIN_PASSWORD` to the tests.

| Variable           | Meaning                                                                                                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `RUSTEGON_BIN_DIR` | directory with `rustegon` and `rustegond` (default `../target/release`; `cargo build --release -p rustegond -p rustegon-cli`)                                                  |
| `RGN_E2E_SERVE`    | `proxy` (default): `e2e/gui-server.ts` serves `dist/` under `/ui/` and forwards `/api/` to rustegond on one origin; `rustegond`: rustegond serves `/ui` itself (after lane SG) |

`e2e/fixtures.ts`: `test` (with `baseURL`), `go(page, 'dashboard')`, `signIn(page, user, pw)`,
the `admin` fixture (REST client logged in as `admin` with a bearer token) and `createUser(...)`.
Tests run serially on one node; use unique user and database names per test.

## Structure (`src/app`)

- `api/`: `schema.d.ts` (generated, do not edit), `ApiClient` (typed `request(method, path, {path, query, body, timeoutMs})`, `get(...)`, `apiUrl(...)`), `ApiError` (`code`, `label` `RGN-xxxx`, `traceId`, `retryable`, `details`).
- `core/`: `SessionService` (login, logout, `/auth/me`, password change), `http.ts` interceptor (`X-RGN-Timeout-Ms`, error mapping, 401 → `/login?returnUrl=`), CSRF via Angular XSRF (`rgn_csrf` cookie → `X-RGN-CSRF`), `PermissionsService.can(action, on)`, `authGuard`, `privilegeGuard(action, on)`, `NotificationService` (toast, announce), `ThemeService`, `i18n.ts`.
- `shared/`: `rg-field` (`FIELD`: `rgLabel`, `rgControl`, `rg-hint`, `rg-error`), `Dialogs` + `rg-dialog` (NgbModal), `rg-toasts`, `rg-logo`, `rg-empty-state`, `rg-error-panel`, `rg-skeleton`, `rg-confirm-dialog` (`confirm(dialogs, {..., typedConfirmation})`), `rg-status-badge`, `rg-bytes`, `rg-duration`, `rg-code-block`, `rg-data-grid`, `rg-icon`, `rg-json-editor` (`[(value)]`, `label`; Monaco in accessible mode with a plain-text alternative), `loadMonaco()` (`monaco.ts`: lazy, memoized; JSON language; tests replace it through `MONACO_LOADER`).
- `shell/`: glass top bar and side nav (expanded ≥ 1280 px, rail 960–1279, offcanvas drawer below), skip link, landmarks, theme/density/language menu, account menu.
- `features/<group>/`: one lazy route file per screen group (`data`, `query`, `indexes`, `security`, `backup`, `settings`); `login/`, `dashboard/`, `errors/`, `placeholder/`.

## Adding a screen (wave-2 lanes)

1. Replace the placeholder in your `features/<group>/<group>.routes.ts`, e.g.
   `{ path: '', title: () => $localize\`:@@data.title:Databases · Rustegon\`, loadComponent: () => import('./databases.page').then((m) => m.DatabasesPage) }`.
Guard actions with `canActivate: [privilegeGuard('create_database', { db })]`where useful; hide controls with`PermissionsService.can`.
2. Load data with `resource({ loader: () => api.get('/api/v1/databases') })` and render
   `rg-skeleton` / `rg-error-panel` / `rg-empty-state` / data (the four states, §2).
3. Strings: `i18n="@@group.key"` in templates, `$localize\`:@@group.key:Text\``in code — never at
module top level (translations load before bootstrap; route titles are functions). Add the
Italian text to`src/locale/messages.it.json`; `npm run lint` fails on a missing id.
4. Tests: a component test per page (loading, empty, error, data) with a mocked `ApiClient`,
   e2e journeys in `e2e/`, add the route to `ROUTES` in `e2e/a11y.spec.ts` and its endpoints to
   `e2e/coverage-map.json` (AC-GUI-001; an operation the GUI does not use goes under `excluded`
   with its reason, `npm test` checks the map against the OpenAPI document, PD-146).

`rg-data-grid`: `<rg-data-grid [columns]="cols" [rows]="rows" label="Collections" (rowActivate)="open($event)" />`
with `cols: GridColumn<T>[] = [{ key: 'name', header: '…', cell?: (r) => string, width?: '200px' }]`;
virtual scrolling, `role=grid`, arrow keys / Home / End / PageUp / PageDown, Enter or click activates.

## Design system ("liquid glass", ADR-033)

Bootstrap 5.3 markup with ng-bootstrap 21 widgets, skinned by `src/styles/` (no Angular
Material). Light and dark are Bootstrap color modes (`data-bs-theme` on `<html>`, set by
`ThemeService`; `system` follows `prefers-color-scheme`); compact density is the `rg-compact`
class. Partials, in load order: `_bootstrap` (variables + the partials in use), `_tokens`
(`--rg-*` custom properties), `_base` (aurora, type, focus, route transition), `_glass`
(material classes + mixins), `_components` (Bootstrap skins), `_layout` (screen blocks),
`_shared` (UI kit), `_a11y` (guards, last).

**Tokens** (never raw colors in components): text `--rg-text`, `--rg-text-muted`,
`--rg-accent-text`; status `--rg-success|warning|danger|info` (+ `-soft` tints); surfaces
`--rg-glass-fill-subtle|fill|fill-strong|solid`, `--rg-hairline`, `--rg-field-border`,
`--rg-hover`, `--rg-accent-soft|softer`; gradients `--rg-gradient-primary|danger`,
`--rg-heading-gradient`; shape and depth `--rg-radius-sm|radius|radius-lg|radius-xl|radius-pill`,
`--rg-shadow-sm|md|lg`, `--rg-glow`, `--rg-blur`; motion `--rg-dur-fast|dur|dur-slow`,
`--rg-ease`; density `--rg-space`, `--rg-control-h`; type (for `font:`)
`--rg-font-headline-small|title-large|title-medium|title-small|body-small|label-medium`.

**Building a screen** (skeleton):

```html
<header class="rg-page-header">
  <div>
    <h1 i18n="@@x.title">Databases</h1>
    <p class="rg-subtitle" i18n="@@x.subtitle">One sentence.</p>
  </div>
  <div class="rg-actions"><button class="btn btn-primary" type="button">Create</button></div>
</header>
<div class="rg-stack">
  <section class="rg-panel" aria-labelledby="x-h">
    <header>
      <h2 id="x-h">Section</h2>
      <button class="btn btn-glass btn-sm" type="button">Refresh</button>
    </header>
    …
  </section>
  <div class="rg-tiles">
    <section class="rg-panel rg-stat">
      <p class="rg-stat-label">Collections</p>
      <p class="rg-stat-value">12</p>
    </section>
  </div>
</div>
```

`main h1` is drawn with the heading gradient automatically (`.rg-gradient-text` elsewhere).

| Need                  | Use                                                                                                                                                                                      |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Surface / section     | `.rg-panel` (or `.card` + `.card-body`); overlays `.rg-glass-strong`; decoration only `.rg-glass-subtle`; clickable tile `+ .rg-lift`; do not nest panels                                |
| Buttons               | `.btn` + `btn-primary` (one per view), `btn-glass` (secondary), `btn-ghost` (quiet), `btn-danger` / `btn-outline-danger`, `btn-sm`; icon-only `btn-ghost btn-icon` with `aria-label`     |
| Form field            | `imports: [...FIELD]`, then `rg-field` > `label rgLabel`, `input rgControl` (or `select` / `textarea`), `rg-hint`, `@if (…) { rg-error }` (see `features/login/login.page.html`)         |
| Extra description     | `[rgDescribedBy]="'id'"` on the control; never bind `aria-describedby` / `aria-invalid` yourself, `rg-field` owns them                                                                   |
| Checkbox / switch     | `.form-check` (`.form-switch`) with `input.form-check-input` + `label.form-check-label[for]`; several in a row: `.rg-checks`                                                             |
| Single-choice toggle  | `.rg-segmented` radiogroup of `label.btn` > `input[type=radio]` + `span` (see `features/query/query.page.html`)                                                                          |
| Select                | native `select rgControl`; outside reactive forms bind `[selected]` on each `option` (a `[value]` on the select is applied before `@for` options exist)                                  |
| Dialog                | `inject(Dialogs).open<Result>(Component, data, { size: 'lg' })` resolves the result or `undefined`; the component injects `DIALOG_DATA` and `NgbActiveModal`, template `rg-dialog`       |
| Dialog markup         | `<rg-dialog heading="…">body<ng-container rgDialogActions>buttons</ng-container></rg-dialog>`; a dialog form wraps it as `<form class="rg-contents">` (`features/data/create-dialog.ts`) |
| Confirm               | `await confirm(dialogs, { title, message, confirmLabel, typedConfirmation })`                                                                                                            |
| Toast / announcement  | `NotificationService.toast(msg)` (background work only), `.announce(msg)` (screen readers)                                                                                               |
| Menus, tooltips, tabs | `ngbDropdown` (action menus: `role="menu"` on the menu, `role="menuitem"` on items), `ngbTooltip`, `ngbNav class="nav-tabs"` (glass segmented tabs), `ngbPagination`                     |
| Tables                | `rg-data-grid` for data; small static tables `<div class="rg-table"><table class="table table-hover">`                                                                                   |
| Layout helpers        | `dl.rg-kv`, `.rg-toolbar`, `.rg-spacer`, `.rg-stack`, `.rg-tiles`, `.rg-form` / `.rg-form-grid`, `.rg-muted`, `.rg-mono`, Bootstrap utilities (`d-flex`, `gap-2`, `mb-3`, …)             |
| Icons, brand          | `<rg-icon name="add" [size]="18" />` (inline SVG, extend `shared/icon.ts`; no icon fonts), `<rg-logo [size]="40" />`                                                                     |

**Checklist before a screen is done**

- Contrast: text only on `.rg-panel` / `.card` / `.rg-glass*` fills or the page canvas, with the
  text tokens; never on `.rg-glass-subtle` and never on a lighter custom fill. Status-colored
  text (`--rg-danger|success|warning|info`, `rg-error`, `.rg-error`) goes on a glass surface: on
  the bare light canvas it can drop to 3.3:1 where aurora blobs overlap (axe cannot see this, it
  reports the aurora as "incomplete"; worst cases are listed in `src/styles/_tokens.scss`). Check light **and**
  dark; add the route to `ROUTES` in `e2e/a11y.spec.ts` (no critical/serious axe violation).
- Focus: every control reachable with Tab, the global `:focus-visible` ring kept (never remove
  outlines), no keyboard trap; dialogs and the drawer return focus (ng-bootstrap does).
- Reduced transparency, missing `backdrop-filter`, reduced motion and forced colors are handled
  in `_a11y.scss`: build effects from the tokens and mixins, or add the matching guard there.
- No `style="…"` attributes or `[style]` strings; Angular style bindings such as
  `[style.height.px]` are fine (PD-131). No external fonts, CDNs or images (air-gapped servers).
- Component styles stay small (`anyComponentStyle` warns at 6 kB, fails at 10 kB): shared rules
  go in a `src/styles` partial. `npm run build` checks the JS budgets (initial ≤ 350 KB gzip).
- Strings: existing `i18n` ids and texts unchanged; a new id needs its Italian text
  (`npm run lint`).
