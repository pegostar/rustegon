// @ts-check
const eslint = require('@eslint/js');
const tseslint = require('typescript-eslint');
const angular = require('angular-eslint');

module.exports = tseslint.config(
  {
    ignores: [
      'dist/',
      '.angular/',
      'node_modules/',
      'src/app/api/schema.d.ts',
      'test-results/',
      'playwright-report/',
    ],
  },
  {
    files: ['**/*.ts'],
    extends: [
      eslint.configs.recommended,
      ...tseslint.configs.strict,
      ...tseslint.configs.stylistic,
      ...angular.configs.tsRecommended,
    ],
    processor: angular.processInlineTemplates,
    rules: {
      '@typescript-eslint/no-extraneous-class': ['error', { allowWithDecorator: true }],
      '@angular-eslint/directive-selector': [
        'error',
        { type: 'attribute', prefix: 'rg', style: 'camelCase' },
      ],
      '@angular-eslint/component-selector': [
        'error',
        { type: 'element', prefix: 'rg', style: 'kebab-case' },
      ],
    },
  },
  {
    files: ['**/*.html'],
    extends: [...angular.configs.templateRecommended, ...angular.configs.templateAccessibility],
    rules: {
      // <label rgLabel> gets its `for` from the enclosing rg-field (shared/field.ts) at run time.
      '@angular-eslint/template/label-has-associated-control': [
        'error',
        { labelComponents: [{ selector: 'label', inputs: ['for', 'htmlFor', 'rgLabel'] }] },
      ],
    },
  },
  {
    files: ['**/*.js', '**/*.mjs'],
    extends: [eslint.configs.recommended],
    languageOptions: {
      globals: {
        require: 'readonly',
        module: 'writable',
        process: 'readonly',
        console: 'readonly',
        URL: 'readonly',
      },
    },
  },
);
