// RGQL support for the S09 editor (angular-gui.md §4 S09; grammar query-language.md §2–§4, §11).
type Monaco = typeof import('monaco-editor');

/** Keywords of query-language.md §3, §11, §12 (keywords are case-insensitive). */
// prettier-ignore
export const RGQL_KEYWORDS = [
  'ADD', 'AFTER', 'AGG', 'ALL', 'ALTER', 'ANALYZE', 'ANALYZER', 'AND', 'ANY', 'AS', 'ASC',
  'BEGIN', 'BETWEEN', 'BOOST', 'BY', 'CASE', 'COLLECTION', 'COLLECTIONS', 'COMMIT', 'CONFLICT',
  'CONTAINS', 'CREATE', 'CURRENT', 'DATABASE', 'DATE', 'DELETE', 'DESC', 'DO', 'DROP', 'ELEM',
  'ELSE', 'END', 'EVERY', 'EXPIRE', 'EXPLAIN', 'FALSE', 'FIRST', 'FROM', 'FULLTEXT', 'GEO', 'GROUP',
  'HAVING', 'HIDDEN', 'ILIKE', 'IN', 'INC', 'INCLUDE', 'INDEX', 'INDEXES', 'INSERT', 'INTERVAL',
  'INTO', 'IS', 'ISOLATION', 'KILL', 'LAST', 'LEVEL', 'LIKE', 'LIMIT', 'LOOKUP', 'MATCH', 'MATCHES',
  'MAX', 'MIN', 'MISSING', 'MUL', 'NEW', 'NOT', 'NOTHING', 'NULL', 'OF', 'OFFSET', 'OID', 'OLD',
  'ON', 'ONLY', 'OPTIONS', 'OR', 'ORDER', 'POP', 'PULL', 'PUSH', 'QUERY', 'READ', 'RELEASE',
  'RENAME', 'REPLACE', 'RETURNING', 'ROLLBACK', 'SATISFIES', 'SAVEPOINT', 'SELECT', 'SET', 'SHOW',
  'SYSTEM', 'TABLE', 'THEN', 'TIME', 'TO', 'TRANSACTION', 'TRUE', 'TTL', 'UNIQUE', 'UNSET',
  'UPDATE', 'UPSERT', 'USING', 'UUID', 'VALUE', 'VALUES', 'VECTOR', 'VISIBLE', 'WHEN', 'WHERE',
  'WITH',
];

/** Function catalog of query-language.md §4.2. */
// prettier-ignore
export const RGQL_FUNCTIONS = [
  'type_of', 'is_number', 'is_string', 'to_string', 'to_int', 'to_float', 'to_decimal', 'to_date',
  'to_bool', 'to_oid', 'coalesce', 'if_null', 'abs', 'ceil', 'floor', 'round', 'trunc', 'sqrt',
  'pow', 'exp', 'ln', 'log10', 'mod', 'greatest', 'least', 'length', 'lower', 'upper', 'trim',
  'ltrim', 'rtrim', 'substr', 'index_of', 'replace', 'split', 'concat', 'starts_with', 'ends_with',
  'regex_match', 'regex_extract', 'format', 'now', 'date_trunc', 'date_add', 'date_diff', 'extract',
  'date_format', 'time_bucket', 'size', 'array_contains', 'slice', 'array_concat', 'array_distinct',
  'array_sort', 'array_reverse', 'filter', 'map', 'reduce', 'first', 'last', 'zip', 'range',
  'array_to_object', 'object_to_array', 'keys', 'values', 'merge_objects', 'get_field', 'set_field',
  'unset_field', 'if', 'switch', 'count', 'count_distinct', 'count_distinct_approx', 'sum', 'avg',
  'min', 'max', 'array_agg', 'set_agg', 'percentile', 'stddev_pop', 'stddev_samp', 'var_pop',
  'var_samp', 'top_k', 'search', 'score', 'highlight', 'vector_near', 'vector_distance', 'rrf',
  'geo_within', 'geo_intersects', 'geo_near', 'geo_distance', 'geo_circle', 'geo_box', 'id', 'rev',
  'load', 'counter', 'writetime', 'ttl', 'metadata',
];

/** Database and collection names offered by completion; the page keeps it current. */
export const catalog = { databases: [] as string[], collections: [] as string[] };

let registered = false;

/** Registers the `rgql` language once (Monaco languages are global). */
export function registerRgql(monaco: Monaco): void {
  if (registered) return;
  registered = true;
  monaco.languages.register({ id: 'rgql' });
  monaco.languages.setLanguageConfiguration('rgql', {
    comments: { lineComment: '--', blockComment: ['/*', '*/'] },
    brackets: [
      ['(', ')'],
      ['[', ']'],
      ['{', '}'],
    ],
    autoClosingPairs: [
      { open: '(', close: ')' },
      { open: '[', close: ']' },
      { open: '{', close: '}' },
      { open: "'", close: "'", notIn: ['string'] },
      { open: '`', close: '`', notIn: ['string'] },
    ],
  });
  monaco.languages.setMonarchTokensProvider('rgql', {
    ignoreCase: true,
    keywords: RGQL_KEYWORDS,
    functions: RGQL_FUNCTIONS,
    tokenizer: {
      root: [
        [/--.*$/, 'comment'],
        [/\/\*/, 'comment', '@comment'],
        [/'/, 'string', '@string'],
        [/`/, 'identifier.quote', '@quoted'],
        [/\$[A-Za-z0-9_]+/, 'variable'],
        [/-?\d+(\.\d+)?([eE][-+]?\d+)?m?/, 'number'],
        [
          /[A-Za-z_][A-Za-z0-9_]*/,
          {
            cases: { '@keywords': 'keyword', '@functions': 'predefined', '@default': 'identifier' },
          },
        ],
        [/\|>|[=!<>]=?|==|\|\||->|[-+*/%]/, 'operator'],
        [/[()[\]{}]/, '@brackets'],
      ],
      comment: [
        [/\*\//, 'comment', '@pop'],
        [/./, 'comment'],
      ],
      string: [
        [/''/, 'string.escape'],
        [/\\./, 'string.escape'],
        [/'/, 'string', '@pop'],
        [/[^'\\]+/, 'string'],
      ],
      quoted: [
        [/``/, 'identifier.quote'],
        [/`/, 'identifier.quote', '@pop'],
        [/[^`]+/, 'identifier'],
      ],
    },
  });
  monaco.languages.registerCompletionItemProvider('rgql', {
    provideCompletionItems: (model, position) => {
      const word = model.getWordUntilPosition(position);
      const range = new monaco.Range(
        position.lineNumber,
        word.startColumn,
        position.lineNumber,
        word.endColumn,
      );
      const K = monaco.languages.CompletionItemKind;
      const item = (label: string, kind: number, insertText = label) => ({
        label,
        kind,
        insertText,
        range,
      });
      return {
        suggestions: [
          ...RGQL_KEYWORDS.map((k) => item(k, K.Keyword)),
          ...RGQL_FUNCTIONS.map((f) => item(f, K.Function, `${f}(`)),
          ...catalog.databases.map((d) => item(d, K.Module, quoteIdent(d))),
          ...catalog.collections.map((c) => item(c, K.Class, quoteIdent(c))),
        ],
      };
    },
  });
}

/** Identifiers outside `[A-Za-z_][A-Za-z0-9_]*` are back-quoted (query-language.md §2). */
export function quoteIdent(name: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : `\`${name.replaceAll('`', '``')}\``;
}

/** Statements the spec asks to confirm (§4 S09): DROP, and DELETE/UPDATE without WHERE. */
export function isDangerous(text: string): boolean {
  const code = text
    .replace(/--.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/'(?:[^']|'')*'/g, "''")
    .trim();
  if (/^drop\b/i.test(code)) return true;
  return /^(delete|update)\b/i.test(code) && !/\bwhere\b/i.test(code);
}

/** Line/column (1-based) of an `RGN-1010` syntax error, from its `line`/`column` details. */
export function syntaxPosition(
  details: Readonly<Record<string, string>>,
): { line: number; column: number } | null {
  const line = Number(details['line']);
  const column = Number(details['column']);
  return line > 0 && column > 0 ? { line, column } : null;
}

/** CSV of rows (RFC 4180 quoting); nested values as JSON. */
export function toCsv(columns: string[], rows: unknown[]): string {
  const esc = (s: string) => (/[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s);
  const lines = [columns.map(esc).join(',')];
  for (const r of rows) lines.push(columns.map((c) => esc(cellText(field(r, c)))).join(','));
  return lines.join('\r\n');
}

/** Column `value` stands for non-object rows (`SELECT VALUE`). */
export function field(row: unknown, column: string): unknown {
  if (row !== null && typeof row === 'object' && !Array.isArray(row))
    return (row as Record<string, unknown>)[column];
  return column === 'value' ? row : undefined;
}

export function cellText(v: unknown): string {
  if (v === undefined) return '';
  return typeof v === 'string' ? v : JSON.stringify(v);
}

/** Result columns: the top-level fields of the first rows, in first-seen order. */
export function columnsOf(rows: unknown[], max = 50): string[] {
  const cols = new Set<string>();
  for (const r of rows.slice(0, 200)) {
    if (r !== null && typeof r === 'object' && !Array.isArray(r)) {
      for (const k of Object.keys(r)) if (cols.size < max) cols.add(k);
    } else cols.add('value');
  }
  return [...cols];
}
