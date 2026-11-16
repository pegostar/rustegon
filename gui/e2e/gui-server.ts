import { readFileSync, existsSync, statSync } from 'node:fs';
import { createServer, IncomingMessage, request, Server, ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';
import { extname, join, normalize, resolve, sep } from 'node:path';

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
};

/**
 * Stand-in for rustegond's own /ui (lane SG, ADR-027) until it lands: serves `dist/` under
 * /ui/ with the SPA fallback and forwards /api/ to rustegond, so the browser sees one origin
 * (rustegond serves plain http, the single-node default, ADR-034). shortcut: plain http on localhost only; drop this file once rustegond serves /ui.
 */
export async function startGuiServer(
  distDir: string,
  api: string,
): Promise<{ url: string; close(): Promise<void> }> {
  const root = resolve(distDir);
  const index = join(root, 'index.html');
  if (!existsSync(index)) throw new Error(`${index} not found: run \`npm run build\` first`);
  const [host, port] = [
    api.slice(0, api.lastIndexOf(':')),
    Number(api.slice(api.lastIndexOf(':') + 1)),
  ];

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      const upstream = request(
        {
          host,
          port,
          method: req.method,
          path: req.url,
          headers: { ...req.headers, host: api },
        },
        (up) => {
          res.writeHead(up.statusCode ?? 502, up.headers);
          up.pipe(res);
        },
      );
      upstream.on('error', (e) => {
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end(`proxy error: ${e.message}`);
      });
      req.pipe(upstream);
      return;
    }
    if (!url.pathname.startsWith('/ui/')) {
      res.writeHead(302, { location: '/ui/' });
      res.end();
      return;
    }
    const file = normalize(join(root, decodeURIComponent(url.pathname.slice('/ui/'.length))));
    const path =
      file.startsWith(root + sep) && existsSync(file) && statSync(file).isFile() ? file : index;
    res.writeHead(200, {
      'content-type': TYPES[extname(path)] ?? 'application/octet-stream',
      'cache-control': 'no-store',
    });
    res.end(readFileSync(path));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port: own } = server.address() as AddressInfo;
  return {
    url: `http://localhost:${own}/ui/`,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
