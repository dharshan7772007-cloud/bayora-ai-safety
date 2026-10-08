import type { IncomingMessage, ServerResponse } from 'http';
import app from '../server/app.ts';

export default function handler(req: IncomingMessage, res: ServerResponse) {
  const request = req as any;

  // Extract raw path and query string
  const rawUrl = request.url || '/';
  const [pathname, queryString] = rawUrl.split('?');
  const qs = queryString ? `?${queryString}` : '';

  // Check Vercel-injected headers for rewritten paths
  const matchedPath =
    (request.headers['x-matched-path'] as string) ||
    (request.headers['x-forwarded-uri'] as string) ||
    (request.headers['x-invoke-path'] as string);

  if (matchedPath && matchedPath !== '/api' && matchedPath !== '/') {
    request.url = (matchedPath.startsWith('/api') ? matchedPath : `/api${matchedPath}`) + qs;
  } else if (request.query && request.query.slug) {
    const slugVal = Array.isArray(request.query.slug) ? request.query.slug.join('/') : request.query.slug;
    const cleanSlug = String(slugVal).replace(/^\/+/, '');
    request.url = `/api/${cleanSlug}` + qs;
  } else if (!pathname.startsWith('/api')) {
    request.url = `/api${pathname}` + qs;
  }

  return app(request, res as any);
}

export { app };
