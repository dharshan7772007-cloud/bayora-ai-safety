import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import { apiRouter } from './routes.ts';

dotenv.config();

const app = express();

// 1. CORS Headers & Preflight Handling
app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-bayora-role');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

// 2. Vercel / Serverless body parsing safeguard:
// If the hosting runtime (Vercel, proxy, etc.) already parsed the body or sent a JSON string,
// prevent body-parser from hanging on an already-read request stream.
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.body) {
    if (typeof req.body === 'string') {
      try {
        req.body = JSON.parse(req.body);
        (req as any)._body = true;
      } catch {
        // preserve non-JSON string
      }
    } else if (typeof req.body === 'object') {
      (req as any)._body = true;
    }
  }
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 3. Mount Centralized API Router
app.use('/api', apiRouter);

// 4. API 404 Not Found Handler (only catches unhandled /api/* requests)
app.use('/api', (req: Request, res: Response) => {
  res.status(404).json({
    error: `Endpoint not found: ${req.method} ${req.originalUrl || req.url}`,
    system: 'BAYORA Enclave Policy Gateway',
    availableEndpoints: [
      '/api/state',
      '/api/status',
      '/api/security-tests',
      '/api/security-tests/run',
      '/api/redteam/probe',
      '/api/evaluations',
      '/api/audit/verify',
    ],
  });
});

// 5. Central Error Handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('[BAYORA App Error]:', err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    reason: err.reason || err.message,
  });
});

export { app };
export default app;
