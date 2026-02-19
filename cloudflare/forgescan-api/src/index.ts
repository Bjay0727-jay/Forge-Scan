import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { authMiddleware } from './middleware/auth';
import { auth } from './routes/auth';
import { assets } from './routes/assets';
import { findings } from './routes/findings';
import { scans } from './routes/scans';
import { ingest } from './routes/ingest';
import { dashboard } from './routes/dashboard';
import { reports } from './routes/reports';
import { exports } from './routes/exports';
import { vulnerabilities } from './routes/vulnerabilities';
import { importRoutes } from './routes/import';

export interface Env {
  DB: D1Database;
  STORAGE: R2Bucket;
  CACHE: KVNamespace;
  ENVIRONMENT: string;
  API_VERSION: string;
  CORS_ORIGIN: string;
  JWT_SECRET: string;
  NVD_API_KEY?: string;
  SENDGRID_API_KEY?: string;
}

const app = new Hono<{ Bindings: Env }>();

// Middleware
app.use('*', logger());
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));

// Health check (public)
app.get('/', (c) => {
  return c.json({
    name: 'ForgeScan 360 API',
    version: c.env.API_VERSION,
    status: 'healthy',
    environment: c.env.ENVIRONMENT,
  });
});

app.get('/health', (c) => {
  return c.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Auth middleware for all /api/v1/* routes (skips public paths internally)
app.use('/api/v1/*', authMiddleware);

// Auth routes (login/register are public, others require auth)
app.route('/api/v1/auth', auth);

// Protected API Routes
app.route('/api/v1/assets', assets);
app.route('/api/v1/findings', findings);
app.route('/api/v1/scans', scans);
app.route('/api/v1/ingest', ingest);
app.route('/api/v1/dashboard', dashboard);
app.route('/api/v1/reports', reports);
app.route('/api/v1/exports', exports);
app.route('/api/v1/vulnerabilities', vulnerabilities);
app.route('/api/v1/import', importRoutes);

// 404 handler
app.notFound((c) => {
  return c.json({ error: 'Not Found', path: c.req.path }, 404);
});

// Error handler
app.onError((err, c) => {
  console.error('Error:', err);
  return c.json({ error: 'Internal Server Error', message: err.message }, 500);
});

export default app;
