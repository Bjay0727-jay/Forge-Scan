import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { assets } from './routes/assets';
import { findings } from './routes/findings';
import { scans } from './routes/scans';
import { ingest } from './routes/ingest';
import { dashboard } from './routes/dashboard';

export interface Env {
  DB: D1Database;
  STORAGE: R2Bucket;
  CACHE: KVNamespace;
  ENVIRONMENT: string;
  API_VERSION: string;
  CORS_ORIGIN: string;
}

const app = new Hono<{ Bindings: Env }>();

// Middleware
app.use('*', logger());
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));

// Health check
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

// API Routes
app.route('/api/v1/assets', assets);
app.route('/api/v1/findings', findings);
app.route('/api/v1/scans', scans);
app.route('/api/v1/ingest', ingest);
app.route('/api/v1/dashboard', dashboard);

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
