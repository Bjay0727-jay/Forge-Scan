import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { authMiddleware } from './middleware/auth';
import { errorHandler } from './middleware/error-handler';
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
import { scanner } from './routes/scanner';
import { integrations } from './routes/integrations';
import { notifications } from './routes/notifications';
import { compliance } from './routes/compliance';
import { redops } from './routes/redops';
import { events } from './routes/events';
import { soc } from './routes/soc';
import { onboarding } from './routes/onboarding';
import { mssp } from './routes/mssp';
import { containers } from './routes/containers';
import { sast } from './routes/sast';
import { soar } from './routes/soar';
import { threatIntel } from './routes/threat-intel';
import { docs } from './routes/docs';
import { registerSOCHandlers } from './services/forgesoc/alert-handler';

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
  ANTHROPIC_API_KEY?: string;
}

const app = new Hono<{ Bindings: Env }>();

// Register ForgeSOC event bus handlers at module load
registerSOCHandlers();

// Middleware
app.use('*', logger());
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Scanner-Key'],
}));

// Health check (public)
app.get('/', (c) => {
  return c.json({
    name: 'ForgeScan API',
    version: c.env.API_VERSION,
    status: 'healthy',
    environment: c.env.ENVIRONMENT,
  });
});

app.get('/health', (c) => {
  return c.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API Documentation (public – no auth required)
app.route('/api/docs', docs);

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
app.route('/api/v1/scanner', scanner);
app.route('/api/v1/integrations', integrations);
app.route('/api/v1/notifications', notifications);
app.route('/api/v1/compliance', compliance);
app.route('/api/v1/redops', redops);
app.route('/api/v1/events', events);
app.route('/api/v1/soc', soc);
app.route('/api/v1/onboarding', onboarding);
app.route('/api/v1/mssp', mssp);
app.route('/api/v1/containers', containers);
app.route('/api/v1/sast', sast);
app.route('/api/v1/soar', soar);
app.route('/api/v1/threat-intel', threatIntel);

// 404 handler
app.notFound((c) => {
  return c.json({
    error: { code: 'NOT_FOUND', message: `Route not found: ${c.req.method} ${c.req.path}` },
  }, 404);
});

// Global error handler – catches ApiError + unexpected errors
app.onError(errorHandler);

export default app;
