import { Hono } from 'hono';
import type { Env } from '../index';
import { requireRole } from '../middleware/auth';
import {
  dispatchToIntegration,
  testIntegration,
  type Integration,
} from '../services/integrations/manager';

interface AuthUser {
  id: string;
  email: string;
  role: string;
  display_name: string;
}

export const integrations = new Hono<{ Bindings: Env; Variables: { user: AuthUser } }>();

// GET /api/v1/integrations - List all integrations
integrations.get('/', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const result = await c.env.DB.prepare(
    'SELECT * FROM integrations ORDER BY created_at DESC'
  ).all<Integration>();

  // Mask sensitive config fields
  const items = (result.results || []).map(i => {
    const config = JSON.parse(i.config);
    // Mask API keys and secrets
    if (config.api_key) config.api_key = '***masked***';
    if (config.secret) config.secret = '***masked***';
    return { ...i, config: JSON.stringify(config) };
  });

  return c.json({ integrations: items });
});

// GET /api/v1/integrations/:id - Get integration detail
integrations.get('/:id', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const id = c.req.param('id');
  const integration = await c.env.DB.prepare(
    'SELECT * FROM integrations WHERE id = ?'
  ).bind(id).first<Integration>();

  if (!integration) {
    return c.json({ error: 'Integration not found' }, 404);
  }

  // Mask sensitive config
  const config = JSON.parse(integration.config);
  if (config.api_key) config.api_key = '***masked***';
  if (config.secret) config.secret = '***masked***';

  return c.json({ ...integration, config: JSON.stringify(config) });
});

// POST /api/v1/integrations - Create an integration
integrations.post('/', requireRole('platform_admin'), async (c) => {
  const body = await c.req.json();
  const user = c.get('user');

  const { name, type, provider, config } = body;

  if (!name || !type || !provider || !config) {
    return c.json({ error: 'name, type, provider, and config are required' }, 400);
  }

  if (!['email', 'webhook'].includes(type)) {
    return c.json({ error: 'type must be email or webhook' }, 400);
  }

  if (type === 'email' && !['sendgrid', 'mailgun'].includes(provider)) {
    return c.json({ error: 'email provider must be sendgrid or mailgun' }, 400);
  }

  // Validate config based on type
  const parsedConfig = typeof config === 'string' ? JSON.parse(config) : config;

  if (type === 'email') {
    if (!parsedConfig.to_addresses || !Array.isArray(parsedConfig.to_addresses) || parsedConfig.to_addresses.length === 0) {
      return c.json({ error: 'Email config requires to_addresses array' }, 400);
    }
  } else if (type === 'webhook') {
    if (!parsedConfig.url) {
      return c.json({ error: 'Webhook config requires url' }, 400);
    }
  }

  const id = crypto.randomUUID();

  await c.env.DB.prepare(`
    INSERT INTO integrations (id, name, type, provider, config, is_active, created_by)
    VALUES (?, ?, ?, ?, ?, 1, ?)
  `).bind(id, name, type, provider, JSON.stringify(parsedConfig), user?.id || null).run();

  return c.json({ id, name, type, provider, message: 'Integration created' }, 201);
});

// PUT /api/v1/integrations/:id - Update an integration
integrations.put('/:id', requireRole('platform_admin'), async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  const existing = await c.env.DB.prepare(
    'SELECT * FROM integrations WHERE id = ?'
  ).bind(id).first<Integration>();

  if (!existing) {
    return c.json({ error: 'Integration not found' }, 404);
  }

  const updates: string[] = [];
  const params: unknown[] = [];

  if (body.name !== undefined) {
    updates.push('name = ?');
    params.push(body.name);
  }
  if (body.config !== undefined) {
    const newConfig = typeof body.config === 'string' ? body.config : JSON.stringify(body.config);
    updates.push('config = ?');
    params.push(newConfig);
  }
  if (body.is_active !== undefined) {
    updates.push('is_active = ?');
    params.push(body.is_active ? 1 : 0);
  }

  if (updates.length === 0) {
    return c.json({ error: 'No updates provided' }, 400);
  }

  updates.push("updated_at = datetime('now')");

  await c.env.DB.prepare(
    `UPDATE integrations SET ${updates.join(', ')} WHERE id = ?`
  ).bind(...params, id).run();

  return c.json({ message: 'Integration updated' });
});

// DELETE /api/v1/integrations/:id - Delete an integration
integrations.delete('/:id', requireRole('platform_admin'), async (c) => {
  const id = c.req.param('id');
  const result = await c.env.DB.prepare('DELETE FROM integrations WHERE id = ?').bind(id).run();

  if (result.meta.changes === 0) {
    return c.json({ error: 'Integration not found' }, 404);
  }

  return c.json({ message: 'Integration deleted' });
});

// POST /api/v1/integrations/:id/test - Test an integration
integrations.post('/:id/test', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const id = c.req.param('id');

  const integration = await c.env.DB.prepare(
    'SELECT * FROM integrations WHERE id = ?'
  ).bind(id).first<Integration>();

  if (!integration) {
    return c.json({ error: 'Integration not found' }, 404);
  }

  const result = await testIntegration(c.env.DB, integration, c.env.SENDGRID_API_KEY);

  return c.json({
    success: result.success,
    status_code: result.status_code,
    error: result.error,
    duration_ms: result.duration_ms,
    message: result.success ? 'Test successful' : 'Test failed',
  });
});

// POST /api/v1/integrations/:id/dispatch - Manually dispatch an event
integrations.post('/:id/dispatch', requireRole('platform_admin'), async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  const { event_type, data } = body;
  if (!event_type) {
    return c.json({ error: 'event_type is required' }, 400);
  }

  const integration = await c.env.DB.prepare(
    'SELECT * FROM integrations WHERE id = ?'
  ).bind(id).first<Integration>();

  if (!integration) {
    return c.json({ error: 'Integration not found' }, 404);
  }

  const result = await dispatchToIntegration(
    c.env.DB, integration, event_type, data || {}, c.env.SENDGRID_API_KEY
  );

  return c.json({
    success: result.success,
    status_code: result.status_code,
    error: result.error,
    duration_ms: result.duration_ms,
  });
});

// GET /api/v1/integrations/:id/logs - Get logs for an integration
integrations.get('/:id/logs', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const id = c.req.param('id');
  const { limit = '50', offset = '0' } = c.req.query();

  const result = await c.env.DB.prepare(
    'SELECT * FROM integration_logs WHERE integration_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ).bind(id, parseInt(limit), parseInt(offset)).all();

  const countResult = await c.env.DB.prepare(
    'SELECT COUNT(*) as total FROM integration_logs WHERE integration_id = ?'
  ).bind(id).first<{ total: number }>();

  return c.json({
    logs: result.results || [],
    total: countResult?.total || 0,
  });
});

// GET /api/v1/integrations/logs/recent - Get recent logs across all integrations
integrations.get('/logs/recent', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const { limit = '50' } = c.req.query();

  const result = await c.env.DB.prepare(`
    SELECT il.*, i.name as integration_name, i.type as integration_type
    FROM integration_logs il
    LEFT JOIN integrations i ON il.integration_id = i.id
    ORDER BY il.created_at DESC
    LIMIT ?
  `).bind(parseInt(limit)).all();

  return c.json({ logs: result.results || [] });
});
