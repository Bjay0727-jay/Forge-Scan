import { Hono } from 'hono';
import type { Env } from '../index';
import { requireRole } from '../middleware/auth';
import { emitEvent, getNotificationStats } from '../services/notifications/engine';

interface AuthUser {
  id: string; email: string; role: string; display_name: string;
}

export const notifications = new Hono<{ Bindings: Env; Variables: { user: AuthUser } }>();

// GET /stats - Get notification statistics
notifications.get('/stats', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const stats = await getNotificationStats(c.env.DB);
  return c.json(stats);
});

// GET / - List notification rules
notifications.get('/', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const result = await c.env.DB.prepare(`
    SELECT nr.*, i.name as integration_name, i.type as integration_type
    FROM notification_rules nr
    LEFT JOIN integrations i ON nr.integration_id = i.id
    ORDER BY nr.created_at DESC
  `).all();
  return c.json({ rules: result.results || [] });
});

// POST / - Create notification rule
notifications.post('/', requireRole('platform_admin'), async (c) => {
  const body = await c.req.json();
  const user = c.get('user');
  const { name, event_type, conditions, integration_id, template } = body;

  if (!name || !event_type || !integration_id) {
    return c.json({ error: 'name, event_type, and integration_id are required' }, 400);
  }

  const validEvents = ['scan.completed', 'scan.failed', 'finding.critical', 'finding.high', 'finding.detected', 'nvd.sync_completed', 'report.generated'];
  if (!validEvents.includes(event_type)) {
    return c.json({ error: `Invalid event_type. Valid: ${validEvents.join(', ')}` }, 400);
  }

  // Verify integration exists
  const integration = await c.env.DB.prepare('SELECT id FROM integrations WHERE id = ?').bind(integration_id).first();
  if (!integration) {
    return c.json({ error: 'Integration not found' }, 404);
  }

  const id = crypto.randomUUID();
  await c.env.DB.prepare(`
    INSERT INTO notification_rules (id, name, event_type, conditions, integration_id, template, is_active, created_by)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
  `).bind(id, name, event_type, JSON.stringify(conditions || {}), integration_id, template || null, user?.id || null).run();

  return c.json({ id, name, event_type, message: 'Notification rule created' }, 201);
});

// PUT /:id - Update notification rule
notifications.put('/:id', requireRole('platform_admin'), async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  const updates: string[] = [];
  const params: unknown[] = [];

  if (body.name !== undefined) { updates.push('name = ?'); params.push(body.name); }
  if (body.event_type !== undefined) { updates.push('event_type = ?'); params.push(body.event_type); }
  if (body.conditions !== undefined) { updates.push('conditions = ?'); params.push(JSON.stringify(body.conditions)); }
  if (body.integration_id !== undefined) { updates.push('integration_id = ?'); params.push(body.integration_id); }
  if (body.template !== undefined) { updates.push('template = ?'); params.push(body.template); }
  if (body.is_active !== undefined) { updates.push('is_active = ?'); params.push(body.is_active ? 1 : 0); }

  if (updates.length === 0) return c.json({ error: 'No updates provided' }, 400);
  updates.push("updated_at = datetime('now')");

  await c.env.DB.prepare(`UPDATE notification_rules SET ${updates.join(', ')} WHERE id = ?`).bind(...params, id).run();
  return c.json({ message: 'Rule updated' });
});

// DELETE /:id - Delete notification rule
notifications.delete('/:id', requireRole('platform_admin'), async (c) => {
  const id = c.req.param('id');
  const result = await c.env.DB.prepare('DELETE FROM notification_rules WHERE id = ?').bind(id).run();
  if (result.meta.changes === 0) return c.json({ error: 'Rule not found' }, 404);
  return c.json({ message: 'Rule deleted' });
});

// POST /:id/test - Test a notification rule by emitting a test event
notifications.post('/:id/test', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const id = c.req.param('id');
  const rule = await c.env.DB.prepare('SELECT * FROM notification_rules WHERE id = ?').bind(id).first();
  if (!rule) return c.json({ error: 'Rule not found' }, 404);

  const result = await emitEvent(c.env.DB, {
    event_type: rule.event_type as string,
    data: {
      title: 'Test notification',
      message: `This is a test of the "${rule.name}" notification rule`,
      severity: 'high',
      scan_name: 'Test Scan',
      findings_count: 42,
      test: true,
    },
  }, c.env.SENDGRID_API_KEY);

  return c.json({ ...result, message: result.sent > 0 ? 'Test sent' : 'No notifications dispatched' });
});

// GET /log - View notification log
notifications.get('/log', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const { limit = '50', offset = '0', rule_id, event_type } = c.req.query();
  let query = 'SELECT nl.*, nr.name as rule_name FROM notification_log nl LEFT JOIN notification_rules nr ON nl.rule_id = nr.id WHERE 1=1';
  const params: unknown[] = [];

  if (rule_id) { query += ' AND nl.rule_id = ?'; params.push(rule_id); }
  if (event_type) { query += ' AND nl.event_type = ?'; params.push(event_type); }

  query += ' ORDER BY nl.created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit as string), parseInt(offset as string));

  const result = await c.env.DB.prepare(query).bind(...params).all();
  return c.json({ logs: result.results || [] });
});
