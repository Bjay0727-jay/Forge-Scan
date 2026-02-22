import { Hono } from 'hono';
import type { Env } from '../index';
import { queryEvents, publish } from '../services/event-bus';
import { badRequest } from '../lib/errors';

export const events = new Hono<{ Bindings: Env }>();

// ─────────────────────────────────────────────────────────────────────────────
// GET /events — List persisted events with filtering
// ─────────────────────────────────────────────────────────────────────────────
events.get('/', async (c) => {
  const page = parseInt(c.req.query('page') || '1', 10);
  const pageSize = parseInt(c.req.query('page_size') || '50', 10);

  const result = await queryEvents(c.env.DB, {
    event_type: c.req.query('event_type') || undefined,
    source: c.req.query('source') || undefined,
    correlation_id: c.req.query('correlation_id') || undefined,
    since: c.req.query('since') || undefined,
    until: c.req.query('until') || undefined,
    page,
    page_size: pageSize,
  });

  return c.json({
    ...result,
    total_pages: Math.ceil(result.total / result.page_size),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /events/:id — Get single event with subscription execution log
// ─────────────────────────────────────────────────────────────────────────────
events.get('/:id', async (c) => {
  const id = c.req.param('id');

  const event = await c.env.DB
    .prepare('SELECT * FROM forge_events WHERE id = ?')
    .bind(id)
    .first();

  if (!event) {
    return c.json({ error: 'Event not found' }, 404);
  }

  // Get execution log for this event
  const execLog = await c.env.DB
    .prepare(
      `SELECT esl.*, es.name as subscription_name, es.handler_type
       FROM event_subscription_log esl
       JOIN event_subscriptions es ON esl.subscription_id = es.id
       WHERE esl.event_id = ?
       ORDER BY esl.created_at ASC`
    )
    .bind(id)
    .all();

  return c.json({
    ...event,
    payload: typeof event.payload === 'string' ? JSON.parse(event.payload as string) : event.payload,
    metadata: event.metadata ? (typeof event.metadata === 'string' ? JSON.parse(event.metadata as string) : event.metadata) : null,
    subscription_log: execLog.results || [],
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /events/stats — Event statistics
// ─────────────────────────────────────────────────────────────────────────────
events.get('/stats/summary', async (c) => {
  const [eventStats, subStats, recentByType] = await Promise.all([
    c.env.DB
      .prepare(
        `SELECT
          COUNT(*) as total_events,
          SUM(CASE WHEN created_at > datetime('now', '-24 hours') THEN 1 ELSE 0 END) as events_24h,
          SUM(CASE WHEN created_at > datetime('now', '-1 hour') THEN 1 ELSE 0 END) as events_1h
        FROM forge_events`
      )
      .first<{ total_events: number; events_24h: number; events_1h: number }>(),

    c.env.DB
      .prepare(
        `SELECT
          COUNT(*) as total_subscriptions,
          SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_subscriptions
        FROM event_subscriptions`
      )
      .first<{ total_subscriptions: number; active_subscriptions: number }>(),

    c.env.DB
      .prepare(
        `SELECT event_type, COUNT(*) as count
         FROM forge_events
         WHERE created_at > datetime('now', '-24 hours')
         GROUP BY event_type
         ORDER BY count DESC
         LIMIT 10`
      )
      .all<{ event_type: string; count: number }>(),
  ]);

  return c.json({
    total_events: eventStats?.total_events || 0,
    events_24h: eventStats?.events_24h || 0,
    events_1h: eventStats?.events_1h || 0,
    total_subscriptions: subStats?.total_subscriptions || 0,
    active_subscriptions: subStats?.active_subscriptions || 0,
    recent_by_type: recentByType.results || [],
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /events/subscriptions — List event subscriptions
// ─────────────────────────────────────────────────────────────────────────────
events.get('/subscriptions/list', async (c) => {
  const result = await c.env.DB
    .prepare('SELECT * FROM event_subscriptions ORDER BY priority ASC, created_at DESC')
    .all();

  return c.json({ items: result.results || [] });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /events/subscriptions — Create event subscription
// ─────────────────────────────────────────────────────────────────────────────
events.post('/subscriptions', async (c) => {
  const body = await c.req.json();

  if (!body.name || !body.event_pattern || !body.handler_type) {
    throw badRequest('name, event_pattern, and handler_type are required');
  }

  const validTypes = ['notification', 'redops_trigger', 'compliance_check', 'webhook', 'custom'];
  if (!validTypes.includes(body.handler_type)) {
    throw badRequest(`handler_type must be one of: ${validTypes.join(', ')}`);
  }

  const id = crypto.randomUUID();

  await c.env.DB
    .prepare(
      `INSERT INTO event_subscriptions (id, name, event_pattern, handler_type, handler_config, conditions, is_active, priority, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`
    )
    .bind(
      id,
      body.name,
      body.event_pattern,
      body.handler_type,
      body.handler_config ? (typeof body.handler_config === 'string' ? body.handler_config : JSON.stringify(body.handler_config)) : null,
      body.conditions ? (typeof body.conditions === 'string' ? body.conditions : JSON.stringify(body.conditions)) : null,
      body.is_active !== false ? 1 : 0,
      body.priority || 100,
      body.created_by || null
    )
    .run();

  const subscription = await c.env.DB
    .prepare('SELECT * FROM event_subscriptions WHERE id = ?')
    .bind(id)
    .first();

  return c.json(subscription, 201);
});

// ─────────────────────────────────────────────────────────────────────────────
// PUT /events/subscriptions/:id — Update subscription
// ─────────────────────────────────────────────────────────────────────────────
events.put('/subscriptions/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  const existing = await c.env.DB
    .prepare('SELECT * FROM event_subscriptions WHERE id = ?')
    .bind(id)
    .first();

  if (!existing) {
    return c.json({ error: 'Subscription not found' }, 404);
  }

  const fields: string[] = [];
  const values: unknown[] = [];
  const updatable = ['name', 'event_pattern', 'handler_type', 'handler_config', 'conditions', 'is_active', 'priority'];

  for (const field of updatable) {
    if (body[field] !== undefined) {
      const value = typeof body[field] === 'object' ? JSON.stringify(body[field]) : body[field];
      fields.push(`${field} = ?`);
      values.push(value);
    }
  }

  if (fields.length === 0) throw badRequest('No fields to update');

  fields.push("updated_at = datetime('now')");
  values.push(id);

  await c.env.DB
    .prepare(`UPDATE event_subscriptions SET ${fields.join(', ')} WHERE id = ?`)
    .bind(...values)
    .run();

  const updated = await c.env.DB
    .prepare('SELECT * FROM event_subscriptions WHERE id = ?')
    .bind(id)
    .first();

  return c.json(updated);
});

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /events/subscriptions/:id — Delete subscription
// ─────────────────────────────────────────────────────────────────────────────
events.delete('/subscriptions/:id', async (c) => {
  const id = c.req.param('id');

  const result = await c.env.DB
    .prepare('DELETE FROM event_subscriptions WHERE id = ?')
    .bind(id)
    .run();

  if (!result.meta.changes) {
    return c.json({ error: 'Subscription not found' }, 404);
  }

  return c.json({ message: 'Subscription deleted' });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /events/test — Publish a test event (for development/debugging)
// ─────────────────────────────────────────────────────────────────────────────
events.post('/test', async (c) => {
  const body = await c.req.json();

  if (!body.event_type || !body.source) {
    throw badRequest('event_type and source are required');
  }

  const result = await publish(c.env.DB, body.event_type, body.source, body.payload || {}, {
    correlation_id: body.correlation_id,
    metadata: body.metadata,
    sendgridApiKey: c.env.SENDGRID_API_KEY,
  });

  return c.json(result, 201);
});
