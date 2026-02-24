import { Hono } from 'hono';
import type { Env } from '../index';
import { requireRole } from '../middleware/auth';

export const audit = new Hono<{ Bindings: Env }>();

// ─────────────────────────────────────────────────────────────────────────────
// GET /audit — Query audit log entries (platform_admin only)
// ─────────────────────────────────────────────────────────────────────────────
audit.get('/', requireRole('platform_admin'), async (c) => {
  const page = parseInt(c.req.query('page') || '1', 10);
  const pageSize = Math.min(parseInt(c.req.query('page_size') || '50', 10), 200);
  const offset = (page - 1) * pageSize;

  const action = c.req.query('action');
  const actor = c.req.query('actor');
  const since = c.req.query('since');
  const until = c.req.query('until');

  let query = "SELECT * FROM forge_events WHERE event_type LIKE 'audit.%'";
  let countQuery = "SELECT COUNT(*) as total FROM forge_events WHERE event_type LIKE 'audit.%'";
  const params: string[] = [];
  const countParams: string[] = [];

  if (action) {
    query += ' AND event_type = ?';
    countQuery += ' AND event_type = ?';
    params.push(`audit.${action}`);
    countParams.push(`audit.${action}`);
  }

  if (actor) {
    query += ' AND payload LIKE ?';
    countQuery += ' AND payload LIKE ?';
    const actorPattern = `%"actor_email":"${actor}"%`;
    params.push(actorPattern);
    countParams.push(actorPattern);
  }

  if (since) {
    query += ' AND created_at >= ?';
    countQuery += ' AND created_at >= ?';
    params.push(since);
    countParams.push(since);
  }

  if (until) {
    query += ' AND created_at <= ?';
    countQuery += ' AND created_at <= ?';
    params.push(until);
    countParams.push(until);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';

  const [result, countResult] = await Promise.all([
    c.env.DB.prepare(query).bind(...params, pageSize, offset).all(),
    c.env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>(),
  ]);

  const total = countResult?.total || 0;

  const items = (result.results || []).map((e: Record<string, unknown>) => ({
    id: e.id,
    action: (e.event_type as string).replace('audit.', ''),
    payload: typeof e.payload === 'string' ? JSON.parse(e.payload as string) : e.payload,
    created_at: e.created_at,
  }));

  return c.json({
    items,
    total,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(total / pageSize),
  });
});
