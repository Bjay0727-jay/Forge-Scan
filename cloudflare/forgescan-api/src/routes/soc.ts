// ─────────────────────────────────────────────────────────────────────────────
// ForgeSOC Routes — Security Operations Center API
// ─────────────────────────────────────────────────────────────────────────────

import { Hono } from 'hono';
import type { Env } from '../index';
import { badRequest } from '../lib/errors';

export const soc = new Hono<{ Bindings: Env }>();

// ─────────────────────────────────────────────────────────────────────────────
// GET /soc/overview — SOC dashboard overview
// ─────────────────────────────────────────────────────────────────────────────
soc.get('/overview', async (c) => {
  const [alertStats, incidentStats, severityBreakdown, recentAlerts, activeIncidents] = await Promise.all([
    c.env.DB
      .prepare(
        `SELECT
          COUNT(*) as total_alerts,
          SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new_alerts,
          SUM(CASE WHEN status IN ('triaged', 'investigating', 'escalated') THEN 1 ELSE 0 END) as active_alerts,
          SUM(CASE WHEN status IN ('resolved', 'closed', 'false_positive') THEN 1 ELSE 0 END) as resolved_alerts,
          SUM(CASE WHEN created_at > datetime('now', '-24 hours') THEN 1 ELSE 0 END) as alerts_24h
        FROM soc_alerts`
      )
      .first<{ total_alerts: number; new_alerts: number; active_alerts: number; resolved_alerts: number; alerts_24h: number }>(),

    c.env.DB
      .prepare(
        `SELECT
          COUNT(*) as total_incidents,
          SUM(CASE WHEN status IN ('open', 'investigating', 'containment') THEN 1 ELSE 0 END) as active_incidents,
          SUM(CASE WHEN status IN ('closed', 'post_incident') THEN 1 ELSE 0 END) as closed_incidents
        FROM soc_incidents`
      )
      .first<{ total_incidents: number; active_incidents: number; closed_incidents: number }>(),

    c.env.DB
      .prepare(
        `SELECT severity, COUNT(*) as count
         FROM soc_alerts
         WHERE status NOT IN ('closed', 'false_positive')
         GROUP BY severity
         ORDER BY CASE severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2
           WHEN 'medium' THEN 3 WHEN 'low' THEN 4
           WHEN 'info' THEN 5 END`
      )
      .all<{ severity: string; count: number }>(),

    c.env.DB
      .prepare(
        `SELECT id, title, severity, status, source, alert_type, created_at
         FROM soc_alerts
         ORDER BY created_at DESC
         LIMIT 10`
      )
      .all(),

    c.env.DB
      .prepare(
        `SELECT id, title, severity, status, priority, alert_count, created_at
         FROM soc_incidents
         WHERE status NOT IN ('closed', 'post_incident')
         ORDER BY priority ASC, created_at DESC
         LIMIT 5`
      )
      .all(),
  ]);

  return c.json({
    alerts: {
      total: alertStats?.total_alerts || 0,
      new: alertStats?.new_alerts || 0,
      active: alertStats?.active_alerts || 0,
      resolved: alertStats?.resolved_alerts || 0,
      last_24h: alertStats?.alerts_24h || 0,
    },
    incidents: {
      total: incidentStats?.total_incidents || 0,
      active: incidentStats?.active_incidents || 0,
      closed: incidentStats?.closed_incidents || 0,
    },
    severity_breakdown: severityBreakdown.results || [],
    recent_alerts: recentAlerts.results || [],
    active_incidents: activeIncidents.results || [],
    generated_at: new Date().toISOString(),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /soc/alerts — List alerts with filtering
// ─────────────────────────────────────────────────────────────────────────────
soc.get('/alerts', async (c) => {
  const page = parseInt(c.req.query('page') || '1', 10);
  const pageSize = Math.min(parseInt(c.req.query('page_size') || '25', 10), 100);

  let where = 'WHERE 1=1';
  const params: unknown[] = [];

  const severity = c.req.query('severity');
  if (severity) {
    where += ' AND severity = ?';
    params.push(severity);
  }

  const status = c.req.query('status');
  if (status) {
    where += ' AND status = ?';
    params.push(status);
  }

  const alertType = c.req.query('alert_type');
  if (alertType) {
    where += ' AND alert_type = ?';
    params.push(alertType);
  }

  const source = c.req.query('source');
  if (source) {
    where += ' AND source = ?';
    params.push(source);
  }

  const countResult = await c.env.DB
    .prepare(`SELECT COUNT(*) as total FROM soc_alerts ${where}`)
    .bind(...params)
    .first<{ total: number }>();

  const total = countResult?.total || 0;

  const dataParams = [...params, pageSize, (page - 1) * pageSize];
  const alerts = await c.env.DB
    .prepare(
      `SELECT * FROM soc_alerts ${where}
       ORDER BY CASE severity
         WHEN 'critical' THEN 1 WHEN 'high' THEN 2
         WHEN 'medium' THEN 3 WHEN 'low' THEN 4
         WHEN 'info' THEN 5 END,
       created_at DESC
       LIMIT ? OFFSET ?`
    )
    .bind(...dataParams)
    .all();

  return c.json({
    items: alerts.results || [],
    total,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(total / pageSize),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /soc/alerts/:id — Get single alert
// ─────────────────────────────────────────────────────────────────────────────
soc.get('/alerts/:id', async (c) => {
  const id = c.req.param('id');
  const alert = await c.env.DB
    .prepare('SELECT * FROM soc_alerts WHERE id = ?')
    .bind(id)
    .first();

  if (!alert) return c.json({ error: 'Alert not found' }, 404);
  return c.json(alert);
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /soc/alerts — Create manual alert
// ─────────────────────────────────────────────────────────────────────────────
soc.post('/alerts', async (c) => {
  const body = await c.req.json();
  if (!body.title) throw badRequest('title is required');

  const id = crypto.randomUUID();
  await c.env.DB
    .prepare(
      `INSERT INTO soc_alerts (id, title, description, severity, status, source, alert_type, tags, assigned_to, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'new', 'manual', ?, ?, ?, datetime('now'), datetime('now'))`
    )
    .bind(
      id,
      body.title,
      body.description || null,
      body.severity || 'medium',
      body.alert_type || 'vulnerability',
      body.tags ? JSON.stringify(body.tags) : null,
      body.assigned_to || null
    )
    .run();

  const alert = await c.env.DB
    .prepare('SELECT * FROM soc_alerts WHERE id = ?')
    .bind(id)
    .first();

  return c.json(alert, 201);
});

// ─────────────────────────────────────────────────────────────────────────────
// PUT /soc/alerts/:id — Update alert
// ─────────────────────────────────────────────────────────────────────────────
soc.put('/alerts/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  const existing = await c.env.DB
    .prepare('SELECT * FROM soc_alerts WHERE id = ?')
    .bind(id)
    .first();

  if (!existing) return c.json({ error: 'Alert not found' }, 404);

  const fields: string[] = [];
  const values: unknown[] = [];
  const updatable = ['title', 'description', 'severity', 'status', 'assigned_to', 'tags', 'incident_id'];

  for (const field of updatable) {
    if (body[field] !== undefined) {
      const value = typeof body[field] === 'object' ? JSON.stringify(body[field]) : body[field];
      fields.push(`${field} = ?`);
      values.push(value);
    }
  }

  if (body.status && ['resolved', 'closed'].includes(body.status)) {
    fields.push('resolved_at = datetime(\'now\')');
  }

  if (fields.length === 0) throw badRequest('No fields to update');

  fields.push("updated_at = datetime('now')");
  values.push(id);

  await c.env.DB
    .prepare(`UPDATE soc_alerts SET ${fields.join(', ')} WHERE id = ?`)
    .bind(...values)
    .run();

  const updated = await c.env.DB
    .prepare('SELECT * FROM soc_alerts WHERE id = ?')
    .bind(id)
    .first();

  return c.json(updated);
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /soc/incidents — List incidents
// ─────────────────────────────────────────────────────────────────────────────
soc.get('/incidents', async (c) => {
  const page = parseInt(c.req.query('page') || '1', 10);
  const pageSize = Math.min(parseInt(c.req.query('page_size') || '25', 10), 100);

  let where = 'WHERE 1=1';
  const params: unknown[] = [];

  const status = c.req.query('status');
  if (status) {
    where += ' AND status = ?';
    params.push(status);
  }

  const severity = c.req.query('severity');
  if (severity) {
    where += ' AND severity = ?';
    params.push(severity);
  }

  const countResult = await c.env.DB
    .prepare(`SELECT COUNT(*) as total FROM soc_incidents ${where}`)
    .bind(...params)
    .first<{ total: number }>();

  const total = countResult?.total || 0;

  const dataParams = [...params, pageSize, (page - 1) * pageSize];
  const incidents = await c.env.DB
    .prepare(
      `SELECT * FROM soc_incidents ${where}
       ORDER BY priority ASC, created_at DESC
       LIMIT ? OFFSET ?`
    )
    .bind(...dataParams)
    .all();

  return c.json({
    items: incidents.results || [],
    total,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(total / pageSize),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /soc/incidents/:id — Get single incident with timeline
// ─────────────────────────────────────────────────────────────────────────────
soc.get('/incidents/:id', async (c) => {
  const id = c.req.param('id');

  const incident = await c.env.DB
    .prepare('SELECT * FROM soc_incidents WHERE id = ?')
    .bind(id)
    .first();

  if (!incident) return c.json({ error: 'Incident not found' }, 404);

  const [timeline, alerts] = await Promise.all([
    c.env.DB
      .prepare(
        `SELECT * FROM soc_incident_timeline
         WHERE incident_id = ?
         ORDER BY created_at ASC`
      )
      .bind(id)
      .all(),
    c.env.DB
      .prepare(
        `SELECT a.* FROM soc_alerts a
         JOIN soc_alert_incidents ai ON a.id = ai.alert_id
         WHERE ai.incident_id = ?
         ORDER BY a.created_at DESC`
      )
      .bind(id)
      .all(),
  ]);

  return c.json({
    ...incident,
    timeline: timeline.results || [],
    alerts: alerts.results || [],
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /soc/incidents — Create incident
// ─────────────────────────────────────────────────────────────────────────────
soc.post('/incidents', async (c) => {
  const body = await c.req.json();
  if (!body.title) throw badRequest('title is required');

  const id = crypto.randomUUID();
  const priority = body.severity === 'critical' ? 1 : body.severity === 'high' ? 2 : body.severity === 'medium' ? 3 : 4;

  await c.env.DB
    .prepare(
      `INSERT INTO soc_incidents (id, title, description, severity, status, priority, incident_type, lead_analyst, started_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'open', ?, ?, ?, datetime('now'), datetime('now'), datetime('now'))`
    )
    .bind(
      id,
      body.title,
      body.description || null,
      body.severity || 'medium',
      priority,
      body.incident_type || 'security',
      body.lead_analyst || null
    )
    .run();

  // Create timeline entry
  await c.env.DB
    .prepare(
      `INSERT INTO soc_incident_timeline (id, incident_id, action, description, created_at)
       VALUES (?, ?, 'created', 'Incident created', datetime('now'))`
    )
    .bind(crypto.randomUUID(), id)
    .run();

  const incident = await c.env.DB
    .prepare('SELECT * FROM soc_incidents WHERE id = ?')
    .bind(id)
    .first();

  return c.json(incident, 201);
});

// ─────────────────────────────────────────────────────────────────────────────
// PUT /soc/incidents/:id — Update incident
// ─────────────────────────────────────────────────────────────────────────────
soc.put('/incidents/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  const existing = await c.env.DB
    .prepare('SELECT * FROM soc_incidents WHERE id = ?')
    .bind(id)
    .first();

  if (!existing) return c.json({ error: 'Incident not found' }, 404);

  const fields: string[] = [];
  const values: unknown[] = [];
  const updatable = ['title', 'description', 'severity', 'status', 'priority', 'lead_analyst', 'root_cause', 'lessons_learned', 'containment_actions'];

  for (const field of updatable) {
    if (body[field] !== undefined) {
      const value = typeof body[field] === 'object' ? JSON.stringify(body[field]) : body[field];
      fields.push(`${field} = ?`);
      values.push(value);
    }
  }

  // Track status transitions with timestamps
  if (body.status) {
    if (body.status === 'containment' && !existing.contained_at) {
      fields.push('contained_at = datetime(\'now\')');
    }
    if (['recovery', 'post_incident', 'closed'].includes(body.status) && !existing.resolved_at) {
      fields.push('resolved_at = datetime(\'now\')');
    }
    if (body.status === 'closed' && !existing.closed_at) {
      fields.push('closed_at = datetime(\'now\')');
    }
  }

  if (fields.length === 0) throw badRequest('No fields to update');

  fields.push("updated_at = datetime('now')");
  values.push(id);

  await c.env.DB
    .prepare(`UPDATE soc_incidents SET ${fields.join(', ')} WHERE id = ?`)
    .bind(...values)
    .run();

  // Add timeline entry for status changes
  if (body.status && body.status !== existing.status) {
    await c.env.DB
      .prepare(
        `INSERT INTO soc_incident_timeline (id, incident_id, action, description, old_value, new_value, created_at)
         VALUES (?, ?, 'status_changed', ?, ?, ?, datetime('now'))`
      )
      .bind(
        crypto.randomUUID(),
        id,
        `Status changed from ${existing.status} to ${body.status}`,
        existing.status as string,
        body.status
      )
      .run();
  }

  const updated = await c.env.DB
    .prepare('SELECT * FROM soc_incidents WHERE id = ?')
    .bind(id)
    .first();

  return c.json(updated);
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /soc/incidents/:id/alerts — Link alert to incident
// ─────────────────────────────────────────────────────────────────────────────
soc.post('/incidents/:id/alerts', async (c) => {
  const incidentId = c.req.param('id');
  const body = await c.req.json();

  if (!body.alert_id) throw badRequest('alert_id is required');

  const incident = await c.env.DB
    .prepare('SELECT * FROM soc_incidents WHERE id = ?')
    .bind(incidentId)
    .first();
  if (!incident) return c.json({ error: 'Incident not found' }, 404);

  const alert = await c.env.DB
    .prepare('SELECT * FROM soc_alerts WHERE id = ?')
    .bind(body.alert_id)
    .first();
  if (!alert) return c.json({ error: 'Alert not found' }, 404);

  await c.env.DB
    .prepare('INSERT OR IGNORE INTO soc_alert_incidents (alert_id, incident_id) VALUES (?, ?)')
    .bind(body.alert_id, incidentId)
    .run();

  // Update alert status
  await c.env.DB
    .prepare('UPDATE soc_alerts SET incident_id = ?, status = \'escalated\', updated_at = datetime(\'now\') WHERE id = ?')
    .bind(incidentId, body.alert_id)
    .run();

  // Update incident alert count
  const countResult = await c.env.DB
    .prepare('SELECT COUNT(*) as cnt FROM soc_alert_incidents WHERE incident_id = ?')
    .bind(incidentId)
    .first<{ cnt: number }>();

  await c.env.DB
    .prepare('UPDATE soc_incidents SET alert_count = ?, updated_at = datetime(\'now\') WHERE id = ?')
    .bind(countResult?.cnt || 0, incidentId)
    .run();

  // Timeline entry
  await c.env.DB
    .prepare(
      `INSERT INTO soc_incident_timeline (id, incident_id, action, description, created_at)
       VALUES (?, ?, 'alert_added', ?, datetime('now'))`
    )
    .bind(crypto.randomUUID(), incidentId, `Alert linked: ${alert.title}`)
    .run();

  return c.json({ message: 'Alert linked to incident' });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /soc/detection-rules — List detection rules
// ─────────────────────────────────────────────────────────────────────────────
soc.get('/detection-rules', async (c) => {
  const rules = await c.env.DB
    .prepare('SELECT * FROM soc_detection_rules ORDER BY is_active DESC, created_at DESC')
    .all();

  return c.json({ items: rules.results || [] });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /soc/detection-rules — Create detection rule
// ─────────────────────────────────────────────────────────────────────────────
soc.post('/detection-rules', async (c) => {
  const body = await c.req.json();

  if (!body.name || !body.event_pattern) {
    throw badRequest('name and event_pattern are required');
  }

  const id = crypto.randomUUID();
  await c.env.DB
    .prepare(
      `INSERT INTO soc_detection_rules (id, name, description, event_pattern, conditions, alert_severity, alert_type, tags, is_active, auto_escalate, cooldown_seconds, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`
    )
    .bind(
      id,
      body.name,
      body.description || null,
      body.event_pattern,
      body.conditions ? (typeof body.conditions === 'string' ? body.conditions : JSON.stringify(body.conditions)) : null,
      body.alert_severity || 'medium',
      body.alert_type || 'vulnerability',
      body.tags ? JSON.stringify(body.tags) : null,
      body.is_active !== false ? 1 : 0,
      body.auto_escalate ? 1 : 0,
      body.cooldown_seconds || 300,
      body.created_by || null
    )
    .run();

  const rule = await c.env.DB
    .prepare('SELECT * FROM soc_detection_rules WHERE id = ?')
    .bind(id)
    .first();

  return c.json(rule, 201);
});

// ─────────────────────────────────────────────────────────────────────────────
// PUT /soc/detection-rules/:id — Update detection rule
// ─────────────────────────────────────────────────────────────────────────────
soc.put('/detection-rules/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  const existing = await c.env.DB
    .prepare('SELECT * FROM soc_detection_rules WHERE id = ?')
    .bind(id)
    .first();

  if (!existing) return c.json({ error: 'Detection rule not found' }, 404);

  const fields: string[] = [];
  const values: unknown[] = [];
  const updatable = ['name', 'description', 'event_pattern', 'conditions', 'alert_severity', 'alert_type', 'tags', 'is_active', 'auto_escalate', 'cooldown_seconds'];

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
    .prepare(`UPDATE soc_detection_rules SET ${fields.join(', ')} WHERE id = ?`)
    .bind(...values)
    .run();

  const updated = await c.env.DB
    .prepare('SELECT * FROM soc_detection_rules WHERE id = ?')
    .bind(id)
    .first();

  return c.json(updated);
});

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /soc/detection-rules/:id — Delete detection rule
// ─────────────────────────────────────────────────────────────────────────────
soc.delete('/detection-rules/:id', async (c) => {
  const id = c.req.param('id');

  const result = await c.env.DB
    .prepare('DELETE FROM soc_detection_rules WHERE id = ?')
    .bind(id)
    .run();

  if (!result.meta.changes) {
    return c.json({ error: 'Detection rule not found' }, 404);
  }

  return c.json({ message: 'Detection rule deleted' });
});
