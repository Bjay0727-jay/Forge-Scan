import { Hono } from 'hono';
import type { Env } from '../index';

export const findings = new Hono<{ Bindings: Env }>();

// List findings with filtering
findings.get('/', async (c) => {
  const {
    limit = '50',
    offset = '0',
    severity,
    state = 'open',
    vendor,
    asset_id,
    search,
  } = c.req.query();

  let query = 'SELECT f.*, a.hostname, a.ip_addresses FROM findings f LEFT JOIN assets a ON f.asset_id = a.id WHERE 1=1';
  const params: any[] = [];

  if (severity) {
    query += ' AND f.severity = ?';
    params.push(severity);
  }

  if (state) {
    query += ' AND f.state = ?';
    params.push(state);
  }

  if (vendor) {
    query += ' AND f.vendor = ?';
    params.push(vendor);
  }

  if (asset_id) {
    query += ' AND f.asset_id = ?';
    params.push(asset_id);
  }

  if (search) {
    query += ' AND (f.title LIKE ? OR f.description LIKE ? OR f.vendor_id LIKE ?)';
    const searchPattern = `%${search}%`;
    params.push(searchPattern, searchPattern, searchPattern);
  }

  // Order by severity (Critical > High > Medium > Low > Info), then by FRS score
  query += ` ORDER BY
    CASE f.severity
      WHEN 'critical' THEN 1
      WHEN 'high' THEN 2
      WHEN 'medium' THEN 3
      WHEN 'low' THEN 4
      ELSE 5
    END,
    f.frs_score DESC NULLS LAST,
    f.last_seen DESC
    LIMIT ? OFFSET ?`;
  params.push(parseInt(limit), parseInt(offset));

  const result = await c.env.DB.prepare(query).bind(...params).all();

  // Get total count
  let countQuery = 'SELECT COUNT(*) as total FROM findings f WHERE 1=1';
  const countParams: any[] = [];

  if (severity) {
    countQuery += ' AND f.severity = ?';
    countParams.push(severity);
  }
  if (state) {
    countQuery += ' AND f.state = ?';
    countParams.push(state);
  }
  if (vendor) {
    countQuery += ' AND f.vendor = ?';
    countParams.push(vendor);
  }
  if (asset_id) {
    countQuery += ' AND f.asset_id = ?';
    countParams.push(asset_id);
  }

  const countResult = await c.env.DB.prepare(countQuery)
    .bind(...countParams)
    .first<{ total: number }>();

  return c.json({
    data: result.results,
    pagination: {
      total: countResult?.total || 0,
      limit: parseInt(limit),
      offset: parseInt(offset),
    },
  });
});

// Get finding by ID
findings.get('/:id', async (c) => {
  const id = c.req.param('id');

  const finding = await c.env.DB.prepare(`
    SELECT f.*, a.hostname, a.ip_addresses, a.os, v.cve_id, v.cvss_score, v.cvss_vector, v.epss_score, v.in_kev
    FROM findings f
    LEFT JOIN assets a ON f.asset_id = a.id
    LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
    WHERE f.id = ?
  `).bind(id).first();

  if (!finding) {
    return c.json({ error: 'Finding not found' }, 404);
  }

  return c.json(finding);
});

// Create finding
findings.post('/', async (c) => {
  const body = await c.req.json();
  const id = crypto.randomUUID();

  await c.env.DB.prepare(`
    INSERT INTO findings (
      id, asset_id, vulnerability_id, vendor, vendor_id, title, description,
      severity, frs_score, port, protocol, service, state, solution, evidence, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    body.asset_id,
    body.vulnerability_id || null,
    body.vendor,
    body.vendor_id,
    body.title,
    body.description || null,
    body.severity,
    body.frs_score || null,
    body.port || null,
    body.protocol || null,
    body.service || null,
    body.state || 'open',
    body.solution || null,
    body.evidence || null,
    JSON.stringify(body.metadata || {}),
  ).run();

  return c.json({ id, message: 'Finding created' }, 201);
});

// Update finding state
findings.patch('/:id/state', async (c) => {
  const id = c.req.param('id');
  const { state } = await c.req.json();

  const validStates = ['open', 'fixed', 'accepted', 'false_positive', 'reopened'];
  if (!validStates.includes(state)) {
    return c.json({ error: 'Invalid state' }, 400);
  }

  const updates: string[] = ['state = ?', 'updated_at = datetime(\'now\')'];
  const params: any[] = [state];

  if (state === 'fixed') {
    updates.push('fixed_at = datetime(\'now\')');
  }

  await c.env.DB.prepare(`
    UPDATE findings SET ${updates.join(', ')} WHERE id = ?
  `).bind(...params, id).run();

  return c.json({ message: 'Finding state updated' });
});

// Bulk update findings
findings.post('/bulk/state', async (c) => {
  const { ids, state } = await c.req.json();

  if (!Array.isArray(ids) || ids.length === 0) {
    return c.json({ error: 'No finding IDs provided' }, 400);
  }

  const placeholders = ids.map(() => '?').join(',');

  await c.env.DB.prepare(`
    UPDATE findings
    SET state = ?, updated_at = datetime('now')
    WHERE id IN (${placeholders})
  `).bind(state, ...ids).run();

  return c.json({ message: `Updated ${ids.length} findings` });
});

// Get severity distribution
findings.get('/stats/severity', async (c) => {
  const { state = 'open' } = c.req.query();

  const result = await c.env.DB.prepare(`
    SELECT severity, COUNT(*) as count
    FROM findings
    WHERE state = ?
    GROUP BY severity
    ORDER BY
      CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
      END
  `).bind(state).all();

  return c.json(result.results);
});

// Get vendor distribution
findings.get('/stats/vendors', async (c) => {
  const result = await c.env.DB.prepare(`
    SELECT vendor, COUNT(*) as count
    FROM findings
    WHERE state = 'open'
    GROUP BY vendor
    ORDER BY count DESC
  `).all();

  return c.json(result.results);
});
