import { Hono } from 'hono';
import type { Env } from '../index';
import { notFound, badRequest, databaseError } from '../lib/errors';
import { parsePagination, requireEnum, validateSort, validateSortOrder } from '../lib/validate';

export const findings = new Hono<{ Bindings: Env }>();

const VALID_STATES = ['open', 'acknowledged', 'resolved', 'false_positive', 'reopened', 'fixed', 'accepted'] as const;
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

// List findings with filtering
findings.get('/', async (c) => {
  const {
    severity,
    state,
    vendor,
    asset_id,
    search,
    sort_by,
    sort_order,
  } = c.req.query();

  const { page, pageSize, offset } = parsePagination(c.req.query('page'), c.req.query('page_size'));
  const sortField = validateSort(sort_by, ['severity', 'title', 'frs_score', 'last_seen', 'created_at'], 'severity');
  const sortDir = validateSortOrder(sort_order);

  let query = 'SELECT f.*, a.hostname, a.ip_addresses FROM findings f LEFT JOIN assets a ON f.asset_id = a.id WHERE 1=1';
  let countQuery = 'SELECT COUNT(*) as total FROM findings f WHERE 1=1';
  const params: string[] = [];
  const countParams: string[] = [];

  if (severity) {
    query += ' AND f.severity = ?';
    countQuery += ' AND f.severity = ?';
    params.push(severity);
    countParams.push(severity);
  }

  if (state) {
    query += ' AND f.state = ?';
    countQuery += ' AND f.state = ?';
    params.push(state);
    countParams.push(state);
  }

  if (vendor) {
    query += ' AND f.vendor = ?';
    countQuery += ' AND f.vendor = ?';
    params.push(vendor);
    countParams.push(vendor);
  }

  if (asset_id) {
    query += ' AND f.asset_id = ?';
    countQuery += ' AND f.asset_id = ?';
    params.push(asset_id);
    countParams.push(asset_id);
  }

  if (search) {
    query += ' AND (f.title LIKE ? OR f.description LIKE ? OR f.vendor_id LIKE ?)';
    countQuery += ' AND (f.title LIKE ? OR f.description LIKE ? OR f.vendor_id LIKE ?)';
    const searchPattern = `%${search}%`;
    params.push(searchPattern, searchPattern, searchPattern);
    countParams.push(searchPattern, searchPattern, searchPattern);
  }

  // Dynamic sort
  if (sortField === 'severity') {
    query += ` ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END ${sortDir}, f.frs_score DESC NULLS LAST, f.last_seen DESC LIMIT ? OFFSET ?`;
  } else {
    query += ` ORDER BY f.${sortField} ${sortDir} NULLS LAST LIMIT ? OFFSET ?`;
  }

  try {
    const result = await c.env.DB.prepare(query).bind(...params, pageSize, offset).all();
    const countResult = await c.env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>();

    const total = countResult?.total || 0;
    const totalPages = Math.ceil(total / pageSize);

    // Transform to match frontend expected format
    const items = (result.results || []).map((f: Record<string, unknown>) => ({
      id: f.id,
      asset_id: f.asset_id,
      scan_id: f.scan_id,
      title: f.title,
      description: f.description,
      severity: f.severity,
      state: f.state,
      cve_id: f.cve_id,
      cvss_score: f.cvss_score,
      affected_component: f.affected_component || f.vendor_id,
      remediation: f.remediation,
      references: f.references ? JSON.parse(String(f.references)) : [],
      first_seen: f.first_seen,
      last_seen: f.last_seen,
      created_at: f.created_at || f.first_seen,
      updated_at: f.updated_at || f.last_seen,
    }));

    return c.json({
      items,
      total,
      page,
      page_size: pageSize,
      total_pages: totalPages,
    });
  } catch (err) {
    throw databaseError(err);
  }
});

// Get finding by ID
findings.get('/:id', async (c) => {
  const id = c.req.param('id');

  try {
    const finding = await c.env.DB.prepare(`
      SELECT f.*, a.hostname, a.ip_addresses, a.os, v.cve_id, v.cvss_score, v.cvss_vector, v.epss_score, v.in_kev
      FROM findings f
      LEFT JOIN assets a ON f.asset_id = a.id
      LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
      WHERE f.id = ?
    `).bind(id).first();

    if (!finding) {
      throw notFound('Finding', id);
    }

    return c.json(finding);
  } catch (err) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// Create finding
findings.post('/', async (c) => {
  const body = await c.req.json();
  const id = crypto.randomUUID();

  try {
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
  } catch (err) {
    throw databaseError(err);
  }
});

// Update finding (PUT) - supports state changes and other field updates
findings.put('/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  try {
    const existing = await c.env.DB.prepare(
      'SELECT id FROM findings WHERE id = ?'
    ).bind(id).first();

    if (!existing) {
      throw notFound('Finding', id);
    }

    const updates: string[] = [];
    const params: (string | number | null)[] = [];

    if (body.state !== undefined) {
      requireEnum(body.state, 'state', VALID_STATES);
      updates.push('state = ?');
      params.push(body.state);
      if (body.state === 'fixed' || body.state === 'resolved') {
        updates.push("fixed_at = datetime('now')");
      }
    }

    if (body.severity !== undefined) {
      requireEnum(body.severity, 'severity', VALID_SEVERITIES);
      updates.push('severity = ?');
      params.push(body.severity);
    }

    if (body.description !== undefined) {
      updates.push('description = ?');
      params.push(body.description);
    }

    if (body.solution !== undefined) {
      updates.push('solution = ?');
      params.push(body.solution);
    }

    if (updates.length === 0) {
      throw badRequest('No fields to update');
    }

    updates.push("updated_at = datetime('now')");
    params.push(id);

    await c.env.DB.prepare(
      `UPDATE findings SET ${updates.join(', ')} WHERE id = ?`
    ).bind(...params).run();

    // Return updated finding
    const updated = await c.env.DB.prepare(
      'SELECT f.*, a.hostname, a.ip_addresses FROM findings f LEFT JOIN assets a ON f.asset_id = a.id WHERE f.id = ?'
    ).bind(id).first();

    return c.json(updated);
  } catch (err) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// Update finding state
findings.patch('/:id/state', async (c) => {
  const id = c.req.param('id');
  const { state } = await c.req.json();

  const validStates = ['open', 'fixed', 'accepted', 'false_positive', 'reopened'] as const;
  requireEnum(state, 'state', validStates);

  try {
    const updates: string[] = ['state = ?', 'updated_at = datetime(\'now\')'];
    const params: any[] = [state];

    if (state === 'fixed') {
      updates.push('fixed_at = datetime(\'now\')');
    }

    await c.env.DB.prepare(`
      UPDATE findings SET ${updates.join(', ')} WHERE id = ?
    `).bind(...params, id).run();

    return c.json({ message: 'Finding state updated' });
  } catch (err) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// Bulk update findings
findings.post('/bulk/state', async (c) => {
  const { ids, state } = await c.req.json();

  if (!Array.isArray(ids) || ids.length === 0) {
    throw badRequest('No finding IDs provided');
  }

  requireEnum(state, 'state', VALID_STATES);

  try {
    const placeholders = ids.map(() => '?').join(',');

    await c.env.DB.prepare(`
      UPDATE findings
      SET state = ?, updated_at = datetime('now')
      WHERE id IN (${placeholders})
    `).bind(state, ...ids).run();

    return c.json({ message: `Updated ${ids.length} findings` });
  } catch (err) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// Get severity distribution
findings.get('/stats/severity', async (c) => {
  const { state = 'open' } = c.req.query();

  try {
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
  } catch (err) {
    throw databaseError(err);
  }
});

// Get vendor distribution
findings.get('/stats/vendors', async (c) => {
  try {
    const result = await c.env.DB.prepare(`
      SELECT vendor, COUNT(*) as count
      FROM findings
      WHERE state = 'open'
      GROUP BY vendor
      ORDER BY count DESC
    `).all();

    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});
