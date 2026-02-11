import { Hono } from 'hono';
import type { Env } from '../index';

export const scans = new Hono<{ Bindings: Env }>();

// List scans
scans.get('/', async (c) => {
  const { limit = '20', offset = '0', status, scan_type } = c.req.query();

  let query = 'SELECT * FROM scans WHERE 1=1';
  const params: any[] = [];

  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }

  if (scan_type) {
    query += ' AND scan_type = ?';
    params.push(scan_type);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));

  const result = await c.env.DB.prepare(query).bind(...params).all();

  return c.json({
    data: result.results,
    pagination: {
      limit: parseInt(limit),
      offset: parseInt(offset),
    },
  });
});

// Get scan by ID
scans.get('/:id', async (c) => {
  const id = c.req.param('id');

  const scan = await c.env.DB.prepare(
    'SELECT * FROM scans WHERE id = ?'
  ).bind(id).first();

  if (!scan) {
    return c.json({ error: 'Scan not found' }, 404);
  }

  return c.json(scan);
});

// Create new scan
scans.post('/', async (c) => {
  const body = await c.req.json();
  const id = crypto.randomUUID();

  const validTypes = ['network', 'webapp', 'cloud', 'config_audit', 'full'];
  if (!validTypes.includes(body.scan_type)) {
    return c.json({ error: 'Invalid scan type' }, 400);
  }

  await c.env.DB.prepare(`
    INSERT INTO scans (id, name, scan_type, targets, config, status, created_by)
    VALUES (?, ?, ?, ?, ?, 'pending', ?)
  `).bind(
    id,
    body.name,
    body.scan_type,
    JSON.stringify(body.targets),
    JSON.stringify(body.config || {}),
    body.created_by || null,
  ).run();

  return c.json({ id, message: 'Scan created', status: 'pending' }, 201);
});

// Update scan status
scans.patch('/:id/status', async (c) => {
  const id = c.req.param('id');
  const { status, error_message, findings_count, assets_count } = await c.req.json();

  const validStatuses = ['pending', 'running', 'completed', 'failed', 'cancelled'];
  if (!validStatuses.includes(status)) {
    return c.json({ error: 'Invalid status' }, 400);
  }

  let updates = ['status = ?', 'updated_at = datetime(\'now\')'];
  let params: any[] = [status];

  if (status === 'running') {
    updates.push('started_at = datetime(\'now\')');
  }

  if (status === 'completed' || status === 'failed') {
    updates.push('completed_at = datetime(\'now\')');
  }

  if (error_message) {
    updates.push('error_message = ?');
    params.push(error_message);
  }

  if (findings_count !== undefined) {
    updates.push('findings_count = ?');
    params.push(findings_count);
  }

  if (assets_count !== undefined) {
    updates.push('assets_count = ?');
    params.push(assets_count);
  }

  await c.env.DB.prepare(`
    UPDATE scans SET ${updates.join(', ')} WHERE id = ?
  `).bind(...params, id).run();

  return c.json({ message: 'Scan status updated' });
});

// Cancel scan
scans.post('/:id/cancel', async (c) => {
  const id = c.req.param('id');

  const scan = await c.env.DB.prepare(
    'SELECT status FROM scans WHERE id = ?'
  ).bind(id).first<{ status: string }>();

  if (!scan) {
    return c.json({ error: 'Scan not found' }, 404);
  }

  if (scan.status !== 'pending' && scan.status !== 'running') {
    return c.json({ error: 'Scan cannot be cancelled' }, 400);
  }

  await c.env.DB.prepare(`
    UPDATE scans SET status = 'cancelled', completed_at = datetime('now'), updated_at = datetime('now')
    WHERE id = ?
  `).bind(id).run();

  return c.json({ message: 'Scan cancelled' });
});

// Delete scan
scans.delete('/:id', async (c) => {
  const id = c.req.param('id');

  await c.env.DB.prepare('DELETE FROM scans WHERE id = ?').bind(id).run();

  return c.json({ message: 'Scan deleted' });
});

// Get scan statistics
scans.get('/stats/summary', async (c) => {
  const result = await c.env.DB.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
      SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
      SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
      SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
      SUM(findings_count) as total_findings
    FROM scans
  `).first();

  return c.json(result);
});
