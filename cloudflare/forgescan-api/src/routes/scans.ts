import { Hono } from 'hono';
import type { Env } from '../index';
import { createTasksForScan, getTasksForScan, cancelScanTasks } from '../services/scan-orchestrator';

export const scans = new Hono<{ Bindings: Env }>();

// List scans
scans.get('/', async (c) => {
  const { page = '1', page_size = '20', status, type } = c.req.query();
  const pageNum = parseInt(page);
  const pageSizeNum = parseInt(page_size);
  const offset = (pageNum - 1) * pageSizeNum;

  let query = 'SELECT * FROM scans WHERE 1=1';
  let countQuery = 'SELECT COUNT(*) as total FROM scans WHERE 1=1';
  const params: string[] = [];
  const countParams: string[] = [];

  if (status) {
    query += ' AND status = ?';
    countQuery += ' AND status = ?';
    params.push(status);
    countParams.push(status);
  }

  if (type) {
    query += ' AND scan_type = ?';
    countQuery += ' AND scan_type = ?';
    params.push(type);
    countParams.push(type);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';

  const result = await c.env.DB.prepare(query).bind(...params, pageSizeNum, offset).all();
  const countResult = await c.env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>();

  const total = countResult?.total || 0;
  const totalPages = Math.ceil(total / pageSizeNum);

  // Transform to match frontend expected format
  const items = (result.results || []).map((s: Record<string, unknown>) => ({
    id: s.id,
    name: s.name,
    type: s.scan_type,
    status: s.status,
    target: s.targets ? JSON.parse(String(s.targets)).join(', ') : '',
    configuration: s.config ? JSON.parse(String(s.config)) : {},
    findings_count: s.findings_count || 0,
    started_at: s.started_at,
    completed_at: s.completed_at,
    created_at: s.created_at,
    updated_at: s.updated_at || s.created_at,
  }));

  return c.json({
    items,
    total,
    page: pageNum,
    page_size: pageSizeNum,
    total_pages: totalPages,
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
  try {
    const body = await c.req.json();
    const id = crypto.randomUUID();

    // Support both frontend format (type, target, configuration) and API format (scan_type, targets, config)
    const scanType = body.type || body.scan_type;
    const target = body.target || body.targets;
    const config = body.configuration || body.config || {};

    const validTypes = ['network', 'container', 'cloud', 'web', 'code', 'compliance', 'webapp', 'config_audit', 'full'];
    if (!validTypes.includes(scanType)) {
      return c.json({ error: `Invalid scan type: ${scanType}. Valid types: ${validTypes.join(', ')}` }, 400);
    }

    // Normalize targets to array
    const targets = Array.isArray(target) ? target : [target];

    await c.env.DB.prepare(`
      INSERT INTO scans (id, name, scan_type, targets, config, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'pending', datetime('now'))
    `).bind(
      id,
      body.name,
      scanType,
      JSON.stringify(targets),
      JSON.stringify(config),
    ).run();

    // Return the created scan in the format frontend expects
    return c.json({
      id,
      name: body.name,
      type: scanType,
      status: 'pending',
      target: targets.join(', '),
      configuration: config,
      findings_count: 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }, 201);
  } catch (error: unknown) {
    console.error('Create scan error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to create scan', message }, 500);
  }
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

// Start scan - creates scanner tasks for the Rust engine to pick up
scans.post('/:id/start', async (c) => {
  const id = c.req.param('id');

  const scan = await c.env.DB.prepare(
    'SELECT * FROM scans WHERE id = ?'
  ).bind(id).first<{ id: string; status: string; name: string; scan_type: string; targets: string; config: string }>();

  if (!scan) {
    return c.json({ error: 'Scan not found' }, 404);
  }

  if (scan.status !== 'pending') {
    return c.json({ error: `Scan cannot be started - current status is '${scan.status}'` }, 400);
  }

  try {
    // Create scanner tasks via the orchestrator
    const taskIds = await createTasksForScan(c.env.DB, id);

    // Update scan status to running
    await c.env.DB.prepare(`
      UPDATE scans SET status = 'running', started_at = datetime('now'), updated_at = datetime('now')
      WHERE id = ?
    `).bind(id).run();

    return c.json({
      id: scan.id,
      name: scan.name,
      type: scan.scan_type,
      status: 'running',
      message: 'Scan started - tasks queued for scanner engine',
      tasks_created: taskIds.length,
      task_ids: taskIds,
      started_at: new Date().toISOString(),
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to start scan', message }, 500);
  }
});

// Get scan tasks - returns tasks for a specific scan
scans.get('/:id/tasks', async (c) => {
  const id = c.req.param('id');
  const tasks = await getTasksForScan(c.env.DB, id);
  return c.json({ tasks });
});

// Cancel scan - also cancels associated scanner tasks
scans.post('/:id/cancel', async (c) => {
  const id = c.req.param('id');

  const scan = await c.env.DB.prepare(
    'SELECT status FROM scans WHERE id = ?'
  ).bind(id).first<{ status: string }>();

  if (!scan) {
    return c.json({ error: 'Scan not found' }, 404);
  }

  if (scan.status !== 'pending' && scan.status !== 'running' && scan.status !== 'queued') {
    return c.json({ error: 'Scan cannot be cancelled' }, 400);
  }

  // Cancel all associated scanner tasks
  const cancelledTasks = await cancelScanTasks(c.env.DB, id);

  await c.env.DB.prepare(`
    UPDATE scans SET status = 'cancelled', completed_at = datetime('now'), updated_at = datetime('now')
    WHERE id = ?
  `).bind(id).run();

  return c.json({ message: 'Scan cancelled', tasks_cancelled: cancelledTasks });
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
