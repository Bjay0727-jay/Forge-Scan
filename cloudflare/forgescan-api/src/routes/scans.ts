import { Hono } from 'hono';
import type { Env } from '../index';
import { createTasksForScan, getTasksForScan, cancelScanTasks } from '../services/scan-orchestrator';
import { ApiError, notFound, badRequest, invalidStateTransition, databaseError } from '../lib/errors';
import { parsePagination, requireEnum, validateSort, validateSortOrder } from '../lib/validate';
import { auditLog } from '../services/audit';

export const scans = new Hono<{ Bindings: Env }>();

const VALID_SCAN_TYPES = ['network', 'container', 'cloud', 'web', 'code', 'compliance', 'webapp', 'config_audit', 'full'] as const;
const VALID_STATUSES = ['pending', 'running', 'completed', 'failed', 'cancelled'] as const;

// List scans
scans.get('/', async (c) => {
  const { status, type, sort_by, sort_order } = c.req.query();
  const { page, pageSize, offset } = parsePagination(c.req.query('page'), c.req.query('page_size'));

  const sortField = validateSort(sort_by, ['name', 'status', 'scan_type', 'created_at', 'findings_count'], 'created_at');
  const order = validateSortOrder(sort_order);

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

  query += ` ORDER BY ${sortField} ${order} NULLS LAST LIMIT ? OFFSET ?`;

  try {
    const result = await c.env.DB.prepare(query).bind(...params, pageSize, offset).all();
    const countResult = await c.env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>();

    const total = countResult?.total || 0;
    const totalPages = Math.ceil(total / pageSize);

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
      page,
      page_size: pageSize,
      total_pages: totalPages,
    });
  } catch (err) {
    throw databaseError(err);
  }
});

// Get active scans with task progress (for dashboard polling)
scans.get('/active', async (c) => {
  try {
    const result = await c.env.DB.prepare(`
      SELECT s.id, s.name, s.scan_type, s.status, s.targets, s.findings_count,
             s.assets_count, s.started_at, s.created_at, s.updated_at,
             (SELECT COUNT(*) FROM scan_tasks t WHERE t.scan_id = s.id) as total_tasks,
             (SELECT COUNT(*) FROM scan_tasks t WHERE t.scan_id = s.id AND t.status = 'completed') as completed_tasks,
             (SELECT COUNT(*) FROM scan_tasks t WHERE t.scan_id = s.id AND t.status = 'running') as running_tasks,
             (SELECT COUNT(*) FROM scan_tasks t WHERE t.scan_id = s.id AND t.status = 'failed') as failed_tasks,
             (SELECT COUNT(*) FROM scan_tasks t WHERE t.scan_id = s.id AND t.status = 'queued') as queued_tasks,
             (SELECT COUNT(*) FROM scan_tasks t WHERE t.scan_id = s.id AND t.status = 'assigned') as assigned_tasks
      FROM scans s
      WHERE s.status IN ('running', 'pending', 'queued')
      ORDER BY s.started_at DESC NULLS LAST, s.created_at DESC
    `).all();

    const items = (result.results || []).map((s: Record<string, unknown>) => {
      const totalTasks = (s.total_tasks as number) || 0;
      const completedTasks = (s.completed_tasks as number) || 0;
      const failedTasks = (s.failed_tasks as number) || 0;

      return {
        id: s.id,
        name: s.name,
        type: s.scan_type,
        status: s.status,
        target: s.targets ? JSON.parse(String(s.targets)).join(', ') : '',
        findings_count: s.findings_count || 0,
        assets_count: s.assets_count || 0,
        started_at: s.started_at,
        created_at: s.created_at,
        progress: {
          total_tasks: totalTasks,
          completed_tasks: completedTasks,
          running_tasks: (s.running_tasks as number) || 0,
          failed_tasks: failedTasks,
          queued_tasks: (s.queued_tasks as number) || 0,
          assigned_tasks: (s.assigned_tasks as number) || 0,
          percentage: totalTasks > 0
            ? Math.round((completedTasks + failedTasks) / totalTasks * 100)
            : 0,
        },
      };
    });

    return c.json({ items, has_active: items.length > 0 });
  } catch (err) {
    throw databaseError(err);
  }
});

// Get scan by ID
scans.get('/:id', async (c) => {
  const id = c.req.param('id');

  try {
    const scan = await c.env.DB.prepare(
      'SELECT * FROM scans WHERE id = ?'
    ).bind(id).first();

    if (!scan) {
      throw notFound('Scan', id);
    }

    return c.json(scan);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw databaseError(err);
  }
});

// Create new scan
scans.post('/', async (c) => {
  const body = await c.req.json();
  const id = crypto.randomUUID();

  // Support both frontend format (type, target, configuration) and API format (scan_type, targets, config)
  const scanType = body.type || body.scan_type;
  const target = body.target || body.targets;
  const config = body.configuration || body.config || {};

  requireEnum(scanType, 'type', VALID_SCAN_TYPES);

  if (!target) {
    throw badRequest('Missing required field: target');
  }

  // Normalize targets to array
  const targets = Array.isArray(target) ? target : [target];

  try {
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

    // Audit: scan created
    auditLog(c.env.DB, { action: 'scan.created', resource_type: 'scan', resource_id: id, details: { scan_type: scanType, targets } });

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
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw databaseError(err);
  }
});

// Update scan status
scans.patch('/:id/status', async (c) => {
  const id = c.req.param('id');
  const { status, error_message, findings_count, assets_count } = await c.req.json();

  requireEnum(status, 'status', VALID_STATUSES);

  try {
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
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw databaseError(err);
  }
});

// Start scan - creates scanner tasks for the Rust engine to pick up
scans.post('/:id/start', async (c) => {
  const id = c.req.param('id');

  try {
    const scan = await c.env.DB.prepare(
      'SELECT * FROM scans WHERE id = ?'
    ).bind(id).first<{ id: string; status: string; name: string; scan_type: string; targets: string; config: string }>();

    if (!scan) {
      throw notFound('Scan', id);
    }

    if (scan.status !== 'pending') {
      throw invalidStateTransition(scan.status, 'running');
    }

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
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw databaseError(err);
  }
});

// Get scan tasks with summary - returns tasks for a specific scan
scans.get('/:id/tasks', async (c) => {
  const id = c.req.param('id');

  try {
    const tasks = await getTasksForScan(c.env.DB, id);

    const summary = {
      total: tasks.length,
      completed: tasks.filter((t) => t.status === 'completed').length,
      running: tasks.filter((t) => t.status === 'running').length,
      failed: tasks.filter((t) => t.status === 'failed').length,
      queued: tasks.filter((t) => t.status === 'queued').length,
      assigned: tasks.filter((t) => t.status === 'assigned').length,
      total_findings: tasks.reduce((sum, t) => sum + (t.findings_count || 0), 0),
      total_assets: tasks.reduce((sum, t) => sum + (t.assets_discovered || 0), 0),
    };

    return c.json({ tasks, summary });
  } catch (err) {
    throw databaseError(err);
  }
});

// Cancel scan - also cancels associated scanner tasks
scans.post('/:id/cancel', async (c) => {
  const id = c.req.param('id');

  try {
    const scan = await c.env.DB.prepare(
      'SELECT status FROM scans WHERE id = ?'
    ).bind(id).first<{ status: string }>();

    if (!scan) {
      throw notFound('Scan', id);
    }

    const cancellable = ['pending', 'running', 'queued'];
    if (!cancellable.includes(scan.status)) {
      throw invalidStateTransition(scan.status, 'cancelled');
    }

    // Cancel all associated scanner tasks
    const cancelledTasks = await cancelScanTasks(c.env.DB, id);

    await c.env.DB.prepare(`
      UPDATE scans SET status = 'cancelled', completed_at = datetime('now'), updated_at = datetime('now')
      WHERE id = ?
    `).bind(id).run();

    return c.json({ message: 'Scan cancelled', tasks_cancelled: cancelledTasks });
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw databaseError(err);
  }
});

// Delete scan
scans.delete('/:id', async (c) => {
  const id = c.req.param('id');

  try {
    const existing = await c.env.DB.prepare(
      'SELECT id FROM scans WHERE id = ?'
    ).bind(id).first();

    if (!existing) {
      throw notFound('Scan', id);
    }

    await c.env.DB.prepare('DELETE FROM scans WHERE id = ?').bind(id).run();

    // Audit: scan deleted
    auditLog(c.env.DB, { action: 'scan.deleted', resource_type: 'scan', resource_id: id });

    return c.json({ message: 'Scan deleted' });
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw databaseError(err);
  }
});

// Get scan statistics
scans.get('/stats/summary', async (c) => {
  try {
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
  } catch (err) {
    throw databaseError(err);
  }
});
