/**
 * POA&M (Plan of Action & Milestones) Routes
 *
 * CRUD for POA&M items plus automation pipeline that generates
 * POA&M entries from scan findings using CWE-to-control mapping.
 */
import { Hono } from 'hono';
import type { Env } from '../index';
import { badRequest, notFound, databaseError } from '../lib/errors';
import { getOrgFilter, getOrgIdForInsert } from '../middleware/org-scope';
import { parsePositiveInt } from '../lib/validate';
import { generatePOAMEntry } from '../services/compliance-core/mapping';

interface AuthUser {
  id: string;
  email: string;
  role: string;
}

export const poam = new Hono<{ Bindings: Env; Variables: { user: AuthUser } }>();

// ─── List POA&M items ───────────────────────────────────────────────────────

poam.get('/', async (c) => {
  const { orgId } = getOrgFilter(c);
  const { limit = '20', offset = '0', status, severity } = c.req.query();
  const limitNum = parsePositiveInt(limit, 20);
  const offsetNum = parseInt(offset) || 0;

  let query = 'SELECT * FROM poam_items WHERE 1=1';
  const params: any[] = [];

  if (orgId) {
    query += ' AND org_id = ?';
    params.push(orgId);
  }
  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }
  if (severity) {
    query += ' AND severity = ?';
    params.push(severity);
  }

  // Get total count
  const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
  const countResult = await c.env.DB.prepare(countQuery).bind(...params).first<{ total: number }>();

  query += ' ORDER BY CASE severity WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 ELSE 4 END, created_at DESC LIMIT ? OFFSET ?';
  params.push(limitNum, offsetNum);

  const result = await c.env.DB.prepare(query).bind(...params).all();

  return c.json({
    data: result.results,
    pagination: {
      total: countResult?.total || 0,
      limit: limitNum,
      offset: offsetNum,
    },
  });
});

// ─── Get POA&M item by ID ───────────────────────────────────────────────────

poam.get('/:id', async (c) => {
  const id = c.req.param('id');
  const { orgId } = getOrgFilter(c);

  const query = orgId
    ? 'SELECT * FROM poam_items WHERE id = ? AND org_id = ?'
    : 'SELECT * FROM poam_items WHERE id = ?';
  const params = orgId ? [id, orgId] : [id];

  const item = await c.env.DB.prepare(query).bind(...params).first();
  if (!item) {
    throw notFound('POA&M item', id);
  }

  return c.json(item);
});

// ─── Create POA&M item ──────────────────────────────────────────────────────

poam.post('/', async (c) => {
  const orgId = getOrgIdForInsert(c);
  const user = c.get('user');
  const body = await c.req.json();

  const {
    finding_id, finding_title, weakness, severity, controls,
    remediation, remediation_effort, scheduled_completion,
    milestones, assigned_to, notes,
  } = body;

  if (!finding_title || !severity) {
    throw badRequest('finding_title and severity are required');
  }

  const id = crypto.randomUUID();

  await c.env.DB.prepare(`
    INSERT INTO poam_items (
      id, org_id, finding_id, finding_title, weakness, severity, controls,
      remediation, remediation_effort, scheduled_completion, status,
      milestones, assigned_to, notes, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)
  `).bind(
    id, orgId, finding_id || null, finding_title,
    weakness || 'Unclassified', severity,
    controls ? JSON.stringify(controls) : '[]',
    remediation || 'Pending assessment',
    remediation_effort || 'moderate',
    scheduled_completion || null,
    milestones ? JSON.stringify(milestones) : '[]',
    assigned_to || null, notes || null,
    user.id,
  ).run();

  return c.json({ id, message: 'POA&M item created' }, 201);
});

// ─── Update POA&M item ──────────────────────────────────────────────────────

poam.patch('/:id', async (c) => {
  const id = c.req.param('id');
  const { orgId } = getOrgFilter(c);
  const body = await c.req.json();

  const checkQuery = orgId
    ? 'SELECT id FROM poam_items WHERE id = ? AND org_id = ?'
    : 'SELECT id FROM poam_items WHERE id = ?';
  const checkParams = orgId ? [id, orgId] : [id];

  const existing = await c.env.DB.prepare(checkQuery).bind(...checkParams).first();
  if (!existing) {
    throw notFound('POA&M item', id);
  }

  const updates: string[] = [];
  const updateParams: any[] = [];

  const fields: Record<string, (v: any) => any> = {
    finding_title: (v) => v,
    weakness: (v) => v,
    severity: (v) => v,
    remediation: (v) => v,
    remediation_effort: (v) => v,
    scheduled_completion: (v) => v,
    status: (v) => v,
    assigned_to: (v) => v,
    notes: (v) => v,
  };

  for (const [field, transform] of Object.entries(fields)) {
    if (body[field] !== undefined) {
      updates.push(`${field} = ?`);
      updateParams.push(transform(body[field]));
    }
  }

  if (body.controls !== undefined) {
    updates.push('controls = ?');
    updateParams.push(JSON.stringify(body.controls));
  }
  if (body.milestones !== undefined) {
    updates.push('milestones = ?');
    updateParams.push(JSON.stringify(body.milestones));
  }

  // Auto-set closed_at when status changes to completed
  if (body.status === 'completed') {
    updates.push("closed_at = datetime('now')");
  } else if (body.status && body.status !== 'completed') {
    updates.push('closed_at = NULL');
  }

  if (updates.length === 0) {
    throw badRequest('No fields to update');
  }

  updates.push("updated_at = datetime('now')");
  updateParams.push(id);
  if (orgId) updateParams.push(orgId);

  const updateQuery = `UPDATE poam_items SET ${updates.join(', ')} WHERE id = ?${orgId ? ' AND org_id = ?' : ''}`;
  await c.env.DB.prepare(updateQuery).bind(...updateParams).run();

  return c.json({ id, message: 'POA&M item updated' });
});

// ─── Delete POA&M item ──────────────────────────────────────────────────────

poam.delete('/:id', async (c) => {
  const id = c.req.param('id');
  const { orgId } = getOrgFilter(c);

  const query = orgId
    ? 'DELETE FROM poam_items WHERE id = ? AND org_id = ?'
    : 'DELETE FROM poam_items WHERE id = ?';
  const params = orgId ? [id, orgId] : [id];

  const result = await c.env.DB.prepare(query).bind(...params).run();
  if (!result.meta.changes) {
    throw notFound('POA&M item', id);
  }

  return c.json({ message: 'POA&M item deleted' });
});

// ─── POA&M Statistics ───────────────────────────────────────────────────────

poam.get('/stats/summary', async (c) => {
  const { orgId } = getOrgFilter(c);

  const orgClause = orgId ? ' AND org_id = ?' : '';
  const params = orgId ? [orgId] : [];

  const [byStatus, bySeverity, overdue] = await Promise.all([
    c.env.DB.prepare(
      `SELECT status, COUNT(*) as count FROM poam_items WHERE 1=1${orgClause} GROUP BY status`
    ).bind(...params).all(),
    c.env.DB.prepare(
      `SELECT severity, COUNT(*) as count FROM poam_items WHERE 1=1${orgClause} GROUP BY severity`
    ).bind(...params).all(),
    c.env.DB.prepare(
      `SELECT COUNT(*) as count FROM poam_items WHERE status NOT IN ('completed') AND scheduled_completion < date('now')${orgClause}`
    ).bind(...params).first<{ count: number }>(),
  ]);

  return c.json({
    by_status: byStatus.results,
    by_severity: bySeverity.results,
    overdue_count: overdue?.count || 0,
  });
});

// ─── Auto-generate POA&M from findings ──────────────────────────────────────

poam.post('/generate', async (c) => {
  const orgId = getOrgIdForInsert(c);
  const user = c.get('user');
  const body = await c.req.json();

  const { finding_ids, scan_id, severity_filter } = body;

  // Build query to get findings
  let findingsQuery = "SELECT id, title, severity, cve_id, solution, metadata FROM findings WHERE state = 'open'";
  const findingsParams: any[] = [];

  findingsQuery += ' AND org_id = ?';
  findingsParams.push(orgId);

  if (finding_ids && Array.isArray(finding_ids) && finding_ids.length > 0) {
    findingsQuery += ` AND id IN (${finding_ids.map(() => '?').join(',')})`;
    findingsParams.push(...finding_ids);
  }

  if (scan_id) {
    findingsQuery += ' AND scan_id = ?';
    findingsParams.push(scan_id);
  }

  if (severity_filter && Array.isArray(severity_filter)) {
    findingsQuery += ` AND severity IN (${severity_filter.map(() => '?').join(',')})`;
    findingsParams.push(...severity_filter);
  }

  findingsQuery += ' ORDER BY CASE severity WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 ELSE 4 END';

  const findingsResult = await c.env.DB.prepare(findingsQuery).bind(...findingsParams).all<{
    id: string; title: string; severity: string; cve_id: string; solution: string; metadata: string;
  }>();

  const findings = findingsResult.results || [];
  let created = 0;
  let skipped = 0;
  const errors: string[] = [];

  for (const finding of findings) {
    try {
      // Check if POA&M already exists for this finding
      const existing = await c.env.DB.prepare(
        'SELECT id FROM poam_items WHERE finding_id = ? AND org_id = ? AND status != \'completed\''
      ).bind(finding.id, orgId).first();

      if (existing) {
        skipped++;
        continue;
      }

      // Extract CWE from metadata if available
      let metadata: any = {};
      try { metadata = JSON.parse(finding.metadata || '{}'); } catch { /* empty */ }
      const cweId = metadata.cwe || metadata.cwe_id || null;

      // Generate POA&M entry using compliance mapping
      const poamEntry = generatePOAMEntry({
        id: finding.id,
        title: finding.title,
        cwe_id: cweId,
        severity: finding.severity,
        remediation: finding.solution,
      });

      await c.env.DB.prepare(`
        INSERT INTO poam_items (
          id, org_id, finding_id, finding_title, weakness, severity, controls,
          remediation, remediation_effort, scheduled_completion, status,
          milestones, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
      `).bind(
        poamEntry.id, orgId, finding.id, poamEntry.finding_title,
        poamEntry.weakness, poamEntry.severity,
        JSON.stringify(poamEntry.controls),
        poamEntry.remediation, poamEntry.remediation_effort,
        poamEntry.scheduled_completion,
        JSON.stringify(poamEntry.milestones),
        user.id,
      ).run();

      created++;
    } catch (err) {
      errors.push(`Finding "${finding.title}": ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return c.json({
    findings_processed: findings.length,
    poam_created: created,
    poam_skipped: skipped,
    errors: errors.slice(0, 10),
  });
});
