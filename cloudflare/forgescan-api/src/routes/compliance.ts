import { Hono } from 'hono';
import type { Env } from '../index';
import { requireRole } from '../middleware/auth';
import { seedFrameworks, getFrameworkCompliance, getGapAnalysis } from '../services/compliance';

interface AuthUser {
  id: string;
  email: string;
  role: string;
  display_name: string;
}

export const compliance = new Hono<{ Bindings: Env; Variables: { user: AuthUser } }>();

// GET /api/v1/compliance - List all frameworks with compliance stats
compliance.get('/', async (c) => {
  const result = await c.env.DB.prepare(
    'SELECT * FROM compliance_frameworks ORDER BY name'
  ).all();

  const frameworks = [];
  for (const fw of result.results || []) {
    const stats = await getFrameworkCompliance(c.env.DB, fw.id as string);
    frameworks.push({ ...fw, compliance_percentage: stats.compliance_percentage });
  }

  return c.json({ data: frameworks });
});

// GET /api/v1/compliance/mappings - List compliance mappings with filtering
compliance.get('/mappings', async (c) => {
  const {
    framework_id,
    status,
    finding_id,
    limit = '50',
    offset = '0',
  } = c.req.query();

  let query = `
    SELECT cm.*, cc.control_id as control_code, cc.name as control_name, cc.family,
           cf.name as framework_name
    FROM compliance_mappings cm
    LEFT JOIN compliance_controls cc ON cm.control_id = cc.id
    LEFT JOIN compliance_frameworks cf ON cm.framework_id = cf.id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (framework_id) {
    query += ' AND cm.framework_id = ?';
    params.push(framework_id);
  }
  if (status) {
    query += ' AND cm.status = ?';
    params.push(status);
  }
  if (finding_id) {
    query += ' AND cm.finding_id = ?';
    params.push(finding_id);
  }

  query += ' ORDER BY cm.created_at DESC LIMIT ? OFFSET ?';
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

// GET /api/v1/compliance/:id - Get framework detail with all controls
compliance.get('/:id', async (c) => {
  const id = c.req.param('id');

  const framework = await c.env.DB.prepare(
    'SELECT * FROM compliance_frameworks WHERE id = ?'
  ).bind(id).first();

  if (!framework) {
    return c.json({ error: 'Framework not found' }, 404);
  }

  const controls = await c.env.DB.prepare(
    'SELECT * FROM compliance_controls WHERE framework_id = ? ORDER BY family, control_id'
  ).bind(id).all();

  const stats = await getFrameworkCompliance(c.env.DB, id);

  return c.json({
    ...framework,
    controls: controls.results,
    stats,
  });
});

// GET /api/v1/compliance/:id/controls - Get controls with compliance status
compliance.get('/:id/controls', async (c) => {
  const id = c.req.param('id');

  const controls = await c.env.DB.prepare(`
    SELECT cc.*,
      cm.status as compliance_status,
      cm.evidence,
      cm.assessed_at,
      cm.assessed_by
    FROM compliance_controls cc
    LEFT JOIN compliance_mappings cm ON cc.id = cm.control_id AND cm.framework_id = ?
    WHERE cc.framework_id = ?
    ORDER BY cc.family, cc.control_id
  `).bind(id, id).all();

  return c.json({ data: controls.results });
});

// GET /api/v1/compliance/:id/gaps - Get gap analysis
compliance.get('/:id/gaps', async (c) => {
  const id = c.req.param('id');

  const framework = await c.env.DB.prepare(
    'SELECT * FROM compliance_frameworks WHERE id = ?'
  ).bind(id).first();

  if (!framework) {
    return c.json({ error: 'Framework not found' }, 404);
  }

  const gaps = await getGapAnalysis(c.env.DB, id);

  return c.json({
    framework,
    gaps,
  });
});

// POST /api/v1/compliance/seed - Seed frameworks (platform_admin only)
compliance.post('/seed', requireRole('platform_admin'), async (c) => {
  try {
    const result = await seedFrameworks(c.env.DB);
    return c.json({
      message: 'Compliance frameworks seeded successfully',
      ...result,
    });
  } catch (err) {
    return c.json({
      error: 'Failed to seed frameworks',
      message: err instanceof Error ? err.message : 'Unknown error',
    }, 500);
  }
});

// POST /api/v1/compliance/assess - Create/update compliance mapping
compliance.post('/assess', requireRole('platform_admin', 'scan_admin'), async (c) => {
  const body = await c.req.json();
  const { framework_id, control_id, status, finding_id, vulnerability_id, evidence } = body;

  if (!framework_id || !control_id || !status) {
    return c.json({ error: 'framework_id, control_id, and status are required' }, 400);
  }

  const validStatuses = ['compliant', 'non_compliant', 'partial', 'not_assessed'];
  if (!validStatuses.includes(status)) {
    return c.json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` }, 400);
  }

  const user = c.get('user');

  // Check if mapping already exists
  const existing = await c.env.DB.prepare(
    'SELECT id FROM compliance_mappings WHERE framework_id = ? AND control_id = ?'
  ).bind(framework_id, control_id).first<{ id: string }>();

  if (existing) {
    await c.env.DB.prepare(`
      UPDATE compliance_mappings SET
        status = ?,
        finding_id = ?,
        vulnerability_id = ?,
        evidence = ?,
        assessed_by = ?,
        assessed_at = datetime('now'),
        updated_at = datetime('now')
      WHERE id = ?
    `).bind(status, finding_id || null, vulnerability_id || null, evidence || null, user.id, existing.id).run();

    return c.json({ id: existing.id, message: 'Compliance mapping updated' });
  }

  const id = crypto.randomUUID();
  await c.env.DB.prepare(`
    INSERT INTO compliance_mappings (
      id, framework_id, control_id, status, finding_id, vulnerability_id,
      evidence, assessed_by, assessed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).bind(id, framework_id, control_id, status, finding_id || null, vulnerability_id || null, evidence || null, user.id).run();

  return c.json({ id, message: 'Compliance mapping created' }, 201);
});
