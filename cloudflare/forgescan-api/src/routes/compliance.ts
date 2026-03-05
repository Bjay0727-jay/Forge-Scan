import { Hono } from 'hono';
import type { Env } from '../index';
import { requireRole } from '../middleware/auth';
import { seedFrameworks, getFrameworkCompliance, getGapAnalysis } from '../services/compliance';
import { getOrgFilter, getOrgIdForInsert } from '../middleware/org-scope';
import {
  generateSSP,
  generateAssessmentResults,
  generatePOAMDocument,
  oscalJsonToXml,
} from '../services/oscal-generator';

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
  const { orgId } = getOrgFilter(c);
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

  if (orgId) {
    query += ' AND cm.org_id = ?';
    params.push(orgId);
  }
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
  const { orgId } = getOrgFilter(c);
  const id = c.req.param('id');

  let controlsQuery = `
    SELECT cc.*,
      cm.status as compliance_status,
      cm.evidence,
      cm.assessed_at,
      cm.assessed_by
    FROM compliance_controls cc
    LEFT JOIN compliance_mappings cm ON cc.id = cm.control_id AND cm.framework_id = ?`;
  const controlsParams: any[] = [id];

  if (orgId) {
    controlsQuery += ' AND cm.org_id = ?';
    controlsParams.push(orgId);
  }

  controlsQuery += `
    WHERE cc.framework_id = ?
    ORDER BY cc.family, cc.control_id`;
  controlsParams.push(id);

  const controls = await c.env.DB.prepare(controlsQuery).bind(...controlsParams).all();

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
  const { orgId } = getOrgFilter(c);
  const orgIdForInsert = getOrgIdForInsert(c);

  // Check if mapping already exists
  let existingQuery = 'SELECT id FROM compliance_mappings WHERE framework_id = ? AND control_id = ?';
  const existingParams: any[] = [framework_id, control_id];
  if (orgId) {
    existingQuery += ' AND org_id = ?';
    existingParams.push(orgId);
  }
  const existing = await c.env.DB.prepare(existingQuery).bind(...existingParams).first<{ id: string }>();

  if (existing) {
    let updateQuery = `
      UPDATE compliance_mappings SET
        status = ?,
        finding_id = ?,
        vulnerability_id = ?,
        evidence = ?,
        assessed_by = ?,
        assessed_at = datetime('now'),
        updated_at = datetime('now')
      WHERE id = ?`;
    const updateParams: any[] = [status, finding_id || null, vulnerability_id || null, evidence || null, user.id, existing.id];
    if (orgId) {
      updateQuery += ' AND org_id = ?';
      updateParams.push(orgId);
    }
    await c.env.DB.prepare(updateQuery).bind(...updateParams).run();

    return c.json({ id: existing.id, message: 'Compliance mapping updated' });
  }

  const id = crypto.randomUUID();
  await c.env.DB.prepare(`
    INSERT INTO compliance_mappings (
      id, framework_id, control_id, status, finding_id, vulnerability_id,
      evidence, assessed_by, assessed_at, org_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
  `).bind(id, framework_id, control_id, status, finding_id || null, vulnerability_id || null, evidence || null, user.id, orgIdForInsert).run();

  return c.json({ id, message: 'Compliance mapping created' }, 201);
});

// ─── OSCAL Exports ──────────────────────────────────────────────────────────

// GET /api/v1/compliance/:id/oscal/ssp - Generate OSCAL SSP
compliance.get('/:id/oscal/ssp', async (c) => {
  const { orgId } = getOrgFilter(c);
  const id = c.req.param('id');
  const format = c.req.query('format') || 'json'; // 'json' or 'xml'

  const framework = await c.env.DB.prepare(
    'SELECT * FROM compliance_frameworks WHERE id = ?'
  ).bind(id).first<{ id: string; name: string; version: string; description: string }>();

  if (!framework) {
    return c.json({ error: 'Framework not found' }, 404);
  }

  // Get controls with compliance status
  let controlsQuery = `
    SELECT cc.*, cm.status as compliance_status, cm.evidence, cm.assessed_at, cm.assessed_by
    FROM compliance_controls cc
    LEFT JOIN compliance_mappings cm ON cc.id = cm.control_id AND cm.framework_id = ?`;
  const controlsParams: any[] = [id];
  if (orgId) {
    controlsQuery += ' AND cm.org_id = ?';
    controlsParams.push(orgId);
  }
  controlsQuery += ' WHERE cc.framework_id = ? ORDER BY cc.family, cc.control_id';
  controlsParams.push(id);

  const controls = await c.env.DB.prepare(controlsQuery).bind(...controlsParams).all();

  // Get org name
  let orgName = 'Organization';
  if (orgId) {
    const org = await c.env.DB.prepare('SELECT name FROM organizations WHERE id = ?').bind(orgId).first<{ name: string }>();
    if (org) orgName = org.name;
  }

  // Enrich controls with auto-generated evidence from scan events
  const enrichedControls = controls.results as any[];
  if (orgId) {
    try {
      const autoEvidence = await c.env.DB.prepare(`
        SELECT cel.control_id, cel.description, cel.created_at, fe.event_type
        FROM compliance_evidence_links cel
        LEFT JOIN forge_events fe ON cel.event_id = fe.id
        WHERE cel.org_id = ? AND cel.control_id IS NOT NULL
        ORDER BY cel.created_at DESC
      `).bind(orgId).all<{ control_id: string; description: string; created_at: string; event_type: string }>();

      // Group evidence by control_id
      const evidenceByControl = new Map<string, string[]>();
      for (const ev of autoEvidence.results || []) {
        if (!ev.control_id) continue;
        const list = evidenceByControl.get(ev.control_id) || [];
        list.push(`[${ev.created_at}] ${ev.description}`);
        evidenceByControl.set(ev.control_id, list);
      }

      // Merge into controls that lack manual evidence
      for (const ctrl of enrichedControls) {
        const autoEv = evidenceByControl.get(ctrl.control_id);
        if (autoEv && !ctrl.evidence) {
          ctrl.evidence = `Auto-generated scan evidence:\n${autoEv.slice(0, 5).join('\n')}`;
        }
      }
    } catch { /* compliance_evidence_links table may not exist yet */ }
  }

  const ssp = generateSSP(framework, enrichedControls, orgName);

  if (format === 'xml') {
    return new Response(oscalJsonToXml(ssp), {
      headers: {
        'Content-Type': 'application/xml',
        'Content-Disposition': `attachment; filename="ssp-${framework.name}.xml"`,
      },
    });
  }

  return c.json(ssp);
});

// GET /api/v1/compliance/:id/oscal/assessment - Generate OSCAL Assessment Results
compliance.get('/:id/oscal/assessment', async (c) => {
  const { orgId } = getOrgFilter(c);
  const id = c.req.param('id');
  const format = c.req.query('format') || 'json';

  const framework = await c.env.DB.prepare(
    'SELECT * FROM compliance_frameworks WHERE id = ?'
  ).bind(id).first<{ id: string; name: string; version: string; description: string }>();

  if (!framework) {
    return c.json({ error: 'Framework not found' }, 404);
  }

  // Get controls
  let controlsQuery = `
    SELECT cc.*, cm.status as compliance_status, cm.evidence, cm.assessed_at, cm.assessed_by
    FROM compliance_controls cc
    LEFT JOIN compliance_mappings cm ON cc.id = cm.control_id AND cm.framework_id = ?`;
  const controlsParams: any[] = [id];
  if (orgId) {
    controlsQuery += ' AND cm.org_id = ?';
    controlsParams.push(orgId);
  }
  controlsQuery += ' WHERE cc.framework_id = ?';
  controlsParams.push(id);
  const controls = await c.env.DB.prepare(controlsQuery).bind(...controlsParams).all();

  // Get open findings for this org
  let findingsQuery = "SELECT id, title, description, severity, state, cve_id FROM findings WHERE state = 'open'";
  const findingsParams: any[] = [];
  if (orgId) {
    findingsQuery += ' AND org_id = ?';
    findingsParams.push(orgId);
  }
  findingsQuery += ' LIMIT 500';
  const findings = await c.env.DB.prepare(findingsQuery).bind(...findingsParams).all();

  let orgName = 'Organization';
  if (orgId) {
    const org = await c.env.DB.prepare('SELECT name FROM organizations WHERE id = ?').bind(orgId).first<{ name: string }>();
    if (org) orgName = org.name;
  }

  const assessment = generateAssessmentResults(
    framework, controls.results as any[], findings.results as any[], orgName,
  );

  if (format === 'xml') {
    return new Response(oscalJsonToXml(assessment), {
      headers: {
        'Content-Type': 'application/xml',
        'Content-Disposition': `attachment; filename="assessment-${framework.name}.xml"`,
      },
    });
  }

  return c.json(assessment);
});

// GET /api/v1/compliance/oscal/poam - Generate OSCAL POA&M document
compliance.get('/oscal/poam', async (c) => {
  const { orgId } = getOrgFilter(c);
  const format = c.req.query('format') || 'json';

  let query = "SELECT * FROM poam_items WHERE status != 'completed'";
  const params: any[] = [];
  if (orgId) {
    query += ' AND org_id = ?';
    params.push(orgId);
  }
  query += ' ORDER BY created_at DESC';

  const poamItems = await c.env.DB.prepare(query).bind(...params).all();

  let orgName = 'Organization';
  if (orgId) {
    const org = await c.env.DB.prepare('SELECT name FROM organizations WHERE id = ?').bind(orgId).first<{ name: string }>();
    if (org) orgName = org.name;
  }

  const poamDoc = generatePOAMDocument(poamItems.results as any[], orgName);

  if (format === 'xml') {
    return new Response(oscalJsonToXml(poamDoc), {
      headers: {
        'Content-Type': 'application/xml',
        'Content-Disposition': `attachment; filename="poam.xml"`,
      },
    });
  }

  return c.json(poamDoc);
});

// GET /api/v1/compliance/evidence/auto - List auto-generated compliance evidence links
compliance.get('/evidence/auto', async (c) => {
  const { orgId } = getOrgFilter(c);
  const { limit = '50', offset = '0', control_id } = c.req.query();

  let query = `
    SELECT cel.*, fe.event_type, fe.source, fe.payload
    FROM compliance_evidence_links cel
    LEFT JOIN forge_events fe ON cel.event_id = fe.id
    WHERE 1=1`;
  const params: any[] = [];

  if (orgId) {
    query += ' AND cel.org_id = ?';
    params.push(orgId);
  }
  if (control_id) {
    query += ' AND cel.control_id = ?';
    params.push(control_id);
  }

  query += ' ORDER BY cel.created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));

  const result = await c.env.DB.prepare(query).bind(...params).all();

  return c.json({
    data: (result.results || []).map((r: any) => ({
      ...r,
      payload: r.payload ? (typeof r.payload === 'string' ? JSON.parse(r.payload) : r.payload) : null,
    })),
    pagination: { limit: parseInt(limit), offset: parseInt(offset) },
  });
});
