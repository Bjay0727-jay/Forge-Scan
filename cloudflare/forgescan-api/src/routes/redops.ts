import { Hono } from 'hono';
import type { Env } from '../index';
import { notFound, badRequest, databaseError } from '../lib/errors';
import { requireField, parsePagination, validateSortOrder } from '../lib/validate';

export const redops = new Hono<{ Bindings: Env }>();

// ─────────────────────────────────────────────────────────────────────────────
// CAMPAIGNS
// ─────────────────────────────────────────────────────────────────────────────

// List campaigns
redops.get('/campaigns', async (c) => {
  const { page, pageSize } = parsePagination(c.req.query('page'), c.req.query('page_size'));
  const status = c.req.query('status');
  const campaignType = c.req.query('type');
  const sort = validateSortOrder(c.req.query('sort'));

  let query = 'SELECT COUNT(*) as total FROM redops_campaigns WHERE 1=1';
  let dataQuery = 'SELECT * FROM redops_campaigns WHERE 1=1';
  const params: unknown[] = [];
  const countParams: unknown[] = [];

  if (status) {
    query += ' AND status = ?';
    dataQuery += ' AND status = ?';
    params.push(status);
    countParams.push(status);
  }

  if (campaignType) {
    query += ' AND campaign_type = ?';
    dataQuery += ' AND campaign_type = ?';
    params.push(campaignType);
    countParams.push(campaignType);
  }

  dataQuery += ` ORDER BY created_at ${sort} LIMIT ? OFFSET ?`;
  params.push(pageSize, (page - 1) * pageSize);

  try {
    const [countResult, dataResult] = await Promise.all([
      c.env.DB.prepare(query).bind(...countParams).first<{ total: number }>(),
      c.env.DB.prepare(dataQuery).bind(...params).all(),
    ]);

    const total = countResult?.total ?? 0;

    return c.json({
      items: dataResult.results,
      total,
      page,
      page_size: pageSize,
      total_pages: Math.ceil(total / pageSize),
    });
  } catch (err) {
    throw databaseError(err);
  }
});

// Get campaign by ID
redops.get('/campaigns/:id', async (c) => {
  const id = c.req.param('id');

  try {
    const campaign = await c.env.DB.prepare(
      'SELECT * FROM redops_campaigns WHERE id = ?'
    ).bind(id).first();

    if (!campaign) throw notFound('Campaign', id);
    return c.json(campaign);
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// Create campaign
redops.post('/campaigns', async (c) => {
  const body = await c.req.json();
  const id = crypto.randomUUID();

  requireField(body.name, 'name');
  requireField(body.target_scope, 'target_scope');

  const agentCategories = body.agent_categories || ['web', 'api', 'cloud', 'network', 'identity'];
  const exploitationLevel = body.exploitation_level || 'safe';
  const campaignType = body.campaign_type || 'full';
  const maxConcurrent = body.max_concurrent_agents || 6;

  if (!['passive', 'safe', 'moderate', 'aggressive'].includes(exploitationLevel)) {
    throw badRequest('exploitation_level must be: passive, safe, moderate, or aggressive');
  }

  if (!['full', 'targeted', 'continuous', 'validation'].includes(campaignType)) {
    throw badRequest('campaign_type must be: full, targeted, continuous, or validation');
  }

  try {
    await c.env.DB.prepare(`
      INSERT INTO redops_campaigns (
        id, name, description, status, campaign_type,
        target_scope, exclusions, agent_categories,
        max_concurrent_agents, exploitation_level,
        risk_threshold, auto_poam, compliance_mapping,
        scheduled_at, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, 'created', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
    `).bind(
      id,
      body.name,
      body.description || null,
      campaignType,
      typeof body.target_scope === 'string' ? body.target_scope : JSON.stringify(body.target_scope),
      body.exclusions ? (typeof body.exclusions === 'string' ? body.exclusions : JSON.stringify(body.exclusions)) : null,
      JSON.stringify(agentCategories),
      maxConcurrent,
      exploitationLevel,
      body.risk_threshold || 'critical',
      body.auto_poam ? 1 : 0,
      body.compliance_mapping !== false ? 1 : 0,
      body.scheduled_at || null,
      body.created_by || null,
    ).run();

    const campaign = await c.env.DB.prepare(
      'SELECT * FROM redops_campaigns WHERE id = ?'
    ).bind(id).first();

    return c.json(campaign, 201);
  } catch (err) {
    throw databaseError(err);
  }
});

// Update campaign
redops.put('/campaigns/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  try {
    const existing = await c.env.DB.prepare(
      'SELECT * FROM redops_campaigns WHERE id = ?'
    ).bind(id).first();

    if (!existing) throw notFound('Campaign', id);

    // Only allow updates to non-running campaigns
    if (['reconnaissance', 'scanning', 'exploitation'].includes(existing.status as string)) {
      throw badRequest('Cannot update a campaign that is currently running');
    }

    const fields: string[] = [];
    const values: unknown[] = [];

    const updatable = ['name', 'description', 'campaign_type', 'target_scope', 'exclusions',
      'agent_categories', 'max_concurrent_agents', 'exploitation_level',
      'risk_threshold', 'auto_poam', 'compliance_mapping', 'scheduled_at'];

    for (const field of updatable) {
      if (body[field] !== undefined) {
        const value = typeof body[field] === 'object' ? JSON.stringify(body[field]) : body[field];
        fields.push(`${field} = ?`);
        values.push(value);
      }
    }

    if (fields.length === 0) throw badRequest('No fields to update');

    fields.push('updated_at = datetime(\'now\')');
    values.push(id);

    await c.env.DB.prepare(
      `UPDATE redops_campaigns SET ${fields.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    const updated = await c.env.DB.prepare(
      'SELECT * FROM redops_campaigns WHERE id = ?'
    ).bind(id).first();

    return c.json(updated);
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// Launch campaign (transition to queued -> start agents)
redops.post('/campaigns/:id/launch', async (c) => {
  const id = c.req.param('id');

  try {
    const campaign = await c.env.DB.prepare(
      'SELECT * FROM redops_campaigns WHERE id = ?'
    ).bind(id).first();

    if (!campaign) throw notFound('Campaign', id);

    if (campaign.status !== 'created' && campaign.status !== 'failed') {
      throw badRequest(`Campaign cannot be launched from status: ${campaign.status}`);
    }

    const categories: string[] = JSON.parse(campaign.agent_categories as string);

    // Look up agent types for the selected categories
    const agentTypes = await c.env.DB.prepare(
      `SELECT id, category FROM redops_agent_types WHERE category IN (${categories.map(() => '?').join(',')}) AND enabled = 1`
    ).bind(...categories).all();

    // Create agent instances
    let totalAgents = 0;
    for (const agentType of agentTypes.results) {
      const agentId = crypto.randomUUID();
      await c.env.DB.prepare(`
        INSERT INTO redops_agents (
          id, campaign_id, agent_type, agent_category, status,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'queued', datetime('now'), datetime('now'))
      `).bind(agentId, id, agentType.id, agentType.category).run();
      totalAgents++;
    }

    // Update campaign status
    await c.env.DB.prepare(`
      UPDATE redops_campaigns SET
        status = 'queued',
        total_agents = ?,
        started_at = datetime('now'),
        updated_at = datetime('now')
      WHERE id = ?
    `).bind(totalAgents, id).run();

    const updated = await c.env.DB.prepare(
      'SELECT * FROM redops_campaigns WHERE id = ?'
    ).bind(id).first();

    return c.json({
      campaign: updated,
      agents_created: totalAgents,
      message: `Campaign launched with ${totalAgents} agents across ${categories.length} categories`,
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// Cancel campaign
redops.post('/campaigns/:id/cancel', async (c) => {
  const id = c.req.param('id');

  try {
    const campaign = await c.env.DB.prepare(
      'SELECT * FROM redops_campaigns WHERE id = ?'
    ).bind(id).first();

    if (!campaign) throw notFound('Campaign', id);

    const runningStatuses = ['created', 'queued', 'reconnaissance', 'scanning', 'exploitation'];
    if (!runningStatuses.includes(campaign.status as string)) {
      throw badRequest(`Campaign cannot be cancelled from status: ${campaign.status}`);
    }

    // Stop all active agents
    await c.env.DB.prepare(`
      UPDATE redops_agents SET
        status = 'stopped',
        updated_at = datetime('now')
      WHERE campaign_id = ? AND status NOT IN ('completed', 'failed', 'stopped')
    `).bind(id).run();

    // Update campaign
    await c.env.DB.prepare(`
      UPDATE redops_campaigns SET
        status = 'cancelled',
        completed_at = datetime('now'),
        updated_at = datetime('now')
      WHERE id = ?
    `).bind(id).run();

    return c.json({ message: 'Campaign cancelled' });
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// Delete campaign
redops.delete('/campaigns/:id', async (c) => {
  const id = c.req.param('id');

  try {
    const campaign = await c.env.DB.prepare(
      'SELECT * FROM redops_campaigns WHERE id = ?'
    ).bind(id).first();

    if (!campaign) throw notFound('Campaign', id);

    const activeStatuses = ['reconnaissance', 'scanning', 'exploitation'];
    if (activeStatuses.includes(campaign.status as string)) {
      throw badRequest('Cannot delete a running campaign. Cancel it first.');
    }

    // CASCADE will handle agents and findings
    await c.env.DB.prepare('DELETE FROM redops_campaigns WHERE id = ?').bind(id).run();

    return c.json({ message: 'Campaign deleted' });
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AGENTS
// ─────────────────────────────────────────────────────────────────────────────

// List agents for a campaign
redops.get('/campaigns/:id/agents', async (c) => {
  const campaignId = c.req.param('id');
  const status = c.req.query('status');
  const category = c.req.query('category');

  let query = 'SELECT * FROM redops_agents WHERE campaign_id = ?';
  const params: unknown[] = [campaignId];

  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }

  if (category) {
    query += ' AND agent_category = ?';
    params.push(category);
  }

  query += ' ORDER BY agent_category, agent_type';

  try {
    const result = await c.env.DB.prepare(query).bind(...params).all();
    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});

// Get agent details
redops.get('/agents/:id', async (c) => {
  const id = c.req.param('id');

  try {
    const agent = await c.env.DB.prepare(
      'SELECT * FROM redops_agents WHERE id = ?'
    ).bind(id).first();

    if (!agent) throw notFound('Agent', id);
    return c.json(agent);
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// Get all agent type definitions
redops.get('/agent-types', async (c) => {
  const category = c.req.query('category');

  let query = 'SELECT * FROM redops_agent_types WHERE 1=1';
  const params: unknown[] = [];

  if (category) {
    query += ' AND category = ?';
    params.push(category);
  }

  query += ' ORDER BY category, id';

  try {
    const result = await c.env.DB.prepare(query).bind(...params).all();
    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDINGS
// ─────────────────────────────────────────────────────────────────────────────

// List findings for a campaign
redops.get('/campaigns/:id/findings', async (c) => {
  const campaignId = c.req.param('id');
  const { page, pageSize } = parsePagination(c.req.query('page'), c.req.query('page_size'));
  const severity = c.req.query('severity');
  const exploitable = c.req.query('exploitable');
  const status = c.req.query('status');

  let countQuery = 'SELECT COUNT(*) as total FROM redops_findings WHERE campaign_id = ?';
  let dataQuery = 'SELECT * FROM redops_findings WHERE campaign_id = ?';
  const countParams: unknown[] = [campaignId];
  const params: unknown[] = [campaignId];

  if (severity) {
    countQuery += ' AND severity = ?';
    dataQuery += ' AND severity = ?';
    countParams.push(severity);
    params.push(severity);
  }

  if (exploitable !== undefined) {
    countQuery += ' AND exploitable = ?';
    dataQuery += ' AND exploitable = ?';
    const val = exploitable === 'true' ? 1 : 0;
    countParams.push(val);
    params.push(val);
  }

  if (status) {
    countQuery += ' AND status = ?';
    dataQuery += ' AND status = ?';
    countParams.push(status);
    params.push(status);
  }

  dataQuery += ' ORDER BY CASE severity WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 ELSE 4 END, exploitable DESC LIMIT ? OFFSET ?';
  params.push(pageSize, (page - 1) * pageSize);

  try {
    const [countResult, dataResult] = await Promise.all([
      c.env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>(),
      c.env.DB.prepare(dataQuery).bind(...params).all(),
    ]);

    const total = countResult?.total ?? 0;

    return c.json({
      items: dataResult.results,
      total,
      page,
      page_size: pageSize,
      total_pages: Math.ceil(total / pageSize),
    });
  } catch (err) {
    throw databaseError(err);
  }
});

// Get all findings across campaigns (global view)
redops.get('/findings', async (c) => {
  const { page, pageSize } = parsePagination(c.req.query('page'), c.req.query('page_size'));
  const severity = c.req.query('severity');
  const exploitable = c.req.query('exploitable');
  const status = c.req.query('status');

  let countQuery = 'SELECT COUNT(*) as total FROM redops_findings WHERE 1=1';
  let dataQuery = `SELECT f.*, c.name as campaign_name
    FROM redops_findings f
    LEFT JOIN redops_campaigns c ON f.campaign_id = c.id
    WHERE 1=1`;
  const countParams: unknown[] = [];
  const params: unknown[] = [];

  if (severity) {
    countQuery += ' AND severity = ?';
    dataQuery += ' AND f.severity = ?';
    countParams.push(severity);
    params.push(severity);
  }

  if (exploitable !== undefined) {
    const val = exploitable === 'true' ? 1 : 0;
    countQuery += ' AND exploitable = ?';
    dataQuery += ' AND f.exploitable = ?';
    countParams.push(val);
    params.push(val);
  }

  if (status) {
    countQuery += ' AND status = ?';
    dataQuery += ' AND f.status = ?';
    countParams.push(status);
    params.push(status);
  }

  dataQuery += ' ORDER BY CASE f.severity WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 ELSE 4 END, f.exploitable DESC LIMIT ? OFFSET ?';
  params.push(pageSize, (page - 1) * pageSize);

  try {
    const [countResult, dataResult] = await Promise.all([
      c.env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>(),
      c.env.DB.prepare(dataQuery).bind(...params).all(),
    ]);

    const total = countResult?.total ?? 0;

    return c.json({
      items: dataResult.results,
      total,
      page,
      page_size: pageSize,
      total_pages: Math.ceil(total / pageSize),
    });
  } catch (err) {
    throw databaseError(err);
  }
});

// Update finding status
redops.put('/findings/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  try {
    const existing = await c.env.DB.prepare(
      'SELECT * FROM redops_findings WHERE id = ?'
    ).bind(id).first();

    if (!existing) throw notFound('Finding', id);

    const fields: string[] = [];
    const values: unknown[] = [];

    const updatable = ['status', 'remediation', 'remediation_effort'];
    for (const field of updatable) {
      if (body[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(body[field]);
      }
    }

    if (fields.length === 0) throw badRequest('No fields to update');

    fields.push('updated_at = datetime(\'now\')');
    values.push(id);

    await c.env.DB.prepare(
      `UPDATE redops_findings SET ${fields.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    const updated = await c.env.DB.prepare(
      'SELECT * FROM redops_findings WHERE id = ?'
    ).bind(id).first();

    return c.json(updated);
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD / STATS
// ─────────────────────────────────────────────────────────────────────────────

// RedOPS overview stats
redops.get('/overview', async (c) => {
  try {
    const [campaigns, findings, agentStats, recentCampaigns] = await Promise.all([
      c.env.DB.prepare(`
        SELECT
          COUNT(*) as total_campaigns,
          SUM(CASE WHEN status IN ('reconnaissance', 'scanning', 'exploitation') THEN 1 ELSE 0 END) as active_campaigns,
          SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_campaigns,
          SUM(findings_count) as total_findings,
          SUM(exploitable_count) as total_exploitable
        FROM redops_campaigns
      `).first(),

      c.env.DB.prepare(`
        SELECT
          severity,
          COUNT(*) as count,
          SUM(CASE WHEN exploitable = 1 THEN 1 ELSE 0 END) as exploitable
        FROM redops_findings
        GROUP BY severity
      `).all(),

      c.env.DB.prepare(`
        SELECT
          agent_category,
          COUNT(*) as total,
          SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
          SUM(findings_count) as findings
        FROM redops_agents
        GROUP BY agent_category
      `).all(),

      c.env.DB.prepare(`
        SELECT id, name, status, campaign_type, findings_count, exploitable_count,
               critical_count, high_count, started_at, completed_at, created_at
        FROM redops_campaigns
        ORDER BY created_at DESC
        LIMIT 5
      `).all(),
    ]);

    // Build severity breakdown
    const severityBreakdown: Record<string, { count: number; exploitable: number }> = {
      critical: { count: 0, exploitable: 0 },
      high: { count: 0, exploitable: 0 },
      medium: { count: 0, exploitable: 0 },
      low: { count: 0, exploitable: 0 },
      info: { count: 0, exploitable: 0 },
    };

    for (const row of findings.results) {
      const sev = row.severity as string;
      if (severityBreakdown[sev]) {
        severityBreakdown[sev] = {
          count: row.count as number,
          exploitable: row.exploitable as number,
        };
      }
    }

    return c.json({
      campaigns: {
        total: campaigns?.total_campaigns ?? 0,
        active: campaigns?.active_campaigns ?? 0,
        completed: campaigns?.completed_campaigns ?? 0,
      },
      findings: {
        total: campaigns?.total_findings ?? 0,
        exploitable: campaigns?.total_exploitable ?? 0,
        severity_breakdown: severityBreakdown,
      },
      agents_by_category: agentStats.results,
      recent_campaigns: recentCampaigns.results,
      generated_at: new Date().toISOString(),
    });
  } catch (err) {
    throw databaseError(err);
  }
});
