import { Hono } from 'hono';

interface Env { DB: D1Database; STORAGE: R2Bucket; CACHE: KVNamespace; JWT_SECRET: string }
interface AuthUser { id: string; email: string; role: string; display_name: string }
type Ctx = { Bindings: Env; Variables: { user: AuthUser } };

const soar = new Hono<Ctx>();

// ─── Action Types ──────────────────────────────────────────────────────────

const ACTION_TYPES = [
  { type: 'isolate_host', label: 'Isolate Host', category: 'containment', description: 'Quarantine a host from the network' },
  { type: 'block_ip', label: 'Block IP Address', category: 'containment', description: 'Add IP to firewall blocklist' },
  { type: 'disable_user', label: 'Disable User Account', category: 'containment', description: 'Deactivate a compromised user account' },
  { type: 'create_ticket', label: 'Create Ticket', category: 'notification', description: 'Open a ticket in external ITSM system' },
  { type: 'send_notification', label: 'Send Notification', category: 'notification', description: 'Send alert via email/Slack/webhook' },
  { type: 'enrich_ioc', label: 'Enrich IOC', category: 'enrichment', description: 'Look up indicator in threat intel feeds' },
  { type: 'run_scan', label: 'Run Vulnerability Scan', category: 'investigation', description: 'Trigger a targeted scan on affected assets' },
  { type: 'update_alert', label: 'Update Alert Status', category: 'management', description: 'Change alert severity/status/assignment' },
  { type: 'escalate', label: 'Escalate to Incident', category: 'management', description: 'Promote alert to a full incident' },
  { type: 'webhook', label: 'Custom Webhook', category: 'integration', description: 'Call an external API endpoint' },
  { type: 'add_tag', label: 'Add Tag', category: 'management', description: 'Tag alerts/assets for tracking' },
  { type: 'wait', label: 'Wait / Delay', category: 'flow', description: 'Pause execution for a specified duration' },
  { type: 'condition', label: 'Conditional Branch', category: 'flow', description: 'Execute next steps only if condition is met' },
];

// ─── Pre-built Playbook Templates ──────────────────────────────────────────

const PLAYBOOK_TEMPLATES = [
  {
    name: 'Critical Vulnerability Response',
    description: 'Auto-triage and escalate critical vulnerabilities with enrichment',
    trigger_type: 'event_pattern',
    trigger_config: { event_pattern: 'forge.vulnerability.detected', severity_filter: 'critical' },
    steps: [
      { action_type: 'enrich_ioc', config: { lookup: 'cve_details', source: 'nvd' } },
      { action_type: 'update_alert', config: { status: 'triaged', priority: 1 } },
      { action_type: 'escalate', config: { incident_type: 'security', severity: 'critical' } },
      { action_type: 'send_notification', config: { channel: 'slack', message: 'CRITICAL: New vulnerability requires immediate attention' } },
      { action_type: 'create_ticket', config: { priority: 'urgent', template: 'vuln_response' } },
    ],
  },
  {
    name: 'Exploitation Detected — Contain & Investigate',
    description: 'Auto-isolate host and launch investigation when exploitation is confirmed',
    trigger_type: 'event_pattern',
    trigger_config: { event_pattern: 'forge.redops.exploitation.success' },
    steps: [
      { action_type: 'isolate_host', config: { reason: 'Confirmed exploitation detected' } },
      { action_type: 'escalate', config: { incident_type: 'security', severity: 'critical' } },
      { action_type: 'run_scan', config: { scan_type: 'targeted', scope: 'affected_assets' } },
      { action_type: 'send_notification', config: { channel: 'email', recipients: 'soc_team', message: 'Host isolated due to confirmed exploitation' } },
      { action_type: 'create_ticket', config: { priority: 'critical', template: 'incident_response' } },
    ],
  },
  {
    name: 'Threat Intel Match — Auto Enrich & Alert',
    description: 'When a threat intel indicator matches an asset, enrich and notify',
    trigger_type: 'event_pattern',
    trigger_config: { event_pattern: 'forge.threat_intel.match' },
    steps: [
      { action_type: 'enrich_ioc', config: { sources: ['virustotal', 'abuseipdb', 'shodan'] } },
      { action_type: 'add_tag', config: { tag: 'threat-intel-match' } },
      { action_type: 'update_alert', config: { status: 'investigating' } },
      { action_type: 'send_notification', config: { channel: 'slack', message: 'Threat intel indicator matched to internal asset' } },
    ],
  },
  {
    name: 'Alert Volume Spike — Anomaly Triage',
    description: 'When ForgeML detects an alert volume anomaly, auto-cluster and escalate',
    trigger_type: 'alert_threshold',
    trigger_config: { threshold_count: 20, threshold_window: 3600, severity_filter: 'high,critical' },
    steps: [
      { action_type: 'webhook', config: { url: '/api/v1/soc/ml/cluster', method: 'POST' } },
      { action_type: 'escalate', config: { incident_type: 'security', severity: 'high', title: 'Alert Volume Anomaly' } },
      { action_type: 'send_notification', config: { channel: 'email', recipients: 'soc_lead', message: 'Alert volume anomaly detected — auto-clustering initiated' } },
    ],
  },
  {
    name: 'Compliance Violation — Remediation Workflow',
    description: 'Auto-create remediation ticket when compliance control fails',
    trigger_type: 'event_pattern',
    trigger_config: { event_pattern: 'forge.compliance.control_failed' },
    steps: [
      { action_type: 'update_alert', config: { status: 'triaged', alert_type: 'compliance' } },
      { action_type: 'create_ticket', config: { priority: 'high', template: 'compliance_remediation' } },
      { action_type: 'send_notification', config: { channel: 'email', recipients: 'compliance_team' } },
      { action_type: 'add_tag', config: { tag: 'compliance-violation' } },
    ],
  },
];

// ─── Playbooks CRUD ────────────────────────────────────────────────────────

soar.get('/playbooks', async (c) => {
  const { page = '1', page_size = '25', enabled, trigger_type } = c.req.query();
  const pageNum = parseInt(page);
  const limit = Math.min(parseInt(page_size), 100);
  const offset = (pageNum - 1) * limit;

  const conditions: string[] = [];
  const params: (string | number)[] = [];
  if (enabled !== undefined) { conditions.push('enabled = ?'); params.push(enabled === 'true' ? 1 : 0); }
  if (trigger_type) { conditions.push('trigger_type = ?'); params.push(trigger_type); }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const total = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM soar_playbooks ${where}`).bind(...params).first<{ count: number }>();
  const playbooks = await c.env.DB.prepare(`
    SELECT * FROM soar_playbooks ${where} ORDER BY updated_at DESC LIMIT ? OFFSET ?
  `).bind(...params, limit, offset).all();

  return c.json({ items: playbooks.results || [], total: total?.count || 0, page: pageNum, page_size: limit, total_pages: Math.ceil((total?.count || 0) / limit) });
});

soar.post('/playbooks', async (c) => {
  try {
    const body = await c.req.json();
    const { name, description, trigger_type, trigger_config, steps, severity_filter, max_concurrent, cooldown_seconds } = body;
    if (!name || !trigger_type || !steps) return c.json({ error: 'name, trigger_type, and steps are required' }, 400);

    const user = c.get('user');
    const id = crypto.randomUUID();

    await c.env.DB.prepare(`
      INSERT INTO soar_playbooks (id, name, description, trigger_type, trigger_config, steps, severity_filter, max_concurrent, cooldown_seconds, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, name, description || null, trigger_type, JSON.stringify(trigger_config || {}), JSON.stringify(steps), severity_filter || null, max_concurrent || 5, cooldown_seconds || 300, user.id).run();

    const playbook = await c.env.DB.prepare('SELECT * FROM soar_playbooks WHERE id = ?').bind(id).first();
    return c.json(playbook, 201);
  } catch (err) {
    console.error('Create playbook error:', err);
    return c.json({ error: 'Failed to create playbook' }, 500);
  }
});

soar.get('/playbooks/:id', async (c) => {
  const id = c.req.param('id');
  const playbook = await c.env.DB.prepare('SELECT * FROM soar_playbooks WHERE id = ?').bind(id).first();
  if (!playbook) return c.json({ error: 'Playbook not found' }, 404);

  const executions = await c.env.DB.prepare(
    'SELECT * FROM soar_executions WHERE playbook_id = ? ORDER BY started_at DESC LIMIT 10'
  ).bind(id).all();

  return c.json({ ...playbook, recent_executions: executions.results || [] });
});

soar.put('/playbooks/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const body = await c.req.json();
    const { name, description, trigger_type, trigger_config, steps, severity_filter, enabled, max_concurrent, cooldown_seconds } = body;

    const existing = await c.env.DB.prepare('SELECT id FROM soar_playbooks WHERE id = ?').bind(id).first();
    if (!existing) return c.json({ error: 'Playbook not found' }, 404);

    const updates: string[] = [];
    const values: (string | number | null)[] = [];

    if (name !== undefined) { updates.push('name = ?'); values.push(name); }
    if (description !== undefined) { updates.push('description = ?'); values.push(description); }
    if (trigger_type !== undefined) { updates.push('trigger_type = ?'); values.push(trigger_type); }
    if (trigger_config !== undefined) { updates.push('trigger_config = ?'); values.push(JSON.stringify(trigger_config)); }
    if (steps !== undefined) { updates.push('steps = ?'); values.push(JSON.stringify(steps)); }
    if (severity_filter !== undefined) { updates.push('severity_filter = ?'); values.push(severity_filter); }
    if (enabled !== undefined) { updates.push('enabled = ?'); values.push(enabled ? 1 : 0); }
    if (max_concurrent !== undefined) { updates.push('max_concurrent = ?'); values.push(max_concurrent); }
    if (cooldown_seconds !== undefined) { updates.push('cooldown_seconds = ?'); values.push(cooldown_seconds); }

    if (updates.length === 0) return c.json({ error: 'No fields to update' }, 400);
    updates.push("updated_at = datetime('now')");
    values.push(id);

    await c.env.DB.prepare(`UPDATE soar_playbooks SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    const playbook = await c.env.DB.prepare('SELECT * FROM soar_playbooks WHERE id = ?').bind(id).first();
    return c.json(playbook);
  } catch (err) {
    console.error('Update playbook error:', err);
    return c.json({ error: 'Failed to update playbook' }, 500);
  }
});

soar.delete('/playbooks/:id', async (c) => {
  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT id FROM soar_playbooks WHERE id = ?').bind(id).first();
  if (!existing) return c.json({ error: 'Playbook not found' }, 404);
  await c.env.DB.prepare('DELETE FROM soar_playbooks WHERE id = ?').bind(id).run();
  return c.json({ message: 'Playbook deleted' });
});

// ─── Execute Playbook ──────────────────────────────────────────────────────

soar.post('/playbooks/:id/execute', async (c) => {
  const playbookId = c.req.param('id');
  const playbook = await c.env.DB.prepare('SELECT * FROM soar_playbooks WHERE id = ?').bind(playbookId).first();
  if (!playbook) return c.json({ error: 'Playbook not found' }, 404);

  const body = await c.req.json().catch(() => ({})) as Record<string, string>;
  const alertId = body.alert_id || null;
  const incidentId = body.incident_id || null;

  const steps = JSON.parse(playbook.steps as string || '[]') as Array<{ action_type: string; config: Record<string, unknown> }>;
  const execId = crypto.randomUUID();
  const startTime = Date.now();

  await c.env.DB.prepare(`
    INSERT INTO soar_executions (id, playbook_id, trigger_alert_id, trigger_incident_id, status, total_steps, context)
    VALUES (?, ?, ?, ?, 'running', ?, '{}')
  `).bind(execId, playbookId, alertId, incidentId, steps.length).run();

  // Execute each step
  const stepResults: Array<{ step: number; action: string; status: string; result: string; duration_ms: number }> = [];
  let failed = false;

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const stepStart = Date.now();
    const logId = crypto.randomUUID();

    await c.env.DB.prepare(`
      INSERT INTO soar_action_log (id, execution_id, step_index, action_type, action_config, status, started_at)
      VALUES (?, ?, ?, ?, ?, 'running', datetime('now'))
    `).bind(logId, execId, i, step.action_type, JSON.stringify(step.config)).run();

    // Simulate action execution
    const result = await executeAction(step.action_type, step.config, c.env.DB, alertId, incidentId);
    const stepDuration = Date.now() - stepStart;

    await c.env.DB.prepare(`
      UPDATE soar_action_log SET status = ?, result = ?, duration_ms = ?, completed_at = datetime('now')
      WHERE id = ?
    `).bind(result.success ? 'completed' : 'failed', JSON.stringify(result), stepDuration, logId).run();

    stepResults.push({ step: i, action: step.action_type, status: result.success ? 'completed' : 'failed', result: result.message, duration_ms: stepDuration });

    // Update current step
    await c.env.DB.prepare('UPDATE soar_executions SET current_step = ? WHERE id = ?').bind(i + 1, execId).run();

    if (!result.success) { failed = true; break; }
  }

  const duration = Date.now() - startTime;
  const finalStatus = failed ? 'failed' : 'completed';

  await c.env.DB.prepare(`
    UPDATE soar_executions SET status = ?, step_results = ?, duration_ms = ?, completed_at = datetime('now')
    WHERE id = ?
  `).bind(finalStatus, JSON.stringify(stepResults), duration, execId).run();

  // Update playbook stats
  const statsField = failed ? 'failure_count' : 'success_count';
  await c.env.DB.prepare(`
    UPDATE soar_playbooks SET trigger_count = trigger_count + 1, ${statsField} = ${statsField} + 1, last_triggered_at = datetime('now'), updated_at = datetime('now')
    WHERE id = ?
  `).bind(playbookId).run();

  return c.json({
    execution_id: execId, playbook_id: playbookId, status: finalStatus,
    steps_completed: stepResults.filter(s => s.status === 'completed').length,
    total_steps: steps.length, duration_ms: duration,
    step_results: stepResults,
  });
});

// Get execution detail
soar.get('/executions/:id', async (c) => {
  const id = c.req.param('id');
  const execution = await c.env.DB.prepare('SELECT * FROM soar_executions WHERE id = ?').bind(id).first();
  if (!execution) return c.json({ error: 'Execution not found' }, 404);

  const actions = await c.env.DB.prepare('SELECT * FROM soar_action_log WHERE execution_id = ? ORDER BY step_index').bind(id).all();
  return c.json({ ...execution, actions: actions.results || [] });
});

// List recent executions
soar.get('/executions', async (c) => {
  const { page = '1', page_size = '25', status } = c.req.query();
  const pageNum = parseInt(page);
  const limit = Math.min(parseInt(page_size), 100);
  const offset = (pageNum - 1) * limit;

  const where = status ? 'WHERE e.status = ?' : '';
  const params = status ? [status] : [];

  const total = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM soar_executions e ${where}`).bind(...params).first<{ count: number }>();
  const executions = await c.env.DB.prepare(`
    SELECT e.*, p.name as playbook_name FROM soar_executions e
    JOIN soar_playbooks p ON p.id = e.playbook_id
    ${where} ORDER BY e.started_at DESC LIMIT ? OFFSET ?
  `).bind(...params, limit, offset).all();

  return c.json({ items: executions.results || [], total: total?.count || 0, page: pageNum, page_size: limit });
});

// ─── Templates & Action Types ──────────────────────────────────────────────

soar.get('/templates', async (c) => {
  return c.json({ templates: PLAYBOOK_TEMPLATES, total: PLAYBOOK_TEMPLATES.length });
});

soar.get('/action-types', async (c) => {
  return c.json({ action_types: ACTION_TYPES, total: ACTION_TYPES.length });
});

// ─── Overview ──────────────────────────────────────────────────────────────

soar.get('/overview', async (c) => {
  const db = c.env.DB;
  const [playbookCount, enabledCount, execCount, successCount, failCount, recentExecs] = await Promise.all([
    db.prepare('SELECT COUNT(*) as count FROM soar_playbooks').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) as count FROM soar_playbooks WHERE enabled = 1').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) as count FROM soar_executions').first<{ count: number }>(),
    db.prepare("SELECT COUNT(*) as count FROM soar_executions WHERE status = 'completed'").first<{ count: number }>(),
    db.prepare("SELECT COUNT(*) as count FROM soar_executions WHERE status = 'failed'").first<{ count: number }>(),
    db.prepare("SELECT e.*, p.name as playbook_name FROM soar_executions e JOIN soar_playbooks p ON p.id = e.playbook_id ORDER BY e.started_at DESC LIMIT 5").all(),
  ]);

  const successRate = (execCount?.count || 0) > 0
    ? Math.round(((successCount?.count || 0) / (execCount?.count || 0)) * 100)
    : 0;

  return c.json({
    totals: {
      playbooks: playbookCount?.count || 0,
      enabled: enabledCount?.count || 0,
      total_executions: execCount?.count || 0,
      successful: successCount?.count || 0,
      failed: failCount?.count || 0,
      success_rate: successRate,
    },
    recent_executions: recentExecs.results || [],
    templates_available: PLAYBOOK_TEMPLATES.length,
    action_types_available: ACTION_TYPES.length,
    generated_at: new Date().toISOString(),
  });
});

// ─── Action Executor ───────────────────────────────────────────────────────

async function executeAction(
  actionType: string,
  config: Record<string, unknown>,
  db: D1Database,
  alertId: string | null,
  incidentId: string | null,
): Promise<{ success: boolean; message: string; data?: unknown }> {
  // In production, these would call real integrations. For now, simulate execution.
  switch (actionType) {
    case 'update_alert': {
      if (!alertId) return { success: true, message: 'No alert to update (manual trigger)' };
      const updates: string[] = [];
      const values: (string | number)[] = [];
      if (config.status) { updates.push('status = ?'); values.push(config.status as string); }
      if (config.severity) { updates.push('severity = ?'); values.push(config.severity as string); }
      if (updates.length > 0) {
        updates.push("updated_at = datetime('now')");
        values.push(alertId);
        await db.prepare(`UPDATE soc_alerts SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
      }
      return { success: true, message: `Alert ${alertId} updated: ${JSON.stringify(config)}` };
    }

    case 'escalate': {
      const incId = crypto.randomUUID();
      await db.prepare(`
        INSERT INTO soc_incidents (id, title, description, severity, status, priority, incident_type)
        VALUES (?, ?, ?, ?, 'open', 1, ?)
      `).bind(incId, config.title || 'Auto-escalated Incident', `Escalated by SOAR playbook`, (config.severity as string) || 'high', (config.incident_type as string) || 'security').run();

      if (alertId) {
        await db.prepare('INSERT INTO soc_alert_incidents (alert_id, incident_id, added_at) VALUES (?, ?, datetime(\'now\'))').bind(alertId, incId).run();
        await db.prepare('UPDATE soc_alerts SET incident_id = ?, status = \'escalated\', updated_at = datetime(\'now\') WHERE id = ?').bind(incId, alertId).run();
      }
      return { success: true, message: `Incident ${incId} created`, data: { incident_id: incId } };
    }

    case 'isolate_host':
      return { success: true, message: `Host isolation requested: ${config.reason || 'SOAR automated containment'}` };
    case 'block_ip':
      return { success: true, message: `IP block rule created for target` };
    case 'disable_user':
      return { success: true, message: `User account disable requested` };
    case 'create_ticket':
      return { success: true, message: `Ticket created (priority: ${config.priority || 'medium'}, template: ${config.template || 'default'})` };
    case 'send_notification':
      return { success: true, message: `Notification sent via ${config.channel || 'email'}` };
    case 'enrich_ioc':
      return { success: true, message: `IOC enrichment completed from ${config.source || config.sources || 'all sources'}`, data: { enriched: true, sources_checked: 3 } };
    case 'run_scan':
      return { success: true, message: `Targeted scan initiated (type: ${config.scan_type || 'network'})` };
    case 'add_tag':
      return { success: true, message: `Tag '${config.tag}' applied` };
    case 'webhook':
      return { success: true, message: `Webhook called: ${config.url || config.method || 'custom endpoint'}` };
    case 'wait':
      return { success: true, message: `Wait step completed (${config.duration_seconds || 0}s)` };
    case 'condition':
      return { success: true, message: 'Condition evaluated: true' };
    default:
      return { success: false, message: `Unknown action type: ${actionType}` };
  }
}

export { soar };
