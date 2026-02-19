import { dispatchToIntegration, type Integration } from '../integrations/manager';

export interface NotificationEvent {
  event_type: string;
  data: Record<string, unknown>;
}

// Emit an event and dispatch to matching notification rules
export async function emitEvent(
  db: D1Database,
  event: NotificationEvent,
  sendgridApiKey?: string
): Promise<{ matched: number; sent: number; failed: number }> {
  // Find active rules matching this event type
  const rules = await db.prepare(`
    SELECT nr.*, i.id as int_id, i.name as int_name, i.type as int_type, i.provider as int_provider,
           i.config as int_config, i.is_active as int_active
    FROM notification_rules nr
    JOIN integrations i ON nr.integration_id = i.id
    WHERE nr.event_type = ? AND nr.is_active = 1 AND i.is_active = 1
  `).bind(event.event_type).all<any>();

  let matched = 0;
  let sent = 0;
  let failed = 0;

  for (const rule of rules.results || []) {
    matched++;

    // Check conditions
    if (rule.conditions && rule.conditions !== '{}') {
      const conditions = JSON.parse(rule.conditions);
      if (!evaluateConditions(conditions, event.data)) continue;
    }

    // Build the integration object
    const integration: Integration = {
      id: rule.int_id,
      name: rule.int_name,
      type: rule.int_type,
      provider: rule.int_provider,
      config: rule.int_config,
      is_active: rule.int_active,
      last_tested_at: null,
      last_used_at: null,
      created_by: null,
      created_at: '',
      updated_at: '',
    };

    // Dispatch
    const result = await dispatchToIntegration(db, integration, event.event_type, event.data, sendgridApiKey);

    // Determine recipient for logging
    const config = JSON.parse(rule.int_config);
    const recipient = rule.int_type === 'email'
      ? (config.to_addresses || []).join(', ')
      : config.url || 'unknown';

    // Log the notification
    await db.prepare(`
      INSERT INTO notification_log (id, rule_id, event_type, recipient, channel, status, event_data, error_message)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      rule.id,
      event.event_type,
      recipient,
      rule.int_type,
      result.success ? 'success' : 'failed',
      JSON.stringify(event.data).substring(0, 2000),
      result.error || null,
    ).run();

    // Update rule stats
    await db.prepare(`
      UPDATE notification_rules SET last_triggered_at = datetime('now'), trigger_count = trigger_count + 1, updated_at = datetime('now')
      WHERE id = ?
    `).bind(rule.id).run();

    if (result.success) sent++;
    else failed++;
  }

  return { matched, sent, failed };
}

// Evaluate rule conditions against event data
function evaluateConditions(conditions: Record<string, unknown>, data: Record<string, unknown>): boolean {
  for (const [key, value] of Object.entries(conditions)) {
    if (key === 'severity' && data.severity) {
      // Severity matching: condition value can be a string or array
      const allowed = Array.isArray(value) ? value : [value];
      if (!allowed.includes(data.severity)) return false;
    }
    if (key === 'scan_type' && data.scan_type) {
      const allowed = Array.isArray(value) ? value : [value];
      if (!allowed.includes(data.scan_type)) return false;
    }
    if (key === 'min_cvss' && typeof data.cvss_score === 'number') {
      if (data.cvss_score < (value as number)) return false;
    }
    if (key === 'min_findings' && typeof data.findings_count === 'number') {
      if (data.findings_count < (value as number)) return false;
    }
  }
  return true;
}

// Get notification stats
export async function getNotificationStats(db: D1Database): Promise<{
  total_rules: number;
  active_rules: number;
  total_sent: number;
  total_failed: number;
  recent_events: number;
}> {
  const ruleStats = await db.prepare(`
    SELECT
      COUNT(*) as total_rules,
      SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_rules
    FROM notification_rules
  `).first<{ total_rules: number; active_rules: number }>();

  const logStats = await db.prepare(`
    SELECT
      SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as total_sent,
      SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as total_failed,
      SUM(CASE WHEN created_at > datetime('now', '-24 hours') THEN 1 ELSE 0 END) as recent_events
    FROM notification_log
  `).first<{ total_sent: number; total_failed: number; recent_events: number }>();

  return {
    total_rules: ruleStats?.total_rules || 0,
    active_rules: ruleStats?.active_rules || 0,
    total_sent: logStats?.total_sent || 0,
    total_failed: logStats?.total_failed || 0,
    recent_events: logStats?.recent_events || 0,
  };
}
