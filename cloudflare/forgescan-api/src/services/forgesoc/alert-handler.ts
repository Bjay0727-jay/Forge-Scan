// ─────────────────────────────────────────────────────────────────────────────
// ForgeSOC Alert Handler — Event Bus Subscriber
// Creates SOC alerts from cross-product events
// ─────────────────────────────────────────────────────────────────────────────

import { registerHandler } from '../event-bus';
import type { ForgeEvent } from '../event-bus/types';

/**
 * Create a SOC alert from an event, checking detection rules for matching.
 */
export async function createAlertFromEvent(
  event: ForgeEvent,
  db: D1Database
): Promise<{ alert_id: string | null; incident_id: string | null }> {
  // Find matching active detection rules
  const rules = await db
    .prepare(
      `SELECT * FROM soc_detection_rules
       WHERE is_active = 1
       ORDER BY alert_severity ASC`
    )
    .all<any>();

  let alertId: string | null = null;
  let incidentId: string | null = null;

  for (const rule of rules.results || []) {
    if (!matchesRulePattern(event.event_type, rule.event_pattern)) continue;

    // Evaluate conditions against event payload
    if (rule.conditions && rule.conditions !== '{}') {
      const conditions = JSON.parse(rule.conditions);
      if (!evaluateRuleConditions(conditions, event.payload)) continue;
    }

    // Check cooldown (deduplicate)
    if (rule.cooldown_seconds > 0 && rule.last_triggered_at) {
      const lastTriggered = new Date(rule.last_triggered_at).getTime();
      const cooldownMs = rule.cooldown_seconds * 1000;
      if (Date.now() - lastTriggered < cooldownMs) continue;
    }

    // Create the alert
    alertId = crypto.randomUUID();
    const tags = rule.tags ? JSON.parse(rule.tags) : [];
    const title = buildAlertTitle(event, rule);
    const description = buildAlertDescription(event, rule);

    await db
      .prepare(
        `INSERT INTO soc_alerts (
          id, title, description, severity, status, source, source_event_id,
          source_finding_id, alert_type, tags, correlation_id,
          mitre_tactic, mitre_technique, affected_assets, raw_data,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`
      )
      .bind(
        alertId,
        title,
        description,
        rule.alert_severity,
        event.source,
        event.id,
        (event.payload.finding_id as string) || null,
        rule.alert_type,
        JSON.stringify(tags),
        event.correlation_id || null,
        (event.payload.mitre_tactic as string) || null,
        (event.payload.mitre_technique as string) || null,
        event.payload.affected_assets ? JSON.stringify(event.payload.affected_assets) : null,
        JSON.stringify(event.payload)
      )
      .run();

    // Update rule trigger tracking
    await db
      .prepare(
        `UPDATE soc_detection_rules
         SET last_triggered_at = datetime('now'), trigger_count = trigger_count + 1, updated_at = datetime('now')
         WHERE id = ?`
      )
      .bind(rule.id)
      .run();

    // Auto-escalate to incident if configured
    if (rule.auto_escalate) {
      incidentId = await createIncidentFromAlert(db, alertId, title, rule.alert_severity);
    }

    // Only one alert per event (first matching rule wins)
    break;
  }

  return { alert_id: alertId, incident_id: incidentId };
}

/**
 * Create an incident from an alert (auto-escalation).
 */
async function createIncidentFromAlert(
  db: D1Database,
  alertId: string,
  alertTitle: string,
  severity: string
): Promise<string> {
  const incidentId = crypto.randomUUID();
  const priority = severity === 'critical' ? 1 : severity === 'high' ? 2 : 3;

  await db
    .prepare(
      `INSERT INTO soc_incidents (
        id, title, description, severity, status, priority, incident_type,
        alert_count, started_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'open', ?, 'security', 1, datetime('now'), datetime('now'), datetime('now'))`
    )
    .bind(
      incidentId,
      `Incident: ${alertTitle}`,
      `Auto-escalated from alert ${alertId}`,
      severity,
      priority
    )
    .run();

  // Link alert to incident
  await db
    .prepare('INSERT INTO soc_alert_incidents (alert_id, incident_id) VALUES (?, ?)')
    .bind(alertId, incidentId)
    .run();

  // Update alert with incident reference
  await db
    .prepare('UPDATE soc_alerts SET incident_id = ?, status = \'escalated\', updated_at = datetime(\'now\') WHERE id = ?')
    .bind(incidentId, alertId)
    .run();

  // Create timeline entry
  await db
    .prepare(
      `INSERT INTO soc_incident_timeline (id, incident_id, action, description, created_at)
       VALUES (?, ?, 'created', ?, datetime('now'))`
    )
    .bind(crypto.randomUUID(), incidentId, `Incident auto-created from alert: ${alertTitle}`)
    .run();

  return incidentId;
}

// ─── Cross-Product Correlation ────────────────────────────────────────────────

/**
 * Correlate all RedOps findings from a completed campaign with ForgeScan findings,
 * then create a SOC summary alert with the results.
 */
export async function correlateCampaignFindings(
  db: D1Database,
  campaignId: string
): Promise<{ correlated: number; alert_id: string | null; incident_id: string | null }> {
  // Get campaign info
  const campaign = await db
    .prepare('SELECT id, name, findings_count, exploitable_count, critical_count, high_count FROM redops_campaigns WHERE id = ?')
    .bind(campaignId)
    .first<{ id: string; name: string; findings_count: number; exploitable_count: number; critical_count: number; high_count: number }>();

  if (!campaign) return { correlated: 0, alert_id: null, incident_id: null };

  // Fetch uncorrelated RedOps findings for this campaign
  const redopsFindings = await db
    .prepare(
      `SELECT id, title, cve_id, cwe_id, severity, target_host, affected_component
       FROM redops_findings
       WHERE campaign_id = ? AND finding_id IS NULL
       ORDER BY severity ASC LIMIT 50`
    )
    .bind(campaignId)
    .all<{ id: string; title: string; cve_id: string | null; cwe_id: string | null; severity: string; target_host: string | null; affected_component: string | null }>();

  let correlated = 0;

  for (const rf of redopsFindings.results || []) {
    // Try matching by CVE
    let matchId: string | null = null;
    let matchAssetId: string | null = null;

    if (rf.cve_id) {
      const match = await db
        .prepare('SELECT id, asset_id FROM findings WHERE vendor_id = ? LIMIT 1')
        .bind(rf.cve_id)
        .first<{ id: string; asset_id: string }>();
      if (match) {
        matchId = match.id;
        matchAssetId = match.asset_id;
      }
    }

    // Try matching by CWE + title keywords
    if (!matchId && rf.cwe_id) {
      const match = await db
        .prepare("SELECT id, asset_id FROM findings WHERE evidence LIKE ? LIMIT 1")
        .bind(`%${rf.cwe_id}%`)
        .first<{ id: string; asset_id: string }>();
      if (match) {
        matchId = match.id;
        matchAssetId = match.asset_id;
      }
    }

    if (matchId) {
      await db
        .prepare("UPDATE redops_findings SET finding_id = ?, asset_id = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(matchId, matchAssetId, rf.id)
        .run();
      correlated++;
    }
  }

  // Create a SOC summary alert for the campaign completion
  const alertId = crypto.randomUUID();
  const severity = campaign.critical_count > 0 ? 'critical' : campaign.high_count > 0 ? 'high' : 'medium';
  const title = `[CAMPAIGN COMPLETE] ${campaign.name}: ${campaign.findings_count} findings (${campaign.exploitable_count} exploitable)`;

  await db
    .prepare(
      `INSERT INTO soc_alerts (
        id, title, description, severity, status, source, alert_type, tags,
        correlation_id, raw_data, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'new', 'forgeredops', 'exploitation', ?, ?, ?, datetime('now'), datetime('now'))`
    )
    .bind(
      alertId,
      title,
      `RedOps campaign "${campaign.name}" completed. ${campaign.findings_count} total findings, ` +
        `${campaign.exploitable_count} exploitable, ${correlated} correlated with existing vulnerabilities. ` +
        `Severity breakdown: ${campaign.critical_count} critical, ${campaign.high_count} high.`,
      severity,
      JSON.stringify(['campaign-complete', 'redops', 'correlation']),
      campaignId,
      JSON.stringify({ campaign_id: campaignId, findings_count: campaign.findings_count, correlated })
    )
    .run();

  // Auto-escalate to incident if critical findings
  let incidentId: string | null = null;
  if (campaign.critical_count > 0 || campaign.exploitable_count >= 3) {
    incidentId = crypto.randomUUID();
    const priority = campaign.critical_count > 0 ? 1 : 2;

    await db
      .prepare(
        `INSERT INTO soc_incidents (
          id, title, description, severity, status, priority, incident_type,
          alert_count, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'open', ?, 'exploitation', 1, datetime('now'), datetime('now'), datetime('now'))`
      )
      .bind(
        incidentId,
        `Incident: ${campaign.name} — ${campaign.exploitable_count} exploitable findings`,
        `Auto-created from RedOps campaign completion with ${campaign.critical_count} critical findings`,
        severity,
        priority
      )
      .run();

    await db
      .prepare('INSERT INTO soc_alert_incidents (alert_id, incident_id) VALUES (?, ?)')
      .bind(alertId, incidentId)
      .run();

    await db
      .prepare("UPDATE soc_alerts SET incident_id = ?, status = 'escalated', updated_at = datetime('now') WHERE id = ?")
      .bind(incidentId, alertId)
      .run();

    await db
      .prepare(
        `INSERT INTO soc_incident_timeline (id, incident_id, action, description, created_at)
         VALUES (?, ?, 'created', ?, datetime('now'))`
      )
      .bind(crypto.randomUUID(), incidentId, `Incident auto-created from RedOps campaign: ${campaign.name}`)
      .run();
  }

  return { correlated, alert_id: alertId, incident_id: incidentId };
}

// ─── Event Bus Registration ──────────────────────────────────────────────────

/**
 * Register ForgeSOC handlers with the Event Bus.
 * Call this at app startup.
 */
export function registerSOCHandlers(): void {
  // Handle vulnerability events
  registerHandler({
    id: 'forgesoc-vuln-handler',
    event_pattern: 'forge.vulnerability.*',
    handler: async (event, db) => {
      const result = await createAlertFromEvent(event, db);
      return {
        success: true,
        message: result.alert_id
          ? `Created alert ${result.alert_id}${result.incident_id ? ` and incident ${result.incident_id}` : ''}`
          : 'No matching detection rules',
      };
    },
  });

  // Handle RedOps exploitation events (individual findings)
  registerHandler({
    id: 'forgesoc-redops-handler',
    event_pattern: 'forge.redops.**',
    handler: async (event, db) => {
      // For campaign completion events, run cross-product correlation
      if (event.event_type === 'forge.redops.campaign.completed' && event.payload.campaign_id) {
        const result = await correlateCampaignFindings(db, event.payload.campaign_id as string);
        return {
          success: true,
          message: `Campaign correlated ${result.correlated} findings. Alert: ${result.alert_id}` +
            (result.incident_id ? `, Incident: ${result.incident_id}` : ''),
        };
      }

      // For other RedOps events, use detection rules
      const result = await createAlertFromEvent(event, db);
      return {
        success: true,
        message: result.alert_id
          ? `Created alert ${result.alert_id}${result.incident_id ? ` and incident ${result.incident_id}` : ''}`
          : 'No matching detection rules',
      };
    },
  });
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

function matchesRulePattern(eventType: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (pattern === eventType) return true;
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -2);
    return eventType.startsWith(prefix + '.');
  }
  if (pattern.endsWith('.**')) {
    const prefix = pattern.slice(0, -3);
    return eventType.startsWith(prefix + '.');
  }
  return false;
}

function evaluateRuleConditions(
  conditions: Record<string, unknown>,
  payload: Record<string, unknown>
): boolean {
  for (const [key, value] of Object.entries(conditions)) {
    if (key === 'severity' && payload.severity) {
      const allowed = Array.isArray(value) ? value : [value];
      if (!allowed.includes(payload.severity)) return false;
    }
    if (key === 'min_cvss' && typeof payload.cvss_score === 'number') {
      if (payload.cvss_score < (value as number)) return false;
    }
    if (key === 'min_findings' && typeof payload.findings_count === 'number') {
      if (payload.findings_count < (value as number)) return false;
    }
    if (key === 'exploitable' && typeof payload.exploitable === 'boolean') {
      if (payload.exploitable !== value) return false;
    }
  }
  return true;
}

function buildAlertTitle(event: ForgeEvent, rule: any): string {
  const payloadTitle = event.payload.title as string | undefined;
  if (payloadTitle) return `[${rule.alert_severity.toUpperCase()}] ${payloadTitle}`;

  const cveId = event.payload.cve_id as string | undefined;
  if (cveId) return `[${rule.alert_severity.toUpperCase()}] ${cveId} detected`;

  return `[${rule.alert_severity.toUpperCase()}] ${rule.name}`;
}

function buildAlertDescription(event: ForgeEvent, rule: any): string {
  const parts: string[] = [];
  parts.push(`Detection rule: ${rule.name}`);
  parts.push(`Event: ${event.event_type} from ${event.source}`);

  if (event.payload.description) {
    parts.push(`Details: ${event.payload.description}`);
  }
  if (event.payload.remediation) {
    parts.push(`Remediation: ${event.payload.remediation}`);
  }

  return parts.join('\n');
}
