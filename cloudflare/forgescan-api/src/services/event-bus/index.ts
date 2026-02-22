// ─────────────────────────────────────────────────────────────────────────────
// Forge Event Bus — Cross-Product Event Backbone
// ─────────────────────────────────────────────────────────────────────────────

import { emitEvent as emitNotificationEvent } from '../notifications/engine';
import type {
  ForgeEvent,
  ForgeEventSource,
  ForgeEventType,
  EventSubscription,
  EventHandler,
  HandlerResult,
  PublishResult,
} from './types';

export type { ForgeEvent, ForgeEventType, ForgeEventSource, PublishResult };

// In-memory handlers registered programmatically (e.g., by the RedOps controller)
const inMemoryHandlers: EventHandler[] = [];

/**
 * Register an in-memory event handler.
 * These are evaluated alongside DB-stored subscriptions.
 */
export function registerHandler(handler: EventHandler): void {
  inMemoryHandlers.push(handler);
}

/**
 * Remove an in-memory handler by ID.
 */
export function unregisterHandler(handlerId: string): void {
  const idx = inMemoryHandlers.findIndex((h) => h.id === handlerId);
  if (idx !== -1) inMemoryHandlers.splice(idx, 1);
}

/**
 * Publish an event to the bus. This will:
 * 1. Persist the event to forge_events
 * 2. Match DB subscriptions by event_pattern and conditions
 * 3. Execute in-memory handlers
 * 4. Log results to event_subscription_log
 */
export async function publish(
  db: D1Database,
  eventType: ForgeEventType | string,
  source: ForgeEventSource,
  payload: Record<string, unknown>,
  options?: {
    correlation_id?: string;
    metadata?: Record<string, unknown>;
    sendgridApiKey?: string;
  }
): Promise<PublishResult> {
  const eventId = crypto.randomUUID();
  const now = new Date().toISOString();

  const event: ForgeEvent = {
    id: eventId,
    event_type: eventType,
    source,
    correlation_id: options?.correlation_id,
    payload,
    metadata: options?.metadata,
    created_at: now,
  };

  // 1. Persist the event
  await db
    .prepare(
      `INSERT INTO forge_events (id, event_type, source, correlation_id, payload, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      eventId,
      eventType,
      source,
      options?.correlation_id || null,
      JSON.stringify(payload),
      options?.metadata ? JSON.stringify(options.metadata) : null,
      now
    )
    .run();

  // 2. Find matching DB subscriptions
  const subscriptions = await db
    .prepare(
      `SELECT * FROM event_subscriptions WHERE is_active = 1 ORDER BY priority ASC`
    )
    .all<EventSubscription>();

  const results: PublishResult = {
    event_id: eventId,
    subscriptions_matched: 0,
    subscriptions_executed: 0,
    subscriptions_failed: 0,
    handler_results: [],
  };

  for (const sub of subscriptions.results || []) {
    // Check pattern match
    if (!matchesPattern(eventType, sub.event_pattern)) continue;

    // Check conditions
    if (sub.conditions && sub.conditions !== '{}') {
      const conditions = JSON.parse(sub.conditions);
      if (!evaluateConditions(conditions, payload)) continue;
    }

    results.subscriptions_matched++;

    // Execute handler based on type
    let handlerResult: HandlerResult;
    try {
      handlerResult = await executeSubscriptionHandler(db, event, sub, options?.sendgridApiKey);
      results.subscriptions_executed++;
    } catch (err) {
      handlerResult = {
        success: false,
        message: err instanceof Error ? err.message : 'Handler execution failed',
      };
      results.subscriptions_failed++;
    }

    // Log the execution
    await db
      .prepare(
        `INSERT INTO event_subscription_log (id, event_id, subscription_id, status, result, duration_ms, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        crypto.randomUUID(),
        eventId,
        sub.id,
        handlerResult.success ? 'success' : 'failed',
        JSON.stringify(handlerResult).substring(0, 2000),
        null,
        now
      )
      .run();

    results.handler_results.push({
      subscription_id: sub.id,
      status: handlerResult.success ? 'success' : 'failed',
      message: handlerResult.message,
    });
  }

  // 3. Execute in-memory handlers
  for (const handler of inMemoryHandlers) {
    if (!matchesPattern(eventType, handler.event_pattern)) continue;

    try {
      const result = await handler.handler(event, db);
      results.subscriptions_matched++;
      if (result.success) results.subscriptions_executed++;
      else results.subscriptions_failed++;
    } catch {
      results.subscriptions_failed++;
    }
  }

  return results;
}

/**
 * Query persisted events with filtering.
 */
export async function queryEvents(
  db: D1Database,
  filters: {
    event_type?: string;
    source?: string;
    correlation_id?: string;
    since?: string;
    until?: string;
    page?: number;
    page_size?: number;
  }
): Promise<{ items: ForgeEvent[]; total: number; page: number; page_size: number }> {
  const page = filters.page || 1;
  const pageSize = Math.min(filters.page_size || 50, 200);

  let where = 'WHERE 1=1';
  const params: unknown[] = [];

  if (filters.event_type) {
    where += ' AND event_type = ?';
    params.push(filters.event_type);
  }
  if (filters.source) {
    where += ' AND source = ?';
    params.push(filters.source);
  }
  if (filters.correlation_id) {
    where += ' AND correlation_id = ?';
    params.push(filters.correlation_id);
  }
  if (filters.since) {
    where += ' AND created_at >= ?';
    params.push(filters.since);
  }
  if (filters.until) {
    where += ' AND created_at <= ?';
    params.push(filters.until);
  }

  const countResult = await db
    .prepare(`SELECT COUNT(*) as total FROM forge_events ${where}`)
    .bind(...params)
    .first<{ total: number }>();

  const total = countResult?.total || 0;

  const dataParams = [...params, pageSize, (page - 1) * pageSize];
  const dataResult = await db
    .prepare(
      `SELECT id, event_type, source, correlation_id, payload, metadata, created_at
       FROM forge_events ${where}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`
    )
    .bind(...dataParams)
    .all<any>();

  const items: ForgeEvent[] = (dataResult.results || []).map((row: any) => ({
    id: row.id,
    event_type: row.event_type,
    source: row.source,
    correlation_id: row.correlation_id,
    payload: typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload,
    metadata: row.metadata ? (typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata) : undefined,
    created_at: row.created_at,
  }));

  return { items, total, page, page_size: pageSize };
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Match event type against a subscription pattern (exact or glob with trailing *) */
function matchesPattern(eventType: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (pattern === eventType) return true;
  // Support trailing wildcard: 'forge.vulnerability.*' matches 'forge.vulnerability.detected'
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -2);
    return eventType.startsWith(prefix + '.');
  }
  // Support double wildcard: 'forge.**' matches anything starting with 'forge.'
  if (pattern.endsWith('.**')) {
    const prefix = pattern.slice(0, -3);
    return eventType.startsWith(prefix + '.');
  }
  return false;
}

/** Evaluate subscription conditions against event payload */
function evaluateConditions(conditions: Record<string, unknown>, data: Record<string, unknown>): boolean {
  for (const [key, value] of Object.entries(conditions)) {
    if (key === 'severity' && data.severity) {
      const allowed = Array.isArray(value) ? value : [value];
      if (!allowed.includes(data.severity)) return false;
    }
    if (key === 'min_cvss' && typeof data.cvss_score === 'number') {
      if (data.cvss_score < (value as number)) return false;
    }
    if (key === 'scan_type' && data.scan_type) {
      const allowed = Array.isArray(value) ? value : [value];
      if (!allowed.includes(data.scan_type)) return false;
    }
    if (key === 'min_findings' && typeof data.findings_count === 'number') {
      if (data.findings_count < (value as number)) return false;
    }
    if (key === 'exploitable' && typeof data.exploitable === 'boolean') {
      if (data.exploitable !== value) return false;
    }
    if (key === 'source' && data.source) {
      const allowed = Array.isArray(value) ? value : [value];
      if (!allowed.includes(data.source)) return false;
    }
  }
  return true;
}

/** Execute a subscription handler based on its type */
async function executeSubscriptionHandler(
  db: D1Database,
  event: ForgeEvent,
  subscription: EventSubscription,
  sendgridApiKey?: string
): Promise<HandlerResult> {
  const config = subscription.handler_config ? JSON.parse(subscription.handler_config) : {};

  switch (subscription.handler_type) {
    case 'notification':
      return executeNotificationHandler(db, event, config, sendgridApiKey);

    case 'redops_trigger':
      return executeRedOpsTriggerHandler(db, event, config);

    case 'webhook':
      return executeWebhookHandler(event, config);

    case 'compliance_check':
      return { success: true, message: 'Compliance check handler not yet implemented' };

    case 'custom':
      return { success: true, message: 'Custom handler not yet implemented' };

    default:
      return { success: false, message: `Unknown handler type: ${subscription.handler_type}` };
  }
}

/** Dispatch event to the existing notification engine */
async function executeNotificationHandler(
  db: D1Database,
  event: ForgeEvent,
  _config: Record<string, unknown>,
  sendgridApiKey?: string
): Promise<HandlerResult> {
  const result = await emitNotificationEvent(
    db,
    { event_type: event.event_type, data: event.payload },
    sendgridApiKey
  );
  return {
    success: result.sent > 0 || result.matched === 0,
    message: `Matched ${result.matched} rules, sent ${result.sent}, failed ${result.failed}`,
    data: result as unknown as Record<string, unknown>,
  };
}

/** Auto-create a ForgeRedOps validation campaign from a vulnerability event */
async function executeRedOpsTriggerHandler(
  db: D1Database,
  event: ForgeEvent,
  config: Record<string, unknown>
): Promise<HandlerResult> {
  const action = config.action || 'create_validation_campaign';

  if (action === 'create_validation_campaign') {
    const campaignId = crypto.randomUUID();
    const targetScope = buildTargetScope(event.payload);
    const campaignType = (config.campaign_type as string) || 'validation';
    const exploitationLevel = (config.exploitation_level as string) || 'safe';

    const campaignName = `Auto-validate: ${event.payload.title || event.payload.cve_id || 'Critical finding'}`;

    await db
      .prepare(
        `INSERT INTO redops_campaigns (
          id, name, description, status, campaign_type,
          target_scope, agent_categories, max_concurrent_agents,
          exploitation_level, risk_threshold, auto_poam, compliance_mapping,
          created_at, updated_at
        ) VALUES (?, ?, ?, 'created', ?, ?, '["web","api"]', 2, ?, 'critical', 1, 1, datetime('now'), datetime('now'))`
      )
      .bind(
        campaignId,
        campaignName,
        `Auto-created from event ${event.id}: ${event.event_type}`,
        campaignType,
        JSON.stringify(targetScope),
        exploitationLevel
      )
      .run();

    return {
      success: true,
      message: `Created validation campaign ${campaignId} (requires manual approval to launch)`,
      data: { campaign_id: campaignId, auto_launch: config.auto_launch === true },
    };
  }

  return { success: false, message: `Unknown RedOps trigger action: ${action}` };
}

/** Build a target scope from vulnerability event payload */
function buildTargetScope(payload: Record<string, unknown>): Record<string, unknown> {
  const scope: Record<string, string[]> = { hosts: [], urls: [] };

  if (payload.ip) scope.hosts.push(payload.ip as string);
  if (payload.hostname) scope.hosts.push(payload.hostname as string);
  if (payload.target) scope.hosts.push(payload.target as string);
  if (payload.url) scope.urls.push(payload.url as string);

  // Extract from asset data if present
  if (payload.asset && typeof payload.asset === 'object') {
    const asset = payload.asset as Record<string, unknown>;
    if (asset.ip_addresses) scope.hosts.push(asset.ip_addresses as string);
    if (asset.hostname) scope.hosts.push(asset.hostname as string);
  }

  return scope;
}

/** Execute a webhook handler */
async function executeWebhookHandler(
  event: ForgeEvent,
  config: Record<string, unknown>
): Promise<HandlerResult> {
  const url = config.url as string;
  if (!url) return { success: false, message: 'No webhook URL configured' };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(config.headers as Record<string, string> || {}),
      },
      body: JSON.stringify({
        event_type: event.event_type,
        source: event.source,
        timestamp: event.created_at,
        data: event.payload,
      }),
    });

    return {
      success: response.ok,
      message: `Webhook ${response.ok ? 'delivered' : 'failed'}: ${response.status}`,
    };
  } catch (err) {
    return {
      success: false,
      message: `Webhook error: ${err instanceof Error ? err.message : 'Unknown error'}`,
    };
  }
}
