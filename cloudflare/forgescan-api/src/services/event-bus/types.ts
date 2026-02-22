// ─────────────────────────────────────────────────────────────────────────────
// Forge Event Bus — Type Definitions
// ─────────────────────────────────────────────────────────────────────────────

/** Core event structure for cross-product communication */
export interface ForgeEvent {
  id: string;
  event_type: ForgeEventType | string;
  source: ForgeEventSource;
  correlation_id?: string;
  payload: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  created_at: string;
}

/** Known event sources */
export type ForgeEventSource = 'forgescan' | 'forgeredops' | 'forgesoc' | 'compliance' | 'system';

/** Known event types — extensible via string union */
export type ForgeEventType =
  // ForgeScan events
  | 'forge.scan.started'
  | 'forge.scan.completed'
  | 'forge.scan.failed'
  | 'forge.vulnerability.detected'
  | 'forge.vulnerability.status_changed'
  | 'forge.asset.discovered'
  | 'forge.asset.classification_changed'
  // ForgeRedOps events
  | 'forge.redops.campaign.created'
  | 'forge.redops.campaign.launched'
  | 'forge.redops.campaign.completed'
  | 'forge.redops.finding.discovered'
  | 'forge.redops.exploitation.success'
  | 'forge.redops.exploitation.failed'
  // ForgeSOC events (future)
  | 'forge.soc.alert_created'
  | 'forge.soc.incident_created'
  // Compliance events
  | 'forge.compliance.control_failed'
  | 'forge.compliance.poam_generated';

/** Event subscription stored in DB */
export interface EventSubscription {
  id: string;
  name: string;
  event_pattern: string;
  handler_type: EventHandlerType;
  handler_config: string | null;
  conditions: string | null;
  is_active: number;
  priority: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export type EventHandlerType = 'notification' | 'redops_trigger' | 'compliance_check' | 'webhook' | 'custom';

/** In-memory event handler (registered programmatically, not from DB) */
export interface EventHandler {
  id: string;
  event_pattern: string;
  handler: (event: ForgeEvent, db: D1Database) => Promise<HandlerResult>;
}

export interface HandlerResult {
  success: boolean;
  message?: string;
  data?: Record<string, unknown>;
}

/** Result of publishing an event */
export interface PublishResult {
  event_id: string;
  subscriptions_matched: number;
  subscriptions_executed: number;
  subscriptions_failed: number;
  handler_results: Array<{
    subscription_id: string;
    status: 'success' | 'failed' | 'skipped';
    message?: string;
  }>;
}
