-- ============================================================================
-- Migration 009: Forge Event Bus — Cross-Product Event Backbone
-- ============================================================================

-- Persisted event log for audit, replay, and cross-product correlation
CREATE TABLE IF NOT EXISTS forge_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,               -- e.g., 'forge.vulnerability.detected'
  source TEXT NOT NULL,                   -- e.g., 'forgescan', 'forgeredops', 'system'
  correlation_id TEXT,                    -- Links related events across products
  payload TEXT NOT NULL,                  -- JSON event data
  metadata TEXT,                          -- JSON: { user_id, scanner_id, campaign_id, ... }
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_forge_events_type ON forge_events(event_type);
CREATE INDEX IF NOT EXISTS idx_forge_events_source ON forge_events(source);
CREATE INDEX IF NOT EXISTS idx_forge_events_correlation ON forge_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_forge_events_created_at ON forge_events(created_at);

-- Event subscriptions: declarative handlers that react to events
CREATE TABLE IF NOT EXISTS event_subscriptions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  event_pattern TEXT NOT NULL,            -- Exact match or glob: 'forge.vulnerability.*'
  handler_type TEXT NOT NULL              -- 'notification', 'redops_trigger', 'compliance_check', 'webhook'
    CHECK (handler_type IN ('notification', 'redops_trigger', 'compliance_check', 'webhook', 'custom')),
  handler_config TEXT,                    -- JSON: handler-specific configuration
  conditions TEXT,                        -- JSON: conditions that must match event payload
  is_active INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 100,  -- Lower = higher priority
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_event_subs_pattern ON event_subscriptions(event_pattern);
CREATE INDEX IF NOT EXISTS idx_event_subs_active ON event_subscriptions(is_active);

-- Subscription execution log: track handler results
CREATE TABLE IF NOT EXISTS event_subscription_log (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES forge_events(id) ON DELETE CASCADE,
  subscription_id TEXT NOT NULL REFERENCES event_subscriptions(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'success', 'failed', 'skipped')),
  result TEXT,                            -- JSON: handler result or error details
  duration_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_event_sub_log_event ON event_subscription_log(event_id);
CREATE INDEX IF NOT EXISTS idx_event_sub_log_sub ON event_subscription_log(subscription_id);

-- Seed default cross-product subscriptions

-- Auto-create RedOps validation campaign for critical vulnerabilities
INSERT OR IGNORE INTO event_subscriptions (id, name, event_pattern, handler_type, handler_config, conditions, is_active, priority)
VALUES (
  'sub_redops_critical_vuln',
  'Auto-validate critical vulnerabilities',
  'forge.vulnerability.detected',
  'redops_trigger',
  '{"action":"create_validation_campaign","campaign_type":"validation","exploitation_level":"safe","auto_launch":false}',
  '{"severity":["critical"],"min_cvss":9.0}',
  1,
  50
);

-- Notify on exploitation success
INSERT OR IGNORE INTO event_subscriptions (id, name, event_pattern, handler_type, handler_config, conditions, is_active, priority)
VALUES (
  'sub_notify_exploitation',
  'Alert on successful exploitation',
  'forge.redops.exploitation.success',
  'notification',
  '{"urgency":"high","channels":["all"]}',
  '{}',
  1,
  10
);
