-- Phase 5: Notification System
-- Tables for notification rules and delivery logging

-- Notification rules: match events to integrations
CREATE TABLE IF NOT EXISTS notification_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  event_type TEXT NOT NULL,
  conditions TEXT DEFAULT '{}',
  integration_id TEXT NOT NULL,
  template TEXT,
  is_active INTEGER DEFAULT 1,
  last_triggered_at TEXT,
  trigger_count INTEGER DEFAULT 0,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE CASCADE
);

-- Notification log: record of all notifications sent
CREATE TABLE IF NOT EXISTS notification_log (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  recipient TEXT,
  channel TEXT NOT NULL,
  status TEXT NOT NULL,
  event_data TEXT,
  error_message TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (rule_id) REFERENCES notification_rules(id) ON DELETE CASCADE
);

-- Indexes for notification_rules
CREATE INDEX IF NOT EXISTS idx_notification_rules_event_type ON notification_rules(event_type);
CREATE INDEX IF NOT EXISTS idx_notification_rules_integration_id ON notification_rules(integration_id);
CREATE INDEX IF NOT EXISTS idx_notification_rules_is_active ON notification_rules(is_active);

-- Indexes for notification_log
CREATE INDEX IF NOT EXISTS idx_notification_log_rule_id ON notification_log(rule_id);
CREATE INDEX IF NOT EXISTS idx_notification_log_event_type ON notification_log(event_type);
CREATE INDEX IF NOT EXISTS idx_notification_log_created_at ON notification_log(created_at);
