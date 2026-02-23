-- ============================================================================
-- Migration 010: ForgeSOC — Security Operations Center Foundation
-- ============================================================================

-- SOC Alerts: auto-created from Event Bus subscriptions or manually
CREATE TABLE IF NOT EXISTS soc_alerts (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL DEFAULT 'medium'
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  status TEXT NOT NULL DEFAULT 'new'
    CHECK (status IN ('new', 'triaged', 'investigating', 'escalated', 'resolved', 'closed', 'false_positive')),
  source TEXT NOT NULL DEFAULT 'system',          -- 'forgescan', 'forgeredops', 'manual', 'detection_rule', 'system'
  source_event_id TEXT,                            -- FK to forge_events if auto-created
  source_finding_id TEXT,                          -- FK to findings or redops_findings
  alert_type TEXT NOT NULL DEFAULT 'vulnerability', -- 'vulnerability', 'exploitation', 'anomaly', 'compliance', 'threat_intel'
  tags TEXT,                                       -- JSON array of tags
  assigned_to TEXT REFERENCES users(id) ON DELETE SET NULL,
  incident_id TEXT,                                -- FK to soc_incidents if escalated
  correlation_id TEXT,                             -- Links related alerts
  mitre_tactic TEXT,
  mitre_technique TEXT,
  affected_assets TEXT,                            -- JSON array of asset references
  raw_data TEXT,                                   -- JSON: original event payload
  resolved_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_soc_alerts_severity ON soc_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_status ON soc_alerts(status);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_source ON soc_alerts(source);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_type ON soc_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_assigned ON soc_alerts(assigned_to);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_incident ON soc_alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_created ON soc_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_correlation ON soc_alerts(correlation_id);

-- SOC Incidents: escalated collections of alerts
CREATE TABLE IF NOT EXISTS soc_incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL DEFAULT 'medium'
    CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'investigating', 'containment', 'eradication', 'recovery', 'post_incident', 'closed')),
  priority INTEGER NOT NULL DEFAULT 3
    CHECK (priority BETWEEN 1 AND 5),             -- 1=critical, 5=low
  incident_type TEXT NOT NULL DEFAULT 'security',  -- 'security', 'compliance', 'operational'
  lead_analyst TEXT REFERENCES users(id) ON DELETE SET NULL,
  alert_count INTEGER NOT NULL DEFAULT 0,
  affected_asset_count INTEGER NOT NULL DEFAULT 0,
  tags TEXT,                                       -- JSON array
  mitre_tactics TEXT,                              -- JSON array of tactics
  mitre_techniques TEXT,                           -- JSON array of techniques
  containment_actions TEXT,                        -- JSON array of actions taken
  root_cause TEXT,
  lessons_learned TEXT,
  started_at TEXT,
  contained_at TEXT,
  resolved_at TEXT,
  closed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_soc_incidents_severity ON soc_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_status ON soc_incidents(status);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_priority ON soc_incidents(priority);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_lead ON soc_incidents(lead_analyst);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_created ON soc_incidents(created_at);

-- SOC Incident Timeline: audit trail of actions on an incident
CREATE TABLE IF NOT EXISTS soc_incident_timeline (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES soc_incidents(id) ON DELETE CASCADE,
  action TEXT NOT NULL,                            -- 'created', 'status_changed', 'assigned', 'alert_added', 'note_added', 'escalated', 'resolved'
  description TEXT,
  actor TEXT REFERENCES users(id) ON DELETE SET NULL,
  old_value TEXT,
  new_value TEXT,
  metadata TEXT,                                   -- JSON extra context
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_soc_timeline_incident ON soc_incident_timeline(incident_id);
CREATE INDEX IF NOT EXISTS idx_soc_timeline_created ON soc_incident_timeline(created_at);

-- SOC Alert-Incident link table (many-to-many)
CREATE TABLE IF NOT EXISTS soc_alert_incidents (
  alert_id TEXT NOT NULL REFERENCES soc_alerts(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL REFERENCES soc_incidents(id) ON DELETE CASCADE,
  added_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (alert_id, incident_id)
);

-- SOC Detection Rules: automated alert creation logic
CREATE TABLE IF NOT EXISTS soc_detection_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  event_pattern TEXT NOT NULL,                     -- Event bus pattern to match
  conditions TEXT,                                 -- JSON conditions on event payload
  alert_severity TEXT NOT NULL DEFAULT 'medium'
    CHECK (alert_severity IN ('critical', 'high', 'medium', 'low', 'info')),
  alert_type TEXT NOT NULL DEFAULT 'vulnerability',
  tags TEXT,                                       -- JSON array of tags to apply to created alerts
  is_active INTEGER NOT NULL DEFAULT 1,
  auto_escalate INTEGER NOT NULL DEFAULT 0,        -- Auto-create incident on match
  cooldown_seconds INTEGER NOT NULL DEFAULT 300,   -- Deduplicate window
  last_triggered_at TEXT,
  trigger_count INTEGER NOT NULL DEFAULT 0,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_soc_rules_pattern ON soc_detection_rules(event_pattern);
CREATE INDEX IF NOT EXISTS idx_soc_rules_active ON soc_detection_rules(is_active);

-- Seed default SOC detection rules

-- Auto-alert on critical vulnerabilities
INSERT OR IGNORE INTO soc_detection_rules (id, name, description, event_pattern, conditions, alert_severity, alert_type, is_active, auto_escalate)
VALUES (
  'rule_critical_vuln',
  'Critical Vulnerability Detected',
  'Create SOC alert when a critical vulnerability is found by ForgeScan',
  'forge.vulnerability.detected',
  '{"severity":["critical"]}',
  'critical',
  'vulnerability',
  1,
  1
);

-- Auto-alert on successful exploitation
INSERT OR IGNORE INTO soc_detection_rules (id, name, description, event_pattern, conditions, alert_severity, alert_type, is_active, auto_escalate)
VALUES (
  'rule_exploitation_success',
  'Exploitation Confirmed',
  'Create SOC alert when ForgeRedOps confirms a vulnerability is exploitable',
  'forge.redops.exploitation.success',
  '{}',
  'high',
  'exploitation',
  1,
  0
);

-- Auto-alert on high-severity vulnerability findings
INSERT OR IGNORE INTO soc_detection_rules (id, name, description, event_pattern, conditions, alert_severity, alert_type, is_active, auto_escalate)
VALUES (
  'rule_high_vuln',
  'High Vulnerability Detected',
  'Create SOC alert when a high-severity vulnerability is found',
  'forge.vulnerability.detected',
  '{"severity":["high"]}',
  'high',
  'vulnerability',
  1,
  0
);

-- Auto-alert on RedOps campaign completion
INSERT OR IGNORE INTO soc_detection_rules (id, name, description, event_pattern, conditions, alert_severity, alert_type, is_active, auto_escalate)
VALUES (
  'rule_campaign_complete',
  'RedOps Campaign Completed',
  'Alert SOC when a RedOps campaign finishes with findings',
  'forge.redops.campaign.completed',
  '{"min_findings":1}',
  'medium',
  'security',
  1,
  0
);

-- Seed SOC event subscription in event bus to route events to the SOC handler
INSERT OR IGNORE INTO event_subscriptions (id, name, event_pattern, handler_type, handler_config, conditions, is_active, priority)
VALUES (
  'sub_soc_vuln_alert',
  'ForgeSOC: Alert on vulnerabilities',
  'forge.vulnerability.detected',
  'custom',
  '{"handler":"forgesoc_alert","action":"create_alert"}',
  '{"severity":["critical","high"]}',
  1,
  20
);

INSERT OR IGNORE INTO event_subscriptions (id, name, event_pattern, handler_type, handler_config, conditions, is_active, priority)
VALUES (
  'sub_soc_exploitation_alert',
  'ForgeSOC: Alert on exploitation',
  'forge.redops.exploitation.success',
  'custom',
  '{"handler":"forgesoc_alert","action":"create_alert"}',
  '{}',
  1,
  20
);
