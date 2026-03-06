-- ─────────────────────────────────────────────────────────────────────────────
-- 019: ForgeComply 360 Integration — Unified Data Model
-- ─────────────────────────────────────────────────────────────────────────────

-- Extend findings table for ForgeComply 360 alignment
ALTER TABLE findings ADD COLUMN plugin_id TEXT;
ALTER TABLE findings ADD COLUMN cvss3_score REAL;
ALTER TABLE findings ADD COLUMN control_mappings TEXT DEFAULT '[]';

-- Index for plugin_id lookups (Nessus dedup, ForgeComply correlation)
CREATE INDEX IF NOT EXISTS idx_findings_plugin_id ON findings(plugin_id);

-- Auto-evidence tracking: links scan events to compliance evidence
CREATE TABLE IF NOT EXISTS compliance_evidence_links (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  framework_id TEXT,
  control_id TEXT,
  finding_id TEXT,
  evidence_type TEXT NOT NULL DEFAULT 'scan_result',
  description TEXT,
  auto_generated INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (org_id) REFERENCES organizations(id),
  FOREIGN KEY (event_id) REFERENCES forge_events(id)
);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_links_org ON compliance_evidence_links(org_id);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_links_event ON compliance_evidence_links(event_id);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_links_control ON compliance_evidence_links(control_id);

-- Seed compliance_check subscription for auto-mapping findings to controls
INSERT OR IGNORE INTO event_subscriptions (id, name, event_pattern, handler_type, handler_config, conditions, is_active, priority, created_at, updated_at)
VALUES
  ('sub-comply-scan-complete', 'Auto-map scan findings to compliance controls', 'forge.scan.completed', 'compliance_check', '{"action":"map_findings","auto_poam":true,"auto_evidence":true}', '{}', 1, 40, datetime('now'), datetime('now')),
  ('sub-comply-vuln-detected', 'Map new vulnerabilities to compliance controls', 'forge.vulnerability.detected', 'compliance_check', '{"action":"map_single_finding","auto_evidence":true}', '{"severity":["critical","high"]}', 1, 45, datetime('now'), datetime('now'));
