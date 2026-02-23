-- ============================================================================
-- Migration 014: Container/K8s Scanning, SAST, SOAR Playbooks, Threat Intel
-- Closes competitive gaps with CrowdStrike, Palo Alto, SentinelOne
-- ============================================================================

-- ─── Container / Kubernetes Scanning ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS container_images (
  id TEXT PRIMARY KEY,
  org_id TEXT REFERENCES organizations(id),
  registry TEXT NOT NULL,         -- docker.io, ecr, gcr, ghcr, etc.
  repository TEXT NOT NULL,       -- e.g. "myapp/backend"
  tag TEXT NOT NULL DEFAULT 'latest',
  digest TEXT,                    -- sha256 digest
  os TEXT,
  architecture TEXT,
  size_bytes INTEGER,
  layer_count INTEGER,
  base_image TEXT,                -- parent image ref
  labels TEXT,                    -- JSON key-value
  first_seen TEXT NOT NULL DEFAULT (datetime('now')),
  last_scanned TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS container_scan_results (
  id TEXT PRIMARY KEY,
  image_id TEXT NOT NULL REFERENCES container_images(id) ON DELETE CASCADE,
  scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  org_id TEXT REFERENCES organizations(id),
  scanner TEXT NOT NULL DEFAULT 'forge',  -- forge, trivy, grype, snyk
  status TEXT NOT NULL DEFAULT 'pending', -- pending, running, completed, failed
  os_vulns INTEGER DEFAULT 0,
  app_vulns INTEGER DEFAULT 0,
  config_issues INTEGER DEFAULT 0,
  secrets_found INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  compliance_pass INTEGER DEFAULT 0,
  compliance_fail INTEGER DEFAULT 0,
  sbom TEXT,              -- JSON software bill of materials (top packages)
  started_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS container_findings (
  id TEXT PRIMARY KEY,
  scan_result_id TEXT NOT NULL REFERENCES container_scan_results(id) ON DELETE CASCADE,
  image_id TEXT NOT NULL REFERENCES container_images(id) ON DELETE CASCADE,
  org_id TEXT REFERENCES organizations(id),
  finding_type TEXT NOT NULL,     -- os_vuln, app_vuln, config, secret, license
  package_name TEXT,
  installed_version TEXT,
  fixed_version TEXT,
  cve_id TEXT,
  severity TEXT NOT NULL,
  cvss_score REAL,
  title TEXT NOT NULL,
  description TEXT,
  layer_index INTEGER,
  file_path TEXT,
  remediation TEXT,
  state TEXT NOT NULL DEFAULT 'open',  -- open, acknowledged, fixed, accepted, false_positive
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_container_images_org ON container_images(org_id);
CREATE INDEX IF NOT EXISTS idx_container_images_repo ON container_images(registry, repository);
CREATE INDEX IF NOT EXISTS idx_container_scan_results_image ON container_scan_results(image_id);
CREATE INDEX IF NOT EXISTS idx_container_findings_image ON container_findings(image_id);
CREATE INDEX IF NOT EXISTS idx_container_findings_cve ON container_findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_container_findings_severity ON container_findings(severity);

-- ─── SAST / Code Scanning ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sast_projects (
  id TEXT PRIMARY KEY,
  org_id TEXT REFERENCES organizations(id),
  name TEXT NOT NULL,
  repository_url TEXT,
  branch TEXT DEFAULT 'main',
  language TEXT,                  -- primary language
  languages TEXT,                 -- JSON array of all detected languages
  framework TEXT,                 -- detected framework
  loc INTEGER,                   -- lines of code
  file_count INTEGER,
  last_scanned TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sast_scan_results (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES sast_projects(id) ON DELETE CASCADE,
  scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  org_id TEXT REFERENCES organizations(id),
  status TEXT NOT NULL DEFAULT 'pending',  -- pending, analyzing, completed, failed
  commit_sha TEXT,
  branch TEXT,
  files_analyzed INTEGER DEFAULT 0,
  issues_found INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  info_count INTEGER DEFAULT 0,
  scan_duration_ms INTEGER,
  rules_applied INTEGER DEFAULT 0,
  started_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sast_findings (
  id TEXT PRIMARY KEY,
  scan_result_id TEXT NOT NULL REFERENCES sast_scan_results(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES sast_projects(id) ON DELETE CASCADE,
  org_id TEXT REFERENCES organizations(id),
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  category TEXT NOT NULL,         -- injection, xss, auth, crypto, config, info_leak, etc.
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'high',  -- high, medium, low
  file_path TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  end_line INTEGER,
  start_column INTEGER,
  code_snippet TEXT,              -- relevant code context
  message TEXT NOT NULL,
  cwe_id TEXT,
  owasp_category TEXT,            -- A01:2021, A02:2021, etc.
  remediation TEXT,
  fix_suggestion TEXT,            -- AI-generated fix
  state TEXT NOT NULL DEFAULT 'open',
  false_positive_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sast_projects_org ON sast_projects(org_id);
CREATE INDEX IF NOT EXISTS idx_sast_scan_results_project ON sast_scan_results(project_id);
CREATE INDEX IF NOT EXISTS idx_sast_findings_project ON sast_findings(project_id);
CREATE INDEX IF NOT EXISTS idx_sast_findings_rule ON sast_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_sast_findings_severity ON sast_findings(severity);
CREATE INDEX IF NOT EXISTS idx_sast_findings_cwe ON sast_findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_sast_findings_file ON sast_findings(file_path);

-- ─── SOAR Playbooks ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS soar_playbooks (
  id TEXT PRIMARY KEY,
  org_id TEXT REFERENCES organizations(id),
  name TEXT NOT NULL,
  description TEXT,
  trigger_type TEXT NOT NULL,      -- event_pattern, manual, scheduled, alert_threshold
  trigger_config TEXT NOT NULL,    -- JSON: { event_pattern, schedule, threshold_count, threshold_window }
  steps TEXT NOT NULL,             -- JSON array of action steps
  enabled INTEGER NOT NULL DEFAULT 1,
  severity_filter TEXT,            -- comma-separated: "critical,high"
  max_concurrent INTEGER DEFAULT 5,
  cooldown_seconds INTEGER DEFAULT 300,
  last_triggered_at TEXT,
  trigger_count INTEGER DEFAULT 0,
  success_count INTEGER DEFAULT 0,
  failure_count INTEGER DEFAULT 0,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS soar_executions (
  id TEXT PRIMARY KEY,
  playbook_id TEXT NOT NULL REFERENCES soar_playbooks(id) ON DELETE CASCADE,
  org_id TEXT REFERENCES organizations(id),
  trigger_event_id TEXT,           -- event that triggered this execution
  trigger_alert_id TEXT REFERENCES soc_alerts(id) ON DELETE SET NULL,
  trigger_incident_id TEXT REFERENCES soc_incidents(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'running',  -- running, completed, failed, cancelled
  current_step INTEGER DEFAULT 0,
  total_steps INTEGER DEFAULT 0,
  step_results TEXT,               -- JSON array of per-step results
  context TEXT,                    -- JSON: accumulated context variables
  error_message TEXT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS soar_action_log (
  id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL REFERENCES soar_executions(id) ON DELETE CASCADE,
  step_index INTEGER NOT NULL,
  action_type TEXT NOT NULL,       -- isolate_host, block_ip, create_ticket, send_notification, enrich_ioc, run_scan, update_alert, escalate, webhook, wait
  action_config TEXT NOT NULL,     -- JSON config for this specific action
  status TEXT NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed, skipped
  result TEXT,                     -- JSON result
  error_message TEXT,
  started_at TEXT,
  completed_at TEXT,
  duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_soar_playbooks_org ON soar_playbooks(org_id);
CREATE INDEX IF NOT EXISTS idx_soar_playbooks_trigger ON soar_playbooks(trigger_type);
CREATE INDEX IF NOT EXISTS idx_soar_executions_playbook ON soar_executions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_soar_executions_status ON soar_executions(status);
CREATE INDEX IF NOT EXISTS idx_soar_action_log_exec ON soar_action_log(execution_id);

-- ─── Threat Intel Feeds ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_intel_feeds (
  id TEXT PRIMARY KEY,
  org_id TEXT REFERENCES organizations(id),
  name TEXT NOT NULL,
  feed_type TEXT NOT NULL,        -- vulnerability, indicator, malware, apt, abuse
  source_url TEXT,
  format TEXT DEFAULT 'stix',     -- stix, csv, json, taxii, misp
  auth_config TEXT,               -- JSON: { api_key, bearer_token, basic_auth }
  poll_interval_minutes INTEGER DEFAULT 60,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_fetch_at TEXT,
  last_fetch_status TEXT,         -- success, failed, partial
  indicators_count INTEGER DEFAULT 0,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS threat_intel_indicators (
  id TEXT PRIMARY KEY,
  feed_id TEXT NOT NULL REFERENCES threat_intel_feeds(id) ON DELETE CASCADE,
  org_id TEXT REFERENCES organizations(id),
  indicator_type TEXT NOT NULL,   -- ip, domain, url, hash_md5, hash_sha1, hash_sha256, email, cve, cidr
  indicator_value TEXT NOT NULL,
  severity TEXT DEFAULT 'medium',
  confidence INTEGER DEFAULT 50,  -- 0-100
  tlp TEXT DEFAULT 'amber',       -- white, green, amber, red
  tags TEXT,                      -- JSON array
  context TEXT,                   -- JSON: additional context from feed
  source_ref TEXT,                -- original reference ID from feed
  first_seen TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS threat_intel_matches (
  id TEXT PRIMARY KEY,
  indicator_id TEXT NOT NULL REFERENCES threat_intel_indicators(id) ON DELETE CASCADE,
  org_id TEXT REFERENCES organizations(id),
  match_type TEXT NOT NULL,       -- asset_ip, finding_cve, domain_match, hash_match
  matched_entity_type TEXT NOT NULL, -- asset, finding, soc_alert, container_image
  matched_entity_id TEXT NOT NULL,
  match_confidence INTEGER DEFAULT 100, -- 0-100
  alert_id TEXT REFERENCES soc_alerts(id) ON DELETE SET NULL,
  acknowledged INTEGER DEFAULT 0,
  matched_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ti_feeds_org ON threat_intel_feeds(org_id);
CREATE INDEX IF NOT EXISTS idx_ti_indicators_feed ON threat_intel_indicators(feed_id);
CREATE INDEX IF NOT EXISTS idx_ti_indicators_type ON threat_intel_indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_ti_indicators_value ON threat_intel_indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_ti_indicators_active ON threat_intel_indicators(is_active);
CREATE INDEX IF NOT EXISTS idx_ti_matches_indicator ON threat_intel_matches(indicator_id);
CREATE INDEX IF NOT EXISTS idx_ti_matches_entity ON threat_intel_matches(matched_entity_type, matched_entity_id);
