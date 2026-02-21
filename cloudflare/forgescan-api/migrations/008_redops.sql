-- ============================================================================
-- Migration 008: ForgeRedOPS — AI Penetration Testing & Offensive Security
-- ============================================================================

-- Pen test campaigns (top-level orchestration unit)
CREATE TABLE IF NOT EXISTS redops_campaigns (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'created'
    CHECK (status IN ('created', 'queued', 'reconnaissance', 'scanning', 'exploitation', 'reporting', 'completed', 'failed', 'cancelled')),
  campaign_type TEXT NOT NULL DEFAULT 'full'
    CHECK (campaign_type IN ('full', 'targeted', 'continuous', 'validation')),

  -- Targeting
  target_scope TEXT NOT NULL,            -- JSON: { hosts: [], networks: [], urls: [], domains: [] }
  exclusions TEXT,                        -- JSON: { hosts: [], networks: [], paths: [] }

  -- Agent configuration
  agent_categories TEXT NOT NULL DEFAULT '["web","api","cloud","network","identity"]',  -- JSON array
  max_concurrent_agents INTEGER NOT NULL DEFAULT 6,
  exploitation_level TEXT NOT NULL DEFAULT 'safe'
    CHECK (exploitation_level IN ('passive', 'safe', 'moderate', 'aggressive')),

  -- Risk & compliance
  risk_threshold TEXT DEFAULT 'critical', -- Minimum severity to attempt exploitation
  auto_poam INTEGER NOT NULL DEFAULT 0,  -- Auto-generate POA&M entries
  compliance_mapping INTEGER NOT NULL DEFAULT 1, -- Auto-map to NIST controls

  -- Schedule
  scheduled_at TEXT,                      -- ISO datetime for scheduled campaigns

  -- Progress
  total_agents INTEGER NOT NULL DEFAULT 0,
  active_agents INTEGER NOT NULL DEFAULT 0,
  completed_agents INTEGER NOT NULL DEFAULT 0,
  failed_agents INTEGER NOT NULL DEFAULT 0,

  -- Results summary
  findings_count INTEGER NOT NULL DEFAULT 0,
  critical_count INTEGER NOT NULL DEFAULT 0,
  high_count INTEGER NOT NULL DEFAULT 0,
  medium_count INTEGER NOT NULL DEFAULT 0,
  low_count INTEGER NOT NULL DEFAULT 0,
  info_count INTEGER NOT NULL DEFAULT 0,
  exploitable_count INTEGER NOT NULL DEFAULT 0,

  -- Metadata
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  started_at TEXT,
  completed_at TEXT,
  duration_seconds INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_redops_campaigns_status ON redops_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_redops_campaigns_created_at ON redops_campaigns(created_at);

-- AI agent instances (individual pen test agents within a campaign)
CREATE TABLE IF NOT EXISTS redops_agents (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES redops_campaigns(id) ON DELETE CASCADE,

  agent_type TEXT NOT NULL
    CHECK (agent_type IN (
      'web_injection', 'web_xss', 'web_csrf', 'web_ssrf', 'web_auth', 'web_misconfig',
      'api_auth_bypass', 'api_bola', 'api_rate_limit', 'api_injection',
      'cloud_iam', 'cloud_storage', 'cloud_network', 'cloud_compute', 'cloud_secrets', 'cloud_logging',
      'net_portscan', 'net_service_enum', 'net_lateral', 'net_pivot',
      'id_credential', 'id_session', 'id_privilege_esc', 'id_password_spray'
    )),
  agent_category TEXT NOT NULL
    CHECK (agent_category IN ('web', 'api', 'cloud', 'network', 'identity')),

  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'initializing', 'reconnaissance', 'testing', 'exploiting', 'reporting', 'completed', 'failed', 'stopped')),

  -- Target assignment
  target TEXT,                            -- Specific target for this agent

  -- Progress
  tests_planned INTEGER NOT NULL DEFAULT 0,
  tests_completed INTEGER NOT NULL DEFAULT 0,
  tests_passed INTEGER NOT NULL DEFAULT 0,    -- No vulnerability found
  tests_failed INTEGER NOT NULL DEFAULT 0,    -- Vulnerability confirmed

  -- Results
  findings_count INTEGER NOT NULL DEFAULT 0,
  exploitable_count INTEGER NOT NULL DEFAULT 0,

  -- Execution details
  last_activity TEXT,
  error_message TEXT,
  execution_log TEXT,                     -- JSON array of log entries

  -- Timing
  started_at TEXT,
  completed_at TEXT,
  duration_seconds INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_redops_agents_campaign ON redops_agents(campaign_id);
CREATE INDEX IF NOT EXISTS idx_redops_agents_status ON redops_agents(status);
CREATE INDEX IF NOT EXISTS idx_redops_agents_type ON redops_agents(agent_type);

-- Pen test findings (vulnerabilities discovered by AI agents)
CREATE TABLE IF NOT EXISTS redops_findings (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES redops_campaigns(id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL REFERENCES redops_agents(id) ON DELETE CASCADE,
  asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,

  -- Finding details
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL DEFAULT 'info'
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),

  -- Attack details
  attack_vector TEXT,                     -- e.g., "SQL Injection via login form"
  attack_category TEXT,                   -- OWASP/CWE category
  cwe_id TEXT,                            -- CWE identifier (e.g., "CWE-89")
  cve_id TEXT,                            -- Related CVE if applicable
  cvss_score REAL,

  -- Exploitation
  exploitable INTEGER NOT NULL DEFAULT 0,
  exploitation_proof TEXT,                -- Evidence/proof of exploitation
  exploitation_steps TEXT,                -- JSON array of steps taken

  -- MITRE ATT&CK mapping
  mitre_tactic TEXT,                      -- e.g., "initial-access", "lateral-movement"
  mitre_technique TEXT,                   -- e.g., "T1190", "T1021"

  -- Remediation
  remediation TEXT,
  remediation_effort TEXT                 -- 'quick_fix', 'moderate', 'significant', 'architectural'
    CHECK (remediation_effort IN ('quick_fix', 'moderate', 'significant', 'architectural')),

  -- Compliance mapping
  nist_controls TEXT,                     -- JSON array of mapped NIST 800-53 controls

  -- Status tracking
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'confirmed', 'remediated', 'accepted_risk', 'false_positive')),

  -- Linked data
  vulnerability_id TEXT REFERENCES vulnerabilities(id) ON DELETE SET NULL,
  finding_id TEXT REFERENCES findings(id) ON DELETE SET NULL,    -- Link to ForgeScan finding

  -- Evidence
  request_data TEXT,                      -- HTTP request that triggered the finding
  response_data TEXT,                     -- Server response
  screenshot_key TEXT,                    -- R2 key for screenshot evidence

  -- Metadata
  discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_redops_findings_campaign ON redops_findings(campaign_id);
CREATE INDEX IF NOT EXISTS idx_redops_findings_agent ON redops_findings(agent_id);
CREATE INDEX IF NOT EXISTS idx_redops_findings_severity ON redops_findings(severity);
CREATE INDEX IF NOT EXISTS idx_redops_findings_status ON redops_findings(status);
CREATE INDEX IF NOT EXISTS idx_redops_findings_exploitable ON redops_findings(exploitable);

-- Agent type definitions (metadata about each agent type)
CREATE TABLE IF NOT EXISTS redops_agent_types (
  id TEXT PRIMARY KEY,                    -- Same as agent_type enum value
  category TEXT NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT,
  test_count INTEGER NOT NULL DEFAULT 0,  -- Number of tests this agent runs
  mitre_techniques TEXT,                  -- JSON array of MITRE techniques covered
  owasp_categories TEXT,                  -- JSON array of OWASP categories covered
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed agent type definitions
INSERT OR IGNORE INTO redops_agent_types (id, category, display_name, description, test_count, mitre_techniques, owasp_categories) VALUES
  -- Web Application Agents (6)
  ('web_injection', 'web', 'SQL/NoSQL Injection', 'Tests for SQL injection, NoSQL injection, LDAP injection, and command injection vulnerabilities', 45, '["T1190","T1059"]', '["A03:2021"]'),
  ('web_xss', 'web', 'Cross-Site Scripting', 'Tests for reflected, stored, and DOM-based XSS vulnerabilities', 38, '["T1189","T1059.007"]', '["A03:2021"]'),
  ('web_csrf', 'web', 'Cross-Site Request Forgery', 'Tests for CSRF token absence, weak tokens, and same-site cookie issues', 18, '["T1185"]', '["A01:2021"]'),
  ('web_ssrf', 'web', 'Server-Side Request Forgery', 'Tests for SSRF via URL parameters, file uploads, and XML/JSON parsing', 22, '["T1190"]', '["A10:2021"]'),
  ('web_auth', 'web', 'Authentication Bypass', 'Tests for broken authentication, session fixation, and credential stuffing', 35, '["T1078","T1110"]', '["A07:2021"]'),
  ('web_misconfig', 'web', 'Security Misconfiguration', 'Tests for default credentials, debug endpoints, directory listing, and header issues', 52, '["T1190"]', '["A05:2021"]'),

  -- API Security Agents (4)
  ('api_auth_bypass', 'api', 'API Auth Bypass', 'Tests for broken object-level authorization, function-level authorization, and JWT vulnerabilities', 28, '["T1078"]', '["A01:2021"]'),
  ('api_bola', 'api', 'Broken Object Level Auth', 'Tests for IDOR, horizontal privilege escalation, and data exposure through API endpoints', 24, '["T1078"]', '["A01:2021"]'),
  ('api_rate_limit', 'api', 'Rate Limiting & DoS', 'Tests for missing rate limits, resource exhaustion, and denial of service vectors', 15, '["T1499"]', '["A04:2021"]'),
  ('api_injection', 'api', 'API Injection', 'Tests for injection through API parameters, headers, and body payloads', 32, '["T1190","T1059"]', '["A03:2021"]'),

  -- Cloud Configuration Agents (6)
  ('cloud_iam', 'cloud', 'IAM Misconfiguration', 'Tests for overly permissive IAM policies, unused credentials, and role escalation paths', 48, '["T1078.004","T1098"]', '[]'),
  ('cloud_storage', 'cloud', 'Storage Exposure', 'Tests for public S3 buckets, blob storage access, and data exposure', 25, '["T1530"]', '[]'),
  ('cloud_network', 'cloud', 'Network Security', 'Tests for open security groups, public subnets, and network ACL misconfigurations', 35, '["T1190"]', '[]'),
  ('cloud_compute', 'cloud', 'Compute Security', 'Tests for unpatched instances, metadata exposure, and instance profile abuse', 30, '["T1190","T1552"]', '[]'),
  ('cloud_secrets', 'cloud', 'Secrets Management', 'Tests for hardcoded secrets, exposed environment variables, and secret rotation', 20, '["T1552"]', '[]'),
  ('cloud_logging', 'cloud', 'Logging & Monitoring', 'Tests for disabled CloudTrail, missing log groups, and audit gaps', 22, '["T1562.008"]', '[]'),

  -- Network Agents (4)
  ('net_portscan', 'network', 'Port Scanning', 'Discovers open ports, running services, and version detection across target scope', 0, '["T1046"]', '[]'),
  ('net_service_enum', 'network', 'Service Enumeration', 'Deep enumeration of discovered services for known vulnerabilities and misconfigurations', 0, '["T1046","T1018"]', '[]'),
  ('net_lateral', 'network', 'Lateral Movement', 'Tests for lateral movement paths using discovered credentials and trust relationships', 28, '["T1021","T1071"]', '[]'),
  ('net_pivot', 'network', 'Network Pivoting', 'Tests for network segmentation bypasses and pivot points between zones', 18, '["T1090"]', '[]'),

  -- Identity & Access Agents (4)
  ('id_credential', 'identity', 'Credential Testing', 'Tests for default credentials, leaked credentials, and weak password policies', 40, '["T1110","T1078"]', '["A07:2021"]'),
  ('id_session', 'identity', 'Session Hijacking', 'Tests for session fixation, cookie theft, and insecure session management', 22, '["T1185","T1539"]', '["A07:2021"]'),
  ('id_privilege_esc', 'identity', 'Privilege Escalation', 'Tests for vertical privilege escalation through role abuse and permission flaws', 30, '["T1068","T1548"]', '["A01:2021"]'),
  ('id_password_spray', 'identity', 'Password Spraying', 'Controlled password spray testing with lockout awareness and timing controls', 12, '["T1110.003"]', '["A07:2021"]');
