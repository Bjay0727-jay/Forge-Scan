-- ─────────────────────────────────────────────────────────────────────────────
-- 018: Nessus scan imports, Evidence vault, POA&M automation
-- ─────────────────────────────────────────────────────────────────────────────

-- ─── Scan Imports (tracks Nessus/.nessus file imports) ───────────────────────
CREATE TABLE IF NOT EXISTS scan_imports (
  id TEXT PRIMARY KEY,
  org_id TEXT,
  scan_id TEXT,
  vendor TEXT NOT NULL DEFAULT 'nessus',
  file_name TEXT,
  file_hash TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  hosts_total INTEGER DEFAULT 0,
  hosts_processed INTEGER DEFAULT 0,
  findings_created INTEGER DEFAULT 0,
  findings_updated INTEGER DEFAULT 0,
  errors TEXT,
  started_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);
CREATE INDEX IF NOT EXISTS idx_scan_imports_org ON scan_imports(org_id);
CREATE INDEX IF NOT EXISTS idx_scan_imports_status ON scan_imports(status);

-- ─── Evidence Files (R2-backed evidence vault) ──────────────────────────────
CREATE TABLE IF NOT EXISTS evidence_files (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  file_name TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  r2_key TEXT NOT NULL,
  sha256_hash TEXT NOT NULL,
  uploaded_by TEXT NOT NULL,
  compliance_mapping_id TEXT,
  finding_id TEXT,
  tags TEXT DEFAULT '[]',
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (org_id) REFERENCES organizations(id),
  FOREIGN KEY (uploaded_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_files_org ON evidence_files(org_id);
CREATE INDEX IF NOT EXISTS idx_evidence_files_mapping ON evidence_files(compliance_mapping_id);
CREATE INDEX IF NOT EXISTS idx_evidence_files_finding ON evidence_files(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_files_expires ON evidence_files(expires_at);

-- ─── POA&M Items (Plan of Action & Milestones) ─────────────────────────────
CREATE TABLE IF NOT EXISTS poam_items (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  finding_id TEXT,
  finding_title TEXT NOT NULL,
  weakness TEXT NOT NULL DEFAULT 'Unclassified',
  severity TEXT NOT NULL,
  controls TEXT DEFAULT '[]',
  remediation TEXT DEFAULT 'Pending assessment',
  remediation_effort TEXT DEFAULT 'moderate',
  scheduled_completion TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  milestones TEXT DEFAULT '[]',
  assigned_to TEXT,
  notes TEXT,
  created_by TEXT,
  closed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (org_id) REFERENCES organizations(id),
  FOREIGN KEY (finding_id) REFERENCES findings(id)
);
CREATE INDEX IF NOT EXISTS idx_poam_items_org ON poam_items(org_id);
CREATE INDEX IF NOT EXISTS idx_poam_items_status ON poam_items(status);
CREATE INDEX IF NOT EXISTS idx_poam_items_finding ON poam_items(finding_id);
CREATE INDEX IF NOT EXISTS idx_poam_items_severity ON poam_items(severity);
