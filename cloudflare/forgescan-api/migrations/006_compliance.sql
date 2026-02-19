-- Phase 6: Compliance Mapping
-- Tables for compliance frameworks, controls, and finding-to-control mappings

-- Compliance frameworks (NIST, CIS, PCI DSS, HIPAA, etc.)
CREATE TABLE IF NOT EXISTS compliance_frameworks (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  short_name TEXT NOT NULL UNIQUE,
  version TEXT,
  description TEXT,
  controls_count INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Individual controls within a framework
CREATE TABLE IF NOT EXISTS compliance_controls (
  id TEXT PRIMARY KEY,
  framework_id TEXT NOT NULL,
  control_id TEXT NOT NULL,
  control_name TEXT NOT NULL,
  description TEXT,
  family TEXT,
  level TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(framework_id, control_id),
  FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(id) ON DELETE CASCADE
);

-- Mappings linking findings/vulnerabilities to compliance controls
CREATE TABLE IF NOT EXISTS compliance_mappings (
  id TEXT PRIMARY KEY,
  finding_id TEXT,
  vulnerability_id TEXT,
  framework_id TEXT NOT NULL,
  control_id TEXT NOT NULL,
  status TEXT DEFAULT 'non_compliant',
  evidence TEXT,
  assessed_at TEXT DEFAULT (datetime('now')),
  assessed_by TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL,
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE SET NULL,
  FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(id) ON DELETE CASCADE
);

-- Indexes for compliance_controls
CREATE INDEX IF NOT EXISTS idx_compliance_controls_framework_id ON compliance_controls(framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_controls_family ON compliance_controls(family);

-- Indexes for compliance_mappings
CREATE INDEX IF NOT EXISTS idx_compliance_mappings_framework_id ON compliance_mappings(framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_mappings_finding_id ON compliance_mappings(finding_id);
CREATE INDEX IF NOT EXISTS idx_compliance_mappings_status ON compliance_mappings(status);
