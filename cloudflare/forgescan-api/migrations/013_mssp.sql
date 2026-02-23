-- ============================================================================
-- Migration 013: MSSP Multi-Tenant Support & White-Label
-- Adds organizations (tenants), membership, branding, and tenant isolation
-- ============================================================================

-- Organizations (tenants managed by the MSSP)
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  tier TEXT NOT NULL DEFAULT 'standard',  -- trial | standard | professional | enterprise
  status TEXT NOT NULL DEFAULT 'active',  -- active | suspended | deactivated
  max_assets INTEGER NOT NULL DEFAULT 1000,
  max_users INTEGER NOT NULL DEFAULT 25,
  max_scanners INTEGER NOT NULL DEFAULT 5,
  contact_email TEXT,
  contact_name TEXT,
  industry TEXT,
  notes TEXT,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Organization membership (user ↔ org many-to-many)
CREATE TABLE IF NOT EXISTS organization_members (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_role TEXT NOT NULL DEFAULT 'viewer',  -- owner | admin | analyst | viewer
  is_primary INTEGER NOT NULL DEFAULT 0,
  joined_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(organization_id, user_id)
);

-- White-label / branding configuration per organization
CREATE TABLE IF NOT EXISTS organization_branding (
  id TEXT PRIMARY KEY,
  organization_id TEXT UNIQUE NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  company_name TEXT,
  logo_url TEXT,
  favicon_url TEXT,
  primary_color TEXT DEFAULT '#14b8a6',
  accent_color TEXT DEFAULT '#0d9488',
  sidebar_bg TEXT DEFAULT '#0b1929',
  login_title TEXT,
  login_subtitle TEXT,
  support_email TEXT,
  support_url TEXT,
  custom_domain TEXT,
  powered_by_visible INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Add org_id to all major data tables for tenant isolation
ALTER TABLE assets ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE findings ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE scans ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE scan_tasks ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE scanner_registrations ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE integrations ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE notification_rules ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE reports ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE compliance_mappings ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE redops_campaigns ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE soc_alerts ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE soc_incidents ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE soc_detection_rules ADD COLUMN org_id TEXT REFERENCES organizations(id);
ALTER TABLE forge_events ADD COLUMN org_id TEXT REFERENCES organizations(id);

-- Indexes for tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id);
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id);
CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_org ON scan_tasks(org_id);
CREATE INDEX IF NOT EXISTS idx_scanner_reg_org ON scanner_registrations(org_id);
CREATE INDEX IF NOT EXISTS idx_integrations_org ON integrations(org_id);
CREATE INDEX IF NOT EXISTS idx_notification_rules_org ON notification_rules(org_id);
CREATE INDEX IF NOT EXISTS idx_reports_org ON reports(org_id);
CREATE INDEX IF NOT EXISTS idx_compliance_mappings_org ON compliance_mappings(org_id);
CREATE INDEX IF NOT EXISTS idx_redops_campaigns_org ON redops_campaigns(org_id);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_org ON soc_alerts(org_id);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_org ON soc_incidents(org_id);
CREATE INDEX IF NOT EXISTS idx_soc_detection_rules_org ON soc_detection_rules(org_id);
CREATE INDEX IF NOT EXISTS idx_forge_events_org ON forge_events(org_id);
CREATE INDEX IF NOT EXISTS idx_org_members_org ON organization_members(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_status ON organizations(status);
