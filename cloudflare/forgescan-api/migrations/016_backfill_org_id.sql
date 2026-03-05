-- Migration 016: Backfill NULL org_id values
-- Assigns all existing records with NULL org_id to a default organization.
-- This ensures multi-tenant data isolation can be enforced consistently.

-- Create a default organization for existing data
INSERT OR IGNORE INTO organizations (id, name, slug, tier, status, max_assets, max_users, max_scanners, created_at, updated_at)
VALUES ('org-default', 'Default Organization', 'default', 'enterprise', 'active', 100000, 1000, 100, datetime('now'), datetime('now'));

-- Backfill org_id on all tables that were given the column in migration 013
UPDATE assets SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE findings SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE scans SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE scan_tasks SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE scanner_registrations SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE integrations SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE notification_rules SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE reports SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE compliance_mappings SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE redops_campaigns SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE soc_alerts SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE soc_incidents SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE soc_detection_rules SET org_id = 'org-default' WHERE org_id IS NULL;
UPDATE forge_events SET org_id = 'org-default' WHERE org_id IS NULL;

-- Assign all existing users without an org membership to the default org
INSERT OR IGNORE INTO organization_members (id, organization_id, user_id, org_role, is_primary, joined_at)
SELECT
  'om-' || id,
  'org-default',
  id,
  CASE WHEN role = 'platform_admin' THEN 'owner' ELSE 'analyst' END,
  1,
  datetime('now')
FROM users
WHERE id NOT IN (SELECT user_id FROM organization_members);
