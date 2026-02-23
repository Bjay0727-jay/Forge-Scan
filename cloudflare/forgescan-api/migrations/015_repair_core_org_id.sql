-- ============================================================================
-- Migration 015: Repair core tables — add org_id after 000_core DROP/CREATE
--
-- Migration 000_core.sql dropped and recreated assets, scans, and findings.
-- Migration 013 (which adds org_id via ALTER TABLE) had already been applied
-- and won't re-run, so the recreated tables are missing org_id.
--
-- This migration drops and recreates all three tables with the complete
-- schema including org_id.  This is safe because no production data exists
-- yet (only demo-seeded data which the seed endpoint will repopulate).
-- ============================================================================

-- Drop in reverse dependency order
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS assets;

-- Discovered assets
CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    fqdn TEXT,
    ip_addresses TEXT DEFAULT '[]',
    mac_addresses TEXT DEFAULT '[]',
    os TEXT,
    os_version TEXT,
    asset_type TEXT DEFAULT 'unknown',
    network_zone TEXT,
    tags TEXT DEFAULT '[]',
    attributes TEXT DEFAULT '{}',
    risk_score INTEGER DEFAULT 0,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    org_id TEXT
);

-- Scan jobs
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    name TEXT,
    scan_type TEXT NOT NULL,
    targets TEXT DEFAULT '[]',
    config TEXT DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    findings_count INTEGER DEFAULT 0,
    assets_count INTEGER DEFAULT 0,
    error_message TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    org_id TEXT
);

-- Vulnerability findings
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
    vulnerability_id TEXT,
    vendor TEXT,
    vendor_id TEXT,
    title TEXT,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    frs_score REAL,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    state TEXT NOT NULL DEFAULT 'open',
    solution TEXT,
    remediation TEXT,
    evidence TEXT,
    cve_id TEXT,
    cvss_score REAL,
    risk_score REAL,
    affected_component TEXT,
    "references" TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}',
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    fixed_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    org_id TEXT
);

-- Recreate all indexes
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_asset_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_risk_score ON assets(risk_score);
CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_scan_type ON scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id);

CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
CREATE INDEX IF NOT EXISTS idx_findings_vendor ON findings(vendor);
CREATE INDEX IF NOT EXISTS idx_findings_cve_id ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id);
