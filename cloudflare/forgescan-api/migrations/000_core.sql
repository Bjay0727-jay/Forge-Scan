-- ============================================================================
-- Migration 000: Core Tables
-- Creates the three foundational tables: assets, scans, and findings
-- These must exist before any other migration that references them.
-- ============================================================================

-- Discovered assets (hosts, containers, cloud resources, etc.)
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    fqdn TEXT,
    ip_addresses TEXT DEFAULT '[]',     -- JSON array of IP strings
    mac_addresses TEXT DEFAULT '[]',    -- JSON array of MAC strings
    os TEXT,
    os_version TEXT,
    asset_type TEXT DEFAULT 'unknown',
    network_zone TEXT,
    tags TEXT DEFAULT '[]',             -- JSON array of tag strings
    attributes TEXT DEFAULT '{}',       -- JSON object of extra metadata
    risk_score INTEGER DEFAULT 0,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Scan jobs (network, container, web, code, cloud, compliance)
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    name TEXT,
    scan_type TEXT NOT NULL,
    targets TEXT DEFAULT '[]',          -- JSON array of target strings
    config TEXT DEFAULT '{}',           -- JSON object of scan configuration
    status TEXT NOT NULL DEFAULT 'pending',
    findings_count INTEGER DEFAULT 0,
    assets_count INTEGER DEFAULT 0,
    error_message TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Individual vulnerability findings linked to assets and scans
CREATE TABLE IF NOT EXISTS findings (
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
    "references" TEXT DEFAULT '[]',     -- JSON array of reference URLs
    metadata TEXT DEFAULT '{}',         -- JSON object of extra data
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    fixed_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_asset_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_risk_score ON assets(risk_score);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_scan_type ON scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);

CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
CREATE INDEX IF NOT EXISTS idx_findings_vendor ON findings(vendor);
CREATE INDEX IF NOT EXISTS idx_findings_cve_id ON findings(cve_id);
