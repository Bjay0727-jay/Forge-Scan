-- Migration 002: NVD/CVE Sync tables
-- Run: wrangler d1 execute forgescan-db --file=migrations/002_nvd_sync.sql

-- Ensure vulnerabilities table exists with all needed columns
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,
    description TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    cvss_version TEXT DEFAULT '3.1',
    epss_score REAL,
    epss_percentile REAL,
    in_kev INTEGER DEFAULT 0,
    kev_date_added TEXT,
    kev_due_date TEXT,
    cwe_ids TEXT DEFAULT '[]',
    affected_products TEXT DEFAULT '[]',
    references_list TEXT DEFAULT '[]',
    severity TEXT,
    published_at TEXT,
    modified_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Sync state singleton table
CREATE TABLE IF NOT EXISTS nvd_sync_state (
    id TEXT PRIMARY KEY DEFAULT 'current',
    last_full_sync_at TEXT,
    last_incremental_sync_at TEXT,
    last_modified_date TEXT,
    total_cves_synced INTEGER DEFAULT 0,
    last_kev_sync_at TEXT,
    last_epss_sync_at TEXT,
    kev_total INTEGER DEFAULT 0,
    epss_total INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Sync jobs table for tracking chunked sync progress
CREATE TABLE IF NOT EXISTS nvd_sync_jobs (
    id TEXT PRIMARY KEY,
    sync_type TEXT NOT NULL DEFAULT 'incremental',
    source TEXT DEFAULT 'nvd',
    config TEXT DEFAULT '{}',
    status TEXT DEFAULT 'pending',
    cursor INTEGER DEFAULT 0,
    total_results INTEGER DEFAULT 0,
    records_processed INTEGER DEFAULT 0,
    records_added INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    current_page INTEGER DEFAULT 0,
    total_pages INTEGER DEFAULT 0,
    error_message TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Initialize sync state if not exists
INSERT OR IGNORE INTO nvd_sync_state (id) VALUES ('current');

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss ON vulnerabilities(cvss_score);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_epss ON vulnerabilities(epss_score);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_kev ON vulnerabilities(in_kev);
CREATE INDEX IF NOT EXISTS idx_nvd_sync_jobs_status ON nvd_sync_jobs(status);
