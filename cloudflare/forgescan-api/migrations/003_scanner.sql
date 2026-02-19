-- Migration 003: Scanner Bridge
-- Creates tables for scanner registration and scan task dispatch

-- Scanner instances that connect to the Worker API via REST
CREATE TABLE IF NOT EXISTS scanner_registrations (
    id TEXT PRIMARY KEY,
    scanner_id TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL,
    version TEXT,
    status TEXT DEFAULT 'registered',
    capabilities TEXT DEFAULT '[]',
    api_key_hash TEXT NOT NULL,
    api_key_prefix TEXT NOT NULL,
    last_heartbeat_at TEXT,
    tasks_completed INTEGER DEFAULT 0,
    tasks_failed INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Individual task units dispatched to scanners
CREATE TABLE IF NOT EXISTS scan_tasks (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    scanner_id TEXT,
    task_type TEXT NOT NULL,
    task_payload TEXT NOT NULL,
    status TEXT DEFAULT 'queued',
    priority INTEGER DEFAULT 5,
    result_summary TEXT,
    findings_count INTEGER DEFAULT 0,
    assets_discovered INTEGER DEFAULT 0,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    assigned_at TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Indexes for scanner_registrations
CREATE INDEX IF NOT EXISTS idx_scanner_registrations_scanner_id ON scanner_registrations(scanner_id);
CREATE INDEX IF NOT EXISTS idx_scanner_registrations_status ON scanner_registrations(status);

-- Indexes for scan_tasks
CREATE INDEX IF NOT EXISTS idx_scan_tasks_scan_id ON scan_tasks(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_scanner_id ON scan_tasks(scanner_id);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_priority_status ON scan_tasks(priority, status);
