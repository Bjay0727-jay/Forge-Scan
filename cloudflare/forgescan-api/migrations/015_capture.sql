-- Migration 015: Packet Capture
-- Adds table for capture session metadata.
-- Raw PCAPs are stored locally on scanners or in R2 — never in D1.

CREATE TABLE IF NOT EXISTS capture_sessions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    scan_id TEXT,
    scanner_id TEXT NOT NULL,
    interface TEXT,
    filter TEXT,
    capture_mode TEXT NOT NULL DEFAULT 'targeted',  -- targeted, scan_correlated, passive
    status TEXT NOT NULL DEFAULT 'running',          -- running, completed, failed, cancelled
    packets_captured INTEGER DEFAULT 0,
    bytes_captured INTEGER DEFAULT 0,
    capture_duration_ms INTEGER DEFAULT 0,
    protocol_breakdown TEXT,                         -- JSON map of protocol -> count
    top_talkers TEXT,                                -- JSON array of [ip, bytes] pairs
    pcap_r2_key TEXT,                                -- R2 object key if uploaded
    pcap_size_bytes INTEGER DEFAULT 0,
    started_at TEXT DEFAULT (datetime('now')),
    ended_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (task_id) REFERENCES scan_tasks(id),
    FOREIGN KEY (scanner_id) REFERENCES scanner_registrations(scanner_id)
);

CREATE INDEX IF NOT EXISTS idx_capture_sessions_task_id ON capture_sessions(task_id);
CREATE INDEX IF NOT EXISTS idx_capture_sessions_scanner_id ON capture_sessions(scanner_id);
CREATE INDEX IF NOT EXISTS idx_capture_sessions_scan_id ON capture_sessions(scan_id);
CREATE INDEX IF NOT EXISTS idx_capture_sessions_status ON capture_sessions(status);
