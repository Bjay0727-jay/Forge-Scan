-- Migration 004: Integration Hub
-- Creates tables for configured integration instances and dispatch logs

-- Configured integration instances (email, webhook, etc.)
CREATE TABLE IF NOT EXISTS integrations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    provider TEXT NOT NULL,
    config TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    last_tested_at TEXT,
    last_used_at TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Log of all integration dispatches
CREATE TABLE IF NOT EXISTS integration_logs (
    id TEXT PRIMARY KEY,
    integration_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    request_payload TEXT,
    response_code INTEGER,
    response_body TEXT,
    error_message TEXT,
    duration_ms INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE CASCADE
);

-- Indexes for integrations
CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(type);
CREATE INDEX IF NOT EXISTS idx_integrations_is_active ON integrations(is_active);

-- Indexes for integration_logs
CREATE INDEX IF NOT EXISTS idx_integration_logs_integration_id ON integration_logs(integration_id);
CREATE INDEX IF NOT EXISTS idx_integration_logs_event_type ON integration_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_integration_logs_status ON integration_logs(status);
CREATE INDEX IF NOT EXISTS idx_integration_logs_created_at ON integration_logs(created_at);
