-- Phase 7: Reporting Engine
-- Ensure reports and export_schedules tables exist with proper schema

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  report_type TEXT NOT NULL,
  format TEXT DEFAULT 'json',
  filters TEXT DEFAULT '{}',
  storage_key TEXT,
  file_size INTEGER DEFAULT 0,
  status TEXT DEFAULT 'pending',
  generated_by TEXT,
  error_message TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  completed_at TEXT,
  FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS export_schedules (
  id TEXT PRIMARY KEY,
  export_type TEXT NOT NULL,
  format TEXT NOT NULL DEFAULT 'csv',
  schedule TEXT NOT NULL DEFAULT 'weekly',
  filters TEXT DEFAULT '{}',
  destination TEXT DEFAULT '{"type":"r2"}',
  enabled INTEGER DEFAULT 1,
  next_run TEXT,
  last_run TEXT,
  run_count INTEGER DEFAULT 0,
  created_by TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
CREATE INDEX IF NOT EXISTS idx_export_schedules_enabled ON export_schedules(enabled);
CREATE INDEX IF NOT EXISTS idx_export_schedules_next_run ON export_schedules(next_run);
