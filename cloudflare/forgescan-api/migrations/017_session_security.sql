-- Migration 017: Session security enhancements
-- Adds account lockout fields and refresh token support

-- Account lockout columns on users table
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TEXT;

-- Refresh token support on sessions table
ALTER TABLE sessions ADD COLUMN refresh_token_hash TEXT;
ALTER TABLE sessions ADD COLUMN refresh_expires_at TEXT;

-- Index for refresh token lookups
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token_hash);
