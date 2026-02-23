-- ============================================================================
-- Migration 012: ForgeML — ML Correlation Columns for SOC Alerts
-- ============================================================================

-- Add confidence scoring columns to soc_alerts
ALTER TABLE soc_alerts ADD COLUMN confidence_score INTEGER;
ALTER TABLE soc_alerts ADD COLUMN confidence_level TEXT;
ALTER TABLE soc_alerts ADD COLUMN confidence_signals TEXT;  -- JSON array of signal breakdowns

CREATE INDEX IF NOT EXISTS idx_soc_alerts_confidence ON soc_alerts(confidence_score);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_confidence_level ON soc_alerts(confidence_level);
