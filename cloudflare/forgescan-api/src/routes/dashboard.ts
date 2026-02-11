import { Hono } from 'hono';
import type { Env } from '../index';

export const dashboard = new Hono<{ Bindings: Env }>();

// Get dashboard overview
dashboard.get('/overview', async (c) => {
  // Try to get from cache first
  const cacheKey = 'dashboard:overview';
  const cached = await c.env.CACHE.get(cacheKey);
  if (cached) {
    return c.json(JSON.parse(cached));
  }

  // Get total counts
  const totals = await c.env.DB.prepare(`
    SELECT
      (SELECT COUNT(*) FROM assets) as total_assets,
      (SELECT COUNT(*) FROM findings WHERE state = 'open') as open_findings,
      (SELECT COUNT(*) FROM findings WHERE state = 'fixed') as fixed_findings,
      (SELECT COUNT(*) FROM scans WHERE status = 'completed') as completed_scans
  `).first();

  // Get severity breakdown
  const severityCounts = await c.env.DB.prepare(`
    SELECT severity, COUNT(*) as count
    FROM findings
    WHERE state = 'open'
    GROUP BY severity
  `).all();

  // Get recent findings
  const recentFindings = await c.env.DB.prepare(`
    SELECT f.id, f.title, f.severity, f.vendor, f.created_at, a.hostname
    FROM findings f
    LEFT JOIN assets a ON f.asset_id = a.id
    WHERE f.state = 'open'
    ORDER BY f.created_at DESC
    LIMIT 10
  `).all();

  // Get top vulnerable assets
  const topAssets = await c.env.DB.prepare(`
    SELECT
      a.id,
      a.hostname,
      a.ip_addresses,
      COUNT(f.id) as finding_count,
      SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
      SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high_count
    FROM assets a
    LEFT JOIN findings f ON a.id = f.asset_id AND f.state = 'open'
    GROUP BY a.id
    HAVING finding_count > 0
    ORDER BY critical_count DESC, high_count DESC, finding_count DESC
    LIMIT 10
  `).all();

  const result = {
    totals,
    severity_breakdown: severityCounts.results,
    recent_findings: recentFindings.results,
    top_vulnerable_assets: topAssets.results,
    generated_at: new Date().toISOString(),
  };

  // Cache for 5 minutes
  await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 300 });

  return c.json(result);
});

// Get findings trend over time
dashboard.get('/trends/findings', async (c) => {
  const { days = '30' } = c.req.query();

  const result = await c.env.DB.prepare(`
    SELECT
      date(created_at) as date,
      COUNT(*) as new_findings,
      SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
    FROM findings
    WHERE created_at >= date('now', '-' || ? || ' days')
    GROUP BY date(created_at)
    ORDER BY date ASC
  `).bind(parseInt(days)).all();

  return c.json(result.results);
});

// Get remediation trend
dashboard.get('/trends/remediation', async (c) => {
  const { days = '30' } = c.req.query();

  const result = await c.env.DB.prepare(`
    SELECT
      date(fixed_at) as date,
      COUNT(*) as fixed_count
    FROM findings
    WHERE fixed_at IS NOT NULL
      AND fixed_at >= date('now', '-' || ? || ' days')
    GROUP BY date(fixed_at)
    ORDER BY date ASC
  `).bind(parseInt(days)).all();

  return c.json(result.results);
});

// Get MTTR (Mean Time to Remediate)
dashboard.get('/metrics/mttr', async (c) => {
  const result = await c.env.DB.prepare(`
    SELECT
      severity,
      AVG(julianday(fixed_at) - julianday(first_seen)) as avg_days_to_fix,
      COUNT(*) as sample_size
    FROM findings
    WHERE fixed_at IS NOT NULL
    GROUP BY severity
  `).all();

  return c.json(result.results);
});

// Get risk score summary
dashboard.get('/metrics/risk-score', async (c) => {
  // Calculate overall risk score based on open findings
  const weights = { critical: 10, high: 5, medium: 2, low: 1, info: 0 };

  const counts = await c.env.DB.prepare(`
    SELECT
      SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) as info,
      COUNT(*) as total
    FROM findings
    WHERE state = 'open'
  `).first<{
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  }>();

  if (!counts || counts.total === 0) {
    return c.json({ risk_score: 0, grade: 'A', counts: {} });
  }

  const rawScore =
    (counts.critical * weights.critical) +
    (counts.high * weights.high) +
    (counts.medium * weights.medium) +
    (counts.low * weights.low);

  // Normalize to 0-100 scale (max assumes 100 critical findings)
  const normalizedScore = Math.min(100, (rawScore / 1000) * 100);

  // Assign grade
  let grade = 'A';
  if (normalizedScore >= 80) grade = 'F';
  else if (normalizedScore >= 60) grade = 'D';
  else if (normalizedScore >= 40) grade = 'C';
  else if (normalizedScore >= 20) grade = 'B';

  return c.json({
    risk_score: Math.round(normalizedScore),
    grade,
    counts,
  });
});

// Get vendor breakdown
dashboard.get('/breakdown/vendors', async (c) => {
  const result = await c.env.DB.prepare(`
    SELECT
      vendor,
      COUNT(*) as total_findings,
      SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as open_findings,
      SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high
    FROM findings
    GROUP BY vendor
    ORDER BY open_findings DESC
  `).all();

  return c.json(result.results);
});

// Get asset type breakdown
dashboard.get('/breakdown/asset-types', async (c) => {
  const result = await c.env.DB.prepare(`
    SELECT
      a.asset_type,
      COUNT(DISTINCT a.id) as asset_count,
      COUNT(f.id) as finding_count
    FROM assets a
    LEFT JOIN findings f ON a.id = f.asset_id AND f.state = 'open'
    GROUP BY a.asset_type
    ORDER BY finding_count DESC
  `).all();

  return c.json(result.results);
});
