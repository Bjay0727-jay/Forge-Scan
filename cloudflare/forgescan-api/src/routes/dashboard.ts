import { Hono } from 'hono';
import type { Env } from '../index';
import { databaseError } from '../lib/errors';
import { parsePositiveInt } from '../lib/validate';

export const dashboard = new Hono<{ Bindings: Env }>();

// Get dashboard overview
dashboard.get('/overview', async (c) => {
  try {
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
  } catch (err) {
    throw databaseError(err);
  }
});

// Get findings trend over time
dashboard.get('/trends/findings', async (c) => {
  const { days = '30' } = c.req.query();
  const daysNum = parsePositiveInt(days, 30);

  try {
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
    `).bind(daysNum).all();

    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});

// Get remediation trend
dashboard.get('/trends/remediation', async (c) => {
  const { days = '30' } = c.req.query();
  const daysNum = parsePositiveInt(days, 30);

  try {
    const result = await c.env.DB.prepare(`
      SELECT
        date(fixed_at) as date,
        COUNT(*) as fixed_count
      FROM findings
      WHERE fixed_at IS NOT NULL
        AND fixed_at >= date('now', '-' || ? || ' days')
      GROUP BY date(fixed_at)
      ORDER BY date ASC
    `).bind(daysNum).all();

    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});

// Get MTTR (Mean Time to Remediate)
dashboard.get('/metrics/mttr', async (c) => {
  try {
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
  } catch (err) {
    throw databaseError(err);
  }
});

// Get dashboard stats (for frontend Dashboard page)
dashboard.get('/stats', async (c) => {
  try {
    // Get total counts
    const totals = await c.env.DB.prepare(`
      SELECT
        (SELECT COUNT(*) FROM assets) as total_assets,
        (SELECT COUNT(*) FROM findings) as total_findings,
        (SELECT COUNT(*) FROM scans) as total_scans
    `).first<{ total_assets: number; total_findings: number; total_scans: number }>();

    // Get findings by severity
    const severityResults = await c.env.DB.prepare(`
      SELECT severity, COUNT(*) as count
      FROM findings
      GROUP BY severity
    `).all();

    const findings_by_severity: Record<string, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0
    };
    (severityResults.results as { severity: string; count: number }[])?.forEach((row) => {
      findings_by_severity[row.severity] = row.count;
    });

    // Get findings by state
    const stateResults = await c.env.DB.prepare(`
      SELECT state, COUNT(*) as count
      FROM findings
      GROUP BY state
    `).all();

    const findings_by_state: Record<string, number> = {
      open: 0, acknowledged: 0, resolved: 0, false_positive: 0
    };
    (stateResults.results as { state: string; count: number }[])?.forEach((row) => {
      findings_by_state[row.state] = row.count;
    });

    // Get recent findings
    const recentFindings = await c.env.DB.prepare(`
      SELECT id, asset_id, scan_id, title, description, severity, state,
             cve_id, cvss_score, affected_component, remediation,
             first_seen, last_seen, created_at, updated_at
      FROM findings
      ORDER BY created_at DESC
      LIMIT 10
    `).all();

    // Get risk trend (last 30 days)
    const riskTrend = await c.env.DB.prepare(`
      SELECT
        date(created_at) as date,
        SUM(CASE WHEN severity = 'critical' THEN 10
                 WHEN severity = 'high' THEN 5
                 WHEN severity = 'medium' THEN 2
                 WHEN severity = 'low' THEN 1
                 ELSE 0 END) as risk_score,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
      FROM findings
      WHERE created_at >= date('now', '-30 days')
      GROUP BY date(created_at)
      ORDER BY date ASC
    `).all();

    // Get top vulnerabilities
    const topVulns = await c.env.DB.prepare(`
      SELECT
        cve_id,
        title,
        severity,
        COUNT(DISTINCT asset_id) as affected_assets,
        MAX(cvss_score) as cvss_score
      FROM findings
      WHERE cve_id IS NOT NULL
      GROUP BY cve_id
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          ELSE 5
        END,
        affected_assets DESC
      LIMIT 10
    `).all();

    return c.json({
      total_assets: totals?.total_assets || 0,
      total_findings: totals?.total_findings || 0,
      total_scans: totals?.total_scans || 0,
      findings_by_severity,
      findings_by_state,
      recent_findings: recentFindings.results || [],
      risk_trend: riskTrend.results || [],
      top_vulnerabilities: topVulns.results || [],
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    return c.json({
      total_assets: 0,
      total_findings: 0,
      total_scans: 0,
      findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      findings_by_state: { open: 0, acknowledged: 0, resolved: 0, false_positive: 0 },
      recent_findings: [],
      risk_trend: [],
      top_vulnerabilities: [],
    });
  }
});

// Get risk score summary
dashboard.get('/metrics/risk-score', async (c) => {
  try {
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
  } catch (err) {
    throw databaseError(err);
  }
});

// Executive dashboard — single endpoint for CISO-grade metrics
dashboard.get('/executive', async (c) => {
  const { days = '90' } = c.req.query();
  const daysNum = parsePositiveInt(days, 90);

  try {
    // Try cache first
    const cacheKey = `dashboard:executive:${daysNum}`;
    const cached = await c.env.CACHE.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }

    // ── Risk Grade ────────────────────────────────────────────
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
    `).first<{ critical: number; high: number; medium: number; low: number; info: number; total: number }>();

    const c_ = counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    const rawScore = c_.critical * 10 + c_.high * 5 + c_.medium * 2 + c_.low * 1;
    const riskScore = Math.min(100, Math.round((rawScore / 1000) * 100));

    let grade = 'A';
    if (riskScore >= 80) grade = 'F';
    else if (riskScore >= 60) grade = 'D';
    else if (riskScore >= 40) grade = 'C';
    else if (riskScore >= 20) grade = 'B';

    // ── MTTR by severity ──────────────────────────────────────
    const mttrResults = await c.env.DB.prepare(`
      SELECT
        severity,
        ROUND(AVG(julianday(fixed_at) - julianday(first_seen)), 1) as avg_days,
        ROUND(MIN(julianday(fixed_at) - julianday(first_seen)), 1) as min_days,
        ROUND(MAX(julianday(fixed_at) - julianday(first_seen)), 1) as max_days,
        COUNT(*) as sample_size
      FROM findings
      WHERE fixed_at IS NOT NULL
        AND first_seen IS NOT NULL
        AND fixed_at >= date('now', '-' || ? || ' days')
      GROUP BY severity
    `).bind(daysNum).all();

    const mttr: Record<string, { avg_days: number; min_days: number; max_days: number; sample_size: number }> = {};
    (mttrResults.results as { severity: string; avg_days: number; min_days: number; max_days: number; sample_size: number }[])?.forEach((r) => {
      mttr[r.severity] = { avg_days: r.avg_days || 0, min_days: r.min_days || 0, max_days: r.max_days || 0, sample_size: r.sample_size };
    });

    // Overall MTTR across all severities
    const overallMttr = await c.env.DB.prepare(`
      SELECT
        ROUND(AVG(julianday(fixed_at) - julianday(first_seen)), 1) as avg_days,
        COUNT(*) as sample_size
      FROM findings
      WHERE fixed_at IS NOT NULL
        AND first_seen IS NOT NULL
        AND fixed_at >= date('now', '-' || ? || ' days')
    `).bind(daysNum).first<{ avg_days: number; sample_size: number }>();

    // ── SLA Compliance ────────────────────────────────────────
    // Standard SLA targets: Critical 7d, High 30d, Medium 90d, Low 180d
    const slaTargets = { critical: 7, high: 30, medium: 90, low: 180 };

    const slaResults = await c.env.DB.prepare(`
      SELECT
        severity,
        COUNT(*) as total_fixed,
        SUM(CASE
          WHEN severity = 'critical' AND (julianday(fixed_at) - julianday(first_seen)) <= 7 THEN 1
          WHEN severity = 'high' AND (julianday(fixed_at) - julianday(first_seen)) <= 30 THEN 1
          WHEN severity = 'medium' AND (julianday(fixed_at) - julianday(first_seen)) <= 90 THEN 1
          WHEN severity = 'low' AND (julianday(fixed_at) - julianday(first_seen)) <= 180 THEN 1
          ELSE 0
        END) as within_sla
      FROM findings
      WHERE fixed_at IS NOT NULL
        AND first_seen IS NOT NULL
        AND severity IN ('critical', 'high', 'medium', 'low')
      GROUP BY severity
    `).all();

    let totalFixed = 0;
    let totalWithinSla = 0;
    const slaBySeverity: Record<string, { total: number; within_sla: number; compliance_pct: number; target_days: number }> = {};
    (slaResults.results as { severity: string; total_fixed: number; within_sla: number }[])?.forEach((r) => {
      const pct = r.total_fixed > 0 ? Math.round((r.within_sla / r.total_fixed) * 100) : 100;
      slaBySeverity[r.severity] = {
        total: r.total_fixed,
        within_sla: r.within_sla,
        compliance_pct: pct,
        target_days: slaTargets[r.severity as keyof typeof slaTargets] || 0,
      };
      totalFixed += r.total_fixed;
      totalWithinSla += r.within_sla;
    });

    const overallSlaCompliance = totalFixed > 0 ? Math.round((totalWithinSla / totalFixed) * 100) : 100;

    // ── Overdue findings (past SLA) ───────────────────────────
    const overdueResult = await c.env.DB.prepare(`
      SELECT
        COUNT(*) as overdue_count,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as overdue_critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as overdue_high
      FROM findings
      WHERE state = 'open'
        AND first_seen IS NOT NULL
        AND (
          (severity = 'critical' AND julianday('now') - julianday(first_seen) > 7)
          OR (severity = 'high' AND julianday('now') - julianday(first_seen) > 30)
          OR (severity = 'medium' AND julianday('now') - julianday(first_seen) > 90)
          OR (severity = 'low' AND julianday('now') - julianday(first_seen) > 180)
        )
    `).first<{ overdue_count: number; overdue_critical: number; overdue_high: number }>();

    // ── Risk Posture Trend (weekly buckets) ───────────────────
    const trendResults = await c.env.DB.prepare(`
      SELECT
        date(created_at, 'weekday 0', '-6 days') as week_start,
        SUM(CASE WHEN severity = 'critical' THEN 10
                 WHEN severity = 'high' THEN 5
                 WHEN severity = 'medium' THEN 2
                 WHEN severity = 'low' THEN 1
                 ELSE 0 END) as risk_score,
        COUNT(*) as new_findings,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
      FROM findings
      WHERE created_at >= date('now', '-' || ? || ' days')
      GROUP BY week_start
      ORDER BY week_start ASC
    `).bind(daysNum).all();

    // Remediation trend (weekly)
    const remediationTrend = await c.env.DB.prepare(`
      SELECT
        date(fixed_at, 'weekday 0', '-6 days') as week_start,
        COUNT(*) as fixed_count
      FROM findings
      WHERE fixed_at IS NOT NULL
        AND fixed_at >= date('now', '-' || ? || ' days')
      GROUP BY week_start
      ORDER BY week_start ASC
    `).bind(daysNum).all();

    // Merge new findings and remediation into a single trend
    const trendMap = new Map<string, { week: string; new_findings: number; fixed: number; risk_score: number; critical: number; high: number; medium: number; low: number }>();
    (trendResults.results as { week_start: string; risk_score: number; new_findings: number; critical: number; high: number; medium: number; low: number }[])?.forEach((r) => {
      trendMap.set(r.week_start, {
        week: r.week_start,
        new_findings: r.new_findings,
        fixed: 0,
        risk_score: r.risk_score,
        critical: r.critical,
        high: r.high,
        medium: r.medium,
        low: r.low,
      });
    });
    (remediationTrend.results as { week_start: string; fixed_count: number }[])?.forEach((r) => {
      const existing = trendMap.get(r.week_start);
      if (existing) {
        existing.fixed = r.fixed_count;
      } else {
        trendMap.set(r.week_start, {
          week: r.week_start,
          new_findings: 0,
          fixed: r.fixed_count,
          risk_score: 0,
          critical: 0, high: 0, medium: 0, low: 0,
        });
      }
    });
    const postureTrend = Array.from(trendMap.values()).sort((a, b) => a.week.localeCompare(b.week));

    // ── RedOps Coverage (if tables exist) ─────────────────────
    let redopsValidated = 0;
    let redopsExploitable = 0;
    try {
      const redopsStats = await c.env.DB.prepare(`
        SELECT
          COUNT(DISTINCT rf.cve_id) as validated_cves,
          SUM(CASE WHEN rf.exploitable = 1 THEN 1 ELSE 0 END) as exploitable
        FROM redops_findings rf
        WHERE rf.cve_id IS NOT NULL
      `).first<{ validated_cves: number; exploitable: number }>();
      redopsValidated = redopsStats?.validated_cves || 0;
      redopsExploitable = redopsStats?.exploitable || 0;
    } catch { /* RedOps tables may not exist yet */ }

    // ── Assemble response ─────────────────────────────────────
    const result = {
      risk_grade: {
        grade,
        score: riskScore,
        open_findings: c_.total,
        severity_counts: { critical: c_.critical, high: c_.high, medium: c_.medium, low: c_.low, info: c_.info },
      },
      mttr: {
        overall_avg_days: overallMttr?.avg_days || 0,
        overall_sample_size: overallMttr?.sample_size || 0,
        by_severity: mttr,
      },
      sla_compliance: {
        overall_pct: overallSlaCompliance,
        by_severity: slaBySeverity,
        targets: slaTargets,
        overdue: {
          total: overdueResult?.overdue_count || 0,
          critical: overdueResult?.overdue_critical || 0,
          high: overdueResult?.overdue_high || 0,
        },
      },
      posture_trend: postureTrend,
      redops_coverage: {
        validated_cves: redopsValidated,
        exploitable: redopsExploitable,
      },
      period_days: daysNum,
      generated_at: new Date().toISOString(),
    };

    // Cache for 10 minutes
    await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 600 });

    return c.json(result);
  } catch (err) {
    throw databaseError(err);
  }
});

// Get vendor breakdown
dashboard.get('/breakdown/vendors', async (c) => {
  try {
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
  } catch (err) {
    throw databaseError(err);
  }
});

// Get asset type breakdown
dashboard.get('/breakdown/asset-types', async (c) => {
  try {
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
  } catch (err) {
    throw databaseError(err);
  }
});
