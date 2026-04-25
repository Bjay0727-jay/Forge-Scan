import { Hono } from 'hono';
import type { Env } from '../index';
import { databaseError } from '../lib/errors';
import { parsePositiveInt } from '../lib/validate';
import { orgWhereClause, getOrgFilter } from '../middleware/org-scope';

export const dashboard = new Hono<{ Bindings: Env }>();

/**
 * Run a query that returns a single row, falling back to a default value
 * (and logging the cause) if D1 errors out — typically a missing column
 * after schema drift. Lets the dashboard render with partial data instead
 * of 500ing the entire response.
 */
async function safeFirst<T>(
  label: string,
  exec: () => Promise<T | null | undefined>,
  fallback: T,
): Promise<T> {
  try {
    const row = await exec();
    return (row ?? fallback) as T;
  } catch (err) {
    console.error(`[dashboard.safeFirst] ${label} failed:`, err);
    return fallback;
  }
}

async function safeAll<T>(
  label: string,
  exec: () => Promise<{ results?: T[] } | null | undefined>,
): Promise<T[]> {
  try {
    const out = await exec();
    return (out?.results ?? []) as T[];
  } catch (err) {
    console.error(`[dashboard.safeAll] ${label} failed:`, err);
    return [];
  }
}

// Get dashboard overview
//
// Each independent sub-query runs through `safeFirst` / `safeAll` so a single
// schema-drift error (e.g. a missing org_id column on a table that wasn't
// migrated) does not 500 the whole dashboard. Partial data is preferable to
// no dashboard. The full SQL error is logged to the worker console for
// triage without leaking it to the client.
dashboard.get('/overview', async (c) => {
  try {
    const { orgId } = getOrgFilter(c);
    const orgFilter = orgId ? 'AND org_id = ?' : '';
    const orgFilterF = orgId ? 'AND f.org_id = ?' : '';
    const orgFilterA = orgId ? 'AND a.org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

    // Try to get from cache first
    const cacheKey = `dashboard:overview:${orgId || 'all'}`;
    const cached = await c.env.CACHE.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }

    type Totals = {
      total_assets: number;
      open_findings: number;
      fixed_findings: number;
      completed_scans: number;
    };
    const ZERO_TOTALS: Totals = {
      total_assets: 0,
      open_findings: 0,
      fixed_findings: 0,
      completed_scans: 0,
    };

    const totals = await safeFirst<Totals>(
      'totals',
      () =>
        c.env.DB.prepare(
          `
      SELECT
        (SELECT COUNT(*) FROM assets WHERE 1=1 ${orgFilter}) as total_assets,
        (SELECT COUNT(*) FROM findings WHERE state = 'open' ${orgFilter}) as open_findings,
        (SELECT COUNT(*) FROM findings WHERE state = 'fixed' ${orgFilter}) as fixed_findings,
        (SELECT COUNT(*) FROM scans WHERE status = 'completed' ${orgFilter}) as completed_scans
    `,
        )
          .bind(...orgParams, ...orgParams, ...orgParams, ...orgParams)
          .first<Totals>(),
      ZERO_TOTALS,
    );

    const severityResults = await safeAll<{ severity: string; count: number }>(
      'severity_breakdown',
      () =>
        c.env.DB.prepare(
          `
      SELECT severity, COUNT(*) as count
      FROM findings
      WHERE state = 'open' ${orgFilter}
      GROUP BY severity
    `,
        )
          .bind(...orgParams)
          .all(),
    );

    const recentFindings = await safeAll(
      'recent_findings',
      () =>
        c.env.DB.prepare(
          `
      SELECT f.id, f.title, f.severity, f.vendor, f.created_at, a.hostname
      FROM findings f
      LEFT JOIN assets a ON f.asset_id = a.id
      WHERE f.state = 'open' ${orgFilterF}
      ORDER BY f.created_at DESC
      LIMIT 10
    `,
        )
          .bind(...orgParams)
          .all(),
    );

    const topAssets = await safeAll(
      'top_vulnerable_assets',
      () =>
        c.env.DB.prepare(
          `
      SELECT
        a.id,
        a.hostname,
        a.ip_addresses,
        COUNT(f.id) as finding_count,
        SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
        SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high_count
      FROM assets a
      LEFT JOIN findings f ON a.id = f.asset_id AND f.state = 'open'
      WHERE 1=1 ${orgFilterA}
      GROUP BY a.id
      HAVING finding_count > 0
      ORDER BY critical_count DESC, high_count DESC, finding_count DESC
      LIMIT 10
    `,
        )
          .bind(...orgParams)
          .all(),
    );

    const result = {
      totals,
      severity_breakdown: severityResults,
      recent_findings: recentFindings,
      top_vulnerable_assets: topAssets,
      generated_at: new Date().toISOString(),
    };

    // Cache for 5 minutes
    await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 300 });

    return c.json(result);
  } catch (err) {
    // Anything that escaped the safe-* helpers (cache layer, etc.) lands here.
    console.error('[dashboard./overview] unexpected:', err);
    throw databaseError(err);
  }
});

// Get findings trend over time
dashboard.get('/trends/findings', async (c) => {
  const { days = '30' } = c.req.query();
  const daysNum = parsePositiveInt(days, 30);

  try {
    const { orgId } = getOrgFilter(c);
    const orgFilter = orgId ? 'AND org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

    const result = await c.env.DB.prepare(`
      SELECT
        date(created_at) as date,
        COUNT(*) as new_findings,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
      FROM findings
      WHERE created_at >= date('now', '-' || ? || ' days') ${orgFilter}
      GROUP BY date(created_at)
      ORDER BY date ASC
    `).bind(daysNum, ...orgParams).all();

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
    const { orgId } = getOrgFilter(c);
    const orgFilter = orgId ? 'AND org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

    const result = await c.env.DB.prepare(`
      SELECT
        date(fixed_at) as date,
        COUNT(*) as fixed_count
      FROM findings
      WHERE fixed_at IS NOT NULL
        AND fixed_at >= date('now', '-' || ? || ' days') ${orgFilter}
      GROUP BY date(fixed_at)
      ORDER BY date ASC
    `).bind(daysNum, ...orgParams).all();

    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});

// Get MTTR (Mean Time to Remediate)
dashboard.get('/metrics/mttr', async (c) => {
  try {
    const { orgId } = getOrgFilter(c);
    const orgFilter = orgId ? 'AND org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

    const result = await c.env.DB.prepare(`
      SELECT
        severity,
        AVG(julianday(fixed_at) - julianday(first_seen)) as avg_days_to_fix,
        COUNT(*) as sample_size
      FROM findings
      WHERE fixed_at IS NOT NULL ${orgFilter}
      GROUP BY severity
    `).bind(...orgParams).all();

    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});

// Get dashboard stats (for frontend Dashboard page)
dashboard.get('/stats', async (c) => {
  try {
    const { orgId } = getOrgFilter(c);
    const orgFilter = orgId ? 'AND org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

    // Get total counts
    const totals = await c.env.DB.prepare(`
      SELECT
        (SELECT COUNT(*) FROM assets WHERE 1=1 ${orgFilter}) as total_assets,
        (SELECT COUNT(*) FROM findings WHERE 1=1 ${orgFilter}) as total_findings,
        (SELECT COUNT(*) FROM scans WHERE 1=1 ${orgFilter}) as total_scans
    `).bind(...orgParams, ...orgParams, ...orgParams).first<{ total_assets: number; total_findings: number; total_scans: number }>();

    // Get findings by severity
    const severityResults = await c.env.DB.prepare(`
      SELECT severity, COUNT(*) as count
      FROM findings
      WHERE 1=1 ${orgFilter}
      GROUP BY severity
    `).bind(...orgParams).all();

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
      WHERE 1=1 ${orgFilter}
      GROUP BY state
    `).bind(...orgParams).all();

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
      WHERE 1=1 ${orgFilter}
      ORDER BY created_at DESC
      LIMIT 10
    `).bind(...orgParams).all();

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
      WHERE created_at >= date('now', '-30 days') ${orgFilter}
      GROUP BY date(created_at)
      ORDER BY date ASC
    `).bind(...orgParams).all();

    // Get top vulnerabilities
    const topVulns = await c.env.DB.prepare(`
      SELECT
        cve_id,
        title,
        severity,
        COUNT(DISTINCT asset_id) as affected_assets,
        MAX(cvss_score) as cvss_score
      FROM findings
      WHERE cve_id IS NOT NULL ${orgFilter}
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
    `).bind(...orgParams).all();

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
    const { orgId } = getOrgFilter(c);
    const orgFilter = orgId ? 'AND org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

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
      WHERE state = 'open' ${orgFilter}
    `).bind(...orgParams).first<{
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

// Executive dashboard -- single endpoint for CISO-grade metrics
dashboard.get('/executive', async (c) => {
  const { days = '90' } = c.req.query();
  const daysNum = parsePositiveInt(days, 90);

  try {
    const { orgId } = getOrgFilter(c);
    const orgFilter = orgId ? 'AND org_id = ?' : '';
    const orgFilterRf = orgId ? 'AND rf.org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

    // Try cache first
    const cacheKey = `dashboard:executive:${orgId || 'all'}:${daysNum}`;
    const cached = await c.env.CACHE.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }

    // -- Risk Grade ------------------------------------------------
    type SeverityCounts = {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
      total: number;
    };
    const ZERO_COUNTS: SeverityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0,
    };
    const c_ = await safeFirst<SeverityCounts>(
      'severity_counts',
      () =>
        c.env.DB.prepare(
          `
      SELECT
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
        SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) as info,
        COUNT(*) as total
      FROM findings
      WHERE state = 'open' ${orgFilter}
    `,
        )
          .bind(...orgParams)
          .first<SeverityCounts>(),
      ZERO_COUNTS,
    );
    const rawScore = c_.critical * 10 + c_.high * 5 + c_.medium * 2 + c_.low * 1;
    const riskScore = Math.min(100, Math.round((rawScore / 1000) * 100));

    let grade = 'A';
    if (riskScore >= 80) grade = 'F';
    else if (riskScore >= 60) grade = 'D';
    else if (riskScore >= 40) grade = 'C';
    else if (riskScore >= 20) grade = 'B';

    // -- MTTR by severity ------------------------------------------
    const mttrResults = await safeAll<{
      severity: string;
      avg_days: number;
      min_days: number;
      max_days: number;
      sample_size: number;
    }>('mttr_by_severity', () =>
      c.env.DB.prepare(
        `
      SELECT
        severity,
        ROUND(AVG(julianday(fixed_at) - julianday(first_seen)), 1) as avg_days,
        ROUND(MIN(julianday(fixed_at) - julianday(first_seen)), 1) as min_days,
        ROUND(MAX(julianday(fixed_at) - julianday(first_seen)), 1) as max_days,
        COUNT(*) as sample_size
      FROM findings
      WHERE fixed_at IS NOT NULL
        AND first_seen IS NOT NULL
        AND fixed_at >= date('now', '-' || ? || ' days') ${orgFilter}
      GROUP BY severity
    `,
      )
        .bind(daysNum, ...orgParams)
        .all(),
    );

    const mttr: Record<
      string,
      { avg_days: number; min_days: number; max_days: number; sample_size: number }
    > = {};
    mttrResults.forEach((r) => {
      mttr[r.severity] = {
        avg_days: r.avg_days || 0,
        min_days: r.min_days || 0,
        max_days: r.max_days || 0,
        sample_size: r.sample_size,
      };
    });

    // Overall MTTR across all severities
    const overallMttr = await safeFirst<{ avg_days: number; sample_size: number }>(
      'overall_mttr',
      () =>
        c.env.DB.prepare(
          `
      SELECT
        ROUND(AVG(julianday(fixed_at) - julianday(first_seen)), 1) as avg_days,
        COUNT(*) as sample_size
      FROM findings
      WHERE fixed_at IS NOT NULL
        AND first_seen IS NOT NULL
        AND fixed_at >= date('now', '-' || ? || ' days') ${orgFilter}
    `,
        )
          .bind(daysNum, ...orgParams)
          .first<{ avg_days: number; sample_size: number }>(),
      { avg_days: 0, sample_size: 0 },
    );

    // -- SLA Compliance --------------------------------------------
    // Standard SLA targets: Critical 7d, High 30d, Medium 90d, Low 180d
    const slaTargets = { critical: 7, high: 30, medium: 90, low: 180 };

    const slaResults = await safeAll<{
      severity: string;
      total_fixed: number;
      within_sla: number;
    }>('sla_by_severity', () =>
      c.env.DB.prepare(
        `
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
        AND severity IN ('critical', 'high', 'medium', 'low') ${orgFilter}
      GROUP BY severity
    `,
      )
        .bind(...orgParams)
        .all(),
    );

    let totalFixed = 0;
    let totalWithinSla = 0;
    const slaBySeverity: Record<string, { total: number; within_sla: number; compliance_pct: number; target_days: number }> = {};
    slaResults.forEach((r) => {
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

    // -- Overdue findings (past SLA) -------------------------------
    const overdueResult = await safeFirst<{
      overdue_count: number;
      overdue_critical: number;
      overdue_high: number;
    }>(
      'overdue',
      () =>
        c.env.DB.prepare(
          `
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
        ) ${orgFilter}
    `,
        )
          .bind(...orgParams)
          .first<{ overdue_count: number; overdue_critical: number; overdue_high: number }>(),
      { overdue_count: 0, overdue_critical: 0, overdue_high: 0 },
    );

    // -- Risk Posture Trend (weekly buckets) -----------------------
    const trendResults = await safeAll<{
      week_start: string;
      risk_score: number;
      new_findings: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    }>('posture_trend', () =>
      c.env.DB.prepare(
        `
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
      WHERE created_at >= date('now', '-' || ? || ' days') ${orgFilter}
      GROUP BY week_start
      ORDER BY week_start ASC
    `,
      )
        .bind(daysNum, ...orgParams)
        .all(),
    );

    // Remediation trend (weekly)
    const remediationTrend = await safeAll<{ week_start: string; fixed_count: number }>(
      'remediation_trend',
      () =>
        c.env.DB.prepare(
          `
      SELECT
        date(fixed_at, 'weekday 0', '-6 days') as week_start,
        COUNT(*) as fixed_count
      FROM findings
      WHERE fixed_at IS NOT NULL
        AND fixed_at >= date('now', '-' || ? || ' days') ${orgFilter}
      GROUP BY week_start
      ORDER BY week_start ASC
    `,
        )
          .bind(daysNum, ...orgParams)
          .all(),
    );

    // Merge new findings and remediation into a single trend
    const trendMap = new Map<string, { week: string; new_findings: number; fixed: number; risk_score: number; critical: number; high: number; medium: number; low: number }>();
    trendResults.forEach((r) => {
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
    remediationTrend.forEach((r) => {
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

    // -- RedOps Coverage (if tables exist) -------------------------
    let redopsValidated = 0;
    let redopsExploitable = 0;
    try {
      const redopsStats = await c.env.DB.prepare(`
        SELECT
          COUNT(DISTINCT rf.cve_id) as validated_cves,
          SUM(CASE WHEN rf.exploitable = 1 THEN 1 ELSE 0 END) as exploitable
        FROM redops_findings rf
        WHERE rf.cve_id IS NOT NULL ${orgFilterRf}
      `).bind(...orgParams).first<{ validated_cves: number; exploitable: number }>();
      redopsValidated = redopsStats?.validated_cves || 0;
      redopsExploitable = redopsStats?.exploitable || 0;
    } catch { /* RedOps tables may not exist yet */ }

    // -- Assemble response -----------------------------------------
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
    console.error('[dashboard./executive] unexpected:', err);
    throw databaseError(err);
  }
});

// Get vendor breakdown
dashboard.get('/breakdown/vendors', async (c) => {
  try {
    const { orgId } = getOrgFilter(c);
    const orgFilter = orgId ? 'AND org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

    const result = await c.env.DB.prepare(`
      SELECT
        vendor,
        COUNT(*) as total_findings,
        SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as open_findings,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high
      FROM findings
      WHERE 1=1 ${orgFilter}
      GROUP BY vendor
      ORDER BY open_findings DESC
    `).bind(...orgParams).all();

    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});

// Get asset type breakdown
dashboard.get('/breakdown/asset-types', async (c) => {
  try {
    const { orgId } = getOrgFilter(c);
    const orgFilterA = orgId ? 'AND a.org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

    const result = await c.env.DB.prepare(`
      SELECT
        a.asset_type,
        COUNT(DISTINCT a.id) as asset_count,
        COUNT(f.id) as finding_count
      FROM assets a
      LEFT JOIN findings f ON a.id = f.asset_id AND f.state = 'open'
      WHERE 1=1 ${orgFilterA}
      GROUP BY a.asset_type
      ORDER BY finding_count DESC
    `).bind(...orgParams).all();

    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});

// ─── Unified Compliance + Threats Dashboard ─────────────────────────────────
// Single-pane view combining compliance posture (ForgeComply 360) and active
// threats (Forge-Scan) for CISO-grade situational awareness.

dashboard.get('/unified', async (c) => {
  try {
    const { orgId } = getOrgFilter(c);
    const orgFilter = orgId ? 'AND org_id = ?' : '';
    const orgWhere = orgId ? 'WHERE org_id = ?' : '';
    const orgParams = orgId ? [orgId] : [];

    // Try cache first
    const cacheKey = `dashboard:unified:${orgId || 'all'}`;
    const cached = await c.env.CACHE.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }

    // ── Threat Posture ────────────────────────────────────────────────

    const threatCounts = await c.env.DB.prepare(`
      SELECT
        COUNT(*) as total_open,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
        SUM(CASE WHEN severity = 'critical' THEN 10
                 WHEN severity = 'high' THEN 5
                 WHEN severity = 'medium' THEN 2
                 WHEN severity = 'low' THEN 1
                 ELSE 0 END) as risk_score
      FROM findings
      WHERE state = 'open' ${orgFilter}
    `).bind(...orgParams).first<{
      total_open: number; critical: number; high: number; medium: number; low: number; risk_score: number;
    }>();

    const tc = threatCounts || { total_open: 0, critical: 0, high: 0, medium: 0, low: 0, risk_score: 0 };
    const normalizedRisk = Math.min(100, Math.round((tc.risk_score / 1000) * 100));

    // Recent critical/high findings with control mappings
    const recentThreats = await c.env.DB.prepare(`
      SELECT f.id, f.title, f.severity, f.vendor, f.cve_id, f.cvss_score,
             f.control_mappings, f.created_at, a.hostname, a.ip_addresses
      FROM findings f
      LEFT JOIN assets a ON f.asset_id = a.id
      WHERE f.state = 'open' AND f.severity IN ('critical', 'high') ${orgFilter ? 'AND f.org_id = ?' : ''}
      ORDER BY f.created_at DESC
      LIMIT 10
    `).bind(...orgParams).all();

    // ── Compliance Posture ────────────────────────────────────────────

    const frameworks = await c.env.DB.prepare(
      'SELECT id, name, version FROM compliance_frameworks ORDER BY name'
    ).all<{ id: string; name: string; version: string }>();

    const compliancePosture: Array<{
      framework_id: string; framework_name: string; version: string;
      total_controls: number; compliant: number; non_compliant: number;
      partial: number; not_assessed: number; compliance_pct: number;
    }> = [];

    for (const fw of frameworks.results || []) {
      const stats = await c.env.DB.prepare(`
        SELECT
          COUNT(*) as total_controls,
          SUM(CASE WHEN cm.status = 'compliant' THEN 1 ELSE 0 END) as compliant,
          SUM(CASE WHEN cm.status = 'non_compliant' THEN 1 ELSE 0 END) as non_compliant,
          SUM(CASE WHEN cm.status = 'partial' THEN 1 ELSE 0 END) as partial,
          SUM(CASE WHEN cm.status IS NULL OR cm.status = 'not_assessed' THEN 1 ELSE 0 END) as not_assessed
        FROM compliance_controls cc
        LEFT JOIN compliance_mappings cm ON cc.id = cm.control_id AND cm.framework_id = ?
          ${orgId ? 'AND cm.org_id = ?' : ''}
        WHERE cc.framework_id = ?
      `).bind(fw.id, ...(orgId ? [orgId] : []), fw.id).first<{
        total_controls: number; compliant: number; non_compliant: number; partial: number; not_assessed: number;
      }>();

      const s = stats || { total_controls: 0, compliant: 0, non_compliant: 0, partial: 0, not_assessed: 0 };
      const assessed = s.total_controls - s.not_assessed;
      const compliancePct = assessed > 0 ? Math.round((s.compliant / assessed) * 100) : 0;

      compliancePosture.push({
        framework_id: fw.id,
        framework_name: fw.name,
        version: fw.version,
        total_controls: s.total_controls,
        compliant: s.compliant,
        non_compliant: s.non_compliant,
        partial: s.partial,
        not_assessed: s.not_assessed,
        compliance_pct: compliancePct,
      });
    }

    // ── POA&M Summary ────────────────────────────────────────────────

    const poamStats = await c.env.DB.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count,
        SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN status = 'delayed' THEN 1 ELSE 0 END) as delayed,
        SUM(CASE WHEN status NOT IN ('completed') AND scheduled_completion < date('now') THEN 1 ELSE 0 END) as overdue
      FROM poam_items
      ${orgWhere}
    `).bind(...orgParams).first<{
      total: number; open_count: number; in_progress: number; completed: number; delayed: number; overdue: number;
    }>();

    const ps = poamStats || { total: 0, open_count: 0, in_progress: 0, completed: 0, delayed: 0, overdue: 0 };

    // ── Evidence Vault Summary ───────────────────────────────────────

    const evidenceStats = await c.env.DB.prepare(`
      SELECT
        COUNT(*) as total_evidence,
        SUM(CASE WHEN expires_at IS NOT NULL AND expires_at < datetime('now') THEN 1 ELSE 0 END) as expired
      FROM evidence_files
      ${orgWhere}
    `).bind(...orgParams).first<{ total_evidence: number; expired: number }>();

    // ── Control-to-Threat Correlation ────────────────────────────────
    // Show which compliance controls are most impacted by open findings

    let controlCorrelation: any = { results: [] };
    try {
      controlCorrelation = await c.env.DB.prepare(`
        SELECT
          json_extract(value, '$.control_id') as control_id,
          json_extract(value, '$.control_name') as control_name,
          json_extract(value, '$.framework') as framework,
          COUNT(DISTINCT f.id) as finding_count,
          SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical_count
        FROM findings f, json_each(f.control_mappings)
        WHERE f.state = 'open'
          AND f.control_mappings IS NOT NULL
          AND f.control_mappings != '[]'
          ${orgFilter ? 'AND f.org_id = ?' : ''}
        GROUP BY control_id, control_name, framework
        ORDER BY finding_count DESC
        LIMIT 10
      `).bind(...orgParams).all();
    } catch {
      // json_each may not work if control_mappings column is missing on older data
    }

    // ── Recent Compliance Events ─────────────────────────────────────

    const recentEvents = await c.env.DB.prepare(`
      SELECT id, event_type, source, created_at
      FROM forge_events
      WHERE (event_type LIKE 'forge.compliance.%' OR event_type LIKE 'forge.scan.%' OR event_type LIKE 'forge.vulnerability.%')
        ${orgFilter}
      ORDER BY created_at DESC
      LIMIT 10
    `).bind(...orgParams).all();

    // ── Assemble Response ────────────────────────────────────────────

    let riskGrade = 'A';
    if (normalizedRisk >= 80) riskGrade = 'F';
    else if (normalizedRisk >= 60) riskGrade = 'D';
    else if (normalizedRisk >= 40) riskGrade = 'C';
    else if (normalizedRisk >= 20) riskGrade = 'B';

    const unifiedResult = {
      threat_posture: {
        risk_score: normalizedRisk,
        risk_grade: riskGrade,
        open_findings: tc.total_open,
        severity_counts: { critical: tc.critical, high: tc.high, medium: tc.medium, low: tc.low },
        recent_threats: recentThreats.results,
      },
      compliance_posture: {
        frameworks: compliancePosture,
        overall_compliance_pct: compliancePosture.length > 0
          ? Math.round(compliancePosture.reduce((sum, f) => sum + f.compliance_pct, 0) / compliancePosture.length)
          : 0,
      },
      poam_summary: {
        total: ps.total,
        open: ps.open_count,
        in_progress: ps.in_progress,
        completed: ps.completed,
        delayed: ps.delayed,
        overdue: ps.overdue,
      },
      evidence_summary: {
        total: evidenceStats?.total_evidence || 0,
        expired: evidenceStats?.expired || 0,
      },
      control_threat_correlation: controlCorrelation.results || [],
      recent_events: recentEvents.results,
      generated_at: new Date().toISOString(),
    };

    // Cache for 5 minutes
    await c.env.CACHE.put(cacheKey, JSON.stringify(unifiedResult), { expirationTtl: 300 });

    return c.json(unifiedResult);
  } catch (err) {
    throw databaseError(err);
  }
});
