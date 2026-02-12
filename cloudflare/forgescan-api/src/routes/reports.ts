import { Hono } from 'hono';
import type { Env } from '../index';

export const reports = new Hono<{ Bindings: Env }>();

// Types for reports
interface ExecutiveSummary {
  generated_at: string;
  period: {
    start: string;
    end: string;
  };
  totals: {
    assets: number;
    open_findings: number;
    fixed_findings: number;
    new_findings_period: number;
    remediation_rate: number;
  };
  risk_score: {
    current: number;
    grade: string;
  };
  severity_breakdown: Array<{ severity: string; count: number }>;
  top_risks: Array<{
    title: string;
    severity: string;
    affected_assets: number;
    frs_score: number | null;
  }>;
  recommendations: string[];
}

interface ComplianceStatus {
  framework: string;
  status: string;
  controls_passed: number;
  controls_failed: number;
  controls_total: number;
  compliance_percentage: number;
}

interface GenerateReportRequest {
  report_type: 'executive' | 'findings' | 'compliance' | 'assets' | 'custom';
  title?: string;
  filters?: {
    severity?: string[];
    vendors?: string[];
    asset_types?: string[];
    date_from?: string;
    date_to?: string;
  };
  format?: 'json' | 'csv';
  include_sections?: string[];
}

// GET /api/v1/reports/executive - Executive summary report
reports.get('/executive', async (c) => {
  const { days = '30' } = c.req.query();
  const periodDays = parseInt(days);

  // Try cache first
  const cacheKey = `report:executive:${periodDays}`;
  const cached = await c.env.CACHE.get(cacheKey);
  if (cached) {
    return c.json(JSON.parse(cached));
  }

  // Get totals
  const totals = await c.env.DB.prepare(`
    SELECT
      (SELECT COUNT(*) FROM assets) as assets,
      (SELECT COUNT(*) FROM findings WHERE state = 'open') as open_findings,
      (SELECT COUNT(*) FROM findings WHERE state = 'fixed') as fixed_findings,
      (SELECT COUNT(*) FROM findings WHERE created_at >= date('now', '-' || ? || ' days')) as new_findings_period,
      (SELECT COUNT(*) FROM findings WHERE fixed_at >= date('now', '-' || ? || ' days')) as fixed_period
  `).bind(periodDays, periodDays).first<{
    assets: number;
    open_findings: number;
    fixed_findings: number;
    new_findings_period: number;
    fixed_period: number;
  }>();

  // Get severity breakdown
  const severityResult = await c.env.DB.prepare(`
    SELECT severity, COUNT(*) as count
    FROM findings
    WHERE state = 'open'
    GROUP BY severity
    ORDER BY
      CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
      END
  `).all();

  // Calculate risk score
  const weights = { critical: 10, high: 5, medium: 2, low: 1, info: 0 };
  const severityMap: Record<string, number> = {};
  for (const row of severityResult.results as Array<{ severity: string; count: number }>) {
    severityMap[row.severity] = row.count;
  }

  const rawScore =
    ((severityMap['critical'] || 0) * weights.critical) +
    ((severityMap['high'] || 0) * weights.high) +
    ((severityMap['medium'] || 0) * weights.medium) +
    ((severityMap['low'] || 0) * weights.low);

  const normalizedScore = Math.min(100, (rawScore / 1000) * 100);
  let grade = 'A';
  if (normalizedScore >= 80) grade = 'F';
  else if (normalizedScore >= 60) grade = 'D';
  else if (normalizedScore >= 40) grade = 'C';
  else if (normalizedScore >= 20) grade = 'B';

  // Get top risks
  const topRisks = await c.env.DB.prepare(`
    SELECT
      f.title,
      f.severity,
      COUNT(DISTINCT f.asset_id) as affected_assets,
      MAX(f.frs_score) as frs_score
    FROM findings f
    WHERE f.state = 'open' AND f.severity IN ('critical', 'high')
    GROUP BY f.title, f.severity
    ORDER BY
      CASE f.severity WHEN 'critical' THEN 1 ELSE 2 END,
      affected_assets DESC,
      frs_score DESC
    LIMIT 10
  `).all();

  // Generate recommendations based on findings
  const recommendations: string[] = [];
  if ((severityMap['critical'] || 0) > 0) {
    recommendations.push(`Address ${severityMap['critical']} critical severity findings immediately`);
  }
  if ((severityMap['high'] || 0) > 10) {
    recommendations.push(`Prioritize remediation of ${severityMap['high']} high severity findings`);
  }
  if (totals && totals.new_findings_period > totals.fixed_period) {
    recommendations.push('Increase remediation velocity - new findings exceed fixed findings');
  }

  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - periodDays);

  const remediationRate = totals && totals.new_findings_period > 0
    ? Math.round((totals.fixed_period / totals.new_findings_period) * 100)
    : 100;

  const report: ExecutiveSummary = {
    generated_at: new Date().toISOString(),
    period: {
      start: startDate.toISOString().split('T')[0],
      end: endDate.toISOString().split('T')[0],
    },
    totals: {
      assets: totals?.assets || 0,
      open_findings: totals?.open_findings || 0,
      fixed_findings: totals?.fixed_findings || 0,
      new_findings_period: totals?.new_findings_period || 0,
      remediation_rate: remediationRate,
    },
    risk_score: {
      current: Math.round(normalizedScore),
      grade,
    },
    severity_breakdown: severityResult.results as Array<{ severity: string; count: number }>,
    top_risks: topRisks.results as Array<{
      title: string;
      severity: string;
      affected_assets: number;
      frs_score: number | null;
    }>,
    recommendations,
  };

  // Cache for 15 minutes
  await c.env.CACHE.put(cacheKey, JSON.stringify(report), { expirationTtl: 900 });

  return c.json(report);
});

// GET /api/v1/reports/findings - Detailed findings report with filters
reports.get('/findings', async (c) => {
  const {
    severity,
    vendor,
    state = 'open',
    asset_type,
    date_from,
    date_to,
    group_by = 'severity',
    limit = '100',
    offset = '0',
  } = c.req.query();

  let query = `
    SELECT
      f.*,
      a.hostname,
      a.ip_addresses,
      a.asset_type,
      v.cve_id,
      v.cvss_score,
      v.epss_score
    FROM findings f
    LEFT JOIN assets a ON f.asset_id = a.id
    LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (severity) {
    const severities = severity.split(',');
    query += ` AND f.severity IN (${severities.map(() => '?').join(',')})`;
    params.push(...severities);
  }

  if (vendor) {
    const vendors = vendor.split(',');
    query += ` AND f.vendor IN (${vendors.map(() => '?').join(',')})`;
    params.push(...vendors);
  }

  if (state) {
    query += ' AND f.state = ?';
    params.push(state);
  }

  if (asset_type) {
    query += ' AND a.asset_type = ?';
    params.push(asset_type);
  }

  if (date_from) {
    query += ' AND f.created_at >= ?';
    params.push(date_from);
  }

  if (date_to) {
    query += ' AND f.created_at <= ?';
    params.push(date_to);
  }

  query += ` ORDER BY
    CASE f.severity
      WHEN 'critical' THEN 1
      WHEN 'high' THEN 2
      WHEN 'medium' THEN 3
      WHEN 'low' THEN 4
      ELSE 5
    END,
    f.frs_score DESC NULLS LAST,
    f.created_at DESC
    LIMIT ? OFFSET ?
  `;
  params.push(parseInt(limit), parseInt(offset));

  const result = await c.env.DB.prepare(query).bind(...params).all();

  // Get summary stats
  let summaryQuery = `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN f.severity = 'info' THEN 1 ELSE 0 END) as info,
      COUNT(DISTINCT f.asset_id) as affected_assets,
      COUNT(DISTINCT f.vendor) as vendors
    FROM findings f
    LEFT JOIN assets a ON f.asset_id = a.id
    WHERE 1=1
  `;
  const summaryParams: any[] = [];

  if (severity) {
    const severities = severity.split(',');
    summaryQuery += ` AND f.severity IN (${severities.map(() => '?').join(',')})`;
    summaryParams.push(...severities);
  }
  if (state) {
    summaryQuery += ' AND f.state = ?';
    summaryParams.push(state);
  }

  const summary = await c.env.DB.prepare(summaryQuery).bind(...summaryParams).first();

  return c.json({
    generated_at: new Date().toISOString(),
    filters: { severity, vendor, state, asset_type, date_from, date_to },
    summary,
    data: result.results,
    pagination: {
      limit: parseInt(limit),
      offset: parseInt(offset),
    },
  });
});

// GET /api/v1/reports/compliance - Compliance status report
reports.get('/compliance', async (c) => {
  const { framework } = c.req.query();

  // Get compliance mappings from findings metadata
  // This assumes findings have compliance framework tags in metadata
  let query = `
    SELECT
      f.id,
      f.title,
      f.severity,
      f.state,
      f.metadata
    FROM findings f
    WHERE f.metadata IS NOT NULL
  `;

  if (framework) {
    query += ` AND f.metadata LIKE ?`;
  }

  const params = framework ? [`%"${framework}"%`] : [];
  const result = await c.env.DB.prepare(query).bind(...params).all();

  // Parse and aggregate compliance data
  const frameworks: Record<string, { passed: number; failed: number; total: number }> = {};

  for (const finding of result.results as Array<{ metadata: string; state: string }>) {
    try {
      const metadata = JSON.parse(finding.metadata || '{}');
      const complianceFrameworks = metadata.compliance || [];

      for (const fw of complianceFrameworks) {
        if (!frameworks[fw]) {
          frameworks[fw] = { passed: 0, failed: 0, total: 0 };
        }
        frameworks[fw].total++;
        if (finding.state === 'fixed' || finding.state === 'false_positive') {
          frameworks[fw].passed++;
        } else {
          frameworks[fw].failed++;
        }
      }
    } catch {
      // Skip findings with invalid metadata
    }
  }

  const complianceStatuses: ComplianceStatus[] = Object.entries(frameworks).map(([fw, data]) => ({
    framework: fw,
    status: data.failed === 0 ? 'compliant' : data.failed > data.total * 0.2 ? 'non-compliant' : 'partial',
    controls_passed: data.passed,
    controls_failed: data.failed,
    controls_total: data.total,
    compliance_percentage: data.total > 0 ? Math.round((data.passed / data.total) * 100) : 100,
  }));

  // Add common frameworks with defaults if not found
  const defaultFrameworks = ['PCI-DSS', 'HIPAA', 'SOC2', 'NIST', 'CIS'];
  for (const fw of defaultFrameworks) {
    if (!frameworks[fw]) {
      complianceStatuses.push({
        framework: fw,
        status: 'unknown',
        controls_passed: 0,
        controls_failed: 0,
        controls_total: 0,
        compliance_percentage: 0,
      });
    }
  }

  return c.json({
    generated_at: new Date().toISOString(),
    frameworks: complianceStatuses.sort((a, b) => a.framework.localeCompare(b.framework)),
    overall_status: complianceStatuses.every(s => s.status === 'compliant' || s.status === 'unknown')
      ? 'compliant'
      : 'needs-attention',
  });
});

// GET /api/v1/reports/assets - Asset inventory report
reports.get('/assets', async (c) => {
  const {
    asset_type,
    network_zone,
    include_findings = 'true',
    limit = '100',
    offset = '0',
  } = c.req.query();

  let query = `
    SELECT
      a.*,
      COUNT(CASE WHEN f.state = 'open' THEN 1 END) as open_findings,
      SUM(CASE WHEN f.severity = 'critical' AND f.state = 'open' THEN 1 ELSE 0 END) as critical_findings,
      SUM(CASE WHEN f.severity = 'high' AND f.state = 'open' THEN 1 ELSE 0 END) as high_findings,
      MAX(f.frs_score) as max_frs_score
    FROM assets a
    LEFT JOIN findings f ON a.id = f.asset_id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (asset_type) {
    query += ' AND a.asset_type = ?';
    params.push(asset_type);
  }

  if (network_zone) {
    query += ' AND a.network_zone = ?';
    params.push(network_zone);
  }

  query += ` GROUP BY a.id
    ORDER BY critical_findings DESC, high_findings DESC, open_findings DESC
    LIMIT ? OFFSET ?
  `;
  params.push(parseInt(limit), parseInt(offset));

  const result = await c.env.DB.prepare(query).bind(...params).all();

  // Get summary statistics
  const summaryQuery = `
    SELECT
      COUNT(*) as total_assets,
      COUNT(DISTINCT asset_type) as asset_types,
      COUNT(DISTINCT network_zone) as network_zones
    FROM assets
  `;
  const summary = await c.env.DB.prepare(summaryQuery).first();

  // Get breakdown by type
  const typeBreakdown = await c.env.DB.prepare(`
    SELECT asset_type, COUNT(*) as count
    FROM assets
    GROUP BY asset_type
    ORDER BY count DESC
  `).all();

  return c.json({
    generated_at: new Date().toISOString(),
    summary,
    breakdown_by_type: typeBreakdown.results,
    data: result.results,
    pagination: {
      limit: parseInt(limit),
      offset: parseInt(offset),
    },
  });
});

// POST /api/v1/reports/generate - Generate custom report and store in R2
reports.post('/generate', async (c) => {
  const body = await c.req.json<GenerateReportRequest>();
  const reportId = crypto.randomUUID();

  const validTypes = ['executive', 'findings', 'compliance', 'assets', 'custom'];
  if (!validTypes.includes(body.report_type)) {
    return c.json({ error: 'Invalid report type' }, 400);
  }

  // Generate report based on type
  let reportData: any;
  const reportTitle = body.title || `${body.report_type}_report_${new Date().toISOString().split('T')[0]}`;

  try {
    switch (body.report_type) {
      case 'executive': {
        // Fetch executive summary data
        const totals = await c.env.DB.prepare(`
          SELECT
            (SELECT COUNT(*) FROM assets) as assets,
            (SELECT COUNT(*) FROM findings WHERE state = 'open') as open_findings,
            (SELECT COUNT(*) FROM findings WHERE state = 'fixed') as fixed_findings
        `).first();

        const severities = await c.env.DB.prepare(`
          SELECT severity, COUNT(*) as count FROM findings WHERE state = 'open' GROUP BY severity
        `).all();

        reportData = {
          type: 'executive',
          title: reportTitle,
          generated_at: new Date().toISOString(),
          totals,
          severity_breakdown: severities.results,
        };
        break;
      }

      case 'findings': {
        let query = 'SELECT * FROM findings WHERE 1=1';
        const params: any[] = [];

        if (body.filters?.severity?.length) {
          query += ` AND severity IN (${body.filters.severity.map(() => '?').join(',')})`;
          params.push(...body.filters.severity);
        }

        if (body.filters?.vendors?.length) {
          query += ` AND vendor IN (${body.filters.vendors.map(() => '?').join(',')})`;
          params.push(...body.filters.vendors);
        }

        if (body.filters?.date_from) {
          query += ' AND created_at >= ?';
          params.push(body.filters.date_from);
        }

        if (body.filters?.date_to) {
          query += ' AND created_at <= ?';
          params.push(body.filters.date_to);
        }

        query += ' ORDER BY created_at DESC';
        const findings = await c.env.DB.prepare(query).bind(...params).all();

        reportData = {
          type: 'findings',
          title: reportTitle,
          generated_at: new Date().toISOString(),
          filters: body.filters,
          total_findings: findings.results?.length || 0,
          findings: findings.results,
        };
        break;
      }

      case 'assets': {
        let query = 'SELECT * FROM assets WHERE 1=1';
        const params: any[] = [];

        if (body.filters?.asset_types?.length) {
          query += ` AND asset_type IN (${body.filters.asset_types.map(() => '?').join(',')})`;
          params.push(...body.filters.asset_types);
        }

        const assets = await c.env.DB.prepare(query).bind(...params).all();

        reportData = {
          type: 'assets',
          title: reportTitle,
          generated_at: new Date().toISOString(),
          filters: body.filters,
          total_assets: assets.results?.length || 0,
          assets: assets.results,
        };
        break;
      }

      case 'compliance':
      case 'custom':
      default: {
        reportData = {
          type: body.report_type,
          title: reportTitle,
          generated_at: new Date().toISOString(),
          filters: body.filters,
          sections: body.include_sections || [],
        };
      }
    }

    // Store report in R2
    const reportKey = `reports/${reportId}.json`;
    await c.env.STORAGE.put(reportKey, JSON.stringify(reportData, null, 2), {
      customMetadata: {
        report_type: body.report_type,
        title: reportTitle,
        generated_at: new Date().toISOString(),
      },
    });

    // Store report metadata in database for tracking
    await c.env.DB.prepare(`
      INSERT INTO reports (id, title, report_type, filters, storage_key, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'completed', datetime('now'))
    `).bind(
      reportId,
      reportTitle,
      body.report_type,
      JSON.stringify(body.filters || {}),
      reportKey,
    ).run().catch(() => {
      // Reports table might not exist, continue anyway
    });

    return c.json({
      id: reportId,
      title: reportTitle,
      report_type: body.report_type,
      storage_key: reportKey,
      status: 'completed',
      download_url: `/api/v1/reports/${reportId}/download`,
      generated_at: new Date().toISOString(),
    }, 201);

  } catch (error) {
    console.error('Report generation error:', error);
    return c.json({
      error: 'Failed to generate report',
      message: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// GET /api/v1/reports/:id/download - Download generated report from R2
reports.get('/:id/download', async (c) => {
  const id = c.req.param('id');
  const reportKey = `reports/${id}.json`;

  const object = await c.env.STORAGE.get(reportKey);

  if (!object) {
    return c.json({ error: 'Report not found' }, 404);
  }

  const data = await object.text();

  return new Response(data, {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="report-${id}.json"`,
    },
  });
});

// GET /api/v1/reports/list - List generated reports
reports.get('/list/all', async (c) => {
  const { limit = '20', offset = '0' } = c.req.query();

  // Try to list from database first
  try {
    const result = await c.env.DB.prepare(`
      SELECT * FROM reports
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).bind(parseInt(limit), parseInt(offset)).all();

    return c.json({
      data: result.results,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
      },
    });
  } catch {
    // Fallback to listing from R2
    const listed = await c.env.STORAGE.list({ prefix: 'reports/' });

    const reports = listed.objects.map(obj => ({
      key: obj.key,
      size: obj.size,
      uploaded: obj.uploaded,
      customMetadata: obj.customMetadata,
    }));

    return c.json({
      data: reports.slice(parseInt(offset), parseInt(offset) + parseInt(limit)),
      pagination: {
        total: reports.length,
        limit: parseInt(limit),
        offset: parseInt(offset),
      },
    });
  }
});
