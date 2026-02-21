import { Hono } from 'hono';
import type { Env } from '../index';
import { requireRole } from '../middleware/auth';
import { generateExecutivePDF, generateFindingsPDF, generateCompliancePDF, generateAssetsPDF } from '../services/reporting/pdf-generator';
import { generateFindingsCSV, generateAssetsCSV, generateComplianceCSV } from '../services/reporting/csv-generator';
import { getFrameworkCompliance, getGapAnalysis } from '../services/compliance';

interface AuthUser {
  id: string;
  email: string;
  role: string;
  display_name: string;
}

export const reports = new Hono<{ Bindings: Env; Variables: { user: AuthUser } }>();

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

interface GenerateReportRequest {
  report_type: 'executive' | 'findings' | 'compliance' | 'assets';
  title?: string;
  filters?: {
    severity?: string[];
    vendors?: string[];
    asset_types?: string[];
    date_from?: string;
    date_to?: string;
  };
  format?: 'json' | 'csv' | 'pdf';
}

// ---- Helper: build executive summary data ----
async function buildExecutiveData(db: D1Database, cache: KVNamespace, periodDays: number): Promise<ExecutiveSummary> {
  const cacheKey = `report:executive:${periodDays}`;
  const cached = await cache.get(cacheKey);
  if (cached) return JSON.parse(cached);

  const totals = await db.prepare(`
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

  const severityResult = await db.prepare(`
    SELECT severity, COUNT(*) as count FROM findings WHERE state = 'open'
    GROUP BY severity
    ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
  `).all();

  const weights: Record<string, number> = { critical: 10, high: 5, medium: 2, low: 1, info: 0 };
  const severityMap: Record<string, number> = {};
  for (const row of severityResult.results as Array<{ severity: string; count: number }>) {
    severityMap[row.severity] = row.count;
  }

  const rawScore = Object.entries(severityMap).reduce((s, [k, v]) => s + v * (weights[k] || 0), 0);
  const normalizedScore = Math.min(100, (rawScore / 1000) * 100);
  let grade = 'A';
  if (normalizedScore >= 80) grade = 'F';
  else if (normalizedScore >= 60) grade = 'D';
  else if (normalizedScore >= 40) grade = 'C';
  else if (normalizedScore >= 20) grade = 'B';

  const topRisks = await db.prepare(`
    SELECT f.title, f.severity, COUNT(DISTINCT f.asset_id) as affected_assets, MAX(f.frs_score) as frs_score
    FROM findings f WHERE f.state = 'open' AND f.severity IN ('critical', 'high')
    GROUP BY f.title, f.severity
    ORDER BY CASE f.severity WHEN 'critical' THEN 1 ELSE 2 END, affected_assets DESC, frs_score DESC
    LIMIT 10
  `).all();

  const recommendations: string[] = [];
  if ((severityMap['critical'] || 0) > 0) recommendations.push(`Address ${severityMap['critical']} critical severity findings immediately`);
  if ((severityMap['high'] || 0) > 10) recommendations.push(`Prioritize remediation of ${severityMap['high']} high severity findings`);
  if (totals && totals.new_findings_period > totals.fixed_period) recommendations.push('Increase remediation velocity - new findings exceed fixed findings');

  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - periodDays);

  const remediationRate = totals && totals.new_findings_period > 0
    ? Math.round(((totals.fixed_period || 0) / totals.new_findings_period) * 100) : 100;

  const report: ExecutiveSummary = {
    generated_at: new Date().toISOString(),
    period: { start: startDate.toISOString().split('T')[0], end: endDate.toISOString().split('T')[0] },
    totals: {
      assets: totals?.assets || 0,
      open_findings: totals?.open_findings || 0,
      fixed_findings: totals?.fixed_findings || 0,
      new_findings_period: totals?.new_findings_period || 0,
      remediation_rate: remediationRate,
    },
    risk_score: { current: Math.round(normalizedScore), grade },
    severity_breakdown: severityResult.results as Array<{ severity: string; count: number }>,
    top_risks: topRisks.results as Array<{ title: string; severity: string; affected_assets: number; frs_score: number | null }>,
    recommendations,
  };

  await cache.put(cacheKey, JSON.stringify(report), { expirationTtl: 900 });
  return report;
}

// ---- Helper: build findings data ----
async function buildFindingsData(db: D1Database, filters: GenerateReportRequest['filters']) {
  let query = `
    SELECT f.*, a.hostname, a.ip_addresses, a.asset_type, a.os,
           v.cve_id, v.cvss_score, v.epss_score
    FROM findings f
    LEFT JOIN assets a ON f.asset_id = a.id
    LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (filters?.severity?.length) {
    query += ` AND f.severity IN (${filters.severity.map(() => '?').join(',')})`;
    params.push(...filters.severity);
  }
  if (filters?.vendors?.length) {
    query += ` AND f.vendor IN (${filters.vendors.map(() => '?').join(',')})`;
    params.push(...filters.vendors);
  }
  if (filters?.date_from) { query += ' AND f.created_at >= ?'; params.push(filters.date_from); }
  if (filters?.date_to) { query += ' AND f.created_at <= ?'; params.push(filters.date_to); }

  query += ` ORDER BY
    CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
    f.frs_score DESC NULLS LAST, f.created_at DESC LIMIT 5000`;

  const result = await db.prepare(query).bind(...params).all();

  const summaryQuery = `
    SELECT COUNT(*) as total,
      SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN f.severity = 'info' THEN 1 ELSE 0 END) as info,
      COUNT(DISTINCT f.asset_id) as affected_assets
    FROM findings f WHERE f.state = 'open'
  `;
  const summary = await db.prepare(summaryQuery).first<any>();

  return {
    summary: summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, affected_assets: 0 },
    findings: (result.results || []) as any[],
    filters: filters || {},
  };
}

// ---- Helper: build compliance data ----
async function buildComplianceData(db: D1Database) {
  const fwResult = await db.prepare('SELECT * FROM compliance_frameworks ORDER BY name').all();
  const frameworks = [];

  for (const fw of fwResult.results || []) {
    const stats = await getFrameworkCompliance(db, fw.id as string);
    frameworks.push({
      name: fw.name as string,
      version: fw.version as string,
      compliance_percentage: stats.compliance_percentage,
      total_controls: stats.total_controls,
      compliant: stats.compliant,
      non_compliant: stats.non_compliant,
      partial: stats.partial,
      not_assessed: stats.not_assessed,
    });
  }

  // Gather gap details across all frameworks
  const gaps: any[] = [];
  for (const fw of fwResult.results || []) {
    const fwGaps = await getGapAnalysis(db, fw.id as string);
    for (const g of fwGaps) {
      if (g.compliance_status === 'non_compliant' || g.compliance_status === 'partial') {
        gaps.push({
          framework_name: fw.name as string,
          control_id: g.control_id,
          control_name: g.control_name,
          status: g.compliance_status,
          family: g.family,
        });
      }
    }
  }

  return { frameworks, gaps };
}

// ---- Helper: build assets data ----
async function buildAssetsData(db: D1Database, filters: GenerateReportRequest['filters']) {
  let query = `
    SELECT a.*,
      COUNT(CASE WHEN f.state = 'open' THEN 1 END) as open_findings,
      SUM(CASE WHEN f.severity = 'critical' AND f.state = 'open' THEN 1 ELSE 0 END) as critical_findings,
      SUM(CASE WHEN f.severity = 'high' AND f.state = 'open' THEN 1 ELSE 0 END) as high_findings,
      MAX(f.frs_score) as max_frs_score
    FROM assets a LEFT JOIN findings f ON a.id = f.asset_id WHERE 1=1
  `;
  const params: any[] = [];

  if (filters?.asset_types?.length) {
    query += ` AND a.asset_type IN (${filters.asset_types.map(() => '?').join(',')})`;
    params.push(...filters.asset_types);
  }

  query += ' GROUP BY a.id ORDER BY critical_findings DESC, high_findings DESC, open_findings DESC LIMIT 5000';
  const result = await db.prepare(query).bind(...params).all();

  const summary = await db.prepare(`
    SELECT COUNT(*) as total_assets, COUNT(DISTINCT asset_type) as asset_types, COUNT(DISTINCT network_zone) as network_zones FROM assets
  `).first<any>();

  const typeBreakdown = await db.prepare('SELECT asset_type, COUNT(*) as count FROM assets GROUP BY asset_type ORDER BY count DESC').all();

  return {
    summary: summary || { total_assets: 0, asset_types: 0, network_zones: 0 },
    breakdown_by_type: (typeBreakdown.results || []) as any[],
    assets: (result.results || []) as any[],
  };
}

// ---- GET /api/v1/reports/executive ----
reports.get('/executive', async (c) => {
  const { days = '30' } = c.req.query();
  const report = await buildExecutiveData(c.env.DB, c.env.CACHE, parseInt(days));
  return c.json(report);
});

// ---- GET /api/v1/reports/findings ----
reports.get('/findings', async (c) => {
  const { severity, vendor, state = 'open', asset_type, date_from, date_to, limit = '100', offset = '0' } = c.req.query();

  let query = `
    SELECT f.*, a.hostname, a.ip_addresses, a.asset_type, v.cve_id, v.cvss_score, v.epss_score
    FROM findings f LEFT JOIN assets a ON f.asset_id = a.id LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (severity) { const s = severity.split(','); query += ` AND f.severity IN (${s.map(() => '?').join(',')})`; params.push(...s); }
  if (vendor) { const v = vendor.split(','); query += ` AND f.vendor IN (${v.map(() => '?').join(',')})`; params.push(...v); }
  if (state) { query += ' AND f.state = ?'; params.push(state); }
  if (asset_type) { query += ' AND a.asset_type = ?'; params.push(asset_type); }
  if (date_from) { query += ' AND f.created_at >= ?'; params.push(date_from); }
  if (date_to) { query += ' AND f.created_at <= ?'; params.push(date_to); }

  query += ` ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
    f.frs_score DESC NULLS LAST, f.created_at DESC LIMIT ? OFFSET ?`;
  params.push(parseInt(limit), parseInt(offset));

  const result = await c.env.DB.prepare(query).bind(...params).all();

  let summaryQuery = `SELECT COUNT(*) as total,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) as high,
    SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) as medium,
    SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) as low,
    SUM(CASE WHEN f.severity = 'info' THEN 1 ELSE 0 END) as info,
    COUNT(DISTINCT f.asset_id) as affected_assets, COUNT(DISTINCT f.vendor) as vendors
    FROM findings f LEFT JOIN assets a ON f.asset_id = a.id WHERE 1=1`;
  const sp: any[] = [];
  if (severity) { const s = severity.split(','); summaryQuery += ` AND f.severity IN (${s.map(() => '?').join(',')})`; sp.push(...s); }
  if (state) { summaryQuery += ' AND f.state = ?'; sp.push(state); }

  const summary = await c.env.DB.prepare(summaryQuery).bind(...sp).first();

  return c.json({
    generated_at: new Date().toISOString(),
    filters: { severity, vendor, state, asset_type, date_from, date_to },
    summary,
    data: result.results,
    pagination: { limit: parseInt(limit), offset: parseInt(offset) },
  });
});

// ---- GET /api/v1/reports/compliance ----
reports.get('/compliance', async (c) => {
  const data = await buildComplianceData(c.env.DB);
  return c.json({ generated_at: new Date().toISOString(), ...data });
});

// ---- GET /api/v1/reports/assets ----
reports.get('/assets', async (c) => {
  const { asset_type, network_zone, limit = '100', offset = '0' } = c.req.query();

  let query = `
    SELECT a.*, COUNT(CASE WHEN f.state = 'open' THEN 1 END) as open_findings,
      SUM(CASE WHEN f.severity = 'critical' AND f.state = 'open' THEN 1 ELSE 0 END) as critical_findings,
      SUM(CASE WHEN f.severity = 'high' AND f.state = 'open' THEN 1 ELSE 0 END) as high_findings,
      MAX(f.frs_score) as max_frs_score
    FROM assets a LEFT JOIN findings f ON a.id = f.asset_id WHERE 1=1`;
  const params: any[] = [];
  if (asset_type) { query += ' AND a.asset_type = ?'; params.push(asset_type); }
  if (network_zone) { query += ' AND a.network_zone = ?'; params.push(network_zone); }
  query += ` GROUP BY a.id ORDER BY critical_findings DESC, high_findings DESC, open_findings DESC LIMIT ? OFFSET ?`;
  params.push(parseInt(limit), parseInt(offset));

  const result = await c.env.DB.prepare(query).bind(...params).all();
  const summary = await c.env.DB.prepare('SELECT COUNT(*) as total_assets, COUNT(DISTINCT asset_type) as asset_types, COUNT(DISTINCT network_zone) as network_zones FROM assets').first();
  const typeBreakdown = await c.env.DB.prepare('SELECT asset_type, COUNT(*) as count FROM assets GROUP BY asset_type ORDER BY count DESC').all();

  return c.json({
    generated_at: new Date().toISOString(),
    summary,
    breakdown_by_type: typeBreakdown.results,
    data: result.results,
    pagination: { limit: parseInt(limit), offset: parseInt(offset) },
  });
});

// ---- POST /api/v1/reports/generate - Generate report in PDF/CSV/JSON, store in R2 ----
reports.post('/generate', requireRole('platform_admin', 'scan_admin', 'vuln_manager', 'auditor'), async (c) => {
  const body = await c.req.json<GenerateReportRequest>();
  const user = c.get('user');
  const reportId = crypto.randomUUID();
  const format = body.format || 'json';
  const reportTitle = body.title || `${body.report_type}_report_${new Date().toISOString().split('T')[0]}`;

  const validTypes = ['executive', 'findings', 'compliance', 'assets'];
  if (!validTypes.includes(body.report_type)) {
    return c.json({ error: 'Invalid report type. Must be: executive, findings, compliance, or assets' }, 400);
  }
  if (!['json', 'csv', 'pdf'].includes(format)) {
    return c.json({ error: 'Invalid format. Must be: json, csv, or pdf' }, 400);
  }

  try {
    let content: string | Uint8Array;
    let contentType: string;
    let extension: string;

    switch (body.report_type) {
      case 'executive': {
        const data = await buildExecutiveData(c.env.DB, c.env.CACHE, 30);
        if (format === 'pdf') {
          content = await generateExecutivePDF(data);
          contentType = 'application/pdf';
          extension = 'pdf';
        } else {
          // CSV not meaningful for executive; fallback to JSON
          content = JSON.stringify({ title: reportTitle, ...data }, null, 2);
          contentType = 'application/json';
          extension = 'json';
        }
        break;
      }

      case 'findings': {
        const data = await buildFindingsData(c.env.DB, body.filters);
        if (format === 'pdf') {
          // Flatten array filters to comma-separated strings for PDF generator
          const pdfFilters: Record<string, string | undefined> = {};
          if (data.filters) {
            for (const [key, value] of Object.entries(data.filters)) {
              pdfFilters[key] = Array.isArray(value) ? value.join(', ') : value;
            }
          }
          content = await generateFindingsPDF({ ...data, filters: pdfFilters });
          contentType = 'application/pdf';
          extension = 'pdf';
        } else if (format === 'csv') {
          content = generateFindingsCSV(data.findings);
          contentType = 'text/csv; charset=utf-8';
          extension = 'csv';
        } else {
          content = JSON.stringify({ title: reportTitle, generated_at: new Date().toISOString(), ...data }, null, 2);
          contentType = 'application/json';
          extension = 'json';
        }
        break;
      }

      case 'compliance': {
        const data = await buildComplianceData(c.env.DB);
        if (format === 'pdf') {
          content = await generateCompliancePDF(data);
          contentType = 'application/pdf';
          extension = 'pdf';
        } else if (format === 'csv') {
          // Flatten controls from all frameworks with gap data
          const allControls: any[] = [];
          const fwResult = await c.env.DB.prepare('SELECT * FROM compliance_frameworks ORDER BY name').all();
          for (const fw of fwResult.results || []) {
            const ctrlResult = await c.env.DB.prepare(`
              SELECT cc.*, COALESCE(cm.status, 'not_assessed') as compliance_status, cm.evidence, cm.assessed_by, cm.assessed_at
              FROM compliance_controls cc
              LEFT JOIN compliance_mappings cm ON cc.framework_id = cm.framework_id AND cc.control_id = cm.control_id
              WHERE cc.framework_id = ?
              ORDER BY cc.family, cc.control_id
            `).bind(fw.id).all();
            for (const ctrl of ctrlResult.results || []) {
              allControls.push({ framework_name: fw.name, ...ctrl });
            }
          }
          content = generateComplianceCSV(allControls);
          contentType = 'text/csv; charset=utf-8';
          extension = 'csv';
        } else {
          content = JSON.stringify({ title: reportTitle, generated_at: new Date().toISOString(), ...data }, null, 2);
          contentType = 'application/json';
          extension = 'json';
        }
        break;
      }

      case 'assets': {
        const data = await buildAssetsData(c.env.DB, body.filters);
        if (format === 'pdf') {
          content = await generateAssetsPDF(data);
          contentType = 'application/pdf';
          extension = 'pdf';
        } else if (format === 'csv') {
          content = generateAssetsCSV(data.assets);
          contentType = 'text/csv; charset=utf-8';
          extension = 'csv';
        } else {
          content = JSON.stringify({ title: reportTitle, generated_at: new Date().toISOString(), ...data }, null, 2);
          contentType = 'application/json';
          extension = 'json';
        }
        break;
      }

      default:
        return c.json({ error: 'Invalid report type' }, 400);
    }

    // Store in R2
    const storageKey = `reports/${reportId}.${extension}`;
    const bodyToStore = typeof content === 'string' ? content : content;
    const fileSize = typeof content === 'string' ? new TextEncoder().encode(content).byteLength : content.byteLength;

    await c.env.STORAGE.put(storageKey, bodyToStore, {
      customMetadata: {
        report_type: body.report_type,
        format: extension,
        title: reportTitle,
        generated_at: new Date().toISOString(),
        generated_by: user?.email || 'system',
      },
    });

    // Store metadata in D1
    await c.env.DB.prepare(`
      INSERT INTO reports (id, title, report_type, format, filters, storage_key, file_size, status, generated_by, created_at, completed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', ?, datetime('now'), datetime('now'))
    `).bind(
      reportId, reportTitle, body.report_type, extension,
      JSON.stringify(body.filters || {}), storageKey, fileSize,
      user?.id || null,
    ).run();

    return c.json({
      id: reportId,
      title: reportTitle,
      report_type: body.report_type,
      format: extension,
      file_size: fileSize,
      storage_key: storageKey,
      status: 'completed',
      download_url: `/api/v1/reports/${reportId}/download`,
      generated_at: new Date().toISOString(),
    }, 201);

  } catch (error) {
    console.error('Report generation error:', error);

    // Log failure in D1
    await c.env.DB.prepare(`
      INSERT INTO reports (id, title, report_type, format, filters, status, error_message, generated_by, created_at)
      VALUES (?, ?, ?, ?, ?, 'failed', ?, ?, datetime('now'))
    `).bind(
      reportId, reportTitle, body.report_type, format,
      JSON.stringify(body.filters || {}),
      error instanceof Error ? error.message : 'Unknown error',
      user?.id || null,
    ).run().catch(() => {});

    return c.json({
      error: 'Failed to generate report',
      message: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// ---- GET /api/v1/reports/:id/download ----
reports.get('/:id/download', async (c) => {
  const id = c.req.param('id');

  // Look up report metadata to determine format
  const meta = await c.env.DB.prepare('SELECT * FROM reports WHERE id = ?').bind(id).first<any>();

  if (meta?.storage_key) {
    const object = await c.env.STORAGE.get(meta.storage_key);
    if (!object) return c.json({ error: 'Report file not found in storage' }, 404);

    const contentTypeMap: Record<string, string> = {
      pdf: 'application/pdf',
      csv: 'text/csv; charset=utf-8',
      json: 'application/json',
    };
    const ext = meta.format || 'json';
    const ct = contentTypeMap[ext] || 'application/octet-stream';

    const body = await object.arrayBuffer();
    return new Response(body, {
      headers: {
        'Content-Type': ct,
        'Content-Disposition': `attachment; filename="report-${id}.${ext}"`,
        'Content-Length': String(body.byteLength),
      },
    });
  }

  // Fallback: try old-style JSON report
  const object = await c.env.STORAGE.get(`reports/${id}.json`);
  if (!object) return c.json({ error: 'Report not found' }, 404);

  const data = await object.text();
  return new Response(data, {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="report-${id}.json"`,
    },
  });
});

// ---- GET /api/v1/reports/list/all ----
reports.get('/list/all', async (c) => {
  const { limit = '20', offset = '0', report_type } = c.req.query();

  try {
    let query = 'SELECT * FROM reports WHERE 1=1';
    const params: any[] = [];

    if (report_type) { query += ' AND report_type = ?'; params.push(report_type); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const result = await c.env.DB.prepare(query).bind(...params).all();

    const countQuery = report_type
      ? await c.env.DB.prepare('SELECT COUNT(*) as total FROM reports WHERE report_type = ?').bind(report_type).first<{ total: number }>()
      : await c.env.DB.prepare('SELECT COUNT(*) as total FROM reports').first<{ total: number }>();

    return c.json({
      data: result.results,
      total: countQuery?.total || 0,
      pagination: { limit: parseInt(limit), offset: parseInt(offset) },
    });
  } catch {
    // Fallback to R2 listing
    const listed = await c.env.STORAGE.list({ prefix: 'reports/' });
    const items = listed.objects.map(obj => ({
      key: obj.key,
      size: obj.size,
      uploaded: obj.uploaded,
      customMetadata: obj.customMetadata,
    }));
    return c.json({
      data: items.slice(parseInt(offset), parseInt(offset) + parseInt(limit)),
      total: items.length,
      pagination: { limit: parseInt(limit), offset: parseInt(offset) },
    });
  }
});

// ---- DELETE /api/v1/reports/:id ----
reports.delete('/:id', requireRole('platform_admin'), async (c) => {
  const id = c.req.param('id');
  const meta = await c.env.DB.prepare('SELECT storage_key FROM reports WHERE id = ?').bind(id).first<{ storage_key: string }>();

  if (meta?.storage_key) {
    await c.env.STORAGE.delete(meta.storage_key);
  }

  await c.env.DB.prepare('DELETE FROM reports WHERE id = ?').bind(id).run();
  return c.json({ message: 'Report deleted' });
});
