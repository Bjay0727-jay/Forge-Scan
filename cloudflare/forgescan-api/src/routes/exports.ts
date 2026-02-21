import { Hono } from 'hono';
import type { Env } from '../index';
import { notFound, databaseError } from '../lib/errors';
import { requireEnum } from '../lib/validate';

export const exports = new Hono<{ Bindings: Env }>();

// Types
interface ScheduleExportRequest {
  export_type: 'findings' | 'assets';
  format: 'csv' | 'json';
  schedule: 'daily' | 'weekly' | 'monthly';
  filters?: {
    severity?: string[];
    vendors?: string[];
    state?: string;
    asset_types?: string[];
  };
  destination?: {
    type: 'r2' | 'email';
    email?: string;
  };
  enabled?: boolean;
}

// Helper function to convert data to CSV
function toCSV(data: any[], columns?: string[]): string {
  if (!data || data.length === 0) {
    return '';
  }

  const headers = columns || Object.keys(data[0]);

  const escapeCSV = (value: any): string => {
    if (value === null || value === undefined) {
      return '';
    }
    const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const headerRow = headers.join(',');
  const dataRows = data.map(row =>
    headers.map(header => escapeCSV(row[header])).join(',')
  );

  return [headerRow, ...dataRows].join('\n');
}

// GET /api/v1/exports/findings/csv - Export findings as CSV
exports.get('/findings/csv', async (c) => {
  const {
    severity,
    vendor,
    state = 'open',
    limit = '10000',
    include_asset = 'true',
  } = c.req.query();

  let query: string;
  const params: any[] = [];

  if (include_asset === 'true') {
    query = `
      SELECT
        f.id,
        f.title,
        f.description,
        f.severity,
        f.state,
        f.vendor,
        f.vendor_id,
        f.port,
        f.protocol,
        f.service,
        f.frs_score,
        f.solution,
        f.first_seen,
        f.last_seen,
        f.fixed_at,
        a.hostname,
        a.ip_addresses,
        a.os,
        a.asset_type
      FROM findings f
      LEFT JOIN assets a ON f.asset_id = a.id
      WHERE 1=1
    `;
  } else {
    query = `
      SELECT
        id,
        title,
        description,
        severity,
        state,
        vendor,
        vendor_id,
        port,
        protocol,
        service,
        frs_score,
        solution,
        first_seen,
        last_seen,
        fixed_at
      FROM findings
      WHERE 1=1
    `;
  }

  if (severity) {
    const severities = severity.split(',');
    query += ` AND ${include_asset === 'true' ? 'f.' : ''}severity IN (${severities.map(() => '?').join(',')})`;
    params.push(...severities);
  }

  if (vendor) {
    const vendors = vendor.split(',');
    query += ` AND ${include_asset === 'true' ? 'f.' : ''}vendor IN (${vendors.map(() => '?').join(',')})`;
    params.push(...vendors);
  }

  if (state) {
    query += ` AND ${include_asset === 'true' ? 'f.' : ''}state = ?`;
    params.push(state);
  }

  query += ` ORDER BY ${include_asset === 'true' ? 'f.' : ''}created_at DESC LIMIT ?`;
  params.push(parseInt(limit));

  try {
    const result = await c.env.DB.prepare(query).bind(...params).all();

    const csv = toCSV(result.results as any[]);
    const filename = `findings_export_${new Date().toISOString().split('T')[0]}.csv`;

    return new Response(csv, {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
      },
    });
  } catch (err) {
    throw databaseError(err);
  }
});

// GET /api/v1/exports/findings/json - Export findings as JSON
exports.get('/findings/json', async (c) => {
  const {
    severity,
    vendor,
    state = 'open',
    limit = '10000',
    pretty = 'false',
  } = c.req.query();

  let query = `
    SELECT
      f.*,
      a.hostname,
      a.ip_addresses,
      a.os,
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

  query += ' ORDER BY f.created_at DESC LIMIT ?';
  params.push(parseInt(limit));

  try {
    const result = await c.env.DB.prepare(query).bind(...params).all();

    const exportData = {
      exported_at: new Date().toISOString(),
      filters: { severity, vendor, state },
      total_count: result.results?.length || 0,
      findings: result.results,
    };

    const jsonStr = pretty === 'true'
      ? JSON.stringify(exportData, null, 2)
      : JSON.stringify(exportData);

    const filename = `findings_export_${new Date().toISOString().split('T')[0]}.json`;

    return new Response(jsonStr, {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
      },
    });
  } catch (err) {
    throw databaseError(err);
  }
});

// GET /api/v1/exports/assets/csv - Export assets as CSV
exports.get('/assets/csv', async (c) => {
  const {
    asset_type,
    network_zone,
    include_findings_count = 'true',
    limit = '10000',
  } = c.req.query();

  let query: string;
  const params: any[] = [];

  if (include_findings_count === 'true') {
    query = `
      SELECT
        a.id,
        a.hostname,
        a.fqdn,
        a.ip_addresses,
        a.mac_addresses,
        a.os,
        a.os_version,
        a.asset_type,
        a.network_zone,
        a.tags,
        a.first_seen,
        a.last_seen,
        COUNT(CASE WHEN f.state = 'open' THEN 1 END) as open_findings,
        SUM(CASE WHEN f.severity = 'critical' AND f.state = 'open' THEN 1 ELSE 0 END) as critical_findings,
        SUM(CASE WHEN f.severity = 'high' AND f.state = 'open' THEN 1 ELSE 0 END) as high_findings
      FROM assets a
      LEFT JOIN findings f ON a.id = f.asset_id
      WHERE 1=1
    `;
  } else {
    query = `
      SELECT
        id,
        hostname,
        fqdn,
        ip_addresses,
        mac_addresses,
        os,
        os_version,
        asset_type,
        network_zone,
        tags,
        first_seen,
        last_seen
      FROM assets
      WHERE 1=1
    `;
  }

  if (asset_type) {
    query += ` AND ${include_findings_count === 'true' ? 'a.' : ''}asset_type = ?`;
    params.push(asset_type);
  }

  if (network_zone) {
    query += ` AND ${include_findings_count === 'true' ? 'a.' : ''}network_zone = ?`;
    params.push(network_zone);
  }

  if (include_findings_count === 'true') {
    query += ' GROUP BY a.id';
  }

  query += ` ORDER BY ${include_findings_count === 'true' ? 'a.' : ''}last_seen DESC LIMIT ?`;
  params.push(parseInt(limit));

  try {
    const result = await c.env.DB.prepare(query).bind(...params).all();

    const csv = toCSV(result.results as any[]);
    const filename = `assets_export_${new Date().toISOString().split('T')[0]}.csv`;

    return new Response(csv, {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
      },
    });
  } catch (err) {
    throw databaseError(err);
  }
});

// GET /api/v1/exports/assets/json - Export assets as JSON
exports.get('/assets/json', async (c) => {
  const {
    asset_type,
    network_zone,
    include_findings = 'false',
    limit = '10000',
    pretty = 'false',
  } = c.req.query();

  let query = 'SELECT * FROM assets WHERE 1=1';
  const params: any[] = [];

  if (asset_type) {
    query += ' AND asset_type = ?';
    params.push(asset_type);
  }

  if (network_zone) {
    query += ' AND network_zone = ?';
    params.push(network_zone);
  }

  query += ' ORDER BY last_seen DESC LIMIT ?';
  params.push(parseInt(limit));

  try {
    const result = await c.env.DB.prepare(query).bind(...params).all();

    let assets = result.results as any[];

    // Optionally include findings for each asset
    if (include_findings === 'true') {
      for (const asset of assets) {
        const findingsResult = await c.env.DB.prepare(`
          SELECT id, title, severity, state, vendor, first_seen
          FROM findings
          WHERE asset_id = ? AND state = 'open'
          ORDER BY severity, created_at DESC
        `).bind(asset.id).all();

        asset.findings = findingsResult.results;
        asset.findings_count = findingsResult.results?.length || 0;
      }
    }

    const exportData = {
      exported_at: new Date().toISOString(),
      filters: { asset_type, network_zone },
      total_count: assets.length,
      assets,
    };

    const jsonStr = pretty === 'true'
      ? JSON.stringify(exportData, null, 2)
      : JSON.stringify(exportData);

    const filename = `assets_export_${new Date().toISOString().split('T')[0]}.json`;

    return new Response(jsonStr, {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
      },
    });
  } catch (err) {
    throw databaseError(err);
  }
});

// POST /api/v1/exports/schedule - Schedule recurring export
exports.post('/schedule', async (c) => {
  const body = await c.req.json<ScheduleExportRequest>();
  const scheduleId = crypto.randomUUID();

  // Validate request
  requireEnum(body.export_type, 'export_type', ['findings', 'assets'] as const);
  requireEnum(body.format, 'format', ['csv', 'json'] as const);
  requireEnum(body.schedule, 'schedule', ['daily', 'weekly', 'monthly'] as const);

  // Calculate next run time
  const now = new Date();
  let nextRun: Date;

  switch (body.schedule) {
    case 'daily':
      nextRun = new Date(now);
      nextRun.setDate(nextRun.getDate() + 1);
      nextRun.setHours(0, 0, 0, 0);
      break;
    case 'weekly':
      nextRun = new Date(now);
      nextRun.setDate(nextRun.getDate() + (7 - nextRun.getDay()));
      nextRun.setHours(0, 0, 0, 0);
      break;
    case 'monthly':
      nextRun = new Date(now.getFullYear(), now.getMonth() + 1, 1, 0, 0, 0, 0);
      break;
    default:
      nextRun = new Date(now);
      nextRun.setDate(nextRun.getDate() + 1);
  }

  const scheduleConfig = {
    id: scheduleId,
    export_type: body.export_type,
    format: body.format,
    schedule: body.schedule,
    filters: body.filters || {},
    destination: body.destination || { type: 'r2' },
    enabled: body.enabled !== false,
    created_at: now.toISOString(),
    next_run: nextRun.toISOString(),
  };

  // Store schedule in database
  try {
    await c.env.DB.prepare(`
      INSERT INTO export_schedules (id, export_type, format, schedule, filters, destination, enabled, next_run, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      scheduleId,
      body.export_type,
      body.format,
      body.schedule,
      JSON.stringify(body.filters || {}),
      JSON.stringify(body.destination || { type: 'r2' }),
      body.enabled !== false ? 1 : 0,
      nextRun.toISOString(),
    ).run();
  } catch (error) {
    // Table might not exist, store in KV as fallback
    await c.env.CACHE.put(
      `export_schedule:${scheduleId}`,
      JSON.stringify(scheduleConfig),
      { expirationTtl: 60 * 60 * 24 * 365 } // 1 year
    );
  }

  return c.json({
    id: scheduleId,
    message: 'Export schedule created',
    schedule: scheduleConfig,
  }, 201);
});

// GET /api/v1/exports/schedules - List scheduled exports
exports.get('/schedules', async (c) => {
  try {
    const result = await c.env.DB.prepare(`
      SELECT * FROM export_schedules
      ORDER BY created_at DESC
    `).all();

    return c.json({
      data: result.results,
    });
  } catch {
    // Fallback to KV listing
    const list = await c.env.CACHE.list({ prefix: 'export_schedule:' });
    const schedules = [];

    for (const key of list.keys) {
      const value = await c.env.CACHE.get(key.name);
      if (value) {
        schedules.push(JSON.parse(value));
      }
    }

    return c.json({
      data: schedules,
    });
  }
});

// DELETE /api/v1/exports/schedules/:id - Delete scheduled export
exports.delete('/schedules/:id', async (c) => {
  const id = c.req.param('id');

  try {
    await c.env.DB.prepare('DELETE FROM export_schedules WHERE id = ?').bind(id).run();
  } catch {
    // Fallback to KV
    await c.env.CACHE.delete(`export_schedule:${id}`);
  }

  return c.json({ message: 'Export schedule deleted' });
});

// PATCH /api/v1/exports/schedules/:id - Update scheduled export
exports.patch('/schedules/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json<Partial<ScheduleExportRequest>>();

  try {
    const updates: string[] = ['updated_at = datetime(\'now\')'];
    const params: any[] = [];

    if (body.schedule) {
      updates.push('schedule = ?');
      params.push(body.schedule);
    }

    if (body.filters !== undefined) {
      updates.push('filters = ?');
      params.push(JSON.stringify(body.filters));
    }

    if (body.enabled !== undefined) {
      updates.push('enabled = ?');
      params.push(body.enabled ? 1 : 0);
    }

    if (updates.length > 1) {
      await c.env.DB.prepare(`
        UPDATE export_schedules SET ${updates.join(', ')} WHERE id = ?
      `).bind(...params, id).run();
    }

    return c.json({ message: 'Export schedule updated' });
  } catch (err) {
    throw databaseError(err);
  }
});

// POST /api/v1/exports/run/:id - Manually trigger scheduled export
exports.post('/run/:id', async (c) => {
  const id = c.req.param('id');

  // Get schedule config
  let schedule: any;
  try {
    schedule = await c.env.DB.prepare(
      'SELECT * FROM export_schedules WHERE id = ?'
    ).bind(id).first();
  } catch {
    const value = await c.env.CACHE.get(`export_schedule:${id}`);
    if (value) {
      schedule = JSON.parse(value);
    }
  }

  if (!schedule) {
    throw notFound('Schedule', id);
  }

  try {
    // Generate export
    const exportId = crypto.randomUUID();
    const filters = typeof schedule.filters === 'string'
      ? JSON.parse(schedule.filters)
      : schedule.filters;

    let query: string;
    let data: any[];

    if (schedule.export_type === 'findings') {
      query = 'SELECT * FROM findings WHERE 1=1';
      const params: any[] = [];

      if (filters.severity?.length) {
        query += ` AND severity IN (${filters.severity.map(() => '?').join(',')})`;
        params.push(...filters.severity);
      }
      if (filters.state) {
        query += ' AND state = ?';
        params.push(filters.state);
      }

      const result = await c.env.DB.prepare(query).bind(...params).all();
      data = result.results as any[];
    } else {
      query = 'SELECT * FROM assets WHERE 1=1';
      const params: any[] = [];

      if (filters.asset_types?.length) {
        query += ` AND asset_type IN (${filters.asset_types.map(() => '?').join(',')})`;
        params.push(...filters.asset_types);
      }

      const result = await c.env.DB.prepare(query).bind(...params).all();
      data = result.results as any[];
    }

    // Format data
    let content: string;
    let contentType: string;
    let extension: string;

    if (schedule.format === 'csv') {
      content = toCSV(data);
      contentType = 'text/csv';
      extension = 'csv';
    } else {
      content = JSON.stringify({
        exported_at: new Date().toISOString(),
        schedule_id: id,
        total_count: data.length,
        data,
      }, null, 2);
      contentType = 'application/json';
      extension = 'json';
    }

    // Store in R2
    const filename = `exports/scheduled/${id}/${exportId}.${extension}`;
    await c.env.STORAGE.put(filename, content, {
      customMetadata: {
        schedule_id: id,
        export_type: schedule.export_type,
        format: schedule.format,
        created_at: new Date().toISOString(),
      },
    });

    return c.json({
      id: exportId,
      schedule_id: id,
      storage_key: filename,
      record_count: data.length,
      format: schedule.format,
      created_at: new Date().toISOString(),
    });
  } catch (err) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});
