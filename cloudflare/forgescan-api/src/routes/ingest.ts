import { Hono } from 'hono';
import type { Env } from '../index';
import { ApiError, notFound, badRequest, databaseError } from '../lib/errors';
import { parsePositiveInt } from '../lib/validate';
import {
  parseFindingsCSV,
  parseAssetsCSV,
  detectCSVType,
  normalizeSeverity,
  getSupportedVendors,
} from '../lib/csv-parser';

export const ingest = new Hono<{ Bindings: Env }>();

// ─── List ingestion jobs ────────────────────────────────────────────────────

ingest.get('/jobs', async (c) => {
  const { limit = '20', vendor, status } = c.req.query();
  const limitNum = parsePositiveInt(limit, 20);

  let query = 'SELECT * FROM ingestion_jobs WHERE 1=1';
  const params: any[] = [];

  if (vendor) {
    query += ' AND vendor = ?';
    params.push(vendor);
  }

  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }

  query += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limitNum);

  try {
    const result = await c.env.DB.prepare(query).bind(...params).all();
    return c.json(result.results);
  } catch (err) {
    throw databaseError(err);
  }
});

// ─── Get ingestion job by ID ────────────────────────────────────────────────

ingest.get('/jobs/:id', async (c) => {
  const id = c.req.param('id');

  try {
    const job = await c.env.DB.prepare(
      'SELECT * FROM ingestion_jobs WHERE id = ?'
    ).bind(id).first();

    if (!job) {
      throw notFound('Job', id);
    }

    return c.json(job);
  } catch (err) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    throw databaseError(err);
  }
});

// ─── Upload findings (JSON, CSV, multipart file) ───────────────────────────

ingest.post('/upload', async (c) => {
  const contentType = c.req.header('content-type') || '';
  const vendor = c.req.query('vendor') || 'generic';
  const dataType = c.req.query('type') || 'findings'; // 'findings' | 'assets'
  const jobId = crypto.randomUUID();

  // Create ingestion job
  try {
    await c.env.DB.prepare(`
      INSERT INTO ingestion_jobs (id, vendor, source, status, started_at)
      VALUES (?, ?, 'file_upload', 'processing', datetime('now'))
    `).bind(jobId, vendor).run();
  } catch (err) {
    throw databaseError(err);
  }

  try {
    let findings: any[] = [];
    let assetRows: any[] = [];
    let parseErrors: string[] = [];
    let isAssetImport = dataType === 'assets';

    // ── JSON body ────────────────────────────────────────────────────────
    if (contentType.includes('application/json')) {
      const body = await c.req.json();
      findings = Array.isArray(body)
        ? body
        : body.findings || body.vulnerabilities || [];

    // ── CSV body (raw text/csv) ──────────────────────────────────────────
    } else if (contentType.includes('text/csv')) {
      const csvText = await c.req.text();

      if (!csvText.trim()) {
        throw badRequest('Empty CSV body');
      }

      // Auto-detect if not explicitly set
      if (dataType === 'auto' || !dataType) {
        const detected = detectCSVType(csvText);
        isAssetImport = detected === 'assets';
      }

      if (isAssetImport) {
        const result = parseAssetsCSV(csvText);
        assetRows = result.rows;
        parseErrors = result.errors;
      } else {
        const result = parseFindingsCSV(csvText, vendor);
        findings = result.rows;
        parseErrors = result.errors;
      }

    // ── Multipart form-data (file upload) ────────────────────────────────
    } else if (contentType.includes('multipart/form-data')) {
      const formData = await c.req.formData();
      const file = formData.get('file') as unknown as File | null;

      if (!file) {
        throw badRequest('No file provided in multipart upload');
      }

      const content = await file.text();
      if (!content.trim()) {
        throw badRequest('Uploaded file is empty');
      }

      // Determine format from file extension or form field
      const format = (formData.get('format') as string) || '';
      const fileName = file.name || '';

      if (format === 'json' || fileName.endsWith('.json')) {
        // JSON file upload
        const body = JSON.parse(content);
        findings = Array.isArray(body)
          ? body
          : body.findings || body.vulnerabilities || [];

      } else if (format === 'csv' || fileName.endsWith('.csv') || !format) {
        // CSV file upload (default for unknown extensions)
        if (dataType === 'auto') {
          const detected = detectCSVType(content);
          isAssetImport = detected === 'assets';
        }

        if (isAssetImport) {
          const result = parseAssetsCSV(content);
          assetRows = result.rows;
          parseErrors = result.errors;
        } else {
          const result = parseFindingsCSV(content, vendor);
          findings = result.rows;
          parseErrors = result.errors;
        }
      } else {
        throw badRequest(`Unsupported file format: ${format || fileName}`);
      }

    } else {
      throw badRequest(`Unsupported content type: ${contentType}`);
    }

    // ── Process asset imports ────────────────────────────────────────────
    if (isAssetImport && assetRows.length > 0) {
      const result = await importAssets(c.env.DB, assetRows);
      parseErrors.push(...result.errors);

      await c.env.DB.prepare(`
        UPDATE ingestion_jobs SET
          status = 'completed',
          completed_at = datetime('now'),
          records_processed = ?,
          records_imported = ?,
          records_skipped = ?,
          errors = ?
        WHERE id = ?
      `).bind(
        assetRows.length,
        result.imported,
        result.skipped,
        parseErrors.length > 0 ? JSON.stringify(parseErrors.slice(0, 50)) : null,
        jobId,
      ).run();

      return c.json({
        job_id: jobId,
        type: 'assets',
        status: 'completed',
        records_processed: assetRows.length,
        records_imported: result.imported,
        records_skipped: result.skipped,
        errors: parseErrors.slice(0, 10),
      });
    }

    // ── Process findings imports ─────────────────────────────────────────
    let imported = 0;
    let skipped = 0;

    for (const finding of findings) {
      try {
        // Ensure asset exists if hostname/IP provided
        let assetId = finding.asset_id || null;
        const hostname = finding.hostname || finding.host || null;
        const ip = finding.ip || finding.ip_address || null;

        if (!assetId && (ip || hostname)) {
          assetId = crypto.randomUUID();
          await c.env.DB.prepare(`
            INSERT OR IGNORE INTO assets (id, hostname, ip_addresses, created_at, updated_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now'))
          `).bind(
            assetId,
            hostname,
            JSON.stringify(ip ? [ip] : []),
          ).run();
        }

        // Create finding
        const findingId = crypto.randomUUID();
        await c.env.DB.prepare(`
          INSERT INTO findings (
            id, asset_id, vendor, vendor_id, title, description, severity,
            port, protocol, service, solution, evidence, cve_id, cvss_score,
            affected_component, references, metadata,
            state, first_seen, last_seen, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open',
            datetime('now'), datetime('now'), datetime('now'), datetime('now'))
        `).bind(
          findingId,
          assetId,
          vendor,
          finding.vendor_id || finding.id || finding.vuln_id || finding.plugin_id || findingId,
          finding.title || finding.name || 'Unknown',
          finding.description || null,
          normalizeSeverity(finding.severity, finding.cvss_score || finding.cvss),
          finding.port || null,
          finding.protocol || null,
          finding.service || null,
          finding.solution || finding.remediation || null,
          finding.evidence || finding.output || null,
          finding.cve_id || null,
          finding.cvss_score || finding.cvss || null,
          finding.affected_component || null,
          finding.references ? (typeof finding.references === 'string' ? finding.references : JSON.stringify(finding.references)) : null,
          JSON.stringify(finding),
        ).run();

        imported++;
      } catch (err) {
        console.error('Error importing finding:', err);
        skipped++;
        parseErrors.push(`Finding "${finding.title || 'unknown'}": ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // Update job status
    await c.env.DB.prepare(`
      UPDATE ingestion_jobs SET
        status = 'completed',
        completed_at = datetime('now'),
        records_processed = ?,
        records_imported = ?,
        records_skipped = ?,
        errors = ?
      WHERE id = ?
    `).bind(
      findings.length,
      imported,
      skipped,
      parseErrors.length > 0 ? JSON.stringify(parseErrors.slice(0, 50)) : null,
      jobId,
    ).run();

    return c.json({
      job_id: jobId,
      type: 'findings',
      status: 'completed',
      records_processed: findings.length,
      records_imported: imported,
      records_skipped: skipped,
      errors: parseErrors.slice(0, 10),
    });

  } catch (err: any) {
    // Update job as failed
    const errMessage = err instanceof ApiError ? err.message : (err instanceof Error ? err.message : String(err));
    try {
      await c.env.DB.prepare(`
        UPDATE ingestion_jobs SET
          status = 'failed',
          completed_at = datetime('now'),
          errors = ?
        WHERE id = ?
      `).bind(JSON.stringify([errMessage]), jobId).run();
    } catch {
      // Best-effort update
    }

    if (err instanceof ApiError) throw err;
    throw databaseError(err);
  }
});

// ─── Get supported vendors ──────────────────────────────────────────────────

ingest.get('/vendors', (c) => {
  return c.json({
    vendors: getSupportedVendors(),
    note: 'Use ?vendor=<name> when uploading CSV to apply vendor-specific column mappings',
  });
});

// ─── Vendor-specific placeholders ───────────────────────────────────────────

ingest.post('/tenable', async (c) => {
  return c.json({
    message: 'Tenable import should be triggered from the scanner service',
    note: 'Use POST /upload?vendor=tenable to import exported Nessus CSV data',
  }, 501);
});

ingest.post('/qualys', async (c) => {
  return c.json({
    message: 'Qualys import should be triggered from the scanner service',
    note: 'Use POST /upload?vendor=qualys to import exported Qualys CSV data',
  }, 501);
});

ingest.post('/rapid7', async (c) => {
  return c.json({
    message: 'Rapid7 import should be triggered from the scanner service',
    note: 'Use POST /upload?vendor=rapid7 to import exported Rapid7 CSV data',
  }, 501);
});

// ─── Asset import helper ────────────────────────────────────────────────────

async function importAssets(
  db: D1Database,
  assets: any[],
): Promise<{ imported: number; skipped: number; errors: string[] }> {
  let imported = 0;
  let skipped = 0;
  const errors: string[] = [];

  for (const asset of assets) {
    try {
      const id = crypto.randomUUID();
      const ipAddresses = asset.ip_address
        ? (Array.isArray(asset.ip_address) ? asset.ip_address : [asset.ip_address])
        : [];
      const tags = asset.tags || [];

      await db.prepare(`
        INSERT INTO assets (
          id, hostname, fqdn, ip_addresses, os, os_version,
          asset_type, network_zone, tags, attributes,
          first_seen, last_seen, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now'), datetime('now'))
      `).bind(
        id,
        asset.hostname || null,
        asset.fqdn || null,
        JSON.stringify(ipAddresses),
        asset.os || null,
        asset.os_version || null,
        asset.asset_type || 'host',
        asset.network_zone || null,
        JSON.stringify(tags),
        JSON.stringify({
          owner: asset.owner || null,
          department: asset.department || null,
          location: asset.location || null,
          mac_addresses: asset.mac_address || null,
        }),
      ).run();

      imported++;
    } catch (err: any) {
      skipped++;
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('UNIQUE constraint')) {
        errors.push(`Asset "${asset.hostname || asset.ip_address}": Duplicate record`);
      } else {
        errors.push(`Asset "${asset.hostname || asset.ip_address}": ${msg}`);
      }
    }
  }

  return { imported, skipped, errors };
}
