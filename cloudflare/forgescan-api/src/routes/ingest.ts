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
import { getOrgFilter, getOrgIdForInsert } from '../middleware/org-scope';
import { parseNessusXML, mapNessusSeverity } from '../services/nessus-parser';

export const ingest = new Hono<{ Bindings: Env }>();

// ─── List ingestion jobs ────────────────────────────────────────────────────

ingest.get('/jobs', async (c) => {
  const { limit = '20', vendor, status } = c.req.query();
  const limitNum = parsePositiveInt(limit, 20);
  const { orgId } = getOrgFilter(c);

  let query = 'SELECT * FROM ingestion_jobs WHERE 1=1';
  const params: any[] = [];

  if (orgId) {
    query += ' AND org_id = ?';
    params.push(orgId);
  }

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
  const { orgId } = getOrgFilter(c);

  try {
    const job = orgId
      ? await c.env.DB.prepare(
          'SELECT * FROM ingestion_jobs WHERE id = ? AND org_id = ?'
        ).bind(id, orgId).first()
      : await c.env.DB.prepare(
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

  const orgId = getOrgIdForInsert(c);

  // Create ingestion job
  try {
    await c.env.DB.prepare(`
      INSERT INTO ingestion_jobs (id, vendor, source, status, started_at, org_id)
      VALUES (?, ?, 'file_upload', 'processing', datetime('now'), ?)
    `).bind(jobId, vendor, orgId).run();
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
      const result = await importAssets(c.env.DB, assetRows, orgId);
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
            INSERT OR IGNORE INTO assets (id, hostname, ip_addresses, created_at, updated_at, org_id)
            VALUES (?, ?, ?, datetime('now'), datetime('now'), ?)
          `).bind(
            assetId,
            hostname,
            JSON.stringify(ip ? [ip] : []),
            orgId,
          ).run();
        }

        // Create finding
        const findingId = crypto.randomUUID();
        await c.env.DB.prepare(`
          INSERT INTO findings (
            id, asset_id, vendor, vendor_id, title, description, severity,
            port, protocol, service, solution, evidence, cve_id, cvss_score,
            affected_component, references, metadata,
            state, first_seen, last_seen, created_at, updated_at, org_id
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open',
            datetime('now'), datetime('now'), datetime('now'), datetime('now'), ?)
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
          orgId,
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

// ─── Nessus XML (.nessus) import ─────────────────────────────────────────────

ingest.post('/nessus', async (c) => {
  const orgId = getOrgIdForInsert(c);
  const contentType = c.req.header('content-type') || '';
  const importId = crypto.randomUUID();

  let xmlContent: string;
  let fileName = 'upload.nessus';

  if (contentType.includes('multipart/form-data')) {
    const formData = await c.req.formData();
    const file = formData.get('file') as unknown as File | null;
    if (!file) {
      throw badRequest('No file provided in multipart upload');
    }
    xmlContent = await file.text();
    fileName = file.name || fileName;
  } else if (contentType.includes('text/xml') || contentType.includes('application/xml')) {
    xmlContent = await c.req.text();
  } else {
    throw badRequest('Content-Type must be multipart/form-data, text/xml, or application/xml');
  }

  if (!xmlContent.trim()) {
    throw badRequest('Empty file content');
  }

  // Validate it looks like Nessus XML
  if (!xmlContent.includes('NessusClientData_v2') && !xmlContent.includes('<Report')) {
    throw badRequest('File does not appear to be a valid .nessus XML file');
  }

  // Compute file hash
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(xmlContent));
  const fileHash = Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');

  // Create scan_import record
  try {
    await c.env.DB.prepare(`
      INSERT INTO scan_imports (id, org_id, vendor, file_name, file_hash, status, started_at)
      VALUES (?, ?, 'nessus', ?, ?, 'processing', datetime('now'))
    `).bind(importId, orgId, fileName, fileHash).run();
  } catch (err) {
    throw databaseError(err);
  }

  try {
    const parseResult = parseNessusXML(xmlContent);
    let findingsCreated = 0;
    let findingsUpdated = 0;
    const importErrors: string[] = [...parseResult.errors];

    for (const host of parseResult.hosts) {
      // Upsert asset
      const assetId = crypto.randomUUID();
      try {
        await c.env.DB.prepare(`
          INSERT INTO assets (id, hostname, fqdn, ip_addresses, os, asset_type, first_seen, last_seen, created_at, updated_at, org_id)
          VALUES (?, ?, ?, ?, ?, 'host', datetime('now'), datetime('now'), datetime('now'), datetime('now'), ?)
          ON CONFLICT(id) DO UPDATE SET last_seen = datetime('now'), updated_at = datetime('now')
        `).bind(
          assetId,
          host.hostname || null,
          host.fqdn || null,
          JSON.stringify(host.ip ? [host.ip] : []),
          host.os || null,
          orgId,
        ).run();
      } catch (err) {
        // Try to find existing asset by IP
        if (host.ip) {
          const existing = await c.env.DB.prepare(
            "SELECT id FROM assets WHERE ip_addresses LIKE ? AND org_id = ? LIMIT 1"
          ).bind(`%${host.ip}%`, orgId).first<{ id: string }>();
          if (existing) {
            // Reuse existing asset ID — but we continue using assetId for findings below
            // Update the reference
            Object.defineProperty(host, '_assetId', { value: existing.id });
          }
        }
      }

      const effectiveAssetId = (host as any)._assetId || assetId;

      for (const finding of host.findings) {
        // Skip informational findings (severity 0) unless they have CVEs
        if (finding.severity === 0 && finding.cves.length === 0) continue;

        try {
          const findingId = crypto.randomUUID();
          const bestScore = finding.cvss3Score || finding.cvssScore || null;
          const primaryCve = finding.cves.length > 0 ? finding.cves[0] : null;

          // Check if finding already exists (same plugin + asset)
          const existingFinding = await c.env.DB.prepare(
            "SELECT id FROM findings WHERE vendor_id = ? AND asset_id = ? AND org_id = ?"
          ).bind(finding.pluginId, effectiveAssetId, orgId).first<{ id: string }>();

          if (existingFinding) {
            // Update existing finding
            await c.env.DB.prepare(`
              UPDATE findings SET
                last_seen = datetime('now'),
                severity = ?,
                cvss_score = ?,
                solution = ?,
                evidence = ?,
                updated_at = datetime('now')
              WHERE id = ?
            `).bind(
              mapNessusSeverity(finding.severity),
              bestScore,
              finding.solution || null,
              finding.output || null,
              existingFinding.id,
            ).run();
            findingsUpdated++;
          } else {
            await c.env.DB.prepare(`
              INSERT INTO findings (
                id, asset_id, vendor, vendor_id, title, description, severity,
                port, protocol, service, solution, evidence, cve_id, cvss_score,
                metadata, state, first_seen, last_seen, created_at, updated_at, org_id
              ) VALUES (?, ?, 'nessus', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open',
                datetime('now'), datetime('now'), datetime('now'), datetime('now'), ?)
            `).bind(
              findingId, effectiveAssetId, finding.pluginId,
              finding.pluginName, finding.description || finding.synopsis || null,
              mapNessusSeverity(finding.severity),
              finding.port || null, finding.protocol || null, finding.service || null,
              finding.solution || null, finding.output || null,
              primaryCve, bestScore,
              JSON.stringify({
                plugin_id: finding.pluginId,
                cves: finding.cves,
                cwe: finding.cwe,
                risk_factor: finding.riskFactor,
                see_also: finding.seeAlso,
                synopsis: finding.synopsis,
              }),
              orgId,
            ).run();
            findingsCreated++;
          }
        } catch (err) {
          importErrors.push(`Plugin ${finding.pluginId}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    // Update scan_import record
    await c.env.DB.prepare(`
      UPDATE scan_imports SET
        status = 'completed',
        hosts_total = ?,
        hosts_processed = ?,
        findings_created = ?,
        findings_updated = ?,
        errors = ?,
        completed_at = datetime('now')
      WHERE id = ?
    `).bind(
      parseResult.hosts.length,
      parseResult.hosts.length,
      findingsCreated,
      findingsUpdated,
      importErrors.length > 0 ? JSON.stringify(importErrors.slice(0, 50)) : null,
      importId,
    ).run();

    return c.json({
      import_id: importId,
      report_name: parseResult.reportName,
      status: 'completed',
      hosts_total: parseResult.hosts.length,
      findings_created: findingsCreated,
      findings_updated: findingsUpdated,
      errors: importErrors.slice(0, 10),
    });

  } catch (err: any) {
    try {
      await c.env.DB.prepare(`
        UPDATE scan_imports SET status = 'failed', errors = ?, completed_at = datetime('now')
        WHERE id = ?
      `).bind(JSON.stringify([err.message || String(err)]), importId).run();
    } catch { /* best effort */ }

    if (err instanceof ApiError) throw err;
    throw databaseError(err);
  }
});

ingest.post('/tenable', async (c) => {
  return c.json({
    message: 'Use POST /api/v1/ingest/nessus to import .nessus XML files directly',
    note: 'For CSV exports, use POST /api/v1/ingest/upload?vendor=tenable',
  }, 301);
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
  orgId: string | null = null,
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
          first_seen, last_seen, created_at, updated_at, org_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now'), datetime('now'), ?)
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
        orgId,
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
