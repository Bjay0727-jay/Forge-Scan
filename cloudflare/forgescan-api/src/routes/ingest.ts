import { Hono } from 'hono';
import type { Env } from '../index';
import { notFound, badRequest, databaseError } from '../lib/errors';
import { parsePositiveInt } from '../lib/validate';

export const ingest = new Hono<{ Bindings: Env }>();

// List ingestion jobs
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

// Get ingestion job by ID
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

// Import findings from JSON/CSV
ingest.post('/upload', async (c) => {
  const contentType = c.req.header('content-type') || '';
  const vendor = c.req.query('vendor') || 'generic';
  const jobId = crypto.randomUUID();

  // Create ingestion job
  await c.env.DB.prepare(`
    INSERT INTO ingestion_jobs (id, vendor, source, status, started_at)
    VALUES (?, ?, 'file_upload', 'processing', datetime('now'))
  `).bind(jobId, vendor).run();

  try {
    let findings: any[] = [];

    if (contentType.includes('application/json')) {
      const body = await c.req.json();
      findings = Array.isArray(body) ? body : body.findings || body.vulnerabilities || [];
    } else if (contentType.includes('text/csv') || contentType.includes('multipart/form-data')) {
      // For CSV, we'd parse it here - simplified for now
      throw badRequest('CSV parsing not yet implemented in edge worker');
    } else {
      throw badRequest(`Unsupported content type: ${contentType}`);
    }

    let imported = 0;
    let skipped = 0;

    for (const finding of findings) {
      try {
        // Ensure asset exists
        let assetId = finding.asset_id;
        if (!assetId && (finding.ip || finding.hostname)) {
          assetId = crypto.randomUUID();
          await c.env.DB.prepare(`
            INSERT OR IGNORE INTO assets (id, hostname, ip_addresses)
            VALUES (?, ?, ?)
          `).bind(
            assetId,
            finding.hostname || null,
            JSON.stringify(finding.ip ? [finding.ip] : []),
          ).run();
        }

        // Create finding
        const findingId = crypto.randomUUID();
        await c.env.DB.prepare(`
          INSERT INTO findings (
            id, asset_id, vendor, vendor_id, title, description, severity,
            port, protocol, solution, evidence, metadata
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          findingId,
          assetId,
          vendor,
          finding.id || finding.vuln_id || finding.plugin_id || findingId,
          finding.title || finding.name || 'Unknown',
          finding.description || null,
          normalizeSeverity(finding.severity, finding.cvss),
          finding.port || null,
          finding.protocol || null,
          finding.solution || finding.remediation || null,
          finding.evidence || finding.output || null,
          JSON.stringify(finding),
        ).run();

        imported++;
      } catch (err) {
        console.error('Error importing finding:', err);
        skipped++;
      }
    }

    // Update job status
    await c.env.DB.prepare(`
      UPDATE ingestion_jobs SET
        status = 'completed',
        completed_at = datetime('now'),
        records_processed = ?,
        records_imported = ?,
        records_skipped = ?
      WHERE id = ?
    `).bind(findings.length, imported, skipped, jobId).run();

    return c.json({
      job_id: jobId,
      status: 'completed',
      records_processed: findings.length,
      records_imported: imported,
      records_skipped: skipped,
    });

  } catch (err: any) {
    // Update job as failed
    await c.env.DB.prepare(`
      UPDATE ingestion_jobs SET
        status = 'failed',
        completed_at = datetime('now'),
        errors = ?
      WHERE id = ?
    `).bind(JSON.stringify([err.message]), jobId).run();

    throw databaseError(err);
  }
});

// Import from Tenable.io (webhook or manual trigger)
ingest.post('/tenable', async (c) => {
  // This would be called by a scheduled job or webhook
  // The actual Tenable API calls would happen in the scanner component
  return c.json({
    message: 'Tenable import should be triggered from the scanner service',
    note: 'Use POST /upload to import exported Tenable data',
  }, 501);
});

// Import from Qualys
ingest.post('/qualys', async (c) => {
  return c.json({
    message: 'Qualys import should be triggered from the scanner service',
    note: 'Use POST /upload to import exported Qualys data',
  }, 501);
});

// Import from Rapid7
ingest.post('/rapid7', async (c) => {
  return c.json({
    message: 'Rapid7 import should be triggered from the scanner service',
    note: 'Use POST /upload to import exported Rapid7 data',
  }, 501);
});

// Normalize severity from various formats
function normalizeSeverity(severity: string | number | undefined, cvss?: number): string {
  if (cvss !== undefined) {
    if (cvss >= 9.0) return 'critical';
    if (cvss >= 7.0) return 'high';
    if (cvss >= 4.0) return 'medium';
    if (cvss >= 0.1) return 'low';
    return 'info';
  }

  if (typeof severity === 'number') {
    if (severity >= 4) return 'critical';
    if (severity === 3) return 'high';
    if (severity === 2) return 'medium';
    if (severity === 1) return 'low';
    return 'info';
  }

  const sevLower = (severity || '').toLowerCase();
  if (['critical', 'urgent', '4'].includes(sevLower)) return 'critical';
  if (['high', 'serious', '3'].includes(sevLower)) return 'high';
  if (['medium', 'moderate', '2'].includes(sevLower)) return 'medium';
  if (['low', 'minimal', '1'].includes(sevLower)) return 'low';
  return 'info';
}
