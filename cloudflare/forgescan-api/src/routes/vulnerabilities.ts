import { Hono } from 'hono';
import type { Env } from '../index';

export const vulnerabilities = new Hono<{ Bindings: Env }>();

// Types
interface VulnerabilityRecord {
  id: string;
  cve_id: string;
  description: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  epss_score: number | null;
  in_kev: boolean;
  published_at: string | null;
  modified_at: string | null;
  cwe_ids: string | null;
  affected_products: string | null;
  references: string | null;
  created_at: string;
  updated_at: string;
}

interface NVDSyncResult {
  sync_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at?: string;
  records_processed?: number;
  records_added?: number;
  records_updated?: number;
  error_message?: string;
}

// GET /api/v1/vulnerabilities - List CVEs in database
vulnerabilities.get('/', async (c) => {
  const {
    limit = '50',
    offset = '0',
    min_cvss,
    max_cvss,
    in_kev,
    has_epss,
    sort_by = 'cvss_score',
    sort_order = 'desc',
  } = c.req.query();

  let query = 'SELECT * FROM vulnerabilities WHERE 1=1';
  const params: any[] = [];

  if (min_cvss) {
    query += ' AND cvss_score >= ?';
    params.push(parseFloat(min_cvss));
  }

  if (max_cvss) {
    query += ' AND cvss_score <= ?';
    params.push(parseFloat(max_cvss));
  }

  if (in_kev === 'true') {
    query += ' AND in_kev = 1';
  } else if (in_kev === 'false') {
    query += ' AND (in_kev = 0 OR in_kev IS NULL)';
  }

  if (has_epss === 'true') {
    query += ' AND epss_score IS NOT NULL';
  }

  // Validate and apply sorting
  const validSortFields = ['cvss_score', 'epss_score', 'published_at', 'cve_id', 'created_at'];
  const sortField = validSortFields.includes(sort_by) ? sort_by : 'cvss_score';
  const order = sort_order.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

  query += ` ORDER BY ${sortField} ${order} NULLS LAST LIMIT ? OFFSET ?`;
  params.push(parseInt(limit), parseInt(offset));

  const result = await c.env.DB.prepare(query).bind(...params).all();

  // Get total count
  let countQuery = 'SELECT COUNT(*) as total FROM vulnerabilities WHERE 1=1';
  const countParams: any[] = [];

  if (min_cvss) {
    countQuery += ' AND cvss_score >= ?';
    countParams.push(parseFloat(min_cvss));
  }
  if (max_cvss) {
    countQuery += ' AND cvss_score <= ?';
    countParams.push(parseFloat(max_cvss));
  }
  if (in_kev === 'true') {
    countQuery += ' AND in_kev = 1';
  }

  const countResult = await c.env.DB.prepare(countQuery)
    .bind(...countParams)
    .first<{ total: number }>();

  return c.json({
    data: result.results,
    pagination: {
      total: countResult?.total || 0,
      limit: parseInt(limit),
      offset: parseInt(offset),
    },
  });
});

// GET /api/v1/vulnerabilities/stats - Get vulnerability statistics
vulnerabilities.get('/stats', async (c) => {
  const result = await c.env.DB.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN cvss_score >= 9.0 THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN cvss_score >= 7.0 AND cvss_score < 9.0 THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN cvss_score >= 4.0 AND cvss_score < 7.0 THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN cvss_score < 4.0 THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN in_kev = 1 THEN 1 ELSE 0 END) as in_kev,
      SUM(CASE WHEN epss_score IS NOT NULL THEN 1 ELSE 0 END) as has_epss,
      AVG(cvss_score) as avg_cvss,
      AVG(epss_score) as avg_epss,
      MAX(published_at) as latest_published
    FROM vulnerabilities
  `).first();

  return c.json(result);
});

// GET /api/v1/vulnerabilities/search - Search vulnerabilities
vulnerabilities.get('/search', async (c) => {
  const {
    q,
    cve_pattern,
    cwe,
    product,
    vendor,
    limit = '50',
    offset = '0',
  } = c.req.query();

  if (!q && !cve_pattern && !cwe && !product && !vendor) {
    return c.json({ error: 'At least one search parameter is required (q, cve_pattern, cwe, product, vendor)' }, 400);
  }

  let query = 'SELECT * FROM vulnerabilities WHERE 1=1';
  const params: any[] = [];

  // General text search
  if (q) {
    query += ' AND (cve_id LIKE ? OR description LIKE ? OR affected_products LIKE ?)';
    const searchPattern = `%${q}%`;
    params.push(searchPattern, searchPattern, searchPattern);
  }

  // CVE pattern (e.g., CVE-2023-%)
  if (cve_pattern) {
    query += ' AND cve_id LIKE ?';
    params.push(cve_pattern.includes('%') ? cve_pattern : `%${cve_pattern}%`);
  }

  // CWE filter
  if (cwe) {
    query += ' AND cwe_ids LIKE ?';
    params.push(`%${cwe}%`);
  }

  // Product filter
  if (product) {
    query += ' AND affected_products LIKE ?';
    params.push(`%${product}%`);
  }

  // Vendor filter (in affected_products JSON)
  if (vendor) {
    query += ' AND affected_products LIKE ?';
    params.push(`%${vendor}%`);
  }

  query += ' ORDER BY cvss_score DESC NULLS LAST, published_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));

  const result = await c.env.DB.prepare(query).bind(...params).all();

  return c.json({
    query: { q, cve_pattern, cwe, product, vendor },
    data: result.results,
    count: result.results?.length || 0,
    pagination: {
      limit: parseInt(limit),
      offset: parseInt(offset),
    },
  });
});

// GET /api/v1/vulnerabilities/kev - Get Known Exploited Vulnerabilities
vulnerabilities.get('/kev', async (c) => {
  const { limit = '100', offset = '0' } = c.req.query();

  const result = await c.env.DB.prepare(`
    SELECT * FROM vulnerabilities
    WHERE in_kev = 1
    ORDER BY cvss_score DESC NULLS LAST, published_at DESC
    LIMIT ? OFFSET ?
  `).bind(parseInt(limit), parseInt(offset)).all();

  const countResult = await c.env.DB.prepare(
    'SELECT COUNT(*) as total FROM vulnerabilities WHERE in_kev = 1'
  ).first<{ total: number }>();

  return c.json({
    data: result.results,
    pagination: {
      total: countResult?.total || 0,
      limit: parseInt(limit),
      offset: parseInt(offset),
    },
  });
});

// GET /api/v1/vulnerabilities/high-risk - Get high-risk vulnerabilities (high CVSS + high EPSS)
vulnerabilities.get('/high-risk', async (c) => {
  const {
    min_cvss = '7.0',
    min_epss = '0.1',
    limit = '50',
  } = c.req.query();

  const result = await c.env.DB.prepare(`
    SELECT * FROM vulnerabilities
    WHERE cvss_score >= ? AND epss_score >= ?
    ORDER BY
      CASE WHEN in_kev = 1 THEN 0 ELSE 1 END,
      epss_score DESC,
      cvss_score DESC
    LIMIT ?
  `).bind(parseFloat(min_cvss), parseFloat(min_epss), parseInt(limit)).all();

  return c.json({
    criteria: {
      min_cvss: parseFloat(min_cvss),
      min_epss: parseFloat(min_epss),
    },
    data: result.results,
    count: result.results?.length || 0,
  });
});

// GET /api/v1/vulnerabilities/:cve - Get CVE details
vulnerabilities.get('/:cve', async (c) => {
  const cve = c.req.param('cve').toUpperCase();

  // Validate CVE format
  if (!/^CVE-\d{4}-\d+$/.test(cve)) {
    return c.json({ error: 'Invalid CVE format. Expected format: CVE-YYYY-NNNNN' }, 400);
  }

  const vulnerability = await c.env.DB.prepare(`
    SELECT * FROM vulnerabilities WHERE cve_id = ?
  `).bind(cve).first<VulnerabilityRecord>();

  if (!vulnerability) {
    return c.json({ error: 'CVE not found', cve_id: cve }, 404);
  }

  // Get related findings
  const relatedFindings = await c.env.DB.prepare(`
    SELECT
      f.id,
      f.title,
      f.severity,
      f.state,
      a.hostname,
      a.ip_addresses
    FROM findings f
    LEFT JOIN assets a ON f.asset_id = a.id
    WHERE f.vulnerability_id = ?
    LIMIT 20
  `).bind(vulnerability.id).all();

  // Parse JSON fields
  let cweIds = [];
  let affectedProducts = [];
  let references = [];

  try {
    if (vulnerability.cwe_ids) cweIds = JSON.parse(vulnerability.cwe_ids);
    if (vulnerability.affected_products) affectedProducts = JSON.parse(vulnerability.affected_products);
    if (vulnerability.references) references = JSON.parse(vulnerability.references);
  } catch {
    // Keep as strings if parsing fails
  }

  return c.json({
    ...vulnerability,
    cwe_ids: cweIds,
    affected_products: affectedProducts,
    references: references,
    related_findings: relatedFindings.results,
    related_findings_count: relatedFindings.results?.length || 0,
  });
});

// POST /api/v1/vulnerabilities - Create/update vulnerability
vulnerabilities.post('/', async (c) => {
  const body = await c.req.json();

  if (!body.cve_id) {
    return c.json({ error: 'cve_id is required' }, 400);
  }

  // Validate CVE format
  if (!/^CVE-\d{4}-\d+$/i.test(body.cve_id)) {
    return c.json({ error: 'Invalid CVE format. Expected format: CVE-YYYY-NNNNN' }, 400);
  }

  const cveId = body.cve_id.toUpperCase();

  // Check if CVE exists
  const existing = await c.env.DB.prepare(
    'SELECT id FROM vulnerabilities WHERE cve_id = ?'
  ).bind(cveId).first<{ id: string }>();

  if (existing) {
    // Update existing
    await c.env.DB.prepare(`
      UPDATE vulnerabilities SET
        description = COALESCE(?, description),
        cvss_score = COALESCE(?, cvss_score),
        cvss_vector = COALESCE(?, cvss_vector),
        epss_score = COALESCE(?, epss_score),
        in_kev = COALESCE(?, in_kev),
        cwe_ids = COALESCE(?, cwe_ids),
        affected_products = COALESCE(?, affected_products),
        references = COALESCE(?, references),
        modified_at = COALESCE(?, modified_at),
        updated_at = datetime('now')
      WHERE cve_id = ?
    `).bind(
      body.description,
      body.cvss_score,
      body.cvss_vector,
      body.epss_score,
      body.in_kev ? 1 : 0,
      body.cwe_ids ? JSON.stringify(body.cwe_ids) : null,
      body.affected_products ? JSON.stringify(body.affected_products) : null,
      body.references ? JSON.stringify(body.references) : null,
      body.modified_at,
      cveId,
    ).run();

    return c.json({ id: existing.id, cve_id: cveId, message: 'Vulnerability updated' });
  }

  // Create new
  const id = crypto.randomUUID();

  await c.env.DB.prepare(`
    INSERT INTO vulnerabilities (
      id, cve_id, description, cvss_score, cvss_vector, epss_score,
      in_kev, published_at, modified_at, cwe_ids, affected_products, references
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    cveId,
    body.description || null,
    body.cvss_score || null,
    body.cvss_vector || null,
    body.epss_score || null,
    body.in_kev ? 1 : 0,
    body.published_at || null,
    body.modified_at || null,
    body.cwe_ids ? JSON.stringify(body.cwe_ids) : null,
    body.affected_products ? JSON.stringify(body.affected_products) : null,
    body.references ? JSON.stringify(body.references) : null,
  ).run();

  return c.json({ id, cve_id: cveId, message: 'Vulnerability created' }, 201);
});

// POST /api/v1/vulnerabilities/sync - Trigger NVD sync (placeholder)
vulnerabilities.post('/sync', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const syncId = crypto.randomUUID();

  const syncConfig = {
    sync_id: syncId,
    sync_type: body.sync_type || 'incremental', // 'full' or 'incremental'
    date_from: body.date_from || null,
    date_to: body.date_to || null,
    cve_pattern: body.cve_pattern || null,
    include_kev: body.include_kev !== false,
    include_epss: body.include_epss !== false,
  };

  // Store sync job in database/KV
  const syncJob: NVDSyncResult = {
    sync_id: syncId,
    status: 'pending',
    started_at: new Date().toISOString(),
  };

  try {
    await c.env.DB.prepare(`
      INSERT INTO nvd_sync_jobs (id, config, status, started_at)
      VALUES (?, ?, 'pending', datetime('now'))
    `).bind(syncId, JSON.stringify(syncConfig)).run();
  } catch {
    // Table might not exist, store in KV
    await c.env.CACHE.put(
      `nvd_sync:${syncId}`,
      JSON.stringify({ ...syncJob, config: syncConfig }),
      { expirationTtl: 86400 } // 24 hours
    );
  }

  // In a real implementation, this would trigger a background job
  // For now, return a placeholder response

  return c.json({
    message: 'NVD sync job queued',
    sync_id: syncId,
    config: syncConfig,
    status: 'pending',
    note: 'This is a placeholder. Implement actual NVD API integration for production.',
    documentation: {
      nvd_api: 'https://nvd.nist.gov/developers/vulnerabilities',
      kev_feed: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      epss_api: 'https://api.first.org/data/v1/epss',
    },
  }, 202);
});

// GET /api/v1/vulnerabilities/sync/:id - Get sync job status
vulnerabilities.get('/sync/:id', async (c) => {
  const id = c.req.param('id');

  try {
    const job = await c.env.DB.prepare(
      'SELECT * FROM nvd_sync_jobs WHERE id = ?'
    ).bind(id).first();

    if (job) {
      return c.json(job);
    }
  } catch {
    // Try KV fallback
    const cached = await c.env.CACHE.get(`nvd_sync:${id}`);
    if (cached) {
      return c.json(JSON.parse(cached));
    }
  }

  return c.json({ error: 'Sync job not found' }, 404);
});

// POST /api/v1/vulnerabilities/bulk - Bulk import vulnerabilities
vulnerabilities.post('/bulk', async (c) => {
  const body = await c.req.json<{ vulnerabilities: any[] }>();

  if (!Array.isArray(body.vulnerabilities) || body.vulnerabilities.length === 0) {
    return c.json({ error: 'vulnerabilities array is required' }, 400);
  }

  if (body.vulnerabilities.length > 1000) {
    return c.json({ error: 'Maximum 1000 vulnerabilities per request' }, 400);
  }

  let added = 0;
  let updated = 0;
  let errors = 0;

  for (const vuln of body.vulnerabilities) {
    if (!vuln.cve_id || !/^CVE-\d{4}-\d+$/i.test(vuln.cve_id)) {
      errors++;
      continue;
    }

    const cveId = vuln.cve_id.toUpperCase();

    try {
      const existing = await c.env.DB.prepare(
        'SELECT id FROM vulnerabilities WHERE cve_id = ?'
      ).bind(cveId).first();

      if (existing) {
        await c.env.DB.prepare(`
          UPDATE vulnerabilities SET
            description = COALESCE(?, description),
            cvss_score = COALESCE(?, cvss_score),
            cvss_vector = COALESCE(?, cvss_vector),
            epss_score = COALESCE(?, epss_score),
            in_kev = COALESCE(?, in_kev),
            updated_at = datetime('now')
          WHERE cve_id = ?
        `).bind(
          vuln.description,
          vuln.cvss_score,
          vuln.cvss_vector,
          vuln.epss_score,
          vuln.in_kev ? 1 : 0,
          cveId,
        ).run();
        updated++;
      } else {
        const id = crypto.randomUUID();
        await c.env.DB.prepare(`
          INSERT INTO vulnerabilities (
            id, cve_id, description, cvss_score, cvss_vector, epss_score, in_kev, published_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          id,
          cveId,
          vuln.description || null,
          vuln.cvss_score || null,
          vuln.cvss_vector || null,
          vuln.epss_score || null,
          vuln.in_kev ? 1 : 0,
          vuln.published_at || null,
        ).run();
        added++;
      }
    } catch (error) {
      console.error(`Error processing ${cveId}:`, error);
      errors++;
    }
  }

  return c.json({
    message: 'Bulk import completed',
    results: {
      total: body.vulnerabilities.length,
      added,
      updated,
      errors,
    },
  });
});

// DELETE /api/v1/vulnerabilities/:cve - Delete vulnerability
vulnerabilities.delete('/:cve', async (c) => {
  const cve = c.req.param('cve').toUpperCase();

  if (!/^CVE-\d{4}-\d+$/.test(cve)) {
    return c.json({ error: 'Invalid CVE format' }, 400);
  }

  const result = await c.env.DB.prepare(
    'DELETE FROM vulnerabilities WHERE cve_id = ?'
  ).bind(cve).run();

  if (result.meta.changes === 0) {
    return c.json({ error: 'CVE not found' }, 404);
  }

  return c.json({ message: 'Vulnerability deleted', cve_id: cve });
});
