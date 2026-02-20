// NVD Sync Service - Chunked processing for Cloudflare Workers
// Each invocation processes one page of CVEs (~2000), then yields
// Cron Trigger picks up the next page every 5 minutes

import { NVDClient, transformNVDtoCVE, type VulnerabilityRecord } from '../lib/nvd-client';

const PAGE_SIZE = 200; // Reduced from 2000 to stay within Workers subrequest limits (each CVE = 2 DB queries)

interface SyncJob {
  id: string;
  sync_type: string;
  source: string;
  config: string;
  status: string;
  cursor: number;
  total_results: number;
  records_processed: number;
  records_added: number;
  records_updated: number;
  current_page: number;
  total_pages: number;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
}

interface SyncState {
  last_full_sync_at: string | null;
  last_incremental_sync_at: string | null;
  last_modified_date: string | null;
  total_cves_synced: number;
  last_kev_sync_at: string | null;
  last_epss_sync_at: string | null;
  kev_total: number;
  epss_total: number;
}

// --- Start a full NVD sync ---
export async function startFullSync(
  db: D1Database,
  apiKey?: string
): Promise<string> {
  const client = new NVDClient(apiKey);
  const jobId = crypto.randomUUID();

  // Query NVD for total count first (1 result to get totalResults)
  const probe = await client.fetchCVEs({ resultsPerPage: 1 });
  const totalResults = probe.totalResults;
  const totalPages = Math.ceil(totalResults / PAGE_SIZE);

  await db.prepare(`
    INSERT INTO nvd_sync_jobs (id, sync_type, source, status, cursor, total_results, total_pages, started_at)
    VALUES (?, 'full', 'nvd', 'running', 0, ?, ?, datetime('now'))
  `).bind(jobId, totalResults, totalPages).run();

  // Don't process first page inline — let frontend polling via /sync/process-next handle it
  // This avoids hitting Cloudflare Workers subrequest/CPU limits

  return jobId;
}

// --- Start an incremental sync ---
export async function startIncrementalSync(
  db: D1Database,
  apiKey?: string
): Promise<string> {
  const state = await db.prepare(
    "SELECT * FROM nvd_sync_state WHERE id = 'current'"
  ).first<SyncState>();

  const jobId = crypto.randomUUID();

  // Use last modified date or default to 120 days ago
  const lastModDate = state?.last_modified_date ||
    new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString();

  const now = new Date().toISOString();

  const config = JSON.stringify({
    lastModStartDate: lastModDate,
    lastModEndDate: now,
  });

  const client = new NVDClient(apiKey);
  const probe = await client.fetchCVEs({
    lastModStartDate: lastModDate,
    lastModEndDate: now,
    resultsPerPage: 1,
  });

  const totalResults = probe.totalResults;
  const totalPages = Math.ceil(totalResults / PAGE_SIZE);

  await db.prepare(`
    INSERT INTO nvd_sync_jobs (id, sync_type, source, config, status, cursor, total_results, total_pages, started_at)
    VALUES (?, 'incremental', 'nvd', ?, 'running', 0, ?, ?, datetime('now'))
  `).bind(jobId, config, totalResults, totalPages).run();

  if (totalResults === 0) {
    // Nothing to sync - mark complete
    await db.prepare(`
      UPDATE nvd_sync_jobs SET status = 'completed', completed_at = datetime('now') WHERE id = ?
    `).bind(jobId).run();

    await db.prepare(`
      UPDATE nvd_sync_state SET last_incremental_sync_at = datetime('now'), last_modified_date = ?, updated_at = datetime('now')
      WHERE id = 'current'
    `).bind(now).run();
  }

  return jobId;
}

// --- Process next page of a running sync job ---
export async function processNextPage(
  db: D1Database,
  apiKey?: string
): Promise<boolean> {
  // Find a running sync job
  const job = await db.prepare(
    "SELECT * FROM nvd_sync_jobs WHERE status = 'running' ORDER BY created_at ASC LIMIT 1"
  ).first<SyncJob>();

  if (!job) return false;

  try {
    const client = new NVDClient(apiKey);

    // Build fetch params
    const config = job.config ? JSON.parse(job.config) : {};
    const params: Record<string, unknown> = {
      startIndex: job.cursor,
      resultsPerPage: PAGE_SIZE,
    };

    if (config.lastModStartDate) params.lastModStartDate = config.lastModStartDate;
    if (config.lastModEndDate) params.lastModEndDate = config.lastModEndDate;

    // Fetch page from NVD
    const response = await client.fetchCVEs(params as any);

    // Transform and upsert CVEs
    let added = 0;
    let updated = 0;

    for (const nvdItem of response.vulnerabilities) {
      const record = transformNVDtoCVE(nvdItem);
      const result = await upsertVulnerability(db, record);
      if (result === 'added') added++;
      else if (result === 'updated') updated++;
    }

    const newCursor = job.cursor + response.vulnerabilities.length;
    const newPage = job.current_page + 1;
    const isComplete = newCursor >= job.total_results;

    if (isComplete) {
      // Sync complete
      await db.prepare(`
        UPDATE nvd_sync_jobs SET
          status = 'completed',
          cursor = ?,
          current_page = ?,
          records_processed = records_processed + ?,
          records_added = records_added + ?,
          records_updated = records_updated + ?,
          completed_at = datetime('now')
        WHERE id = ?
      `).bind(
        newCursor, newPage, response.vulnerabilities.length, added, updated, job.id
      ).run();

      // Update sync state
      const syncType = job.sync_type === 'full' ? 'last_full_sync_at' : 'last_incremental_sync_at';
      await db.prepare(`
        UPDATE nvd_sync_state SET
          ${syncType} = datetime('now'),
          last_modified_date = datetime('now'),
          total_cves_synced = (SELECT COUNT(*) FROM vulnerabilities),
          updated_at = datetime('now')
        WHERE id = 'current'
      `).run();

      return false; // No more pages
    } else {
      // More pages to process
      await db.prepare(`
        UPDATE nvd_sync_jobs SET
          cursor = ?,
          current_page = ?,
          records_processed = records_processed + ?,
          records_added = records_added + ?,
          records_updated = records_updated + ?
        WHERE id = ?
      `).bind(
        newCursor, newPage, response.vulnerabilities.length, added, updated, job.id
      ).run();

      return true; // More pages remain
    }
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : 'Unknown error';
    await db.prepare(`
      UPDATE nvd_sync_jobs SET status = 'failed', error_message = ?, completed_at = datetime('now')
      WHERE id = ?
    `).bind(errorMsg, job.id).run();
    return false;
  }
}

// --- CISA KEV Sync ---
export async function syncKEV(db: D1Database): Promise<{ updated: number; total: number }> {
  const client = new NVDClient();
  const catalog = await client.fetchKEV();

  let updated = 0;
  for (const entry of catalog.vulnerabilities) {
    const result = await db.prepare(`
      UPDATE vulnerabilities SET
        in_kev = 1,
        kev_date_added = ?,
        kev_due_date = ?,
        updated_at = datetime('now')
      WHERE cve_id = ?
    `).bind(entry.dateAdded, entry.dueDate, entry.cveID).run();

    if (result.meta.changes && result.meta.changes > 0) updated++;
  }

  // Also insert KEV entries that don't exist in our DB yet (as stubs)
  for (const entry of catalog.vulnerabilities) {
    const exists = await db.prepare(
      'SELECT id FROM vulnerabilities WHERE cve_id = ?'
    ).bind(entry.cveID).first();

    if (!exists) {
      const kevTitle = `${entry.cveID}: ${entry.vulnerabilityName}`;
      const kevDesc = `${entry.vulnerabilityName} - ${entry.requiredAction}`;
      await db.prepare(`
        INSERT INTO vulnerabilities (id, cve_id, title, description, in_kev, kev_date_added, kev_due_date, severity)
        VALUES (?, ?, ?, ?, 1, ?, ?, 'high')
      `).bind(
        crypto.randomUUID(),
        entry.cveID,
        kevTitle,
        kevDesc,
        entry.dateAdded,
        entry.dueDate
      ).run();
    }
  }

  await db.prepare(`
    UPDATE nvd_sync_state SET
      last_kev_sync_at = datetime('now'),
      kev_total = ?,
      updated_at = datetime('now')
    WHERE id = 'current'
  `).bind(catalog.count).run();

  return { updated, total: catalog.count };
}

// --- EPSS Sync ---
export async function syncEPSS(
  db: D1Database,
  cveIds?: string[]
): Promise<{ updated: number }> {
  const client = new NVDClient();
  let updated = 0;

  if (cveIds && cveIds.length > 0) {
    // Batch process in chunks of 100
    for (let i = 0; i < cveIds.length; i += 100) {
      const batch = cveIds.slice(i, i + 100);
      const response = await client.fetchEPSS(batch);

      for (const entry of response.data) {
        const result = await db.prepare(`
          UPDATE vulnerabilities SET
            epss_score = ?,
            epss_percentile = ?,
            updated_at = datetime('now')
          WHERE cve_id = ?
        `).bind(parseFloat(entry.epss), parseFloat(entry.percentile), entry.cve).run();

        if (result.meta.changes && result.meta.changes > 0) updated++;
      }
    }
  } else {
    // Fetch CVEs from our DB that lack EPSS scores (batch of 100)
    const missing = await db.prepare(
      'SELECT cve_id FROM vulnerabilities WHERE epss_score IS NULL LIMIT 100'
    ).all<{ cve_id: string }>();

    if (missing.results && missing.results.length > 0) {
      const ids = missing.results.map(r => r.cve_id);
      const response = await client.fetchEPSS(ids);

      for (const entry of response.data) {
        const result = await db.prepare(`
          UPDATE vulnerabilities SET
            epss_score = ?,
            epss_percentile = ?,
            updated_at = datetime('now')
          WHERE cve_id = ?
        `).bind(parseFloat(entry.epss), parseFloat(entry.percentile), entry.cve).run();

        if (result.meta.changes && result.meta.changes > 0) updated++;
      }
    }
  }

  await db.prepare(`
    UPDATE nvd_sync_state SET
      last_epss_sync_at = datetime('now'),
      epss_total = (SELECT COUNT(*) FROM vulnerabilities WHERE epss_score IS NOT NULL),
      updated_at = datetime('now')
    WHERE id = 'current'
  `).run();

  return { updated };
}

// --- Get sync status ---
export async function getSyncStatus(db: D1Database): Promise<{
  state: SyncState | null;
  activeJob: SyncJob | null;
  recentJobs: SyncJob[];
}> {
  const state = await db.prepare(
    "SELECT * FROM nvd_sync_state WHERE id = 'current'"
  ).first<SyncState>();

  const activeJob = await db.prepare(
    "SELECT * FROM nvd_sync_jobs WHERE status = 'running' ORDER BY created_at DESC LIMIT 1"
  ).first<SyncJob>();

  const recentJobs = await db.prepare(
    'SELECT * FROM nvd_sync_jobs ORDER BY created_at DESC LIMIT 10'
  ).all<SyncJob>();

  return {
    state,
    activeJob,
    recentJobs: recentJobs.results || [],
  };
}

// --- Helper: Upsert vulnerability ---
async function upsertVulnerability(
  db: D1Database,
  record: VulnerabilityRecord
): Promise<'added' | 'updated' | 'skipped'> {
  const existing = await db.prepare(
    'SELECT id, modified_at FROM vulnerabilities WHERE cve_id = ?'
  ).bind(record.cve_id).first<{ id: string; modified_at: string }>();

  if (existing) {
    // Update if modified date is newer
    if (record.modified_at > (existing.modified_at || '')) {
      await db.prepare(`
        UPDATE vulnerabilities SET
          description = ?,
          cvss_score = ?,
          cvss_vector = ?,
          cvss_version = ?,
          severity = ?,
          cwe_ids = ?,
          affected_products = ?,
          references_list = ?,
          published_at = ?,
          modified_at = ?,
          updated_at = datetime('now')
        WHERE id = ?
      `).bind(
        record.description,
        record.cvss_score,
        record.cvss_vector,
        record.cvss_version,
        record.severity,
        JSON.stringify(record.cwe_ids),
        JSON.stringify(record.affected_products),
        JSON.stringify(record.references_list),
        record.published_at,
        record.modified_at,
        existing.id
      ).run();
      return 'updated';
    }
    return 'skipped';
  } else {
    // Generate title from CVE ID + first 120 chars of description
    const title = record.description
      ? `${record.cve_id}: ${record.description.substring(0, 120)}${record.description.length > 120 ? '...' : ''}`
      : record.cve_id;

    await db.prepare(`
      INSERT INTO vulnerabilities (id, cve_id, title, description, cvss_score, cvss_vector, cvss_version, severity, cwe_ids, affected_products, references_list, published_at, modified_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      record.cve_id,
      title,
      record.description,
      record.cvss_score,
      record.cvss_vector,
      record.cvss_version,
      record.severity,
      JSON.stringify(record.cwe_ids),
      JSON.stringify(record.affected_products),
      JSON.stringify(record.references_list),
      record.published_at,
      record.modified_at
    ).run();
    return 'added';
  }
}
