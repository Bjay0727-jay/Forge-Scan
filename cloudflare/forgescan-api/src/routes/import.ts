import { Hono } from 'hono';
import type { Env } from '../index';
import { badRequest, databaseError } from '../lib/errors';
import {
  parseCSV,
  parseFindingsCSV,
  parseAssetsCSV,
  normalizeSeverity,
} from '../lib/csv-parser';

export const importRoutes = new Hono<{ Bindings: Env }>();

// ─── Import findings (JSON, CSV, SARIF, CycloneDX) ─────────────────────────

importRoutes.post('/', async (c) => {
  try {
    const body = await c.req.json();
    const { format, data } = body;

    if (!format || !data) {
      throw badRequest('Missing format or data');
    }

    let findings: any[] = [];
    const errors: string[] = [];

    if (format === 'csv') {
      const result = parseFindingsCSV(typeof data === 'string' ? data : '');
      findings = result.rows;
      errors.push(...result.errors);
    } else if (format === 'json') {
      findings = Array.isArray(data) ? data : [data];
    } else if (format === 'sarif') {
      // Parse SARIF format
      const sarif = typeof data === 'string' ? JSON.parse(data) : data;
      for (const run of sarif.runs || []) {
        for (const result of run.results || []) {
          findings.push({
            title: result.message?.text || result.ruleId || 'Unknown',
            description: result.message?.markdown || result.message?.text,
            severity: mapSarifLevel(result.level),
            affected_component: result.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
            cve_id: result.ruleId?.startsWith('CVE-') ? result.ruleId : null,
          });
        }
      }
    } else if (format === 'cyclonedx') {
      // Parse CycloneDX SBOM with vulnerabilities
      const bom = typeof data === 'string' ? JSON.parse(data) : data;
      for (const vuln of bom.vulnerabilities || []) {
        findings.push({
          title: vuln.id || 'Unknown Vulnerability',
          description: vuln.description,
          severity: mapCycloneDXSeverity(vuln.ratings?.[0]?.severity),
          cve_id: vuln.id?.startsWith('CVE-') ? vuln.id : null,
          cvss_score: vuln.ratings?.[0]?.score,
          affected_component: vuln.affects?.[0]?.ref,
        });
      }
    } else {
      throw badRequest(`Unsupported format: ${format}`);
    }

    let imported = 0;
    let failed = 0;

    for (const finding of findings) {
      try {
        const id = crypto.randomUUID();
        await c.env.DB.prepare(`
          INSERT INTO findings (
            id, title, description, severity, state, cve_id, cvss_score,
            affected_component, remediation, vendor, first_seen, last_seen,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, 'import', datetime('now'), datetime('now'),
            datetime('now'), datetime('now'))
        `).bind(
          id,
          finding.title || 'Unknown Finding',
          finding.description || null,
          normalizeSeverity(finding.severity),
          finding.cve_id || null,
          finding.cvss_score || null,
          finding.affected_component || null,
          finding.remediation || null
        ).run();
        imported++;
      } catch (err: any) {
        failed++;
        errors.push(`Row ${imported + failed}: ${err.message}`);
      }
    }

    return c.json({
      success: failed === 0,
      imported_count: imported,
      failed_count: failed,
      errors: errors.slice(0, 10),
    });

  } catch (err: any) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    return c.json({
      success: false,
      imported_count: 0,
      failed_count: 0,
      errors: [err.message],
    }, 500);
  }
});

// ─── Import findings via file upload ────────────────────────────────────────

importRoutes.post('/upload', async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get('file') as unknown as File;
    const format = (formData.get('format') as string) || '';

    if (!file) {
      throw badRequest('No file provided');
    }

    const content = await file.text();

    // Detect format from file extension if not specified
    let detectedFormat = format;
    if (!detectedFormat) {
      if (file.name?.endsWith('.csv')) detectedFormat = 'csv';
      else if (file.name?.endsWith('.json')) detectedFormat = 'json';
      else if (file.name?.endsWith('.sarif')) detectedFormat = 'sarif';
    }

    if (!detectedFormat) {
      throw badRequest('Could not detect file format. Please specify the format parameter.');
    }

    // Reuse the main import logic by constructing an internal request
    const response = await importRoutes.request(
      new Request('http://localhost/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: detectedFormat, data: content }),
      }),
      c.env as unknown as RequestInit
    );

    return response;

  } catch (err: any) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    return c.json({
      success: false,
      imported_count: 0,
      failed_count: 0,
      errors: [err.message],
    }, 500);
  }
});

// ─── Import assets (CSV, JSON) ──────────────────────────────────────────────

importRoutes.post('/assets', async (c) => {
  try {
    const body = await c.req.json();
    const { format, data } = body;

    if (!format || !data) {
      throw badRequest('Missing format or data');
    }

    let assets: any[] = [];
    const errors: string[] = [];

    if (format === 'csv') {
      const result = parseAssetsCSV(typeof data === 'string' ? data : '');
      assets = result.rows;
      errors.push(...result.errors);
    } else if (format === 'json') {
      assets = Array.isArray(data) ? data : [data];
    } else {
      throw badRequest(`Unsupported format: ${format}`);
    }

    let imported = 0;
    let failed = 0;

    for (const asset of assets) {
      try {
        const id = crypto.randomUUID();
        const ipAddresses = asset.ip_address
          ? (Array.isArray(asset.ip_address) ? asset.ip_address : [asset.ip_address])
          : [];
        const tags = asset.tags || [];

        await c.env.DB.prepare(`
          INSERT INTO assets (
            id, hostname, fqdn, ip_addresses, os, os_version,
            asset_type, network_zone, tags, attributes,
            first_seen, last_seen, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'),
            datetime('now'), datetime('now'))
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
          })
        ).run();
        imported++;
      } catch (err: any) {
        failed++;
        if (err.message?.includes('UNIQUE constraint')) {
          errors.push(`Row ${imported + failed}: Duplicate asset (hostname or IP already exists)`);
        } else {
          errors.push(`Row ${imported + failed}: ${err.message}`);
        }
      }
    }

    return c.json({
      success: failed === 0,
      imported_count: imported,
      failed_count: failed,
      errors: errors.slice(0, 10),
    });

  } catch (err: any) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    return c.json({
      success: false,
      imported_count: 0,
      failed_count: 0,
      errors: [err.message],
    }, 500);
  }
});

// ─── Import assets via file upload ──────────────────────────────────────────

importRoutes.post('/assets/upload', async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get('file') as unknown as File;
    const format = formData.get('format') as string;

    if (!file) {
      throw badRequest('No file provided');
    }

    // Excel files not supported in edge runtime
    if (format === 'xlsx' || file.name?.endsWith('.xlsx') || file.name?.endsWith('.xls')) {
      throw badRequest('Excel file support requires conversion to CSV first. Please export your Excel file as CSV and try again.');
    }

    const content = await file.text();

    // Determine format from file extension if not specified
    let detectedFormat = format;
    if (!detectedFormat) {
      if (file.name?.endsWith('.csv')) detectedFormat = 'csv';
      else if (file.name?.endsWith('.json')) detectedFormat = 'json';
    }

    if (!detectedFormat) {
      throw badRequest('Could not detect file format. Please specify the format parameter.');
    }

    let assets: any[] = [];
    const errors: string[] = [];

    if (detectedFormat === 'csv') {
      const result = parseAssetsCSV(content);
      assets = result.rows;
      errors.push(...result.errors);
    } else if (detectedFormat === 'json') {
      const parsed = JSON.parse(content);
      assets = Array.isArray(parsed) ? parsed : [parsed];
    } else {
      throw badRequest(`Unsupported format: ${detectedFormat}`);
    }

    let imported = 0;
    let failed = 0;

    for (const asset of assets) {
      try {
        const id = crypto.randomUUID();
        const ipAddresses = asset.ip_address
          ? (Array.isArray(asset.ip_address) ? asset.ip_address : [asset.ip_address])
          : [];
        const tags = asset.tags || [];

        await c.env.DB.prepare(`
          INSERT INTO assets (
            id, hostname, fqdn, ip_addresses, os, os_version,
            asset_type, network_zone, tags, attributes,
            first_seen, last_seen, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'),
            datetime('now'), datetime('now'))
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
          })
        ).run();
        imported++;
      } catch (err: any) {
        failed++;
        if (err.message?.includes('UNIQUE constraint')) {
          errors.push(`Row ${imported + failed}: Duplicate asset`);
        } else {
          errors.push(`Row ${imported + failed}: ${err.message}`);
        }
      }
    }

    return c.json({
      success: failed === 0,
      imported_count: imported,
      failed_count: failed,
      errors: errors.slice(0, 10),
    });

  } catch (err: any) {
    if (err instanceof Error && err.name === 'ApiError') throw err;
    return c.json({
      success: false,
      imported_count: 0,
      failed_count: 0,
      errors: [err.message],
    }, 500);
  }
});

// ─── Helper functions ───────────────────────────────────────────────────────

function mapSarifLevel(level: string | undefined): string {
  switch (level) {
    case 'error': return 'high';
    case 'warning': return 'medium';
    case 'note': return 'low';
    default: return 'info';
  }
}

function mapCycloneDXSeverity(severity: string | undefined): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'info';
  }
}
