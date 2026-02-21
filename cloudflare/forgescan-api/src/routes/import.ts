import { Hono } from 'hono';
import type { Env } from '../index';

export const importRoutes = new Hono<{ Bindings: Env }>();

// Helper function to parse CSV
function parseCSV(csvText: string): Record<string, string>[] {
  const lines = csvText.trim().split('\n');
  if (lines.length < 2) return [];

  // Parse header row
  const headers = parseCSVLine(lines[0]);
  const results: Record<string, string>[] = [];

  // Parse data rows
  for (let i = 1; i < lines.length; i++) {
    const values = parseCSVLine(lines[i]);
    const row: Record<string, string> = {};

    headers.forEach((header, index) => {
      row[header.trim().toLowerCase().replace(/\s+/g, '_')] = values[index] || '';
    });

    results.push(row);
  }

  return results;
}

// Parse a single CSV line (handles quoted values)
function parseCSVLine(line: string): string[] {
  const values: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      values.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }

  values.push(current.trim());
  return values;
}

// Import findings (supports JSON, CSV, SARIF)
importRoutes.post('/', async (c) => {
  try {
    const body = await c.req.json();
    const { format, data } = body;

    if (!format || !data) {
      return c.json({ error: 'Missing format or data' }, 400);
    }

    let findings: any[] = [];
    const errors: string[] = [];

    if (format === 'csv') {
      const parsed = parseCSV(typeof data === 'string' ? data : '');
      findings = parsed;
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
      return c.json({ error: `Unsupported format: ${format}` }, 400);
    }

    let imported = 0;
    let failed = 0;

    for (const finding of findings) {
      try {
        const id = crypto.randomUUID();
        await c.env.DB.prepare(`
          INSERT INTO findings (
            id, title, description, severity, state, cve_id, cvss_score,
            affected_component, remediation, vendor, first_seen, last_seen
          ) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, 'import', datetime('now'), datetime('now'))
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
    return c.json({
      success: false,
      imported_count: 0,
      failed_count: 0,
      errors: [err.message],
    }, 500);
  }
});

// Import findings via file upload
importRoutes.post('/upload', async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get('file') as unknown as File;
    const format = formData.get('format') as string;

    if (!file) {
      return c.json({ error: 'No file provided' }, 400);
    }

    const content = await file.text();

    // Reuse the main import logic
    const response = await importRoutes.request(
      new Request('http://localhost/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format, data: content }),
      }),
      c.env as unknown as RequestInit
    );

    return response;

  } catch (err: any) {
    return c.json({
      success: false,
      imported_count: 0,
      failed_count: 0,
      errors: [err.message],
    }, 500);
  }
});

// Import assets (CSV, JSON, XLSX)
importRoutes.post('/assets', async (c) => {
  try {
    const body = await c.req.json();
    const { format, data } = body;

    if (!format || !data) {
      return c.json({ error: 'Missing format or data' }, 400);
    }

    let assets: any[] = [];
    const errors: string[] = [];

    if (format === 'csv') {
      const parsed = parseCSV(typeof data === 'string' ? data : '');
      assets = parsed;
    } else if (format === 'json') {
      assets = Array.isArray(data) ? data : [data];
    } else {
      return c.json({ error: `Unsupported format: ${format}` }, 400);
    }

    let imported = 0;
    let failed = 0;

    for (const asset of assets) {
      try {
        // Handle various column name formats
        const hostname = asset.hostname || asset.host_name || asset.name || asset.server_name;
        const ipAddress = asset.ip_address || asset.ip || asset.ip_addresses;

        if (!hostname && !ipAddress) {
          failed++;
          errors.push(`Row ${imported + failed}: Missing hostname or ip_address`);
          continue;
        }

        const id = crypto.randomUUID();
        const ipAddresses = Array.isArray(ipAddress) ? ipAddress : (ipAddress ? [ipAddress] : []);
        const tags = asset.tags ? (Array.isArray(asset.tags) ? asset.tags : asset.tags.split(',').map((t: string) => t.trim())) : [];

        await c.env.DB.prepare(`
          INSERT INTO assets (
            id, hostname, fqdn, ip_addresses, os, os_version,
            asset_type, network_zone, tags, attributes, first_seen, last_seen
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).bind(
          id,
          hostname || null,
          asset.fqdn || asset.fully_qualified_domain_name || null,
          JSON.stringify(ipAddresses),
          asset.os || asset.operating_system || null,
          asset.os_version || null,
          asset.asset_type || asset.type || 'host',
          asset.network_zone || asset.environment || null,
          JSON.stringify(tags),
          JSON.stringify({
            owner: asset.owner,
            department: asset.department,
            location: asset.location,
            mac_addresses: asset.mac_address || asset.mac_addresses,
          })
        ).run();
        imported++;
      } catch (err: any) {
        failed++;
        if (err.message.includes('UNIQUE constraint')) {
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
    return c.json({
      success: false,
      imported_count: 0,
      failed_count: 0,
      errors: [err.message],
    }, 500);
  }
});

// Import assets via file upload
importRoutes.post('/assets/upload', async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get('file') as unknown as File;
    const format = formData.get('format') as string;

    if (!file) {
      return c.json({ error: 'No file provided' }, 400);
    }

    // For XLSX files, we'd need a library - return error for now
    if (format === 'xlsx' || file.name.endsWith('.xlsx') || file.name.endsWith('.xls')) {
      return c.json({
        success: false,
        imported_count: 0,
        failed_count: 0,
        errors: ['Excel file support requires conversion to CSV first. Please export your Excel file as CSV and try again.'],
      }, 400);
    }

    const content = await file.text();

    // Determine format from file extension if not specified
    let detectedFormat = format;
    if (!detectedFormat) {
      if (file.name.endsWith('.csv')) {
        detectedFormat = 'csv';
      } else if (file.name.endsWith('.json')) {
        detectedFormat = 'json';
      }
    }

    // Parse and import
    let assets: any[] = [];
    const errors: string[] = [];

    if (detectedFormat === 'csv') {
      assets = parseCSV(content);
    } else if (detectedFormat === 'json') {
      const parsed = JSON.parse(content);
      assets = Array.isArray(parsed) ? parsed : [parsed];
    } else {
      return c.json({ error: `Unsupported format: ${detectedFormat}` }, 400);
    }

    let imported = 0;
    let failed = 0;

    for (const asset of assets) {
      try {
        const hostname = asset.hostname || asset.host_name || asset.name || asset.server_name;
        const ipAddress = asset.ip_address || asset.ip || asset.ip_addresses;

        if (!hostname && !ipAddress) {
          failed++;
          errors.push(`Row ${imported + failed}: Missing hostname or ip_address`);
          continue;
        }

        const id = crypto.randomUUID();
        const ipAddresses = Array.isArray(ipAddress) ? ipAddress : (ipAddress ? [ipAddress] : []);
        const tags = asset.tags ? (Array.isArray(asset.tags) ? asset.tags : asset.tags.split(',').map((t: string) => t.trim())) : [];

        await c.env.DB.prepare(`
          INSERT INTO assets (
            id, hostname, fqdn, ip_addresses, os, os_version,
            asset_type, network_zone, tags, attributes, first_seen, last_seen
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).bind(
          id,
          hostname || null,
          asset.fqdn || asset.fully_qualified_domain_name || null,
          JSON.stringify(ipAddresses),
          asset.os || asset.operating_system || null,
          asset.os_version || null,
          asset.asset_type || asset.type || 'host',
          asset.network_zone || asset.environment || null,
          JSON.stringify(tags),
          JSON.stringify({
            owner: asset.owner,
            department: asset.department,
            location: asset.location,
            mac_addresses: asset.mac_address || asset.mac_addresses,
          })
        ).run();
        imported++;
      } catch (err: any) {
        failed++;
        if (err.message.includes('UNIQUE constraint')) {
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
    return c.json({
      success: false,
      imported_count: 0,
      failed_count: 0,
      errors: [err.message],
    }, 500);
  }
});

// Helper functions
function normalizeSeverity(severity: string | number | undefined): string {
  if (typeof severity === 'number') {
    if (severity >= 9.0) return 'critical';
    if (severity >= 7.0) return 'high';
    if (severity >= 4.0) return 'medium';
    if (severity >= 0.1) return 'low';
    return 'info';
  }

  const sevLower = (severity || '').toLowerCase();
  if (['critical', 'urgent', 'crit'].includes(sevLower)) return 'critical';
  if (['high', 'serious', 'important'].includes(sevLower)) return 'high';
  if (['medium', 'moderate', 'med'].includes(sevLower)) return 'medium';
  if (['low', 'minimal'].includes(sevLower)) return 'low';
  return 'info';
}

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
