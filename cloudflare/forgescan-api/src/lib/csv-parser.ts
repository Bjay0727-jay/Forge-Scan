/**
 * CSV Parser for ForgeScan 360
 *
 * Handles parsing of vulnerability scan exports from various vendors
 * (Nessus, Qualys, Rapid7, generic) into normalised finding/asset records.
 *
 * Features:
 *  - RFC 4180-compliant CSV parsing (quoted fields, escaped quotes, newlines)
 *  - Automatic header normalisation (lowercase, underscored)
 *  - Flexible column mapping with vendor-specific presets
 *  - Row-level error collection (caps at maxErrors to avoid huge payloads)
 *  - Severity normalisation from numeric/text/CVSS inputs
 */

import { badRequest } from './errors';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface CSVParseOptions {
  /** Skip rows that produce no usable data (default: true) */
  skipEmpty?: boolean;
  /** Maximum errors to collect before aborting (default: 50) */
  maxErrors?: number;
  /** Custom delimiter (default: ',') */
  delimiter?: string;
  /** Whether the first row is a header row (default: true) */
  hasHeader?: boolean;
}

export interface CSVParseResult<T = Record<string, string>> {
  rows: T[];
  errors: string[];
  totalRows: number;
}

export interface ColumnMapping {
  /** CSV column name(s) that map to this field (first match wins) */
  [targetField: string]: string[];
}

export interface FindingRecord {
  title: string;
  description: string | null;
  severity: string;
  vendor_id: string | null;
  hostname: string | null;
  ip: string | null;
  port: number | null;
  protocol: string | null;
  service: string | null;
  solution: string | null;
  evidence: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  affected_component: string | null;
  references: string | null;
}

export interface AssetRecord {
  hostname: string | null;
  fqdn: string | null;
  ip_address: string | null;
  mac_address: string | null;
  os: string | null;
  os_version: string | null;
  asset_type: string;
  network_zone: string | null;
  tags: string[];
  owner: string | null;
  department: string | null;
  location: string | null;
}

// ─── Core CSV Parser ────────────────────────────────────────────────────────

/**
 * Parse a single CSV line handling quoted values with commas and escaped
 * quotes (RFC 4180).
 */
export function parseCSVLine(line: string, delimiter = ','): string[] {
  const values: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        // Escaped quote ""
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === delimiter && !inQuotes) {
      values.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }

  values.push(current.trim());
  return values;
}

/**
 * Split CSV text into lines, correctly handling newlines inside quoted fields.
 */
export function splitCSVLines(text: string): string[] {
  const lines: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];

    if (char === '"') {
      current += char;
      if (inQuotes && text[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if ((char === '\n' || (char === '\r' && text[i + 1] === '\n')) && !inQuotes) {
      if (char === '\r') i++; // skip \n in \r\n
      lines.push(current);
      current = '';
    } else if (char === '\r' && !inQuotes) {
      lines.push(current);
      current = '';
    } else {
      current += char;
    }
  }

  if (current.length > 0) {
    lines.push(current);
  }

  return lines;
}

/**
 * Normalise a header name: trim, lowercase, replace whitespace/hyphens with
 * underscores, strip non-alphanumeric chars (except underscores).
 */
export function normalizeHeader(header: string): string {
  return header
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_')
    .replace(/[^a-z0-9_]/g, '');
}

/**
 * Parse a CSV string into an array of key-value records.
 *
 * Headers are normalised to lowercase_with_underscores so column mappings
 * work regardless of how the export tool capitalised them.
 */
export function parseCSV(
  csvText: string,
  options: CSVParseOptions = {},
): CSVParseResult {
  const {
    skipEmpty = true,
    maxErrors = 50,
    delimiter = ',',
    hasHeader = true,
  } = options;

  const trimmed = csvText.trim();
  if (!trimmed) {
    return { rows: [], errors: [], totalRows: 0 };
  }

  // Handle BOM
  const clean = trimmed.charCodeAt(0) === 0xFEFF ? trimmed.slice(1) : trimmed;
  const lines = splitCSVLines(clean);

  if (lines.length === 0) {
    return { rows: [], errors: [], totalRows: 0 };
  }

  if (hasHeader && lines.length < 2) {
    return { rows: [], errors: [], totalRows: 0 };
  }

  const headerLine = hasHeader ? 0 : -1;
  const headers = hasHeader
    ? parseCSVLine(lines[0], delimiter).map(normalizeHeader)
    : [];

  const rows: Record<string, string>[] = [];
  const errors: string[] = [];
  const startLine = hasHeader ? 1 : 0;

  for (let i = startLine; i < lines.length; i++) {
    if (errors.length >= maxErrors) {
      errors.push(`Stopped processing after ${maxErrors} errors`);
      break;
    }

    const line = lines[i];
    if (skipEmpty && !line.trim()) continue;

    try {
      const values = parseCSVLine(line, delimiter);
      const row: Record<string, string> = {};

      if (hasHeader) {
        headers.forEach((header, idx) => {
          row[header] = values[idx] || '';
        });
      } else {
        values.forEach((val, idx) => {
          row[`col_${idx}`] = val;
        });
      }

      rows.push(row);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`Row ${i + 1}: ${msg}`);
    }
  }

  return { rows, errors, totalRows: rows.length };
}

// ─── Column Mapping ─────────────────────────────────────────────────────────

/**
 * Apply a column mapping to a parsed row. For each target field, try each
 * source column name in order — first non-empty match wins.
 */
export function applyColumnMapping(
  row: Record<string, string>,
  mapping: ColumnMapping,
): Record<string, string> {
  const result: Record<string, string> = {};

  for (const [targetField, sourceColumns] of Object.entries(mapping)) {
    for (const col of sourceColumns) {
      const normalised = normalizeHeader(col);
      if (row[normalised] !== undefined && row[normalised] !== '') {
        result[targetField] = row[normalised];
        break;
      }
    }
  }

  return result;
}

// ─── Finding Column Mappings (vendor presets) ───────────────────────────────

const FINDING_COLUMNS_GENERIC: ColumnMapping = {
  title:              ['title', 'name', 'vulnerability', 'vuln_name', 'finding', 'summary'],
  description:        ['description', 'synopsis', 'details', 'vuln_description'],
  severity:           ['severity', 'risk', 'risk_level', 'threat', 'impact'],
  vendor_id:          ['vendor_id', 'plugin_id', 'vuln_id', 'qid', 'vulnerability_id', 'id'],
  hostname:           ['hostname', 'host', 'host_name', 'server', 'target', 'dns_name'],
  ip:                 ['ip', 'ip_address', 'host_ip', 'target_ip', 'address'],
  port:               ['port', 'service_port', 'dest_port'],
  protocol:           ['protocol', 'proto', 'service_protocol'],
  service:            ['service', 'service_name', 'svc_name'],
  solution:           ['solution', 'remediation', 'fix', 'recommendation', 'mitigation'],
  evidence:           ['evidence', 'output', 'plugin_output', 'proof', 'result'],
  cve_id:             ['cve_id', 'cve', 'cves', 'vuln_cve'],
  cvss_score:         ['cvss_score', 'cvss', 'cvss_v3', 'cvss_base_score', 'cvss3_base_score', 'base_score'],
  affected_component: ['affected_component', 'component', 'affected_software', 'package', 'asset_name'],
  references:         ['references', 'refs', 'see_also', 'links', 'urls'],
};

const FINDING_COLUMNS_NESSUS: ColumnMapping = {
  title:              ['name', 'plugin_name'],
  description:        ['synopsis', 'description'],
  severity:           ['risk', 'severity'],
  vendor_id:          ['plugin_id'],
  hostname:           ['host', 'dns_name', 'netbios_name'],
  ip:                 ['host_ip', 'ip'],
  port:               ['port'],
  protocol:           ['protocol'],
  service:            ['svc_name'],
  solution:           ['solution'],
  evidence:           ['plugin_output'],
  cve_id:             ['cve'],
  cvss_score:         ['cvss3_base_score', 'cvss_base_score'],
  affected_component: ['plugin_name'],
  references:         ['see_also'],
};

const FINDING_COLUMNS_QUALYS: ColumnMapping = {
  title:              ['title', 'vulnerability'],
  description:        ['threat', 'impact', 'description'],
  severity:           ['severity'],
  vendor_id:          ['qid'],
  hostname:           ['dns', 'dns_name', 'hostname'],
  ip:                 ['ip', 'ip_address'],
  port:               ['port'],
  protocol:           ['protocol'],
  service:            ['service'],
  solution:           ['solution'],
  evidence:           ['results'],
  cve_id:             ['cve_id', 'cves'],
  cvss_score:         ['cvss3_base', 'cvss_base'],
  affected_component: ['category'],
  references:         ['vendor_reference'],
};

const FINDING_COLUMNS_RAPID7: ColumnMapping = {
  title:              ['vulnerability_title', 'title', 'name'],
  description:        ['description', 'vulnerability_description'],
  severity:           ['severity', 'risk_score'],
  vendor_id:          ['vulnerability_id'],
  hostname:           ['asset_name', 'host_name'],
  ip:                 ['asset_ip_address', 'ip_address'],
  port:               ['service_port', 'port'],
  protocol:           ['service_protocol', 'protocol'],
  service:            ['service_name'],
  solution:           ['solution', 'remediation'],
  evidence:           ['proof', 'output'],
  cve_id:             ['cve_id'],
  cvss_score:         ['cvss_score', 'cvss_v3_score'],
  affected_component: ['asset_name'],
  references:         ['references'],
};

const VENDOR_FINDING_MAPPINGS: Record<string, ColumnMapping> = {
  generic: FINDING_COLUMNS_GENERIC,
  tenable: FINDING_COLUMNS_NESSUS,
  nessus:  FINDING_COLUMNS_NESSUS,
  qualys:  FINDING_COLUMNS_QUALYS,
  rapid7:  FINDING_COLUMNS_RAPID7,
  nexpose: FINDING_COLUMNS_RAPID7,
};

// ─── Asset Column Mappings ──────────────────────────────────────────────────

const ASSET_COLUMNS: ColumnMapping = {
  hostname:     ['hostname', 'host_name', 'name', 'server_name', 'server', 'host'],
  fqdn:         ['fqdn', 'fully_qualified_domain_name', 'dns_name', 'domain'],
  ip_address:   ['ip_address', 'ip', 'ip_addresses', 'address', 'host_ip'],
  mac_address:  ['mac_address', 'mac_addresses', 'mac', 'physical_address'],
  os:           ['os', 'operating_system', 'os_name', 'platform'],
  os_version:   ['os_version', 'os_ver'],
  asset_type:   ['asset_type', 'type', 'device_type', 'category'],
  network_zone: ['network_zone', 'zone', 'environment', 'env', 'network', 'segment'],
  tags:         ['tags', 'labels', 'categories'],
  owner:        ['owner', 'asset_owner', 'responsible'],
  department:   ['department', 'dept', 'business_unit', 'bu'],
  location:     ['location', 'site', 'data_center', 'dc', 'region'],
};

// ─── Severity Normalisation ─────────────────────────────────────────────────

/**
 * Normalise severity from various vendor formats into a consistent set:
 * critical | high | medium | low | info
 */
export function normalizeSeverity(
  severity: string | number | undefined | null,
  cvss?: number | null,
): string {
  // CVSS score takes priority if provided
  if (cvss !== undefined && cvss !== null && !isNaN(Number(cvss))) {
    const score = Number(cvss);
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    if (score >= 0.1) return 'low';
    return 'info';
  }

  if (severity === undefined || severity === null) return 'info';

  // Numeric severity (Nessus-style: 0-4)
  if (typeof severity === 'number') {
    if (severity >= 4) return 'critical';
    if (severity === 3) return 'high';
    if (severity === 2) return 'medium';
    if (severity === 1) return 'low';
    return 'info';
  }

  // Numeric string — could be CVSS or Nessus-style
  const num = parseFloat(severity);
  if (!isNaN(num)) {
    if (num >= 9.0) return 'critical';
    if (num >= 7.0) return 'high';
    if (num >= 4.0) return 'medium';
    if (num >= 0.1) return 'low';
    return 'info';
  }

  // Text-based severity
  const sev = severity.toLowerCase().trim();
  if (['critical', 'urgent', 'crit', '4'].includes(sev)) return 'critical';
  if (['high', 'serious', 'important', '3'].includes(sev)) return 'high';
  if (['medium', 'moderate', 'med', '2'].includes(sev)) return 'medium';
  if (['low', 'minimal', '1'].includes(sev)) return 'low';
  if (['info', 'informational', 'none', '0'].includes(sev)) return 'info';
  return 'info';
}

// ─── High-level Parsers ─────────────────────────────────────────────────────

/**
 * Parse a CSV string into normalised finding records, using vendor-specific
 * column mappings.
 */
export function parseFindingsCSV(
  csvText: string,
  vendor: string = 'generic',
  options: CSVParseOptions = {},
): CSVParseResult<FindingRecord> {
  const { rows, errors, totalRows } = parseCSV(csvText, options);
  const mapping = VENDOR_FINDING_MAPPINGS[vendor.toLowerCase()] || FINDING_COLUMNS_GENERIC;

  const findings: FindingRecord[] = [];
  const parseErrors = [...errors];

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const mapped = applyColumnMapping(row, mapping);

    // Must have at least a title
    const title = mapped.title as string || '';
    if (!title && !mapped.vendor_id && !mapped.cve_id) {
      parseErrors.push(`Row ${i + 2}: No title, vendor_id, or cve_id — skipping`);
      continue;
    }

    const cvssRaw = mapped.cvss_score as string | undefined;
    const cvssScore = cvssRaw ? parseFloat(cvssRaw) : null;
    const portRaw = mapped.port as string | undefined;
    const port = portRaw ? parseInt(portRaw, 10) : null;

    findings.push({
      title:              title || mapped.cve_id as string || `Finding ${mapped.vendor_id}`,
      description:        (mapped.description as string) || null,
      severity:           normalizeSeverity(mapped.severity as string, cvssScore),
      vendor_id:          (mapped.vendor_id as string) || null,
      hostname:           (mapped.hostname as string) || null,
      ip:                 (mapped.ip as string) || null,
      port:               port !== null && !isNaN(port) ? port : null,
      protocol:           (mapped.protocol as string) || null,
      service:            (mapped.service as string) || null,
      solution:           (mapped.solution as string) || null,
      evidence:           (mapped.evidence as string) || null,
      cve_id:             (mapped.cve_id as string) || null,
      cvss_score:         cvssScore !== null && !isNaN(cvssScore) ? cvssScore : null,
      affected_component: (mapped.affected_component as string) || null,
      references:         (mapped.references as string) || null,
    });
  }

  return { rows: findings, errors: parseErrors, totalRows: findings.length };
}

/**
 * Parse a CSV string into normalised asset records.
 */
export function parseAssetsCSV(
  csvText: string,
  options: CSVParseOptions = {},
): CSVParseResult<AssetRecord> {
  const { rows, errors, totalRows } = parseCSV(csvText, options);
  const assets: AssetRecord[] = [];
  const parseErrors = [...errors];

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const mapped = applyColumnMapping(row, ASSET_COLUMNS);

    const hostname = mapped.hostname as string || null;
    const ipAddress = mapped.ip_address as string || null;

    if (!hostname && !ipAddress) {
      parseErrors.push(`Row ${i + 2}: Missing hostname or ip_address — skipping`);
      continue;
    }

    const tagsRaw = mapped.tags || '';
    const tags = tagsRaw
      ? tagsRaw.split(',').map((t: string) => t.trim()).filter(Boolean)
      : [];

    assets.push({
      hostname,
      fqdn:         (mapped.fqdn as string) || null,
      ip_address:   ipAddress,
      mac_address:  (mapped.mac_address as string) || null,
      os:           (mapped.os as string) || null,
      os_version:   (mapped.os_version as string) || null,
      asset_type:   (mapped.asset_type as string) || 'host',
      network_zone: (mapped.network_zone as string) || null,
      tags,
      owner:        (mapped.owner as string) || null,
      department:   (mapped.department as string) || null,
      location:     (mapped.location as string) || null,
    });
  }

  return { rows: assets, errors: parseErrors, totalRows: assets.length };
}

/**
 * Auto-detect CSV type (findings vs assets) by inspecting header names.
 * Returns 'findings' if any vulnerability-related columns are found,
 * 'assets' if only asset-related columns are found.
 */
export function detectCSVType(csvText: string): 'findings' | 'assets' | 'unknown' {
  const firstLine = csvText.split(/\r?\n/)[0] || '';
  const headers = parseCSVLine(firstLine).map(normalizeHeader);

  const findingIndicators = ['severity', 'risk', 'cve', 'cve_id', 'cvss', 'vulnerability',
    'plugin_id', 'qid', 'vuln_id', 'threat', 'solution', 'remediation'];
  const assetIndicators = ['os', 'operating_system', 'os_version', 'asset_type',
    'network_zone', 'mac_address', 'fqdn'];

  const hasFindingCols = headers.some(h => findingIndicators.includes(h));
  const hasAssetCols = headers.some(h => assetIndicators.includes(h));

  if (hasFindingCols) return 'findings';
  if (hasAssetCols) return 'assets';
  return 'unknown';
}

/**
 * List supported vendor names for findings CSV parsing.
 */
export function getSupportedVendors(): string[] {
  return Object.keys(VENDOR_FINDING_MAPPINGS);
}
