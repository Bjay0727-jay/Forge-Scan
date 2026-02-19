// Enhanced CSV Generator
// Generates CSV exports with UTF-8 BOM, proper escaping, and flattened JSON fields

const UTF8_BOM = '\uFEFF';

function escapeCSV(value: unknown): string {
  if (value === null || value === undefined) return '';

  let str: string;
  if (typeof value === 'object') {
    try {
      str = JSON.stringify(value);
    } catch {
      str = String(value);
    }
  } else {
    str = String(value);
  }

  // Escape if contains comma, quote, newline, or starts with special chars
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r') || str.startsWith('=') || str.startsWith('+') || str.startsWith('-') || str.startsWith('@')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

// Flatten nested objects into dot-notation keys
function flattenObject(obj: Record<string, unknown>, prefix = ''): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      Object.assign(result, flattenObject(value as Record<string, unknown>, fullKey));
    } else {
      result[fullKey] = value;
    }
  }
  return result;
}

export interface CSVOptions {
  columns?: string[];          // Specific columns to include (default: all)
  columnLabels?: Record<string, string>;  // Rename columns for display
  flattenJson?: boolean;       // Flatten nested JSON fields
  includeBOM?: boolean;        // Include UTF-8 BOM (default: true)
  delimiter?: string;          // Field delimiter (default: comma)
}

export function generateCSV(data: Record<string, unknown>[], options: CSVOptions = {}): string {
  if (!data || data.length === 0) {
    return options.includeBOM !== false ? UTF8_BOM : '';
  }

  const {
    flattenJson = true,
    includeBOM = true,
    delimiter = ',',
    columnLabels = {},
  } = options;

  // Flatten data if needed
  const processedData = flattenJson
    ? data.map(row => flattenObject(row as Record<string, unknown>))
    : data;

  // Determine columns
  const columns = options.columns || [...new Set(processedData.flatMap(row => Object.keys(row)))];

  // Header row with optional labels
  const headerRow = columns.map(col => escapeCSV(columnLabels[col] || col)).join(delimiter);

  // Data rows
  const dataRows = processedData.map(row =>
    columns.map(col => escapeCSV(row[col])).join(delimiter)
  );

  const csv = [headerRow, ...dataRows].join('\r\n');
  return includeBOM ? UTF8_BOM + csv : csv;
}

// Pre-configured generators for common report types

export function generateFindingsCSV(findings: Record<string, unknown>[]): string {
  return generateCSV(findings, {
    columns: [
      'id', 'title', 'description', 'severity', 'state', 'vendor', 'vendor_id',
      'hostname', 'ip_addresses', 'os', 'asset_type',
      'port', 'protocol', 'service',
      'cve_id', 'cvss_score', 'epss_score',
      'frs_score', 'solution',
      'first_seen', 'last_seen', 'fixed_at',
    ],
    columnLabels: {
      'id': 'Finding ID',
      'title': 'Title',
      'description': 'Description',
      'severity': 'Severity',
      'state': 'State',
      'vendor': 'Scanner',
      'vendor_id': 'Scanner Plugin ID',
      'hostname': 'Asset Hostname',
      'ip_addresses': 'IP Address',
      'os': 'Operating System',
      'asset_type': 'Asset Type',
      'port': 'Port',
      'protocol': 'Protocol',
      'service': 'Service',
      'cve_id': 'CVE ID',
      'cvss_score': 'CVSS Score',
      'epss_score': 'EPSS Score',
      'frs_score': 'FRS Score',
      'solution': 'Solution',
      'first_seen': 'First Seen',
      'last_seen': 'Last Seen',
      'fixed_at': 'Fixed At',
    },
  });
}

export function generateAssetsCSV(assets: Record<string, unknown>[]): string {
  return generateCSV(assets, {
    columns: [
      'id', 'hostname', 'fqdn', 'ip_addresses', 'mac_addresses',
      'os', 'os_version', 'asset_type', 'network_zone',
      'tags', 'owner', 'business_unit',
      'open_findings', 'critical_findings', 'high_findings',
      'first_seen', 'last_seen',
    ],
    columnLabels: {
      'id': 'Asset ID',
      'hostname': 'Hostname',
      'fqdn': 'FQDN',
      'ip_addresses': 'IP Addresses',
      'mac_addresses': 'MAC Addresses',
      'os': 'Operating System',
      'os_version': 'OS Version',
      'asset_type': 'Asset Type',
      'network_zone': 'Network Zone',
      'tags': 'Tags',
      'owner': 'Owner',
      'business_unit': 'Business Unit',
      'open_findings': 'Open Findings',
      'critical_findings': 'Critical Findings',
      'high_findings': 'High Findings',
      'first_seen': 'First Seen',
      'last_seen': 'Last Seen',
    },
  });
}

export function generateComplianceCSV(controls: Record<string, unknown>[]): string {
  return generateCSV(controls, {
    columns: [
      'framework_name', 'control_id', 'control_name', 'family', 'level',
      'compliance_status', 'evidence', 'assessed_by', 'assessed_at',
    ],
    columnLabels: {
      'framework_name': 'Framework',
      'control_id': 'Control ID',
      'control_name': 'Control Name',
      'family': 'Control Family',
      'level': 'Level',
      'compliance_status': 'Status',
      'evidence': 'Evidence',
      'assessed_by': 'Assessed By',
      'assessed_at': 'Assessed At',
    },
  });
}
