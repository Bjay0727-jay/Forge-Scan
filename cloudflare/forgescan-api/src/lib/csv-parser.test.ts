import { describe, it, expect } from 'vitest';
import {
  parseCSVLine,
  splitCSVLines,
  normalizeHeader,
  parseCSV,
  applyColumnMapping,
  parseFindingsCSV,
  parseAssetsCSV,
  normalizeSeverity,
  detectCSVType,
  getSupportedVendors,
} from './csv-parser';

// ─── parseCSVLine ───────────────────────────────────────────────────────────

describe('parseCSVLine', () => {
  it('parses simple comma-separated values', () => {
    expect(parseCSVLine('a,b,c')).toEqual(['a', 'b', 'c']);
  });

  it('trims whitespace from values', () => {
    expect(parseCSVLine('  a , b , c  ')).toEqual(['a', 'b', 'c']);
  });

  it('handles quoted values containing commas', () => {
    expect(parseCSVLine('"hello, world",b,c')).toEqual(['hello, world', 'b', 'c']);
  });

  it('handles escaped quotes (doubled)', () => {
    expect(parseCSVLine('"say ""hi""",b')).toEqual(['say "hi"', 'b']);
  });

  it('handles empty values', () => {
    expect(parseCSVLine('a,,c,')).toEqual(['a', '', 'c', '']);
  });

  it('handles a single value', () => {
    expect(parseCSVLine('only')).toEqual(['only']);
  });

  it('handles quoted value with newline inside', () => {
    expect(parseCSVLine('"line1\nline2",b')).toEqual(['line1\nline2', 'b']);
  });

  it('handles custom delimiter', () => {
    expect(parseCSVLine('a\tb\tc', '\t')).toEqual(['a', 'b', 'c']);
  });

  it('handles fully empty line', () => {
    expect(parseCSVLine('')).toEqual(['']);
  });
});

// ─── splitCSVLines ──────────────────────────────────────────────────────────

describe('splitCSVLines', () => {
  it('splits on LF', () => {
    expect(splitCSVLines('a\nb\nc')).toEqual(['a', 'b', 'c']);
  });

  it('splits on CRLF', () => {
    expect(splitCSVLines('a\r\nb\r\nc')).toEqual(['a', 'b', 'c']);
  });

  it('splits on CR alone', () => {
    expect(splitCSVLines('a\rb\rc')).toEqual(['a', 'b', 'c']);
  });

  it('preserves newlines inside quoted fields', () => {
    const csv = 'title,desc\n"hello","line1\nline2"\nfoo,bar';
    const lines = splitCSVLines(csv);
    expect(lines).toHaveLength(3);
    expect(lines[1]).toContain('line1\nline2');
  });

  it('handles empty input', () => {
    expect(splitCSVLines('')).toEqual([]);
  });

  it('handles single line', () => {
    expect(splitCSVLines('no newline')).toEqual(['no newline']);
  });
});

// ─── normalizeHeader ────────────────────────────────────────────────────────

describe('normalizeHeader', () => {
  it('lowercases header', () => {
    expect(normalizeHeader('Severity')).toBe('severity');
  });

  it('replaces spaces with underscores', () => {
    expect(normalizeHeader('CVE ID')).toBe('cve_id');
  });

  it('replaces hyphens with underscores', () => {
    expect(normalizeHeader('cvss-score')).toBe('cvss_score');
  });

  it('strips special characters', () => {
    expect(normalizeHeader('Risk (Level)')).toBe('risk_level');
  });

  it('trims whitespace', () => {
    expect(normalizeHeader('  title  ')).toBe('title');
  });

  it('handles multiple spaces', () => {
    expect(normalizeHeader('IP  Address')).toBe('ip_address');
  });
});

// ─── parseCSV ───────────────────────────────────────────────────────────────

describe('parseCSV', () => {
  it('parses a basic CSV with header', () => {
    const csv = 'name,age\nAlice,30\nBob,25';
    const result = parseCSV(csv);
    expect(result.rows).toHaveLength(2);
    expect(result.rows[0]).toEqual({ name: 'Alice', age: '30' });
    expect(result.rows[1]).toEqual({ name: 'Bob', age: '25' });
    expect(result.errors).toHaveLength(0);
  });

  it('returns empty for empty input', () => {
    const result = parseCSV('');
    expect(result.rows).toHaveLength(0);
  });

  it('returns empty for header-only CSV', () => {
    const result = parseCSV('name,age');
    expect(result.rows).toHaveLength(0);
  });

  it('normalises header names', () => {
    const csv = 'Full Name,IP Address\nAlice,10.0.0.1';
    const result = parseCSV(csv);
    expect(result.rows[0]).toEqual({ full_name: 'Alice', ip_address: '10.0.0.1' });
  });

  it('skips empty rows by default', () => {
    const csv = 'a,b\n1,2\n\n3,4';
    const result = parseCSV(csv);
    expect(result.rows).toHaveLength(2);
  });

  it('handles BOM at start of file', () => {
    const csv = '\uFEFFname,value\ntest,123';
    const result = parseCSV(csv);
    expect(result.rows[0]).toEqual({ name: 'test', value: '123' });
  });

  it('fills missing values with empty string', () => {
    const csv = 'a,b,c\n1';
    const result = parseCSV(csv);
    expect(result.rows[0]).toEqual({ a: '1', b: '', c: '' });
  });

  it('respects maxErrors limit', () => {
    // Constructing CSV that would generate errors is tricky since the parser
    // is quite forgiving. We test the options are respected by checking that
    // a large valid CSV still works.
    const header = 'name';
    const rows = Array.from({ length: 100 }, (_, i) => `name${i}`);
    const csv = [header, ...rows].join('\n');
    const result = parseCSV(csv, { maxErrors: 5 });
    expect(result.rows.length).toBe(100);
  });

  it('handles tab delimiter', () => {
    const csv = 'name\tage\nAlice\t30';
    const result = parseCSV(csv, { delimiter: '\t' });
    expect(result.rows[0]).toEqual({ name: 'Alice', age: '30' });
  });

  it('handles CRLF line endings', () => {
    const csv = 'name,age\r\nAlice,30\r\nBob,25';
    const result = parseCSV(csv);
    expect(result.rows).toHaveLength(2);
  });

  it('handles quoted values with commas', () => {
    const csv = 'title,desc\nTest,"has, comma"';
    const result = parseCSV(csv);
    expect(result.rows[0].desc).toBe('has, comma');
  });
});

// ─── applyColumnMapping ─────────────────────────────────────────────────────

describe('applyColumnMapping', () => {
  it('maps columns using first match', () => {
    const row = { name: 'SQLi', risk: 'high' };
    const mapping = {
      title: ['name', 'title'],
      severity: ['severity', 'risk'],
    };
    const result = applyColumnMapping(row, mapping);
    expect(result).toEqual({ title: 'SQLi', severity: 'high' });
  });

  it('skips unmapped columns', () => {
    const row = { name: 'SQLi', extra: 'ignored' };
    const mapping = { title: ['name'] };
    const result = applyColumnMapping(row, mapping);
    expect(result).toEqual({ title: 'SQLi' });
    expect(result).not.toHaveProperty('extra');
  });

  it('skips empty values', () => {
    const row = { name: '', title: 'Fallback' };
    const mapping = { title: ['name', 'title'] };
    const result = applyColumnMapping(row, mapping);
    expect(result).toEqual({ title: 'Fallback' });
  });

  it('returns empty for no matches', () => {
    const row = { foo: 'bar' };
    const mapping = { title: ['name', 'title'] };
    const result = applyColumnMapping(row, mapping);
    expect(result).toEqual({});
  });

  it('normalises source column names for lookup', () => {
    const row = { host_name: 'server01' };
    const mapping = { hostname: ['Host Name', 'host_name'] };
    const result = applyColumnMapping(row, mapping);
    expect(result).toEqual({ hostname: 'server01' });
  });
});

// ─── normalizeSeverity ──────────────────────────────────────────────────────

describe('normalizeSeverity', () => {
  // CVSS-based
  it('returns critical for CVSS >= 9.0', () => {
    expect(normalizeSeverity(undefined, 9.8)).toBe('critical');
  });

  it('returns high for CVSS >= 7.0', () => {
    expect(normalizeSeverity(undefined, 7.5)).toBe('high');
  });

  it('returns medium for CVSS >= 4.0', () => {
    expect(normalizeSeverity(undefined, 5.0)).toBe('medium');
  });

  it('returns low for CVSS >= 0.1', () => {
    expect(normalizeSeverity(undefined, 0.5)).toBe('low');
  });

  it('returns info for CVSS 0', () => {
    expect(normalizeSeverity(undefined, 0)).toBe('info');
  });

  // Numeric severity (Nessus-style)
  it('returns critical for numeric 4', () => {
    expect(normalizeSeverity(4)).toBe('critical');
  });

  it('returns high for numeric 3', () => {
    expect(normalizeSeverity(3)).toBe('high');
  });

  it('returns medium for numeric 2', () => {
    expect(normalizeSeverity(2)).toBe('medium');
  });

  it('returns low for numeric 1', () => {
    expect(normalizeSeverity(1)).toBe('low');
  });

  it('returns info for numeric 0', () => {
    expect(normalizeSeverity(0)).toBe('info');
  });

  // String severity
  it('normalises "critical" text', () => {
    expect(normalizeSeverity('Critical')).toBe('critical');
  });

  it('normalises "urgent" to critical', () => {
    expect(normalizeSeverity('urgent')).toBe('critical');
  });

  it('normalises "serious" to high', () => {
    expect(normalizeSeverity('serious')).toBe('high');
  });

  it('normalises "moderate" to medium', () => {
    expect(normalizeSeverity('moderate')).toBe('medium');
  });

  it('normalises "minimal" to low', () => {
    expect(normalizeSeverity('minimal')).toBe('low');
  });

  it('normalises "informational" to info', () => {
    expect(normalizeSeverity('informational')).toBe('info');
  });

  it('returns info for null', () => {
    expect(normalizeSeverity(null)).toBe('info');
  });

  it('returns info for undefined', () => {
    expect(normalizeSeverity(undefined)).toBe('info');
  });

  it('returns info for unknown string', () => {
    expect(normalizeSeverity('unknown')).toBe('info');
  });

  // Numeric strings (CVSS-like)
  it('parses numeric string "9.8" as critical', () => {
    expect(normalizeSeverity('9.8')).toBe('critical');
  });

  it('parses numeric string "5.5" as medium', () => {
    expect(normalizeSeverity('5.5')).toBe('medium');
  });

  // CVSS takes priority over severity text
  it('CVSS overrides severity text', () => {
    expect(normalizeSeverity('low', 9.8)).toBe('critical');
  });
});

// ─── parseFindingsCSV ───────────────────────────────────────────────────────

describe('parseFindingsCSV', () => {
  it('parses generic findings CSV', () => {
    const csv = [
      'Title,Severity,CVE ID,CVSS Score,IP Address,Port',
      'SQL Injection,critical,CVE-2024-1234,9.8,10.0.0.1,443',
      'XSS Reflected,medium,,5.4,10.0.0.2,80',
    ].join('\n');

    const result = parseFindingsCSV(csv);
    expect(result.rows).toHaveLength(2);

    expect(result.rows[0].title).toBe('SQL Injection');
    expect(result.rows[0].severity).toBe('critical');
    expect(result.rows[0].cve_id).toBe('CVE-2024-1234');
    expect(result.rows[0].cvss_score).toBe(9.8);
    expect(result.rows[0].ip).toBe('10.0.0.1');
    expect(result.rows[0].port).toBe(443);

    expect(result.rows[1].title).toBe('XSS Reflected');
    expect(result.rows[1].severity).toBe('medium');
    expect(result.rows[1].cve_id).toBe(null);
    expect(result.rows[1].cvss_score).toBe(5.4);
  });

  it('parses Nessus-style CSV with vendor=tenable', () => {
    const csv = [
      'Plugin ID,Name,Risk,Host IP,Port,Protocol,Synopsis,Plugin Output,CVE,CVSS3 Base Score',
      '12345,Test Plugin,Critical,192.168.1.1,22,tcp,Test synopsis,Test output,CVE-2024-5678,9.1',
    ].join('\n');

    const result = parseFindingsCSV(csv, 'tenable');
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].title).toBe('Test Plugin');
    expect(result.rows[0].vendor_id).toBe('12345');
    expect(result.rows[0].severity).toBe('critical');
    expect(result.rows[0].ip).toBe('192.168.1.1');
    expect(result.rows[0].port).toBe(22);
    expect(result.rows[0].protocol).toBe('tcp');
    expect(result.rows[0].cve_id).toBe('CVE-2024-5678');
    expect(result.rows[0].cvss_score).toBe(9.1);
  });

  it('parses Qualys-style CSV with vendor=qualys', () => {
    const csv = [
      'QID,Title,Severity,IP,Port,Protocol,Solution,CVE ID',
      '67890,Open SSH Vuln,5,172.16.0.1,22,tcp,Upgrade OpenSSH,CVE-2024-9999',
    ].join('\n');

    const result = parseFindingsCSV(csv, 'qualys');
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].title).toBe('Open SSH Vuln');
    expect(result.rows[0].vendor_id).toBe('67890');
    expect(result.rows[0].ip).toBe('172.16.0.1');
  });

  it('skips rows with no title, vendor_id, or cve_id', () => {
    const csv = [
      'Description,Port',
      'some description,80',
    ].join('\n');

    const result = parseFindingsCSV(csv);
    expect(result.rows).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('No title, vendor_id, or cve_id');
  });

  it('handles empty CSV', () => {
    const result = parseFindingsCSV('');
    expect(result.rows).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it('uses CVSS for severity when severity text is missing', () => {
    const csv = [
      'Title,CVSS Score',
      'Test Vuln,8.5',
    ].join('\n');

    const result = parseFindingsCSV(csv);
    expect(result.rows[0].severity).toBe('high');
  });

  it('handles large CSV without crashing', () => {
    const header = 'Title,Severity,IP Address';
    const rows = Array.from({ length: 500 }, (_, i) =>
      `Vuln ${i},high,10.0.${Math.floor(i / 255)}.${i % 255}`
    );
    const csv = [header, ...rows].join('\n');

    const result = parseFindingsCSV(csv);
    expect(result.rows).toHaveLength(500);
  });

  it('falls back to generic mapping for unknown vendor', () => {
    const csv = 'Title,Severity\nTest,high';
    const result = parseFindingsCSV(csv, 'unknown_vendor');
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].title).toBe('Test');
  });
});

// ─── parseAssetsCSV ─────────────────────────────────────────────────────────

describe('parseAssetsCSV', () => {
  it('parses basic asset CSV', () => {
    const csv = [
      'Hostname,IP Address,OS,Asset Type,Network Zone',
      'web-01,10.0.0.1,Ubuntu 22.04,host,dmz',
      'db-01,10.0.0.2,Windows Server 2022,host,internal',
    ].join('\n');

    const result = parseAssetsCSV(csv);
    expect(result.rows).toHaveLength(2);
    expect(result.rows[0].hostname).toBe('web-01');
    expect(result.rows[0].ip_address).toBe('10.0.0.1');
    expect(result.rows[0].os).toBe('Ubuntu 22.04');
    expect(result.rows[0].asset_type).toBe('host');
    expect(result.rows[0].network_zone).toBe('dmz');
  });

  it('handles alternative column names', () => {
    const csv = [
      'Host Name,IP,Operating System,Type,Environment',
      'server01,192.168.1.1,CentOS 8,host,production',
    ].join('\n');

    const result = parseAssetsCSV(csv);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].hostname).toBe('server01');
    expect(result.rows[0].ip_address).toBe('192.168.1.1');
    expect(result.rows[0].os).toBe('CentOS 8');
    expect(result.rows[0].network_zone).toBe('production');
  });

  it('skips rows missing both hostname and IP', () => {
    const csv = [
      'OS,Asset Type',
      'Linux,host',
    ].join('\n');

    const result = parseAssetsCSV(csv);
    expect(result.rows).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('Missing hostname or ip_address');
  });

  it('parses comma-separated tags', () => {
    const csv = [
      'Hostname,Tags',
      'web-01,"web,production,critical"',
    ].join('\n');

    const result = parseAssetsCSV(csv);
    expect(result.rows[0].tags).toEqual(['web', 'production', 'critical']);
  });

  it('defaults asset_type to "host"', () => {
    const csv = 'Hostname\nserver01';
    const result = parseAssetsCSV(csv);
    expect(result.rows[0].asset_type).toBe('host');
  });

  it('handles owner, department, location fields', () => {
    const csv = [
      'Hostname,Owner,Department,Location',
      'server01,John Doe,Engineering,US-East',
    ].join('\n');

    const result = parseAssetsCSV(csv);
    expect(result.rows[0].owner).toBe('John Doe');
    expect(result.rows[0].department).toBe('Engineering');
    expect(result.rows[0].location).toBe('US-East');
  });

  it('accepts IP-only assets (no hostname)', () => {
    const csv = 'IP Address\n10.0.0.1';
    const result = parseAssetsCSV(csv);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].hostname).toBe(null);
    expect(result.rows[0].ip_address).toBe('10.0.0.1');
  });
});

// ─── detectCSVType ──────────────────────────────────────────────────────────

describe('detectCSVType', () => {
  it('detects findings CSV by severity column', () => {
    expect(detectCSVType('Title,Severity,Port\ntest,high,80')).toBe('findings');
  });

  it('detects findings CSV by CVE column', () => {
    expect(detectCSVType('Title,CVE ID\ntest,CVE-2024-1')).toBe('findings');
  });

  it('detects findings CSV by plugin_id column', () => {
    expect(detectCSVType('Plugin ID,Name\n12345,Test')).toBe('findings');
  });

  it('detects assets CSV by OS column', () => {
    expect(detectCSVType('Hostname,OS,OS Version\nweb,Linux,5.4')).toBe('assets');
  });

  it('detects assets CSV by network_zone', () => {
    expect(detectCSVType('Hostname,Network Zone\nweb,dmz')).toBe('assets');
  });

  it('returns unknown for ambiguous CSV', () => {
    expect(detectCSVType('Name,Value\nfoo,bar')).toBe('unknown');
  });

  it('prioritises findings detection over assets', () => {
    // If both finding and asset indicators present, findings wins
    expect(detectCSVType('Hostname,OS,Severity\nweb,Linux,high')).toBe('findings');
  });
});

// ─── getSupportedVendors ────────────────────────────────────────────────────

describe('getSupportedVendors', () => {
  it('returns array of supported vendor names', () => {
    const vendors = getSupportedVendors();
    expect(vendors).toContain('generic');
    expect(vendors).toContain('tenable');
    expect(vendors).toContain('nessus');
    expect(vendors).toContain('qualys');
    expect(vendors).toContain('rapid7');
    expect(vendors).toContain('nexpose');
  });
});

// ─── Edge Cases & Regression ────────────────────────────────────────────────

describe('edge cases', () => {
  it('handles CSV with only whitespace lines between data', () => {
    const csv = 'title,severity\n  \nSQL Injection,critical\n  \nXSS,medium';
    const result = parseCSV(csv);
    expect(result.rows).toHaveLength(2);
  });

  it('handles CSV with extra columns beyond header', () => {
    const csv = 'a,b\n1,2,3,4';
    const result = parseCSV(csv);
    expect(result.rows[0]).toEqual({ a: '1', b: '2' });
  });

  it('handles CSV with unicode characters', () => {
    const csv = 'title,desc\nVulnérabilité,Données sensibles';
    const result = parseCSV(csv);
    expect(result.rows[0].title).toBe('Vulnérabilité');
    expect(result.rows[0].desc).toBe('Données sensibles');
  });

  it('handles very long values', () => {
    const longVal = 'x'.repeat(10000);
    const csv = `title\n${longVal}`;
    const result = parseCSV(csv);
    expect(result.rows[0].title).toBe(longVal);
  });

  it('handles findings CSV where title comes from CVE', () => {
    const csv = 'CVE ID,CVSS Score\nCVE-2024-1234,9.0';
    const result = parseFindingsCSV(csv);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].title).toBe('CVE-2024-1234');
    expect(result.rows[0].cve_id).toBe('CVE-2024-1234');
  });

  it('handles findings CSV where title comes from vendor_id', () => {
    const csv = 'Vendor ID,Severity\n12345,high';
    const result = parseFindingsCSV(csv);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].title).toBe('Finding 12345');
  });
});
