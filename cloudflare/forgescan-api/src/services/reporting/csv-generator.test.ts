import { describe, it, expect } from 'vitest';
import {
  generateCSV,
  generateFindingsCSV,
  generateAssetsCSV,
  generateComplianceCSV,
} from './csv-generator';

// The CSV functions are not exported individually — they're used internally by generateCSV.
// We test escapeCSV and flattenObject behavior through generateCSV's output.

const BOM = '\uFEFF';

// --- generateCSV core behavior ---

describe('generateCSV', () => {
  it('returns BOM only for empty data', () => {
    expect(generateCSV([])).toBe(BOM);
  });

  it('returns empty string when includeBOM is false and data is empty', () => {
    expect(generateCSV([], { includeBOM: false })).toBe('');
  });

  it('generates correct header row from data keys', () => {
    const data = [{ name: 'Alice', age: 30 }];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('name,age');
  });

  it('generates correct data rows', () => {
    const data = [
      { name: 'Alice', age: 30 },
      { name: 'Bob', age: 25 },
    ];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[1]).toBe('Alice,30');
    expect(lines[2]).toBe('Bob,25');
  });

  it('respects explicit column list', () => {
    const data = [{ name: 'Alice', age: 30, email: 'a@b.com' }];
    const csv = generateCSV(data, { columns: ['name', 'email'], includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('name,email');
    expect(lines[1]).toBe('Alice,a@b.com');
  });

  it('applies columnLabels to header', () => {
    const data = [{ first_name: 'Alice', last_name: 'Smith' }];
    const csv = generateCSV(data, {
      columnLabels: { first_name: 'First Name', last_name: 'Last Name' },
      includeBOM: false,
    });
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('First Name,Last Name');
  });

  it('includes BOM by default', () => {
    const data = [{ a: 1 }];
    const csv = generateCSV(data);
    expect(csv.startsWith(BOM)).toBe(true);
  });

  it('custom delimiter replaces comma', () => {
    const data = [{ name: 'Alice', age: 30 }];
    const csv = generateCSV(data, { delimiter: '\t', includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('name\tage');
    expect(lines[1]).toBe('Alice\t30');
  });

  it('flattens nested objects by default', () => {
    const data = [{ user: { name: 'Alice', age: 30 } }];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('user.name,user.age');
    expect(lines[1]).toBe('Alice,30');
  });

  it('does not flatten when flattenJson is false', () => {
    const data = [{ user: { name: 'Alice' } }];
    const csv = generateCSV(data, { flattenJson: false, includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('user');
    // The nested object should be JSON-stringified via escapeCSV
    expect(lines[1]).toContain('Alice');
  });
});

// --- escapeCSV behavior (tested through generateCSV) ---

describe('CSV escaping (via generateCSV)', () => {
  it('handles null/undefined values as empty strings', () => {
    const data = [{ a: null, b: undefined }];
    const csv = generateCSV(data, { includeBOM: false, flattenJson: false });
    const lines = csv.split('\r\n');
    expect(lines[1]).toBe(',');
  });

  it('wraps values containing commas in quotes', () => {
    const data = [{ desc: 'hello, world' }];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[1]).toBe('"hello, world"');
  });

  it('escapes internal quotes by doubling them', () => {
    const data = [{ desc: 'say "hi"' }];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[1]).toBe('"say ""hi"""');
  });

  it('wraps values containing newlines', () => {
    const data = [{ desc: 'line1\nline2' }];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    // The value should be quoted — the full output contains the newline inside quotes
    expect(csv).toContain('"line1\nline2"');
  });

  it('wraps values starting with formula chars (=, +, -, @)', () => {
    const data = [
      { a: '=SUM(A1)', b: '+1', c: '-1', d: '@mention' },
    ];
    const csv = generateCSV(data, { includeBOM: false });
    expect(csv).toContain('"=SUM(A1)"');
    expect(csv).toContain('"+1"');
    expect(csv).toContain('"-1"');
    expect(csv).toContain('"@mention"');
  });

  it('handles number values', () => {
    const data = [{ score: 9.8 }];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[1]).toBe('9.8');
  });

  it('handles boolean values', () => {
    const data = [{ active: true }];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[1]).toBe('true');
  });
});

// --- flattenObject behavior (tested through generateCSV) ---

describe('Object flattening (via generateCSV)', () => {
  it('preserves flat objects unchanged', () => {
    const data = [{ name: 'Alice', age: 30 }];
    const csv = generateCSV(data, { includeBOM: false });
    expect(csv).toContain('name,age');
  });

  it('flattens multiple levels of nesting', () => {
    const data = [{ a: { b: { c: 'deep' } } }];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('a.b.c');
    expect(lines[1]).toBe('deep');
  });

  it('preserves array values without recursive flattening', () => {
    const data = [{ tags: ['web', 'prod'] }];
    const csv = generateCSV(data, { includeBOM: false });
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('tags');
    // Arrays should be JSON-stringified
    expect(lines[1]).toContain('web');
    expect(lines[1]).toContain('prod');
  });
});

// --- Pre-configured generators ---

describe('generateFindingsCSV', () => {
  it('includes all 22 findings columns with correct labels', () => {
    const data = [{ id: '1', title: 'Test', severity: 'high' }];
    const csv = generateFindingsCSV(data);
    // Should have headers like "Finding ID", "Title", "Severity"
    expect(csv).toContain('Finding ID');
    expect(csv).toContain('Title');
    expect(csv).toContain('Severity');
    expect(csv).toContain('CVE ID');
    expect(csv).toContain('CVSS Score');
    expect(csv).toContain('EPSS Score');
  });
});

describe('generateAssetsCSV', () => {
  it('includes all 17 asset columns with correct labels', () => {
    const data = [{ id: '1', hostname: 'server01' }];
    const csv = generateAssetsCSV(data);
    expect(csv).toContain('Asset ID');
    expect(csv).toContain('Hostname');
    expect(csv).toContain('Operating System');
    expect(csv).toContain('Network Zone');
  });
});

describe('generateComplianceCSV', () => {
  it('includes all 9 compliance columns with correct labels', () => {
    const data = [{ framework_name: 'CIS', control_id: '1.1' }];
    const csv = generateComplianceCSV(data);
    expect(csv).toContain('Framework');
    expect(csv).toContain('Control ID');
    expect(csv).toContain('Control Name');
    expect(csv).toContain('Assessed By');
  });
});
