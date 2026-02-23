// ─────────────────────────────────────────────────────────────────────────────
// Compliance Core — Mapping Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  mapFindingToControls,
  mapCWEToNISTControls,
  mapCWEToCISControls,
  generatePOAMEntry,
} from './mapping';

describe('mapCWEToNISTControls()', () => {
  it('maps SQL Injection (CWE-89) to SI-10 and SI-2', () => {
    const controls = mapCWEToNISTControls('CWE-89');

    expect(controls.length).toBeGreaterThanOrEqual(2);
    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('SI-10');
    expect(controlIds).toContain('SI-2');
    expect(controls[0].framework).toBe('nist-800-53');
    expect(controls[0].relevance).toBe('primary');
  });

  it('maps XSS (CWE-79) to SI-10 and SI-2', () => {
    const controls = mapCWEToNISTControls('CWE-79');

    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('SI-10');
    expect(controlIds).toContain('SI-2');
  });

  it('maps Improper Auth (CWE-287) to IA-2, IA-5, AC-3', () => {
    const controls = mapCWEToNISTControls('CWE-287');

    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('IA-2');
    expect(controlIds).toContain('IA-5');
    expect(controlIds).toContain('AC-3');
  });

  it('maps Broken Crypto (CWE-327) to SC-13 and SC-8', () => {
    const controls = mapCWEToNISTControls('CWE-327');

    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('SC-13');
    expect(controlIds).toContain('SC-8');
  });

  it('maps Hardcoded Credentials (CWE-798) to IA-5 and SC-13', () => {
    const controls = mapCWEToNISTControls('CWE-798');

    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('IA-5');
    expect(controlIds).toContain('SC-13');
  });

  it('returns empty array for unknown CWE', () => {
    const controls = mapCWEToNISTControls('CWE-99999');
    expect(controls).toHaveLength(0);
  });

  it('includes control names from NIST lookup', () => {
    const controls = mapCWEToNISTControls('CWE-89');
    const si10 = controls.find((c) => c.control_id === 'SI-10');

    expect(si10).toBeDefined();
    expect(si10!.control_name).toBe('Information Input Validation');
  });
});

describe('mapCWEToCISControls()', () => {
  it('maps SQL Injection (CWE-89) to CIS-16', () => {
    const controls = mapCWEToCISControls('CWE-89');

    expect(controls.length).toBeGreaterThanOrEqual(1);
    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('CIS-16');
    expect(controls[0].framework).toBe('cis-v8');
  });

  it('maps XSS (CWE-79) to CIS-16 and CIS-9', () => {
    const controls = mapCWEToCISControls('CWE-79');

    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('CIS-16');
    expect(controlIds).toContain('CIS-9');
  });

  it('maps Improper Auth (CWE-287) to CIS-5 and CIS-6', () => {
    const controls = mapCWEToCISControls('CWE-287');

    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('CIS-5');
    expect(controlIds).toContain('CIS-6');
  });

  it('maps Config Issues (CWE-16) to CIS-4', () => {
    const controls = mapCWEToCISControls('CWE-16');

    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('CIS-4');
  });

  it('returns empty array for unknown CWE', () => {
    const controls = mapCWEToCISControls('CWE-99999');
    expect(controls).toHaveLength(0);
  });

  it('includes control names from CIS lookup', () => {
    const controls = mapCWEToCISControls('CWE-89');
    const cis16 = controls.find((c) => c.control_id === 'CIS-16');

    expect(cis16).toBeDefined();
    expect(cis16!.control_name).toBe('Application Software Security');
  });

  it('sets all CIS mappings as primary relevance', () => {
    const controls = mapCWEToCISControls('CWE-79');

    for (const ctrl of controls) {
      expect(ctrl.relevance).toBe('primary');
    }
  });
});

describe('mapFindingToControls()', () => {
  it('maps finding with CWE to both NIST and CIS controls', () => {
    const controls = mapFindingToControls({ cwe_id: 'CWE-89' });

    const frameworks = new Set(controls.map((c) => c.framework));
    expect(frameworks.has('nist-800-53')).toBe(true);
    expect(frameworks.has('cis-v8')).toBe(true);
  });

  it('always includes RA-5 as secondary control', () => {
    const controls = mapFindingToControls({ cwe_id: 'CWE-89' });

    const ra5 = controls.find((c) => c.control_id === 'RA-5');
    expect(ra5).toBeDefined();
    expect(ra5!.relevance).toBe('secondary');
  });

  it('maps explicit NIST controls from finding', () => {
    const controls = mapFindingToControls({
      nist_controls: ['AC-2', 'AC-6'],
    });

    const controlIds = controls.map((c) => c.control_id);
    expect(controlIds).toContain('AC-2');
    expect(controlIds).toContain('AC-6');
  });

  it('deduplicates controls across CWE and explicit NIST', () => {
    // CWE-287 maps to IA-2, IA-5, AC-3 via CWE mapping
    // Explicit IA-2 should not create a duplicate
    const controls = mapFindingToControls({
      cwe_id: 'CWE-287',
      nist_controls: ['IA-2'],
    });

    const ia2Controls = controls.filter((c) => c.control_id === 'IA-2');
    expect(ia2Controls).toHaveLength(1);
  });

  it('returns only RA-5 for unknown CWE with no NIST controls', () => {
    const controls = mapFindingToControls({ cwe_id: 'CWE-99999' });

    expect(controls).toHaveLength(1);
    expect(controls[0].control_id).toBe('RA-5');
    expect(controls[0].relevance).toBe('secondary');
  });

  it('returns RA-5 for finding with no CWE and no NIST controls', () => {
    const controls = mapFindingToControls({});

    expect(controls).toHaveLength(1);
    expect(controls[0].control_id).toBe('RA-5');
  });

  it('does not duplicate RA-5 if explicitly in nist_controls', () => {
    const controls = mapFindingToControls({
      nist_controls: ['RA-5'],
    });

    const ra5Controls = controls.filter((c) => c.control_id === 'RA-5');
    expect(ra5Controls).toHaveLength(1);
    // The explicit one should be primary
    expect(ra5Controls[0].relevance).toBe('primary');
  });
});

describe('generatePOAMEntry()', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('poam-uuid-test'),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('generates POA&M entry with correct structure', () => {
    const entry = generatePOAMEntry({
      id: 'finding-001',
      title: 'SQL Injection',
      cwe_id: 'CWE-89',
      severity: 'critical',
      remediation: 'Use parameterized queries',
    });

    expect(entry.id).toBe('poam-uuid-test');
    expect(entry.finding_title).toBe('SQL Injection');
    expect(entry.weakness).toBe('CWE-89');
    expect(entry.severity).toBe('critical');
    expect(entry.remediation).toBe('Use parameterized queries');
    expect(entry.status).toBe('open');
    expect(entry.milestones).toHaveLength(4);
    expect(entry.controls.length).toBeGreaterThan(0);
    expect(entry.created_at).toBeDefined();
    expect(entry.scheduled_completion).toBeDefined();
  });

  it('sets 15-day remediation deadline for critical findings', () => {
    const entry = generatePOAMEntry({
      id: 'f-1',
      title: 'Critical Bug',
      severity: 'critical',
    });

    const scheduled = new Date(entry.scheduled_completion);
    const today = new Date(new Date().toISOString().split('T')[0]);
    const diffDays = Math.round((scheduled.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));

    expect(diffDays).toBe(15);
  });

  it('sets 30-day remediation deadline for high findings', () => {
    const entry = generatePOAMEntry({
      id: 'f-2',
      title: 'High Bug',
      severity: 'high',
    });

    const scheduled = new Date(entry.scheduled_completion);
    const today = new Date(new Date().toISOString().split('T')[0]);
    const diffDays = Math.round((scheduled.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));

    expect(diffDays).toBe(30);
  });

  it('sets 90-day remediation deadline for medium findings', () => {
    const entry = generatePOAMEntry({
      id: 'f-3',
      title: 'Medium Bug',
      severity: 'medium',
    });

    const scheduled = new Date(entry.scheduled_completion);
    const today = new Date(new Date().toISOString().split('T')[0]);
    const diffDays = Math.round((scheduled.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));

    expect(diffDays).toBe(90);
  });

  it('sets 180-day remediation deadline for low findings', () => {
    const entry = generatePOAMEntry({
      id: 'f-4',
      title: 'Low Bug',
      severity: 'low',
    });

    const scheduled = new Date(entry.scheduled_completion);
    const today = new Date(new Date().toISOString().split('T')[0]);
    const diffDays = Math.round((scheduled.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));

    expect(diffDays).toBe(180);
  });

  it('defaults to "Unclassified" weakness when no CWE', () => {
    const entry = generatePOAMEntry({
      id: 'f-5',
      title: 'No CWE',
      severity: 'medium',
    });

    expect(entry.weakness).toBe('Unclassified');
  });

  it('defaults to "Pending assessment" remediation when none provided', () => {
    const entry = generatePOAMEntry({
      id: 'f-6',
      title: 'No Remediation',
      severity: 'medium',
    });

    expect(entry.remediation).toBe('Pending assessment');
  });

  it('defaults to "moderate" remediation effort when none provided', () => {
    const entry = generatePOAMEntry({
      id: 'f-7',
      title: 'No Effort',
      severity: 'medium',
    });

    expect(entry.remediation_effort).toBe('moderate');
  });

  it('includes mapped controls in POA&M entry', () => {
    const entry = generatePOAMEntry({
      id: 'f-8',
      title: 'With Controls',
      cwe_id: 'CWE-89',
      severity: 'critical',
      nist_controls: ['IR-4'],
    });

    const controlIds = entry.controls.map((c) => c.control_id);
    // Should have CWE-mapped controls + explicit IR-4 + RA-5
    expect(controlIds).toContain('SI-10');
    expect(controlIds).toContain('IR-4');
    expect(controlIds).toContain('RA-5');
  });

  it('uses provided remediation_effort', () => {
    const entry = generatePOAMEntry({
      id: 'f-9',
      title: 'Custom Effort',
      severity: 'high',
      remediation_effort: 'low',
    });

    expect(entry.remediation_effort).toBe('low');
  });
});
