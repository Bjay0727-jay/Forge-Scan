import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleScanCompleted, handleVulnerabilityDetected } from './comply360-bridge';
import type { ForgeEvent } from './event-bus/types';

// Mock the compliance-core mapping module
vi.mock('./compliance-core/mapping', () => ({
  mapFindingToControls: vi.fn().mockReturnValue([
    { framework: 'nist-800-53', control_id: 'SI-10', control_name: 'Input Validation', relevance: 'primary' },
    { framework: 'nist-800-53', control_id: 'RA-5', control_name: 'Vulnerability Scanning', relevance: 'secondary' },
  ]),
  generatePOAMEntry: vi.fn().mockReturnValue({
    id: 'poam-gen-001',
    finding_title: 'SQL Injection',
    weakness: 'CWE-89',
    severity: 'critical',
    controls: [{ framework: 'nist-800-53', control_id: 'SI-10' }],
    remediation: 'Use parameterized queries',
    remediation_effort: 'moderate',
    scheduled_completion: '2024-06-01',
    milestones: ['Identify', 'Fix', 'Verify'],
    created_at: '2024-01-01T00:00:00Z',
  }),
}));

beforeEach(() => {
  vi.stubGlobal('crypto', {
    randomUUID: vi.fn().mockReturnValue('test-uuid'),
    subtle: { digest: vi.fn() },
  });
});

function createMockDB(options: {
  findings?: any[];
  existingPoam?: any;
} = {}) {
  const { findings = [], existingPoam = null } = options;
  let callIndex = 0;

  return {
    prepare: vi.fn().mockImplementation((sql: string) => {
      const isSelect = sql.trimStart().startsWith('SELECT');
      const isInsert = sql.trimStart().startsWith('INSERT');
      const isUpdate = sql.trimStart().startsWith('UPDATE');
      const isPoamCheck = sql.includes('poam_items') && isSelect;
      const isFindingsSelect = sql.includes('FROM findings') && isSelect;
      const isSingleFinding = sql.includes('WHERE id = ?') && isFindingsSelect;

      return {
        bind: vi.fn().mockReturnValue({
          run: vi.fn().mockResolvedValue({ success: true }),
          first: vi.fn().mockImplementation(() => {
            if (isPoamCheck) return Promise.resolve(existingPoam);
            if (isSingleFinding && findings.length > 0) return Promise.resolve(findings[0]);
            return Promise.resolve(null);
          }),
          all: vi.fn().mockImplementation(() => {
            if (isFindingsSelect) return Promise.resolve({ results: findings });
            return Promise.resolve({ results: [] });
          }),
        }),
      };
    }),
  } as unknown as D1Database;
}

function makeEvent(overrides: Partial<ForgeEvent> = {}): ForgeEvent {
  return {
    id: 'event-001',
    event_type: 'forge.scan.completed',
    source: 'forgescan',
    payload: {
      scan_id: 'scan-001',
      org_id: 'org-test-001',
    },
    metadata: { org_id: 'org-test-001' },
    created_at: '2024-01-15T00:00:00Z',
    ...overrides,
  };
}

describe('ForgeComply 360 Bridge', () => {
  describe('handleScanCompleted', () => {
    it('maps findings to controls and returns counts', async () => {
      const db = createMockDB({
        findings: [
          { id: 'f-1', title: 'SQL Injection', severity: 'critical', cve_id: null, solution: 'Fix it', metadata: '{"cwe":"CWE-89"}', vendor_id: '12345' },
          { id: 'f-2', title: 'XSS', severity: 'high', cve_id: null, solution: null, metadata: '{}', vendor_id: '12346' },
        ],
      });

      const result = await handleScanCompleted(db, makeEvent(), { auto_poam: true, auto_evidence: true });

      expect(result.controls_mapped).toBeGreaterThan(0);
      expect(result.findings_updated).toBe(2);
      expect(result.evidence_linked).toBe(1);
      expect(result.errors).toHaveLength(0);
    });

    it('generates POA&M for critical/high findings', async () => {
      const db = createMockDB({
        findings: [
          { id: 'f-1', title: 'RCE', severity: 'critical', cve_id: null, solution: 'Patch', metadata: '{}', vendor_id: '1' },
        ],
      });

      const result = await handleScanCompleted(db, makeEvent(), { auto_poam: true, auto_evidence: true });
      expect(result.poam_created).toBe(1);
    });

    it('skips POA&M when auto_poam is false', async () => {
      const db = createMockDB({
        findings: [
          { id: 'f-1', title: 'RCE', severity: 'critical', cve_id: null, solution: 'Patch', metadata: '{}', vendor_id: '1' },
        ],
      });

      const result = await handleScanCompleted(db, makeEvent(), { auto_poam: false, auto_evidence: false });
      expect(result.poam_created).toBe(0);
      expect(result.evidence_linked).toBe(0);
    });

    it('does not create duplicate POA&M entries', async () => {
      const db = createMockDB({
        findings: [
          { id: 'f-1', title: 'RCE', severity: 'critical', cve_id: null, solution: 'Patch', metadata: '{}', vendor_id: '1' },
        ],
        existingPoam: { id: 'existing-poam' },
      });

      const result = await handleScanCompleted(db, makeEvent(), { auto_poam: true, auto_evidence: true });
      expect(result.poam_created).toBe(0);
    });

    it('returns empty result when no org_id', async () => {
      const db = createMockDB();
      const event = makeEvent({ payload: {}, metadata: undefined });

      const result = await handleScanCompleted(db, event, {});
      expect(result.findings_updated).toBe(0);
      expect(result.controls_mapped).toBe(0);
    });

    it('skips medium/low findings for POA&M generation', async () => {
      const db = createMockDB({
        findings: [
          { id: 'f-1', title: 'Info leak', severity: 'medium', cve_id: null, solution: null, metadata: '{}', vendor_id: '1' },
        ],
      });

      const result = await handleScanCompleted(db, makeEvent(), { auto_poam: true, auto_evidence: true });
      expect(result.poam_created).toBe(0);
      expect(result.controls_mapped).toBeGreaterThan(0);
    });
  });

  describe('handleVulnerabilityDetected', () => {
    it('maps a single finding to controls', async () => {
      const db = createMockDB({
        findings: [
          { id: 'f-1', title: 'SQL Injection', severity: 'critical', cve_id: 'CVE-2024-0001', solution: 'Fix', metadata: '{"cwe":"CWE-89"}' },
        ],
      });

      const event = makeEvent({
        event_type: 'forge.vulnerability.detected',
        payload: { finding_id: 'f-1', org_id: 'org-test-001', severity: 'critical' },
      });

      const result = await handleVulnerabilityDetected(db, event, { auto_evidence: true });
      expect(result.controls_mapped).toBe(2);
      expect(result.findings_updated).toBe(1);
      expect(result.evidence_linked).toBe(1);
    });

    it('returns empty when finding_id is missing', async () => {
      const db = createMockDB();
      const event = makeEvent({
        event_type: 'forge.vulnerability.detected',
        payload: { org_id: 'org-test-001' },
      });

      const result = await handleVulnerabilityDetected(db, event, {});
      expect(result.findings_updated).toBe(0);
    });

    it('returns empty when finding not found in DB', async () => {
      const db = createMockDB({ findings: [] });
      const event = makeEvent({
        event_type: 'forge.vulnerability.detected',
        payload: { finding_id: 'nonexistent', org_id: 'org-test-001' },
      });

      const result = await handleVulnerabilityDetected(db, event, {});
      expect(result.findings_updated).toBe(0);
    });
  });
});
