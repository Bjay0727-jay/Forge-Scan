import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateSSP, generateAssessmentResults, generatePOAMDocument, oscalJsonToXml } from './oscal-generator';

beforeEach(() => {
  vi.stubGlobal('crypto', {
    randomUUID: vi.fn().mockReturnValue('test-uuid'),
  });
});

const mockFramework = {
  id: 'nist-800-53',
  name: 'NIST 800-53',
  version: 'Rev 5',
  description: 'Security and Privacy Controls',
};

const mockControls = [
  {
    id: 'ctrl-1', control_id: 'AC-2', name: 'Account Management',
    family: 'Access Control', description: 'Manage accounts',
    compliance_status: 'compliant', evidence: 'Tested via automated scan',
    assessed_at: '2024-01-15', assessed_by: 'user-001',
  },
  {
    id: 'ctrl-2', control_id: 'SI-10', name: 'Information Input Validation',
    family: 'System Integrity', description: 'Validate inputs',
    compliance_status: 'non_compliant',
  },
  {
    id: 'ctrl-3', control_id: 'RA-5', name: 'Vulnerability Scanning',
    family: 'Risk Assessment', description: 'Scan for vulns',
  },
];

describe('OSCAL Generator', () => {
  describe('generateSSP', () => {
    it('produces valid SSP structure', () => {
      const ssp = generateSSP(mockFramework, mockControls, 'Acme Corp');
      const root = ssp['system-security-plan'];
      expect(root).toBeDefined();
      expect(root.uuid).toBe('test-uuid');
      expect(root.metadata.title).toContain('NIST 800-53');
      expect(root.metadata['oscal-version']).toBe('1.1.2');
    });

    it('includes organization as party', () => {
      const ssp = generateSSP(mockFramework, mockControls, 'Acme Corp');
      const parties = ssp['system-security-plan'].metadata.parties;
      expect(parties).toHaveLength(1);
      expect(parties[0].name).toBe('Acme Corp');
      expect(parties[0].type).toBe('organization');
    });

    it('maps all controls to implemented-requirements', () => {
      const ssp = generateSSP(mockFramework, mockControls, 'Acme Corp');
      const reqs = ssp['system-security-plan']['control-implementation']['implemented-requirements'];
      expect(reqs).toHaveLength(3);
      expect(reqs[0]['control-id']).toBe('AC-2');
      expect(reqs[1]['control-id']).toBe('SI-10');
    });

    it('maps compliance status correctly', () => {
      const ssp = generateSSP(mockFramework, mockControls, 'Acme Corp');
      const reqs = ssp['system-security-plan']['control-implementation']['implemented-requirements'];

      const compliantProp = reqs[0].props.find((p: any) => p.name === 'implementation-status');
      expect(compliantProp.value).toBe('implemented');

      const nonCompliantProp = reqs[1].props.find((p: any) => p.name === 'implementation-status');
      expect(nonCompliantProp.value).toBe('planned');

      // null status maps to 'planned'
      const notAssessedProp = reqs[2].props.find((p: any) => p.name === 'implementation-status');
      expect(notAssessedProp.value).toBe('planned');
    });

    it('includes evidence as statement when present', () => {
      const ssp = generateSSP(mockFramework, mockControls, 'Acme Corp');
      const reqs = ssp['system-security-plan']['control-implementation']['implemented-requirements'];
      expect(reqs[0].statements).toBeDefined();
      expect(reqs[0].statements[0].description).toBe('Tested via automated scan');
      expect(reqs[1].statements).toBeUndefined();
    });
  });

  describe('generateAssessmentResults', () => {
    const mockFindings = [
      { id: 'f-1', title: 'SQL Injection', description: 'Desc', severity: 'critical', state: 'open', cve_id: 'CVE-2024-0001' },
      { id: 'f-2', title: 'XSS', description: 'Desc', severity: 'high', state: 'open' },
    ];

    it('produces valid assessment results structure', () => {
      const ar = generateAssessmentResults(mockFramework, mockControls, mockFindings as any, 'Acme Corp');
      const root = ar['assessment-results'];
      expect(root).toBeDefined();
      expect(root.metadata['oscal-version']).toBe('1.1.2');
      expect(root.results).toHaveLength(1);
    });

    it('includes findings with severity props', () => {
      const ar = generateAssessmentResults(mockFramework, mockControls, mockFindings as any, 'Acme Corp');
      const findings = ar['assessment-results'].results[0].findings;
      expect(findings).toHaveLength(2);
      expect(findings[0].title).toBe('SQL Injection');
      const sev = findings[0].props.find((p: any) => p.name === 'severity');
      expect(sev.value).toBe('critical');
    });

    it('marks open findings as not-satisfied', () => {
      const ar = generateAssessmentResults(mockFramework, mockControls, mockFindings as any, 'Acme Corp');
      const f = ar['assessment-results'].results[0].findings[0];
      expect(f.target.status.state).toBe('not-satisfied');
    });

    it('includes observations for assessed controls', () => {
      const ar = generateAssessmentResults(mockFramework, mockControls, mockFindings as any, 'Acme Corp');
      const obs = ar['assessment-results'].results[0].observations;
      // Only controls with compliance_status (first two)
      expect(obs).toHaveLength(2);
    });
  });

  describe('generatePOAMDocument', () => {
    const mockPOAM = [
      {
        id: 'poam-1', finding_title: 'SQL Injection', weakness: 'CWE-89',
        severity: 'critical', controls: JSON.stringify([{ control_id: 'SI-10' }]),
        remediation: 'Use parameterized queries', scheduled_completion: '2024-06-01',
        status: 'open', milestones: JSON.stringify(['Identify', 'Fix', 'Verify']),
      },
    ];

    it('produces valid POA&M structure', () => {
      const doc = generatePOAMDocument(mockPOAM as any, 'Acme Corp');
      const root = doc['plan-of-action-and-milestones'];
      expect(root).toBeDefined();
      expect(root.metadata['oscal-version']).toBe('1.1.2');
    });

    it('maps POA&M items with milestones', () => {
      const doc = generatePOAMDocument(mockPOAM as any, 'Acme Corp');
      const items = doc['plan-of-action-and-milestones']['poam-items'];
      expect(items).toHaveLength(1);
      expect(items[0].title).toBe('SQL Injection');
      expect(items[0].milestones).toHaveLength(3);
      expect(items[0].milestones[0].title).toBe('Identify');
    });

    it('includes severity and status props', () => {
      const doc = generatePOAMDocument(mockPOAM as any, 'Acme Corp');
      const item = doc['plan-of-action-and-milestones']['poam-items'][0];
      const sev = item.props.find((p: any) => p.name === 'severity');
      expect(sev.value).toBe('critical');
      const stat = item.props.find((p: any) => p.name === 'status');
      expect(stat.value).toBe('open');
    });

    it('handles empty milestones gracefully', () => {
      const noMilestones = [{ ...mockPOAM[0], milestones: '[]' }];
      const doc = generatePOAMDocument(noMilestones as any, 'Acme Corp');
      expect(doc['plan-of-action-and-milestones']['poam-items'][0].milestones).toHaveLength(0);
    });
  });

  describe('oscalJsonToXml', () => {
    it('produces well-formed XML with declaration', () => {
      const ssp = generateSSP(mockFramework, [mockControls[0]], 'Acme Corp');
      const xml = oscalJsonToXml(ssp);
      expect(xml).toMatch(/^<\?xml version="1\.0" encoding="UTF-8"\?>/);
      expect(xml).toContain('<system-security-plan');
      expect(xml).toContain('</system-security-plan>');
    });

    it('escapes special characters in XML', () => {
      const doc = {
        'test-doc': {
          title: 'Test & <Report>',
          description: "Quote's \"here\"",
        },
      };
      const xml = oscalJsonToXml(doc);
      expect(xml).toContain('&amp;');
      expect(xml).toContain('&lt;Report&gt;');
      expect(xml).toContain('&apos;');
    });

    it('handles arrays as repeated elements', () => {
      const doc = {
        'test-doc': {
          items: ['one', 'two', 'three'],
        },
      };
      const xml = oscalJsonToXml(doc);
      expect(xml).toContain('<items>one</items>');
      expect(xml).toContain('<items>two</items>');
      expect(xml).toContain('<items>three</items>');
    });
  });
});
