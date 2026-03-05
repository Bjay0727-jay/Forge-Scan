/**
 * OSCAL (Open Security Controls Assessment Language) Generator
 *
 * Generates OSCAL 1.1.2-compatible JSON documents for:
 *   - System Security Plan (SSP)
 *   - Assessment Results
 *   - POA&M
 *
 * Reference: https://pages.nist.gov/OSCAL/reference/
 */

export interface OSCALMetadata {
  title: string;
  version: string;
  oscalVersion: string;
  published: string;
  lastModified: string;
  parties: OSCALParty[];
}

export interface OSCALParty {
  uuid: string;
  type: 'organization' | 'person';
  name: string;
}

export interface FrameworkData {
  id: string;
  name: string;
  version: string;
  description: string;
}

export interface ControlData {
  id: string;
  control_id: string;
  name: string;
  family: string;
  description: string;
  compliance_status?: string;
  evidence?: string;
  assessed_at?: string;
  assessed_by?: string;
}

export interface FindingData {
  id: string;
  title: string;
  description: string;
  severity: string;
  state: string;
  cve_id?: string;
  asset_id?: string;
}

export interface POAMData {
  id: string;
  finding_title: string;
  weakness: string;
  severity: string;
  controls: string; // JSON stringified array
  remediation: string;
  scheduled_completion: string;
  status: string;
  milestones: string; // JSON stringified array
}

// ─── SSP Generation ─────────────────────────────────────────────────────────

export function generateSSP(
  framework: FrameworkData,
  controls: ControlData[],
  orgName: string,
): Record<string, any> {
  const uuid = crypto.randomUUID();
  const now = new Date().toISOString();
  const orgUuid = crypto.randomUUID();

  return {
    'system-security-plan': {
      uuid,
      metadata: {
        title: `System Security Plan - ${framework.name}`,
        'last-modified': now,
        version: '1.0.0',
        'oscal-version': '1.1.2',
        roles: [
          { id: 'system-owner', title: 'System Owner' },
          { id: 'authorizing-official', title: 'Authorizing Official' },
        ],
        parties: [
          {
            uuid: orgUuid,
            type: 'organization',
            name: orgName,
          },
        ],
      },
      'import-profile': {
        href: `#${framework.id}`,
      },
      'system-characteristics': {
        'system-ids': [{ id: framework.id }],
        'system-name': `${orgName} - ${framework.name}`,
        description: framework.description || `Security plan for ${framework.name}`,
        'security-sensitivity-level': 'moderate',
        'system-information': {
          'information-types': [
            {
              title: 'System Information',
              description: 'General system information managed by ForgeScan',
              'confidentiality-impact': { base: 'moderate' },
              'integrity-impact': { base: 'moderate' },
              'availability-impact': { base: 'low' },
            },
          ],
        },
        'security-impact-level': {
          'security-objective-confidentiality': 'moderate',
          'security-objective-integrity': 'moderate',
          'security-objective-availability': 'low',
        },
        status: { state: 'operational' },
        'authorization-boundary': {
          description: 'Authorization boundary as defined by the system owner',
        },
      },
      'system-implementation': {
        users: [
          {
            uuid: crypto.randomUUID(),
            'role-ids': ['system-owner'],
            props: [{ name: 'type', value: 'internal' }],
          },
        ],
        components: [
          {
            uuid: crypto.randomUUID(),
            type: 'this-system',
            title: orgName,
            description: `System managed under ${framework.name}`,
            status: { state: 'operational' },
          },
        ],
      },
      'control-implementation': {
        description: `Control implementation for ${framework.name}`,
        'implemented-requirements': controls.map((ctrl) => ({
          uuid: crypto.randomUUID(),
          'control-id': ctrl.control_id,
          description: ctrl.name,
          props: [
            {
              name: 'implementation-status',
              value: mapComplianceStatus(ctrl.compliance_status),
            },
          ],
          statements: ctrl.evidence
            ? [{
                'statement-id': `${ctrl.control_id}_smt`,
                uuid: crypto.randomUUID(),
                description: ctrl.evidence,
              }]
            : undefined,
        })),
      },
    },
  };
}

// ─── Assessment Results Generation ──────────────────────────────────────────

export function generateAssessmentResults(
  framework: FrameworkData,
  controls: ControlData[],
  findings: FindingData[],
  orgName: string,
): Record<string, any> {
  const uuid = crypto.randomUUID();
  const now = new Date().toISOString();

  return {
    'assessment-results': {
      uuid,
      metadata: {
        title: `Assessment Results - ${framework.name}`,
        'last-modified': now,
        version: '1.0.0',
        'oscal-version': '1.1.2',
        parties: [
          {
            uuid: crypto.randomUUID(),
            type: 'organization',
            name: orgName,
          },
        ],
      },
      'import-ap': {
        href: '#assessment-plan',
      },
      results: [
        {
          uuid: crypto.randomUUID(),
          title: `${framework.name} Assessment`,
          description: `Automated assessment results generated by ForgeScan`,
          start: now,
          'reviewed-controls': {
            'control-selections': [
              {
                description: 'All controls assessed',
                'include-all': {},
              },
            ],
          },
          findings: findings.map((f) => ({
            uuid: crypto.randomUUID(),
            title: f.title,
            description: f.description || f.title,
            props: [
              { name: 'severity', value: f.severity },
              { name: 'state', value: f.state },
            ],
            'target': {
              'type': 'finding',
              'target-id': f.id,
              status: { state: f.state === 'open' ? 'not-satisfied' : 'satisfied' },
            },
            ...(f.cve_id ? { 'related-observations': [{ description: `CVE: ${f.cve_id}` }] } : {}),
          })),
          observations: controls
            .filter((c) => c.compliance_status)
            .map((ctrl) => ({
              uuid: crypto.randomUUID(),
              title: `${ctrl.control_id}: ${ctrl.name}`,
              description: `Assessment of control ${ctrl.control_id}`,
              methods: ['EXAMINE', 'TEST'],
              props: [
                { name: 'status', value: mapComplianceStatus(ctrl.compliance_status) },
              ],
              collected: ctrl.assessed_at || now,
            })),
        },
      ],
    },
  };
}

// ─── POA&M Generation ───────────────────────────────────────────────────────

export function generatePOAMDocument(
  poamItems: POAMData[],
  orgName: string,
): Record<string, any> {
  const uuid = crypto.randomUUID();
  const now = new Date().toISOString();

  return {
    'plan-of-action-and-milestones': {
      uuid,
      metadata: {
        title: `Plan of Action and Milestones - ${orgName}`,
        'last-modified': now,
        version: '1.0.0',
        'oscal-version': '1.1.2',
        parties: [
          {
            uuid: crypto.randomUUID(),
            type: 'organization',
            name: orgName,
          },
        ],
      },
      'import-ssp': {
        href: '#ssp',
      },
      'poam-items': poamItems.map((item) => {
        let controls: any[] = [];
        try { controls = JSON.parse(item.controls); } catch { /* empty */ }
        let milestones: string[] = [];
        try { milestones = JSON.parse(item.milestones); } catch { /* empty */ }

        return {
          uuid: item.id,
          title: item.finding_title,
          description: `Weakness: ${item.weakness}. ${item.remediation}`,
          props: [
            { name: 'severity', value: item.severity },
            { name: 'status', value: item.status },
            { name: 'scheduled-completion', value: item.scheduled_completion },
          ],
          'related-findings': controls.map((ctrl: any) => ({
            'finding-uuid': crypto.randomUUID(),
            'objective-id': ctrl.control_id || ctrl,
          })),
          'risk': {
            uuid: crypto.randomUUID(),
            title: item.finding_title,
            description: `${item.severity} severity finding requiring remediation`,
            status: item.status,
          },
          milestones: milestones.map((ms, i) => ({
            uuid: crypto.randomUUID(),
            title: ms,
            'schedule': {
              'task-date': item.scheduled_completion,
            },
          })),
        };
      }),
    },
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function mapComplianceStatus(status?: string): string {
  switch (status) {
    case 'compliant': return 'implemented';
    case 'partial': return 'partially-implemented';
    case 'non_compliant': return 'planned';
    case 'not_assessed': return 'not-applicable';
    default: return 'planned';
  }
}

/**
 * Convert OSCAL JSON to simplified XML representation.
 * This produces a well-formed XML document suitable for OSCAL consumption.
 */
export function oscalJsonToXml(oscalJson: Record<string, any>): string {
  const rootKey = Object.keys(oscalJson)[0];
  const lines: string[] = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<${rootKey} xmlns="http://csrc.nist.gov/ns/oscal/1.0">`,
  ];
  jsonToXmlLines(oscalJson[rootKey], lines, 1);
  lines.push(`</${rootKey}>`);
  return lines.join('\n');
}

function jsonToXmlLines(obj: any, lines: string[], depth: number): void {
  const indent = '  '.repeat(depth);

  if (obj === null || obj === undefined) return;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (typeof item === 'object' && item !== null) {
        jsonToXmlLines(item, lines, depth);
      } else {
        lines.push(`${indent}${escapeXml(String(item))}`);
      }
    }
    return;
  }

  if (typeof obj !== 'object') {
    lines.push(`${indent}${escapeXml(String(obj))}`);
    return;
  }

  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) continue;

    if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'object' && item !== null) {
          lines.push(`${indent}<${key}>`);
          jsonToXmlLines(item, lines, depth + 1);
          lines.push(`${indent}</${key}>`);
        } else {
          lines.push(`${indent}<${key}>${escapeXml(String(item))}</${key}>`);
        }
      }
    } else if (typeof value === 'object') {
      lines.push(`${indent}<${key}>`);
      jsonToXmlLines(value, lines, depth + 1);
      lines.push(`${indent}</${key}>`);
    } else {
      lines.push(`${indent}<${key}>${escapeXml(String(value))}</${key}>`);
    }
  }
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
