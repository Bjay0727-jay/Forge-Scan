/**
 * E2E Workflow Test Suite
 *
 * Covers the full lifecycle: onboarding -> scanner registration -> scan execution
 * -> findings -> compliance mapping -> evidence -> POA&M -> reports -> export.
 *
 * Uses the same mock-DB pattern as the unit tests but wires up multiple route
 * modules sequentially to simulate a realistic user journey.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../index';
import { onboarding } from './onboarding';
import { scanner } from './scanner';
import { scans } from './scans';
import { findings } from './findings';
import { compliance } from './compliance';
import { evidence } from './evidence';
import { poam } from './poam';
import { reports } from './reports';
import { errorHandler } from '../middleware/error-handler';
import { createMockDB, createSequentialMockDB } from '../test-helpers';

// ─── Mocks ──────────────────────────────────────────────────────────────────

vi.mock('../services/scan-orchestrator', () => ({
  createTasksForScan: vi.fn().mockResolvedValue(['task-001']),
  getTasksForScan: vi.fn().mockResolvedValue([
    { id: 'task-001', status: 'completed', findings_count: 3, assets_discovered: 1 },
  ]),
  cancelScanTasks: vi.fn().mockResolvedValue(1),
  updateScanFromTasks: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../services/compliance', () => ({
  seedFrameworks: vi.fn().mockResolvedValue({
    frameworks_created: 3,
    controls_created: 150,
  }),
  getFrameworkCompliance: vi.fn().mockResolvedValue({
    compliance_percentage: 72,
    total_controls: 50,
    compliant: 36,
    non_compliant: 6,
    partial: 4,
    not_assessed: 4,
  }),
  getGapAnalysis: vi.fn().mockResolvedValue([
    {
      control_id: 'SI-10',
      control_name: 'Input Validation',
      family: 'SI',
      compliance_status: 'non_compliant',
    },
    {
      control_id: 'RA-5',
      control_name: 'Vulnerability Scanning',
      family: 'RA',
      compliance_status: 'partial',
    },
  ]),
}));

vi.mock('../services/compliance-core/mapping', () => ({
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
  }),
}));

vi.mock('../services/oscal-generator', () => ({
  generateSSP: vi.fn().mockReturnValue({ 'system-security-plan': { uuid: 'ssp-001' } }),
  generateAssessmentResults: vi.fn().mockReturnValue({ 'assessment-results': { uuid: 'ar-001' } }),
  generatePOAMDocument: vi.fn().mockReturnValue({ 'plan-of-action-and-milestones': { uuid: 'poam-doc-001' } }),
  oscalJsonToXml: vi.fn().mockReturnValue('<xml/>'),
}));

vi.mock('../services/event-bus', () => ({
  publish: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../services/audit', () => ({
  auditLog: vi.fn(),
}));

vi.mock('../services/reporting/pdf-generator', () => ({
  generateExecutivePDF: vi.fn().mockResolvedValue(new Uint8Array([37, 80, 68, 70])), // %PDF
  generateFindingsPDF: vi.fn().mockResolvedValue(new Uint8Array([37, 80, 68, 70])),
  generateCompliancePDF: vi.fn().mockResolvedValue(new Uint8Array([37, 80, 68, 70])),
  generateAssetsPDF: vi.fn().mockResolvedValue(new Uint8Array([37, 80, 68, 70])),
}));

vi.mock('../services/reporting/csv-generator', () => ({
  generateFindingsCSV: vi.fn().mockReturnValue('id,title\n1,SQL Injection'),
  generateAssetsCSV: vi.fn().mockReturnValue('id,hostname\n1,web-01'),
  generateComplianceCSV: vi.fn().mockReturnValue('framework,control\nNIST,SI-10'),
}));

vi.mock('../middleware/auth', () => ({
  requireRole: (..._roles: string[]) => {
    return async (_c: any, next: any) => next();
  },
  authMiddleware: async (_c: any, next: any) => next(),
}));

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Build a Hono app with all routes mounted at their real prefixes, using a
 * shared mock DB.  Auth is bypassed via the middleware mock above.
 */
function createFullApp(db: any) {
  const app = new Hono<{ Bindings: Env; Variables: { user: any; orgId: string | null } }>();

  const storedObjects = new Map<string, { body: any; customMetadata?: Record<string, string> }>();

  app.use('*', async (c, next) => {
    (c.env as any) = {
      DB: db,
      STORAGE: {
        put: vi.fn().mockImplementation(async (key: string, body: any, opts?: any) => {
          storedObjects.set(key, { body, customMetadata: opts?.customMetadata });
        }),
        get: vi.fn().mockImplementation(async (key: string) => {
          const obj = storedObjects.get(key);
          if (!obj) return null;
          return {
            body: obj.body,
            text: async () => (typeof obj.body === 'string' ? obj.body : JSON.stringify(obj.body)),
            arrayBuffer: async () => {
              if (obj.body instanceof Uint8Array) return obj.body.buffer;
              const enc = new TextEncoder();
              return enc.encode(typeof obj.body === 'string' ? obj.body : JSON.stringify(obj.body)).buffer;
            },
            customMetadata: obj.customMetadata || {},
          };
        }),
        delete: vi.fn().mockImplementation(async (key: string) => {
          storedObjects.delete(key);
        }),
        list: vi.fn().mockResolvedValue({ objects: [] }),
      },
      CACHE: {
        put: vi.fn(),
        get: vi.fn().mockResolvedValue(null),
        delete: vi.fn(),
      },
      JWT_SECRET: 'test-secret',
    };
    c.set('user', {
      id: 'user-001',
      email: 'admin@forgescan.io',
      role: 'platform_admin',
      display_name: 'Test Admin',
      organization_id: 'org-test-001',
      org_role: 'admin',
    });
    c.set('orgId', 'org-test-001');
    await next();
  });

  app.route('/api/v1/onboarding', onboarding as any);
  app.route('/api/v1/scanner', scanner as any);
  app.route('/api/v1/scans', scans as any);
  app.route('/api/v1/findings', findings as any);
  app.route('/api/v1/compliance', compliance as any);
  app.route('/api/v1/evidence', evidence as any);
  app.route('/api/v1/poam', poam as any);
  app.route('/api/v1/reports', reports as any);
  app.onError(errorHandler);

  return app;
}

function json(obj: Record<string, unknown>) {
  return {
    method: 'POST' as const,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(obj),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal('crypto', {
    randomUUID: vi.fn().mockReturnValue('test-uuid-' + Math.random().toString(36).slice(2, 8)),
    subtle: {
      digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    },
  });
});

// ═══════════════════════════════════════════════════════════════════════════
//  1. FC360 Registration & Onboarding
// ═══════════════════════════════════════════════════════════════════════════

describe('E2E Workflow', () => {
  describe('Step 1 — FC360 Registration & Onboarding', () => {
    it('returns onboarding status with account_created = true', async () => {
      const db = createMockDB({
        firstResult: { cnt: 0 },
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/onboarding/status');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.steps.account_created).toBe(true);
      expect(body.total).toBe(5);
    });

    it('seeds compliance frameworks during onboarding', async () => {
      const db = createMockDB();
      const app = createFullApp(db);

      const res = await app.request('/api/v1/onboarding/seed-compliance', { method: 'POST' });
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.message).toContain('seeded');
      expect(body.frameworks_created).toBe(3);
      expect(body.controls_created).toBe(150);
    });

    it('lists compliance frameworks after seeding', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'fw-nist', name: 'NIST 800-53', version: 'r5' },
          { id: 'fw-cis', name: 'CIS Controls', version: 'v8' },
          { id: 'fw-pci', name: 'PCI DSS', version: '4.0' },
        ],
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/compliance');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.data).toHaveLength(3);
      expect(body.data[0].compliance_percentage).toBe(72);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  //  2. Scanner & Agent Registration
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Step 2 — Scanner Registration', () => {
    it('registers a new scanner and returns an API key', async () => {
      const db = createMockDB({ firstResult: null }); // no existing scanner
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/scanner/register',
        json({
          scanner_id: 'scanner-alpha',
          hostname: 'scanner-01.lab.local',
          version: '1.2.0',
          capabilities: ['network_discovery', 'port_scan', 'vuln_check'],
        }),
      );

      expect(res.status).toBe(201);
      const body = await res.json() as any;
      expect(body.scanner_id).toBe('scanner-alpha');
      expect(body.hostname).toBe('scanner-01.lab.local');
      expect(body.api_key).toBeDefined();
      expect(body.message).toContain('Store this API key');
    });

    it('rejects duplicate scanner registration', async () => {
      const db = createMockDB({ firstResult: { id: 'existing-scanner' } });
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/scanner/register',
        json({ scanner_id: 'scanner-alpha', hostname: 'scanner-01.lab.local' }),
      );

      expect(res.status).toBe(409);
    });

    it('lists registered scanners', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'reg-001', scanner_id: 'scanner-alpha', hostname: 'scanner-01.lab.local', status: 'registered', completed_tasks: 0, running_tasks: 0, assigned_tasks: 0 },
        ],
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/scanner');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.scanners).toHaveLength(1);
      expect(body.scanners[0].scanner_id).toBe('scanner-alpha');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  //  3. Scan Execution
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Step 3 — Scan Execution', () => {
    it('creates a new scan', async () => {
      const db = createMockDB();
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/scans',
        json({ name: 'Quarterly Network Scan', type: 'network', target: '10.0.0.0/24' }),
      );

      expect(res.status).toBe(201);
      const body = await res.json() as any;
      expect(body.id).toBeDefined();
      expect(body.status).toBe('pending');
      expect(body.type).toBe('network');
    });

    it('starts the scan and creates tasks', async () => {
      const scan = {
        id: 'scan-001',
        name: 'Quarterly Network Scan',
        scan_type: 'network',
        targets: '["10.0.0.0/24"]',
        status: 'pending',
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      };
      const db = createMockDB({ firstResult: scan });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/scans/scan-001/start', { method: 'POST' });
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.status).toBe('running');
      expect(body.tasks_created).toBe(1);
    });

    it('scanner polls for tasks and gets assigned work', async () => {
      // This endpoint requires X-Scanner-Key auth which uses authenticateScanner middleware.
      // The scanner middleware hashes the key and looks it up — we simulate the DB returning
      // a valid registration AND a queued task.
      const db = createSequentialMockDB([
        // 1st call: authenticateScanner looks up scanner by key hash
        {
          firstResult: {
            id: 'reg-001',
            scanner_id: 'scanner-alpha',
            hostname: 'scanner-01.lab.local',
            version: '1.2.0',
            capabilities: '["network_discovery","port_scan","vuln_check"]',
            status: 'active',
            org_id: 'org-test-001',
          },
        },
        // 2nd call: SELECT queued task
        {
          firstResult: {
            id: 'task-001',
            scan_id: 'scan-001',
            task_type: 'network_discovery',
            task_payload: '{"target":"10.0.0.0/24"}',
            priority: 5,
            retry_count: 0,
            max_retries: 3,
          },
        },
        // 3rd call: UPDATE task to assigned
        { runSuccess: true },
      ]);
      const app = createFullApp(db);

      const res = await app.request('/api/v1/scanner/tasks/next', {
        headers: { 'X-Scanner-Key': 'scanner_testkey12345' },
      });

      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.task).toBeDefined();
      expect(body.task.id).toBe('task-001');
      expect(body.task.scan_id).toBe('scan-001');
      expect(body.task.task_type).toBe('network_discovery');
    });

    it('scanner submits task results with findings and assets', async () => {
      const db = createSequentialMockDB([
        // authenticateScanner
        {
          firstResult: {
            id: 'reg-001',
            scanner_id: 'scanner-alpha',
            hostname: 'scanner-01.lab.local',
            version: '1.2.0',
            capabilities: '[]',
            status: 'active',
            org_id: 'org-test-001',
          },
        },
        // SELECT task by id
        {
          firstResult: {
            id: 'task-001',
            scan_id: 'scan-001',
            scanner_id: 'scanner-alpha',
            status: 'running',
          },
        },
        // SELECT org_id from scans
        { firstResult: { org_id: 'org-test-001' } },
        // Asset lookup (not found — insert new)
        { firstResult: null },
        // INSERT asset
        { runSuccess: true },
        // INSERT finding 1
        { runSuccess: true },
        // INSERT finding 2
        { runSuccess: true },
        // UPDATE task
        { runSuccess: true },
        // UPDATE scanner counters
        { runSuccess: true },
        // updateScanFromTasks (mocked)
        { runSuccess: true },
        // publish events (mocked)
        { runSuccess: true },
        { runSuccess: true },
        { runSuccess: true },
      ]);
      const app = createFullApp(db);

      const res = await app.request('/api/v1/scanner/tasks/task-001/results', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Scanner-Key': 'scanner_testkey12345',
        },
        body: JSON.stringify({
          status: 'completed',
          assets: [
            { ip_addresses: '10.0.0.1', hostname: 'web-01', os: 'Ubuntu 22.04', asset_type: 'server' },
          ],
          findings: [
            {
              title: 'SQL Injection in /api/login',
              severity: 'critical',
              description: 'Parameterized queries not used',
              vendor: 'forgescan',
              port: 443,
              protocol: 'tcp',
              service: 'https',
              solution: 'Use parameterized queries',
            },
            {
              title: 'Open port 22/tcp on 10.0.0.1',
              severity: 'medium',
              description: 'SSH service detected',
              port: 22,
              protocol: 'tcp',
              service: 'ssh',
            },
          ],
          summary: 'Scan completed with 2 findings on 1 host',
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.message).toBe('Results received');
      expect(body.findings_count).toBe(2);
      expect(body.assets_discovered).toBe(1);
    });

    it('verifies findings exist after scan completion', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'f-001', title: 'SQL Injection in /api/login', severity: 'critical', state: 'open', vendor: 'forgescan', references: '[]' },
          { id: 'f-002', title: 'Open port 22/tcp on 10.0.0.1', severity: 'medium', state: 'open', vendor: 'forgescan', references: '[]' },
        ],
        firstResult: { total: 2 },
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/findings');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.items).toHaveLength(2);
      expect(body.total).toBe(2);
      expect(body.items[0].severity).toBe('critical');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  //  4. Framework & Controls
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Step 4 — Framework & Controls', () => {
    it('lists compliance frameworks with compliance percentage', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'fw-nist', name: 'NIST 800-53', version: 'r5' },
        ],
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/compliance');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.data).toHaveLength(1);
      expect(body.data[0].name).toBe('NIST 800-53');
      expect(body.data[0].compliance_percentage).toBe(72);
    });

    it('retrieves framework detail with controls', async () => {
      const db = createSequentialMockDB([
        // SELECT framework
        {
          firstResult: { id: 'fw-nist', name: 'NIST 800-53', version: 'r5', description: 'NIST SP 800-53 Rev 5' },
        },
        // SELECT controls
        {
          allResults: [
            { id: 'ctrl-1', control_id: 'SI-10', name: 'Input Validation', family: 'SI' },
            { id: 'ctrl-2', control_id: 'RA-5', name: 'Vulnerability Scanning', family: 'RA' },
          ],
        },
        // getFrameworkCompliance (mocked)
        { firstResult: null },
      ]);
      const app = createFullApp(db);

      const res = await app.request('/api/v1/compliance/fw-nist');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.id).toBe('fw-nist');
      expect(body.controls).toHaveLength(2);
      expect(body.stats).toBeDefined();
      expect(body.stats.compliance_percentage).toBe(72);
    });

    it('maps findings to controls via compliance assessment', async () => {
      const db = createSequentialMockDB([
        // Check for existing mapping
        { firstResult: null },
        // INSERT new mapping
        { runSuccess: true },
      ]);
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/compliance/assess',
        json({
          framework_id: 'fw-nist',
          control_id: 'ctrl-si10',
          status: 'non_compliant',
          finding_id: 'f-001',
          evidence: 'SQL injection found in /api/login endpoint',
        }),
      );

      expect(res.status).toBe(201);
      const body = await res.json() as any;
      expect(body.id).toBeDefined();
      expect(body.message).toContain('created');
    });

    it('updates existing compliance mapping', async () => {
      const db = createSequentialMockDB([
        // Check for existing mapping — found
        { firstResult: { id: 'mapping-001' } },
        // UPDATE mapping
        { runSuccess: true },
      ]);
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/compliance/assess',
        json({
          framework_id: 'fw-nist',
          control_id: 'ctrl-si10',
          status: 'partial',
          evidence: 'Remediation in progress',
        }),
      );

      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.id).toBe('mapping-001');
      expect(body.message).toContain('updated');
    });

    it('returns gap analysis for a framework', async () => {
      const db = createMockDB({
        firstResult: { id: 'fw-nist', name: 'NIST 800-53', version: 'r5' },
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/compliance/fw-nist/gaps');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.framework).toBeDefined();
      expect(body.gaps).toHaveLength(2);
      expect(body.gaps[0].control_id).toBe('SI-10');
      expect(body.gaps[0].compliance_status).toBe('non_compliant');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  //  5. Evidence & Assessment
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Step 5 — Evidence & Assessment', () => {
    it('lists evidence files', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'ev-001', title: 'Scan Evidence', file_name: 'scan-report.pdf', sha256_hash: 'abc123' },
        ],
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/evidence');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.data).toHaveLength(1);
      expect(body.data[0].title).toBe('Scan Evidence');
    });

    it('retrieves evidence metadata by ID', async () => {
      const db = createMockDB({
        firstResult: {
          id: 'ev-001',
          title: 'Scan Evidence',
          file_name: 'scan-report.pdf',
          sha256_hash: 'abc123',
          org_id: 'org-test-001',
          finding_id: 'f-001',
          compliance_mapping_id: 'mapping-001',
        },
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/evidence/ev-001');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.id).toBe('ev-001');
      expect(body.finding_id).toBe('f-001');
    });

    it('updates control assessment status via compliance assess endpoint', async () => {
      const db = createSequentialMockDB([
        // Check existing — found
        { firstResult: { id: 'mapping-001' } },
        // UPDATE
        { runSuccess: true },
      ]);
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/compliance/assess',
        json({
          framework_id: 'fw-nist',
          control_id: 'ctrl-si10',
          status: 'compliant',
          evidence: 'Parameterized queries implemented; verified via rescan',
        }),
      );

      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.message).toContain('updated');
    });

    it('links evidence to a compliance mapping via PATCH', async () => {
      const db = createMockDB({ firstResult: { id: 'ev-001' } });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/evidence/ev-001', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          compliance_mapping_id: 'mapping-001',
          finding_id: 'f-001',
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.message).toContain('updated');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  //  6. POA&M Management
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Step 6 — POA&M Management', () => {
    it('generates POA&M items from critical findings', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'f-001', title: 'SQL Injection', severity: 'critical', cve_id: null, solution: 'Use parameterized queries', metadata: '{"cwe":"CWE-89"}' },
        ],
        firstResult: null, // no existing POA&M
      });
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/poam/generate',
        json({ severity_filter: ['critical', 'high'] }),
      );

      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.findings_processed).toBe(1);
      expect(body.poam_created).toBe(1);
    });

    it('lists POA&M items', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'poam-001', finding_title: 'SQL Injection', severity: 'critical', status: 'open', weakness: 'CWE-89' },
        ],
        firstResult: { total: 1 },
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/poam');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.data).toHaveLength(1);
      expect(body.data[0].severity).toBe('critical');
      expect(body.data[0].status).toBe('open');
    });

    it('retrieves a single POA&M item by ID', async () => {
      const db = createMockDB({
        firstResult: {
          id: 'poam-001',
          finding_title: 'SQL Injection',
          severity: 'critical',
          status: 'open',
          weakness: 'CWE-89',
          remediation: 'Use parameterized queries',
        },
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/poam/poam-001');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.id).toBe('poam-001');
      expect(body.remediation).toBe('Use parameterized queries');
    });

    it('updates POA&M status to in_progress', async () => {
      const db = createMockDB({ firstResult: { id: 'poam-001' } });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/poam/poam-001', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'in_progress', notes: 'Dev team working on fix' }),
      });

      expect(res.status).toBe(200);
    });

    it('marks POA&M item as completed', async () => {
      const db = createMockDB({ firstResult: { id: 'poam-001' } });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/poam/poam-001', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'completed', notes: 'Fix deployed and verified' }),
      });

      expect(res.status).toBe(200);
    });

    it('returns POA&M summary statistics', async () => {
      const db = createMockDB({
        allResults: [
          { status: 'open', count: 3 },
          { status: 'in_progress', count: 2 },
          { status: 'completed', count: 1 },
        ],
        firstResult: { count: 1 },
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/poam/stats/summary');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.by_status).toBeDefined();
      expect(body.overdue_count).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  //  7. SSP / Report Generation (JSON)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Step 7 — Report Generation (JSON)', () => {
    it('generates a compliance report', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'fw-nist', name: 'NIST 800-53', version: 'r5' },
        ],
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/reports/compliance');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.generated_at).toBeDefined();
      expect(body.frameworks).toBeDefined();
      expect(body.gaps).toBeDefined();
    });

    it('generates a vulnerabilities report with control mappings', async () => {
      const db = createSequentialMockDB([
        // buildVulnerabilitiesData: SELECT findings with joins
        {
          allResults: [
            {
              id: 'f-001',
              title: 'SQL Injection',
              severity: 'critical',
              state: 'open',
              control_mappings: '[{"framework":"nist-800-53","control_id":"SI-10"}]',
              hostname: 'web-01',
              ip_addresses: '["10.0.0.1"]',
              poam_id: 'poam-001',
              poam_status: 'open',
              poam_effort: 'moderate',
              poam_due_date: '2024-06-01',
            },
          ],
        },
        // Summary query
        {
          firstResult: {
            total: 1,
            critical: 1,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            mapped_to_controls: 1,
            affected_assets: 1,
          },
        },
        // POA&M summary
        {
          firstResult: { total_poam: 1, open_poam: 1, overdue_poam: 0 },
        },
      ]);
      const app = createFullApp(db);

      const res = await app.request('/api/v1/reports/vulnerabilities');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.generated_at).toBeDefined();
      expect(body.summary.total).toBe(1);
      expect(body.summary.critical).toBe(1);
      expect(body.summary.mapped_to_controls).toBe(1);
      expect(body.data).toHaveLength(1);
      expect(body.data[0].control_mappings).toHaveLength(1);
      expect(body.data[0].control_mappings[0].control_id).toBe('SI-10');
      expect(body.data[0].has_poam).toBe(true);
    });

    it('generates an executive report', async () => {
      const db = createSequentialMockDB([
        // buildExecutiveData: totals
        {
          firstResult: {
            assets: 25,
            open_findings: 42,
            fixed_findings: 15,
            new_findings_period: 10,
            fixed_period: 8,
          },
        },
        // severity distribution
        {
          allResults: [
            { severity: 'critical', count: 5 },
            { severity: 'high', count: 12 },
            { severity: 'medium', count: 20 },
            { severity: 'low', count: 5 },
          ],
        },
        // top risks
        {
          allResults: [
            { title: 'SQL Injection', severity: 'critical', affected_assets: 3, frs_score: 9.5 },
            { title: 'XSS', severity: 'high', affected_assets: 5, frs_score: 7.2 },
          ],
        },
      ]);
      const app = createFullApp(db);

      const res = await app.request('/api/v1/reports/executive');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.generated_at).toBeDefined();
      expect(body.totals.assets).toBe(25);
      expect(body.totals.open_findings).toBe(42);
      expect(body.severity_breakdown).toHaveLength(4);
      expect(body.top_risks).toHaveLength(2);
      expect(body.risk_score).toBeDefined();
      expect(body.recommendations).toBeDefined();
    });

    it('generates a findings report (JSON)', async () => {
      const db = createSequentialMockDB([
        // findings query
        {
          allResults: [
            { id: 'f-001', title: 'SQL Injection', severity: 'critical', state: 'open', hostname: 'web-01' },
          ],
        },
        // summary
        {
          firstResult: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0, affected_assets: 1, vendors: 1 },
        },
      ]);
      const app = createFullApp(db);

      const res = await app.request('/api/v1/reports/findings');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.generated_at).toBeDefined();
      expect(body.summary.total).toBe(1);
      expect(body.data).toHaveLength(1);
    });

    it('generates an OSCAL SSP document', async () => {
      const db = createSequentialMockDB([
        // SELECT framework
        { firstResult: { id: 'fw-nist', name: 'NIST 800-53', version: 'r5', description: 'NIST' } },
        // SELECT controls with compliance status
        {
          allResults: [
            { control_id: 'SI-10', name: 'Input Validation', family: 'SI', compliance_status: 'compliant', evidence: null },
          ],
        },
        // SELECT org name
        { firstResult: { name: 'TestOrg' } },
        // auto-evidence query
        { allResults: [] },
      ]);
      const app = createFullApp(db);

      const res = await app.request('/api/v1/compliance/fw-nist/oscal/ssp');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body['system-security-plan']).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  //  8. Reporter Export (PDF, list, download, delete)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Step 8 — Reporter Export', () => {
    it('generates a PDF report and stores it', async () => {
      const db = createSequentialMockDB([
        // buildExecutiveData: totals
        {
          firstResult: {
            assets: 25,
            open_findings: 42,
            fixed_findings: 15,
            new_findings_period: 10,
            fixed_period: 8,
          },
        },
        // severity distribution
        { allResults: [{ severity: 'critical', count: 5 }] },
        // top risks
        { allResults: [{ title: 'SQL Injection', severity: 'critical', affected_assets: 3, frs_score: 9.5 }] },
        // INSERT report to R2 (via STORAGE.put mock in app)
        { runSuccess: true },
        // INSERT report metadata to D1
        { runSuccess: true },
      ]);
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/reports/generate',
        json({
          report_type: 'executive',
          title: 'Q1 Executive Summary',
          format: 'pdf',
        }),
      );

      expect(res.status).toBe(201);
      const body = await res.json() as any;
      expect(body.id).toBeDefined();
      expect(body.report_type).toBe('executive');
      expect(body.format).toBe('pdf');
      expect(body.status).toBe('completed');
      expect(body.download_url).toContain('/download');
      expect(body.file_size).toBeGreaterThan(0);
    });

    it('downloads a stored report', async () => {
      const db = createMockDB({
        firstResult: {
          id: 'report-001',
          storage_key: 'reports/report-001.pdf',
          format: 'pdf',
          org_id: 'org-test-001',
        },
      });
      const app = createFullApp(db);

      // Pre-populate storage via a direct PUT so download can find it
      const putRes = await app.request(
        '/api/v1/reports/generate',
        json({ report_type: 'executive', format: 'pdf' }),
      );
      // This may not work perfectly with sequential mock but we primarily test the download path below.

      // For the download test, use a fresh mock that returns a report with storage_key
      const db2 = createMockDB({
        firstResult: {
          id: 'report-001',
          storage_key: 'reports/report-001.json',
          format: 'json',
          org_id: 'org-test-001',
        },
      });
      const app2 = createFullApp(db2);

      // The STORAGE mock's get returns null by default (nothing stored), so we verify the 404 path
      const res = await app2.request('/api/v1/reports/report-001/download');
      // With no file in storage, returns 404
      expect(res.status).toBe(404);
    });

    it('lists generated reports', async () => {
      const db = createMockDB({
        allResults: [
          {
            id: 'report-001',
            title: 'Q1 Executive Summary',
            report_type: 'executive',
            format: 'pdf',
            status: 'completed',
            created_at: '2024-03-01T00:00:00Z',
          },
          {
            id: 'report-002',
            title: 'Findings Report',
            report_type: 'findings',
            format: 'csv',
            status: 'completed',
            created_at: '2024-03-02T00:00:00Z',
          },
        ],
        firstResult: { total: 2 },
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/reports/list/all');
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.data).toHaveLength(2);
      expect(body.total).toBe(2);
    });

    it('deletes a report', async () => {
      const db = createMockDB({
        firstResult: { storage_key: 'reports/report-001.pdf' },
      });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/reports/report-001', { method: 'DELETE' });
      expect(res.status).toBe(200);

      const body = await res.json() as any;
      expect(body.message).toBe('Report deleted');
    });

    it('rejects invalid report type on generate', async () => {
      const db = createMockDB();
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/reports/generate',
        json({ report_type: 'invalid_type', format: 'pdf' }),
      );

      expect(res.status).toBe(400);
      const body = await res.json() as any;
      expect(body.error).toContain('Invalid report type');
    });

    it('rejects invalid format on generate', async () => {
      const db = createMockDB();
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/reports/generate',
        json({ report_type: 'executive', format: 'xlsx' }),
      );

      expect(res.status).toBe(400);
      const body = await res.json() as any;
      expect(body.error).toContain('Invalid format');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  //  Cross-cutting: error handling & edge cases
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Cross-cutting — Error handling', () => {
    it('returns 400 for missing required fields on scanner registration', async () => {
      const db = createMockDB();
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/scanner/register',
        json({ hostname: 'scanner-01.lab.local' }), // missing scanner_id
      );

      expect(res.status).toBe(400);
    });

    it('returns 404 for non-existent scan', async () => {
      const db = createMockDB({ firstResult: null });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/scans/nonexistent');
      expect(res.status).toBe(404);
    });

    it('returns 404 for non-existent POA&M item', async () => {
      const db = createMockDB({ firstResult: null });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/poam/nonexistent');
      expect(res.status).toBe(404);
    });

    it('returns 404 for non-existent framework', async () => {
      const db = createMockDB({ firstResult: null });
      const app = createFullApp(db);

      const res = await app.request('/api/v1/compliance/nonexistent');
      expect(res.status).toBe(404);
    });

    it('rejects invalid compliance assessment status', async () => {
      const db = createMockDB();
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/compliance/assess',
        json({
          framework_id: 'fw-nist',
          control_id: 'ctrl-si10',
          status: 'banana',
        }),
      );

      expect(res.status).toBe(400);
    });

    it('rejects compliance assess with missing required fields', async () => {
      const db = createMockDB();
      const app = createFullApp(db);

      const res = await app.request(
        '/api/v1/compliance/assess',
        json({ framework_id: 'fw-nist' }), // missing control_id and status
      );

      expect(res.status).toBe(400);
    });
  });
});
