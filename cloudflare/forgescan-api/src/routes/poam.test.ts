import { describe, it, expect, vi } from 'vitest';
import { poam } from './poam';
import { createTestApp, createMockDB, createSequentialMockDB } from '../test-helpers';

// Mock the compliance mapping module
vi.mock('../services/compliance-core/mapping', () => ({
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
  mapFindingToControls: vi.fn().mockReturnValue([]),
}));

function createApp(db?: any) {
  return createTestApp(poam as any, '/api/v1/poam', db);
}

describe('POA&M Routes', () => {
  describe('GET /api/v1/poam', () => {
    it('lists POA&M items with pagination', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'poam-1', finding_title: 'SQL Injection', severity: 'critical', status: 'open' },
          { id: 'poam-2', finding_title: 'XSS', severity: 'high', status: 'in_progress' },
        ],
        firstResult: { total: 2 },
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam');
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.data).toHaveLength(2);
      expect(body.pagination.total).toBe(2);
    });

    it('supports status filter', async () => {
      const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam?status=open');
      expect(res.status).toBe(200);
    });
  });

  describe('GET /api/v1/poam/:id', () => {
    it('returns POA&M item by ID', async () => {
      const db = createMockDB({
        firstResult: { id: 'poam-1', finding_title: 'SQL Injection', severity: 'critical', status: 'open' },
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam/poam-1');
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.id).toBe('poam-1');
    });

    it('returns 404 for missing item', async () => {
      const db = createMockDB({ firstResult: null });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam/nonexistent');
      expect(res.status).toBe(404);
    });
  });

  describe('POST /api/v1/poam', () => {
    it('creates a POA&M item', async () => {
      const db = createMockDB();
      const app = createApp(db);

      const res = await app.request('/api/v1/poam', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding_title: 'SQL Injection',
          severity: 'critical',
          weakness: 'CWE-89',
          remediation: 'Use parameterized queries',
        }),
      });
      expect(res.status).toBe(201);
      const body = await res.json() as any;
      expect(body.id).toBeDefined();
      expect(body.message).toContain('created');
    });

    it('rejects missing required fields', async () => {
      const db = createMockDB();
      const app = createApp(db);

      const res = await app.request('/api/v1/poam', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ weakness: 'CWE-89' }),
      });
      expect(res.status).toBe(400);
    });
  });

  describe('PATCH /api/v1/poam/:id', () => {
    it('updates POA&M item fields', async () => {
      const db = createMockDB({ firstResult: { id: 'poam-1' } });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam/poam-1', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'in_progress', notes: 'Working on it' }),
      });
      expect(res.status).toBe(200);
    });

    it('returns 404 for missing item', async () => {
      const db = createMockDB({ firstResult: null });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam/nonexistent', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'completed' }),
      });
      expect(res.status).toBe(404);
    });

    it('rejects empty update', async () => {
      const db = createMockDB({ firstResult: { id: 'poam-1' } });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam/poam-1', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
    });
  });

  describe('DELETE /api/v1/poam/:id', () => {
    it('deletes POA&M item', async () => {
      const db = createMockDB();
      const app = createApp(db);

      const res = await app.request('/api/v1/poam/poam-1', { method: 'DELETE' });
      expect(res.status).toBe(200);
    });
  });

  describe('GET /api/v1/poam/stats/summary', () => {
    it('returns summary statistics', async () => {
      const db = createMockDB({
        allResults: [
          { status: 'open', count: 5 },
          { status: 'in_progress', count: 3 },
        ],
        firstResult: { count: 2 },
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam/stats/summary');
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.by_status).toBeDefined();
      expect(body.by_severity).toBeDefined();
      expect(body.overdue_count).toBeDefined();
    });
  });

  describe('POST /api/v1/poam/generate', () => {
    it('generates POA&M from findings', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'f-1', title: 'SQL Injection', severity: 'critical', cve_id: null, solution: 'Fix', metadata: '{}' },
        ],
        firstResult: null, // No existing POA&M
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity_filter: ['critical', 'high'] }),
      });
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.findings_processed).toBe(1);
      expect(body.poam_created).toBe(1);
    });

    it('skips findings with existing POA&M', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'f-1', title: 'SQL Injection', severity: 'critical', cve_id: null, solution: 'Fix', metadata: '{}' },
        ],
        firstResult: { id: 'existing-poam' }, // Existing POA&M
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/poam/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.poam_skipped).toBe(1);
      expect(body.poam_created).toBe(0);
    });
  });
});
