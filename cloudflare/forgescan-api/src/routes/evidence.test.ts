import { describe, it, expect, vi } from 'vitest';
import { evidence } from './evidence';
import { createTestApp, createMockDB } from '../test-helpers';

function createApp(db?: any) {
  return createTestApp(evidence as any, '/api/v1/evidence', db);
}

describe('Evidence Vault Routes', () => {
  describe('GET /api/v1/evidence', () => {
    it('lists evidence files', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'ev-1', title: 'Scan Report', file_name: 'report.pdf', sha256_hash: 'abc123' },
          { id: 'ev-2', title: 'Audit Log', file_name: 'audit.csv', sha256_hash: 'def456' },
        ],
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence');
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.data).toHaveLength(2);
      expect(body.pagination).toBeDefined();
    });

    it('supports finding_id filter', async () => {
      const db = createMockDB({ allResults: [] });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence?finding_id=f-001');
      expect(res.status).toBe(200);
      expect(db.prepare).toHaveBeenCalled();
    });
  });

  describe('GET /api/v1/evidence/:id', () => {
    it('returns evidence file metadata', async () => {
      const db = createMockDB({
        firstResult: { id: 'ev-1', title: 'Scan Report', sha256_hash: 'abc123', org_id: 'org-test-001' },
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence/ev-1');
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.id).toBe('ev-1');
    });

    it('returns 404 for missing evidence', async () => {
      const db = createMockDB({ firstResult: null });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence/nonexistent');
      expect(res.status).toBe(404);
    });
  });

  describe('POST /api/v1/evidence/:id/verify', () => {
    it('returns not-found when file missing from storage', async () => {
      const mockStorage = {
        get: vi.fn().mockResolvedValue(null),
        put: vi.fn(),
        delete: vi.fn(),
      };
      const db = createMockDB({
        firstResult: { id: 'ev-1', r2_key: 'evidence/org/ev-1/file.pdf', sha256_hash: 'abc123', file_name: 'file.pdf' },
      });

      const app = createTestApp(evidence as any, '/api/v1/evidence', db);
      // Override STORAGE mock
      app.use('*', async (c, next) => {
        (c.env as any).STORAGE = mockStorage;
        await next();
      });

      const res = await app.request('/api/v1/evidence/ev-1/verify', { method: 'POST' });
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.verified).toBe(false);
      expect(body.reason).toContain('not found');
    });
  });

  describe('PATCH /api/v1/evidence/:id', () => {
    it('updates evidence metadata', async () => {
      const db = createMockDB({ firstResult: { id: 'ev-1' } });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence/ev-1', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'Updated Title', expires_at: '2025-12-31' }),
      });
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.message).toContain('updated');
    });

    it('rejects empty update', async () => {
      const db = createMockDB({ firstResult: { id: 'ev-1' } });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence/ev-1', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
    });

    it('returns 404 for missing evidence', async () => {
      const db = createMockDB({ firstResult: null });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence/nonexistent', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'New' }),
      });
      expect(res.status).toBe(404);
    });
  });

  describe('DELETE /api/v1/evidence/:id', () => {
    it('deletes evidence file', async () => {
      const db = createMockDB({ firstResult: { id: 'ev-1', r2_key: 'evidence/org/ev-1/file.pdf' } });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence/ev-1', { method: 'DELETE' });
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.message).toContain('deleted');
    });

    it('returns 404 for missing evidence', async () => {
      const db = createMockDB({ firstResult: null });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence/nonexistent', { method: 'DELETE' });
      expect(res.status).toBe(404);
    });
  });

  describe('POST /api/v1/evidence/cleanup', () => {
    it('cleans up expired files', async () => {
      const db = createMockDB({
        allResults: [
          { id: 'ev-expired-1', r2_key: 'evidence/org/ev-1/old.pdf' },
        ],
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/evidence/cleanup', { method: 'POST' });
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.expired_count).toBe(1);
    });
  });
});
