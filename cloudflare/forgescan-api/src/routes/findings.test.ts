import { describe, it, expect } from 'vitest';
import { findings } from './findings';
import { createMockDB, createTestApp, mockFinding } from '../test-helpers';

const PREFIX = '/api/v1/findings';
const mkApp = (db: any) => createTestApp(findings, PREFIX, db);

// ─── GET / ──────────────────────────────────────────────────────────────────

describe('GET /api/v1/findings', () => {
  it('returns paginated findings list', async () => {
    const items = [mockFinding(), mockFinding({ id: 'finding-002', title: 'XSS' })];
    const db = createMockDB({ allResults: items, firstResult: { total: 2 } });
    const app = mkApp(db);

    const res = await app.request(PREFIX);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.items).toHaveLength(2);
    expect(body.total).toBe(2);
    expect(body.page).toBe(1);
    expect(body.page_size).toBe(20);
  });

  it('respects page and page_size params', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 50 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?page=2&page_size=10`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.page).toBe(2);
    expect(body.page_size).toBe(10);
    expect(body.total_pages).toBe(5);
  });

  it('filters by severity', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?severity=critical`);
    expect(res.status).toBe(200);
    expect(db.prepare).toHaveBeenCalled();
  });

  it('filters by state', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?state=open`);
    expect(res.status).toBe(200);
    expect(db.prepare).toHaveBeenCalled();
  });

  it('filters by vendor', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?vendor=tenable`);
    expect(res.status).toBe(200);
  });

  it('filters by asset_id', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?asset_id=asset-001`);
    expect(res.status).toBe(200);
  });

  it('supports search query', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?search=injection`);
    expect(res.status).toBe(200);
  });

  it('transforms response to frontend format', async () => {
    const raw = mockFinding({ references: '["https://example.com"]' });
    const db = createMockDB({ allResults: [raw], firstResult: { total: 1 } });
    const app = mkApp(db);

    const res = await app.request(PREFIX);
    const body = await res.json() as any;

    expect(body.items[0].id).toBe('finding-001');
    expect(body.items[0].severity).toBe('critical');
    expect(body.items[0].references).toEqual(['https://example.com']);
  });

  it('returns empty results', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(PREFIX);
    const body = await res.json() as any;

    expect(body.items).toHaveLength(0);
    expect(body.total).toBe(0);
  });
});

// ─── GET /:id ───────────────────────────────────────────────────────────────

describe('GET /api/v1/findings/:id', () => {
  it('returns a finding by ID', async () => {
    const finding = mockFinding();
    const db = createMockDB({ firstResult: finding });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/finding-001`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.id).toBe('finding-001');
    expect(body.title).toBe('SQL Injection');
  });

  it('returns 404 for non-existent finding', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/nonexistent`);
    expect(res.status).toBe(404);

    const body = await res.json() as any;
    expect(body.error.code).toBe('FINDING_NOT_FOUND');
  });
});

// ─── POST / ─────────────────────────────────────────────────────────────────

describe('POST /api/v1/findings', () => {
  it('creates a finding', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(PREFIX, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        asset_id: 'asset-001',
        vendor: 'generic',
        vendor_id: 'VULN-001',
        title: 'Test Finding',
        severity: 'high',
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json() as any;
    expect(body.id).toBeDefined();
    expect(body.message).toBe('Finding created');
  });

  it('handles DB error on create', async () => {
    const db = createMockDB({ shouldFail: true });
    const app = mkApp(db);

    const res = await app.request(PREFIX, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        asset_id: 'asset-001',
        vendor: 'generic',
        vendor_id: 'VULN-001',
        title: 'Test',
        severity: 'high',
      }),
    });

    expect(res.status).toBe(500);
  });
});

// ─── PUT /:id ───────────────────────────────────────────────────────────────

describe('PUT /api/v1/findings/:id', () => {
  it('updates finding state', async () => {
    const existing = { id: 'finding-001' };
    const updated = mockFinding({ state: 'fixed' });
    const db = createMockDB({ firstResult: existing });
    // Override: first call returns existing, run succeeds, second first returns updated
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/finding-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ state: 'fixed' }),
    });

    expect(res.status).toBe(200);
  });

  it('returns 404 for non-existent finding', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/nonexistent`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ state: 'fixed' }),
    });

    expect(res.status).toBe(404);
  });

  it('rejects invalid state enum', async () => {
    const db = createMockDB({ firstResult: { id: 'finding-001' } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/finding-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ state: 'invalid_state' }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.code).toBe('INVALID_ENUM');
  });

  it('rejects request with no fields to update', async () => {
    const db = createMockDB({ firstResult: { id: 'finding-001' } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/finding-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('No fields to update');
  });

  it('updates severity', async () => {
    const db = createMockDB({ firstResult: { id: 'finding-001' } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/finding-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ severity: 'low' }),
    });

    expect(res.status).toBe(200);
  });

  it('rejects invalid severity enum', async () => {
    const db = createMockDB({ firstResult: { id: 'finding-001' } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/finding-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ severity: 'ultra' }),
    });

    expect(res.status).toBe(400);
  });
});

// ─── PATCH /:id/state ───────────────────────────────────────────────────────

describe('PATCH /api/v1/findings/:id/state', () => {
  it('updates finding state to fixed', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/finding-001/state`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ state: 'fixed' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.message).toContain('state updated');
  });

  it('rejects invalid state', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/finding-001/state`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ state: 'banana' }),
    });

    expect(res.status).toBe(400);
  });
});

// ─── POST /bulk/state ───────────────────────────────────────────────────────

describe('POST /api/v1/findings/bulk/state', () => {
  it('bulk updates finding states', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/bulk/state`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ids: ['finding-001', 'finding-002'],
        state: 'acknowledged',
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.message).toContain('Updated 2 findings');
  });

  it('rejects empty IDs array', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/bulk/state`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: [], state: 'fixed' }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('No finding IDs');
  });

  it('rejects invalid state in bulk update', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/bulk/state`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: ['finding-001'], state: 'invalid' }),
    });

    expect(res.status).toBe(400);
  });
});

// ─── GET /stats/severity ────────────────────────────────────────────────────

describe('GET /api/v1/findings/stats/severity', () => {
  it('returns severity distribution', async () => {
    const stats = [
      { severity: 'critical', count: 5 },
      { severity: 'high', count: 12 },
      { severity: 'medium', count: 8 },
    ];
    const db = createMockDB({ allResults: stats });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/stats/severity`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body).toHaveLength(3);
    expect(body[0].severity).toBe('critical');
  });

  it('defaults to open state filter', async () => {
    const db = createMockDB({ allResults: [] });
    const app = mkApp(db);

    await app.request(`${PREFIX}/stats/severity`);
    expect(db.prepare).toHaveBeenCalled();
  });
});

// ─── GET /stats/vendors ─────────────────────────────────────────────────────

describe('GET /api/v1/findings/stats/vendors', () => {
  it('returns vendor distribution', async () => {
    const stats = [
      { vendor: 'tenable', count: 20 },
      { vendor: 'qualys', count: 8 },
    ];
    const db = createMockDB({ allResults: stats });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/stats/vendors`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body).toHaveLength(2);
    expect(body[0].vendor).toBe('tenable');
  });
});
