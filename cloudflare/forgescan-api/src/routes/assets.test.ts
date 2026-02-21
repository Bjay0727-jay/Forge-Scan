import { describe, it, expect } from 'vitest';
import { assets } from './assets';
import { createMockDB, createTestApp, mockAsset, mockFinding } from '../test-helpers';

const PREFIX = '/api/v1/assets';
const mkApp = (db: any) => createTestApp(assets, PREFIX, db);

// ─── GET / ──────────────────────────────────────────────────────────────────

describe('GET /api/v1/assets', () => {
  it('returns paginated assets list', async () => {
    const items = [mockAsset(), mockAsset({ id: 'asset-002', hostname: 'db-01' })];
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
    const db = createMockDB({ allResults: [], firstResult: { total: 100 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?page=3&page_size=25`);
    const body = await res.json() as any;

    expect(body.page).toBe(3);
    expect(body.page_size).toBe(25);
    expect(body.total_pages).toBe(4);
  });

  it('filters by asset type', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?type=server`);
    expect(res.status).toBe(200);
    expect(db.prepare).toHaveBeenCalled();
  });

  it('supports search query', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?search=web-01`);
    expect(res.status).toBe(200);
  });

  it('transforms response to frontend format', async () => {
    const raw = mockAsset();
    const db = createMockDB({ allResults: [raw], firstResult: { total: 1 } });
    const app = mkApp(db);

    const res = await app.request(PREFIX);
    const body = await res.json() as any;

    const item = body.items[0];
    expect(item.id).toBe('asset-001');
    expect(item.name).toBe('web-01');
    expect(item.type).toBe('server');
    expect(item.metadata.ip_addresses).toEqual(['10.0.0.1']);
    expect(item.tags).toEqual(['production']);
  });

  it('handles asset with no hostname (falls back to fqdn)', async () => {
    const raw = mockAsset({ hostname: null, fqdn: 'db.example.com' });
    const db = createMockDB({ allResults: [raw], firstResult: { total: 1 } });
    const app = mkApp(db);

    const res = await app.request(PREFIX);
    const body = await res.json() as any;
    expect(body.items[0].name).toBe('db.example.com');
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

describe('GET /api/v1/assets/:id', () => {
  it('returns asset with findings', async () => {
    const asset = mockAsset();
    const findingsResult = [mockFinding()];
    const db = createMockDB({ firstResult: asset, allResults: findingsResult });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/asset-001`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.id).toBe('asset-001');
    expect(body.findings_count).toBe(1);
  });

  it('returns 404 for non-existent asset', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/nonexistent`);
    expect(res.status).toBe(404);

    const body = await res.json() as any;
    expect(body.error.code).toBe('ASSET_NOT_FOUND');
  });
});

// ─── POST / ─────────────────────────────────────────────────────────────────

describe('POST /api/v1/assets', () => {
  it('creates an asset', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(PREFIX, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hostname: 'new-server',
        ip_addresses: ['192.168.1.100'],
        os: 'CentOS',
        asset_type: 'server',
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json() as any;
    expect(body.id).toBeDefined();
    expect(body.message).toBe('Asset created');
  });

  it('creates asset with minimal fields', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(PREFIX, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(201);
  });
});

// ─── PUT /:id ───────────────────────────────────────────────────────────────

describe('PUT /api/v1/assets/:id', () => {
  it('updates asset fields', async () => {
    const db = createMockDB({ firstResult: { id: 'asset-001' } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/asset-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname: 'updated-server', os: 'RHEL' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.message).toBe('Asset updated');
  });

  it('returns 404 for non-existent asset', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/nonexistent`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname: 'test' }),
    });

    expect(res.status).toBe(404);
  });
});

// ─── DELETE /:id ────────────────────────────────────────────────────────────

describe('DELETE /api/v1/assets/:id', () => {
  it('deletes an asset and its findings', async () => {
    const db = createMockDB({ firstResult: { id: 'asset-001' } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/asset-001`, { method: 'DELETE' });
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.message).toBe('Asset deleted');
    // Should call prepare 3 times: SELECT, DELETE findings, DELETE asset
    expect(db.prepare.mock.calls.length).toBeGreaterThanOrEqual(3);
  });

  it('returns 404 for non-existent asset', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/nonexistent`, { method: 'DELETE' });
    expect(res.status).toBe(404);
  });
});

// ─── GET /:id/summary ──────────────────────────────────────────────────────

describe('GET /api/v1/assets/:id/summary', () => {
  it('returns severity counts for an asset', async () => {
    const stats = [
      { severity: 'critical', count: 2 },
      { severity: 'high', count: 5 },
    ];
    const db = createMockDB({ allResults: stats });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/asset-001/summary`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.asset_id).toBe('asset-001');
    expect(body.severity_counts).toHaveLength(2);
    expect(body.severity_counts[0].severity).toBe('critical');
  });

  it('returns empty severity counts', async () => {
    const db = createMockDB({ allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/asset-999/summary`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.severity_counts).toHaveLength(0);
  });
});
