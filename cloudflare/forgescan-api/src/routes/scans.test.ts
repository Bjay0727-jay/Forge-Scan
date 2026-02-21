import { describe, it, expect, vi } from 'vitest';
import { scans } from './scans';
import { createMockDB, createTestApp, mockScan } from '../test-helpers';

// Mock the scan-orchestrator service since it makes its own DB calls
vi.mock('../services/scan-orchestrator', () => ({
  createTasksForScan: vi.fn().mockResolvedValue(['task-001']),
  getTasksForScan: vi.fn().mockResolvedValue([
    { id: 'task-001', status: 'completed', findings_count: 3, assets_discovered: 1 },
    { id: 'task-002', status: 'running', findings_count: 0, assets_discovered: 0 },
  ]),
  cancelScanTasks: vi.fn().mockResolvedValue(2),
}));

const PREFIX = '/api/v1/scans';
const mkApp = (db: any) => createTestApp(scans, PREFIX, db);

// ─── GET / ──────────────────────────────────────────────────────────────────

describe('GET /api/v1/scans', () => {
  it('returns paginated scans list', async () => {
    const items = [
      mockScan(),
      mockScan({ id: 'scan-002', name: 'Web App Scan' }),
    ];
    const db = createMockDB({ allResults: items, firstResult: { total: 2 } });
    const app = mkApp(db);

    const res = await app.request(PREFIX);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.items).toHaveLength(2);
    expect(body.total).toBe(2);
    expect(body.page).toBe(1);
  });

  it('respects pagination params', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 30 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?page=2&page_size=10`);
    const body = await res.json() as any;

    expect(body.page).toBe(2);
    expect(body.page_size).toBe(10);
    expect(body.total_pages).toBe(3);
  });

  it('filters by status', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?status=running`);
    expect(res.status).toBe(200);
  });

  it('filters by scan type', async () => {
    const db = createMockDB({ allResults: [], firstResult: { total: 0 } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}?type=network`);
    expect(res.status).toBe(200);
  });

  it('transforms response to frontend format', async () => {
    const raw = mockScan();
    const db = createMockDB({ allResults: [raw], firstResult: { total: 1 } });
    const app = mkApp(db);

    const res = await app.request(PREFIX);
    const body = await res.json() as any;

    const item = body.items[0];
    expect(item.id).toBe('scan-001');
    expect(item.type).toBe('network');
    expect(item.target).toBe('10.0.0.0/24');
  });
});

// ─── GET /active ────────────────────────────────────────────────────────────

describe('GET /api/v1/scans/active', () => {
  it('returns active scans with progress', async () => {
    const activeScan = mockScan({
      status: 'running',
      total_tasks: 4,
      completed_tasks: 2,
      running_tasks: 1,
      failed_tasks: 0,
      queued_tasks: 1,
      assigned_tasks: 0,
    });
    const db = createMockDB({ allResults: [activeScan] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/active`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.has_active).toBe(true);
    expect(body.items).toHaveLength(1);
    expect(body.items[0].progress).toBeDefined();
  });

  it('returns has_active=false when no active scans', async () => {
    const db = createMockDB({ allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/active`);
    const body = await res.json() as any;

    expect(body.has_active).toBe(false);
    expect(body.items).toHaveLength(0);
  });
});

// ─── GET /:id ───────────────────────────────────────────────────────────────

describe('GET /api/v1/scans/:id', () => {
  it('returns a scan by ID', async () => {
    const scan = mockScan();
    const db = createMockDB({ firstResult: scan });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.id).toBe('scan-001');
    expect(body.name).toBe('Network Scan Q1');
  });

  it('returns 404 for non-existent scan', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/nonexistent`);
    expect(res.status).toBe(404);

    const body = await res.json() as any;
    expect(body.error.code).toBe('SCAN_NOT_FOUND');
  });
});

// ─── POST / ─────────────────────────────────────────────────────────────────

describe('POST /api/v1/scans', () => {
  it('creates a scan', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(PREFIX, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'New Scan',
        type: 'network',
        target: '10.0.0.0/24',
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json() as any;
    expect(body.id).toBeDefined();
    expect(body.status).toBe('pending');
    expect(body.type).toBe('network');
  });

  it('rejects invalid scan type', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(PREFIX, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Bad Scan',
        type: 'invalid_type',
        target: '10.0.0.1',
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.code).toBe('INVALID_ENUM');
  });

  it('rejects missing target', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(PREFIX, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'No Target',
        type: 'network',
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('target');
  });

  it('accepts array of targets', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(PREFIX, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Multi Target',
        type: 'network',
        target: ['10.0.0.1', '10.0.0.2'],
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json() as any;
    expect(body.target).toBe('10.0.0.1, 10.0.0.2');
  });
});

// ─── POST /:id/start ────────────────────────────────────────────────────────

describe('POST /api/v1/scans/:id/start', () => {
  it('starts a pending scan', async () => {
    const scan = mockScan({ status: 'pending' });
    const db = createMockDB({ firstResult: scan });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001/start`, { method: 'POST' });
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.status).toBe('running');
    expect(body.tasks_created).toBe(1);
  });

  it('returns 404 for non-existent scan', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/nonexistent/start`, { method: 'POST' });
    expect(res.status).toBe(404);
  });

  it('rejects starting a non-pending scan', async () => {
    const scan = mockScan({ status: 'completed' });
    const db = createMockDB({ firstResult: scan });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001/start`, { method: 'POST' });
    expect(res.status).toBe(409);

    const body = await res.json() as any;
    expect(body.error.code).toBe('INVALID_STATE_TRANSITION');
  });
});

// ─── GET /:id/tasks ─────────────────────────────────────────────────────────

describe('GET /api/v1/scans/:id/tasks', () => {
  it('returns tasks with summary', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001/tasks`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.tasks).toHaveLength(2);
    expect(body.summary.total).toBe(2);
    expect(body.summary.completed).toBe(1);
    expect(body.summary.running).toBe(1);
    expect(body.summary.total_findings).toBe(3);
  });
});

// ─── POST /:id/cancel ──────────────────────────────────────────────────────

describe('POST /api/v1/scans/:id/cancel', () => {
  it('cancels a running scan', async () => {
    const scan = mockScan({ status: 'running' });
    const db = createMockDB({ firstResult: scan });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001/cancel`, { method: 'POST' });
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.message).toBe('Scan cancelled');
    expect(body.tasks_cancelled).toBe(2);
  });

  it('returns 404 for non-existent scan', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/nonexistent/cancel`, { method: 'POST' });
    expect(res.status).toBe(404);
  });

  it('rejects cancelling a completed scan', async () => {
    const scan = mockScan({ status: 'completed' });
    const db = createMockDB({ firstResult: scan });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001/cancel`, { method: 'POST' });
    expect(res.status).toBe(409);

    const body = await res.json() as any;
    expect(body.error.code).toBe('INVALID_STATE_TRANSITION');
  });
});

// ─── DELETE /:id ────────────────────────────────────────────────────────────

describe('DELETE /api/v1/scans/:id', () => {
  it('deletes a scan', async () => {
    const db = createMockDB({ firstResult: { id: 'scan-001' } });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001`, { method: 'DELETE' });
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.message).toBe('Scan deleted');
  });

  it('returns 404 for non-existent scan', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/nonexistent`, { method: 'DELETE' });
    expect(res.status).toBe(404);
  });
});

// ─── PATCH /:id/status ──────────────────────────────────────────────────────

describe('PATCH /api/v1/scans/:id/status', () => {
  it('updates scan status to running', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'running' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.message).toContain('status updated');
  });

  it('rejects invalid status', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'invalid' }),
    });

    expect(res.status).toBe(400);
  });

  it('updates with findings count', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/scan-001/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'completed',
        findings_count: 15,
        assets_count: 3,
      }),
    });

    expect(res.status).toBe(200);
  });
});

// ─── GET /stats/summary ────────────────────────────────────────────────────

describe('GET /api/v1/scans/stats/summary', () => {
  it('returns scan statistics', async () => {
    const stats = {
      total: 10,
      completed: 7,
      running: 1,
      pending: 1,
      failed: 1,
      total_findings: 142,
    };
    const db = createMockDB({ firstResult: stats });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/stats/summary`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.total).toBe(10);
    expect(body.completed).toBe(7);
    expect(body.total_findings).toBe(142);
  });
});
