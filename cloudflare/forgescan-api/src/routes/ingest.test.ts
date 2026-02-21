import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { ingest } from './ingest';
import type { Env } from '../index';
import { errorHandler } from '../middleware/error-handler';

// ─── D1 Mock ────────────────────────────────────────────────────────────────

function createMockDB(options: {
  allResults?: any[];
  firstResult?: any;
  runSuccess?: boolean;
  shouldFail?: boolean;
  failMessage?: string;
} = {}) {
  const {
    allResults = [],
    firstResult = null,
    runSuccess = true,
    shouldFail = false,
    failMessage = 'DB error',
  } = options;

  const mockRun = shouldFail
    ? vi.fn().mockRejectedValue(new Error(failMessage))
    : vi.fn().mockResolvedValue({ success: runSuccess });

  const mockFirst = shouldFail
    ? vi.fn().mockRejectedValue(new Error(failMessage))
    : vi.fn().mockResolvedValue(firstResult);

  const mockAll = shouldFail
    ? vi.fn().mockRejectedValue(new Error(failMessage))
    : vi.fn().mockResolvedValue({ results: allResults });

  return {
    prepare: vi.fn().mockReturnValue({
      bind: vi.fn().mockReturnValue({
        run: mockRun,
        first: mockFirst,
        all: mockAll,
      }),
    }),
    _mockRun: mockRun,
    _mockFirst: mockFirst,
  };
}

function createApp(db: any) {
  const app = new Hono<{ Bindings: Env }>();
  app.use('*', async (c, next) => {
    (c.env as any) = { DB: db, STORAGE: {}, CACHE: {} };
    await next();
  });
  app.route('/api/v1/ingest', ingest);
  app.onError(errorHandler);
  return app;
}

// ─── GET /jobs ──────────────────────────────────────────────────────────────

describe('GET /api/v1/ingest/jobs', () => {
  it('returns list of jobs', async () => {
    const jobs = [
      { id: '1', vendor: 'tenable', status: 'completed' },
      { id: '2', vendor: 'qualys', status: 'processing' },
    ];
    const db = createMockDB({ allResults: jobs });
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/jobs');
    expect(res.status).toBe(200);

    const body = await res.json() as any[];
    expect(body).toHaveLength(2);
    expect(body[0].vendor).toBe('tenable');
  });

  it('filters by vendor', async () => {
    const db = createMockDB({ allResults: [] });
    const app = createApp(db);

    await app.request('/api/v1/ingest/jobs?vendor=tenable');
    expect(db.prepare).toHaveBeenCalled();
  });

  it('filters by status', async () => {
    const db = createMockDB({ allResults: [] });
    const app = createApp(db);

    await app.request('/api/v1/ingest/jobs?status=completed');
    expect(db.prepare).toHaveBeenCalled();
  });

  it('respects limit parameter', async () => {
    const db = createMockDB({ allResults: [] });
    const app = createApp(db);

    await app.request('/api/v1/ingest/jobs?limit=5');
    expect(db.prepare).toHaveBeenCalled();
  });
});

// ─── GET /jobs/:id ──────────────────────────────────────────────────────────

describe('GET /api/v1/ingest/jobs/:id', () => {
  it('returns a job by ID', async () => {
    const job = { id: 'test-123', vendor: 'generic', status: 'completed' };
    const db = createMockDB({ firstResult: job });
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/jobs/test-123');
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.id).toBe('test-123');
  });

  it('returns 404 for non-existent job', async () => {
    const db = createMockDB({ firstResult: null });
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/jobs/nonexistent');
    expect(res.status).toBe(404);

    const body = await res.json() as any;
    expect(body.error.code).toBe('JOB_NOT_FOUND');
  });
});

// ─── POST /upload (JSON) ────────────────────────────────────────────────────

describe('POST /api/v1/ingest/upload (JSON)', () => {
  it('imports JSON findings array', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const findings = [
      { title: 'SQLi', severity: 'critical', ip: '10.0.0.1' },
      { title: 'XSS', severity: 'medium' },
    ];

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(findings),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.status).toBe('completed');
    expect(body.records_processed).toBe(2);
    expect(body.records_imported).toBe(2);
    expect(body.type).toBe('findings');
  });

  it('imports JSON with nested findings key', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findings: [{ title: 'Test', severity: 'low' }] }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.records_imported).toBe(1);
  });

  it('imports JSON with vulnerabilities key', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vulnerabilities: [{ title: 'Vuln', severity: 'high' }] }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.records_imported).toBe(1);
  });

  it('creates asset when hostname/IP provided', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([{ title: 'Test', severity: 'low', hostname: 'web-01', ip: '10.0.0.1' }]),
    });

    expect(res.status).toBe(200);
    // Should have called prepare for: job insert + asset insert + finding insert + job update
    expect(db.prepare.mock.calls.length).toBeGreaterThanOrEqual(4);
  });

  it('returns job_id in response', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([]),
    });

    const body = await res.json() as any;
    expect(body.job_id).toBeDefined();
    expect(typeof body.job_id).toBe('string');
  });
});

// ─── POST /upload (CSV) ────────────────────────────────────────────────────

describe('POST /api/v1/ingest/upload (CSV)', () => {
  it('imports CSV findings via text/csv content type', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const csv = [
      'Title,Severity,IP Address,Port,CVE ID',
      'SQL Injection,critical,10.0.0.1,443,CVE-2024-1234',
      'XSS Stored,high,10.0.0.2,80,CVE-2024-5678',
    ].join('\n');

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'text/csv' },
      body: csv,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.status).toBe('completed');
    expect(body.records_processed).toBe(2);
    expect(body.records_imported).toBe(2);
    expect(body.type).toBe('findings');
  });

  it('imports Nessus-style CSV with vendor=tenable', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const csv = [
      'Plugin ID,Name,Risk,Host IP,Port,Protocol',
      '12345,Test Plugin,Critical,192.168.1.1,22,tcp',
    ].join('\n');

    const res = await app.request('/api/v1/ingest/upload?vendor=tenable', {
      method: 'POST',
      headers: { 'Content-Type': 'text/csv' },
      body: csv,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.records_imported).toBe(1);
  });

  it('rejects empty CSV body', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'text/csv' },
      body: '   ',
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('Empty CSV body');
  });

  it('imports asset CSV with type=assets', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const csv = [
      'Hostname,IP Address,OS,Network Zone',
      'web-01,10.0.0.1,Ubuntu,dmz',
      'db-01,10.0.0.2,Windows,internal',
    ].join('\n');

    const res = await app.request('/api/v1/ingest/upload?type=assets', {
      method: 'POST',
      headers: { 'Content-Type': 'text/csv' },
      body: csv,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.type).toBe('assets');
    expect(body.records_processed).toBe(2);
  });
});

// ─── POST /upload (multipart) ───────────────────────────────────────────────

describe('POST /api/v1/ingest/upload (multipart)', () => {
  it('imports CSV via file upload', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const csv = 'Title,Severity\nTest Vuln,high';
    const formData = new FormData();
    formData.append('file', new Blob([csv], { type: 'text/csv' }), 'findings.csv');

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      body: formData,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.records_imported).toBe(1);
  });

  it('imports JSON via file upload', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const json = JSON.stringify([{ title: 'Test', severity: 'low' }]);
    const formData = new FormData();
    formData.append('file', new Blob([json], { type: 'application/json' }), 'findings.json');

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      body: formData,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.records_imported).toBe(1);
  });

  it('rejects upload with no file', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const formData = new FormData();
    formData.append('format', 'csv');

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      body: formData,
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('No file provided');
  });

  it('rejects upload with empty file', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const formData = new FormData();
    formData.append('file', new Blob(['   ']), 'empty.csv');

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      body: formData,
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('empty');
  });

  it('uses format form field over extension', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const json = JSON.stringify([{ title: 'Test', severity: 'low' }]);
    const formData = new FormData();
    formData.append('file', new Blob([json]), 'data.txt');
    formData.append('format', 'json');

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      body: formData,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.records_imported).toBe(1);
  });
});

// ─── POST /upload (error handling) ──────────────────────────────────────────

describe('POST /api/v1/ingest/upload (error handling)', () => {
  it('rejects unsupported content type', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/xml' },
      body: '<findings></findings>',
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('Unsupported content type');
  });

  it('tracks skipped findings when individual inserts fail', async () => {
    // Create a DB that succeeds on job creation + asset inserts + job update,
    // but fails on finding inserts (calls 2 and 3 for asset + finding)
    let callCount = 0;
    const db = {
      prepare: vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          run: vi.fn().mockImplementation(() => {
            callCount++;
            // Call 1 = job create, Call 2 = asset insert, Call 3 = finding insert, Call 4 = job update
            // Fail only on the finding insert (call 3)
            if (callCount === 3) return Promise.reject(new Error('DB write failed'));
            return Promise.resolve({ success: true });
          }),
          first: vi.fn(),
          all: vi.fn(),
        }),
      }),
    };
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([{ title: 'Test', severity: 'high', ip: '10.0.0.1' }]),
    });

    // Finding insert fails but is caught per-row, so job still completes
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.records_skipped).toBe(1);
    expect(body.records_imported).toBe(0);
  });

  it('handles empty JSON array', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([]),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.records_processed).toBe(0);
    expect(body.records_imported).toBe(0);
  });
});

// ─── GET /vendors ───────────────────────────────────────────────────────────

describe('GET /api/v1/ingest/vendors', () => {
  it('returns list of supported vendors', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/vendors');
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.vendors).toContain('generic');
    expect(body.vendors).toContain('tenable');
    expect(body.vendors).toContain('qualys');
    expect(body.vendors).toContain('rapid7');
  });
});

// ─── Vendor placeholders ────────────────────────────────────────────────────

describe('vendor-specific endpoints', () => {
  it('POST /tenable returns 501', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/tenable', { method: 'POST' });
    expect(res.status).toBe(501);
  });

  it('POST /qualys returns 501', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/qualys', { method: 'POST' });
    expect(res.status).toBe(501);
  });

  it('POST /rapid7 returns 501', async () => {
    const db = createMockDB();
    const app = createApp(db);

    const res = await app.request('/api/v1/ingest/rapid7', { method: 'POST' });
    expect(res.status).toBe(501);
  });
});
