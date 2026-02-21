import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mockFetch, mockFetchError } from '@/test/mocks/fetch';

// We need to dynamically import the module AFTER setting up env vars
// api.ts reads import.meta.env.VITE_API_URL at module load time,
// so we import the exports we need.
import {
  ApiError,
  assetsApi,
  findingsApi,
  scansApi,
  dashboardApi,
  healthApi,
  importApi,
} from './api';

// The API_BASE_URL defaults to '/api' when VITE_API_URL is not set
const BASE = '/api';

// --- ApiError ---

describe('ApiError', () => {
  it('extends Error', () => {
    const err = new ApiError('test', 400);
    expect(err).toBeInstanceOf(Error);
  });

  it('sets message and status', () => {
    const err = new ApiError('Not found', 404);
    expect(err.message).toBe('Not found');
    expect(err.status).toBe(404);
  });

  it('sets name to ApiError', () => {
    const err = new ApiError('fail', 500);
    expect(err.name).toBe('ApiError');
  });
});

// --- buildQueryString (tested indirectly through API calls) ---

describe('buildQueryString (via assetsApi.list)', () => {
  let fetchMock: ReturnType<typeof mockFetch>;

  beforeEach(() => {
    fetchMock = mockFetch({
      '/assets': { body: { items: [], total: 0, page: 1, page_size: 20, total_pages: 0 } },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends no query string for empty params', async () => {
    await assetsApi.list({});
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toBe(`${BASE}/assets`);
  });

  it('appends single param', async () => {
    await assetsApi.list({ page: 2 } as Record<string, unknown>);
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain('page=2');
  });

  it('skips undefined and null params', async () => {
    await assetsApi.list({ page: 1, search: undefined } as Record<string, unknown>);
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).not.toContain('search');
  });

  it('skips empty string params', async () => {
    await assetsApi.list({ search: '' } as Record<string, unknown>);
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toBe(`${BASE}/assets`);
  });

  it('converts boolean params', async () => {
    await assetsApi.list({ is_active: true } as Record<string, unknown>);
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain('is_active=true');
  });

  it('converts number params', async () => {
    await assetsApi.list({ page_size: 50 } as Record<string, unknown>);
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain('page_size=50');
  });
});

// --- request() function behavior ---

describe('request() (via API calls)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('calls the correct URL', async () => {
    const fetchMock = mockFetch({
      '/assets/abc': { body: { id: 'abc', hostname: 'host1' } },
    });
    await assetsApi.get('abc');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toBe(`${BASE}/assets/abc`);
  });

  it('includes Content-Type: application/json header', async () => {
    const fetchMock = mockFetch({
      '/health': { body: { data: { status: 'ok' } } },
    });
    await healthApi.check();
    const calledInit = fetchMock.mock.calls[0][1] as RequestInit;
    expect((calledInit.headers as Record<string, string>)['Content-Type']).toBe(
      'application/json'
    );
  });

  it('injects Authorization header when token exists', async () => {
    localStorage.setItem('forgescan_token', 'my-jwt');
    const fetchMock = mockFetch({
      '/health': { body: { data: { status: 'ok' } } },
    });
    await healthApi.check();
    const calledInit = fetchMock.mock.calls[0][1] as RequestInit;
    expect((calledInit.headers as Record<string, string>)['Authorization']).toBe(
      'Bearer my-jwt'
    );
  });

  it('does not inject Authorization header when no token', async () => {
    const fetchMock = mockFetch({
      '/health': { body: { data: { status: 'ok' } } },
    });
    await healthApi.check();
    const calledInit = fetchMock.mock.calls[0][1] as RequestInit;
    expect((calledInit.headers as Record<string, string>)['Authorization']).toBeUndefined();
  });

  it('parses JSON response', async () => {
    mockFetch({
      '/assets/x1': { body: { id: 'x1', hostname: 'webserver' } },
    });
    const result = await assetsApi.get('x1');
    expect(result).toEqual({ id: 'x1', hostname: 'webserver' });
  });

  it('returns empty object for empty response body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('', { status: 200 })
    );
    vi.stubGlobal('fetch', fetchMock);
    const result = await assetsApi.delete('x1');
    expect(result).toEqual({});
  });

  it('throws ApiError on non-OK response with error message', async () => {
    mockFetch({
      '/assets/bad': { status: 422, body: { error: 'Validation failed' } },
    });
    await expect(assetsApi.get('bad')).rejects.toThrow('Validation failed');
    try {
      await assetsApi.get('bad');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(422);
    }
  });

  it('throws ApiError with generic message when error body has no error field', async () => {
    mockFetch({
      '/assets/fail': { status: 500, body: {} },
    });
    await expect(assetsApi.get('fail')).rejects.toThrow('HTTP error 500');
  });

  it('clears storage on 401 response', async () => {
    localStorage.setItem('forgescan_token', 'old-token');
    localStorage.setItem('forgescan_user', '{"id":"1"}');

    // Mock window.location
    const locationMock = { ...window.location, pathname: '/dashboard', href: '' };
    Object.defineProperty(window, 'location', {
      value: locationMock,
      writable: true,
    });

    mockFetch({
      '/assets': { status: 401, body: { error: 'Unauthorized' } },
    });

    await expect(assetsApi.list()).rejects.toThrow('Session expired');
    expect(localStorage.getItem('forgescan_token')).toBeNull();
    expect(localStorage.getItem('forgescan_user')).toBeNull();
  });

  it('redirects to /login on 401', async () => {
    const locationMock = { pathname: '/dashboard', href: '' };
    Object.defineProperty(window, 'location', {
      value: locationMock,
      writable: true,
    });

    mockFetch({
      '/assets': { status: 401, body: { error: 'Unauthorized' } },
    });

    await expect(assetsApi.list()).rejects.toThrow();
    expect(locationMock.href).toBe('/login');
  });

  it('does not redirect when already on /login', async () => {
    const locationMock = { pathname: '/login', href: '' };
    Object.defineProperty(window, 'location', {
      value: locationMock,
      writable: true,
    });

    mockFetch({
      '/assets': { status: 401, body: { error: 'Unauthorized' } },
    });

    await expect(assetsApi.list()).rejects.toThrow();
    expect(locationMock.href).toBe('');
  });

  it('wraps network errors in ApiError with status 0', async () => {
    mockFetchError('Failed to fetch');
    try {
      await assetsApi.list();
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(0);
      expect((err as ApiError).message).toBe('Failed to fetch');
    }
  });
});

// --- Module APIs (correct endpoints + methods) ---

describe('assetsApi', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('list calls GET /assets', async () => {
    const fetchMock = mockFetch({
      '/assets': { body: { items: [], total: 0, page: 1, page_size: 20, total_pages: 0 } },
    });
    await assetsApi.list();
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toBe(`${BASE}/assets`);
  });

  it('get calls GET /assets/:id', async () => {
    const fetchMock = mockFetch({
      '/assets/a1': { body: { id: 'a1' } },
    });
    await assetsApi.get('a1');
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/assets/a1`);
  });

  it('create calls POST /assets with body', async () => {
    const fetchMock = mockFetch({
      '/assets': { body: { id: 'new' } },
    });
    await assetsApi.create({ hostname: 'test', asset_type: 'server' } as never);
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ hostname: 'test', asset_type: 'server' });
  });

  it('update calls PUT /assets/:id', async () => {
    const fetchMock = mockFetch({
      '/assets/a1': { body: { id: 'a1' } },
    });
    await assetsApi.update('a1', { hostname: 'updated' });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('PUT');
  });

  it('delete calls DELETE /assets/:id', async () => {
    const fetchMock = mockFetch({
      '/assets/a1': { body: {} },
    });
    await assetsApi.delete('a1');
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('DELETE');
  });
});

describe('findingsApi', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('list calls GET /findings', async () => {
    const fetchMock = mockFetch({
      '/findings': { body: { items: [], total: 0, page: 1, page_size: 20, total_pages: 0 } },
    });
    await findingsApi.list();
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/findings`);
  });

  it('update calls PUT /findings/:id', async () => {
    const fetchMock = mockFetch({
      '/findings/f1': { body: { id: 'f1' } },
    });
    await findingsApi.update('f1', { state: 'resolved' } as never);
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('PUT');
  });

  it('bulkUpdate calls PUT /findings/bulk with ids', async () => {
    const fetchMock = mockFetch({
      '/findings/bulk': { body: { updated: 3 } },
    });
    await findingsApi.bulkUpdate(['f1', 'f2', 'f3'], { state: 'resolved' } as never);
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('PUT');
    const body = JSON.parse(init.body as string);
    expect(body.ids).toEqual(['f1', 'f2', 'f3']);
  });
});

describe('scansApi', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('list calls GET /scans', async () => {
    const fetchMock = mockFetch({
      '/scans': { body: { items: [], total: 0, page: 1, page_size: 20, total_pages: 0 } },
    });
    await scansApi.list();
    expect((fetchMock.mock.calls[0][0] as string)).toBe(`${BASE}/scans`);
  });

  it('create calls POST /scans', async () => {
    const fetchMock = mockFetch({
      '/scans': { body: { id: 's1' } },
    });
    await scansApi.create({ name: 'Test Scan', scan_type: 'vulnerability' } as never);
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('POST');
  });

  it('start calls POST /scans/:id/start', async () => {
    const fetchMock = mockFetch({
      '/scans/s1/start': { body: { id: 's1', status: 'running' } },
    });
    await scansApi.start('s1');
    expect(fetchMock.mock.calls[0][0]).toContain('/scans/s1/start');
    expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe('POST');
  });

  it('cancel calls POST /scans/:id/cancel', async () => {
    const fetchMock = mockFetch({
      '/scans/s1/cancel': { body: { id: 's1', status: 'cancelled' } },
    });
    await scansApi.cancel('s1');
    expect(fetchMock.mock.calls[0][0]).toContain('/scans/s1/cancel');
  });

  it('delete calls DELETE /scans/:id', async () => {
    const fetchMock = mockFetch({
      '/scans/s1': { body: {} },
    });
    await scansApi.delete('s1');
    expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe('DELETE');
  });

  it('getFindings calls GET /scans/:id/findings', async () => {
    const fetchMock = mockFetch({
      '/scans/s1/findings': { body: { items: [], total: 0, page: 1, page_size: 20, total_pages: 0 } },
    });
    await scansApi.getFindings('s1');
    expect(fetchMock.mock.calls[0][0]).toContain('/scans/s1/findings');
  });

  it('getActive calls GET /scans/active', async () => {
    const fetchMock = mockFetch({
      '/scans/active': {
        body: {
          items: [
            {
              id: 's1',
              name: 'Test Scan',
              type: 'network',
              status: 'running',
              target: '192.168.1.0/24',
              findings_count: 5,
              assets_count: 3,
              started_at: '2024-01-01T00:00:00Z',
              created_at: '2024-01-01T00:00:00Z',
              progress: {
                total_tasks: 10,
                completed_tasks: 4,
                running_tasks: 2,
                failed_tasks: 0,
                queued_tasks: 4,
                assigned_tasks: 0,
                percentage: 40,
              },
            },
          ],
          has_active: true,
        },
      },
    });
    const result = await scansApi.getActive();
    expect(fetchMock.mock.calls[0][0]).toContain('/scans/active');
    expect(result.has_active).toBe(true);
    expect(result.items).toHaveLength(1);
    expect(result.items[0].progress.percentage).toBe(40);
  });

  it('getTasks calls GET /scans/:id/tasks', async () => {
    const fetchMock = mockFetch({
      '/scans/s1/tasks': {
        body: {
          tasks: [
            { id: 't1', scan_id: 's1', status: 'completed', task_type: 'port_scan', findings_count: 3 },
            { id: 't2', scan_id: 's1', status: 'running', task_type: 'vuln_scan', findings_count: 0 },
          ],
          summary: {
            total: 2,
            completed: 1,
            running: 1,
            failed: 0,
            queued: 0,
            assigned: 0,
            total_findings: 3,
            total_assets: 5,
          },
        },
      },
    });
    const result = await scansApi.getTasks('s1');
    expect(fetchMock.mock.calls[0][0]).toContain('/scans/s1/tasks');
    expect(result.tasks).toHaveLength(2);
    expect(result.summary.total).toBe(2);
    expect(result.summary.total_findings).toBe(3);
  });
});

describe('dashboardApi', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('getStats calls GET /dashboard/overview and transforms response', async () => {
    mockFetch({
      '/dashboard/overview': {
        body: {
          totals: { total_assets: 10, open_findings: 5, fixed_findings: 3, completed_scans: 7 },
          severity_breakdown: [
            { severity: 'critical', count: 2 },
            { severity: 'high', count: 3 },
          ],
          recent_findings: [],
          top_vulnerable_assets: [],
          generated_at: '2024-01-01',
        },
      },
    });
    const stats = await dashboardApi.getStats();
    expect(stats.total_assets).toBe(10);
    expect(stats.total_scans).toBe(7);
    expect(stats.findings_by_severity.critical).toBe(2);
    expect(stats.findings_by_severity.high).toBe(3);
    expect(stats.findings_by_severity.medium).toBe(0);
    expect(stats.findings_by_state.open).toBe(5);
    expect(stats.findings_by_state.resolved).toBe(3);
    expect(stats.total_findings).toBe(5); // 2+3+0+0+0
  });
});

describe('importApi', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('importData calls POST /import with format and data', async () => {
    const fetchMock = mockFetch({
      '/import': { body: { findings_created: 5, findings_updated: 0 } },
    });
    await importApi.importData('nessus' as never, '<NessusClientData/>');
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body.format).toBe('nessus');
    expect(body.data).toBe('<NessusClientData/>');
  });
});
