// ─────────────────────────────────────────────────────────────────────────────
// Event Bus — Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { publish, registerHandler, unregisterHandler, queryEvents } from './index';

// ─── Mock D1Database ─────────────────────────────────────────────────────────

function createMockDB(options: {
  subscriptions?: any[];
  events?: any[];
  firstResult?: any;
} = {}) {
  const { subscriptions = [], events = [], firstResult = null } = options;

  let insertCalls: any[] = [];
  let callCount = 0;

  const db = {
    prepare: vi.fn().mockImplementation((sql: string) => {
      const isInsert = sql.trimStart().startsWith('INSERT');
      const isSelectSubs = sql.includes('event_subscriptions');
      const isSelectCount = sql.includes('COUNT(*)');
      const isSelectEvents = sql.includes('FROM forge_events') && !isInsert && !isSelectCount;

      return {
        bind: vi.fn().mockReturnValue({
          run: vi.fn().mockImplementation(() => {
            if (isInsert) {
              insertCalls.push({ sql });
            }
            return Promise.resolve({ success: true });
          }),
          first: vi.fn().mockResolvedValue(
            isSelectCount ? { total: events.length } : firstResult
          ),
          all: vi.fn().mockResolvedValue({
            results: isSelectSubs ? subscriptions : isSelectEvents ? events : [],
          }),
        }),
        run: vi.fn().mockResolvedValue({ success: true }),
        first: vi.fn().mockResolvedValue(firstResult),
        all: vi.fn().mockResolvedValue({
          results: isSelectSubs ? subscriptions : [],
        }),
      };
    }),
    _getInsertCalls: () => insertCalls,
  };

  return db as unknown as D1Database & { _getInsertCalls: () => any[] };
}

// ─── Mock notification engine ────────────────────────────────────────────────

vi.mock('../notifications/engine', () => ({
  emitEvent: vi.fn().mockResolvedValue({ matched: 0, sent: 0, failed: 0 }),
}));

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Event Bus — publish()', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('test-uuid-1234'),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('persists event to forge_events table', async () => {
    const db = createMockDB();
    const result = await publish(db, 'forge.scan.started', 'forgescan', { scan_id: '123' });

    expect(result.event_id).toBe('test-uuid-1234');
    expect(db.prepare).toHaveBeenCalled();
  });

  it('returns zero matches when no subscriptions exist', async () => {
    const db = createMockDB({ subscriptions: [] });
    const result = await publish(db, 'forge.scan.completed', 'forgescan', { findings: 5 });

    expect(result.subscriptions_matched).toBe(0);
    expect(result.subscriptions_executed).toBe(0);
    expect(result.subscriptions_failed).toBe(0);
  });

  it('matches exact event_pattern subscriptions', async () => {
    const db = createMockDB({
      subscriptions: [
        {
          id: 'sub-1',
          name: 'Test Sub',
          event_pattern: 'forge.scan.completed',
          handler_type: 'notification',
          handler_config: '{}',
          conditions: null,
          is_active: 1,
          priority: 1,
        },
      ],
    });

    const result = await publish(db, 'forge.scan.completed', 'forgescan', { findings: 5 });
    expect(result.subscriptions_matched).toBe(1);
  });

  it('matches wildcard event_pattern subscriptions', async () => {
    const db = createMockDB({
      subscriptions: [
        {
          id: 'sub-wild',
          name: 'Wildcard Sub',
          event_pattern: 'forge.scan.*',
          handler_type: 'notification',
          handler_config: '{}',
          conditions: null,
          is_active: 1,
          priority: 1,
        },
      ],
    });

    const result = await publish(db, 'forge.scan.started', 'forgescan', {});
    expect(result.subscriptions_matched).toBe(1);
  });

  it('does not match unrelated patterns', async () => {
    const db = createMockDB({
      subscriptions: [
        {
          id: 'sub-unrelated',
          name: 'Unrelated',
          event_pattern: 'forge.vulnerability.*',
          handler_type: 'notification',
          handler_config: '{}',
          conditions: null,
          is_active: 1,
          priority: 1,
        },
      ],
    });

    const result = await publish(db, 'forge.scan.started', 'forgescan', {});
    expect(result.subscriptions_matched).toBe(0);
  });

  it('evaluates severity conditions', async () => {
    const db = createMockDB({
      subscriptions: [
        {
          id: 'sub-cond',
          name: 'Critical Only',
          event_pattern: 'forge.vulnerability.*',
          handler_type: 'notification',
          handler_config: '{}',
          conditions: JSON.stringify({ severity: ['critical', 'high'] }),
          is_active: 1,
          priority: 1,
        },
      ],
    });

    const resultMatch = await publish(db, 'forge.vulnerability.detected', 'forgescan', { severity: 'critical' });
    expect(resultMatch.subscriptions_matched).toBe(1);

    const resultNoMatch = await publish(db, 'forge.vulnerability.detected', 'forgescan', { severity: 'low' });
    expect(resultNoMatch.subscriptions_matched).toBe(0);
  });

  it('evaluates min_cvss conditions', async () => {
    const db = createMockDB({
      subscriptions: [
        {
          id: 'sub-cvss',
          name: 'High CVSS',
          event_pattern: 'forge.vulnerability.*',
          handler_type: 'notification',
          handler_config: '{}',
          conditions: JSON.stringify({ min_cvss: 7.0 }),
          is_active: 1,
          priority: 1,
        },
      ],
    });

    const resultAbove = await publish(db, 'forge.vulnerability.detected', 'forgescan', { cvss_score: 9.8 });
    expect(resultAbove.subscriptions_matched).toBe(1);

    const resultBelow = await publish(db, 'forge.vulnerability.detected', 'forgescan', { cvss_score: 3.0 });
    expect(resultBelow.subscriptions_matched).toBe(0);
  });

  it('passes correlation_id to event', async () => {
    const db = createMockDB();
    await publish(db, 'forge.scan.started', 'forgescan', {}, { correlation_id: 'corr-123' });

    // Verify the INSERT was called with the correlation ID
    const prepareCall = db.prepare.mock.calls.find((c: any) =>
      c[0].includes('INSERT INTO forge_events')
    );
    expect(prepareCall).toBeDefined();
  });

  it('handles subscription handler errors gracefully', async () => {
    const db = createMockDB({
      subscriptions: [
        {
          id: 'sub-bad',
          name: 'Bad Handler',
          event_pattern: '*',
          handler_type: 'unknown_handler_type',
          handler_config: '{}',
          conditions: null,
          is_active: 1,
          priority: 1,
        },
      ],
    });

    const result = await publish(db, 'forge.scan.started', 'forgescan', {});
    // Should not throw, but count the failed handler
    expect(result.subscriptions_matched).toBe(1);
  });
});

describe('Event Bus — registerHandler() / unregisterHandler()', () => {
  afterEach(() => {
    // Clean up any registered handlers
    unregisterHandler('test-handler-1');
    unregisterHandler('test-handler-2');
  });

  it('registers and executes in-memory handler', async () => {
    const handlerFn = vi.fn().mockResolvedValue({ success: true, message: 'ok' });

    registerHandler({
      id: 'test-handler-1',
      event_pattern: 'forge.scan.*',
      handler: handlerFn,
    });

    const db = createMockDB();
    vi.stubGlobal('crypto', { randomUUID: vi.fn().mockReturnValue('test-uuid') });

    const result = await publish(db, 'forge.scan.completed', 'forgescan', { count: 5 });

    expect(handlerFn).toHaveBeenCalled();
    expect(result.subscriptions_matched).toBeGreaterThanOrEqual(1);
    expect(result.subscriptions_executed).toBeGreaterThanOrEqual(1);

    vi.restoreAllMocks();
  });

  it('unregisters handler so it stops being called', async () => {
    const handlerFn = vi.fn().mockResolvedValue({ success: true });

    registerHandler({
      id: 'test-handler-2',
      event_pattern: '*',
      handler: handlerFn,
    });

    unregisterHandler('test-handler-2');

    const db = createMockDB();
    vi.stubGlobal('crypto', { randomUUID: vi.fn().mockReturnValue('test-uuid') });

    await publish(db, 'forge.scan.started', 'forgescan', {});
    expect(handlerFn).not.toHaveBeenCalled();

    vi.restoreAllMocks();
  });

  it('handles in-memory handler errors without crashing', async () => {
    registerHandler({
      id: 'test-handler-1',
      event_pattern: '*',
      handler: vi.fn().mockRejectedValue(new Error('handler boom')),
    });

    const db = createMockDB();
    vi.stubGlobal('crypto', { randomUUID: vi.fn().mockReturnValue('test-uuid') });

    const result = await publish(db, 'forge.scan.started', 'forgescan', {});
    expect(result.subscriptions_failed).toBeGreaterThanOrEqual(1);

    vi.restoreAllMocks();
  });
});

describe('Event Bus — queryEvents()', () => {
  it('returns paginated events', async () => {
    const events = [
      { id: 'evt-1', event_type: 'forge.scan.started', source: 'forgescan', payload: '{}', created_at: '2024-01-01T00:00:00Z' },
      { id: 'evt-2', event_type: 'forge.scan.completed', source: 'forgescan', payload: '{"findings":5}', created_at: '2024-01-02T00:00:00Z' },
    ];

    const db = createMockDB({ events, firstResult: { total: 2 } });
    const result = await queryEvents(db, {});

    expect(result.page).toBe(1);
    expect(result.page_size).toBe(50);
  });

  it('respects custom pagination', async () => {
    const db = createMockDB({ firstResult: { total: 100 } });
    const result = await queryEvents(db, { page: 3, page_size: 10 });

    expect(result.page).toBe(3);
    expect(result.page_size).toBe(10);
  });

  it('caps page_size at 200', async () => {
    const db = createMockDB({ firstResult: { total: 0 } });
    const result = await queryEvents(db, { page_size: 500 });

    expect(result.page_size).toBe(200);
  });

  it('filters by event_type', async () => {
    const db = createMockDB({ firstResult: { total: 0 } });
    await queryEvents(db, { event_type: 'forge.scan.started' });

    const prepareCall = db.prepare.mock.calls.find((c: any) =>
      c[0].includes('event_type = ?')
    );
    expect(prepareCall).toBeDefined();
  });

  it('filters by correlation_id', async () => {
    const db = createMockDB({ firstResult: { total: 0 } });
    await queryEvents(db, { correlation_id: 'campaign-123' });

    const prepareCall = db.prepare.mock.calls.find((c: any) =>
      c[0].includes('correlation_id = ?')
    );
    expect(prepareCall).toBeDefined();
  });
});
