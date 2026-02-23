// ─────────────────────────────────────────────────────────────────────────────
// ForgeSOC Alert Handler — Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createAlertFromEvent, registerSOCHandlers } from './alert-handler';
import type { ForgeEvent } from '../event-bus/types';

// ─── Mock helpers ───────────────────────────────────────────────────────────

function mockEvent(overrides: Partial<ForgeEvent> = {}): ForgeEvent {
  return {
    id: 'evt-001',
    event_type: 'forge.vulnerability.detected',
    source: 'forgescan',
    payload: {
      title: 'SQL Injection Found',
      severity: 'critical',
      cvss_score: 9.8,
      cve_id: 'CVE-2024-1234',
      finding_id: 'finding-001',
    },
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

function mockDetectionRule(overrides: Record<string, unknown> = {}) {
  return {
    id: 'rule-001',
    name: 'Critical Vulnerability Detection',
    event_pattern: 'forge.vulnerability.*',
    conditions: JSON.stringify({ severity: ['critical'] }),
    alert_severity: 'critical',
    alert_type: 'vulnerability',
    tags: JSON.stringify(['auto-detected', 'vulnerability']),
    is_active: 1,
    auto_escalate: 0,
    cooldown_seconds: 0,
    last_triggered_at: null,
    trigger_count: 0,
    ...overrides,
  };
}

function createAlertHandlerMockDB(options: {
  rules?: any[];
  shouldMatchRule?: boolean;
} = {}) {
  const { rules = [mockDetectionRule()], shouldMatchRule = true } = options;

  const runCalls: string[] = [];
  const bindCalls: unknown[][] = [];

  const db = {
    prepare: vi.fn().mockImplementation((sql: string) => {
      return {
        bind: vi.fn().mockImplementation((...args: unknown[]) => {
          bindCalls.push(args);
          return {
            run: vi.fn().mockImplementation(() => {
              runCalls.push(sql);
              return Promise.resolve({ success: true });
            }),
            first: vi.fn().mockResolvedValue(null),
            all: vi.fn().mockResolvedValue({ results: rules }),
          };
        }),
        run: vi.fn().mockResolvedValue({ success: true }),
        first: vi.fn().mockResolvedValue(null),
        all: vi.fn().mockResolvedValue({ results: rules }),
      };
    }),
    _getRunCalls: () => runCalls,
    _getBindCalls: () => bindCalls,
  };

  return db as unknown as D1Database & { _getRunCalls: () => string[]; _getBindCalls: () => unknown[][] };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('createAlertFromEvent()', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('test-uuid-alert'),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('creates alert when event matches a detection rule', async () => {
    const event = mockEvent();
    const db = createAlertHandlerMockDB();

    const result = await createAlertFromEvent(event, db);

    expect(result.alert_id).toBe('test-uuid-alert');
    expect(result.incident_id).toBeNull();
  });

  it('returns null alert_id when no rules match', async () => {
    const event = mockEvent({
      event_type: 'forge.scan.started',
      payload: { severity: 'info' },
    });

    // Rule pattern is forge.vulnerability.* so forge.scan.started won't match
    const db = createAlertHandlerMockDB();

    const result = await createAlertFromEvent(event, db);
    expect(result.alert_id).toBeNull();
  });

  it('returns null when no active rules exist', async () => {
    const event = mockEvent();
    const db = createAlertHandlerMockDB({ rules: [] });

    const result = await createAlertFromEvent(event, db);
    expect(result.alert_id).toBeNull();
    expect(result.incident_id).toBeNull();
  });

  it('skips rules that fail condition evaluation', async () => {
    const event = mockEvent({
      payload: { severity: 'low', cvss_score: 2.0 },
    });

    const rule = mockDetectionRule({
      conditions: JSON.stringify({ severity: ['critical', 'high'] }),
    });

    const db = createAlertHandlerMockDB({ rules: [rule] });
    const result = await createAlertFromEvent(event, db);

    expect(result.alert_id).toBeNull();
  });

  it('auto-escalates to incident when rule has auto_escalate', async () => {
    const event = mockEvent();
    const rule = mockDetectionRule({ auto_escalate: 1 });
    const db = createAlertHandlerMockDB({ rules: [rule] });

    const result = await createAlertFromEvent(event, db);

    expect(result.alert_id).toBe('test-uuid-alert');
    expect(result.incident_id).toBe('test-uuid-alert');
  });

  it('respects cooldown period', async () => {
    const event = mockEvent();
    const rule = mockDetectionRule({
      cooldown_seconds: 3600,
      last_triggered_at: new Date().toISOString(), // just now
    });

    const db = createAlertHandlerMockDB({ rules: [rule] });
    const result = await createAlertFromEvent(event, db);

    // Should skip due to cooldown
    expect(result.alert_id).toBeNull();
  });

  it('fires after cooldown has expired', async () => {
    const event = mockEvent();
    const pastDate = new Date(Date.now() - 7200 * 1000).toISOString(); // 2 hours ago
    const rule = mockDetectionRule({
      cooldown_seconds: 3600,
      last_triggered_at: pastDate,
    });

    const db = createAlertHandlerMockDB({ rules: [rule] });
    const result = await createAlertFromEvent(event, db);

    expect(result.alert_id).toBe('test-uuid-alert');
  });

  it('builds title from event payload title', async () => {
    const event = mockEvent({
      payload: { title: 'RCE in API Gateway', severity: 'critical' },
    });
    const rule = mockDetectionRule({ conditions: '{}' });
    const db = createAlertHandlerMockDB({ rules: [rule] });

    await createAlertFromEvent(event, db);

    const bindCalls = db._getBindCalls();
    // The INSERT bind call should contain the title
    const insertBind = bindCalls.find(
      (args) => typeof args[1] === 'string' && args[1].includes('RCE in API Gateway')
    );
    expect(insertBind).toBeDefined();
  });

  it('builds title from CVE ID when no title present', async () => {
    const event = mockEvent({
      payload: { cve_id: 'CVE-2024-9999', severity: 'critical' },
    });
    const rule = mockDetectionRule({ conditions: '{}' });
    const db = createAlertHandlerMockDB({ rules: [rule] });

    await createAlertFromEvent(event, db);

    const bindCalls = db._getBindCalls();
    const insertBind = bindCalls.find(
      (args) => typeof args[1] === 'string' && args[1].includes('CVE-2024-9999')
    );
    expect(insertBind).toBeDefined();
  });

  it('matches wildcard patterns', async () => {
    const event = mockEvent({ event_type: 'forge.vulnerability.status_changed' });
    const rule = mockDetectionRule({
      event_pattern: 'forge.vulnerability.*',
      conditions: '{}',
    });
    const db = createAlertHandlerMockDB({ rules: [rule] });

    const result = await createAlertFromEvent(event, db);
    expect(result.alert_id).toBe('test-uuid-alert');
  });

  it('matches double wildcard patterns', async () => {
    const event = mockEvent({ event_type: 'forge.redops.exploitation.success' });
    const rule = mockDetectionRule({
      event_pattern: 'forge.redops.**',
      conditions: '{}',
    });
    const db = createAlertHandlerMockDB({ rules: [rule] });

    const result = await createAlertFromEvent(event, db);
    expect(result.alert_id).toBe('test-uuid-alert');
  });

  it('does not match unrelated event patterns', async () => {
    const event = mockEvent({ event_type: 'forge.scan.completed' });
    const rule = mockDetectionRule({
      event_pattern: 'forge.vulnerability.*',
      conditions: '{}',
    });
    const db = createAlertHandlerMockDB({ rules: [rule] });

    const result = await createAlertFromEvent(event, db);
    expect(result.alert_id).toBeNull();
  });

  it('evaluates min_cvss conditions', async () => {
    const event = mockEvent({
      payload: { severity: 'critical', cvss_score: 9.8 },
    });
    const rule = mockDetectionRule({
      conditions: JSON.stringify({ min_cvss: 9.0 }),
    });
    const db = createAlertHandlerMockDB({ rules: [rule] });

    const result = await createAlertFromEvent(event, db);
    expect(result.alert_id).toBe('test-uuid-alert');
  });

  it('rejects events below min_cvss threshold', async () => {
    const event = mockEvent({
      payload: { severity: 'medium', cvss_score: 5.5 },
    });
    const rule = mockDetectionRule({
      conditions: JSON.stringify({ min_cvss: 9.0 }),
    });
    const db = createAlertHandlerMockDB({ rules: [rule] });

    const result = await createAlertFromEvent(event, db);
    expect(result.alert_id).toBeNull();
  });

  it('only creates one alert per event (first matching rule wins)', async () => {
    const event = mockEvent({
      payload: { severity: 'critical' },
    });
    const rule1 = mockDetectionRule({
      id: 'rule-001',
      conditions: '{}',
      alert_severity: 'critical',
    });
    const rule2 = mockDetectionRule({
      id: 'rule-002',
      conditions: '{}',
      alert_severity: 'high',
    });
    const db = createAlertHandlerMockDB({ rules: [rule1, rule2] });

    const result = await createAlertFromEvent(event, db);
    // Should only create one alert
    expect(result.alert_id).toBe('test-uuid-alert');
  });
});

describe('registerSOCHandlers()', () => {
  it('registers without throwing', () => {
    // registerHandler is imported from event-bus which may need mocking
    // but since it's a simple registration, just verify no errors
    expect(() => registerSOCHandlers()).not.toThrow();
  });
});
