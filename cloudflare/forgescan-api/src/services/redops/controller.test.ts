// ─────────────────────────────────────────────────────────────────────────────
// RedOps Controller — Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { registerAgent, executeCampaign } from './controller';

// ─── Mock dependencies ──────────────────────────────────────────────────────

vi.mock('../event-bus', () => ({
  publish: vi.fn().mockResolvedValue({
    event_id: 'evt-1',
    subscriptions_matched: 0,
    subscriptions_executed: 0,
    subscriptions_failed: 0,
    handler_results: [],
  }),
}));

vi.mock('../ai-provider', () => ({
  createAIProvider: vi.fn().mockReturnValue({
    analyze: vi.fn().mockResolvedValue({ content: 'ok', model: 'test', tokens_used: { total: 100 }, duration_ms: 10 }),
    generateTestPlan: vi.fn().mockResolvedValue({ target: 'x', tests: [], estimated_duration_seconds: 0 }),
    analyzeResponse: vi.fn().mockResolvedValue([]),
    assessRisk: vi.fn().mockResolvedValue({ overall_risk: 'low', exploitability: 1, impact: 1, confidence: 50, reasoning: 'test', recommendations: [] }),
    getTokenUsage: vi.fn().mockReturnValue({ limit: 200000, used: 0, remaining: 200000 }),
  }),
}));

// ─── Mock D1 Database ────────────────────────────────────────────────────────

function createControllerMockDB(options: {
  campaign?: any;
  agents?: any[];
  statusCheck?: any;
} = {}) {
  const {
    campaign = null,
    agents = [],
    statusCheck = { status: 'scanning' },
  } = options;

  let queryCount = 0;

  return {
    prepare: vi.fn().mockImplementation((sql: string) => {
      const isSelect = sql.trimStart().startsWith('SELECT');
      const isUpdate = sql.trimStart().startsWith('UPDATE');
      const isInsert = sql.trimStart().startsWith('INSERT');
      const isCampaignSelect = isSelect && sql.includes('FROM redops_campaigns') && !sql.includes('status FROM');
      const isStatusCheck = isSelect && sql.includes('status FROM redops_campaigns');
      const isAgentSelect = isSelect && sql.includes('FROM redops_agents') && sql.includes('campaign_id');
      const isAgentLog = isSelect && sql.includes('execution_log');

      return {
        bind: vi.fn().mockReturnValue({
          run: vi.fn().mockResolvedValue({ success: true, meta: { changes: 1 } }),
          first: vi.fn().mockImplementation(() => {
            if (isCampaignSelect) return Promise.resolve(campaign);
            if (isStatusCheck) return Promise.resolve(statusCheck);
            if (isAgentLog) return Promise.resolve({ execution_log: '[]' });
            return Promise.resolve(null);
          }),
          all: vi.fn().mockImplementation(() => {
            if (isAgentSelect) return Promise.resolve({ results: agents });
            return Promise.resolve({ results: [] });
          }),
        }),
        run: vi.fn().mockResolvedValue({ success: true }),
        first: vi.fn().mockResolvedValue(null),
        all: vi.fn().mockResolvedValue({ results: [] }),
      };
    }),
  } as unknown as D1Database;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('RedOps Controller — registerAgent()', () => {
  afterEach(() => {
    // Clean up test registrations
  });

  it('registers an agent implementation', () => {
    const impl = {
      execute: vi.fn().mockResolvedValue({ success: true }),
    };

    // Should not throw
    registerAgent('test_agent_type', impl);
  });

  it('overwrites existing registration', () => {
    const impl1 = { execute: vi.fn().mockResolvedValue({ success: true }) };
    const impl2 = { execute: vi.fn().mockResolvedValue({ success: true }) };

    registerAgent('overwrite_test', impl1);
    registerAgent('overwrite_test', impl2);
    // No error — last registration wins
  });
});

describe('RedOps Controller — executeCampaign()', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('test-uuid'),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns error when campaign not found', async () => {
    const db = createControllerMockDB({ campaign: null });
    const result = await executeCampaign(db, 'nonexistent', 'api-key');

    expect(result.success).toBe(false);
    expect(result.error).toBe('Campaign not found');
    expect(result.findings_total).toBe(0);
  });

  it('executes campaign with no agents successfully', async () => {
    const db = createControllerMockDB({
      campaign: {
        id: 'campaign-1',
        name: 'Test Campaign',
        status: 'created',
        campaign_type: 'full',
        target_scope: '{"hosts":["10.0.0.1"],"urls":["https://example.com"]}',
        agent_categories: '["web"]',
        max_concurrent_agents: 3,
        exploitation_level: 'safe',
        risk_threshold: 'critical',
        auto_poam: 0,
        compliance_mapping: 1,
        total_agents: 0,
        active_agents: 0,
        completed_agents: 0,
        failed_agents: 0,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        exploitable_count: 0,
      },
      agents: [],
    });

    const result = await executeCampaign(db, 'campaign-1', 'api-key');
    expect(result.success).toBe(true);
    expect(result.findings_total).toBe(0);
  });

  it('executes agents that have no registered implementation (skip)', async () => {
    const db = createControllerMockDB({
      campaign: {
        id: 'campaign-2',
        name: 'Agent Test',
        status: 'created',
        campaign_type: 'full',
        target_scope: '{"hosts":["10.0.0.1"]}',
        agent_categories: '["web"]',
        max_concurrent_agents: 2,
        exploitation_level: 'safe',
        risk_threshold: 'critical',
        auto_poam: 0,
        compliance_mapping: 1,
        total_agents: 1,
        active_agents: 0,
        completed_agents: 0,
        failed_agents: 0,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        exploitable_count: 0,
      },
      agents: [
        {
          id: 'agent-1',
          campaign_id: 'campaign-2',
          agent_type: 'unregistered_agent_type',
          agent_category: 'web',
          status: 'queued',
          target: null,
          tests_planned: 0,
          tests_completed: 0,
          tests_passed: 0,
          tests_failed: 0,
          findings_count: 0,
          exploitable_count: 0,
          execution_log: null,
        },
      ],
    });

    const result = await executeCampaign(db, 'campaign-2', 'api-key');
    expect(result.success).toBe(true);
    expect(result.findings_total).toBe(0);
  });

  it('executes registered agent and collects findings', async () => {
    // Register a test agent that reports findings
    registerAgent('test_finding_agent', {
      async execute(_agent, _campaign, _targets, _ai, _db, onFinding, onProgress) {
        await onProgress(_agent, 'Starting test');
        await onFinding(
          {
            title: 'Test Vulnerability',
            description: 'Found a test vuln',
            severity: 'high',
            attack_vector: 'HTTP GET /test',
            attack_category: 'OWASP A01:2021',
            cwe_id: 'CWE-89',
            exploitable: true,
            exploitation_proof: 'Proof here',
            remediation: 'Fix it',
            remediation_effort: 'moderate',
            mitre_tactic: 'initial-access',
            mitre_technique: 'T1190',
            nist_controls: ['SI-10'],
          },
          _agent
        );
        return { success: true };
      },
    });

    const db = createControllerMockDB({
      campaign: {
        id: 'campaign-3',
        name: 'Finding Test',
        status: 'created',
        campaign_type: 'targeted',
        target_scope: '{"urls":["https://example.com"]}',
        agent_categories: '["web"]',
        max_concurrent_agents: 1,
        exploitation_level: 'safe',
        risk_threshold: 'critical',
        auto_poam: 0,
        compliance_mapping: 1,
        total_agents: 1,
        active_agents: 0,
        completed_agents: 0,
        failed_agents: 0,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        exploitable_count: 0,
      },
      agents: [
        {
          id: 'agent-finding',
          campaign_id: 'campaign-3',
          agent_type: 'test_finding_agent',
          agent_category: 'web',
          status: 'queued',
          target: null,
          tests_planned: 0,
          tests_completed: 0,
          tests_passed: 0,
          tests_failed: 0,
          findings_count: 0,
          exploitable_count: 0,
          execution_log: null,
        },
      ],
    });

    const result = await executeCampaign(db, 'campaign-3', 'api-key');
    expect(result.success).toBe(true);
    expect(result.findings_total).toBe(1);
  });

  it('handles agent execution errors gracefully', async () => {
    registerAgent('test_error_agent', {
      async execute() {
        throw new Error('Agent crashed');
      },
    });

    const db = createControllerMockDB({
      campaign: {
        id: 'campaign-err',
        name: 'Error Test',
        status: 'created',
        campaign_type: 'full',
        target_scope: '{"hosts":["10.0.0.1"]}',
        agent_categories: '["web"]',
        max_concurrent_agents: 1,
        exploitation_level: 'safe',
        risk_threshold: 'critical',
        auto_poam: 0,
        compliance_mapping: 1,
        total_agents: 1,
        active_agents: 0,
        completed_agents: 0,
        failed_agents: 0,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        exploitable_count: 0,
      },
      agents: [
        {
          id: 'agent-err',
          campaign_id: 'campaign-err',
          agent_type: 'test_error_agent',
          agent_category: 'web',
          status: 'queued',
          target: null,
          tests_planned: 0,
          tests_completed: 0,
          tests_passed: 0,
          tests_failed: 0,
          findings_count: 0,
          exploitable_count: 0,
          execution_log: null,
        },
      ],
    });

    const result = await executeCampaign(db, 'campaign-err', 'api-key');
    // Campaign should still complete, but with failed agents
    expect(result.success).toBe(true);
  });

  it('stops execution when campaign is cancelled', async () => {
    registerAgent('test_slow_agent', {
      async execute(_agent, _campaign, _targets, _ai, _db, _onFinding, onProgress) {
        await onProgress(_agent, 'Running...');
        return { success: true };
      },
    });

    const db = createControllerMockDB({
      campaign: {
        id: 'campaign-cancel',
        name: 'Cancel Test',
        status: 'created',
        campaign_type: 'full',
        target_scope: '{"hosts":["10.0.0.1"]}',
        agent_categories: '["web"]',
        max_concurrent_agents: 1,
        exploitation_level: 'safe',
        risk_threshold: 'critical',
        auto_poam: 0,
        compliance_mapping: 1,
        total_agents: 2,
        active_agents: 0,
        completed_agents: 0,
        failed_agents: 0,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        exploitable_count: 0,
      },
      agents: [
        {
          id: 'agent-c1', campaign_id: 'campaign-cancel', agent_type: 'test_slow_agent', agent_category: 'web',
          status: 'queued', target: null, tests_planned: 0, tests_completed: 0, tests_passed: 0, tests_failed: 0,
          findings_count: 0, exploitable_count: 0, execution_log: null,
        },
        {
          id: 'agent-c2', campaign_id: 'campaign-cancel', agent_type: 'test_slow_agent', agent_category: 'web',
          status: 'queued', target: null, tests_planned: 0, tests_completed: 0, tests_passed: 0, tests_failed: 0,
          findings_count: 0, exploitable_count: 0, execution_log: null,
        },
      ],
      statusCheck: { status: 'cancelled' },
    });

    const result = await executeCampaign(db, 'campaign-cancel', 'api-key');
    expect(result.success).toBe(true);
  });
});
