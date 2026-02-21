import { describe, it, expect } from 'vitest';
import { redops } from './redops';
import { createMockDB, createTestApp, mockCampaign, mockRedOpsFinding } from '../test-helpers';

const PREFIX = '/api/v1/redops';
const mkApp = (db: any) => createTestApp(redops, PREFIX, db);

// ─── GET /campaigns ─────────────────────────────────────────────────────────

describe('GET /api/v1/redops/campaigns', () => {
  it('returns paginated campaigns', async () => {
    const items = [mockCampaign(), mockCampaign({ id: 'campaign-002', name: 'Q2 Test' })];
    const db = createMockDB({ firstResult: { total: 2 }, allResults: items });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.items).toHaveLength(2);
    expect(body.total).toBe(2);
    expect(body.page).toBe(1);
  });

  it('filters by status', async () => {
    const db = createMockDB({ firstResult: { total: 0 }, allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns?status=completed`);
    expect(res.status).toBe(200);
  });

  it('filters by campaign type', async () => {
    const db = createMockDB({ firstResult: { total: 0 }, allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns?type=targeted`);
    expect(res.status).toBe(200);
  });

  it('respects pagination', async () => {
    const db = createMockDB({ firstResult: { total: 50 }, allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns?page=2&page_size=10`);
    const body = await res.json() as any;

    expect(body.page).toBe(2);
    expect(body.page_size).toBe(10);
    expect(body.total_pages).toBe(5);
  });
});

// ─── GET /campaigns/:id ─────────────────────────────────────────────────────

describe('GET /api/v1/redops/campaigns/:id', () => {
  it('returns campaign by ID', async () => {
    const campaign = mockCampaign();
    const db = createMockDB({ firstResult: campaign });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.id).toBe('campaign-001');
    expect(body.name).toBe('Q1 Pen Test');
  });

  it('returns 404 for non-existent campaign', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/nonexistent`);
    expect(res.status).toBe(404);

    const body = await res.json() as any;
    expect(body.error.code).toBe('NOT_FOUND');
  });
});

// ─── POST /campaigns ────────────────────────────────────────────────────────

describe('POST /api/v1/redops/campaigns', () => {
  it('creates a campaign', async () => {
    const created = mockCampaign();
    const db = createMockDB({ firstResult: created });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'New Campaign',
        target_scope: ['10.0.0.0/24'],
        agent_categories: ['web', 'api'],
        exploitation_level: 'safe',
      }),
    });

    expect(res.status).toBe(201);
  });

  it('rejects missing name', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_scope: ['10.0.0.0/24'],
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.code).toBe('MISSING_FIELD');
  });

  it('rejects missing target_scope', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'No Target',
      }),
    });

    expect(res.status).toBe(400);
  });

  it('rejects invalid exploitation_level', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Bad Level',
        target_scope: ['10.0.0.0/24'],
        exploitation_level: 'destructive',
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('exploitation_level');
  });

  it('rejects invalid campaign_type', async () => {
    const db = createMockDB();
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Bad Type',
        target_scope: ['10.0.0.0/24'],
        campaign_type: 'unknown_type',
      }),
    });

    expect(res.status).toBe(400);
  });
});

// ─── PUT /campaigns/:id ─────────────────────────────────────────────────────

describe('PUT /api/v1/redops/campaigns/:id', () => {
  it('updates a campaign', async () => {
    const existing = mockCampaign();
    const updated = mockCampaign({ name: 'Updated Name' });
    const db = createMockDB({ firstResult: existing });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Updated Name' }),
    });

    expect(res.status).toBe(200);
  });

  it('returns 404 for non-existent campaign', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/nonexistent`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Updated' }),
    });

    expect(res.status).toBe(404);
  });

  it('blocks update of running campaign', async () => {
    const running = mockCampaign({ status: 'scanning' });
    const db = createMockDB({ firstResult: running });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Try Update' }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('currently running');
  });

  it('rejects empty update', async () => {
    const existing = mockCampaign();
    const db = createMockDB({ firstResult: existing });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('No fields');
  });
});

// ─── POST /campaigns/:id/launch ─────────────────────────────────────────────

describe('POST /api/v1/redops/campaigns/:id/launch', () => {
  it('launches a created campaign', async () => {
    const campaign = mockCampaign({ status: 'created' });
    const agentTypes = [
      { id: 'web_injection', category: 'web' },
      { id: 'api_auth_bypass', category: 'api' },
    ];
    const updatedCampaign = mockCampaign({ status: 'queued', total_agents: 2 });

    // Build a mock that handles sequential calls
    const db = createMockDB({ firstResult: campaign, allResults: agentTypes });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/launch`, { method: 'POST' });
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.agents_created).toBeDefined();
    expect(body.message).toContain('launched');
  });

  it('returns 404 for non-existent campaign', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/nonexistent/launch`, { method: 'POST' });
    expect(res.status).toBe(404);
  });

  it('rejects launching from non-created status', async () => {
    const campaign = mockCampaign({ status: 'completed' });
    const db = createMockDB({ firstResult: campaign });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/launch`, { method: 'POST' });
    expect(res.status).toBe(400);

    const body = await res.json() as any;
    expect(body.error.message).toContain('cannot be launched');
  });

  it('allows launching from failed status', async () => {
    const campaign = mockCampaign({ status: 'failed' });
    const agentTypes = [{ id: 'web_xss', category: 'web' }];
    const db = createMockDB({ firstResult: campaign, allResults: agentTypes });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/launch`, { method: 'POST' });
    expect(res.status).toBe(200);
  });
});

// ─── POST /campaigns/:id/cancel ─────────────────────────────────────────────

describe('POST /api/v1/redops/campaigns/:id/cancel', () => {
  it('cancels a running campaign', async () => {
    const campaign = mockCampaign({ status: 'scanning' });
    const db = createMockDB({ firstResult: campaign });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/cancel`, { method: 'POST' });
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.message).toBe('Campaign cancelled');
  });

  it('returns 404 for non-existent campaign', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/nonexistent/cancel`, { method: 'POST' });
    expect(res.status).toBe(404);
  });

  it('rejects cancelling a completed campaign', async () => {
    const campaign = mockCampaign({ status: 'completed' });
    const db = createMockDB({ firstResult: campaign });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/cancel`, { method: 'POST' });
    expect(res.status).toBe(400);

    const body = await res.json() as any;
    expect(body.error.message).toContain('cannot be cancelled');
  });
});

// ─── DELETE /campaigns/:id ──────────────────────────────────────────────────

describe('DELETE /api/v1/redops/campaigns/:id', () => {
  it('deletes a created campaign', async () => {
    const campaign = mockCampaign({ status: 'created' });
    const db = createMockDB({ firstResult: campaign });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001`, { method: 'DELETE' });
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.message).toBe('Campaign deleted');
  });

  it('returns 404 for non-existent campaign', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/nonexistent`, { method: 'DELETE' });
    expect(res.status).toBe(404);
  });

  it('blocks deletion of running campaign', async () => {
    const campaign = mockCampaign({ status: 'exploitation' });
    const db = createMockDB({ firstResult: campaign });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001`, { method: 'DELETE' });
    expect(res.status).toBe(400);

    const body = await res.json() as any;
    expect(body.error.message).toContain('Cancel it first');
  });

  it('allows deletion of cancelled campaign', async () => {
    const campaign = mockCampaign({ status: 'cancelled' });
    const db = createMockDB({ firstResult: campaign });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001`, { method: 'DELETE' });
    expect(res.status).toBe(200);
  });
});

// ─── GET /campaigns/:id/agents ──────────────────────────────────────────────

describe('GET /api/v1/redops/campaigns/:id/agents', () => {
  it('returns agents for a campaign', async () => {
    const agents = [
      { id: 'agent-001', campaign_id: 'campaign-001', agent_type: 'web_injection', agent_category: 'web', status: 'completed' },
      { id: 'agent-002', campaign_id: 'campaign-001', agent_type: 'api_auth_bypass', agent_category: 'api', status: 'running' },
    ];
    const db = createMockDB({ allResults: agents });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/agents`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body).toHaveLength(2);
  });

  it('filters by status', async () => {
    const db = createMockDB({ allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/agents?status=running`);
    expect(res.status).toBe(200);
  });

  it('filters by category', async () => {
    const db = createMockDB({ allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/agents?category=web`);
    expect(res.status).toBe(200);
  });
});

// ─── GET /agents/:id ────────────────────────────────────────────────────────

describe('GET /api/v1/redops/agents/:id', () => {
  it('returns agent details', async () => {
    const agent = { id: 'agent-001', agent_type: 'web_injection', status: 'completed' };
    const db = createMockDB({ firstResult: agent });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/agents/agent-001`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.id).toBe('agent-001');
  });

  it('returns 404 for non-existent agent', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/agents/nonexistent`);
    expect(res.status).toBe(404);
  });
});

// ─── GET /agent-types ───────────────────────────────────────────────────────

describe('GET /api/v1/redops/agent-types', () => {
  it('returns all agent types', async () => {
    const types = [
      { id: 'web_injection', category: 'web', name: 'SQL Injection Scanner', enabled: 1 },
      { id: 'web_xss', category: 'web', name: 'XSS Scanner', enabled: 1 },
      { id: 'api_auth_bypass', category: 'api', name: 'API Auth Bypass', enabled: 1 },
    ];
    const db = createMockDB({ allResults: types });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/agent-types`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body).toHaveLength(3);
  });

  it('filters by category', async () => {
    const db = createMockDB({ allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/agent-types?category=web`);
    expect(res.status).toBe(200);
  });
});

// ─── GET /campaigns/:id/findings ────────────────────────────────────────────

describe('GET /api/v1/redops/campaigns/:id/findings', () => {
  it('returns paginated findings for a campaign', async () => {
    const items = [mockRedOpsFinding()];
    const db = createMockDB({ firstResult: { total: 1 }, allResults: items });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/findings`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.items).toHaveLength(1);
    expect(body.total).toBe(1);
  });

  it('filters by severity', async () => {
    const db = createMockDB({ firstResult: { total: 0 }, allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/findings?severity=critical`);
    expect(res.status).toBe(200);
  });

  it('filters by exploitable', async () => {
    const db = createMockDB({ firstResult: { total: 0 }, allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/campaigns/campaign-001/findings?exploitable=true`);
    expect(res.status).toBe(200);
  });
});

// ─── GET /findings (global) ─────────────────────────────────────────────────

describe('GET /api/v1/redops/findings', () => {
  it('returns paginated global findings', async () => {
    const items = [
      mockRedOpsFinding({ campaign_name: 'Q1 Test' }),
      mockRedOpsFinding({ id: 'finding-002', campaign_name: 'Q1 Test' }),
    ];
    const db = createMockDB({ firstResult: { total: 2 }, allResults: items });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/findings`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.items).toHaveLength(2);
    expect(body.total).toBe(2);
  });

  it('filters by status', async () => {
    const db = createMockDB({ firstResult: { total: 0 }, allResults: [] });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/findings?status=confirmed`);
    expect(res.status).toBe(200);
  });
});

// ─── PUT /findings/:id ──────────────────────────────────────────────────────

describe('PUT /api/v1/redops/findings/:id', () => {
  it('updates finding status', async () => {
    const existing = mockRedOpsFinding();
    const updated = mockRedOpsFinding({ status: 'remediated' });
    const db = createMockDB({ firstResult: existing });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/findings/redops-finding-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'remediated' }),
    });

    expect(res.status).toBe(200);
  });

  it('returns 404 for non-existent finding', async () => {
    const db = createMockDB({ firstResult: null });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/findings/nonexistent`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'remediated' }),
    });

    expect(res.status).toBe(404);
  });

  it('rejects empty update', async () => {
    const existing = mockRedOpsFinding();
    const db = createMockDB({ firstResult: existing });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/findings/redops-finding-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error.message).toContain('No fields');
  });

  it('updates remediation text', async () => {
    const existing = mockRedOpsFinding();
    const db = createMockDB({ firstResult: existing });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/findings/redops-finding-001`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ remediation: 'Applied patch XYZ' }),
    });

    expect(res.status).toBe(200);
  });
});

// ─── GET /overview ──────────────────────────────────────────────────────────

describe('GET /api/v1/redops/overview', () => {
  it('returns dashboard overview stats', async () => {
    // The overview endpoint makes 4 parallel queries:
    // 1. campaigns stats (first)
    // 2. findings severity (all)
    // 3. agent stats (all)
    // 4. recent campaigns (all)
    const campaignStats = {
      total_campaigns: 5,
      active_campaigns: 1,
      completed_campaigns: 3,
      total_findings: 42,
      total_exploitable: 8,
    };
    const db = createMockDB({
      firstResult: campaignStats,
      allResults: [],
    });
    const app = mkApp(db);

    const res = await app.request(`${PREFIX}/overview`);
    expect(res.status).toBe(200);

    const body = await res.json() as any;
    expect(body.campaigns).toBeDefined();
    expect(body.findings).toBeDefined();
    expect(body.agents_by_category).toBeDefined();
    expect(body.recent_campaigns).toBeDefined();
    expect(body.generated_at).toBeDefined();
  });
});
