// ─────────────────────────────────────────────────────────────────────────────
// AI Provider — Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ClaudeAIProvider, createAIProvider } from './index';

// ─── Mock fetch ──────────────────────────────────────────────────────────────

function mockFetchResponse(content: string, usage = { input_tokens: 100, output_tokens: 50 }) {
  return vi.fn().mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve({
        content: [{ type: 'text', text: content }],
        model: 'claude-sonnet-4-5-20250929',
        usage,
      }),
  });
}

function mockFetchError(status: number, body: string) {
  return vi.fn().mockResolvedValue({
    ok: false,
    status,
    text: () => Promise.resolve(body),
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('ClaudeAIProvider', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('constructor & configuration', () => {
    it('creates provider with required config', () => {
      const provider = new ClaudeAIProvider({ api_key: 'test-key' });
      expect(provider).toBeDefined();
    });

    it('tracks token usage starting at zero', () => {
      const provider = new ClaudeAIProvider({ api_key: 'test-key' });
      const usage = provider.getTokenUsage();
      expect(usage.used).toBe(0);
      expect(usage.remaining).toBe(Infinity);
    });

    it('respects custom token budget', () => {
      const provider = new ClaudeAIProvider({ api_key: 'test-key', token_budget: 10000 });
      const usage = provider.getTokenUsage();
      expect(usage.limit).toBe(10000);
      expect(usage.remaining).toBe(10000);
    });
  });

  describe('analyze()', () => {
    it('calls Claude API and returns result', async () => {
      globalThis.fetch = mockFetchResponse('Analysis complete.');

      const provider = new ClaudeAIProvider({ api_key: 'test-key' });
      const result = await provider.analyze('Analyze this data');

      expect(result.content).toBe('Analysis complete.');
      expect(result.model).toBe('claude-sonnet-4-5-20250929');
      expect(result.tokens_used.total).toBe(150);
      expect(result.duration_ms).toBeGreaterThanOrEqual(0);
    });

    it('passes system_prompt from context', async () => {
      globalThis.fetch = mockFetchResponse('ok');

      const provider = new ClaudeAIProvider({ api_key: 'test-key' });
      await provider.analyze('prompt', { system_prompt: 'Custom system' });

      const call = (globalThis.fetch as any).mock.calls[0];
      const body = JSON.parse(call[1].body);
      expect(body.system).toBe('Custom system');
    });

    it('sends correct API headers', async () => {
      globalThis.fetch = mockFetchResponse('ok');

      const provider = new ClaudeAIProvider({ api_key: 'my-api-key' });
      await provider.analyze('test');

      const call = (globalThis.fetch as any).mock.calls[0];
      expect(call[1].headers['x-api-key']).toBe('my-api-key');
      expect(call[1].headers['anthropic-version']).toBe('2023-06-01');
      expect(call[1].headers['Content-Type']).toBe('application/json');
    });

    it('uses custom model when configured', async () => {
      globalThis.fetch = mockFetchResponse('ok');

      const provider = new ClaudeAIProvider({ api_key: 'key', model: 'claude-opus-4-6' });
      await provider.analyze('test');

      const body = JSON.parse((globalThis.fetch as any).mock.calls[0][1].body);
      expect(body.model).toBe('claude-opus-4-6');
    });

    it('accumulates token usage across calls', async () => {
      globalThis.fetch = mockFetchResponse('ok', { input_tokens: 100, output_tokens: 200 });

      const provider = new ClaudeAIProvider({ api_key: 'key', token_budget: 100000 });
      await provider.analyze('first');
      await provider.analyze('second');

      const usage = provider.getTokenUsage();
      expect(usage.used).toBe(600); // 300 per call × 2
      expect(usage.remaining).toBe(100000 - 600);
    });

    it('throws on API error', async () => {
      globalThis.fetch = mockFetchError(429, 'Rate limited');

      const provider = new ClaudeAIProvider({ api_key: 'key' });
      await expect(provider.analyze('test')).rejects.toThrow('Claude API error (429)');
    });
  });

  describe('token budget enforcement', () => {
    it('throws when budget is exhausted', async () => {
      globalThis.fetch = mockFetchResponse('ok', { input_tokens: 500, output_tokens: 500 });

      const provider = new ClaudeAIProvider({ api_key: 'key', token_budget: 1000 });
      await provider.analyze('first call'); // Uses 1000 tokens, hits budget

      await expect(provider.analyze('second call')).rejects.toThrow('AI token budget exhausted');
    });

    it('allows calls under budget', async () => {
      globalThis.fetch = mockFetchResponse('ok', { input_tokens: 100, output_tokens: 100 });

      const provider = new ClaudeAIProvider({ api_key: 'key', token_budget: 5000 });
      const result = await provider.analyze('test');

      expect(result.content).toBe('ok');
    });
  });

  describe('generateTestPlan()', () => {
    it('returns parsed JSON test plan', async () => {
      const plan = JSON.stringify({
        target: 'https://example.com',
        tests: [{ id: 'T-001', name: 'SQL Injection', description: 'Test', category: 'injection', risk_level: 'medium', steps: ['step1'] }],
        estimated_duration_seconds: 300,
      });
      globalThis.fetch = mockFetchResponse(plan);

      const provider = new ClaudeAIProvider({ api_key: 'key' });
      const result = await provider.generateTestPlan('web_injection', 'https://example.com', { exploitation_level: 'safe' });

      expect(result.target).toBe('https://example.com');
      expect(result.tests).toHaveLength(1);
      expect(result.tests[0].id).toBe('T-001');
      expect(result.estimated_duration_seconds).toBe(300);
    });

    it('includes exploitation level in system prompt', async () => {
      globalThis.fetch = mockFetchResponse('{"target":"x","tests":[],"estimated_duration_seconds":0}');

      const provider = new ClaudeAIProvider({ api_key: 'key' });
      await provider.generateTestPlan('web_misconfig', 'target', { exploitation_level: 'passive' });

      const body = JSON.parse((globalThis.fetch as any).mock.calls[0][1].body);
      expect(body.system).toContain('passive');
    });
  });

  describe('analyzeResponse()', () => {
    it('returns parsed security findings array', async () => {
      const findings = JSON.stringify([
        {
          title: 'SQL Injection',
          description: 'Found SQLi',
          severity: 'critical',
          attack_vector: 'POST /login',
          attack_category: 'OWASP A03:2021',
          cwe_id: 'CWE-89',
          exploitable: true,
          remediation: 'Use parameterized queries',
          remediation_effort: 'moderate',
        },
      ]);
      globalThis.fetch = mockFetchResponse(findings);

      const provider = new ClaudeAIProvider({ api_key: 'key' });
      const result = await provider.analyzeResponse('web_injection', 'SQLi Test', 'GET /test', 'HTTP 200 OK', {});

      expect(result).toHaveLength(1);
      expect(result[0].title).toBe('SQL Injection');
      expect(result[0].severity).toBe('critical');
      expect(result[0].exploitable).toBe(true);
    });

    it('returns empty array when no findings', async () => {
      globalThis.fetch = mockFetchResponse('[]');

      const provider = new ClaudeAIProvider({ api_key: 'key' });
      const result = await provider.analyzeResponse('web_misconfig', 'Test', 'req', 'resp', {});

      expect(result).toEqual([]);
    });
  });

  describe('assessRisk()', () => {
    it('returns structured risk assessment', async () => {
      const assessment = JSON.stringify({
        overall_risk: 'high',
        exploitability: 8.5,
        impact: 9.0,
        confidence: 85,
        reasoning: 'Publicly exploitable with high impact',
        recommendations: ['Patch immediately', 'Add WAF rule'],
      });
      globalThis.fetch = mockFetchResponse(assessment);

      const provider = new ClaudeAIProvider({ api_key: 'key' });
      const result = await provider.assessRisk(
        { title: 'SQLi', severity: 'critical' },
        { asset_type: 'web_server', criticality: 'high' }
      );

      expect(result.overall_risk).toBe('high');
      expect(result.exploitability).toBe(8.5);
      expect(result.recommendations).toHaveLength(2);
    });
  });
});

describe('createAIProvider() factory', () => {
  it('creates a provider with defaults', () => {
    const provider = createAIProvider('test-key');
    const usage = provider.getTokenUsage();
    expect(usage.limit).toBe(500000); // Default budget
    expect(usage.used).toBe(0);
  });

  it('creates provider with custom options', () => {
    const provider = createAIProvider('test-key', { token_budget: 100000, temperature: 0.5 });
    const usage = provider.getTokenUsage();
    expect(usage.limit).toBe(100000);
  });
});
