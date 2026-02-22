// ─────────────────────────────────────────────────────────────────────────────
// Forge AI Provider — Claude API Implementation
// ─────────────────────────────────────────────────────────────────────────────

import type {
  ForgeAIProvider,
  AIProviderConfig,
  AIResult,
  AISecurityFinding,
  ExploitPlan,
  RiskAssessment,
  TokenBudget,
} from './types';

export type { ForgeAIProvider, AIResult, AISecurityFinding, ExploitPlan, RiskAssessment };

const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';
const DEFAULT_MODEL = 'claude-sonnet-4-5-20250929';
const DEFAULT_MAX_TOKENS = 4096;

/**
 * Claude API implementation of the Forge AI Provider.
 * Runs natively on Cloudflare Workers via fetch().
 */
export class ClaudeAIProvider implements ForgeAIProvider {
  private config: AIProviderConfig;
  private tokensUsed: number = 0;

  constructor(config: AIProviderConfig) {
    this.config = config;
  }

  async analyze(prompt: string, context?: Record<string, unknown>): Promise<AIResult> {
    this.checkBudget();

    const systemPrompt = context?.system_prompt as string || 'You are a security analysis assistant for ForgeScan, an enterprise vulnerability management platform.';
    const userContent = context
      ? `${prompt}\n\nContext:\n${JSON.stringify(context, null, 2)}`
      : prompt;

    const start = Date.now();
    const response = await this.callClaude(systemPrompt, userContent);
    const duration = Date.now() - start;

    this.tokensUsed += response.tokens.total;

    return {
      content: response.content,
      model: response.model,
      tokens_used: response.tokens,
      duration_ms: duration,
    };
  }

  async generateTestPlan(
    agentType: string,
    target: string,
    context: Record<string, unknown>
  ): Promise<ExploitPlan> {
    this.checkBudget();

    const systemPrompt = `You are a security testing planner for ForgeRedOps. Generate structured test plans for automated security testing agents.
You MUST respond with valid JSON only, no markdown or extra text.
Each test must include a risk_level assessment. Only include tests appropriate for the exploitation level: ${context.exploitation_level || 'safe'}.
For 'passive' level: only observe, never send test payloads.
For 'safe' level: can send benign test payloads but never attempt actual exploitation.`;

    const userContent = `Generate a test plan for the "${agentType}" security agent targeting: ${target}

Target context: ${JSON.stringify(context, null, 2)}

Respond with JSON matching this schema:
{
  "target": "string",
  "tests": [
    {
      "id": "string (e.g., WM-001)",
      "name": "string",
      "description": "string",
      "category": "string",
      "risk_level": "none|low|medium|high",
      "steps": ["string"]
    }
  ],
  "estimated_duration_seconds": number
}`;

    const start = Date.now();
    const response = await this.callClaude(systemPrompt, userContent);
    this.tokensUsed += response.tokens.total;

    return JSON.parse(response.content);
  }

  async analyzeResponse(
    agentType: string,
    testName: string,
    requestData: string,
    responseData: string,
    context: Record<string, unknown>
  ): Promise<AISecurityFinding[]> {
    this.checkBudget();

    const systemPrompt = `You are a security response analyzer for ForgeRedOps. Analyze HTTP request/response pairs for security vulnerabilities.
You MUST respond with a valid JSON array of findings. Return an empty array [] if no vulnerabilities are found.
Map findings to CWE, MITRE ATT&CK, and NIST 800-53 controls where applicable.
Be precise — only report real vulnerabilities with clear evidence, not theoretical concerns.`;

    const userContent = `Agent: ${agentType}
Test: ${testName}
Context: ${JSON.stringify(context)}

REQUEST:
${requestData.substring(0, 4000)}

RESPONSE:
${responseData.substring(0, 8000)}

Respond with a JSON array of findings matching this schema:
[{
  "title": "string",
  "description": "string",
  "severity": "critical|high|medium|low|info",
  "attack_vector": "string",
  "attack_category": "string (e.g., OWASP A05:2021)",
  "cwe_id": "string (e.g., CWE-200)",
  "exploitable": boolean,
  "exploitation_proof": "string (evidence from the response)",
  "remediation": "string",
  "remediation_effort": "quick_fix|moderate|significant|architectural",
  "mitre_tactic": "string (e.g., initial-access)",
  "mitre_technique": "string (e.g., T1190)",
  "nist_controls": ["string (e.g., SI-2, CM-6)"]
}]`;

    const start = Date.now();
    const response = await this.callClaude(systemPrompt, userContent);
    this.tokensUsed += response.tokens.total;

    return JSON.parse(response.content);
  }

  async assessRisk(
    finding: Record<string, unknown>,
    assetContext: Record<string, unknown>
  ): Promise<RiskAssessment> {
    this.checkBudget();

    const systemPrompt = `You are a risk assessment engine for ForgeScan. Evaluate vulnerabilities in the context of asset criticality and environmental factors.
You MUST respond with valid JSON only.`;

    const userContent = `Assess the risk of this vulnerability:
Finding: ${JSON.stringify(finding)}
Asset context: ${JSON.stringify(assetContext)}

Respond with JSON:
{
  "overall_risk": "critical|high|medium|low|info",
  "exploitability": number (0-10),
  "impact": number (0-10),
  "confidence": number (0-100),
  "reasoning": "string",
  "recommendations": ["string"]
}`;

    const response = await this.callClaude(systemPrompt, userContent);
    this.tokensUsed += response.tokens.total;

    return JSON.parse(response.content);
  }

  getTokenUsage(): TokenBudget {
    const limit = this.config.token_budget || Infinity;
    return {
      limit,
      used: this.tokensUsed,
      remaining: Math.max(0, limit - this.tokensUsed),
    };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Internal
  // ───────────────────────────────────────────────────────────────────────────

  private checkBudget(): void {
    if (this.config.token_budget && this.tokensUsed >= this.config.token_budget) {
      throw new Error(
        `AI token budget exhausted: used ${this.tokensUsed}/${this.config.token_budget} tokens`
      );
    }
  }

  private async callClaude(
    systemPrompt: string,
    userContent: string
  ): Promise<{
    content: string;
    model: string;
    tokens: { input: number; output: number; total: number };
  }> {
    const response = await fetch(ANTHROPIC_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.config.api_key,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.config.model || DEFAULT_MODEL,
        max_tokens: this.config.max_tokens || DEFAULT_MAX_TOKENS,
        temperature: this.config.temperature ?? 0.1,
        system: systemPrompt,
        messages: [{ role: 'user', content: userContent }],
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Claude API error (${response.status}): ${errorBody.substring(0, 500)}`);
    }

    const data = (await response.json()) as {
      content: Array<{ type: string; text: string }>;
      model: string;
      usage: { input_tokens: number; output_tokens: number };
    };

    const textContent = data.content
      .filter((c) => c.type === 'text')
      .map((c) => c.text)
      .join('');

    return {
      content: textContent,
      model: data.model,
      tokens: {
        input: data.usage.input_tokens,
        output: data.usage.output_tokens,
        total: data.usage.input_tokens + data.usage.output_tokens,
      },
    };
  }
}

/**
 * Factory function to create an AI provider from environment config.
 */
export function createAIProvider(apiKey: string, options?: Partial<AIProviderConfig>): ForgeAIProvider {
  return new ClaudeAIProvider({
    api_key: apiKey,
    model: options?.model,
    max_tokens: options?.max_tokens,
    temperature: options?.temperature,
    token_budget: options?.token_budget || 500000, // Default 500K token budget per session
  });
}
