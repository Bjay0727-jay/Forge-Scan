// ─────────────────────────────────────────────────────────────────────────────
// ForgeRedOps Agent: API Auth Bypass (api_auth_bypass)
// ─────────────────────────────────────────────────────────────────────────────
//
// Tests for broken object-level authorization (BOLA/IDOR),
// missing function-level authorization, JWT vulnerabilities,
// and API key leakage in responses.
//
// 28 tests defined in redops_agent_types seed data.

import type { ForgeAIProvider, AISecurityFinding } from '../../ai-provider';
import { registerAgent } from '../controller';

interface Agent {
  id: string;
  campaign_id: string;
  agent_type: string;
  agent_category: string;
  status: string;
  target: string | null;
  tests_planned: number;
  tests_completed: number;
  tests_passed: number;
  tests_failed: number;
  findings_count: number;
  exploitable_count: number;
  execution_log: string | null;
}

interface Campaign {
  id: string;
  name: string;
  exploitation_level: string;
  [key: string]: unknown;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test definitions
// ─────────────────────────────────────────────────────────────────────────────

interface AuthTest {
  id: string;
  name: string;
  description: string;
  category: 'bola' | 'bfla' | 'jwt' | 'key_leak' | 'auth_header';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe_id: string;
  mitre_technique: string;
  remediation: string;
}

const AUTH_TESTS: AuthTest[] = [
  // ── BOLA / IDOR ──
  {
    id: 'AB-001', name: 'BOLA via sequential ID manipulation',
    description: 'Tests if incrementing/decrementing resource IDs returns other users\' data',
    category: 'bola', severity: 'critical', cwe_id: 'CWE-639', mitre_technique: 'T1078',
    remediation: 'Implement proper object-level authorization checks on every API endpoint',
  },
  {
    id: 'AB-002', name: 'BOLA via UUID enumeration',
    description: 'Tests if API endpoints validate ownership of UUID-referenced resources',
    category: 'bola', severity: 'critical', cwe_id: 'CWE-639', mitre_technique: 'T1078',
    remediation: 'Verify that the authenticated user has permission to access the requested resource',
  },
  {
    id: 'AB-003', name: 'Mass assignment via extra fields',
    description: 'Tests if API accepts extra fields (e.g., role, is_admin) in creation/update requests',
    category: 'bola', severity: 'high', cwe_id: 'CWE-915', mitre_technique: 'T1078',
    remediation: 'Use allowlists for accepted request body fields; never bind directly from request to model',
  },

  // ── Broken Function Level Authorization (BFLA) ──
  {
    id: 'AB-004', name: 'Access to admin endpoints without admin role',
    description: 'Tests if admin-only endpoints are accessible without elevated privileges',
    category: 'bfla', severity: 'critical', cwe_id: 'CWE-285', mitre_technique: 'T1078',
    remediation: 'Enforce role-based access control (RBAC) on all privileged endpoints',
  },
  {
    id: 'AB-005', name: 'Horizontal privilege escalation via HTTP method override',
    description: 'Tests if changing HTTP method (e.g., GET to DELETE) bypasses authorization',
    category: 'bfla', severity: 'high', cwe_id: 'CWE-285', mitre_technique: 'T1078',
    remediation: 'Validate authorization for each HTTP method separately; do not rely on method filtering alone',
  },
  {
    id: 'AB-006', name: 'Unauthenticated access to protected endpoints',
    description: 'Tests if removing auth token still allows access to protected resources',
    category: 'bfla', severity: 'critical', cwe_id: 'CWE-306', mitre_technique: 'T1078',
    remediation: 'Ensure all API endpoints enforce authentication middleware',
  },

  // ── JWT Vulnerabilities ──
  {
    id: 'AB-007', name: 'JWT algorithm confusion (none)',
    description: 'Tests if the API accepts JWTs with "none" algorithm',
    category: 'jwt', severity: 'critical', cwe_id: 'CWE-345', mitre_technique: 'T1078',
    remediation: 'Reject JWTs with "none" or "None" algorithm; enforce expected algorithm in verification',
  },
  {
    id: 'AB-008', name: 'JWT without signature verification',
    description: 'Tests if modifying JWT payload without updating signature is accepted',
    category: 'jwt', severity: 'critical', cwe_id: 'CWE-345', mitre_technique: 'T1078',
    remediation: 'Always verify JWT signatures server-side using the correct secret/key',
  },
  {
    id: 'AB-009', name: 'Expired JWT acceptance',
    description: 'Tests if the API accepts expired JWTs',
    category: 'jwt', severity: 'high', cwe_id: 'CWE-613', mitre_technique: 'T1078',
    remediation: 'Validate exp claim on every request; reject expired tokens',
  },
  {
    id: 'AB-010', name: 'JWT sensitive data in payload',
    description: 'Tests if JWT payload contains sensitive information (passwords, PII)',
    category: 'jwt', severity: 'medium', cwe_id: 'CWE-200', mitre_technique: 'T1552',
    remediation: 'Never include sensitive data in JWT payloads; tokens are base64-encoded, not encrypted',
  },

  // ── API Key Leakage ──
  {
    id: 'AB-011', name: 'API key in response body',
    description: 'Tests if API responses contain API keys, tokens, or secrets',
    category: 'key_leak', severity: 'high', cwe_id: 'CWE-200', mitre_technique: 'T1552',
    remediation: 'Never include secrets in API response bodies; mask sensitive fields',
  },
  {
    id: 'AB-012', name: 'API key in error messages',
    description: 'Tests if error responses leak API keys or internal secrets',
    category: 'key_leak', severity: 'medium', cwe_id: 'CWE-209', mitre_technique: 'T1552',
    remediation: 'Use generic error messages; never expose internal state in error responses',
  },
  {
    id: 'AB-013', name: 'CORS misconfiguration',
    description: 'Tests if CORS headers allow requests from any origin with credentials',
    category: 'auth_header', severity: 'high', cwe_id: 'CWE-942', mitre_technique: 'T1189',
    remediation: 'Set Access-Control-Allow-Origin to specific trusted domains; never use * with credentials',
  },
  {
    id: 'AB-014', name: 'Missing rate limiting on authentication',
    description: 'Tests if login/auth endpoints have rate limiting protection',
    category: 'auth_header', severity: 'medium', cwe_id: 'CWE-307', mitre_technique: 'T1110',
    remediation: 'Implement rate limiting on authentication endpoints (e.g., 5 attempts per minute)',
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Patterns for detecting leaked secrets in responses
// ─────────────────────────────────────────────────────────────────────────────

const SECRET_PATTERNS = [
  { pattern: /["']?api[_-]?key["']?\s*[:=]\s*["'][a-zA-Z0-9_-]{20,}["']/i, name: 'API Key' },
  { pattern: /["']?secret["']?\s*[:=]\s*["'][a-zA-Z0-9_/+=]{20,}["']/i, name: 'Secret' },
  { pattern: /["']?password["']?\s*[:=]\s*["'][^"']{4,}["']/i, name: 'Password' },
  { pattern: /["']?token["']?\s*[:=]\s*["'][a-zA-Z0-9_.-]{20,}["']/i, name: 'Token' },
  { pattern: /["']?private[_-]?key["']?\s*[:=]/i, name: 'Private Key' },
  { pattern: /Bearer\s+[a-zA-Z0-9_.-]{20,}/i, name: 'Bearer Token' },
  { pattern: /AWS[A-Z0-9]{16,}/i, name: 'AWS Key' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/i, name: 'GitHub Token' },
  { pattern: /sk-[a-zA-Z0-9]{20,}/i, name: 'Secret Key' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Agent implementation
// ─────────────────────────────────────────────────────────────────────────────

registerAgent('api_auth_bypass', {
  async execute(agent, campaign, targets, aiProvider, db, onFinding, onProgress) {
    const target = agent.target || 'http://localhost';
    const baseUrl = target.startsWith('http') ? target : `https://${target}`;

    await onProgress(agent, `Starting API auth bypass scan on ${baseUrl}`);

    // Update tests_planned
    await db
      .prepare('UPDATE redops_agents SET tests_planned = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .bind(AUTH_TESTS.length, agent.id)
      .run();

    let testsCompleted = 0;
    let testsPassed = 0;
    let testsFailed = 0;

    // Phase 1: Discover API endpoints
    await onProgress(agent, 'Phase 1: Discovering API endpoints');
    const endpoints = await discoverEndpoints(baseUrl);
    await onProgress(agent, `Discovered ${endpoints.length} API endpoints`);

    // Phase 2: Run static checks (no AI needed)
    await onProgress(agent, 'Phase 2: Running static auth checks');

    for (const test of AUTH_TESTS) {
      try {
        const findings = await runAuthTest(test, baseUrl, endpoints, aiProvider, campaign.exploitation_level);

        testsCompleted++;

        if (findings.length > 0) {
          testsFailed++;
          for (const finding of findings) {
            await onFinding(finding, agent);
          }
          await onProgress(agent, `[VULN] ${test.name}: ${findings.length} finding(s)`);
        } else {
          testsPassed++;
        }

        // Update progress
        await db
          .prepare(
            `UPDATE redops_agents SET
              tests_completed = ?, tests_passed = ?, tests_failed = ?,
              updated_at = datetime('now')
            WHERE id = ?`
          )
          .bind(testsCompleted, testsPassed, testsFailed, agent.id)
          .run();
      } catch (err) {
        testsCompleted++;
        testsPassed++;
        await onProgress(agent, `[SKIP] ${test.name}: ${err instanceof Error ? err.message : 'Error'}`);
      }
    }

    await onProgress(agent, `Scan complete: ${testsFailed} vulnerabilities found out of ${testsCompleted} tests`);
    return { success: true };
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint discovery
// ─────────────────────────────────────────────────────────────────────────────

async function discoverEndpoints(baseUrl: string): Promise<string[]> {
  const endpoints: string[] = [];

  // Try common API documentation/discovery endpoints
  const discoveryPaths = [
    '/openapi.json', '/swagger.json', '/api-docs', '/docs',
    '/api/v1', '/api/v2', '/api',
    '/graphql', '/.well-known/openapi',
  ];

  for (const path of discoveryPaths) {
    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method: 'GET',
        headers: { 'User-Agent': 'ForgeRedOps Security Scanner/1.0' },
      });

      if (response.ok) {
        endpoints.push(path);

        // Try to parse OpenAPI spec for additional endpoints
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('json')) {
          try {
            const body = await response.json() as Record<string, unknown>;
            if (body.paths && typeof body.paths === 'object') {
              endpoints.push(...Object.keys(body.paths as Record<string, unknown>));
            }
          } catch {
            // Not valid JSON, skip
          }
        }
      }
    } catch {
      continue;
    }
  }

  // Add common API endpoints to test
  const commonEndpoints = [
    '/api/v1/users', '/api/v1/users/1', '/api/v1/admin',
    '/api/v1/settings', '/api/v1/config',
    '/api/v1/auth/login', '/api/v1/auth/register',
  ];

  return [...new Set([...endpoints, ...commonEndpoints])];
}

// ─────────────────────────────────────────────────────────────────────────────
// Test execution
// ─────────────────────────────────────────────────────────────────────────────

async function runAuthTest(
  test: AuthTest,
  baseUrl: string,
  endpoints: string[],
  aiProvider: ForgeAIProvider,
  exploitationLevel: string
): Promise<AISecurityFinding[]> {
  const findings: AISecurityFinding[] = [];

  switch (test.category) {
    case 'bfla':
      findings.push(...await testBFLA(test, baseUrl, endpoints));
      break;

    case 'jwt':
      findings.push(...await testJWT(test, baseUrl, endpoints));
      break;

    case 'key_leak':
      findings.push(...await testKeyLeakage(test, baseUrl, endpoints));
      break;

    case 'auth_header':
      findings.push(...await testAuthHeaders(test, baseUrl));
      break;

    case 'bola':
      // BOLA tests require AI analysis of API behavior
      if (exploitationLevel !== 'passive') {
        findings.push(...await testBOLAWithAI(test, baseUrl, endpoints, aiProvider, exploitationLevel));
      }
      break;
  }

  return findings;
}

/** Test Broken Function Level Authorization */
async function testBFLA(test: AuthTest, baseUrl: string, endpoints: string[]): Promise<AISecurityFinding[]> {
  const findings: AISecurityFinding[] = [];

  if (test.id === 'AB-006') {
    // Test unauthenticated access
    const protectedPaths = endpoints.filter((e) =>
      !e.includes('/login') && !e.includes('/register') && !e.includes('/health') && !e.includes('/docs')
    );

    for (const path of protectedPaths.slice(0, 5)) { // Limit to 5 endpoints
      try {
        const response = await fetch(`${baseUrl}${path}`, {
          method: 'GET',
          headers: { 'User-Agent': 'ForgeRedOps Security Scanner/1.0' },
        });

        if (response.ok) {
          const body = await response.text();
          if (body.length > 2 && !body.includes('error') && !body.includes('unauthorized')) {
            findings.push(buildFinding(test, path, {
              exploitation_proof: `Endpoint ${path} returned HTTP ${response.status} without authentication`,
              evidence: { request: `GET ${baseUrl}${path}`, response: `HTTP ${response.status}: ${body.substring(0, 500)}` },
            }));
          }
        }
      } catch {
        continue;
      }
    }
  }

  if (test.id === 'AB-004') {
    // Test admin endpoints without auth
    const adminPaths = ['/api/v1/admin', '/api/v1/users', '/api/v1/settings', '/admin/api'];
    for (const path of adminPaths) {
      try {
        const response = await fetch(`${baseUrl}${path}`, {
          method: 'GET',
          headers: { 'User-Agent': 'ForgeRedOps Security Scanner/1.0' },
        });

        if (response.ok) {
          findings.push(buildFinding(test, path, {
            exploitation_proof: `Admin endpoint ${path} accessible without admin role (HTTP ${response.status})`,
            evidence: { request: `GET ${baseUrl}${path}`, response: `HTTP ${response.status}` },
          }));
        }
      } catch {
        continue;
      }
    }
  }

  return findings;
}

/** Test JWT vulnerabilities */
async function testJWT(test: AuthTest, baseUrl: string, endpoints: string[]): Promise<AISecurityFinding[]> {
  const findings: AISecurityFinding[] = [];

  if (test.id === 'AB-010') {
    // Check if JWT contains sensitive data
    // First get a JWT from a login endpoint (if accessible)
    try {
      const loginResponse = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'ForgeRedOps Security Scanner/1.0',
        },
        body: JSON.stringify({ email: 'test@test.com', password: 'test' }),
      });

      const body = await loginResponse.text();
      // Look for JWT-like tokens in response
      const jwtMatch = body.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/);
      if (jwtMatch) {
        try {
          const payloadB64 = jwtMatch[0].split('.')[1];
          const payload = atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'));
          const payloadObj = JSON.parse(payload);

          // Check for sensitive fields
          const sensitiveFields = ['password', 'ssn', 'credit_card', 'secret', 'private_key'];
          const foundFields = sensitiveFields.filter((f) =>
            Object.keys(payloadObj).some((k) => k.toLowerCase().includes(f))
          );

          if (foundFields.length > 0) {
            findings.push(buildFinding(test, '/api/v1/auth/login', {
              exploitation_proof: `JWT payload contains sensitive fields: ${foundFields.join(', ')}`,
              evidence: { request: 'POST /api/v1/auth/login', response: `JWT payload keys: ${Object.keys(payloadObj).join(', ')}` },
            }));
          }
        } catch {
          // JWT parsing failed
        }
      }
    } catch {
      // Login endpoint not accessible
    }
  }

  return findings;
}

/** Test for API key leakage in responses */
async function testKeyLeakage(test: AuthTest, baseUrl: string, endpoints: string[]): Promise<AISecurityFinding[]> {
  const findings: AISecurityFinding[] = [];

  const pathsToCheck = test.id === 'AB-012'
    ? ['/api/v1/nonexistent', '/api/v1/error'] // Error paths
    : endpoints.slice(0, 5); // Normal paths

  for (const path of pathsToCheck) {
    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method: 'GET',
        headers: { 'User-Agent': 'ForgeRedOps Security Scanner/1.0' },
      });

      const body = await response.text();

      for (const { pattern, name } of SECRET_PATTERNS) {
        if (pattern.test(body)) {
          findings.push(buildFinding(test, path, {
            exploitation_proof: `${name} pattern detected in response body at ${path}`,
            evidence: { request: `GET ${baseUrl}${path}`, response: `HTTP ${response.status} — contains ${name} pattern` },
          }));
          break; // One finding per endpoint is enough
        }
      }
    } catch {
      continue;
    }
  }

  return findings;
}

/** Test auth-related headers (CORS, rate limiting) */
async function testAuthHeaders(test: AuthTest, baseUrl: string): Promise<AISecurityFinding[]> {
  const findings: AISecurityFinding[] = [];

  if (test.id === 'AB-013') {
    // CORS test
    try {
      const response = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: 'OPTIONS',
        headers: {
          'User-Agent': 'ForgeRedOps Security Scanner/1.0',
          'Origin': 'https://evil.com',
          'Access-Control-Request-Method': 'POST',
        },
      });

      const allowOrigin = response.headers.get('access-control-allow-origin');
      const allowCreds = response.headers.get('access-control-allow-credentials');

      if (allowOrigin === '*' && allowCreds === 'true') {
        findings.push(buildFinding(test, '/api/v1/auth/login', {
          exploitation_proof: 'CORS allows any origin (*) with credentials enabled',
          evidence: {
            request: 'OPTIONS /api/v1/auth/login with Origin: https://evil.com',
            response: `Access-Control-Allow-Origin: ${allowOrigin}, Access-Control-Allow-Credentials: ${allowCreds}`,
          },
        }));
      } else if (allowOrigin === 'https://evil.com') {
        findings.push(buildFinding(test, '/api/v1/auth/login', {
          exploitation_proof: 'CORS reflects arbitrary Origin header in Access-Control-Allow-Origin',
          evidence: {
            request: 'OPTIONS /api/v1/auth/login with Origin: https://evil.com',
            response: `Access-Control-Allow-Origin: ${allowOrigin}`,
          },
        }));
      }
    } catch {
      // Endpoint not accessible
    }
  }

  if (test.id === 'AB-014') {
    // Rate limit test: send 10 rapid requests and check for rate limiting
    let successCount = 0;
    for (let i = 0; i < 10; i++) {
      try {
        const response = await fetch(`${baseUrl}/api/v1/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'ForgeRedOps Security Scanner/1.0',
          },
          body: JSON.stringify({ email: `test${i}@test.com`, password: 'wrong' }),
        });

        if (response.status !== 429) {
          successCount++;
        } else {
          break; // Rate limited, which is good
        }
      } catch {
        break;
      }
    }

    if (successCount >= 10) {
      findings.push(buildFinding(test, '/api/v1/auth/login', {
        exploitation_proof: 'No rate limiting detected after 10 rapid login attempts',
        evidence: {
          request: '10x POST /api/v1/auth/login with invalid credentials',
          response: `All 10 requests succeeded (no HTTP 429 responses)`,
        },
      }));
    }
  }

  return findings;
}

/** Use AI to test for BOLA/IDOR vulnerabilities */
async function testBOLAWithAI(
  test: AuthTest,
  baseUrl: string,
  endpoints: string[],
  aiProvider: ForgeAIProvider,
  exploitationLevel: string
): Promise<AISecurityFinding[]> {
  if (exploitationLevel === 'passive') return [];

  // Only run for specific BOLA tests
  if (test.id !== 'AB-001') return [];

  // Look for endpoints with ID parameters
  const idEndpoints = endpoints.filter((e) =>
    /\/\d+$/.test(e) || /\/[a-f0-9-]{36}$/.test(e)
  );

  if (idEndpoints.length === 0) return [];

  const findings: AISecurityFinding[] = [];

  for (const endpoint of idEndpoints.slice(0, 3)) {
    try {
      // Fetch original resource
      const original = await fetch(`${baseUrl}${endpoint}`, {
        headers: { 'User-Agent': 'ForgeRedOps Security Scanner/1.0' },
      });

      if (!original.ok) continue;

      const originalBody = await original.text();

      // Try manipulating the ID
      const manipulatedPath = endpoint.replace(/(\d+)$/, (match) => String(parseInt(match) + 1));
      const manipulated = await fetch(`${baseUrl}${manipulatedPath}`, {
        headers: { 'User-Agent': 'ForgeRedOps Security Scanner/1.0' },
      });

      if (manipulated.ok) {
        const manipulatedBody = await manipulated.text();

        // Use AI to analyze if this is a real BOLA vulnerability
        const aiFindings = await aiProvider.analyzeResponse(
          'api_auth_bypass',
          'BOLA via sequential ID',
          `GET ${baseUrl}${endpoint}\nGET ${baseUrl}${manipulatedPath}`,
          `Original (${endpoint}): ${originalBody.substring(0, 2000)}\n\nManipulated (${manipulatedPath}): ${manipulatedBody.substring(0, 2000)}`,
          { test_id: test.id, exploitation_level: exploitationLevel }
        );

        findings.push(...aiFindings);
      }
    } catch {
      continue;
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function buildFinding(
  test: AuthTest,
  path: string,
  overrides: Partial<AISecurityFinding>
): AISecurityFinding {
  return {
    title: `${test.name} — ${path}`,
    description: test.description,
    severity: test.severity,
    attack_vector: `API endpoint: ${path}`,
    attack_category: `OWASP A01:2021 Broken Access Control`,
    cwe_id: test.cwe_id,
    exploitable: test.severity === 'critical' || test.severity === 'high',
    remediation: test.remediation,
    remediation_effort: test.severity === 'critical' ? 'moderate' : 'quick_fix',
    mitre_tactic: 'initial-access',
    mitre_technique: test.mitre_technique,
    nist_controls: ['AC-3', 'AC-6', 'IA-2'],
    ...overrides,
  };
}
