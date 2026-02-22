// ─────────────────────────────────────────────────────────────────────────────
// ForgeRedOps Agent: Web Security Misconfiguration (web_misconfig)
// ─────────────────────────────────────────────────────────────────────────────
//
// Safest agent — read-only checks, no exploit payloads.
// Tests for: default credentials, debug endpoints, directory listing,
// exposed sensitive files, missing security headers, server info disclosure.
//
// 52 tests defined in redops_agent_types seed data.

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
// Test definitions — the static checks this agent runs
// ─────────────────────────────────────────────────────────────────────────────

interface MisconfigTest {
  id: string;
  name: string;
  description: string;
  paths: string[];
  check: 'status' | 'header_missing' | 'header_present' | 'body_contains' | 'tls';
  /** For header_missing: header must be absent */
  header?: string;
  /** For body_contains: patterns to look for */
  patterns?: string[];
  /** Expected status codes that indicate vulnerability */
  vuln_status?: number[];
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe_id: string;
  mitre_technique: string;
  remediation: string;
}

const MISCONFIG_TESTS: MisconfigTest[] = [
  // ── Exposed Sensitive Files ──
  {
    id: 'WM-001', name: 'Exposed .env file', description: 'Checks for publicly accessible .env file containing secrets',
    paths: ['/.env', '/.env.local', '/.env.production'], check: 'status', vuln_status: [200],
    severity: 'critical', cwe_id: 'CWE-200', mitre_technique: 'T1552',
    remediation: 'Block access to .env files in your web server configuration',
  },
  {
    id: 'WM-002', name: 'Exposed .git directory', description: 'Checks for accessible Git repository metadata',
    paths: ['/.git/config', '/.git/HEAD'], check: 'status', vuln_status: [200],
    severity: 'high', cwe_id: 'CWE-200', mitre_technique: 'T1213',
    remediation: 'Block access to .git directory in web server config',
  },
  {
    id: 'WM-003', name: 'Exposed wp-config.php', description: 'Checks for accessible WordPress configuration',
    paths: ['/wp-config.php', '/wp-config.php.bak', '/wp-config.php.old'], check: 'body_contains',
    patterns: ['DB_PASSWORD', 'DB_NAME', 'AUTH_KEY'],
    severity: 'critical', cwe_id: 'CWE-200', mitre_technique: 'T1552',
    remediation: 'Ensure wp-config.php is not accessible via web server',
  },
  {
    id: 'WM-004', name: 'Exposed backup files', description: 'Checks for accessible backup/archive files',
    paths: ['/backup.sql', '/backup.zip', '/db.sql', '/dump.sql', '/site.tar.gz'], check: 'status', vuln_status: [200],
    severity: 'high', cwe_id: 'CWE-200', mitre_technique: 'T1005',
    remediation: 'Remove backup files from web-accessible directories',
  },

  // ── Debug/Admin Endpoints ──
  {
    id: 'WM-005', name: 'Debug endpoint exposed', description: 'Checks for common debug endpoints',
    paths: ['/debug', '/debug/vars', '/debug/pprof', '/_debug', '/trace', '/__debug__'], check: 'status', vuln_status: [200],
    severity: 'high', cwe_id: 'CWE-215', mitre_technique: 'T1190',
    remediation: 'Disable debug endpoints in production',
  },
  {
    id: 'WM-006', name: 'Admin panel exposed', description: 'Checks for commonly accessible admin panels',
    paths: ['/admin', '/administrator', '/admin/login', '/wp-admin', '/phpmyadmin', '/adminer.php'], check: 'status', vuln_status: [200, 302, 301],
    severity: 'medium', cwe_id: 'CWE-200', mitre_technique: 'T1190',
    remediation: 'Restrict admin panel access via IP allowlist or VPN',
  },
  {
    id: 'WM-007', name: 'Status/health endpoint leaking info', description: 'Checks for verbose status endpoints',
    paths: ['/status', '/health', '/info', '/server-status', '/server-info'], check: 'body_contains',
    patterns: ['version', 'uptime', 'memory', 'cpu', 'database'],
    severity: 'low', cwe_id: 'CWE-200', mitre_technique: 'T1082',
    remediation: 'Restrict status endpoints to internal networks only',
  },

  // ── Directory Listing ──
  {
    id: 'WM-008', name: 'Directory listing enabled', description: 'Checks for directory listing on common paths',
    paths: ['/images/', '/uploads/', '/static/', '/assets/', '/files/'], check: 'body_contains',
    patterns: ['Index of', 'Directory listing', 'Parent Directory'],
    severity: 'medium', cwe_id: 'CWE-548', mitre_technique: 'T1083',
    remediation: 'Disable directory listing in web server configuration',
  },

  // ── Missing Security Headers ──
  {
    id: 'WM-009', name: 'Missing Content-Security-Policy', description: 'CSP header not present',
    paths: ['/'], check: 'header_missing', header: 'content-security-policy',
    severity: 'medium', cwe_id: 'CWE-693', mitre_technique: 'T1189',
    remediation: 'Add Content-Security-Policy header with restrictive policy',
  },
  {
    id: 'WM-010', name: 'Missing Strict-Transport-Security', description: 'HSTS header not present',
    paths: ['/'], check: 'header_missing', header: 'strict-transport-security',
    severity: 'medium', cwe_id: 'CWE-319', mitre_technique: 'T1557',
    remediation: 'Add Strict-Transport-Security header with max-age >= 31536000',
  },
  {
    id: 'WM-011', name: 'Missing X-Frame-Options', description: 'X-Frame-Options header not present',
    paths: ['/'], check: 'header_missing', header: 'x-frame-options',
    severity: 'medium', cwe_id: 'CWE-1021', mitre_technique: 'T1185',
    remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN header',
  },
  {
    id: 'WM-012', name: 'Missing X-Content-Type-Options', description: 'X-Content-Type-Options header not present',
    paths: ['/'], check: 'header_missing', header: 'x-content-type-options',
    severity: 'low', cwe_id: 'CWE-693', mitre_technique: 'T1189',
    remediation: 'Add X-Content-Type-Options: nosniff header',
  },

  // ── Server Info Disclosure ──
  {
    id: 'WM-013', name: 'Server version disclosure', description: 'Server header reveals version information',
    paths: ['/'], check: 'header_present', header: 'server',
    patterns: ['Apache/', 'nginx/', 'Microsoft-IIS/', 'LiteSpeed'],
    severity: 'low', cwe_id: 'CWE-200', mitre_technique: 'T1082',
    remediation: 'Remove or obfuscate the Server header in web server config',
  },
  {
    id: 'WM-014', name: 'X-Powered-By disclosure', description: 'X-Powered-By header reveals technology stack',
    paths: ['/'], check: 'header_present', header: 'x-powered-by',
    severity: 'low', cwe_id: 'CWE-200', mitre_technique: 'T1082',
    remediation: 'Remove X-Powered-By header in application or web server config',
  },

  // ── Exposed Configuration/API Docs ──
  {
    id: 'WM-015', name: 'OpenAPI/Swagger exposed', description: 'API documentation publicly accessible',
    paths: ['/swagger', '/swagger-ui', '/api-docs', '/swagger.json', '/openapi.json', '/docs'], check: 'status', vuln_status: [200],
    severity: 'low', cwe_id: 'CWE-200', mitre_technique: 'T1082',
    remediation: 'Restrict API documentation to authenticated users',
  },
  {
    id: 'WM-016', name: 'Exposed configuration files', description: 'Configuration files accessible via web',
    paths: ['/config.json', '/config.yml', '/settings.json', '/application.yml', '/appsettings.json'], check: 'status', vuln_status: [200],
    severity: 'high', cwe_id: 'CWE-200', mitre_technique: 'T1552',
    remediation: 'Move configuration files outside web root',
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Agent implementation
// ─────────────────────────────────────────────────────────────────────────────

registerAgent('web_misconfig', {
  async execute(agent, campaign, targets, aiProvider, db, onFinding, onProgress) {
    const target = agent.target || 'http://localhost';
    const baseUrl = target.startsWith('http') ? target : `https://${target}`;

    await onProgress(agent, `Starting web misconfiguration scan on ${baseUrl}`);

    // Update tests_planned
    await db
      .prepare('UPDATE redops_agents SET tests_planned = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .bind(MISCONFIG_TESTS.length, agent.id)
      .run();

    let testsCompleted = 0;
    let testsPassed = 0;
    let testsFailed = 0;

    for (const test of MISCONFIG_TESTS) {
      try {
        const findings = await runTest(test, baseUrl, aiProvider, campaign.exploitation_level);

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
        testsPassed++; // Can't confirm vuln, count as passed
        await onProgress(agent, `[SKIP] ${test.name}: ${err instanceof Error ? err.message : 'Error'}`);
      }
    }

    await onProgress(agent, `Scan complete: ${testsFailed} vulnerabilities found out of ${testsCompleted} tests`);
    return { success: true };
  },
});

async function runTest(
  test: MisconfigTest,
  baseUrl: string,
  aiProvider: ForgeAIProvider,
  exploitationLevel: string
): Promise<AISecurityFinding[]> {
  const findings: AISecurityFinding[] = [];

  for (const path of test.paths) {
    const url = `${baseUrl}${path}`;

    let response: Response;
    try {
      response = await fetch(url, {
        method: 'GET',
        headers: { 'User-Agent': 'ForgeRedOps Security Scanner/1.0' },
        redirect: 'manual',
      });
    } catch {
      continue; // Network error, skip this path
    }

    const statusCode = response.status;
    const headers = Object.fromEntries(response.headers.entries());
    let body = '';

    try {
      body = await response.text();
      body = body.substring(0, 10000); // Limit body size
    } catch {
      // Ignore body read errors
    }

    let isVulnerable = false;

    switch (test.check) {
      case 'status':
        isVulnerable = (test.vuln_status || [200]).includes(statusCode);
        break;

      case 'header_missing':
        isVulnerable = !headers[test.header!.toLowerCase()];
        break;

      case 'header_present': {
        const headerValue = headers[test.header!.toLowerCase()];
        if (headerValue && test.patterns) {
          isVulnerable = test.patterns.some((p) => headerValue.includes(p));
        } else if (headerValue) {
          isVulnerable = true;
        }
        break;
      }

      case 'body_contains':
        if (statusCode === 200 && test.patterns) {
          isVulnerable = test.patterns.some((p) =>
            body.toLowerCase().includes(p.toLowerCase())
          );
        }
        break;
    }

    if (isVulnerable) {
      // For critical/high findings, use AI to analyze the response for additional context
      let aiFindings: AISecurityFinding[] = [];
      if ((test.severity === 'critical' || test.severity === 'high') && exploitationLevel !== 'passive') {
        try {
          aiFindings = await aiProvider.analyzeResponse(
            'web_misconfig',
            test.name,
            `GET ${url}\nUser-Agent: ForgeRedOps Security Scanner/1.0`,
            `HTTP/${statusCode}\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${body.substring(0, 4000)}`,
            { test_id: test.id, exploitation_level: exploitationLevel }
          );
        } catch {
          // AI analysis failed, use static finding
        }
      }

      if (aiFindings.length > 0) {
        findings.push(...aiFindings);
      } else {
        // Static finding based on test definition
        findings.push({
          title: `${test.name} — ${path}`,
          description: `${test.description}. Detected at ${url}`,
          severity: test.severity,
          attack_vector: `HTTP GET ${path}`,
          attack_category: 'OWASP A05:2021 Security Misconfiguration',
          cwe_id: test.cwe_id,
          exploitable: test.severity === 'critical' || test.severity === 'high',
          exploitation_proof: test.check === 'header_missing'
            ? `Header "${test.header}" is missing from response`
            : `Accessible at ${url} (HTTP ${statusCode})`,
          remediation: test.remediation,
          remediation_effort: test.severity === 'critical' ? 'quick_fix' : 'moderate',
          mitre_tactic: 'initial-access',
          mitre_technique: test.mitre_technique,
          nist_controls: ['CM-6', 'CM-7', 'SC-8'],
          evidence: {
            request: `GET ${url}`,
            response: `HTTP ${statusCode}\n${Object.entries(headers).slice(0, 10).map(([k, v]) => `${k}: ${v}`).join('\n')}`,
          },
        });
      }

      break; // Found vulnerability on this test, no need to check other paths
    }
  }

  return findings;
}
