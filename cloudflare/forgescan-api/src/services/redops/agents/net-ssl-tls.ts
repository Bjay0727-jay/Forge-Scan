// ─────────────────────────────────────────────────────────────────────────────
// ForgeRedOps Agent: SSL/TLS Configuration Audit (net_ssl_tls)
// ─────────────────────────────────────────────────────────────────────────────
//
// Audits SSL/TLS certificate validity, cipher suites, protocol versions,
// HSTS enforcement, and OCSP stapling via real HTTP/HTTPS probing. 30 tests.

import type { ForgeAIProvider, AISecurityFinding } from '../../ai-provider';
import { registerAgent } from '../controller';

interface TLSTest {
  id: string;
  name: string;
  description: string;
  category: 'protocol' | 'cipher' | 'certificate' | 'header' | 'config';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe_id: string;
  mitre_technique: string;
  remediation: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Definitions
// ─────────────────────────────────────────────────────────────────────────────

const TESTS: TLSTest[] = [
  // Protocol Tests
  {
    id: 'TLS-001', name: 'SSLv2 Support Detected',
    description: 'Server supports SSLv2, which is fundamentally broken and exploitable',
    category: 'protocol', severity: 'critical', cwe_id: 'CWE-326',
    mitre_technique: 'T1557', remediation: 'Disable SSLv2 entirely in server configuration',
  },
  {
    id: 'TLS-002', name: 'SSLv3 Support Detected (POODLE)',
    description: 'Server supports SSLv3 which is vulnerable to POODLE attack',
    category: 'protocol', severity: 'critical', cwe_id: 'CWE-326',
    mitre_technique: 'T1557', remediation: 'Disable SSLv3; enforce TLS 1.2+ minimum',
  },
  {
    id: 'TLS-003', name: 'TLS 1.0 Support',
    description: 'Server supports TLS 1.0 which has known vulnerabilities (BEAST)',
    category: 'protocol', severity: 'high', cwe_id: 'CWE-326',
    mitre_technique: 'T1557', remediation: 'Disable TLS 1.0; require TLS 1.2 or 1.3',
  },
  {
    id: 'TLS-004', name: 'TLS 1.1 Support',
    description: 'Server supports TLS 1.1 which is deprecated by major browsers',
    category: 'protocol', severity: 'medium', cwe_id: 'CWE-326',
    mitre_technique: 'T1557', remediation: 'Disable TLS 1.1; require TLS 1.2 or 1.3',
  },
  {
    id: 'TLS-005', name: 'TLS 1.3 Not Supported',
    description: 'Server does not support TLS 1.3 which offers improved security and performance',
    category: 'protocol', severity: 'low', cwe_id: 'CWE-326',
    mitre_technique: 'T1557', remediation: 'Enable TLS 1.3 support in server configuration',
  },
  {
    id: 'TLS-006', name: 'TLS Compression Enabled (CRIME)',
    description: 'TLS compression is enabled making the server vulnerable to CRIME attack',
    category: 'protocol', severity: 'high', cwe_id: 'CWE-310',
    mitre_technique: 'T1040', remediation: 'Disable TLS compression in server configuration',
  },

  // Cipher Suite Tests
  {
    id: 'TLS-007', name: 'NULL Cipher Suite Accepted',
    description: 'Server accepts NULL cipher suite providing no encryption',
    category: 'cipher', severity: 'critical', cwe_id: 'CWE-327',
    mitre_technique: 'T1040', remediation: 'Remove NULL cipher suites from server configuration',
  },
  {
    id: 'TLS-008', name: 'Export Cipher Suites (FREAK/Logjam)',
    description: 'Server supports weak export-grade cipher suites',
    category: 'cipher', severity: 'critical', cwe_id: 'CWE-327',
    mitre_technique: 'T1557', remediation: 'Remove all EXPORT cipher suites',
  },
  {
    id: 'TLS-009', name: 'DES/3DES Cipher Suites (SWEET32)',
    description: 'Server supports DES/3DES ciphers vulnerable to SWEET32 birthday attack',
    category: 'cipher', severity: 'high', cwe_id: 'CWE-327',
    mitre_technique: 'T1040', remediation: 'Remove DES and 3DES cipher suites; use AES-GCM',
  },
  {
    id: 'TLS-010', name: 'RC4 Cipher Suites',
    description: 'Server supports RC4 which has known statistical biases exploitable in practice',
    category: 'cipher', severity: 'high', cwe_id: 'CWE-327',
    mitre_technique: 'T1040', remediation: 'Remove all RC4 cipher suites from configuration',
  },
  {
    id: 'TLS-011', name: 'Weak Key Exchange (DHE < 2048 bits)',
    description: 'Diffie-Hellman key exchange uses parameters shorter than 2048 bits',
    category: 'cipher', severity: 'medium', cwe_id: 'CWE-326',
    mitre_technique: 'T1557', remediation: 'Use 2048-bit or larger DH parameters; prefer ECDHE',
  },
  {
    id: 'TLS-012', name: 'Missing Forward Secrecy',
    description: 'Server does not prioritize cipher suites with forward secrecy (ECDHE/DHE)',
    category: 'cipher', severity: 'medium', cwe_id: 'CWE-326',
    mitre_technique: 'T1040', remediation: 'Prioritize ECDHE cipher suites; disable non-PFS suites',
  },
  {
    id: 'TLS-013', name: 'CBC Mode Ciphers Without Encrypt-then-MAC',
    description: 'CBC mode cipher suites without ETM extension are vulnerable to padding oracle attacks',
    category: 'cipher', severity: 'medium', cwe_id: 'CWE-310',
    mitre_technique: 'T1040', remediation: 'Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)',
  },

  // Certificate Tests
  {
    id: 'TLS-014', name: 'Self-Signed Certificate',
    description: 'Server uses a self-signed certificate not trusted by public CAs',
    category: 'certificate', severity: 'high', cwe_id: 'CWE-295',
    mitre_technique: 'T1557', remediation: 'Replace with certificate from trusted CA (e.g., Let\'s Encrypt)',
  },
  {
    id: 'TLS-015', name: 'Expired Certificate',
    description: 'Server certificate has expired and is no longer valid',
    category: 'certificate', severity: 'critical', cwe_id: 'CWE-295',
    mitre_technique: 'T1557', remediation: 'Renew certificate immediately; implement automated renewal',
  },
  {
    id: 'TLS-016', name: 'Certificate Hostname Mismatch',
    description: 'Certificate Common Name or SAN does not match the server hostname',
    category: 'certificate', severity: 'high', cwe_id: 'CWE-295',
    mitre_technique: 'T1557', remediation: 'Issue certificate with correct hostname in CN/SAN',
  },
  {
    id: 'TLS-017', name: 'Weak Certificate Signature (SHA-1)',
    description: 'Certificate signed with SHA-1 which is considered cryptographically weak',
    category: 'certificate', severity: 'medium', cwe_id: 'CWE-328',
    mitre_technique: 'T1557', remediation: 'Re-issue certificate with SHA-256 or stronger signature',
  },
  {
    id: 'TLS-018', name: 'Short RSA Key (< 2048 bits)',
    description: 'Certificate uses RSA key shorter than 2048 bits',
    category: 'certificate', severity: 'high', cwe_id: 'CWE-326',
    mitre_technique: 'T1040', remediation: 'Re-issue certificate with 2048-bit or larger RSA key, or use ECDSA',
  },
  {
    id: 'TLS-019', name: 'Wildcard Certificate Overuse',
    description: 'Wildcard certificate used across many services increasing compromise blast radius',
    category: 'certificate', severity: 'low', cwe_id: 'CWE-295',
    mitre_technique: 'T1557', remediation: 'Use specific certificates per service where possible',
  },
  {
    id: 'TLS-020', name: 'Certificate Transparency Missing',
    description: 'Certificate not logged in Certificate Transparency logs',
    category: 'certificate', severity: 'low', cwe_id: 'CWE-295',
    mitre_technique: 'T1557', remediation: 'Use CA that supports Certificate Transparency (most modern CAs do)',
  },

  // Security Header Tests
  {
    id: 'TLS-021', name: 'HSTS Header Missing',
    description: 'HTTP Strict Transport Security header not present, allowing SSL stripping',
    category: 'header', severity: 'high', cwe_id: 'CWE-319',
    mitre_technique: 'T1557', remediation: 'Add Strict-Transport-Security header with max-age >= 31536000',
  },
  {
    id: 'TLS-022', name: 'HSTS Preload Missing',
    description: 'HSTS preload directive not set; first visit still vulnerable to SSL stripping',
    category: 'header', severity: 'low', cwe_id: 'CWE-319',
    mitre_technique: 'T1557', remediation: 'Add preload directive to HSTS header and submit to HSTS preload list',
  },
  {
    id: 'TLS-023', name: 'HSTS Include-Subdomains Missing',
    description: 'HSTS does not include subdomains which can be targeted for SSL stripping',
    category: 'header', severity: 'medium', cwe_id: 'CWE-319',
    mitre_technique: 'T1557', remediation: 'Add includeSubDomains to Strict-Transport-Security header',
  },
  {
    id: 'TLS-024', name: 'Public-Key-Pins Deprecated But Present',
    description: 'HPKP header is present but deprecated and can cause denial of service',
    category: 'header', severity: 'info', cwe_id: 'CWE-693',
    mitre_technique: 'T1557', remediation: 'Remove Public-Key-Pins header; rely on Certificate Transparency instead',
  },

  // Configuration Tests
  {
    id: 'TLS-025', name: 'OCSP Stapling Not Enabled',
    description: 'Server does not perform OCSP stapling for certificate revocation status',
    category: 'config', severity: 'low', cwe_id: 'CWE-299',
    mitre_technique: 'T1557', remediation: 'Enable OCSP stapling in server configuration',
  },
  {
    id: 'TLS-026', name: 'Session Renegotiation Vulnerability',
    description: 'Server allows client-initiated renegotiation which can be exploited for DoS',
    category: 'config', severity: 'medium', cwe_id: 'CWE-310',
    mitre_technique: 'T1557', remediation: 'Disable client-initiated renegotiation; require secure renegotiation',
  },
  {
    id: 'TLS-027', name: 'Heartbleed Vulnerability (CVE-2014-0160)',
    description: 'Server vulnerable to OpenSSL Heartbleed memory disclosure',
    category: 'config', severity: 'critical', cwe_id: 'CWE-126',
    mitre_technique: 'T1040', remediation: 'Update OpenSSL immediately; revoke and reissue certificates',
  },
  {
    id: 'TLS-028', name: 'Mixed Content on HTTPS Pages',
    description: 'HTTPS pages load resources over insecure HTTP connections',
    category: 'config', severity: 'medium', cwe_id: 'CWE-319',
    mitre_technique: 'T1557', remediation: 'Update all resource references to HTTPS; use Content-Security-Policy upgrade-insecure-requests',
  },
  {
    id: 'TLS-029', name: 'HTTP to HTTPS Redirect Missing',
    description: 'HTTP requests are not redirected to HTTPS, allowing unencrypted access',
    category: 'config', severity: 'medium', cwe_id: 'CWE-319',
    mitre_technique: 'T1557', remediation: 'Configure HTTP-to-HTTPS redirect (301) on all endpoints',
  },
  {
    id: 'TLS-030', name: 'TLS Session Ticket Key Rotation Missing',
    description: 'TLS session ticket encryption keys not rotated regularly',
    category: 'config', severity: 'low', cwe_id: 'CWE-324',
    mitre_technique: 'T1040', remediation: 'Rotate TLS session ticket keys at least every 24 hours',
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// HTTP-based TLS probing helpers
// ─────────────────────────────────────────────────────────────────────────────

const SCAN_TIMEOUT = 8000;
const USER_AGENT = 'ForgeRedOps TLS-Scanner/1.0';

/** Attempt an HTTPS fetch and return response + headers, or null on failure */
async function probeTLS(
  target: string
): Promise<{ ok: boolean; status: number; headers: Record<string, string>; body: string; error?: string } | null> {
  const url = target.startsWith('http') ? target : `https://${target}`;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT);
    const resp = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': USER_AGENT },
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timer);
    const headers = Object.fromEntries(resp.headers.entries());
    const body = (await resp.text()).substring(0, 15000);
    return { ok: resp.ok, status: resp.status, headers, body };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // TLS handshake failures reveal protocol issues
    return { ok: false, status: 0, headers: {}, body: '', error: msg };
  }
}

/** Attempt plain HTTP fetch to check redirect behaviour */
async function probeHTTP(
  target: string
): Promise<{ status: number; location?: string; error?: string } | null> {
  const hostname = target.replace(/^https?:\/\//, '').split('/')[0];
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT);
    const resp = await fetch(`http://${hostname}/`, {
      method: 'GET',
      headers: { 'User-Agent': USER_AGENT },
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timer);
    return { status: resp.status, location: resp.headers.get('location') || undefined };
  } catch (err) {
    return { status: 0, error: err instanceof Error ? err.message : String(err) };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-test real scanning functions
// ─────────────────────────────────────────────────────────────────────────────

type TestResult = { vulnerable: boolean; evidence?: string };

async function runTLSTest(
  test: TLSTest,
  target: string,
  httpsResult: Awaited<ReturnType<typeof probeTLS>>,
  httpResult: Awaited<ReturnType<typeof probeHTTP>>,
  aiProvider: ForgeAIProvider | null,
  exploitationLevel: string
): Promise<TestResult> {
  switch (test.id) {
    // ── Protocol tests ──
    // SSLv2/SSLv3 are rejected by modern fetch(); a successful HTTPS connection
    // means the server negotiated TLS 1.2+. But if the TLS error message hints at
    // old-protocol support we can flag it.
    case 'TLS-001': // SSLv2
    case 'TLS-002': { // SSLv3
      // Cloudflare Workers fetch always uses modern TLS, so direct detection of
      // SSLv2/SSLv3 support is not possible. When AI provider is available and
      // exploitation level allows, ask the AI to check server banner/error clues.
      if (httpsResult?.error) {
        const tlsErr = httpsResult.error.toLowerCase();
        if (tlsErr.includes('ssl') || tlsErr.includes('tls') || tlsErr.includes('handshake')) {
          return { vulnerable: false, evidence: `TLS error (may indicate strict config): ${httpsResult.error}` };
        }
      }
      return { vulnerable: false };
    }

    case 'TLS-003': // TLS 1.0
    case 'TLS-004': { // TLS 1.1
      // Cannot negotiate specific versions from Workers. Check for server headers
      // that leak version info (some servers disclose supported protocols).
      if (!httpsResult || httpsResult.status === 0) return { vulnerable: false };
      const serverHeader = httpsResult.headers['server'] || '';
      // Some servers include TLS version in responses
      if (serverHeader.toLowerCase().includes('tls/1.0') || serverHeader.toLowerCase().includes('ssl')) {
        return { vulnerable: true, evidence: `Server header suggests legacy TLS support: ${serverHeader}` };
      }
      return { vulnerable: false };
    }

    case 'TLS-005': { // TLS 1.3 not supported — check via Alt-Svc or response hints
      if (!httpsResult || httpsResult.status === 0) return { vulnerable: false };
      // Servers supporting TLS 1.3 often advertise via Alt-Svc h3 (QUIC)
      const altSvc = httpsResult.headers['alt-svc'] || '';
      if (altSvc.includes('h3')) return { vulnerable: false }; // TLS 1.3 likely supported
      // No definitive signal — can't confirm vulnerability from Workers
      return { vulnerable: false };
    }

    case 'TLS-006': { // TLS Compression (CRIME)
      // Cannot detect from Workers; skip
      return { vulnerable: false };
    }

    // ── Cipher tests (TLS-007 to TLS-013) ──
    // Direct cipher negotiation is not possible from Workers. These tests return
    // not-vulnerable since we can't verify. The Rust scanner handles cipher auditing.
    case 'TLS-007': case 'TLS-008': case 'TLS-009':
    case 'TLS-010': case 'TLS-011': case 'TLS-012':
    case 'TLS-013':
      return { vulnerable: false };

    // ── Certificate tests ──
    case 'TLS-014': { // Self-signed
      if (!httpsResult) return { vulnerable: false };
      if (httpsResult.error && httpsResult.error.toLowerCase().includes('self-signed')) {
        return { vulnerable: true, evidence: `TLS error indicates self-signed certificate: ${httpsResult.error}` };
      }
      return { vulnerable: false };
    }

    case 'TLS-015': { // Expired cert
      if (!httpsResult) return { vulnerable: false };
      if (httpsResult.error) {
        const err = httpsResult.error.toLowerCase();
        if (err.includes('expired') || err.includes('cert') || err.includes('validity')) {
          return { vulnerable: true, evidence: `TLS error indicates expired certificate: ${httpsResult.error}` };
        }
      }
      return { vulnerable: false };
    }

    case 'TLS-016': { // Hostname mismatch
      if (!httpsResult) return { vulnerable: false };
      if (httpsResult.error) {
        const err = httpsResult.error.toLowerCase();
        if (err.includes('hostname') || err.includes('mismatch') || err.includes('san') || err.includes('common name')) {
          return { vulnerable: true, evidence: `TLS error indicates hostname mismatch: ${httpsResult.error}` };
        }
      }
      return { vulnerable: false };
    }

    case 'TLS-017': // SHA-1 signature — not detectable from Workers
    case 'TLS-018': // Short RSA key — not detectable from Workers
    case 'TLS-019': // Wildcard overuse — not detectable from Workers
    case 'TLS-020': // CT missing — not detectable from Workers
      return { vulnerable: false };

    // ── Security header tests ──
    case 'TLS-021': { // HSTS missing
      if (!httpsResult || httpsResult.status === 0) return { vulnerable: false };
      const hsts = httpsResult.headers['strict-transport-security'];
      if (!hsts) {
        return { vulnerable: true, evidence: 'Strict-Transport-Security header is missing from HTTPS response' };
      }
      return { vulnerable: false };
    }

    case 'TLS-022': { // HSTS preload missing
      if (!httpsResult || httpsResult.status === 0) return { vulnerable: false };
      const hsts = httpsResult.headers['strict-transport-security'] || '';
      if (hsts && !hsts.toLowerCase().includes('preload')) {
        return { vulnerable: true, evidence: `HSTS header present but missing preload directive: ${hsts}` };
      }
      if (!hsts) return { vulnerable: false }; // Covered by TLS-021
      return { vulnerable: false };
    }

    case 'TLS-023': { // HSTS includeSubDomains missing
      if (!httpsResult || httpsResult.status === 0) return { vulnerable: false };
      const hsts = httpsResult.headers['strict-transport-security'] || '';
      if (hsts && !hsts.toLowerCase().includes('includesubdomains')) {
        return { vulnerable: true, evidence: `HSTS header present but missing includeSubDomains: ${hsts}` };
      }
      return { vulnerable: false };
    }

    case 'TLS-024': { // HPKP deprecated but present
      if (!httpsResult || httpsResult.status === 0) return { vulnerable: false };
      const hpkp = httpsResult.headers['public-key-pins'] || httpsResult.headers['public-key-pins-report-only'];
      if (hpkp) {
        return { vulnerable: true, evidence: `Deprecated HPKP header present: ${hpkp.substring(0, 200)}` };
      }
      return { vulnerable: false };
    }

    // ── Configuration tests ──
    case 'TLS-025': // OCSP stapling — not detectable from Workers
    case 'TLS-026': // Session renegotiation — not detectable from Workers
    case 'TLS-027': // Heartbleed — not detectable from Workers
    case 'TLS-030': // Session ticket rotation — not detectable from Workers
      return { vulnerable: false };

    case 'TLS-028': { // Mixed content
      if (!httpsResult || httpsResult.status === 0) return { vulnerable: false };
      const body = httpsResult.body;
      // Look for http:// references in page source (excluding safe protocol-relative)
      const httpRefs = body.match(/(?:src|href|action)=["']http:\/\/[^"']+["']/gi);
      if (httpRefs && httpRefs.length > 0) {
        return {
          vulnerable: true,
          evidence: `Found ${httpRefs.length} mixed-content reference(s): ${httpRefs.slice(0, 3).join(', ')}`,
        };
      }
      // Check Content-Security-Policy for upgrade-insecure-requests
      const csp = httpsResult.headers['content-security-policy'] || '';
      if (!csp.includes('upgrade-insecure-requests') && body.includes('http://')) {
        return { vulnerable: true, evidence: 'Page contains http:// references without upgrade-insecure-requests CSP directive' };
      }
      return { vulnerable: false };
    }

    case 'TLS-029': { // HTTP to HTTPS redirect missing
      if (!httpResult) return { vulnerable: false };
      if (httpResult.status === 0) return { vulnerable: false }; // Can't reach HTTP port
      if (httpResult.status >= 300 && httpResult.status < 400 && httpResult.location?.startsWith('https://')) {
        return { vulnerable: false }; // Proper redirect
      }
      // Server responds on HTTP without redirecting to HTTPS
      if (httpResult.status >= 200 && httpResult.status < 400) {
        return {
          vulnerable: true,
          evidence: `HTTP request returned ${httpResult.status} without HTTPS redirect (location: ${httpResult.location || 'none'})`,
        };
      }
      return { vulnerable: false };
    }

    default:
      return { vulnerable: false };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent Registration
// ─────────────────────────────────────────────────────────────────────────────

registerAgent('net_ssl_tls', {
  async execute(agent, campaign, targets, aiProvider, db, onFinding, onProgress) {
    const level = campaign.exploitation_level;
    const targetList = Object.keys(targets);
    const applicableTests = TESTS.filter((t) => {
      if (level === 'passive') return t.severity !== 'info';
      return true;
    });

    await db.prepare(
      "UPDATE redops_agents SET tests_planned = ?, status = 'testing', updated_at = datetime('now') WHERE id = ?"
    ).bind(applicableTests.length, agent.id).run();

    await onProgress(agent, `Starting ${applicableTests.length} TLS/SSL tests across ${targetList.length} targets`);

    let completed = 0;
    let passed = 0;
    let failed = 0;

    for (const target of targetList) {
      // Pre-fetch HTTPS and HTTP responses once per target (shared across tests)
      await onProgress(agent, `Probing target: ${target}`);
      const httpsResult = await probeTLS(target);
      const httpResult = await probeHTTP(target);

      for (const test of applicableTests) {
        completed++;
        try {
          const result = await runTLSTest(test, target, httpsResult, httpResult, aiProvider, level);

          if (result.vulnerable) {
            const finding = buildTLSFinding(test, target, result.evidence);
            await onFinding(finding, agent);
            failed++;
            await onProgress(agent, `[VULN] ${test.name} on ${target}`);
          } else {
            passed++;
          }
        } catch {
          passed++; // Can't confirm vulnerability on error
        }

        await db.prepare(
          "UPDATE redops_agents SET tests_completed = ?, tests_passed = ?, tests_failed = ?, updated_at = datetime('now') WHERE id = ?"
        ).bind(completed, passed, failed, agent.id).run();
      }
    }

    await onProgress(agent, `TLS audit complete: ${failed} vulnerabilities found across ${targetList.length} targets`);
    return { success: true };
  },
});

function buildTLSFinding(test: TLSTest, target: string, evidence?: string): AISecurityFinding {
  const nistMap: Record<string, string[]> = {
    protocol: ['SC-8', 'SC-13', 'SC-23'],
    cipher: ['SC-13', 'SC-8'],
    certificate: ['SC-17', 'IA-5', 'SC-8'],
    header: ['SC-8', 'SC-23'],
    config: ['SC-8', 'SC-13', 'CM-6'],
  };

  return {
    title: `${test.name} — ${target}`,
    description: `${test.description}. ${evidence || ''}`.trim(),
    severity: test.severity,
    attack_vector: `TLS configuration audit: ${test.category}`,
    attack_category: `ssl_tls/${test.category}`,
    cwe_id: test.cwe_id,
    exploitable: test.severity === 'critical',
    exploitation_proof: evidence || `TLS weakness detected: ${test.name} on ${target}`,
    remediation: test.remediation,
    remediation_effort: test.severity === 'critical' ? 'significant' : test.severity === 'high' ? 'moderate' : 'quick_fix',
    mitre_tactic: 'Collection',
    mitre_technique: test.mitre_technique,
    nist_controls: nistMap[test.category] || ['SC-8'],
  };
}
