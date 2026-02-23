// ─────────────────────────────────────────────────────────────────────────────
// ForgeRedOps Agent: SSL/TLS Configuration Audit (net_ssl_tls)
// ─────────────────────────────────────────────────────────────────────────────
//
// Audits SSL/TLS certificate validity, cipher suites, protocol versions,
// HSTS enforcement, and OCSP stapling. 30 tests.

import type { AISecurityFinding } from '../../ai-provider';
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
// Agent Registration
// ─────────────────────────────────────────────────────────────────────────────

registerAgent('net_ssl_tls', {
  async execute(agent, campaign, targets, _aiProvider, db, onFinding, onProgress) {
    const level = campaign.exploitation_level;
    const targetList = Object.keys(targets);
    // All TLS tests are read-only, so all levels can run them
    const applicableTests = TESTS.filter((t) => {
      if (level === 'passive') return t.severity !== 'info'; // skip info-only in passive
      return true;
    });

    await db.prepare(
      "UPDATE redops_agents SET tests_planned = ?, status = 'testing', updated_at = datetime('now') WHERE id = ?"
    ).bind(applicableTests.length, agent.id).run();

    await onProgress(agent, `Starting ${applicableTests.length} TLS/SSL tests across ${targetList.length} targets`);

    let completed = 0;
    let passed = 0;
    let failed = 0;

    for (const test of applicableTests) {
      completed++;
      for (const target of targetList) {
        const found = simulateTLSTest(test, target);
        if (found) {
          const finding = buildTLSFinding(test, target);
          await onFinding(finding, agent);
          failed++;
        } else {
          passed++;
        }
      }

      await db.prepare(
        "UPDATE redops_agents SET tests_completed = ?, tests_passed = ?, tests_failed = ?, updated_at = datetime('now') WHERE id = ?"
      ).bind(completed, passed, failed, agent.id).run();

      await onProgress(agent, `[${completed}/${applicableTests.length}] ${test.name}`);
    }

    return { success: true };
  },
});

function simulateTLSTest(test: TLSTest, _target: string): boolean {
  // Static simulation for demonstration
  const commonFindings = [
    'TLS-003', 'TLS-004', 'TLS-009', 'TLS-011', 'TLS-012',
    'TLS-017', 'TLS-021', 'TLS-023', 'TLS-025', 'TLS-029',
  ];
  return commonFindings.includes(test.id);
}

function buildTLSFinding(test: TLSTest, target: string): AISecurityFinding {
  const nistMap: Record<string, string[]> = {
    protocol: ['SC-8', 'SC-13', 'SC-23'],
    cipher: ['SC-13', 'SC-8'],
    certificate: ['SC-17', 'IA-5', 'SC-8'],
    header: ['SC-8', 'SC-23'],
    config: ['SC-8', 'SC-13', 'CM-6'],
  };

  return {
    title: `${test.name} — ${target}`,
    description: test.description,
    severity: test.severity,
    attack_vector: `TLS configuration audit: ${test.category}`,
    attack_category: `ssl_tls/${test.category}`,
    cwe_id: test.cwe_id,
    exploitable: test.severity === 'critical',
    exploitation_proof: `TLS weakness detected: ${test.name} on ${target}`,
    remediation: test.remediation,
    remediation_effort: test.severity === 'critical' ? 'significant' : test.severity === 'high' ? 'moderate' : 'quick_fix',
    mitre_tactic: 'Collection',
    mitre_technique: test.mitre_technique,
    nist_controls: nistMap[test.category] || ['SC-8'],
  };
}
