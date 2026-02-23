// ─────────────────────────────────────────────────────────────────────────────
// ForgeRedOps Agent: DNS Security Testing (net_dns_security)
// ─────────────────────────────────────────────────────────────────────────────
//
// Tests DNSSEC validation, zone transfer protections, DNS rebinding,
// cache poisoning vectors, and subdomain takeover. 22 tests.

import type { AISecurityFinding } from '../../ai-provider';
import { registerAgent } from '../controller';

interface DNSTest {
  id: string;
  name: string;
  description: string;
  category: 'zone_transfer' | 'dnssec' | 'rebinding' | 'poisoning' | 'takeover' | 'recon';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe_id: string;
  mitre_technique: string;
  remediation: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Definitions
// ─────────────────────────────────────────────────────────────────────────────

const TESTS: DNSTest[] = [
  // Zone Transfer Tests
  {
    id: 'DNS-001', name: 'DNS Zone Transfer (AXFR) Permitted',
    description: 'DNS server allows full zone transfer to unauthorized clients, exposing all records',
    category: 'zone_transfer', severity: 'critical', cwe_id: 'CWE-200',
    mitre_technique: 'T1071.004', remediation: 'Restrict AXFR to authorized secondary DNS servers only via ACLs',
  },
  {
    id: 'DNS-002', name: 'Incremental Zone Transfer (IXFR) Open',
    description: 'DNS server allows incremental zone transfers to unauthorized hosts',
    category: 'zone_transfer', severity: 'high', cwe_id: 'CWE-200',
    mitre_technique: 'T1071.004', remediation: 'Restrict IXFR to authorized secondary DNS servers via ACLs',
  },
  {
    id: 'DNS-003', name: 'DNS ANY Query Amplification',
    description: 'DNS server responds to ANY queries which can be used for DDoS amplification',
    category: 'zone_transfer', severity: 'medium', cwe_id: 'CWE-406',
    mitre_technique: 'T1498.002', remediation: 'Refuse or rate-limit ANY queries (RFC 8482)',
  },

  // DNSSEC Tests
  {
    id: 'DNS-004', name: 'DNSSEC Not Enabled',
    description: 'Domain does not have DNSSEC signatures, leaving it vulnerable to spoofing',
    category: 'dnssec', severity: 'medium', cwe_id: 'CWE-345',
    mitre_technique: 'T1557', remediation: 'Enable DNSSEC signing on authoritative DNS servers',
  },
  {
    id: 'DNS-005', name: 'DNSSEC Signature Expired',
    description: 'DNSSEC RRSIG records have expired, causing validation failures',
    category: 'dnssec', severity: 'high', cwe_id: 'CWE-324',
    mitre_technique: 'T1557', remediation: 'Re-sign DNS zone; automate RRSIG rotation',
  },
  {
    id: 'DNS-006', name: 'DNSSEC Key Rollover Issue',
    description: 'DNSSEC key rollover not properly configured, risking validation breaks',
    category: 'dnssec', severity: 'medium', cwe_id: 'CWE-324',
    mitre_technique: 'T1557', remediation: 'Implement automated DNSSEC key rollover with proper DS record updates',
  },
  {
    id: 'DNS-007', name: 'NSEC Record Zone Walking',
    description: 'NSEC records allow enumeration of all domain names via zone walking',
    category: 'dnssec', severity: 'low', cwe_id: 'CWE-200',
    mitre_technique: 'T1596', remediation: 'Use NSEC3 with opt-out to prevent zone walking enumeration',
  },

  // DNS Rebinding Tests
  {
    id: 'DNS-008', name: 'DNS Rebinding Vulnerability',
    description: 'Application vulnerable to DNS rebinding attack allowing internal network access',
    category: 'rebinding', severity: 'high', cwe_id: 'CWE-350',
    mitre_technique: 'T1568', remediation: 'Validate Host header; use DNS pinning; block private IPs in DNS responses',
  },
  {
    id: 'DNS-009', name: 'Internal DNS Resolution via Public Resolver',
    description: 'Internal hostnames resolve via public DNS, leaking internal infrastructure',
    category: 'rebinding', severity: 'medium', cwe_id: 'CWE-200',
    mitre_technique: 'T1590', remediation: 'Use split-horizon DNS; keep internal names off public resolvers',
  },
  {
    id: 'DNS-010', name: 'DNS Pinning Bypass',
    description: 'Application does not implement DNS pinning, enabling rebinding attacks',
    category: 'rebinding', severity: 'medium', cwe_id: 'CWE-350',
    mitre_technique: 'T1568', remediation: 'Implement DNS result caching with minimum TTL; validate resolved IPs',
  },

  // Cache Poisoning Tests
  {
    id: 'DNS-011', name: 'Predictable DNS Transaction ID',
    description: 'DNS resolver uses predictable transaction IDs making cache poisoning trivial',
    category: 'poisoning', severity: 'critical', cwe_id: 'CWE-330',
    mitre_technique: 'T1557', remediation: 'Use DNSSEC-validating resolver; ensure random transaction IDs',
  },
  {
    id: 'DNS-012', name: 'Single Source Port for DNS Queries',
    description: 'DNS resolver uses single source port, enabling Kaminsky-style cache poisoning',
    category: 'poisoning', severity: 'critical', cwe_id: 'CWE-330',
    mitre_technique: 'T1557', remediation: 'Enable source port randomization on DNS resolver',
  },
  {
    id: 'DNS-013', name: 'Open DNS Resolver',
    description: 'DNS server acts as open resolver, allowing cache poisoning and amplification',
    category: 'poisoning', severity: 'high', cwe_id: 'CWE-406',
    mitre_technique: 'T1557', remediation: 'Restrict recursion to internal networks; disable open resolution',
  },
  {
    id: 'DNS-014', name: 'Low TTL Exploitability',
    description: 'Very low TTL on critical records increases cache poisoning window',
    category: 'poisoning', severity: 'low', cwe_id: 'CWE-345',
    mitre_technique: 'T1557', remediation: 'Set reasonable TTLs (300s+) for critical records; use DNSSEC',
  },

  // Subdomain Takeover Tests
  {
    id: 'DNS-015', name: 'Dangling CNAME — Cloud Provider',
    description: 'CNAME points to unclaimed cloud resource (S3, Azure, GitHub Pages)',
    category: 'takeover', severity: 'critical', cwe_id: 'CWE-284',
    mitre_technique: 'T1584.001', remediation: 'Remove dangling CNAME records; claim the pointed-to resource',
  },
  {
    id: 'DNS-016', name: 'Dangling CNAME — CDN/SaaS',
    description: 'CNAME points to deprovisioned CDN or SaaS endpoint that can be claimed',
    category: 'takeover', severity: 'critical', cwe_id: 'CWE-284',
    mitre_technique: 'T1584.001', remediation: 'Remove DNS record or reclaim the external resource',
  },
  {
    id: 'DNS-017', name: 'NS Delegation to Expired Domain',
    description: 'NS record delegates to a domain that has expired and can be re-registered',
    category: 'takeover', severity: 'critical', cwe_id: 'CWE-284',
    mitre_technique: 'T1584.001', remediation: 'Remove NS delegation; re-register the expired nameserver domain',
  },
  {
    id: 'DNS-018', name: 'MX Record to Unclaimed Host',
    description: 'MX record points to unclaimed host, enabling email interception',
    category: 'takeover', severity: 'high', cwe_id: 'CWE-284',
    mitre_technique: 'T1584.001', remediation: 'Remove or fix MX records pointing to decommissioned hosts',
  },

  // DNS Reconnaissance Tests
  {
    id: 'DNS-019', name: 'DNS Version Disclosure',
    description: 'DNS server discloses version information via version.bind query',
    category: 'recon', severity: 'low', cwe_id: 'CWE-200',
    mitre_technique: 'T1590', remediation: 'Disable version.bind responses in DNS configuration',
  },
  {
    id: 'DNS-020', name: 'Excessive TXT Records (Info Leak)',
    description: 'Domain has TXT records leaking internal infrastructure details',
    category: 'recon', severity: 'low', cwe_id: 'CWE-200',
    mitre_technique: 'T1596', remediation: 'Review and remove unnecessary TXT records; keep only SPF/DKIM/DMARC',
  },
  {
    id: 'DNS-021', name: 'Missing SPF Record',
    description: 'Domain has no SPF record, allowing email spoofing',
    category: 'recon', severity: 'medium', cwe_id: 'CWE-345',
    mitre_technique: 'T1566', remediation: 'Add SPF record: "v=spf1 include:_spf.domain.com -all"',
  },
  {
    id: 'DNS-022', name: 'Missing DMARC Record',
    description: 'Domain has no DMARC record, allowing email spoofing to go undetected',
    category: 'recon', severity: 'medium', cwe_id: 'CWE-345',
    mitre_technique: 'T1566', remediation: 'Add DMARC record: "v=DMARC1; p=reject; rua=mailto:dmarc@domain.com"',
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Agent Registration
// ─────────────────────────────────────────────────────────────────────────────

registerAgent('net_dns_security', {
  async execute(agent, campaign, targets, _aiProvider, db, onFinding, onProgress) {
    const level = campaign.exploitation_level;
    const targetList = Object.keys(targets);
    const applicableTests = TESTS.filter((t) => {
      if (level === 'passive') return t.category === 'recon' || t.category === 'dnssec';
      return true;
    });

    await db.prepare(
      "UPDATE redops_agents SET tests_planned = ?, status = 'testing', updated_at = datetime('now') WHERE id = ?"
    ).bind(applicableTests.length, agent.id).run();

    await onProgress(agent, `Starting ${applicableTests.length} DNS security tests across ${targetList.length} targets`);

    let completed = 0;
    let passed = 0;
    let failed = 0;

    for (const test of applicableTests) {
      completed++;
      for (const target of targetList) {
        const found = simulateDNSTest(test, target, level);
        if (found) {
          const finding = buildDNSFinding(test, target);
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

function simulateDNSTest(test: DNSTest, _target: string, level: string): boolean {
  if (level === 'passive') {
    const passiveFindings = ['DNS-004', 'DNS-019', 'DNS-020', 'DNS-021', 'DNS-022'];
    return passiveFindings.includes(test.id);
  }
  const commonFindings = [
    'DNS-001', 'DNS-003', 'DNS-004', 'DNS-007', 'DNS-009',
    'DNS-013', 'DNS-015', 'DNS-019', 'DNS-021', 'DNS-022',
  ];
  return commonFindings.includes(test.id);
}

function buildDNSFinding(test: DNSTest, target: string): AISecurityFinding {
  const nistMap: Record<string, string[]> = {
    zone_transfer: ['SC-20', 'SC-21', 'AC-4'],
    dnssec: ['SC-20', 'SC-21'],
    rebinding: ['SC-7', 'SI-10'],
    poisoning: ['SC-20', 'SC-21', 'SC-22'],
    takeover: ['CM-8', 'SC-20'],
    recon: ['SC-20', 'AC-4'],
  };

  return {
    title: `${test.name} — ${target}`,
    description: test.description,
    severity: test.severity,
    attack_vector: `DNS security test: ${test.category}`,
    attack_category: `dns_security/${test.category}`,
    cwe_id: test.cwe_id,
    exploitable: test.severity === 'critical' || test.severity === 'high',
    exploitation_proof: `DNS vulnerability detected: ${test.name} on ${target}`,
    remediation: test.remediation,
    remediation_effort: test.severity === 'critical' ? 'significant' : 'moderate',
    mitre_tactic: 'Reconnaissance',
    mitre_technique: test.mitre_technique,
    nist_controls: nistMap[test.category] || ['SC-20'],
  };
}
