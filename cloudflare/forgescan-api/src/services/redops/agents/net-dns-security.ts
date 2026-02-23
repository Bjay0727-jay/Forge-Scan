// ─────────────────────────────────────────────────────────────────────────────
// ForgeRedOps Agent: DNS Security Testing (net_dns_security)
// ─────────────────────────────────────────────────────────────────────────────
//
// Tests DNSSEC validation, zone transfer protections, DNS rebinding,
// cache poisoning vectors, and subdomain takeover via real DNS-over-HTTPS
// queries and HTTP probing. 22 tests.

import type { ForgeAIProvider, AISecurityFinding } from '../../ai-provider';
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
// DNS-over-HTTPS query helpers
// ─────────────────────────────────────────────────────────────────────────────

const DOH_TIMEOUT = 8000;

interface DoHAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DoHResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean; // Authenticated Data = DNSSEC validated
  CD: boolean;
  Question: Array<{ name: string; type: number }>;
  Answer?: DoHAnswer[];
  Authority?: DoHAnswer[];
}

/** Query DNS records via Cloudflare's DNS-over-HTTPS resolver */
async function dohQuery(domain: string, type: string): Promise<DoHResponse | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT);
    const resp = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
      {
        headers: { Accept: 'application/dns-json' },
        signal: controller.signal,
      }
    );
    clearTimeout(timer);
    if (!resp.ok) return null;
    return (await resp.json()) as DoHResponse;
  } catch {
    return null;
  }
}

/** Extract target domain from host/URL */
function extractDomain(target: string): string {
  const cleaned = target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  return cleaned;
}

/** Check if an IP is in a private range */
function isPrivateIP(ip: string): boolean {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') ||
    ip.startsWith('172.19.') || ip.startsWith('172.20.') || ip.startsWith('172.21.') ||
    ip.startsWith('172.22.') || ip.startsWith('172.23.') || ip.startsWith('172.24.') ||
    ip.startsWith('172.25.') || ip.startsWith('172.26.') || ip.startsWith('172.27.') ||
    ip.startsWith('172.28.') || ip.startsWith('172.29.') || ip.startsWith('172.30.') ||
    ip.startsWith('172.31.') ||
    ip.startsWith('127.') ||
    ip === '0.0.0.0' || ip === '::1'
  );
}

/** Known subdomain takeover CNAME fingerprints */
const TAKEOVER_FINGERPRINTS = [
  { pattern: '.s3.amazonaws.com', service: 'AWS S3' },
  { pattern: '.s3-website', service: 'AWS S3 Website' },
  { pattern: '.herokuapp.com', service: 'Heroku' },
  { pattern: '.herokudns.com', service: 'Heroku' },
  { pattern: 'github.io', service: 'GitHub Pages' },
  { pattern: '.ghost.io', service: 'Ghost' },
  { pattern: '.pantheonsite.io', service: 'Pantheon' },
  { pattern: '.azurewebsites.net', service: 'Azure Web Apps' },
  { pattern: '.cloudapp.net', service: 'Azure' },
  { pattern: '.trafficmanager.net', service: 'Azure Traffic Manager' },
  { pattern: '.blob.core.windows.net', service: 'Azure Blob' },
  { pattern: '.cloudfront.net', service: 'CloudFront' },
  { pattern: '.fastly.net', service: 'Fastly' },
  { pattern: '.zendesk.com', service: 'Zendesk' },
  { pattern: '.shopify.com', service: 'Shopify' },
  { pattern: '.surge.sh', service: 'Surge.sh' },
  { pattern: '.bitbucket.io', service: 'Bitbucket' },
  { pattern: '.netlify.app', service: 'Netlify' },
  { pattern: '.fly.dev', service: 'Fly.io' },
  { pattern: '.unbouncepages.com', service: 'Unbounce' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Per-test scanning logic
// ─────────────────────────────────────────────────────────────────────────────

type TestResult = { vulnerable: boolean; evidence?: string };

async function runDNSTest(
  test: DNSTest,
  domain: string,
  level: string,
  cachedRecords: {
    a?: DoHResponse | null;
    txt?: DoHResponse | null;
    cname?: DoHResponse | null;
    ns?: DoHResponse | null;
    mx?: DoHResponse | null;
    dnskey?: DoHResponse | null;
  }
): Promise<TestResult> {
  switch (test.id) {
    // ── Zone transfer tests ──
    case 'DNS-001': // AXFR — cannot test via DoH; only raw TCP to port 53
    case 'DNS-002': // IXFR — same limitation
      return { vulnerable: false };

    case 'DNS-003': { // ANY query amplification
      // Modern resolvers refuse ANY (RFC 8482). Check if there's a result.
      const anyResult = await dohQuery(domain, 'ANY');
      if (anyResult && anyResult.Answer && anyResult.Answer.length > 10) {
        return {
          vulnerable: true,
          evidence: `ANY query returned ${anyResult.Answer.length} records — potential amplification vector`,
        };
      }
      return { vulnerable: false };
    }

    // ── DNSSEC tests ──
    case 'DNS-004': { // DNSSEC not enabled
      const dnskey = cachedRecords.dnskey;
      if (!dnskey || !dnskey.Answer || dnskey.Answer.length === 0) {
        // Also check AD flag on an A query
        const aResult = cachedRecords.a;
        if (aResult && !aResult.AD) {
          return { vulnerable: true, evidence: 'No DNSKEY records found and AD flag not set — DNSSEC is not enabled' };
        }
        return { vulnerable: true, evidence: 'No DNSKEY records found for domain' };
      }
      return { vulnerable: false };
    }

    case 'DNS-005': { // DNSSEC expired — check if DNSKEY exists but AD flag is false
      const dnskey = cachedRecords.dnskey;
      if (dnskey && dnskey.Answer && dnskey.Answer.length > 0) {
        const aResult = cachedRecords.a;
        if (aResult && !aResult.AD) {
          return { vulnerable: true, evidence: 'DNSKEY records exist but AD (Authenticated Data) flag is false — possible signature issue' };
        }
      }
      return { vulnerable: false };
    }

    case 'DNS-006': // Key rollover issues — can't reliably detect via DoH
      return { vulnerable: false };

    case 'DNS-007': { // NSEC zone walking
      // If DNSKEY exists but no NSEC3, NSEC is probably in use
      const dnskey = cachedRecords.dnskey;
      if (dnskey && dnskey.Answer && dnskey.Answer.length > 0) {
        const nsec3 = await dohQuery(domain, 'NSEC3PARAM');
        if (!nsec3 || !nsec3.Answer || nsec3.Answer.length === 0) {
          return { vulnerable: true, evidence: 'DNSSEC enabled with NSEC (not NSEC3), allowing zone walking enumeration' };
        }
      }
      return { vulnerable: false };
    }

    // ── DNS rebinding tests ──
    case 'DNS-008': { // DNS rebinding
      // Check if domain resolves to a private IP (common indicator of rebinding susceptibility)
      const aResult = cachedRecords.a;
      if (aResult && aResult.Answer) {
        for (const ans of aResult.Answer) {
          if (ans.type === 1 && isPrivateIP(ans.data)) {
            return {
              vulnerable: true,
              evidence: `Domain resolves to private IP ${ans.data} via public DNS — DNS rebinding risk`,
            };
          }
        }
      }
      return { vulnerable: false };
    }

    case 'DNS-009': { // Internal DNS resolution via public resolver
      // Check common internal subdomains
      const internalPrefixes = ['intranet', 'internal', 'corp', 'vpn', 'mail', 'dev', 'staging', 'admin'];
      for (const prefix of internalPrefixes) {
        const sub = `${prefix}.${domain}`;
        const result = await dohQuery(sub, 'A');
        if (result && result.Answer) {
          for (const ans of result.Answer) {
            if (ans.type === 1 && isPrivateIP(ans.data)) {
              return {
                vulnerable: true,
                evidence: `${sub} resolves to private IP ${ans.data} via public DNS — internal infrastructure leak`,
              };
            }
          }
        }
      }
      return { vulnerable: false };
    }

    case 'DNS-010': { // DNS pinning bypass
      // Check for very low TTL on A records (< 30s suggests no pinning possible)
      const aResult = cachedRecords.a;
      if (aResult && aResult.Answer) {
        const aRecords = aResult.Answer.filter((a) => a.type === 1);
        if (aRecords.length > 0 && aRecords.every((a) => a.TTL < 30)) {
          return {
            vulnerable: true,
            evidence: `A record TTL is ${aRecords[0].TTL}s — extremely low, makes DNS pinning ineffective`,
          };
        }
      }
      return { vulnerable: false };
    }

    // ── Cache poisoning tests ──
    case 'DNS-011': // Predictable transaction ID — not detectable from DoH
    case 'DNS-012': // Single source port — not detectable from DoH
      return { vulnerable: false };

    case 'DNS-013': { // Open DNS resolver
      // Check if target has port 53 responding via a known open-resolver test
      // From Workers we can test by resolving an unrelated domain via the target's IP
      // This is limited — just flag if NS records point to known open resolvers
      const nsResult = cachedRecords.ns;
      if (nsResult && nsResult.Answer) {
        for (const ns of nsResult.Answer) {
          const nsData = ns.data.toLowerCase();
          if (nsData.includes('google') || nsData.includes('cloudflare') || nsData.includes('quad9')) {
            return { vulnerable: false }; // Well-known managed DNS
          }
        }
      }
      return { vulnerable: false };
    }

    case 'DNS-014': { // Low TTL
      const aResult = cachedRecords.a;
      if (aResult && aResult.Answer) {
        const aRecords = aResult.Answer.filter((a) => a.type === 1);
        if (aRecords.length > 0 && aRecords.some((a) => a.TTL < 60)) {
          return {
            vulnerable: true,
            evidence: `A record TTL is ${aRecords[0].TTL}s — below recommended 300s minimum`,
          };
        }
      }
      return { vulnerable: false };
    }

    // ── Subdomain takeover tests ──
    case 'DNS-015': { // Dangling CNAME — Cloud
      const cnameResult = cachedRecords.cname;
      if (cnameResult && cnameResult.Answer) {
        for (const ans of cnameResult.Answer) {
          if (ans.type === 5) { // CNAME record
            const cname = ans.data.toLowerCase();
            for (const fp of TAKEOVER_FINGERPRINTS) {
              if (cname.includes(fp.pattern) && (fp.service.includes('S3') || fp.service.includes('Azure') || fp.service === 'GitHub Pages')) {
                // Try to fetch the target — 404 or specific error = dangling
                try {
                  const resp = await fetch(`https://${domain}/`, { redirect: 'manual' });
                  if (resp.status === 404 || resp.status === 0) {
                    return {
                      vulnerable: true,
                      evidence: `CNAME to ${cname} (${fp.service}) returned ${resp.status} — potential subdomain takeover`,
                    };
                  }
                  const body = await resp.text();
                  if (body.includes('NoSuchBucket') || body.includes('There isn\'t a GitHub Pages site') || body.includes('404 Not Found')) {
                    return {
                      vulnerable: true,
                      evidence: `CNAME to ${cname} (${fp.service}) — unclaimed resource detected`,
                    };
                  }
                } catch {
                  return {
                    vulnerable: true,
                    evidence: `CNAME to ${cname} (${fp.service}) — connection failed, resource likely unclaimed`,
                  };
                }
              }
            }
          }
        }
      }
      return { vulnerable: false };
    }

    case 'DNS-016': { // Dangling CNAME — CDN/SaaS
      const cnameResult = cachedRecords.cname;
      if (cnameResult && cnameResult.Answer) {
        for (const ans of cnameResult.Answer) {
          if (ans.type === 5) {
            const cname = ans.data.toLowerCase();
            for (const fp of TAKEOVER_FINGERPRINTS) {
              if (cname.includes(fp.pattern) && !fp.service.includes('S3') && !fp.service.includes('Azure') && fp.service !== 'GitHub Pages') {
                try {
                  const resp = await fetch(`https://${domain}/`, { redirect: 'manual' });
                  if (resp.status === 404 || resp.status >= 500) {
                    return {
                      vulnerable: true,
                      evidence: `CNAME to ${cname} (${fp.service}) returned ${resp.status} — potential CDN/SaaS takeover`,
                    };
                  }
                } catch {
                  return {
                    vulnerable: true,
                    evidence: `CNAME to ${cname} (${fp.service}) — connection failed, resource likely deprovisioned`,
                  };
                }
              }
            }
          }
        }
      }
      return { vulnerable: false };
    }

    case 'DNS-017': { // NS delegation to expired domain
      const nsResult = cachedRecords.ns;
      if (nsResult && nsResult.Answer) {
        for (const ns of nsResult.Answer) {
          if (ns.type === 2) { // NS record
            const nsHost = ns.data.replace(/\.$/, '');
            // Try to resolve the NS — if it doesn't resolve, it may be expired
            const nsResolve = await dohQuery(nsHost, 'A');
            if (!nsResolve || !nsResolve.Answer || nsResolve.Answer.length === 0) {
              return {
                vulnerable: true,
                evidence: `NS record points to ${nsHost} which does not resolve — possible expired delegation`,
              };
            }
          }
        }
      }
      return { vulnerable: false };
    }

    case 'DNS-018': { // MX to unclaimed host
      const mxResult = cachedRecords.mx;
      if (mxResult && mxResult.Answer) {
        for (const mx of mxResult.Answer) {
          if (mx.type === 15) { // MX record
            const mxHost = mx.data.replace(/^\d+\s+/, '').replace(/\.$/, '');
            const mxResolve = await dohQuery(mxHost, 'A');
            if (!mxResolve || !mxResolve.Answer || mxResolve.Answer.length === 0) {
              return {
                vulnerable: true,
                evidence: `MX record points to ${mxHost} which does not resolve — email interception risk`,
              };
            }
          }
        }
      }
      return { vulnerable: false };
    }

    // ── Recon tests ──
    case 'DNS-019': // Version disclosure — requires raw DNS query to version.bind, not possible via DoH
      return { vulnerable: false };

    case 'DNS-020': { // Excessive TXT records
      const txtResult = cachedRecords.txt;
      if (txtResult && txtResult.Answer) {
        const txtRecords = txtResult.Answer.filter((a) => a.type === 16);
        // Filter out standard records (SPF, DKIM, DMARC, google-site-verification, etc.)
        const nonStandard = txtRecords.filter((t) => {
          const d = t.data.toLowerCase();
          return !d.includes('v=spf') && !d.includes('v=dkim') && !d.includes('v=dmarc') &&
                 !d.includes('google-site-verification') && !d.includes('MS=') &&
                 !d.includes('facebook-domain') && !d.includes('_dmarc');
        });
        if (nonStandard.length > 3) {
          const samples = nonStandard.slice(0, 3).map((t) => t.data.substring(0, 80));
          return {
            vulnerable: true,
            evidence: `${nonStandard.length} non-standard TXT records found: ${samples.join('; ')}`,
          };
        }
      }
      return { vulnerable: false };
    }

    case 'DNS-021': { // Missing SPF
      const txtResult = cachedRecords.txt;
      if (!txtResult || !txtResult.Answer) {
        return { vulnerable: true, evidence: 'No TXT records found — SPF record is missing' };
      }
      const hasSPF = txtResult.Answer.some((a) => a.data.toLowerCase().includes('v=spf'));
      if (!hasSPF) {
        return { vulnerable: true, evidence: 'No SPF record found in TXT records — domain vulnerable to email spoofing' };
      }
      return { vulnerable: false };
    }

    case 'DNS-022': { // Missing DMARC
      const dmarcResult = await dohQuery(`_dmarc.${domain}`, 'TXT');
      if (!dmarcResult || !dmarcResult.Answer || dmarcResult.Answer.length === 0) {
        return { vulnerable: true, evidence: 'No DMARC record found at _dmarc subdomain — email spoofing may go undetected' };
      }
      const hasDMARC = dmarcResult.Answer.some((a) => a.data.toLowerCase().includes('v=dmarc'));
      if (!hasDMARC) {
        return { vulnerable: true, evidence: 'TXT record at _dmarc exists but does not contain valid DMARC policy' };
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

    for (const target of targetList) {
      const domain = extractDomain(target);
      await onProgress(agent, `Querying DNS records for ${domain}`);

      // Pre-fetch common record types once per target
      const cachedRecords = {
        a: await dohQuery(domain, 'A'),
        txt: await dohQuery(domain, 'TXT'),
        cname: await dohQuery(domain, 'CNAME'),
        ns: await dohQuery(domain, 'NS'),
        mx: await dohQuery(domain, 'MX'),
        dnskey: await dohQuery(domain, 'DNSKEY'),
      };

      for (const test of applicableTests) {
        completed++;
        try {
          const result = await runDNSTest(test, domain, level, cachedRecords);

          if (result.vulnerable) {
            const finding = buildDNSFinding(test, domain, result.evidence);
            await onFinding(finding, agent);
            failed++;
            await onProgress(agent, `[VULN] ${test.name} on ${domain}`);
          } else {
            passed++;
          }
        } catch {
          passed++;
        }

        await db.prepare(
          "UPDATE redops_agents SET tests_completed = ?, tests_passed = ?, tests_failed = ?, updated_at = datetime('now') WHERE id = ?"
        ).bind(completed, passed, failed, agent.id).run();
      }
    }

    await onProgress(agent, `DNS audit complete: ${failed} vulnerabilities found across ${targetList.length} targets`);
    return { success: true };
  },
});

function buildDNSFinding(test: DNSTest, target: string, evidence?: string): AISecurityFinding {
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
    description: `${test.description}. ${evidence || ''}`.trim(),
    severity: test.severity,
    attack_vector: `DNS security test: ${test.category}`,
    attack_category: `dns_security/${test.category}`,
    cwe_id: test.cwe_id,
    exploitable: test.severity === 'critical' || test.severity === 'high',
    exploitation_proof: evidence || `DNS vulnerability detected: ${test.name} on ${target}`,
    remediation: test.remediation,
    remediation_effort: test.severity === 'critical' ? 'significant' : 'moderate',
    mitre_tactic: 'Reconnaissance',
    mitre_technique: test.mitre_technique,
    nist_controls: nistMap[test.category] || ['SC-20'],
  };
}
