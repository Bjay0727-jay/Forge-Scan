// ─────────────────────────────────────────────────────────────────────────────
// ForgeRedOps Agent: Network Segmentation Testing (net_segmentation)
// ─────────────────────────────────────────────────────────────────────────────
//
// Tests network segmentation boundaries, lateral movement paths, firewall
// rules, and egress filtering via HTTP-based service probing. 24 tests.
//
// Note: From Cloudflare Workers, raw TCP/UDP port scanning is not possible.
// This agent probes HTTP/HTTPS endpoints on target ports to detect
// accessible services. For full port scanning, the Rust-based scanner is used.

import type { AISecurityFinding } from '../../ai-provider';
import { registerAgent } from '../controller';

interface SegmentationTest {
  id: string;
  name: string;
  description: string;
  category: 'vlan' | 'firewall' | 'lateral' | 'egress' | 'micro_seg';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe_id: string;
  mitre_technique: string;
  remediation: string;
  ports: number[];
  protocols: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Definitions
// ─────────────────────────────────────────────────────────────────────────────

const TESTS: SegmentationTest[] = [
  // VLAN Isolation Tests
  {
    id: 'NS-001', name: 'VLAN Hopping via Double Tagging',
    description: 'Tests if VLAN hopping is possible via 802.1Q double-tagging attack',
    category: 'vlan', severity: 'critical', cwe_id: 'CWE-284',
    mitre_technique: 'T1046', remediation: 'Disable native VLAN on trunk ports, use dedicated VLAN for trunking',
    ports: [1, 22, 80, 443], protocols: ['tcp'],
  },
  {
    id: 'NS-002', name: 'Inter-VLAN Routing Leak',
    description: 'Checks for unintended routing between VLANs that should be isolated',
    category: 'vlan', severity: 'high', cwe_id: 'CWE-284',
    mitre_technique: 'T1021', remediation: 'Review ACLs on layer 3 switches, disable inter-VLAN routing where not required',
    ports: [22, 80, 443, 3389], protocols: ['tcp'],
  },
  {
    id: 'NS-003', name: 'Management VLAN Access from User Segment',
    description: 'Tests if management interfaces are accessible from user network segments',
    category: 'vlan', severity: 'critical', cwe_id: 'CWE-668',
    mitre_technique: 'T1021', remediation: 'Restrict management VLAN access via ACLs; use out-of-band management',
    ports: [22, 23, 443, 8443, 161, 162], protocols: ['tcp', 'udp'],
  },
  {
    id: 'NS-004', name: 'ARP Spoofing Cross-VLAN',
    description: 'Tests for ARP-based attacks that could bypass VLAN isolation',
    category: 'vlan', severity: 'high', cwe_id: 'CWE-290',
    mitre_technique: 'T1557', remediation: 'Enable Dynamic ARP Inspection (DAI) and DHCP Snooping',
    ports: [], protocols: ['arp'],
  },

  // Firewall Rule Tests
  {
    id: 'NS-005', name: 'Overly Permissive Firewall Rules',
    description: 'Scans for ANY-ANY rules or overly broad CIDR ranges in firewall policies',
    category: 'firewall', severity: 'high', cwe_id: 'CWE-732',
    mitre_technique: 'T1046', remediation: 'Review and tighten firewall rules to principle of least privilege',
    ports: [1, 21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443],
    protocols: ['tcp', 'udp'],
  },
  {
    id: 'NS-006', name: 'Firewall Rule Bypass via Fragmentation',
    description: 'Tests if IP fragmentation can bypass stateless firewall inspection',
    category: 'firewall', severity: 'medium', cwe_id: 'CWE-693',
    mitre_technique: 'T1090', remediation: 'Enable fragment reassembly on firewalls; use stateful inspection',
    ports: [80, 443], protocols: ['tcp'],
  },
  {
    id: 'NS-007', name: 'DMZ to Internal Network Access',
    description: 'Verifies that DMZ hosts cannot reach internal network segments',
    category: 'firewall', severity: 'critical', cwe_id: 'CWE-284',
    mitre_technique: 'T1021', remediation: 'Block all DMZ-to-internal traffic except explicitly allowed services',
    ports: [22, 445, 3389, 1433, 3306, 5432], protocols: ['tcp'],
  },
  {
    id: 'NS-008', name: 'Unused Open Ports',
    description: 'Identifies open ports with no legitimate business purpose',
    category: 'firewall', severity: 'medium', cwe_id: 'CWE-284',
    mitre_technique: 'T1046', remediation: 'Close unused ports in firewall rules and disable unnecessary services',
    ports: [21, 23, 25, 69, 111, 135, 139, 445, 512, 513, 514, 1099, 2049, 6000],
    protocols: ['tcp', 'udp'],
  },

  // Lateral Movement Tests
  {
    id: 'NS-009', name: 'SMB Lateral Movement Path',
    description: 'Tests if SMB/CIFS is accessible between workstation segments',
    category: 'lateral', severity: 'high', cwe_id: 'CWE-284',
    mitre_technique: 'T1021.002', remediation: 'Block SMB (445/tcp) between workstation segments; use host-based firewall',
    ports: [445, 139], protocols: ['tcp'],
  },
  {
    id: 'NS-010', name: 'WinRM Lateral Movement',
    description: 'Tests for WinRM access between segments for remote execution',
    category: 'lateral', severity: 'high', cwe_id: 'CWE-284',
    mitre_technique: 'T1021.006', remediation: 'Restrict WinRM access to management segment only',
    ports: [5985, 5986], protocols: ['tcp'],
  },
  {
    id: 'NS-011', name: 'SSH Lateral Movement Between Zones',
    description: 'Tests if SSH is accessible between network zones that should be isolated',
    category: 'lateral', severity: 'medium', cwe_id: 'CWE-284',
    mitre_technique: 'T1021.004', remediation: 'Restrict SSH access via jump boxes; use network segmentation',
    ports: [22], protocols: ['tcp'],
  },
  {
    id: 'NS-012', name: 'RDP Cross-Segment Access',
    description: 'Tests for unrestricted RDP access between network segments',
    category: 'lateral', severity: 'high', cwe_id: 'CWE-284',
    mitre_technique: 'T1021.001', remediation: 'Block RDP between user segments; require VPN/jump box for remote access',
    ports: [3389], protocols: ['tcp'],
  },
  {
    id: 'NS-013', name: 'Database Direct Access from Web Tier',
    description: 'Tests if web tier can directly access database ports bypassing app tier',
    category: 'lateral', severity: 'critical', cwe_id: 'CWE-284',
    mitre_technique: 'T1046', remediation: 'Enforce three-tier architecture: web → app → DB. Block direct web-to-DB access',
    ports: [1433, 3306, 5432, 27017, 6379, 9042], protocols: ['tcp'],
  },
  {
    id: 'NS-014', name: 'SNMP Lateral Enumeration',
    description: 'Tests if SNMP is accessible across segments enabling network enumeration',
    category: 'lateral', severity: 'medium', cwe_id: 'CWE-200',
    mitre_technique: 'T1046', remediation: 'Restrict SNMP to management network; use SNMPv3 with authentication',
    ports: [161, 162], protocols: ['udp'],
  },

  // Egress Filtering Tests
  {
    id: 'NS-015', name: 'Unrestricted Outbound DNS',
    description: 'Tests if DNS queries can bypass internal resolvers (data exfiltration vector)',
    category: 'egress', severity: 'medium', cwe_id: 'CWE-284',
    mitre_technique: 'T1048', remediation: 'Force all DNS through internal resolvers; block outbound UDP/TCP 53',
    ports: [53], protocols: ['tcp', 'udp'],
  },
  {
    id: 'NS-016', name: 'Unrestricted Outbound HTTP/S',
    description: 'Tests if hosts can reach arbitrary internet destinations without proxy',
    category: 'egress', severity: 'medium', cwe_id: 'CWE-284',
    mitre_technique: 'T1048', remediation: 'Route all web traffic through forward proxy; block direct outbound 80/443',
    ports: [80, 443], protocols: ['tcp'],
  },
  {
    id: 'NS-017', name: 'Data Exfiltration via Non-Standard Ports',
    description: 'Tests if data can be exfiltrated via non-standard ports',
    category: 'egress', severity: 'high', cwe_id: 'CWE-284',
    mitre_technique: 'T1048', remediation: 'Default deny outbound; allow only required ports and destinations',
    ports: [4443, 8080, 8443, 9090, 1194, 1723], protocols: ['tcp'],
  },
  {
    id: 'NS-018', name: 'DNS Tunneling Egress',
    description: 'Tests if DNS tunneling can bypass egress controls for data exfiltration',
    category: 'egress', severity: 'high', cwe_id: 'CWE-693',
    mitre_technique: 'T1572', remediation: 'Monitor DNS query patterns; limit DNS query size; use DNS inspection',
    ports: [53], protocols: ['udp'],
  },
  {
    id: 'NS-019', name: 'ICMP Tunnel Egress',
    description: 'Tests if ICMP tunneling can bypass egress firewalls',
    category: 'egress', severity: 'medium', cwe_id: 'CWE-693',
    mitre_technique: 'T1572', remediation: 'Rate-limit ICMP; inspect ICMP payload sizes; consider blocking ICMP echo',
    ports: [], protocols: ['icmp'],
  },

  // Microsegmentation Tests
  {
    id: 'NS-020', name: 'Container-to-Container Cross-Namespace',
    description: 'Tests if containers in different namespaces can communicate when they should not',
    category: 'micro_seg', severity: 'high', cwe_id: 'CWE-284',
    mitre_technique: 'T1021', remediation: 'Apply Kubernetes NetworkPolicies to restrict cross-namespace traffic',
    ports: [80, 443, 8080, 3000], protocols: ['tcp'],
  },
  {
    id: 'NS-021', name: 'Pod-to-Pod Default Allow',
    description: 'Tests if Kubernetes default-allow networking is in effect',
    category: 'micro_seg', severity: 'medium', cwe_id: 'CWE-284',
    mitre_technique: 'T1046', remediation: 'Apply default-deny NetworkPolicy then whitelist required flows',
    ports: [80, 443, 8080], protocols: ['tcp'],
  },
  {
    id: 'NS-022', name: 'Service Mesh Bypass',
    description: 'Tests if service mesh (Istio/Linkerd) mTLS can be bypassed',
    category: 'micro_seg', severity: 'high', cwe_id: 'CWE-295',
    mitre_technique: 'T1557', remediation: 'Enable strict mTLS mode; verify PeerAuthentication policies',
    ports: [15001, 15006, 15021], protocols: ['tcp'],
  },
  {
    id: 'NS-023', name: 'Workload Identity Spoofing',
    description: 'Tests if workload identities can be spoofed to access unauthorized services',
    category: 'micro_seg', severity: 'critical', cwe_id: 'CWE-290',
    mitre_technique: 'T1036', remediation: 'Use SPIFFE/SPIRE for strong workload identity; enforce AuthorizationPolicy',
    ports: [443, 8443], protocols: ['tcp'],
  },
  {
    id: 'NS-024', name: 'East-West Traffic Monitoring Gap',
    description: 'Tests if east-west (internal) traffic is monitored and logged',
    category: 'micro_seg', severity: 'low', cwe_id: 'CWE-778',
    mitre_technique: 'T1046', remediation: 'Deploy network flow monitoring for east-west traffic; enable access logging',
    ports: [], protocols: ['tcp'],
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// HTTP-based service probing
// ─────────────────────────────────────────────────────────────────────────────

const PROBE_TIMEOUT = 5000;

/** Service fingerprints detected in HTTP responses */
const SERVICE_SIGNATURES: Array<{ pattern: RegExp; service: string }> = [
  { pattern: /Microsoft-HTTPAPI|IIS/i, service: 'Windows IIS' },
  { pattern: /SSH-\d/i, service: 'SSH' },
  { pattern: /SMB|Windows.*File.*Sharing/i, service: 'SMB' },
  { pattern: /MySQL|MariaDB/i, service: 'MySQL/MariaDB' },
  { pattern: /PostgreSQL/i, service: 'PostgreSQL' },
  { pattern: /MongoDB/i, service: 'MongoDB' },
  { pattern: /Redis/i, service: 'Redis' },
  { pattern: /Cassandra/i, service: 'Cassandra' },
  { pattern: /Microsoft SQL Server|MSSQL/i, service: 'MSSQL' },
  { pattern: /RDP|Remote Desktop/i, service: 'RDP' },
  { pattern: /WinRM|WSMan/i, service: 'WinRM' },
  { pattern: /Kubernetes|kube|k8s/i, service: 'Kubernetes' },
  { pattern: /Istio|Envoy/i, service: 'Service Mesh (Istio/Envoy)' },
  { pattern: /Docker/i, service: 'Docker' },
  { pattern: /SNMP|Simple Network Management/i, service: 'SNMP' },
  { pattern: /FTP|FileZilla/i, service: 'FTP' },
  { pattern: /Telnet/i, service: 'Telnet' },
  { pattern: /VPN|OpenVPN|WireGuard|PPTP/i, service: 'VPN' },
];

interface ProbeResult {
  port: number;
  reachable: boolean;
  status?: number;
  service?: string;
  headers?: Record<string, string>;
  body?: string;
}

/** Probe a single port via HTTPS then HTTP fallback */
async function probePort(host: string, port: number): Promise<ProbeResult> {
  // Try HTTPS first for standard web ports
  const protocols = [443, 8443, 5986, 15021].includes(port) ? ['https'] : ['http', 'https'];

  for (const proto of protocols) {
    const url = `${proto}://${host}:${port}/`;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT);
      const resp = await fetch(url, {
        method: 'GET',
        headers: { 'User-Agent': 'ForgeRedOps SegmentTest/1.0' },
        redirect: 'manual',
        signal: controller.signal,
      });
      clearTimeout(timer);
      const headers = Object.fromEntries(resp.headers.entries());
      const body = (await resp.text()).substring(0, 5000);

      // Identify service from response
      let service: string | undefined;
      const fullText = `${JSON.stringify(headers)} ${body}`;
      for (const sig of SERVICE_SIGNATURES) {
        if (sig.pattern.test(fullText)) {
          service = sig.service;
          break;
        }
      }

      return { port, reachable: true, status: resp.status, service, headers, body };
    } catch {
      // Connection refused or timeout — port not reachable via this protocol
      continue;
    }
  }

  return { port, reachable: false };
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-test scanning logic
// ─────────────────────────────────────────────────────────────────────────────

type TestResult = { vulnerable: boolean; evidence?: string };

async function runSegmentationTest(
  test: SegmentationTest,
  host: string,
  portResults: Map<number, ProbeResult>,
  level: string
): Promise<TestResult> {
  // Tests that require raw network access (ARP, ICMP, UDP) can't run from Workers
  if (test.protocols.every((p) => p === 'arp' || p === 'icmp' || p === 'udp')) {
    return { vulnerable: false };
  }

  switch (test.id) {
    // ── VLAN tests (NS-001 to NS-004) ──
    // True VLAN hopping and ARP spoofing require L2 access. From Workers we can
    // only detect if services that should be segmented are reachable via HTTP.
    case 'NS-001': // VLAN hopping — requires L2 access
    case 'NS-004': // ARP spoofing — requires L2 access
      return { vulnerable: false };

    case 'NS-002': { // Inter-VLAN routing leak — check if multiple service ports respond
      const openPorts = test.ports.filter((p) => portResults.get(p)?.reachable);
      if (openPorts.length >= 3) {
        return {
          vulnerable: true,
          evidence: `${openPorts.length} service ports reachable from this segment: ${openPorts.join(', ')} — potential inter-VLAN routing leak`,
        };
      }
      return { vulnerable: false };
    }

    case 'NS-003': { // Management VLAN accessible
      const mgmtPorts = [22, 23, 443, 8443];
      const openMgmt = mgmtPorts.filter((p) => portResults.get(p)?.reachable);
      if (openMgmt.length >= 2) {
        const services = openMgmt.map((p) => `${p}(${portResults.get(p)?.service || 'open'})`);
        return {
          vulnerable: true,
          evidence: `Management ports accessible: ${services.join(', ')} — management VLAN not properly isolated`,
        };
      }
      return { vulnerable: false };
    }

    // ── Firewall tests (NS-005 to NS-008) ──
    case 'NS-005': { // Overly permissive firewall
      const openCount = test.ports.filter((p) => portResults.get(p)?.reachable).length;
      if (openCount >= 6) {
        const openPorts = test.ports.filter((p) => portResults.get(p)?.reachable);
        return {
          vulnerable: true,
          evidence: `${openCount}/${test.ports.length} ports reachable: ${openPorts.join(', ')} — overly permissive firewall rules`,
        };
      }
      return { vulnerable: false };
    }

    case 'NS-006': // Fragmentation bypass — requires raw packets
      return { vulnerable: false };

    case 'NS-007': { // DMZ to internal access
      const dbPorts = [1433, 3306, 5432];
      const mgmtPorts = [22, 3389, 445];
      const openDB = dbPorts.filter((p) => portResults.get(p)?.reachable);
      const openMgmt = mgmtPorts.filter((p) => portResults.get(p)?.reachable);
      if (openDB.length > 0 || openMgmt.length > 0) {
        const allOpen = [...openDB, ...openMgmt];
        return {
          vulnerable: true,
          evidence: `Internal services reachable from DMZ: ${allOpen.map((p) => `${p}(${portResults.get(p)?.service || 'open'})`).join(', ')}`,
        };
      }
      return { vulnerable: false };
    }

    case 'NS-008': { // Unused open ports
      const legacyPorts = [21, 23, 25, 69, 111, 135, 139, 512, 513, 514, 1099, 2049, 6000];
      const openLegacy = legacyPorts.filter((p) => portResults.get(p)?.reachable);
      if (openLegacy.length > 0) {
        return {
          vulnerable: true,
          evidence: `Legacy/unused ports open: ${openLegacy.map((p) => `${p}(${portResults.get(p)?.service || 'open'})`).join(', ')}`,
        };
      }
      return { vulnerable: false };
    }

    // ── Lateral movement tests (NS-009 to NS-014) ──
    case 'NS-009': { // SMB lateral
      const smb445 = portResults.get(445);
      const smb139 = portResults.get(139);
      if (smb445?.reachable || smb139?.reachable) {
        const port = smb445?.reachable ? 445 : 139;
        return {
          vulnerable: true,
          evidence: `SMB service reachable on port ${port} — lateral movement path exists (${portResults.get(port)?.service || 'SMB'})`,
        };
      }
      return { vulnerable: false };
    }

    case 'NS-010': { // WinRM lateral
      for (const p of [5985, 5986]) {
        const result = portResults.get(p);
        if (result?.reachable) {
          return {
            vulnerable: true,
            evidence: `WinRM accessible on port ${p} — remote execution path (${result.service || 'WinRM'})`,
          };
        }
      }
      return { vulnerable: false };
    }

    case 'NS-011': { // SSH lateral
      const ssh = portResults.get(22);
      if (ssh?.reachable) {
        return {
          vulnerable: true,
          evidence: `SSH accessible on port 22 — cross-zone lateral movement path (${ssh.service || 'SSH'})`,
        };
      }
      return { vulnerable: false };
    }

    case 'NS-012': { // RDP cross-segment
      const rdp = portResults.get(3389);
      if (rdp?.reachable) {
        return {
          vulnerable: true,
          evidence: `RDP accessible on port 3389 — unrestricted cross-segment remote desktop (${rdp.service || 'RDP'})`,
        };
      }
      return { vulnerable: false };
    }

    case 'NS-013': { // Database direct access
      const dbPorts = [1433, 3306, 5432, 27017, 6379, 9042];
      const openDB = dbPorts.filter((p) => portResults.get(p)?.reachable);
      if (openDB.length > 0) {
        const services = openDB.map((p) => `${p}(${portResults.get(p)?.service || 'database'})`);
        return {
          vulnerable: true,
          evidence: `Database services directly accessible: ${services.join(', ')} — bypasses three-tier architecture`,
        };
      }
      return { vulnerable: false };
    }

    case 'NS-014': // SNMP — UDP, can't test from Workers
      return { vulnerable: false };

    // ── Egress tests (NS-015 to NS-019) ──
    // Egress tests check if the target can reach external services.
    // From Workers we check FROM outside — so these test if the target has
    // ports open that suggest unrestricted egress capability.
    case 'NS-015': // DNS egress — would need to test from inside the network
    case 'NS-016': // HTTP egress — same
    case 'NS-018': // DNS tunneling — same
    case 'NS-019': // ICMP tunnel — same
      return { vulnerable: false };

    case 'NS-017': { // Non-standard ports — check if target has non-standard ports open
      const nonStd = [4443, 8080, 8443, 9090, 1194, 1723];
      const openNonStd = nonStd.filter((p) => portResults.get(p)?.reachable);
      if (openNonStd.length >= 2) {
        return {
          vulnerable: true,
          evidence: `Non-standard ports open: ${openNonStd.join(', ')} — potential data exfiltration vectors`,
        };
      }
      return { vulnerable: false };
    }

    // ── Microsegmentation tests (NS-020 to NS-024) ──
    case 'NS-020': { // Container cross-namespace
      const webPorts = [80, 443, 8080, 3000];
      const openWeb = webPorts.filter((p) => portResults.get(p)?.reachable);
      // Check for Kubernetes-specific headers
      for (const p of openWeb) {
        const result = portResults.get(p);
        if (result?.headers?.['x-envoy-upstream-service-time'] || result?.body?.includes('kubernetes') || result?.body?.includes('kube-')) {
          return {
            vulnerable: true,
            evidence: `Kubernetes service accessible on port ${p} with cross-namespace indicators`,
          };
        }
      }
      return { vulnerable: false };
    }

    case 'NS-021': { // Pod-to-pod default allow
      const webPorts = [80, 443, 8080];
      const openCount = webPorts.filter((p) => portResults.get(p)?.reachable).length;
      if (openCount === webPorts.length) {
        return {
          vulnerable: true,
          evidence: `All web ports (${webPorts.join(', ')}) accessible — possible default-allow NetworkPolicy in effect`,
        };
      }
      return { vulnerable: false };
    }

    case 'NS-022': { // Service mesh bypass
      const meshPorts = [15001, 15006, 15021];
      const openMesh = meshPorts.filter((p) => portResults.get(p)?.reachable);
      if (openMesh.length > 0) {
        return {
          vulnerable: true,
          evidence: `Service mesh control ports accessible: ${openMesh.join(', ')} — mTLS enforcement may be bypassed`,
        };
      }
      return { vulnerable: false };
    }

    case 'NS-023': { // Workload identity spoofing
      for (const p of [443, 8443]) {
        const result = portResults.get(p);
        if (result?.reachable && result.status === 200) {
          // If the service responds 200 without proper auth, identity may be spoofable
          const noAuth = !result.headers?.['www-authenticate'] && !result.headers?.['authorization'];
          if (noAuth) {
            return {
              vulnerable: true,
              evidence: `Service on port ${p} responds 200 without authentication — workload identity not enforced`,
            };
          }
        }
      }
      return { vulnerable: false };
    }

    case 'NS-024': // East-west monitoring gap — can't detect from outside
      return { vulnerable: false };

    default:
      return { vulnerable: false };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent Registration
// ─────────────────────────────────────────────────────────────────────────────

registerAgent('net_segmentation', {
  async execute(agent, campaign, targets, _aiProvider, db, onFinding, onProgress) {
    const level = campaign.exploitation_level;
    const targetList = Object.keys(targets);
    const applicableTests = TESTS.filter((t) => {
      if (level === 'passive') return t.severity === 'info' || t.category === 'firewall';
      return true;
    });

    await db.prepare(
      "UPDATE redops_agents SET tests_planned = ?, status = 'testing', updated_at = datetime('now') WHERE id = ?"
    ).bind(applicableTests.length, agent.id).run();

    await onProgress(agent, `Starting ${applicableTests.length} segmentation tests across ${targetList.length} targets`);

    let completed = 0;
    let passed = 0;
    let failed = 0;

    for (const target of targetList) {
      const host = target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
      await onProgress(agent, `Probing service ports on ${host}`);

      // Collect all unique ports referenced by applicable tests
      const allPorts = new Set<number>();
      for (const test of applicableTests) {
        for (const p of test.ports) {
          allPorts.add(p);
        }
      }

      // Skip port 1 (not HTTP-accessible) and very low ports
      allPorts.delete(1);
      allPorts.delete(69); // TFTP, UDP only

      // Probe all ports in parallel (batched to avoid overwhelming the target)
      const portArray = Array.from(allPorts);
      const portResults = new Map<number, ProbeResult>();
      const BATCH_SIZE = 8;

      for (let i = 0; i < portArray.length; i += BATCH_SIZE) {
        const batch = portArray.slice(i, i + BATCH_SIZE);
        const results = await Promise.allSettled(batch.map((p) => probePort(host, p)));
        for (let j = 0; j < results.length; j++) {
          if (results[j].status === 'fulfilled') {
            portResults.set(batch[j], (results[j] as PromiseFulfilledResult<ProbeResult>).value);
          } else {
            portResults.set(batch[j], { port: batch[j], reachable: false });
          }
        }
      }

      const openCount = Array.from(portResults.values()).filter((r) => r.reachable).length;
      await onProgress(agent, `Port scan complete: ${openCount}/${portArray.length} ports reachable on ${host}`);

      // Run each test against the cached port results
      for (const test of applicableTests) {
        completed++;
        try {
          const result = await runSegmentationTest(test, host, portResults, level);

          if (result.vulnerable) {
            const finding = buildFinding(test, host, result.evidence);
            await onFinding(finding, agent);
            failed++;
            await onProgress(agent, `[VULN] ${test.name} on ${host}`);
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

    await onProgress(agent, `Segmentation audit complete: ${failed} vulnerabilities found across ${targetList.length} targets`);
    return { success: true };
  },
});

function buildFinding(test: SegmentationTest, target: string, evidence?: string): AISecurityFinding {
  const nistMap: Record<string, string[]> = {
    vlan: ['AC-4', 'SC-7'],
    firewall: ['SC-7', 'AC-4', 'CM-7'],
    lateral: ['AC-4', 'SC-7', 'AC-3'],
    egress: ['SC-7', 'AC-4', 'SI-4'],
    micro_seg: ['AC-4', 'SC-7', 'SC-8'],
  };

  return {
    title: `${test.name} — ${target}`,
    description: `${test.description}. ${evidence || ''}`.trim(),
    severity: test.severity,
    attack_vector: `Network segmentation test: ${test.ports.length > 0 ? `ports ${test.ports.join(',')}` : test.protocols.join(',')}`,
    attack_category: `network_segmentation/${test.category}`,
    cwe_id: test.cwe_id,
    exploitable: test.severity === 'critical' || test.severity === 'high',
    exploitation_proof: evidence || `Segmentation boundary breach detected: ${test.name} on ${target}`,
    remediation: test.remediation,
    remediation_effort: test.severity === 'critical' ? 'significant' : 'moderate',
    mitre_tactic: 'Lateral Movement',
    mitre_technique: test.mitre_technique,
    nist_controls: nistMap[test.category] || ['SC-7'],
  };
}
