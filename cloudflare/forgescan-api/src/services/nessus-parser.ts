/**
 * Nessus XML (.nessus) Parser
 *
 * Parses Nessus v2 XML scan reports into normalized assets and findings.
 * The .nessus format is XML with this structure:
 *   <NessusClientData_v2>
 *     <Report name="...">
 *       <ReportHost name="hostname_or_ip">
 *         <HostProperties>
 *           <tag name="host-ip">10.0.0.1</tag>
 *           <tag name="operating-system">Linux</tag>
 *           ...
 *         </HostProperties>
 *         <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="12345" pluginName="...">
 *           <description>...</description>
 *           <solution>...</solution>
 *           <risk_factor>Medium</risk_factor>
 *           <cvss3_base_score>6.5</cvss3_base_score>
 *           <cve>CVE-2023-1234</cve>
 *           <plugin_output>...</plugin_output>
 *           ...
 *         </ReportItem>
 *       </ReportHost>
 *     </Report>
 *   </NessusClientData_v2>
 *
 * Since Workers doesn't have a full DOM parser, we use regex-based extraction.
 */

export interface NessusHost {
  hostname: string | null;
  ip: string | null;
  fqdn: string | null;
  os: string | null;
  mac: string | null;
  findings: NessusFinding[];
}

export interface NessusFinding {
  pluginId: string;
  pluginName: string;
  port: number;
  protocol: string;
  service: string;
  severity: number; // 0=info, 1=low, 2=medium, 3=high, 4=critical
  description: string | null;
  solution: string | null;
  riskFactor: string | null;
  cvssScore: number | null;
  cvss3Score: number | null;
  cves: string[];
  output: string | null;
  synopsis: string | null;
  seeAlso: string | null;
  cwe: string | null;
}

export interface NessusParseResult {
  reportName: string | null;
  hosts: NessusHost[];
  totalFindings: number;
  errors: string[];
}

/**
 * Parse a .nessus XML string into structured host/finding data.
 */
export function parseNessusXML(xml: string): NessusParseResult {
  const errors: string[] = [];
  const hosts: NessusHost[] = [];
  let totalFindings = 0;

  // Extract report name
  const reportNameMatch = xml.match(/<Report\s+name="([^"]*)"/);
  const reportName = reportNameMatch ? reportNameMatch[1] : null;

  // Extract all ReportHost blocks
  const hostRegex = /<ReportHost\s+name="([^"]*)"[^>]*>([\s\S]*?)<\/ReportHost>/g;
  let hostMatch: RegExpExecArray | null;

  while ((hostMatch = hostRegex.exec(xml)) !== null) {
    try {
      const hostName = hostMatch[1];
      const hostContent = hostMatch[2];

      // Extract host properties
      const host: NessusHost = {
        hostname: hostName,
        ip: extractTag(hostContent, 'host-ip') || (isIPAddress(hostName) ? hostName : null),
        fqdn: extractTag(hostContent, 'host-fqdn') || (!isIPAddress(hostName) ? hostName : null),
        os: extractTag(hostContent, 'operating-system'),
        mac: extractTag(hostContent, 'mac-address'),
        findings: [],
      };

      // If the host name is an IP, don't use it as hostname
      if (isIPAddress(hostName)) {
        host.hostname = null;
      }

      // Extract all ReportItem blocks within this host
      const itemRegex = /<ReportItem\s+([^>]*)>([\s\S]*?)<\/ReportItem>/g;
      let itemMatch: RegExpExecArray | null;

      while ((itemMatch = itemRegex.exec(hostContent)) !== null) {
        try {
          const attrs = itemMatch[1];
          const itemContent = itemMatch[2];

          const finding: NessusFinding = {
            pluginId: extractAttr(attrs, 'pluginID') || '0',
            pluginName: extractAttr(attrs, 'pluginName') || 'Unknown Plugin',
            port: parseInt(extractAttr(attrs, 'port') || '0', 10),
            protocol: extractAttr(attrs, 'protocol') || 'tcp',
            service: extractAttr(attrs, 'svc_name') || '',
            severity: parseInt(extractAttr(attrs, 'severity') || '0', 10),
            description: extractElement(itemContent, 'description'),
            solution: extractElement(itemContent, 'solution'),
            riskFactor: extractElement(itemContent, 'risk_factor'),
            cvssScore: parseFloat(extractElement(itemContent, 'cvss_base_score') || '') || null,
            cvss3Score: parseFloat(extractElement(itemContent, 'cvss3_base_score') || '') || null,
            cves: extractAllElements(itemContent, 'cve'),
            output: extractElement(itemContent, 'plugin_output'),
            synopsis: extractElement(itemContent, 'synopsis'),
            seeAlso: extractElement(itemContent, 'see_also'),
            cwe: extractElement(itemContent, 'cwe'),
          };

          host.findings.push(finding);
          totalFindings++;
        } catch (err) {
          errors.push(`Error parsing ReportItem in host ${hostName}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      hosts.push(host);
    } catch (err) {
      errors.push(`Error parsing ReportHost: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return { reportName, hosts, totalFindings, errors };
}

/**
 * Map Nessus numeric severity (0-4) to ForgeScan severity string.
 */
export function mapNessusSeverity(severity: number): string {
  switch (severity) {
    case 4: return 'critical';
    case 3: return 'high';
    case 2: return 'medium';
    case 1: return 'low';
    default: return 'info';
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function extractTag(content: string, tagName: string): string | null {
  const regex = new RegExp(`<tag\\s+name="${tagName}"[^>]*>([^<]*)<\\/tag>`);
  const match = content.match(regex);
  return match ? decodeXMLEntities(match[1].trim()) : null;
}

function extractAttr(attrs: string, name: string): string | null {
  const regex = new RegExp(`${name}="([^"]*)"`);
  const match = attrs.match(regex);
  return match ? decodeXMLEntities(match[1]) : null;
}

function extractElement(content: string, elementName: string): string | null {
  const regex = new RegExp(`<${elementName}[^>]*>([\\s\\S]*?)<\\/${elementName}>`);
  const match = content.match(regex);
  return match ? decodeXMLEntities(match[1].trim()) : null;
}

function extractAllElements(content: string, elementName: string): string[] {
  const regex = new RegExp(`<${elementName}[^>]*>([^<]*)<\\/${elementName}>`, 'g');
  const results: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    results.push(decodeXMLEntities(match[1].trim()));
  }
  return results;
}

function decodeXMLEntities(str: string): string {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function isIPAddress(str: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(str) || str.includes(':'); // IPv4 or IPv6
}
