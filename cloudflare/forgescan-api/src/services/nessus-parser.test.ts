import { describe, it, expect } from 'vitest';
import { parseNessusXML, mapNessusSeverity } from './nessus-parser';

const MINIMAL_NESSUS = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="host-ip">10.0.0.1</tag>
        <tag name="operating-system">Linux 5.4</tag>
        <tag name="host-fqdn">web-01.example.com</tag>
      </HostProperties>
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="3" pluginID="12345" pluginName="SSH Weak Keys">
        <description>Weak SSH host keys detected</description>
        <solution>Regenerate SSH host keys</solution>
        <risk_factor>High</risk_factor>
        <cvss_base_score>7.5</cvss_base_score>
        <cvss3_base_score>8.1</cvss3_base_score>
        <cve>CVE-2023-1234</cve>
        <cve>CVE-2023-5678</cve>
        <plugin_output>Key type: RSA 1024-bit</plugin_output>
        <cwe>CWE-326</cwe>
        <synopsis>SSH host keys are weak</synopsis>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="99999" pluginName="OS Identification">
        <description>Remote OS detected</description>
        <risk_factor>None</risk_factor>
      </ReportItem>
    </ReportHost>
    <ReportHost name="web-02.example.com">
      <HostProperties>
        <tag name="host-ip">10.0.0.2</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="4" pluginID="54321" pluginName="Critical RCE">
        <description>Remote code execution via deserialization</description>
        <solution>Upgrade to latest version</solution>
        <risk_factor>Critical</risk_factor>
        <cvss3_base_score>9.8</cvss3_base_score>
        <cve>CVE-2024-0001</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

describe('Nessus XML Parser', () => {
  describe('parseNessusXML', () => {
    it('extracts report name', () => {
      const result = parseNessusXML(MINIMAL_NESSUS);
      expect(result.reportName).toBe('Test Scan');
    });

    it('extracts all hosts', () => {
      const result = parseNessusXML(MINIMAL_NESSUS);
      expect(result.hosts).toHaveLength(2);
    });

    it('extracts host properties from IP-named host', () => {
      const result = parseNessusXML(MINIMAL_NESSUS);
      const host = result.hosts[0];
      expect(host.ip).toBe('10.0.0.1');
      expect(host.os).toBe('Linux 5.4');
      expect(host.fqdn).toBe('web-01.example.com');
      // IP-named host should not have hostname set
      expect(host.hostname).toBeNull();
    });

    it('extracts host properties from FQDN-named host', () => {
      const result = parseNessusXML(MINIMAL_NESSUS);
      const host = result.hosts[1];
      expect(host.ip).toBe('10.0.0.2');
      expect(host.fqdn).toBe('web-02.example.com');
    });

    it('extracts findings with full details', () => {
      const result = parseNessusXML(MINIMAL_NESSUS);
      const finding = result.hosts[0].findings[0];
      expect(finding.pluginId).toBe('12345');
      expect(finding.pluginName).toBe('SSH Weak Keys');
      expect(finding.port).toBe(22);
      expect(finding.protocol).toBe('tcp');
      expect(finding.service).toBe('ssh');
      expect(finding.severity).toBe(3);
      expect(finding.description).toBe('Weak SSH host keys detected');
      expect(finding.solution).toBe('Regenerate SSH host keys');
      expect(finding.riskFactor).toBe('High');
      expect(finding.cvssScore).toBe(7.5);
      expect(finding.cvss3Score).toBe(8.1);
      expect(finding.cves).toEqual(['CVE-2023-1234', 'CVE-2023-5678']);
      expect(finding.output).toBe('Key type: RSA 1024-bit');
      expect(finding.cwe).toBe('CWE-326');
      expect(finding.synopsis).toBe('SSH host keys are weak');
    });

    it('extracts critical findings', () => {
      const result = parseNessusXML(MINIMAL_NESSUS);
      const critical = result.hosts[1].findings[0];
      expect(critical.severity).toBe(4);
      expect(critical.cvss3Score).toBe(9.8);
      expect(critical.cves).toEqual(['CVE-2024-0001']);
    });

    it('counts total findings across all hosts', () => {
      const result = parseNessusXML(MINIMAL_NESSUS);
      expect(result.totalFindings).toBe(3); // 2 from host1 + 1 from host2
    });

    it('returns empty results for non-Nessus XML', () => {
      const result = parseNessusXML('<html><body>Not nessus</body></html>');
      expect(result.hosts).toHaveLength(0);
      expect(result.totalFindings).toBe(0);
      expect(result.reportName).toBeNull();
    });

    it('returns empty results for empty string', () => {
      const result = parseNessusXML('');
      expect(result.hosts).toHaveLength(0);
    });

    it('handles XML entities in content', () => {
      const xml = `<NessusClientData_v2>
        <Report name="Scan &amp; Report">
          <ReportHost name="10.0.0.1">
            <HostProperties><tag name="host-ip">10.0.0.1</tag></HostProperties>
            <ReportItem port="80" svc_name="http" protocol="tcp" severity="2" pluginID="1" pluginName="Test &amp; Plugin">
              <description>Value with &lt;html&gt; tags</description>
            </ReportItem>
          </ReportHost>
        </Report>
      </NessusClientData_v2>`;
      const result = parseNessusXML(xml);
      expect(result.reportName).toBe('Scan & Report');
      expect(result.hosts[0].findings[0].pluginName).toBe('Test & Plugin');
      expect(result.hosts[0].findings[0].description).toBe('Value with <html> tags');
    });

    it('reports no errors on valid XML', () => {
      const result = parseNessusXML(MINIMAL_NESSUS);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('mapNessusSeverity', () => {
    it('maps 4 to critical', () => expect(mapNessusSeverity(4)).toBe('critical'));
    it('maps 3 to high', () => expect(mapNessusSeverity(3)).toBe('high'));
    it('maps 2 to medium', () => expect(mapNessusSeverity(2)).toBe('medium'));
    it('maps 1 to low', () => expect(mapNessusSeverity(1)).toBe('low'));
    it('maps 0 to info', () => expect(mapNessusSeverity(0)).toBe('info'));
    it('maps unknown to info', () => expect(mapNessusSeverity(99)).toBe('info'));
  });
});
