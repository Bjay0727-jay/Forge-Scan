import { Hono } from 'hono';
import type { Env } from '../index';
import { databaseError } from '../lib/errors';

export const demo = new Hono<{ Bindings: Env }>();

// ── Helper ───────────────────────────────────────────────────────────────────
function uuid() {
  return crypto.randomUUID();
}

function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

function hoursAgo(n: number): string {
  const d = new Date();
  d.setHours(d.getHours() - n);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

function now(): string {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

// ── POST /demo/seed ──────────────────────────────────────────────────────────
demo.post('/seed', async (c) => {
  const db = c.env.DB;

  try {
    // ── 0. Clear existing demo data so seed is idempotent ────────────────
    const clearTables = [
      'soar_action_log', 'soar_executions', 'soar_playbooks',
      'soc_incident_timeline', 'soc_alert_incidents', 'soc_incidents', 'soc_alerts',
      'threat_intel_matches', 'threat_intel_indicators', 'threat_intel_feeds',
      'sast_findings', 'sast_scan_results', 'sast_projects',
      'container_findings', 'container_scan_results', 'container_images',
      'redops_findings', 'redops_agents', 'redops_campaigns',
      'findings', 'scan_tasks', 'scans', 'assets',
      'organization_branding', 'organization_members', 'organizations',
    ];
    for (const table of clearTables) {
      try {
        await db.prepare(`DELETE FROM ${table}`).run();
      } catch {
        // Table may not exist yet — safe to skip
      }
    }

    // ── 1. Organization ────────────────────────────────────────────────────
    const orgId = uuid();
    await db.prepare(`
      INSERT INTO organizations (id, name, slug, tier, status, max_assets, max_users, max_scanners, contact_email, contact_name, industry, created_at, updated_at)
      VALUES (?, 'Acme Corp', 'acme-corp', 'enterprise', 'active', 5000, 100, 20, 'security@acme.example', 'Jane Chen', 'Technology', ?, ?)
    `).bind(orgId, now(), now()).run();

    await db.prepare(`
      INSERT INTO organization_branding (id, organization_id, company_name, primary_color, accent_color, sidebar_bg, login_title, login_subtitle, powered_by_visible, created_at, updated_at)
      VALUES (?, ?, 'Acme Corporation', '#14b8a6', '#0d9488', '#0b1929', 'Acme Security Portal', 'Unified threat management', 1, ?, ?)
    `).bind(uuid(), orgId, now(), now()).run();

    // ── 2. Assets ──────────────────────────────────────────────────────────
    const assetDefs = [
      { hostname: 'web-prod-01', fqdn: 'web-prod-01.acme.internal', ips: ['10.0.1.10'], os: 'Ubuntu', osVer: '22.04 LTS', type: 'server', zone: 'dmz', risk: 82 },
      { hostname: 'db-primary', fqdn: 'db-primary.acme.internal', ips: ['10.0.2.5'], os: 'Amazon Linux', osVer: '2023', type: 'database', zone: 'internal', risk: 91 },
      { hostname: 'api-gateway', fqdn: 'api-gateway.acme.internal', ips: ['10.0.1.20'], os: 'Alpine Linux', osVer: '3.18', type: 'server', zone: 'dmz', risk: 67 },
      { hostname: 'ci-runner-01', fqdn: 'ci-runner-01.acme.internal', ips: ['10.0.3.15'], os: 'Ubuntu', osVer: '24.04 LTS', type: 'server', zone: 'build', risk: 45 },
      { hostname: 'k8s-node-01', fqdn: 'k8s-node-01.acme.internal', ips: ['10.0.4.10'], os: 'Flatcar', osVer: '3815', type: 'container_host', zone: 'production', risk: 73 },
      { hostname: 'mail-relay', fqdn: 'mail-relay.acme.internal', ips: ['10.0.1.30'], os: 'RHEL', osVer: '9.3', type: 'server', zone: 'dmz', risk: 58 },
      { hostname: 'dev-laptop-jchen', fqdn: 'dev-laptop-jchen.acme.internal', ips: ['10.10.5.42'], os: 'macOS', osVer: '14.4', type: 'workstation', zone: 'corporate', risk: 34 },
      { hostname: 'storage-nas', fqdn: 'storage-nas.acme.internal', ips: ['10.0.2.50'], os: 'TrueNAS', osVer: '13.0-U6', type: 'storage', zone: 'internal', risk: 61 },
    ];

    const assetIds: string[] = [];
    for (const a of assetDefs) {
      const id = uuid();
      assetIds.push(id);
      await db.prepare(`
        INSERT INTO assets (id, hostname, fqdn, ip_addresses, mac_addresses, os, os_version, asset_type, network_zone, tags, attributes, risk_score, first_seen, last_seen, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, '[]', ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?, ?, ?)
      `).bind(
        id, a.hostname, a.fqdn, JSON.stringify(a.ips), a.os, a.osVer, a.type, a.zone,
        JSON.stringify([a.zone, a.type]), a.risk, daysAgo(60), daysAgo(0), daysAgo(60), now(), orgId,
      ).run();
    }

    // ── 3. Vulnerabilities ─────────────────────────────────────────────────
    const vulnDefs = [
      { cve: 'CVE-2024-21762', desc: 'FortiOS out-of-bounds write in SSL VPN', cvss: 9.8, severity: 'critical', kev: 1 },
      { cve: 'CVE-2024-3400', desc: 'PAN-OS GlobalProtect command injection', cvss: 10.0, severity: 'critical', kev: 1 },
      { cve: 'CVE-2024-1709', desc: 'ConnectWise ScreenConnect auth bypass', cvss: 10.0, severity: 'critical', kev: 1 },
      { cve: 'CVE-2023-44228', desc: 'Apache Log4j2 JNDI injection (Log4Shell)', cvss: 10.0, severity: 'critical', kev: 1 },
      { cve: 'CVE-2024-6387', desc: 'OpenSSH regreSSHion race condition RCE', cvss: 8.1, severity: 'high', kev: 1 },
      { cve: 'CVE-2024-4577', desc: 'PHP-CGI argument injection on Windows', cvss: 9.8, severity: 'critical', kev: 1 },
      { cve: 'CVE-2023-46805', desc: 'Ivanti Connect Secure auth bypass', cvss: 8.2, severity: 'high', kev: 1 },
      { cve: 'CVE-2024-27198', desc: 'JetBrains TeamCity auth bypass', cvss: 9.8, severity: 'critical', kev: 1 },
      { cve: 'CVE-2023-34362', desc: 'MOVEit Transfer SQL injection', cvss: 9.8, severity: 'critical', kev: 1 },
      { cve: 'CVE-2024-0012', desc: 'PAN-OS management interface auth bypass', cvss: 9.3, severity: 'critical', kev: 0 },
      { cve: 'CVE-2023-20198', desc: 'Cisco IOS XE web UI privilege escalation', cvss: 10.0, severity: 'critical', kev: 1 },
      { cve: 'CVE-2024-23897', desc: 'Jenkins arbitrary file read via CLI', cvss: 7.5, severity: 'high', kev: 0 },
      { cve: 'CVE-2024-38063', desc: 'Windows TCP/IP IPv6 RCE', cvss: 9.8, severity: 'critical', kev: 0 },
      { cve: 'CVE-2023-4966', desc: 'Citrix Bleed NetScaler session hijacking', cvss: 7.5, severity: 'high', kev: 1 },
      { cve: 'CVE-2024-5806', desc: 'MOVEit Transfer auth bypass', cvss: 7.4, severity: 'high', kev: 0 },
      { cve: 'CVE-2024-21887', desc: 'Ivanti Connect Secure command injection', cvss: 9.1, severity: 'critical', kev: 1 },
      { cve: 'CVE-2023-22515', desc: 'Atlassian Confluence broken access control', cvss: 9.8, severity: 'critical', kev: 1 },
      { cve: 'CVE-2024-29824', desc: 'Ivanti EPM SQL injection', cvss: 8.8, severity: 'high', kev: 0 },
      { cve: 'CVE-2023-36884', desc: 'Microsoft Office HTML RCE via Storm-0978', cvss: 8.3, severity: 'high', kev: 1 },
      { cve: 'CVE-2024-40711', desc: 'Veeam Backup deserialization RCE', cvss: 9.8, severity: 'critical', kev: 0 },
      { cve: 'CVE-2024-12356', desc: 'BeyondTrust RS command injection', cvss: 6.6, severity: 'medium', kev: 0 },
      { cve: 'CVE-2023-50164', desc: 'Apache Struts path traversal', cvss: 5.3, severity: 'medium', kev: 0 },
      { cve: 'CVE-2024-20353', desc: 'Cisco ASA webvpn DoS', cvss: 4.3, severity: 'medium', kev: 0 },
      { cve: 'CVE-2024-1086', desc: 'Linux kernel nf_tables UAF privilege escalation', cvss: 7.8, severity: 'high', kev: 0 },
      { cve: 'CVE-2024-3094', desc: 'XZ Utils backdoor (liblzma)', cvss: 10.0, severity: 'critical', kev: 1 },
    ];

    const vulnIds: string[] = [];
    for (const v of vulnDefs) {
      const id = uuid();
      vulnIds.push(id);
      await db.prepare(`
        INSERT OR IGNORE INTO vulnerabilities (id, cve_id, description, cvss_score, cvss_vector, cvss_version, epss_score, epss_percentile, in_kev, severity, cwe_ids, affected_products, references_list, published_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', '3.1', ?, ?, ?, ?, '[]', '[]', '[]', ?, ?, ?)
      `).bind(
        id, v.cve, v.desc, v.cvss,
        Math.min(0.97, v.cvss / 12), Math.min(0.99, v.cvss / 11),
        v.kev, v.severity, daysAgo(120), daysAgo(120), now(),
      ).run();
    }

    // ── 4. Scans ───────────────────────────────────────────────────────────
    const scanDefs = [
      { name: 'Weekly Network Scan', type: 'network', status: 'completed', target: '10.0.0.0/16', daysAgoStart: 2, findings: 18 },
      { name: 'Container Image Audit', type: 'container', status: 'completed', target: 'registry.acme.internal', daysAgoStart: 5, findings: 12 },
      { name: 'Web App Pen Test', type: 'web', status: 'completed', target: 'https://app.acme.example', daysAgoStart: 8, findings: 7 },
      { name: 'Code Security Scan', type: 'code', status: 'completed', target: 'github.com/acme/core-api', daysAgoStart: 3, findings: 22 },
      { name: 'Cloud Config Audit', type: 'cloud', status: 'completed', target: 'aws:acme-prod', daysAgoStart: 1, findings: 15 },
      { name: 'Full Compliance Check', type: 'compliance', status: 'completed', target: '10.0.0.0/16', daysAgoStart: 7, findings: 9 },
      { name: 'Nightly Vuln Scan', type: 'network', status: 'running', target: '10.0.0.0/8', daysAgoStart: 0, findings: 0 },
    ];

    const scanIds: string[] = [];
    for (const s of scanDefs) {
      const id = uuid();
      scanIds.push(id);
      const startedAt = daysAgo(s.daysAgoStart);
      const completedAt = s.status === 'completed' ? hoursAgo(s.daysAgoStart * 24 - 2) : null;
      await db.prepare(`
        INSERT INTO scans (id, name, scan_type, targets, config, status, findings_count, started_at, completed_at, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, '{}', ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, s.name, s.type, JSON.stringify([s.target]), s.status, s.findings,
        startedAt, completedAt, startedAt, now(), orgId,
      ).run();
    }

    // ── 5. Findings ────────────────────────────────────────────────────────
    const severities = ['critical', 'high', 'medium', 'low'] as const;
    const states = ['open', 'open', 'open', 'acknowledged', 'fixed'] as const;
    const findingIds: string[] = [];

    for (let i = 0; i < vulnDefs.length; i++) {
      const id = uuid();
      findingIds.push(id);
      const assetIdx = i % assetIds.length;
      const scanIdx = i % (scanIds.length - 1); // skip the running scan
      await db.prepare(`
        INSERT INTO findings (id, asset_id, scan_id, vulnerability_id, title, description, severity, state, risk_score, last_seen, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, assetIds[assetIdx], scanIds[scanIdx], vulnIds[i],
        vulnDefs[i].cve + ': ' + vulnDefs[i].desc, vulnDefs[i].desc,
        vulnDefs[i].severity, states[i % states.length],
        vulnDefs[i].cvss * 10, daysAgo(i % 14), daysAgo(30 + i), now(), orgId,
      ).run();
    }

    // ── 6. Container images & scan results ─────────────────────────────────
    const containerImages = [
      { registry: 'docker.io', repo: 'acme/core-api', tag: 'v2.8.1', os: 'linux', arch: 'amd64', layers: 14, base: 'node:20-alpine' },
      { registry: 'docker.io', repo: 'acme/web-frontend', tag: 'v3.1.0', os: 'linux', arch: 'amd64', layers: 11, base: 'nginx:1.25-alpine' },
      { registry: 'ghcr.io', repo: 'acme/auth-service', tag: 'v1.4.2', os: 'linux', arch: 'amd64', layers: 12, base: 'golang:1.22-alpine' },
      { registry: 'docker.io', repo: 'acme/worker', tag: 'v1.0.9', os: 'linux', arch: 'arm64', layers: 9, base: 'python:3.12-slim' },
    ];

    const imageIds: string[] = [];
    for (const img of containerImages) {
      const id = uuid();
      imageIds.push(id);
      await db.prepare(`
        INSERT INTO container_images (id, org_id, registry, repository, tag, digest, os, architecture, size_bytes, layer_count, base_image, labels, first_seen, last_scanned, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?)
      `).bind(
        id, orgId, img.registry, img.repo, img.tag,
        'sha256:' + crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '').slice(0, 32),
        img.os, img.arch, 85_000_000 + Math.floor(Math.random() * 200_000_000),
        img.layers, img.base, daysAgo(30), daysAgo(2), daysAgo(30), now(),
      ).run();
    }

    const containerScanIds: string[] = [];
    for (let i = 0; i < imageIds.length; i++) {
      const id = uuid();
      containerScanIds.push(id);
      await db.prepare(`
        INSERT INTO container_scan_results (id, image_id, scan_id, org_id, scanner, status, os_vulns, app_vulns, config_issues, secrets_found, critical_count, high_count, medium_count, low_count, compliance_pass, compliance_fail, started_at, completed_at, created_at)
        VALUES (?, ?, ?, ?, 'forge', 'completed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, imageIds[i], scanIds[1], orgId,
        3 + i, 5 + i, 2 + i, i % 2,
        i, 2 + i, 4 + i, 1 + i,
        18 - i * 2, i + 1,
        daysAgo(2), hoursAgo(47), daysAgo(2),
      ).run();
    }

    // Container findings
    const containerFindingTypes = ['os_vuln', 'app_vuln', 'config_issue', 'secret'];
    for (let i = 0; i < imageIds.length; i++) {
      for (let j = 0; j < 3; j++) {
        await db.prepare(`
          INSERT INTO container_findings (id, scan_result_id, image_id, org_id, finding_type, package_name, installed_version, fixed_version, cve_id, severity, cvss_score, title, description, layer_index, file_path, remediation, state, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
        `).bind(
          uuid(), containerScanIds[i], imageIds[i], orgId,
          containerFindingTypes[(i + j) % containerFindingTypes.length],
          ['openssl', 'curl', 'libc', 'zlib'][j % 4],
          '1.' + j + '.0',
          '1.' + (j + 1) + '.0',
          vulnDefs[(i * 3 + j) % vulnDefs.length].cve,
          severities[(i + j) % severities.length],
          vulnDefs[(i * 3 + j) % vulnDefs.length].cvss,
          'Vulnerable ' + ['openssl', 'curl', 'libc', 'zlib'][j % 4] + ' in ' + containerImages[i].repo,
          'Outdated package with known vulnerabilities',
          j, '/usr/lib/' + ['openssl', 'curl', 'libc', 'zlib'][j % 4],
          'Upgrade to fixed version',
          daysAgo(2),
        ).run();
      }
    }

    // ── 7. SAST projects & scan results ────────────────────────────────────
    const sastProjects = [
      { name: 'core-api', url: 'https://github.com/acme/core-api', branch: 'main', lang: 'TypeScript', loc: 48000, files: 320 },
      { name: 'auth-service', url: 'https://github.com/acme/auth-service', branch: 'main', lang: 'Go', loc: 12000, files: 85 },
      { name: 'web-frontend', url: 'https://github.com/acme/web-frontend', branch: 'develop', lang: 'TypeScript', loc: 62000, files: 410 },
      { name: 'data-pipeline', url: 'https://github.com/acme/data-pipeline', branch: 'main', lang: 'Python', loc: 18500, files: 120 },
    ];

    const projectIds: string[] = [];
    for (const p of sastProjects) {
      const id = uuid();
      projectIds.push(id);
      await db.prepare(`
        INSERT INTO sast_projects (id, org_id, name, repository_url, branch, language, languages, framework, loc, file_count, last_scanned, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, orgId, p.name, p.url, p.branch, p.lang,
        JSON.stringify([p.lang, 'JSON', 'YAML']),
        p.lang === 'TypeScript' ? 'React' : p.lang === 'Go' ? 'Gin' : p.lang === 'Python' ? 'FastAPI' : 'Express',
        p.loc, p.files, daysAgo(3), daysAgo(45), now(),
      ).run();
    }

    const sastScanIds: string[] = [];
    for (let i = 0; i < projectIds.length; i++) {
      const id = uuid();
      sastScanIds.push(id);
      await db.prepare(`
        INSERT INTO sast_scan_results (id, project_id, scan_id, org_id, status, commit_sha, branch, files_analyzed, issues_found, critical_count, high_count, medium_count, low_count, info_count, scan_duration_ms, rules_applied, started_at, completed_at, created_at)
        VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, projectIds[i], scanIds[3], orgId,
        'a1b2c3d' + i, sastProjects[i].branch,
        sastProjects[i].files, 5 + i * 2,
        i, 2 + i, 3 + i, i, i + 1,
        12000 + i * 3000, 180 + i * 20,
        daysAgo(3), hoursAgo(71), daysAgo(3),
      ).run();
    }

    // SAST findings
    const sastRules = [
      { rule: 'sql-injection', cat: 'injection', cwe: 'CWE-89', owasp: 'A03:2021', sev: 'critical' },
      { rule: 'xss-reflected', cat: 'injection', cwe: 'CWE-79', owasp: 'A03:2021', sev: 'high' },
      { rule: 'path-traversal', cat: 'injection', cwe: 'CWE-22', owasp: 'A01:2021', sev: 'high' },
      { rule: 'hardcoded-secret', cat: 'security', cwe: 'CWE-798', owasp: 'A07:2021', sev: 'critical' },
      { rule: 'insecure-random', cat: 'cryptography', cwe: 'CWE-330', owasp: 'A02:2021', sev: 'medium' },
      { rule: 'open-redirect', cat: 'injection', cwe: 'CWE-601', owasp: 'A01:2021', sev: 'medium' },
      { rule: 'missing-auth-check', cat: 'access-control', cwe: 'CWE-862', owasp: 'A01:2021', sev: 'high' },
      { rule: 'unsafe-deserialization', cat: 'injection', cwe: 'CWE-502', owasp: 'A08:2021', sev: 'critical' },
    ];

    for (let i = 0; i < projectIds.length; i++) {
      for (let j = 0; j < 3; j++) {
        const rule = sastRules[(i * 3 + j) % sastRules.length];
        await db.prepare(`
          INSERT INTO sast_findings (id, scan_result_id, project_id, org_id, rule_id, rule_name, category, severity, confidence, file_path, start_line, end_line, code_snippet, message, cwe_id, owasp_category, remediation, state, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'high', ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
        `).bind(
          uuid(), sastScanIds[i], projectIds[i], orgId,
          rule.rule, rule.rule.replace(/-/g, ' '), rule.cat, rule.sev,
          'src/' + ['controllers', 'services', 'utils', 'middleware'][j % 4] + '/' + ['auth', 'users', 'data', 'api'][i % 4] + '.ts',
          42 + j * 15, 48 + j * 15,
          '// vulnerable code snippet placeholder',
          'Potential ' + rule.rule.replace(/-/g, ' ') + ' detected',
          rule.cwe, rule.owasp,
          'Review and fix the identified ' + rule.rule.replace(/-/g, ' ') + ' vulnerability',
          daysAgo(3),
        ).run();
      }
    }

    // ── 8. Threat Intel ────────────────────────────────────────────────────
    const feedId = uuid();
    await db.prepare(`
      INSERT INTO threat_intel_feeds (id, org_id, name, feed_type, source_url, format, poll_interval_minutes, enabled, last_fetch_at, last_fetch_status, indicators_count, created_at, updated_at)
      VALUES (?, ?, 'CISA KEV Feed', 'kev', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'json', 60, 1, ?, 'success', 12, ?, ?)
    `).bind(feedId, orgId, daysAgo(0), daysAgo(30), now()).run();

    const feed2Id = uuid();
    await db.prepare(`
      INSERT INTO threat_intel_feeds (id, org_id, name, feed_type, source_url, format, poll_interval_minutes, enabled, last_fetch_at, last_fetch_status, indicators_count, created_at, updated_at)
      VALUES (?, ?, 'AlienVault OTX', 'otx', 'https://otx.alienvault.com/api/v1/pulses/subscribed', 'stix', 120, 1, ?, 'success', 8, ?, ?)
    `).bind(feed2Id, orgId, daysAgo(1), daysAgo(25), now()).run();

    const indicatorDefs = [
      { type: 'ip', value: '185.220.101.42', sev: 'high', conf: 90, tlp: 'amber', tag: 'c2-server' },
      { type: 'ip', value: '45.155.205.233', sev: 'critical', conf: 95, tlp: 'red', tag: 'ransomware' },
      { type: 'domain', value: 'evil-payload.example.com', sev: 'high', conf: 85, tlp: 'amber', tag: 'phishing' },
      { type: 'domain', value: 'c2-beacon.example.net', sev: 'critical', conf: 92, tlp: 'red', tag: 'c2-server' },
      { type: 'hash_sha256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', sev: 'high', conf: 80, tlp: 'amber', tag: 'malware' },
      { type: 'url', value: 'https://evil-payload.example.com/stage2.ps1', sev: 'critical', conf: 88, tlp: 'red', tag: 'malware-delivery' },
      { type: 'email', value: 'attacker@phish.example.com', sev: 'medium', conf: 70, tlp: 'green', tag: 'phishing' },
      { type: 'ip', value: '91.92.109.18', sev: 'high', conf: 85, tlp: 'amber', tag: 'scanner' },
    ];

    const indicatorIds: string[] = [];
    for (let i = 0; i < indicatorDefs.length; i++) {
      const id = uuid();
      indicatorIds.push(id);
      const ind = indicatorDefs[i];
      await db.prepare(`
        INSERT INTO threat_intel_indicators (id, feed_id, org_id, indicator_type, indicator_value, severity, confidence, tlp, tags, context, first_seen, last_seen, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
      `).bind(
        id, i < 4 ? feedId : feed2Id, orgId,
        ind.type, ind.value, ind.sev, ind.conf, ind.tlp,
        JSON.stringify([ind.tag]), JSON.stringify({ source: i < 4 ? 'CISA' : 'OTX' }),
        daysAgo(15 + i), daysAgo(i), daysAgo(15 + i),
      ).run();
    }

    // Threat intel matches
    for (let i = 0; i < 4; i++) {
      await db.prepare(`
        INSERT INTO threat_intel_matches (id, indicator_id, org_id, match_type, matched_entity_type, matched_entity_id, match_confidence, acknowledged, matched_at)
        VALUES (?, ?, ?, 'exact', 'asset', ?, ?, 0, ?)
      `).bind(
        uuid(), indicatorIds[i], orgId, assetIds[i % assetIds.length], 85 + i * 3, daysAgo(i),
      ).run();
    }

    // ── 9. SOC Alerts & Incidents ──────────────────────────────────────────
    const alertDefs = [
      { title: 'Critical RCE exploit attempt on web-prod-01', sev: 'critical', status: 'investigating', type: 'exploit', tactic: 'Initial Access', technique: 'T1190' },
      { title: 'Suspicious outbound C2 traffic from db-primary', sev: 'critical', status: 'new', type: 'network_anomaly', tactic: 'Command and Control', technique: 'T1071' },
      { title: 'Brute force login attempts detected', sev: 'high', status: 'investigating', type: 'authentication', tactic: 'Credential Access', technique: 'T1110' },
      { title: 'Privilege escalation on k8s-node-01', sev: 'high', status: 'new', type: 'privilege_escalation', tactic: 'Privilege Escalation', technique: 'T1068' },
      { title: 'Malware hash detected in container image', sev: 'high', status: 'acknowledged', type: 'malware', tactic: 'Execution', technique: 'T1204' },
      { title: 'Data exfiltration attempt via DNS tunneling', sev: 'critical', status: 'investigating', type: 'data_exfiltration', tactic: 'Exfiltration', technique: 'T1048' },
      { title: 'Unauthorized API key usage from unknown IP', sev: 'medium', status: 'new', type: 'authentication', tactic: 'Initial Access', technique: 'T1078' },
      { title: 'SSL certificate nearing expiration on mail-relay', sev: 'low', status: 'acknowledged', type: 'configuration', tactic: 'Reconnaissance', technique: 'T1596' },
      { title: 'Port scan detected from external IP range', sev: 'medium', status: 'closed', type: 'reconnaissance', tactic: 'Reconnaissance', technique: 'T1046' },
      { title: 'Insecure deserialization on api-gateway', sev: 'high', status: 'new', type: 'vulnerability', tactic: 'Execution', technique: 'T1203' },
    ];

    const alertIds: string[] = [];
    for (let i = 0; i < alertDefs.length; i++) {
      const id = uuid();
      alertIds.push(id);
      const a = alertDefs[i];
      await db.prepare(`
        INSERT INTO soc_alerts (id, title, description, severity, status, source, alert_type, tags, mitre_tactic, mitre_technique, affected_assets, confidence_score, confidence_level, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, ?, 'system', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, a.title, 'Automated detection: ' + a.title, a.sev, a.status,
        a.type, JSON.stringify([a.type, a.tactic.toLowerCase().replace(/ /g, '-')]),
        a.tactic, a.technique,
        JSON.stringify([assetIds[i % assetIds.length]]),
        70 + i * 3, i < 4 ? 'high' : 'medium',
        hoursAgo(i * 6), now(), orgId,
      ).run();
    }

    // Incidents
    const incidentDefs = [
      { title: 'Active RCE Campaign Targeting Web Infrastructure', sev: 'critical', status: 'investigating', type: 'security', priority: 1 },
      { title: 'Suspected Data Exfiltration via DNS', sev: 'critical', status: 'open', type: 'security', priority: 1 },
      { title: 'Brute Force Attack on Authentication System', sev: 'high', status: 'contained', type: 'security', priority: 2 },
    ];

    const incidentIds: string[] = [];
    for (let i = 0; i < incidentDefs.length; i++) {
      const id = uuid();
      incidentIds.push(id);
      const inc = incidentDefs[i];
      await db.prepare(`
        INSERT INTO soc_incidents (id, title, description, severity, status, priority, incident_type, alert_count, affected_asset_count, tags, mitre_tactics, mitre_techniques, started_at, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, inc.title, 'Incident investigation: ' + inc.title, inc.sev, inc.status, inc.priority,
        inc.type, 3 - i, 2 + i,
        JSON.stringify(['active-investigation']),
        JSON.stringify(['Initial Access', 'Execution']),
        JSON.stringify(['T1190', 'T1203']),
        hoursAgo(12 + i * 8), hoursAgo(12 + i * 8), now(), orgId,
      ).run();
    }

    // Link alerts to incidents
    for (let i = 0; i < Math.min(alertIds.length, 6); i++) {
      const incIdx = i < 2 ? 0 : i < 4 ? 1 : 2;
      await db.prepare(`
        INSERT INTO soc_alert_incidents (alert_id, incident_id, added_at) VALUES (?, ?, ?)
      `).bind(alertIds[i], incidentIds[incIdx], now()).run();
    }

    // Incident timeline
    for (let i = 0; i < incidentIds.length; i++) {
      const actions = ['Alert triaged', 'Investigation started', 'Evidence collected', 'Containment initiated'];
      for (let j = 0; j < actions.length; j++) {
        await db.prepare(`
          INSERT INTO soc_incident_timeline (id, incident_id, action, description, metadata, created_at)
          VALUES (?, ?, ?, ?, '{}', ?)
        `).bind(uuid(), incidentIds[i], actions[j], actions[j] + ' by SOC analyst', hoursAgo(10 - j * 2 + i * 8)).run();
      }
    }

    // ── 10. SOAR Playbooks & Executions ────────────────────────────────────
    const playbookDefs = [
      { name: 'Auto-Block Malicious IP', trigger: 'alert_created', sev: 'critical', steps: ['lookup_threat_intel', 'block_ip_firewall', 'create_incident', 'notify_soc'] },
      { name: 'Ransomware Response', trigger: 'alert_created', sev: 'critical', steps: ['isolate_host', 'snapshot_memory', 'block_lateral', 'notify_ir_team', 'create_incident'] },
      { name: 'Phishing Triage', trigger: 'alert_created', sev: 'high', steps: ['extract_indicators', 'check_threat_intel', 'quarantine_email', 'notify_user', 'update_blocklist'] },
      { name: 'Vulnerability Remediation', trigger: 'finding_critical', sev: 'critical', steps: ['create_ticket', 'assign_owner', 'verify_patch', 'rescan'] },
    ];

    const playbookIds: string[] = [];
    for (const pb of playbookDefs) {
      const id = uuid();
      playbookIds.push(id);
      await db.prepare(`
        INSERT INTO soar_playbooks (id, org_id, name, description, trigger_type, trigger_config, steps, enabled, severity_filter, max_concurrent, cooldown_seconds, trigger_count, success_count, failure_count, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 5, 300, ?, ?, ?, ?, ?)
      `).bind(
        id, orgId, pb.name, 'Automated playbook: ' + pb.name,
        pb.trigger, JSON.stringify({ severity: pb.sev }),
        JSON.stringify(pb.steps.map((s, i) => ({ index: i, action: s, config: {} }))),
        pb.sev, 12 + playbookIds.length * 3, 10 + playbookIds.length * 2, playbookIds.length,
        daysAgo(40), now(),
      ).run();
    }

    // Executions
    for (let i = 0; i < 3; i++) {
      const execId = uuid();
      await db.prepare(`
        INSERT INTO soar_executions (id, playbook_id, org_id, trigger_alert_id, status, current_step, total_steps, step_results, context, started_at, completed_at, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?)
      `).bind(
        execId, playbookIds[i % playbookIds.length], orgId,
        alertIds[i], i === 0 ? 'completed' : i === 1 ? 'running' : 'completed',
        i === 1 ? 2 : playbookDefs[i % playbookDefs.length].steps.length,
        playbookDefs[i % playbookDefs.length].steps.length,
        JSON.stringify([{ step: 0, status: 'completed', result: 'ok' }]),
        hoursAgo(6 + i * 4), i === 1 ? null : hoursAgo(5 + i * 4),
        i === 1 ? null : 45000 + i * 12000,
      ).run();

      // Action log
      for (let j = 0; j < Math.min(3, playbookDefs[i % playbookDefs.length].steps.length); j++) {
        await db.prepare(`
          INSERT INTO soar_action_log (id, execution_id, step_index, action_type, action_config, status, result, started_at, completed_at, duration_ms)
          VALUES (?, ?, ?, ?, '{}', 'completed', '{"success":true}', ?, ?, ?)
        `).bind(
          uuid(), execId, j, playbookDefs[i % playbookDefs.length].steps[j],
          hoursAgo(6 + i * 4), hoursAgo(6 + i * 4 - 0.1), 3000 + j * 1500,
        ).run();
      }
    }

    // ── 11. RedOps Campaigns ───────────────────────────────────────────────
    const campaignId = uuid();
    await db.prepare(`
      INSERT INTO redops_campaigns (id, name, description, status, campaign_type, target_scope, exclusions, agent_categories, max_concurrent_agents, exploitation_level, total_agents, active_agents, completed_agents, failed_agents, findings_count, critical_count, high_count, medium_count, low_count, info_count, exploitable_count, started_at, completed_at, duration_seconds, created_at, updated_at, org_id)
      VALUES (?, 'Q4 Penetration Test', 'Quarterly red team exercise targeting production infrastructure', 'completed', 'full', '10.0.0.0/16', '10.0.99.0/24', '["web","api","network","identity","cloud"]', 6, 'safe', 8, 0, 7, 1, 14, 3, 5, 4, 2, 0, 6, ?, ?, 14400, ?, ?, ?)
    `).bind(
      campaignId, daysAgo(14), daysAgo(14), daysAgo(14), now(), orgId,
    ).run();

    const campaign2Id = uuid();
    await db.prepare(`
      INSERT INTO redops_campaigns (id, name, description, status, campaign_type, target_scope, exclusions, agent_categories, max_concurrent_agents, exploitation_level, total_agents, active_agents, completed_agents, failed_agents, findings_count, critical_count, high_count, medium_count, low_count, info_count, exploitable_count, started_at, created_at, updated_at, org_id)
      VALUES (?, 'Web App Assessment', 'Focused assessment of customer-facing web applications', 'running', 'targeted', 'https://app.acme.example', NULL, '["web","api"]', 4, 'safe', 4, 2, 1, 1, 5, 1, 2, 2, 0, 0, 3, ?, ?, ?, ?)
    `).bind(
      campaign2Id, hoursAgo(3), hoursAgo(3), now(), orgId,
    ).run();

    // RedOps agents
    const agentTypes = [
      { type: 'web_scanner', cat: 'web' },
      { type: 'api_fuzzer', cat: 'api' },
      { type: 'net_segmentation', cat: 'network' },
      { type: 'identity_audit', cat: 'identity' },
      { type: 'cloud_config', cat: 'cloud' },
    ];

    const redopsAgentIds: string[] = [];
    for (let i = 0; i < agentTypes.length; i++) {
      const id = uuid();
      redopsAgentIds.push(id);
      const at = agentTypes[i];
      await db.prepare(`
        INSERT INTO redops_agents (id, campaign_id, agent_type, agent_category, status, target, tests_planned, tests_completed, tests_passed, tests_failed, findings_count, exploitable_count, started_at, completed_at, duration_seconds, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, '10.0.0.0/16', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, campaignId, at.type, at.cat,
        i < 4 ? 'completed' : 'failed',
        20 + i * 5, i < 4 ? 20 + i * 5 : 10 + i,
        18 + i * 4, i < 4 ? 2 + i : 10,
        3 + i, i < 3 ? 2 : 0,
        daysAgo(14), daysAgo(14), 3600 + i * 600,
        daysAgo(14), now(),
      ).run();
    }

    // RedOps findings
    const redopsFindingDefs = [
      { title: 'SQL Injection in /api/v1/search', sev: 'critical', vector: 'network', cat: 'web', cwe: 'CWE-89', exploitable: 1, tactic: 'Initial Access', technique: 'T1190' },
      { title: 'Broken authentication on admin panel', sev: 'critical', vector: 'network', cat: 'identity', cwe: 'CWE-287', exploitable: 1, tactic: 'Initial Access', technique: 'T1078' },
      { title: 'IDOR in user profile endpoint', sev: 'high', vector: 'network', cat: 'api', cwe: 'CWE-639', exploitable: 1, tactic: 'Collection', technique: 'T1530' },
      { title: 'Missing rate limiting on login', sev: 'high', vector: 'network', cat: 'web', cwe: 'CWE-307', exploitable: 0, tactic: 'Credential Access', technique: 'T1110' },
      { title: 'Unrestricted file upload', sev: 'high', vector: 'network', cat: 'web', cwe: 'CWE-434', exploitable: 1, tactic: 'Execution', technique: 'T1204' },
      { title: 'Exposed management port 9090', sev: 'medium', vector: 'network', cat: 'network', cwe: 'CWE-200', exploitable: 0, tactic: 'Reconnaissance', technique: 'T1046' },
      { title: 'Weak TLS cipher suites accepted', sev: 'medium', vector: 'network', cat: 'network', cwe: 'CWE-326', exploitable: 0, tactic: 'Collection', technique: 'T1557' },
      { title: 'S3 bucket allows public listing', sev: 'critical', vector: 'network', cat: 'cloud', cwe: 'CWE-732', exploitable: 1, tactic: 'Collection', technique: 'T1530' },
    ];

    for (let i = 0; i < redopsFindingDefs.length; i++) {
      const rf = redopsFindingDefs[i];
      await db.prepare(`
        INSERT INTO redops_findings (id, campaign_id, agent_id, asset_id, title, description, severity, attack_vector, attack_category, cwe_id, cvss_score, exploitable, mitre_tactic, mitre_technique, remediation, remediation_effort, status, discovered_at, created_at, updated_at, org_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)
      `).bind(
        uuid(), campaignId, redopsAgentIds[i % redopsAgentIds.length],
        assetIds[i % assetIds.length],
        rf.title, 'Red team finding: ' + rf.title,
        rf.sev, rf.vector, rf.cat, rf.cwe,
        rf.sev === 'critical' ? 9.5 : rf.sev === 'high' ? 7.8 : 5.5,
        rf.exploitable, rf.tactic, rf.technique,
        'Remediate ' + rf.title.toLowerCase(),
        rf.sev === 'critical' ? 'high' : rf.sev === 'high' ? 'medium' : 'low',
        daysAgo(14), daysAgo(14), now(), orgId,
      ).run();
    }

    // ── Summary ────────────────────────────────────────────────────────────
    return c.json({
      message: 'Demo environment seeded successfully',
      counts: {
        organizations: 1,
        assets: assetIds.length,
        vulnerabilities: vulnIds.length,
        scans: scanIds.length,
        findings: findingIds.length,
        container_images: imageIds.length,
        container_scan_results: containerScanIds.length,
        container_findings: imageIds.length * 3,
        sast_projects: projectIds.length,
        sast_scan_results: sastScanIds.length,
        sast_findings: projectIds.length * 3,
        threat_intel_feeds: 2,
        threat_intel_indicators: indicatorIds.length,
        threat_intel_matches: 4,
        soc_alerts: alertIds.length,
        soc_incidents: incidentIds.length,
        soar_playbooks: playbookIds.length,
        soar_executions: 3,
        redops_campaigns: 2,
        redops_agents: redopsAgentIds.length,
        redops_findings: redopsFindingDefs.length,
      },
    }, 201);
  } catch (err) {
    throw databaseError(err);
  }
});

// ── DELETE /demo/clear ───────────────────────────────────────────────────────
demo.delete('/clear', async (c) => {
  const db = c.env.DB;

  try {
    // Delete in dependency order (children first)
    const tables = [
      'soar_action_log',
      'soar_executions',
      'soar_playbooks',
      'soc_incident_timeline',
      'soc_alert_incidents',
      'soc_incidents',
      'soc_alerts',
      'threat_intel_matches',
      'threat_intel_indicators',
      'threat_intel_feeds',
      'sast_findings',
      'sast_scan_results',
      'sast_projects',
      'container_findings',
      'container_scan_results',
      'container_images',
      'redops_findings',
      'redops_agents',
      'redops_campaigns',
      'findings',
      'scan_tasks',
      'scans',
      'assets',
      'organization_branding',
      'organization_members',
      'organizations',
    ];

    const counts: Record<string, number> = {};
    for (const table of tables) {
      const countResult = await db.prepare(`SELECT COUNT(*) as cnt FROM ${table}`).first<{ cnt: number }>();
      counts[table] = countResult?.cnt || 0;
      await db.prepare(`DELETE FROM ${table}`).run();
    }

    return c.json({ message: 'Demo data cleared', deleted: counts });
  } catch (err) {
    throw databaseError(err);
  }
});
