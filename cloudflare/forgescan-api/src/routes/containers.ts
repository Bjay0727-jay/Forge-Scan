import { Hono } from 'hono';

interface Env { DB: D1Database; STORAGE: R2Bucket; CACHE: KVNamespace; JWT_SECRET: string }
interface AuthUser { id: string; email: string; role: string; display_name: string }
type Ctx = { Bindings: Env; Variables: { user: AuthUser } };

const containers = new Hono<Ctx>();

// ─── Container Image Registry ──────────────────────────────────────────────

// List container images
containers.get('/images', async (c) => {
  const { page = '1', page_size = '25', registry, search } = c.req.query();
  const pageNum = parseInt(page);
  const limit = Math.min(parseInt(page_size), 100);
  const offset = (pageNum - 1) * limit;

  const conditions: string[] = [];
  const params: string[] = [];

  if (registry) { conditions.push('registry = ?'); params.push(registry); }
  if (search) { conditions.push('(repository LIKE ? OR tag LIKE ? OR digest LIKE ?)'); params.push(`%${search}%`, `%${search}%`, `%${search}%`); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const total = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM container_images ${where}`).bind(...params).first<{ count: number }>();
  const images = await c.env.DB.prepare(`
    SELECT ci.*,
      (SELECT COUNT(*) FROM container_scan_results csr WHERE csr.image_id = ci.id) as scan_count,
      (SELECT SUM(critical_count) FROM container_scan_results csr WHERE csr.image_id = ci.id AND csr.status = 'completed') as total_critical,
      (SELECT SUM(high_count) FROM container_scan_results csr WHERE csr.image_id = ci.id AND csr.status = 'completed') as total_high
    FROM container_images ci ${where}
    ORDER BY ci.updated_at DESC LIMIT ? OFFSET ?
  `).bind(...params, limit, offset).all();

  return c.json({ items: images.results || [], total: total?.count || 0, page: pageNum, page_size: limit, total_pages: Math.ceil((total?.count || 0) / limit) });
});

// Register/add container image
containers.post('/images', async (c) => {
  const body = await c.req.json();
  const { registry, repository, tag, digest, base_image } = body;
  if (!registry || !repository) return c.json({ error: 'registry and repository are required' }, 400);

  const id = crypto.randomUUID();
  await c.env.DB.prepare(`
    INSERT INTO container_images (id, registry, repository, tag, digest, base_image)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(id, registry, repository, tag || 'latest', digest || null, base_image || null).run();

  const image = await c.env.DB.prepare('SELECT * FROM container_images WHERE id = ?').bind(id).first();
  return c.json(image, 201);
});

// Get image detail with findings
containers.get('/images/:id', async (c) => {
  const id = c.req.param('id');
  const image = await c.env.DB.prepare('SELECT * FROM container_images WHERE id = ?').bind(id).first();
  if (!image) return c.json({ error: 'Image not found' }, 404);

  const scans = await c.env.DB.prepare('SELECT * FROM container_scan_results WHERE image_id = ? ORDER BY created_at DESC LIMIT 10').bind(id).all();
  const latestScan = scans.results?.[0];
  let findings: unknown[] = [];
  if (latestScan) {
    const f = await c.env.DB.prepare('SELECT * FROM container_findings WHERE scan_result_id = ? ORDER BY severity, title').bind(latestScan.id).all();
    findings = f.results || [];
  }

  return c.json({ ...image, scans: scans.results || [], latest_findings: findings });
});

// Delete image
containers.delete('/images/:id', async (c) => {
  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT id FROM container_images WHERE id = ?').bind(id).first();
  if (!existing) return c.json({ error: 'Image not found' }, 404);
  await c.env.DB.prepare('DELETE FROM container_images WHERE id = ?').bind(id).run();
  return c.json({ message: 'Image deleted' });
});

// ─── Container Scanning ────────────────────────────────────────────────────

// Trigger a container image scan
containers.post('/images/:id/scan', async (c) => {
  const imageId = c.req.param('id');
  const image = await c.env.DB.prepare('SELECT * FROM container_images WHERE id = ?').bind(imageId).first();
  if (!image) return c.json({ error: 'Image not found' }, 404);

  const scanResultId = crypto.randomUUID();
  await c.env.DB.prepare(`
    INSERT INTO container_scan_results (id, image_id, scanner, status, started_at)
    VALUES (?, ?, 'forge', 'running', datetime('now'))
  `).bind(scanResultId, imageId).run();

  // Simulate container scan — in production this would dispatch to a scanner worker
  // We generate realistic findings based on common container vulnerabilities
  const findings = generateContainerFindings(imageId, scanResultId, image.base_image as string || 'unknown');

  let critical = 0, high = 0, medium = 0, low = 0, osVulns = 0, appVulns = 0, configIssues = 0;
  for (const f of findings) {
    if (f.severity === 'critical') critical++;
    else if (f.severity === 'high') high++;
    else if (f.severity === 'medium') medium++;
    else low++;
    if (f.finding_type === 'os_vuln') osVulns++;
    else if (f.finding_type === 'app_vuln') appVulns++;
    else if (f.finding_type === 'config') configIssues++;
  }

  // Insert findings
  for (const f of findings) {
    await c.env.DB.prepare(`
      INSERT INTO container_findings (id, scan_result_id, image_id, finding_type, package_name, installed_version, fixed_version, cve_id, severity, cvss_score, title, description, layer_index, file_path, remediation, state)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
    `).bind(f.id, scanResultId, imageId, f.finding_type, f.package_name, f.installed_version, f.fixed_version, f.cve_id, f.severity, f.cvss_score, f.title, f.description, f.layer_index, f.file_path, f.remediation).run();
  }

  // Update scan result
  await c.env.DB.prepare(`
    UPDATE container_scan_results SET status = 'completed', os_vulns = ?, app_vulns = ?, config_issues = ?,
      critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, completed_at = datetime('now')
    WHERE id = ?
  `).bind(osVulns, appVulns, configIssues, critical, high, medium, low, scanResultId).run();

  // Update image last_scanned
  await c.env.DB.prepare("UPDATE container_images SET last_scanned = datetime('now'), updated_at = datetime('now') WHERE id = ?").bind(imageId).run();

  return c.json({
    scan_result_id: scanResultId,
    image_id: imageId,
    status: 'completed',
    findings_count: findings.length,
    critical: critical, high: high, medium: medium, low: low,
    message: `Scanned ${image.repository}:${image.tag} — ${findings.length} vulnerabilities found`,
  });
});

// Get scan result detail
containers.get('/scans/:id', async (c) => {
  const id = c.req.param('id');
  const result = await c.env.DB.prepare('SELECT * FROM container_scan_results WHERE id = ?').bind(id).first();
  if (!result) return c.json({ error: 'Scan result not found' }, 404);

  const findings = await c.env.DB.prepare('SELECT * FROM container_findings WHERE scan_result_id = ? ORDER BY severity, title').bind(id).all();
  return c.json({ ...result, findings: findings.results || [] });
});

// ─── Overview / Dashboard ──────────────────────────────────────────────────

containers.get('/overview', async (c) => {
  const db = c.env.DB;

  const [imageCount, scanCount, findingCount, severityBreakdown, topVulnImages, recentScans] = await Promise.all([
    db.prepare('SELECT COUNT(*) as count FROM container_images').first<{ count: number }>(),
    db.prepare("SELECT COUNT(*) as count FROM container_scan_results WHERE status = 'completed'").first<{ count: number }>(),
    db.prepare("SELECT COUNT(*) as count FROM container_findings WHERE state = 'open'").first<{ count: number }>(),
    db.prepare("SELECT severity, COUNT(*) as count FROM container_findings WHERE state = 'open' GROUP BY severity").all(),
    db.prepare(`
      SELECT ci.repository, ci.tag, ci.registry,
        SUM(csr.critical_count) as critical, SUM(csr.high_count) as high
      FROM container_images ci
      JOIN container_scan_results csr ON csr.image_id = ci.id AND csr.status = 'completed'
      GROUP BY ci.id ORDER BY critical DESC, high DESC LIMIT 5
    `).all(),
    db.prepare("SELECT csr.*, ci.repository, ci.tag FROM container_scan_results csr JOIN container_images ci ON ci.id = csr.image_id ORDER BY csr.created_at DESC LIMIT 5").all(),
  ]);

  return c.json({
    totals: { images: imageCount?.count || 0, scans: scanCount?.count || 0, open_findings: findingCount?.count || 0 },
    severity_breakdown: severityBreakdown.results || [],
    top_vulnerable_images: topVulnImages.results || [],
    recent_scans: recentScans.results || [],
    generated_at: new Date().toISOString(),
  });
});

// ─── Simulated Finding Generator ───────────────────────────────────────────
// In production, replaced by actual Trivy/Grype/Forge scanner integration

interface ContainerFinding {
  id: string; finding_type: string; package_name: string; installed_version: string;
  fixed_version: string | null; cve_id: string | null; severity: string; cvss_score: number;
  title: string; description: string; layer_index: number; file_path: string | null; remediation: string;
}

function generateContainerFindings(imageId: string, scanResultId: string, baseImage: string): ContainerFinding[] {
  const findings: ContainerFinding[] = [];
  const osVulns = [
    { pkg: 'openssl', ver: '1.1.1k', fix: '1.1.1w', cve: 'CVE-2023-5678', sev: 'high', cvss: 7.5, title: 'OpenSSL Buffer Overflow', desc: 'A buffer overflow in X.509 certificate verification may allow remote code execution' },
    { pkg: 'libc6', ver: '2.31-13', fix: '2.31-13+deb11u7', cve: 'CVE-2023-4911', sev: 'critical', cvss: 9.8, title: 'glibc Looney Tunables LPE', desc: 'Buffer overflow in glibc ld.so dynamic loader allows local privilege escalation' },
    { pkg: 'curl', ver: '7.74.0', fix: '7.74.0-1.3+deb11u10', cve: 'CVE-2023-38545', sev: 'high', cvss: 8.1, title: 'curl SOCKS5 Heap Buffer Overflow', desc: 'Heap-based buffer overflow in SOCKS5 proxy handshake' },
    { pkg: 'zlib', ver: '1.2.11', fix: '1.2.13', cve: 'CVE-2022-37434', sev: 'critical', cvss: 9.8, title: 'zlib Heap Buffer Overflow in inflate', desc: 'Heap-based buffer overflow in inflate() via large gzip header extra field' },
    { pkg: 'libexpat1', ver: '2.2.10', fix: '2.5.0', cve: 'CVE-2022-40674', sev: 'high', cvss: 8.1, title: 'Expat Use-After-Free', desc: 'Use-after-free in XML_ExternalEntityParserCreate in libexpat' },
  ];

  const appVulns = [
    { pkg: 'lodash', ver: '4.17.20', fix: '4.17.21', cve: 'CVE-2021-23337', sev: 'high', cvss: 7.2, title: 'lodash Command Injection', desc: 'Prototype pollution in lodash template function' },
    { pkg: 'express', ver: '4.17.1', fix: '4.18.2', cve: 'CVE-2024-29041', sev: 'medium', cvss: 6.1, title: 'Express Open Redirect', desc: 'Open redirect vulnerability in Express.js response.redirect()' },
    { pkg: 'jsonwebtoken', ver: '8.5.1', fix: '9.0.0', cve: 'CVE-2022-23529', sev: 'high', cvss: 7.6, title: 'JWT Secret Poisoning', desc: 'Insecure implementation of key retrieval in jsonwebtoken' },
  ];

  const configIssues = [
    { title: 'Container Running as Root', sev: 'high', cvss: 7.0, desc: 'Container runs as UID 0 (root). Use USER directive to run as non-root.', path: 'Dockerfile', rem: 'Add USER directive: USER 1001' },
    { title: 'No Health Check Defined', sev: 'medium', cvss: 4.0, desc: 'No HEALTHCHECK instruction in Dockerfile.', path: 'Dockerfile', rem: 'Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1' },
    { title: 'Secrets in Environment Variables', sev: 'critical', cvss: 9.1, desc: 'Hardcoded secrets detected in ENV instructions.', path: 'Dockerfile:12', rem: 'Use runtime secrets injection via orchestrator' },
  ];

  // Select subset based on base image randomness
  const seed = imageId.charCodeAt(0) + imageId.charCodeAt(4);
  const osCount = 2 + (seed % 4);
  const appCount = 1 + (seed % 3);
  const cfgCount = 1 + (seed % 2);

  for (let i = 0; i < Math.min(osCount, osVulns.length); i++) {
    const v = osVulns[i];
    findings.push({
      id: crypto.randomUUID(), finding_type: 'os_vuln', package_name: v.pkg,
      installed_version: v.ver, fixed_version: v.fix, cve_id: v.cve,
      severity: v.sev, cvss_score: v.cvss, title: v.title, description: v.desc,
      layer_index: i + 1, file_path: null, remediation: `Upgrade ${v.pkg} to ${v.fix}`,
    });
  }

  for (let i = 0; i < Math.min(appCount, appVulns.length); i++) {
    const v = appVulns[i];
    findings.push({
      id: crypto.randomUUID(), finding_type: 'app_vuln', package_name: v.pkg,
      installed_version: v.ver, fixed_version: v.fix, cve_id: v.cve,
      severity: v.sev, cvss_score: v.cvss, title: v.title, description: v.desc,
      layer_index: osCount + i + 1, file_path: `/app/node_modules/${v.pkg}/package.json`,
      remediation: `Upgrade ${v.pkg} to ${v.fix}`,
    });
  }

  for (let i = 0; i < Math.min(cfgCount, configIssues.length); i++) {
    const v = configIssues[i];
    findings.push({
      id: crypto.randomUUID(), finding_type: 'config', package_name: '',
      installed_version: '', fixed_version: null, cve_id: null,
      severity: v.sev, cvss_score: v.cvss, title: v.title, description: v.desc,
      layer_index: 0, file_path: v.path, remediation: v.rem,
    });
  }

  return findings;
}

export { containers };
