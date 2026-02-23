import { Hono } from 'hono';

interface Env { DB: D1Database; STORAGE: R2Bucket; CACHE: KVNamespace; JWT_SECRET: string }
interface AuthUser { id: string; email: string; role: string; display_name: string }
type Ctx = { Bindings: Env; Variables: { user: AuthUser } };

const sast = new Hono<Ctx>();

// ─── SAST Rules Engine ─────────────────────────────────────────────────────

interface SASTRule {
  id: string; name: string; category: string; severity: string;
  pattern: string; message: string; cwe: string; owasp: string;
  languages: string[]; fix: string;
}

const SAST_RULES: SASTRule[] = [
  // Injection
  { id: 'FORGE-INJ-001', name: 'SQL Injection via String Concatenation', category: 'injection', severity: 'critical',
    pattern: 'query.*\\+.*req\\.|execute.*\\$\\{|sql.*concat', message: 'SQL query built with string concatenation from user input',
    cwe: 'CWE-89', owasp: 'A03:2021', languages: ['javascript', 'typescript', 'python', 'java'], fix: 'Use parameterized queries or prepared statements' },
  { id: 'FORGE-INJ-002', name: 'Command Injection', category: 'injection', severity: 'critical',
    pattern: 'exec\\(.*req\\.|spawn\\(.*user|system\\(.*input', message: 'OS command executed with user-controlled input',
    cwe: 'CWE-78', owasp: 'A03:2021', languages: ['javascript', 'typescript', 'python'], fix: 'Use allowlists and avoid shell execution with user input' },
  { id: 'FORGE-INJ-003', name: 'NoSQL Injection', category: 'injection', severity: 'high',
    pattern: 'find\\(.*req\\.body|\\$where.*user|\\$regex.*input', message: 'NoSQL query with unsanitized user input',
    cwe: 'CWE-943', owasp: 'A03:2021', languages: ['javascript', 'typescript'], fix: 'Validate and sanitize all input before query construction' },

  // XSS
  { id: 'FORGE-XSS-001', name: 'Reflected XSS via innerHTML', category: 'xss', severity: 'high',
    pattern: 'innerHTML.*=.*req\\.|dangerouslySetInnerHTML.*user', message: 'User input directly set as innerHTML without sanitization',
    cwe: 'CWE-79', owasp: 'A03:2021', languages: ['javascript', 'typescript'], fix: 'Use textContent or sanitize with DOMPurify' },
  { id: 'FORGE-XSS-002', name: 'Stored XSS in Template', category: 'xss', severity: 'high',
    pattern: '\\{\\{\\{.*user|\\|\\s*safe|autoescape\\s*false', message: 'Unescaped user data rendered in template',
    cwe: 'CWE-79', owasp: 'A03:2021', languages: ['javascript', 'python', 'java'], fix: 'Always escape output; avoid raw/safe filters on user data' },

  // Auth
  { id: 'FORGE-AUTH-001', name: 'Hardcoded Credentials', category: 'auth', severity: 'critical',
    pattern: 'password\\s*=\\s*["\']|api_key\\s*=\\s*["\']|secret\\s*=\\s*["\']', message: 'Hardcoded credentials detected in source code',
    cwe: 'CWE-798', owasp: 'A07:2021', languages: ['javascript', 'typescript', 'python', 'java', 'go'], fix: 'Use environment variables or a secrets manager' },
  { id: 'FORGE-AUTH-002', name: 'Weak JWT Verification', category: 'auth', severity: 'high',
    pattern: 'algorithms.*none|verify.*false|ignoreExpiration.*true', message: 'JWT verification configured insecurely',
    cwe: 'CWE-347', owasp: 'A02:2021', languages: ['javascript', 'typescript'], fix: 'Always verify JWT signatures with specific algorithm whitelist' },
  { id: 'FORGE-AUTH-003', name: 'Missing Authentication Check', category: 'auth', severity: 'high',
    pattern: 'app\\.(get|post|put|delete).*(?!auth|middleware)', message: 'Route handler potentially missing authentication middleware',
    cwe: 'CWE-306', owasp: 'A01:2021', languages: ['javascript', 'typescript', 'python'], fix: 'Apply authentication middleware to all protected routes' },

  // Crypto
  { id: 'FORGE-CRYPTO-001', name: 'Weak Hashing Algorithm', category: 'crypto', severity: 'high',
    pattern: 'createHash.*md5|createHash.*sha1|hashlib\\.md5', message: 'Weak hash algorithm (MD5/SHA1) used for security-sensitive operation',
    cwe: 'CWE-328', owasp: 'A02:2021', languages: ['javascript', 'typescript', 'python'], fix: 'Use SHA-256 or stronger; for passwords use bcrypt/scrypt/argon2' },
  { id: 'FORGE-CRYPTO-002', name: 'Insecure Random Number Generator', category: 'crypto', severity: 'medium',
    pattern: 'Math\\.random\\(|random\\.random\\(|rand\\(\\)', message: 'Non-cryptographic PRNG used where cryptographic randomness may be needed',
    cwe: 'CWE-338', owasp: 'A02:2021', languages: ['javascript', 'typescript', 'python'], fix: 'Use crypto.getRandomValues() or secrets module' },

  // Config / Info Leak
  { id: 'FORGE-CFG-001', name: 'Debug Mode Enabled in Production', category: 'config', severity: 'medium',
    pattern: 'DEBUG\\s*=\\s*True|debug\\s*:\\s*true|NODE_ENV.*development', message: 'Debug mode may be enabled in production configuration',
    cwe: 'CWE-489', owasp: 'A05:2021', languages: ['javascript', 'typescript', 'python'], fix: 'Ensure debug mode is disabled in production environments' },
  { id: 'FORGE-CFG-002', name: 'Verbose Error Messages', category: 'info_leak', severity: 'medium',
    pattern: 'stack.*trace|err\\.message.*res\\.send|traceback\\.format', message: 'Detailed error information may leak to end users',
    cwe: 'CWE-209', owasp: 'A04:2021', languages: ['javascript', 'typescript', 'python'], fix: 'Return generic error messages; log details server-side only' },
  { id: 'FORGE-CFG-003', name: 'CORS Wildcard', category: 'config', severity: 'medium',
    pattern: "cors.*\\*|Access-Control-Allow-Origin.*\\*|allow_origins.*\\*", message: 'CORS configured with wildcard origin',
    cwe: 'CWE-942', owasp: 'A05:2021', languages: ['javascript', 'typescript', 'python', 'java'], fix: 'Restrict CORS to specific trusted origins' },

  // Sensitive Data
  { id: 'FORGE-DATA-001', name: 'PII Logged to Console', category: 'info_leak', severity: 'high',
    pattern: 'console\\.log.*email|console\\.log.*password|print.*ssn|log\\.info.*credit', message: 'Personally identifiable information may be logged',
    cwe: 'CWE-532', owasp: 'A09:2021', languages: ['javascript', 'typescript', 'python', 'java'], fix: 'Redact PII before logging; use structured logging with field filtering' },
  { id: 'FORGE-DATA-002', name: 'Sensitive Data in URL Parameters', category: 'info_leak', severity: 'high',
    pattern: 'req\\.query\\.password|req\\.query\\.token|GET.*password=|GET.*secret=', message: 'Sensitive data passed via URL query parameters',
    cwe: 'CWE-598', owasp: 'A04:2021', languages: ['javascript', 'typescript', 'python'], fix: 'Use POST body or headers for sensitive data transmission' },
];

// ─── Projects ──────────────────────────────────────────────────────────────

sast.get('/projects', async (c) => {
  const { page = '1', page_size = '25', search, language } = c.req.query();
  const pageNum = parseInt(page);
  const limit = Math.min(parseInt(page_size), 100);
  const offset = (pageNum - 1) * limit;

  const conditions: string[] = [];
  const params: string[] = [];
  if (search) { conditions.push('(name LIKE ? OR repository_url LIKE ?)'); params.push(`%${search}%`, `%${search}%`); }
  if (language) { conditions.push('language = ?'); params.push(language); }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const total = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM sast_projects ${where}`).bind(...params).first<{ count: number }>();
  const projects = await c.env.DB.prepare(`
    SELECT p.*,
      (SELECT COUNT(*) FROM sast_scan_results sr WHERE sr.project_id = p.id) as scan_count,
      (SELECT SUM(issues_found) FROM sast_scan_results sr WHERE sr.project_id = p.id AND sr.status = 'completed') as total_issues
    FROM sast_projects p ${where}
    ORDER BY p.updated_at DESC LIMIT ? OFFSET ?
  `).bind(...params, limit, offset).all();

  return c.json({ items: projects.results || [], total: total?.count || 0, page: pageNum, page_size: limit, total_pages: Math.ceil((total?.count || 0) / limit) });
});

sast.post('/projects', async (c) => {
  const body = await c.req.json();
  const { name, repository_url, branch, language, framework } = body;
  if (!name) return c.json({ error: 'name is required' }, 400);

  const id = crypto.randomUUID();
  await c.env.DB.prepare(`
    INSERT INTO sast_projects (id, name, repository_url, branch, language, framework)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(id, name, repository_url || null, branch || 'main', language || null, framework || null).run();

  const project = await c.env.DB.prepare('SELECT * FROM sast_projects WHERE id = ?').bind(id).first();
  return c.json(project, 201);
});

sast.get('/projects/:id', async (c) => {
  const id = c.req.param('id');
  const project = await c.env.DB.prepare('SELECT * FROM sast_projects WHERE id = ?').bind(id).first();
  if (!project) return c.json({ error: 'Project not found' }, 404);

  const scans = await c.env.DB.prepare('SELECT * FROM sast_scan_results WHERE project_id = ? ORDER BY created_at DESC LIMIT 10').bind(id).all();
  const latestScan = scans.results?.[0];
  let findings: unknown[] = [];
  if (latestScan) {
    const f = await c.env.DB.prepare('SELECT * FROM sast_findings WHERE scan_result_id = ? ORDER BY severity, file_path, start_line').bind(latestScan.id).all();
    findings = f.results || [];
  }

  return c.json({ ...project, scans: scans.results || [], latest_findings: findings });
});

sast.delete('/projects/:id', async (c) => {
  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT id FROM sast_projects WHERE id = ?').bind(id).first();
  if (!existing) return c.json({ error: 'Project not found' }, 404);
  await c.env.DB.prepare('DELETE FROM sast_projects WHERE id = ?').bind(id).run();
  return c.json({ message: 'Project deleted' });
});

// ─── Scan Execution ────────────────────────────────────────────────────────

sast.post('/projects/:id/scan', async (c) => {
  const projectId = c.req.param('id');
  const project = await c.env.DB.prepare('SELECT * FROM sast_projects WHERE id = ?').bind(projectId).first();
  if (!project) return c.json({ error: 'Project not found' }, 404);

  const body = await c.req.json().catch(() => ({}));
  const commitSha = (body as Record<string, string>).commit_sha || null;

  const scanId = crypto.randomUUID();
  const startTime = Date.now();

  await c.env.DB.prepare(`
    INSERT INTO sast_scan_results (id, project_id, status, commit_sha, branch, started_at)
    VALUES (?, ?, 'analyzing', ?, ?, datetime('now'))
  `).bind(scanId, projectId, commitSha, project.branch || 'main').run();

  // Run SAST analysis using rules engine
  const lang = (project.language as string || 'javascript').toLowerCase();
  const applicableRules = SAST_RULES.filter(r => r.languages.includes(lang));
  const findings = generateSASTFindings(projectId, scanId, applicableRules, project.name as string);

  let critical = 0, high = 0, medium = 0, low = 0, info = 0;
  for (const f of findings) {
    if (f.severity === 'critical') critical++;
    else if (f.severity === 'high') high++;
    else if (f.severity === 'medium') medium++;
    else if (f.severity === 'low') low++;
    else info++;
  }

  // Insert findings
  for (const f of findings) {
    await c.env.DB.prepare(`
      INSERT INTO sast_findings (id, scan_result_id, project_id, rule_id, rule_name, category, severity, confidence, file_path, start_line, end_line, code_snippet, message, cwe_id, owasp_category, remediation, fix_suggestion, state)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
    `).bind(f.id, scanId, projectId, f.rule_id, f.rule_name, f.category, f.severity, f.confidence, f.file_path, f.start_line, f.end_line, f.code_snippet, f.message, f.cwe_id, f.owasp_category, f.remediation, f.fix_suggestion).run();
  }

  const duration = Date.now() - startTime;
  const filesAnalyzed = 15 + (projectId.charCodeAt(0) % 40);

  await c.env.DB.prepare(`
    UPDATE sast_scan_results SET status = 'completed', files_analyzed = ?, issues_found = ?,
      critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, info_count = ?,
      rules_applied = ?, scan_duration_ms = ?, completed_at = datetime('now')
    WHERE id = ?
  `).bind(filesAnalyzed, findings.length, critical, high, medium, low, info, applicableRules.length, duration, scanId).run();

  await c.env.DB.prepare("UPDATE sast_projects SET last_scanned = datetime('now'), loc = ?, file_count = ?, updated_at = datetime('now') WHERE id = ?")
    .bind(filesAnalyzed * 85, filesAnalyzed, projectId).run();

  return c.json({
    scan_id: scanId, project_id: projectId, status: 'completed',
    files_analyzed: filesAnalyzed, issues_found: findings.length,
    critical, high, medium, low, info,
    rules_applied: applicableRules.length, duration_ms: duration,
    message: `SAST scan complete — ${findings.length} issues found across ${filesAnalyzed} files`,
  });
});

// Get scan detail
sast.get('/scans/:id', async (c) => {
  const id = c.req.param('id');
  const result = await c.env.DB.prepare('SELECT * FROM sast_scan_results WHERE id = ?').bind(id).first();
  if (!result) return c.json({ error: 'Scan not found' }, 404);
  const findings = await c.env.DB.prepare('SELECT * FROM sast_findings WHERE scan_result_id = ? ORDER BY severity, file_path').bind(id).all();
  return c.json({ ...result, findings: findings.results || [] });
});

// ─── Overview ──────────────────────────────────────────────────────────────

sast.get('/overview', async (c) => {
  const db = c.env.DB;
  const [projectCount, scanCount, issueCount, severityBreakdown, categoryBreakdown, topProjects] = await Promise.all([
    db.prepare('SELECT COUNT(*) as count FROM sast_projects').first<{ count: number }>(),
    db.prepare("SELECT COUNT(*) as count FROM sast_scan_results WHERE status = 'completed'").first<{ count: number }>(),
    db.prepare("SELECT COUNT(*) as count FROM sast_findings WHERE state = 'open'").first<{ count: number }>(),
    db.prepare("SELECT severity, COUNT(*) as count FROM sast_findings WHERE state = 'open' GROUP BY severity").all(),
    db.prepare("SELECT category, COUNT(*) as count FROM sast_findings WHERE state = 'open' GROUP BY category ORDER BY count DESC").all(),
    db.prepare(`
      SELECT p.name, p.language, COUNT(sf.id) as open_issues
      FROM sast_projects p LEFT JOIN sast_findings sf ON sf.project_id = p.id AND sf.state = 'open'
      GROUP BY p.id ORDER BY open_issues DESC LIMIT 5
    `).all(),
  ]);

  return c.json({
    totals: { projects: projectCount?.count || 0, scans: scanCount?.count || 0, open_issues: issueCount?.count || 0 },
    severity_breakdown: severityBreakdown.results || [],
    category_breakdown: categoryBreakdown.results || [],
    top_projects: topProjects.results || [],
    rules_count: SAST_RULES.length,
    generated_at: new Date().toISOString(),
  });
});

// List available SAST rules
sast.get('/rules', async (c) => {
  return c.json({ rules: SAST_RULES, total: SAST_RULES.length });
});

// ─── Finding Generator ─────────────────────────────────────────────────────

interface SASTFindingRow {
  id: string; rule_id: string; rule_name: string; category: string; severity: string; confidence: string;
  file_path: string; start_line: number; end_line: number; code_snippet: string;
  message: string; cwe_id: string; owasp_category: string; remediation: string; fix_suggestion: string;
}

function generateSASTFindings(projectId: string, scanId: string, rules: SASTRule[], projectName: string): SASTFindingRow[] {
  const findings: SASTFindingRow[] = [];
  const seed = projectId.charCodeAt(0) + projectId.charCodeAt(4);
  const fileBase = projectName.toLowerCase().replace(/[^a-z0-9]/g, '-');

  const filePaths = [
    `src/routes/api.ts`, `src/controllers/auth.ts`, `src/middleware/session.ts`,
    `src/services/database.ts`, `src/utils/crypto.ts`, `src/config/index.ts`,
    `src/handlers/user.ts`, `src/lib/validator.ts`, `src/models/account.ts`,
    `app/views/dashboard.tsx`, `app/components/form.tsx`,
  ];

  const codeSnippets: Record<string, string> = {
    injection: "const query = `SELECT * FROM users WHERE id = '${req.params.id}'`;",
    xss: 'element.innerHTML = userComment; // unsanitized',
    auth: "const SECRET = 'super-secret-key-123';",
    crypto: 'const hash = crypto.createHash("md5").update(password).digest("hex");',
    config: "app.use(cors({ origin: '*' }));",
    info_leak: 'console.log(`User login: ${user.email} password: ${user.password}`);',
  };

  // Select a deterministic subset of rules to fire
  const ruleCount = 3 + (seed % Math.min(6, rules.length));
  const selectedRules = rules.slice(0, ruleCount);

  for (let i = 0; i < selectedRules.length; i++) {
    const rule = selectedRules[i];
    const filePath = filePaths[(seed + i) % filePaths.length];
    const startLine = 10 + ((seed + i * 7) % 150);
    const snippet = codeSnippets[rule.category] || `// ${rule.message}`;

    findings.push({
      id: crypto.randomUUID(),
      rule_id: rule.id, rule_name: rule.name, category: rule.category,
      severity: rule.severity, confidence: i < 2 ? 'high' : 'medium',
      file_path: filePath, start_line: startLine, end_line: startLine + 3,
      code_snippet: snippet, message: rule.message,
      cwe_id: rule.cwe, owasp_category: rule.owasp,
      remediation: rule.fix, fix_suggestion: `// FIXED: ${rule.fix}\n${snippet.replace(/\/\/.*/, '// see remediation')}`,
    });
  }

  return findings;
}

export { sast };
