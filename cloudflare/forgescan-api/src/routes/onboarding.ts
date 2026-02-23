import { Hono } from 'hono';
import type { Env } from '../index';
import { seedFrameworks } from '../services/compliance';

interface AuthUser {
  id: string;
  email: string;
  role: string;
  display_name: string;
}

export const onboarding = new Hono<{ Bindings: Env; Variables: { user: AuthUser } }>();

// GET /api/v1/onboarding/status — check what's been set up
onboarding.get('/status', async (c) => {
  try {
    const [assetCount, scanCount, scannerCount, frameworkCount, findingCount] = await Promise.all([
      c.env.DB.prepare('SELECT COUNT(*) as cnt FROM assets').first<{ cnt: number }>(),
      c.env.DB.prepare('SELECT COUNT(*) as cnt FROM scans').first<{ cnt: number }>(),
      c.env.DB.prepare('SELECT COUNT(*) as cnt FROM scanner_registrations').first<{ cnt: number }>(),
      c.env.DB.prepare('SELECT COUNT(*) as cnt FROM compliance_frameworks').first<{ cnt: number }>(),
      c.env.DB.prepare('SELECT COUNT(*) as cnt FROM findings').first<{ cnt: number }>(),
    ]);

    const hasAssets = (assetCount?.cnt || 0) > 0;
    const hasScans = (scanCount?.cnt || 0) > 0;
    const hasScanners = (scannerCount?.cnt || 0) > 0;
    const hasFrameworks = (frameworkCount?.cnt || 0) > 0;
    const hasFindings = (findingCount?.cnt || 0) > 0;

    const steps = {
      account_created: true, // If they can call this, they're authenticated
      compliance_seeded: hasFrameworks,
      scanner_registered: hasScanners,
      first_scan_run: hasScans,
      findings_imported: hasFindings || hasAssets,
    };

    const completedCount = Object.values(steps).filter(Boolean).length;
    const totalSteps = Object.keys(steps).length;
    const isComplete = completedCount === totalSteps;

    return c.json({
      steps,
      completed: completedCount,
      total: totalSteps,
      is_complete: isComplete,
      counts: {
        assets: assetCount?.cnt || 0,
        scans: scanCount?.cnt || 0,
        scanners: scannerCount?.cnt || 0,
        frameworks: frameworkCount?.cnt || 0,
        findings: findingCount?.cnt || 0,
      },
    });
  } catch (err) {
    return c.json({
      steps: { account_created: true, compliance_seeded: false, scanner_registered: false, first_scan_run: false, findings_imported: false },
      completed: 1,
      total: 5,
      is_complete: false,
      counts: { assets: 0, scans: 0, scanners: 0, frameworks: 0, findings: 0 },
    });
  }
});

// POST /api/v1/onboarding/seed-compliance — auto-seed compliance frameworks
onboarding.post('/seed-compliance', async (c) => {
  try {
    const result = await seedFrameworks(c.env.DB);
    return c.json({
      message: 'Compliance frameworks seeded',
      ...result,
    });
  } catch (err) {
    return c.json({
      error: 'Failed to seed frameworks',
      message: err instanceof Error ? err.message : 'Unknown error',
    }, 500);
  }
});

// POST /api/v1/onboarding/quick-scan — create + auto-start a network scan
onboarding.post('/quick-scan', async (c) => {
  const body = await c.req.json();
  const { target } = body;

  if (!target || typeof target !== 'string') {
    return c.json({ error: 'target is required (CIDR range or hostname)' }, 400);
  }

  // Validate target looks like a CIDR, IP, or hostname
  const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const hostnamePattern = /^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$/;
  if (!cidrPattern.test(target) && !hostnamePattern.test(target)) {
    return c.json({ error: 'Invalid target. Use a CIDR range (e.g., 192.168.1.0/24) or hostname' }, 400);
  }

  const user = c.get('user');
  const scanId = crypto.randomUUID();
  const now = new Date().toISOString();

  // Create the scan
  await c.env.DB.prepare(`
    INSERT INTO scans (id, name, type, status, target, configuration, findings_count, created_by, created_at, updated_at)
    VALUES (?, ?, 'network', 'pending', ?, ?, 0, ?, ?, ?)
  `).bind(
    scanId,
    `Quick Scan: ${target}`,
    target,
    JSON.stringify({
      ports: '1-1024,3306,5432,6379,8080,8443,27017',
      intensity: 'normal',
      quick_scan: true,
    }),
    user.id,
    now,
    now,
  ).run();

  // Auto-start the scan: create initial scan tasks
  const taskTypes = ['network_discovery', 'port_scan', 'service_detection', 'vuln_check'];
  for (const taskType of taskTypes) {
    const taskId = crypto.randomUUID();
    await c.env.DB.prepare(`
      INSERT INTO scan_tasks (id, scan_id, task_type, status, priority, findings_count, assets_discovered, created_at)
      VALUES (?, ?, ?, 'queued', 5, 0, 0, ?)
    `).bind(taskId, scanId, taskType, now).run();
  }

  // Transition scan to running
  await c.env.DB.prepare(`
    UPDATE scans SET status = 'running', started_at = ? WHERE id = ?
  `).bind(now, scanId).run();

  return c.json({
    scan_id: scanId,
    name: `Quick Scan: ${target}`,
    target,
    status: 'running',
    tasks_created: taskTypes.length,
    message: `Quick scan started on ${target}`,
  }, 201);
});
