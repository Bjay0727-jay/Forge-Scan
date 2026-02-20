import { Hono, Context, MiddlewareHandler } from 'hono';
import type { Env } from '../index';
import { requireRole } from '../middleware/auth';
import { updateScanFromTasks } from '../services/scan-orchestrator';

// ---------- Types ----------

type ScannerEnv = {
  Bindings: Env;
  Variables: {
    user?: { id: string; email: string; role: string; display_name: string };
    scanner?: {
      id: string;
      scanner_id: string;
      hostname: string;
      version: string | null;
      capabilities: string;
      status: string;
    };
  };
};

// ---------- Helpers ----------

async function hashKey(key: string): Promise<string> {
  const data = new TextEncoder().encode(key);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------- Scanner authentication middleware ----------

const authenticateScanner: MiddlewareHandler<ScannerEnv> = async (c, next) => {
  const apiKey = c.req.header('X-Scanner-Key');
  if (!apiKey) {
    return c.json({ error: 'Unauthorized', message: 'X-Scanner-Key header required' }, 401);
  }

  const keyHash = await hashKey(apiKey);

  const registration = await c.env.DB.prepare(
    'SELECT id, scanner_id, hostname, version, capabilities, status FROM scanner_registrations WHERE api_key_hash = ?'
  ).bind(keyHash).first<{
    id: string;
    scanner_id: string;
    hostname: string;
    version: string | null;
    capabilities: string;
    status: string;
  }>();

  if (!registration) {
    return c.json({ error: 'Unauthorized', message: 'Invalid scanner key' }, 401);
  }

  if (registration.status === 'disabled') {
    return c.json({ error: 'Unauthorized', message: 'Scanner is disabled' }, 401);
  }

  c.set('scanner', registration);
  return next();
};

// ---------- Router ----------

export const scanner = new Hono<ScannerEnv>();

// ==========================================
//  Admin routes (require user JWT auth)
// ==========================================

// POST /register - Register a new scanner (platform_admin only)
scanner.post('/register', requireRole('platform_admin'), async (c) => {
  try {
    const body = await c.req.json();
    const { scanner_id, hostname, version, capabilities } = body;

    if (!scanner_id || !hostname) {
      return c.json({ error: 'scanner_id and hostname are required' }, 400);
    }

    // Check for duplicate scanner_id
    const existing = await c.env.DB.prepare(
      'SELECT id FROM scanner_registrations WHERE scanner_id = ?'
    ).bind(scanner_id).first();

    if (existing) {
      return c.json({ error: 'Scanner with this scanner_id already exists' }, 409);
    }

    // Generate API key
    const rawKey = `scanner_${crypto.randomUUID().replace(/-/g, '')}`;
    const keyHash = await hashKey(rawKey);
    const keyPrefix = rawKey.substring(0, 8);
    const id = crypto.randomUUID();

    await c.env.DB.prepare(`
      INSERT INTO scanner_registrations (id, scanner_id, hostname, version, capabilities, api_key_hash, api_key_prefix, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'registered', datetime('now'), datetime('now'))
    `).bind(
      id,
      scanner_id,
      hostname,
      version || null,
      JSON.stringify(capabilities || []),
      keyHash,
      keyPrefix,
    ).run();

    return c.json({
      id,
      scanner_id,
      hostname,
      version: version || null,
      capabilities: capabilities || [],
      api_key: rawKey,
      api_key_prefix: keyPrefix,
      message: 'Store this API key securely - it will not be shown again',
    }, 201);
  } catch (error: unknown) {
    console.error('Register scanner error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to register scanner', message }, 500);
  }
});

// GET / - List all registered scanners (platform_admin, scan_admin)
scanner.get('/', requireRole('platform_admin', 'scan_admin'), async (c) => {
  try {
    const result = await c.env.DB.prepare(`
      SELECT
        sr.*,
        (SELECT COUNT(*) FROM scan_tasks st WHERE st.scanner_id = sr.scanner_id AND st.status = 'completed') as completed_tasks,
        (SELECT COUNT(*) FROM scan_tasks st WHERE st.scanner_id = sr.scanner_id AND st.status = 'running') as running_tasks,
        (SELECT COUNT(*) FROM scan_tasks st WHERE st.scanner_id = sr.scanner_id AND st.status = 'assigned') as assigned_tasks
      FROM scanner_registrations sr
      ORDER BY sr.created_at DESC
    `).all();

    return c.json({
      scanners: result.results || [],
    });
  } catch (error: unknown) {
    console.error('List scanners error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to list scanners', message }, 500);
  }
});

// DELETE /:id - Deactivate/delete a scanner (platform_admin only)
scanner.delete('/:id', requireRole('platform_admin'), async (c) => {
  try {
    const id = c.req.param('id');

    const existing = await c.env.DB.prepare(
      'SELECT id FROM scanner_registrations WHERE id = ?'
    ).bind(id).first();

    if (!existing) {
      return c.json({ error: 'Scanner not found' }, 404);
    }

    await c.env.DB.prepare(
      "UPDATE scanner_registrations SET status = 'disabled', updated_at = datetime('now') WHERE id = ?"
    ).bind(id).run();

    return c.json({ message: 'Scanner deactivated' });
  } catch (error: unknown) {
    console.error('Delete scanner error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to deactivate scanner', message }, 500);
  }
});

// GET /tasks - List all scan tasks with filtering (platform_admin, scan_admin)
scanner.get('/tasks', requireRole('platform_admin', 'scan_admin'), async (c) => {
  try {
    const { status, scan_id, scanner_id, limit = '50', offset = '0' } = c.req.query();
    const limitNum = Math.min(parseInt(limit) || 50, 200);
    const offsetNum = parseInt(offset) || 0;

    let query = 'SELECT * FROM scan_tasks WHERE 1=1';
    let countQuery = 'SELECT COUNT(*) as total FROM scan_tasks WHERE 1=1';
    const params: string[] = [];
    const countParams: string[] = [];

    if (status) {
      query += ' AND status = ?';
      countQuery += ' AND status = ?';
      params.push(status);
      countParams.push(status);
    }

    if (scan_id) {
      query += ' AND scan_id = ?';
      countQuery += ' AND scan_id = ?';
      params.push(scan_id);
      countParams.push(scan_id);
    }

    if (scanner_id) {
      query += ' AND scanner_id = ?';
      countQuery += ' AND scanner_id = ?';
      params.push(scanner_id);
      countParams.push(scanner_id);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';

    const result = await c.env.DB.prepare(query).bind(...params, limitNum, offsetNum).all();
    const countResult = await c.env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>();

    return c.json({
      tasks: result.results || [],
      total: countResult?.total || 0,
      limit: limitNum,
      offset: offsetNum,
    });
  } catch (error: unknown) {
    console.error('List tasks error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to list tasks', message }, 500);
  }
});

// ==========================================
//  Scanner-facing routes (X-Scanner-Key auth)
// ==========================================

// GET /tasks/next - Poll for next available task
scanner.get('/tasks/next', authenticateScanner, async (c) => {
  try {
    const scannerInfo = c.get('scanner')!;
    const capabilities = JSON.parse(scannerInfo.capabilities || '[]') as string[];

    // Find oldest queued task matching scanner capabilities
    let query: string;
    let task: Record<string, unknown> | null;

    if (capabilities.length > 0) {
      // Build a query that matches tasks whose task_type is in the scanner's capabilities
      const placeholders = capabilities.map(() => '?').join(', ');
      query = `SELECT * FROM scan_tasks WHERE status = 'queued' AND task_type IN (${placeholders}) ORDER BY priority ASC, created_at ASC LIMIT 1`;
      task = await c.env.DB.prepare(query).bind(...capabilities).first();
    } else {
      // Scanner has no specific capabilities, pick any queued task
      query = "SELECT * FROM scan_tasks WHERE status = 'queued' ORDER BY priority ASC, created_at ASC LIMIT 1";
      task = await c.env.DB.prepare(query).first();
    }

    if (!task) {
      return c.body(null, 204);
    }

    // Assign the task to this scanner
    await c.env.DB.prepare(`
      UPDATE scan_tasks SET status = 'assigned', scanner_id = ?, assigned_at = datetime('now'), updated_at = datetime('now')
      WHERE id = ?
    `).bind(scannerInfo.scanner_id, task.id as string).run();

    return c.json({
      task: {
        id: task.id,
        scan_id: task.scan_id,
        task_type: task.task_type,
        task_payload: task.task_payload ? JSON.parse(task.task_payload as string) : {},
        priority: task.priority,
        retry_count: task.retry_count,
        max_retries: task.max_retries,
      },
    });
  } catch (error: unknown) {
    console.error('Get next task error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to get next task', message }, 500);
  }
});

// POST /tasks/:id/start - Scanner reports task started
scanner.post('/tasks/:id/start', authenticateScanner, async (c) => {
  try {
    const taskId = c.req.param('id');
    const scannerInfo = c.get('scanner')!;

    const task = await c.env.DB.prepare(
      'SELECT id, scanner_id, status FROM scan_tasks WHERE id = ?'
    ).bind(taskId).first<{ id: string; scanner_id: string; status: string }>();

    if (!task) {
      return c.json({ error: 'Task not found' }, 404);
    }

    if (task.scanner_id !== scannerInfo.scanner_id) {
      return c.json({ error: 'Task is not assigned to this scanner' }, 403);
    }

    if (task.status !== 'assigned') {
      return c.json({ error: `Task cannot be started - current status is '${task.status}'` }, 400);
    }

    await c.env.DB.prepare(`
      UPDATE scan_tasks SET status = 'running', started_at = datetime('now'), updated_at = datetime('now')
      WHERE id = ?
    `).bind(taskId).run();

    return c.json({ message: 'Task started', task_id: taskId });
  } catch (error: unknown) {
    console.error('Start task error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to start task', message }, 500);
  }
});

// POST /tasks/:id/results - Scanner posts task results
scanner.post('/tasks/:id/results', authenticateScanner, async (c) => {
  try {
    const taskId = c.req.param('id');
    const scannerInfo = c.get('scanner')!;

    const task = await c.env.DB.prepare(
      'SELECT id, scan_id, scanner_id, status FROM scan_tasks WHERE id = ?'
    ).bind(taskId).first<{ id: string; scan_id: string; scanner_id: string; status: string }>();

    if (!task) {
      return c.json({ error: 'Task not found' }, 404);
    }

    if (task.scanner_id !== scannerInfo.scanner_id) {
      return c.json({ error: 'Task is not assigned to this scanner' }, 403);
    }

    const body = await c.req.json();
    const { status, findings, assets, error_message, summary } = body;

    if (!status || !['completed', 'failed'].includes(status)) {
      return c.json({ error: "status must be 'completed' or 'failed'" }, 400);
    }

    const db = c.env.DB;
    let findingsCount = 0;
    let assetsDiscovered = 0;

    // Insert findings if provided
    if (findings && Array.isArray(findings) && findings.length > 0) {
      for (const finding of findings) {
        const findingId = crypto.randomUUID();
        // First, upsert the asset if provided
        let assetId = finding.asset_id;
        if (finding.asset && !assetId) {
          // Look up or create asset by hostname/IP
          const existing = await db.prepare(
            'SELECT id FROM assets WHERE hostname = ? OR ip_addresses LIKE ?'
          ).bind(finding.asset.hostname || '', `%${finding.asset.ip || ''}%`).first();
          assetId = existing?.id as string || crypto.randomUUID();
          if (!existing) {
            await db.prepare(
              'INSERT INTO assets (id, hostname, ip_addresses, os, asset_type, last_seen) VALUES (?, ?, ?, ?, ?, datetime(\'now\'))'
            ).bind(assetId, finding.asset.hostname, finding.asset.ip, finding.asset.os, finding.asset.type || 'host').run();
            assetsDiscovered++;
          }
        }

        await db.prepare(`
          INSERT INTO findings (id, asset_id, scan_id, vendor, vendor_id, title, description, severity, port, protocol, service, state, solution, evidence)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
        `).bind(
          findingId,
          assetId || null,
          task.scan_id,
          finding.vendor || 'forgescan',
          finding.vendor_id || findingId,
          finding.title,
          finding.description || null,
          finding.severity || 'medium',
          finding.port || null,
          finding.protocol || null,
          finding.service || null,
          finding.solution || null,
          finding.evidence || null,
        ).run();

        findingsCount++;
      }
    }

    // Upsert assets if provided separately
    if (assets && Array.isArray(assets) && assets.length > 0) {
      for (const asset of assets) {
        const existing = await db.prepare(
          'SELECT id FROM assets WHERE hostname = ? OR ip_addresses LIKE ?'
        ).bind(asset.hostname || '', `%${asset.ip || ''}%`).first();

        if (existing) {
          await db.prepare(`
            UPDATE assets SET os = COALESCE(?, os), asset_type = COALESCE(?, asset_type), last_seen = datetime('now'), updated_at = datetime('now')
            WHERE id = ?
          `).bind(asset.os || null, asset.type || null, existing.id as string).run();
        } else {
          const assetId = crypto.randomUUID();
          await db.prepare(
            'INSERT INTO assets (id, hostname, ip_addresses, os, asset_type, last_seen) VALUES (?, ?, ?, ?, ?, datetime(\'now\'))'
          ).bind(assetId, asset.hostname, asset.ip, asset.os, asset.type || 'host').run();
          assetsDiscovered++;
        }
      }
    }

    // Update the task
    await db.prepare(`
      UPDATE scan_tasks
      SET status = ?, completed_at = datetime('now'), updated_at = datetime('now'),
          findings_count = ?, assets_discovered = ?, result_summary = ?, error_message = ?
      WHERE id = ?
    `).bind(
      status,
      findingsCount,
      assetsDiscovered,
      summary || null,
      error_message || null,
      taskId,
    ).run();

    // Update scanner task counters
    if (status === 'completed') {
      await db.prepare(
        "UPDATE scanner_registrations SET tasks_completed = tasks_completed + 1, updated_at = datetime('now') WHERE scanner_id = ?"
      ).bind(scannerInfo.scanner_id).run();
    } else if (status === 'failed') {
      await db.prepare(
        "UPDATE scanner_registrations SET tasks_failed = tasks_failed + 1, updated_at = datetime('now') WHERE scanner_id = ?"
      ).bind(scannerInfo.scanner_id).run();
    }

    // Check if parent scan is complete
    await updateScanFromTasks(db, task.scan_id);

    return c.json({
      message: 'Results received',
      task_id: taskId,
      findings_count: findingsCount,
      assets_discovered: assetsDiscovered,
    });
  } catch (error: unknown) {
    console.error('Submit results error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to submit results', message }, 500);
  }
});

// POST /heartbeat - Scanner heartbeat
scanner.post('/heartbeat', authenticateScanner, async (c) => {
  try {
    const scannerInfo = c.get('scanner')!;

    await c.env.DB.prepare(`
      UPDATE scanner_registrations SET last_heartbeat_at = datetime('now'), status = 'active', updated_at = datetime('now')
      WHERE id = ?
    `).bind(scannerInfo.id).run();

    // Return any configuration updates the scanner might need
    const activeTasks = await c.env.DB.prepare(
      "SELECT COUNT(*) as count FROM scan_tasks WHERE scanner_id = ? AND status IN ('assigned', 'running')"
    ).bind(scannerInfo.scanner_id).first<{ count: number }>();

    return c.json({
      status: 'ok',
      scanner_id: scannerInfo.scanner_id,
      active_tasks: activeTasks?.count || 0,
      server_time: new Date().toISOString(),
    });
  } catch (error: unknown) {
    console.error('Heartbeat error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to process heartbeat', message }, 500);
  }
});
