// Scan Orchestrator Service
// Converts user-created scans into task records for the scanner bridge.
// When a user starts a scan, the orchestrator creates scan_tasks that
// the Rust scanner engine can poll and execute.

export interface ScanTask {
  id: string;
  scan_id: string;
  scanner_id: string | null;
  task_type: string;
  task_payload: string;
  status: string;
  priority: number;
  result_summary: string | null;
  findings_count: number;
  assets_discovered: number;
  error_message: string | null;
  retry_count: number;
  max_retries: number;
  assigned_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

interface ScanRecord {
  id: string;
  name: string;
  scan_type: string;
  targets: string;
  config: string;
  status: string;
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

// --- Create tasks for a scan ---
export async function createTasksForScan(
  db: D1Database,
  scanId: string
): Promise<string[]> {
  const scan = await db.prepare(
    'SELECT * FROM scans WHERE id = ?'
  ).bind(scanId).first<ScanRecord>();

  if (!scan) {
    throw new Error(`Scan not found: ${scanId}`);
  }

  const targets: string[] = scan.targets ? JSON.parse(scan.targets) : [];
  const config: Record<string, unknown> = scan.config ? JSON.parse(scan.config) : {};
  const taskIds: string[] = [];

  if (scan.scan_type === 'network') {
    // Network scans: create a single task with targets and port configuration
    const taskId = crypto.randomUUID();
    const payload = JSON.stringify({
      scan_type: 'network',
      targets,
      ports: config.ports || config.port_range || '1-1024',
      protocol: config.protocol || 'tcp',
      scan_speed: config.scan_speed || 'normal',
      ...config,
    });

    await db.prepare(`
      INSERT INTO scan_tasks (id, scan_id, task_type, task_payload, status, priority, created_at, updated_at)
      VALUES (?, ?, 'network_scan', ?, 'queued', ?, datetime('now'), datetime('now'))
    `).bind(
      taskId,
      scanId,
      payload,
      config.priority !== undefined ? Number(config.priority) : 5
    ).run();

    taskIds.push(taskId);
  } else {
    // All other scan types: create a single task with the full config
    const taskId = crypto.randomUUID();
    const taskType = `${scan.scan_type}_scan`;
    const payload = JSON.stringify({
      scan_type: scan.scan_type,
      targets,
      ...config,
    });

    await db.prepare(`
      INSERT INTO scan_tasks (id, scan_id, task_type, task_payload, status, priority, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'queued', ?, datetime('now'), datetime('now'))
    `).bind(
      taskId,
      scanId,
      taskType,
      payload,
      config.priority !== undefined ? Number(config.priority) : 5
    ).run();

    taskIds.push(taskId);
  }

  // Update the scan status to 'queued' now that tasks have been created
  if (taskIds.length > 0) {
    await db.prepare(`
      UPDATE scans SET status = 'queued', updated_at = datetime('now')
      WHERE id = ?
    `).bind(scanId).run();
  }

  return taskIds;
}

// --- Get all tasks for a scan ---
export async function getTasksForScan(
  db: D1Database,
  scanId: string
): Promise<ScanTask[]> {
  const result = await db.prepare(
    'SELECT * FROM scan_tasks WHERE scan_id = ? ORDER BY created_at ASC'
  ).bind(scanId).all<ScanTask>();

  return result.results || [];
}

// --- Update scan status based on aggregated task results ---
export async function updateScanFromTasks(
  db: D1Database,
  scanId: string
): Promise<void> {
  const tasks = await db.prepare(
    'SELECT status, findings_count, assets_discovered FROM scan_tasks WHERE scan_id = ?'
  ).bind(scanId).all<{ status: string; findings_count: number; assets_discovered: number }>();

  const taskList = tasks.results || [];

  if (taskList.length === 0) {
    return;
  }

  // Aggregate counts across all tasks
  let totalFindings = 0;
  let totalAssets = 0;
  let allCompleted = true;
  let anyFailed = false;
  let anyRunning = false;

  for (const task of taskList) {
    totalFindings += task.findings_count || 0;
    totalAssets += task.assets_discovered || 0;

    if (task.status === 'running' || task.status === 'assigned') {
      anyRunning = true;
      allCompleted = false;
    } else if (task.status === 'failed') {
      anyFailed = true;
      allCompleted = false;
    } else if (task.status !== 'completed') {
      // queued or cancelled tasks also mean not all completed
      allCompleted = false;
    }
  }

  if (allCompleted) {
    // All tasks finished successfully
    await db.prepare(`
      UPDATE scans SET
        status = 'completed',
        findings_count = ?,
        assets_count = ?,
        completed_at = datetime('now'),
        updated_at = datetime('now')
      WHERE id = ?
    `).bind(totalFindings, totalAssets, scanId).run();
  } else if (anyFailed && !anyRunning) {
    // At least one task failed and no tasks are still running
    await db.prepare(`
      UPDATE scans SET
        status = 'failed',
        findings_count = ?,
        assets_count = ?,
        completed_at = datetime('now'),
        updated_at = datetime('now')
      WHERE id = ?
    `).bind(totalFindings, totalAssets, scanId).run();
  } else if (anyRunning) {
    // Tasks still in progress - update counts but keep status as running
    await db.prepare(`
      UPDATE scans SET
        status = 'running',
        findings_count = ?,
        assets_count = ?,
        updated_at = datetime('now')
      WHERE id = ?
    `).bind(totalFindings, totalAssets, scanId).run();
  }
}

// --- Cancel all active tasks for a scan ---
export async function cancelScanTasks(
  db: D1Database,
  scanId: string
): Promise<number> {
  const result = await db.prepare(`
    UPDATE scan_tasks SET
      status = 'cancelled',
      completed_at = datetime('now'),
      updated_at = datetime('now')
    WHERE scan_id = ?
      AND status IN ('queued', 'assigned', 'running')
  `).bind(scanId).run();

  return result.meta.changes || 0;
}
