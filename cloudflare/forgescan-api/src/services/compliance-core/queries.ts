// ─────────────────────────────────────────────────────────────────────────────
// Compliance Core — Database Query Functions
// Extracted from services/compliance.ts for cross-product use
// ─────────────────────────────────────────────────────────────────────────────

import { FRAMEWORKS } from './frameworks';

/**
 * Seed all built-in frameworks and their controls into the database.
 * Uses upsert logic so it can be called multiple times safely.
 */
export async function seedFrameworks(db: D1Database): Promise<{ frameworks: number; controls: number }> {
  let totalControls = 0;

  for (const fw of FRAMEWORKS) {
    const existing = await db.prepare('SELECT id FROM compliance_frameworks WHERE short_name = ?').bind(fw.short_name).first();

    let frameworkId: string;
    if (existing) {
      frameworkId = existing.id as string;
    } else {
      frameworkId = crypto.randomUUID();
      await db.prepare(`
        INSERT INTO compliance_frameworks (id, name, short_name, version, description, controls_count)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(frameworkId, fw.name, fw.short_name, fw.version, fw.description, fw.controls.length).run();
    }

    for (const ctrl of fw.controls) {
      const ctrlExists = await db.prepare(
        'SELECT id FROM compliance_controls WHERE framework_id = ? AND control_id = ?'
      ).bind(frameworkId, ctrl.control_id).first();

      if (!ctrlExists) {
        await db.prepare(`
          INSERT INTO compliance_controls (id, framework_id, control_id, control_name, description, family, level)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(crypto.randomUUID(), frameworkId, ctrl.control_id, ctrl.name, ctrl.description, ctrl.family, ctrl.level || 'moderate').run();
        totalControls++;
      }
    }

    const count = await db.prepare('SELECT COUNT(*) as cnt FROM compliance_controls WHERE framework_id = ?').bind(frameworkId).first<{ cnt: number }>();
    await db.prepare('UPDATE compliance_frameworks SET controls_count = ?, updated_at = datetime(\'now\') WHERE id = ?').bind(count?.cnt || 0, frameworkId).run();
  }

  return { frameworks: FRAMEWORKS.length, controls: totalControls };
}

/**
 * Get compliance status summary for a single framework.
 */
export async function getFrameworkCompliance(db: D1Database, frameworkId: string): Promise<{
  total_controls: number;
  compliant: number;
  non_compliant: number;
  partial: number;
  not_assessed: number;
  compliance_percentage: number;
}> {
  const totalResult = await db.prepare(
    'SELECT COUNT(*) as total FROM compliance_controls WHERE framework_id = ?'
  ).bind(frameworkId).first<{ total: number }>();
  const total = totalResult?.total || 0;

  const mappingStats = await db.prepare(`
    SELECT
      SUM(CASE WHEN status = 'compliant' THEN 1 ELSE 0 END) as compliant,
      SUM(CASE WHEN status = 'non_compliant' THEN 1 ELSE 0 END) as non_compliant,
      SUM(CASE WHEN status = 'partial' THEN 1 ELSE 0 END) as partial,
      COUNT(DISTINCT control_id) as assessed
    FROM compliance_mappings WHERE framework_id = ?
  `).bind(frameworkId).first<{ compliant: number; non_compliant: number; partial: number; assessed: number }>();

  const compliant = mappingStats?.compliant || 0;
  const non_compliant = mappingStats?.non_compliant || 0;
  const partial = mappingStats?.partial || 0;
  const assessed = mappingStats?.assessed || 0;

  return {
    total_controls: total,
    compliant,
    non_compliant,
    partial,
    not_assessed: total - assessed,
    compliance_percentage: total > 0 ? Math.round((compliant / total) * 100) : 0,
  };
}

/**
 * Get gap analysis — every control with current compliance status and linked findings.
 */
export async function getGapAnalysis(db: D1Database, frameworkId: string): Promise<any[]> {
  const result = await db.prepare(`
    SELECT cc.control_id, cc.control_name, cc.family, cc.description,
           COALESCE(cm.status, 'not_assessed') as compliance_status,
           COUNT(DISTINCT cm.finding_id) as linked_findings,
           COUNT(DISTINCT cm.vulnerability_id) as linked_vulns
    FROM compliance_controls cc
    LEFT JOIN compliance_mappings cm ON cc.framework_id = cm.framework_id AND cc.control_id = cm.control_id
    WHERE cc.framework_id = ?
    GROUP BY cc.control_id
    ORDER BY cc.family, cc.control_id
  `).bind(frameworkId).all();

  return result.results || [];
}

/**
 * List all active compliance frameworks with their compliance summaries.
 */
export async function listFrameworks(db: D1Database): Promise<any[]> {
  const frameworks = await db.prepare(
    'SELECT * FROM compliance_frameworks WHERE is_active = 1 ORDER BY name'
  ).all();

  const results = [];
  for (const fw of frameworks.results || []) {
    const compliance = await getFrameworkCompliance(db, fw.id as string);
    results.push({ ...fw, ...compliance });
  }

  return results;
}

/**
 * Create or update a compliance mapping.
 */
export async function upsertMapping(db: D1Database, mapping: {
  finding_id?: string;
  vulnerability_id?: string;
  framework_id: string;
  control_id: string;
  status: string;
  evidence?: string;
  assessed_by?: string;
}): Promise<string> {
  const id = crypto.randomUUID();

  await db.prepare(`
    INSERT INTO compliance_mappings (id, finding_id, vulnerability_id, framework_id, control_id, status, evidence, assessed_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT DO NOTHING
  `).bind(
    id,
    mapping.finding_id || null,
    mapping.vulnerability_id || null,
    mapping.framework_id,
    mapping.control_id,
    mapping.status,
    mapping.evidence || null,
    mapping.assessed_by || null,
  ).run();

  return id;
}
