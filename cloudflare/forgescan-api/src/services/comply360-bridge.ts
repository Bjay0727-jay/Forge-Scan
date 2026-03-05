/**
 * ForgeComply 360 Bridge
 *
 * Connects Forge-Scan findings/events to the compliance system:
 *   - Auto-maps findings to NIST/CIS controls via CWE
 *   - Generates POA&M entries from critical/high findings
 *   - Creates compliance evidence links from scan events
 *   - Updates control_mappings column on findings for ForgeComply correlation
 */

import { mapFindingToControls, generatePOAMEntry } from './compliance-core/mapping';
import type { ForgeEvent } from './event-bus/types';

export interface ComplianceBridgeResult {
  controls_mapped: number;
  poam_created: number;
  evidence_linked: number;
  findings_updated: number;
  errors: string[];
}

/**
 * Handle a scan.completed event: map all new findings from the scan to controls,
 * generate POA&M for critical/high, and create evidence links.
 */
export async function handleScanCompleted(
  db: D1Database,
  event: ForgeEvent,
  config: Record<string, unknown>,
): Promise<ComplianceBridgeResult> {
  const result: ComplianceBridgeResult = {
    controls_mapped: 0,
    poam_created: 0,
    evidence_linked: 0,
    findings_updated: 0,
    errors: [],
  };

  const orgId = (event.payload.org_id as string) || (event.metadata?.org_id as string) || null;
  const scanId = event.payload.scan_id as string;
  const autoPoam = config.auto_poam !== false;
  const autoEvidence = config.auto_evidence !== false;

  if (!orgId) return result;

  // Get all open findings that lack control_mappings
  let findingsQuery = `
    SELECT id, title, severity, cve_id, solution, metadata, vendor_id
    FROM findings
    WHERE org_id = ? AND state = 'open'
      AND (control_mappings IS NULL OR control_mappings = '[]')`;
  const params: any[] = [orgId];

  if (scanId) {
    findingsQuery += ' AND scan_id = ?';
    params.push(scanId);
  }
  findingsQuery += ' LIMIT 500';

  const findings = await db.prepare(findingsQuery).bind(...params).all<{
    id: string; title: string; severity: string; cve_id: string;
    solution: string; metadata: string; vendor_id: string;
  }>();

  for (const finding of findings.results || []) {
    try {
      // Extract CWE from metadata
      let meta: any = {};
      try { meta = JSON.parse(finding.metadata || '{}'); } catch { /* empty */ }
      const cweId = meta.cwe || meta.cwe_id || null;

      // Map finding to compliance controls
      const controls = mapFindingToControls({
        cwe_id: cweId,
        nist_controls: meta.nist_controls,
        attack_category: meta.attack_category,
      });

      if (controls.length > 0) {
        // Update the finding with control mappings
        await db.prepare(
          'UPDATE findings SET control_mappings = ?, updated_at = datetime(\'now\') WHERE id = ?'
        ).bind(JSON.stringify(controls), finding.id).run();
        result.controls_mapped += controls.length;
        result.findings_updated++;

        // Update plugin_id and cvss3_score if available from metadata
        if (meta.plugin_id || meta.cvss3_score) {
          const updates: string[] = [];
          const updateParams: any[] = [];
          if (meta.plugin_id) {
            updates.push('plugin_id = ?');
            updateParams.push(meta.plugin_id);
          }
          if (meta.cvss3_score) {
            updates.push('cvss3_score = ?');
            updateParams.push(meta.cvss3_score);
          }
          if (updates.length > 0) {
            updateParams.push(finding.id);
            await db.prepare(
              `UPDATE findings SET ${updates.join(', ')} WHERE id = ?`
            ).bind(...updateParams).run();
          }
        }
      }

      // Auto-generate POA&M for critical/high findings
      if (autoPoam && (finding.severity === 'critical' || finding.severity === 'high')) {
        const existingPoam = await db.prepare(
          'SELECT id FROM poam_items WHERE finding_id = ? AND org_id = ? AND status != \'completed\''
        ).bind(finding.id, orgId).first();

        if (!existingPoam) {
          const poamEntry = generatePOAMEntry({
            id: finding.id,
            title: finding.title,
            cwe_id: cweId,
            severity: finding.severity,
            remediation: finding.solution,
          });

          await db.prepare(`
            INSERT INTO poam_items (
              id, org_id, finding_id, finding_title, weakness, severity, controls,
              remediation, remediation_effort, scheduled_completion, status, milestones
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
          `).bind(
            poamEntry.id, orgId, finding.id, poamEntry.finding_title,
            poamEntry.weakness, poamEntry.severity,
            JSON.stringify(poamEntry.controls),
            poamEntry.remediation, poamEntry.remediation_effort,
            poamEntry.scheduled_completion,
            JSON.stringify(poamEntry.milestones),
          ).run();
          result.poam_created++;
        }
      }
    } catch (err) {
      result.errors.push(`Finding ${finding.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // Create compliance evidence link for this scan event
  if (autoEvidence) {
    try {
      await db.prepare(`
        INSERT INTO compliance_evidence_links (id, org_id, event_id, evidence_type, description)
        VALUES (?, ?, ?, 'scan_result', ?)
      `).bind(
        crypto.randomUUID(), orgId, event.id,
        `Scan completed: ${findings.results?.length || 0} findings processed, ${result.controls_mapped} controls mapped`,
      ).run();
      result.evidence_linked++;
    } catch (err) {
      result.errors.push(`Evidence link: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return result;
}

/**
 * Handle a vulnerability.detected event: map a single finding to controls
 * and create evidence links.
 */
export async function handleVulnerabilityDetected(
  db: D1Database,
  event: ForgeEvent,
  config: Record<string, unknown>,
): Promise<ComplianceBridgeResult> {
  const result: ComplianceBridgeResult = {
    controls_mapped: 0,
    poam_created: 0,
    evidence_linked: 0,
    findings_updated: 0,
    errors: [],
  };

  const orgId = (event.payload.org_id as string) || (event.metadata?.org_id as string) || null;
  const findingId = event.payload.finding_id as string;
  const autoEvidence = config.auto_evidence !== false;

  if (!orgId || !findingId) return result;

  try {
    const finding = await db.prepare(
      'SELECT id, title, severity, cve_id, solution, metadata FROM findings WHERE id = ? AND org_id = ?'
    ).bind(findingId, orgId).first<{
      id: string; title: string; severity: string; cve_id: string;
      solution: string; metadata: string;
    }>();

    if (!finding) return result;

    let meta: any = {};
    try { meta = JSON.parse(finding.metadata || '{}'); } catch { /* empty */ }
    const cweId = meta.cwe || meta.cwe_id || (event.payload.cwe_id as string) || null;

    const controls = mapFindingToControls({
      cwe_id: cweId,
      nist_controls: meta.nist_controls,
    });

    if (controls.length > 0) {
      await db.prepare(
        'UPDATE findings SET control_mappings = ?, updated_at = datetime(\'now\') WHERE id = ?'
      ).bind(JSON.stringify(controls), finding.id).run();
      result.controls_mapped = controls.length;
      result.findings_updated = 1;
    }

    // Create evidence link
    if (autoEvidence) {
      // Link to the RA-5 control (Vulnerability Scanning) by default
      const ra5Control = controls.find((c) => c.control_id === 'RA-5');
      await db.prepare(`
        INSERT INTO compliance_evidence_links (id, org_id, event_id, control_id, finding_id, evidence_type, description)
        VALUES (?, ?, ?, ?, ?, 'vulnerability_finding', ?)
      `).bind(
        crypto.randomUUID(), orgId, event.id,
        ra5Control ? 'RA-5' : null, findingId,
        `${finding.severity} vulnerability: ${finding.title}`,
      ).run();
      result.evidence_linked = 1;
    }
  } catch (err) {
    result.errors.push(`${err instanceof Error ? err.message : String(err)}`);
  }

  return result;
}
