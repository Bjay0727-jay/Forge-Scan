// ─────────────────────────────────────────────────────────────────────────────
// ForgeML Correlation Engine — Statistical ML for ForgeSOC
//
// Implements:
//   1. Anomaly Detection  — Z-score on alert volume, flags spikes
//   2. Alert Clustering    — groups related alerts into incidents
//   3. Confidence Scoring  — multi-signal score for each alert
//
// Runs entirely on Cloudflare Workers (no external ML deps).
// ─────────────────────────────────────────────────────────────────────────────

// ─── 1. Anomaly Detection ────────────────────────────────────────────────────

export interface AnomalyResult {
  is_anomaly: boolean;
  current_rate: number;       // alerts in current window
  baseline_rate: number;      // mean alerts per window (historical)
  std_dev: number;
  z_score: number;
  severity: 'none' | 'elevated' | 'high' | 'critical';
  message: string;
  window_minutes: number;
  baseline_days: number;
}

/**
 * Detect anomalous alert volume by comparing current window
 * against a historical baseline using Z-score analysis.
 *
 * Uses hourly buckets over `baselineDays` to compute mean and stddev,
 * then compares the current `windowMinutes` bucket.
 */
export async function detectAlertVolumeAnomaly(
  db: D1Database,
  windowMinutes: number = 60,
  baselineDays: number = 30,
  zThreshold: number = 2.0
): Promise<AnomalyResult> {
  // Count alerts in current window
  const currentResult = await db
    .prepare(
      `SELECT COUNT(*) as cnt FROM soc_alerts
       WHERE created_at >= datetime('now', '-' || ? || ' minutes')`
    )
    .bind(windowMinutes)
    .first<{ cnt: number }>();

  const currentRate = currentResult?.cnt || 0;

  // Get hourly alert counts for baseline period
  const buckets = await db
    .prepare(
      `SELECT
         strftime('%Y-%m-%d %H', created_at) as hour_bucket,
         COUNT(*) as cnt
       FROM soc_alerts
       WHERE created_at >= datetime('now', '-' || ? || ' days')
         AND created_at < datetime('now', '-' || ? || ' minutes')
       GROUP BY hour_bucket`
    )
    .bind(baselineDays, windowMinutes)
    .all<{ hour_bucket: string; cnt: number }>();

  const counts = (buckets.results || []).map((b) => b.cnt);

  // If insufficient baseline data, can't detect anomaly
  if (counts.length < 24) {
    return {
      is_anomaly: false,
      current_rate: currentRate,
      baseline_rate: 0,
      std_dev: 0,
      z_score: 0,
      severity: 'none',
      message: 'Insufficient baseline data (need at least 24 hours)',
      window_minutes: windowMinutes,
      baseline_days: baselineDays,
    };
  }

  // Scale counts to match the window size (if window != 60min)
  const scaleFactor = windowMinutes / 60;

  const mean = counts.reduce((s, c) => s + c, 0) / counts.length * scaleFactor;
  const variance = counts.reduce((s, c) => s + (c * scaleFactor - mean) ** 2, 0) / counts.length;
  const stdDev = Math.sqrt(variance);

  // Z-score: how many standard deviations above baseline
  const zScore = stdDev > 0 ? (currentRate - mean) / stdDev : 0;

  let severity: AnomalyResult['severity'] = 'none';
  if (zScore >= 4) severity = 'critical';
  else if (zScore >= 3) severity = 'high';
  else if (zScore >= zThreshold) severity = 'elevated';

  const isAnomaly = zScore >= zThreshold;

  return {
    is_anomaly: isAnomaly,
    current_rate: currentRate,
    baseline_rate: Math.round(mean * 10) / 10,
    std_dev: Math.round(stdDev * 10) / 10,
    z_score: Math.round(zScore * 100) / 100,
    severity,
    message: isAnomaly
      ? `Alert volume spike detected: ${currentRate} alerts in last ${windowMinutes}min (baseline: ${Math.round(mean)}). Z-score: ${zScore.toFixed(1)}`
      : `Alert volume normal: ${currentRate} alerts in last ${windowMinutes}min (baseline: ${Math.round(mean)})`,
    window_minutes: windowMinutes,
    baseline_days: baselineDays,
  };
}

// ─── 2. Alert Clustering ─────────────────────────────────────────────────────

export interface AlertCluster {
  cluster_id: string;
  title: string;
  alert_ids: string[];
  alert_count: number;
  severity: string;
  common_source: string | null;
  common_type: string | null;
  common_assets: string[];
  common_tags: string[];
  common_mitre_tactic: string | null;
  confidence: number;
  suggested_incident_title: string;
}

interface ClusterableAlert {
  id: string;
  title: string;
  severity: string;
  source: string;
  alert_type: string;
  tags: string | null;
  correlation_id: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  affected_assets: string | null;
  source_finding_id: string | null;
  raw_data: string | null;
  created_at: string;
}

/**
 * Cluster unclustered alerts into related groups.
 *
 * Clustering signals (weighted):
 *  - Same correlation_id                → weight 1.0  (definitive link)
 *  - Same source_finding_id or CVE      → weight 0.9
 *  - Same MITRE tactic + technique      → weight 0.7
 *  - Same affected_assets               → weight 0.6
 *  - Same alert_type + source           → weight 0.4
 *  - Temporal proximity (< 30min)       → weight 0.3
 *  - Title keyword overlap              → weight 0.2
 */
export async function clusterAlerts(
  db: D1Database,
  windowHours: number = 24,
  minClusterSize: number = 2,
  similarityThreshold: number = 0.5
): Promise<AlertCluster[]> {
  // Fetch recent unclustered alerts
  const alerts = await db
    .prepare(
      `SELECT id, title, severity, source, alert_type, tags, correlation_id,
              mitre_tactic, mitre_technique, affected_assets,
              source_finding_id, raw_data, created_at
       FROM soc_alerts
       WHERE incident_id IS NULL
         AND status NOT IN ('closed', 'false_positive', 'resolved')
         AND created_at >= datetime('now', '-' || ? || ' hours')
       ORDER BY created_at DESC
       LIMIT 200`
    )
    .bind(windowHours)
    .all<ClusterableAlert>();

  const items = alerts.results || [];
  if (items.length < minClusterSize) return [];

  // Compute pairwise similarity matrix
  const n = items.length;
  const similarity: number[][] = Array.from({ length: n }, () => Array(n).fill(0));

  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const sim = computeAlertSimilarity(items[i], items[j]);
      similarity[i][j] = sim;
      similarity[j][i] = sim;
    }
  }

  // Single-linkage agglomerative clustering
  const assigned = new Set<number>();
  const clusters: number[][] = [];

  for (let i = 0; i < n; i++) {
    if (assigned.has(i)) continue;

    const cluster = [i];
    assigned.add(i);

    // BFS: add all alerts connected by similarity >= threshold
    const queue = [i];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      for (let j = 0; j < n; j++) {
        if (assigned.has(j)) continue;
        if (similarity[curr][j] >= similarityThreshold) {
          cluster.push(j);
          assigned.add(j);
          queue.push(j);
        }
      }
    }

    if (cluster.length >= minClusterSize) {
      clusters.push(cluster);
    }
  }

  // Build cluster metadata
  return clusters.map((indices) => {
    const clusterAlerts = indices.map((i) => items[i]);
    const alertIds = clusterAlerts.map((a) => a.id);

    // Determine highest severity
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const severity = sevOrder.find((s) => clusterAlerts.some((a) => a.severity === s)) || 'medium';

    // Find common attributes
    const sources = clusterAlerts.map((a) => a.source);
    const types = clusterAlerts.map((a) => a.alert_type);
    const tactics = clusterAlerts.map((a) => a.mitre_tactic).filter(Boolean);

    const commonSource = allSame(sources) ? sources[0] : null;
    const commonType = allSame(types) ? types[0] : null;
    const commonTactic = allSame(tactics) && tactics.length > 0 ? tactics[0] : null;

    // Gather affected assets across the cluster
    const allAssets = new Set<string>();
    for (const a of clusterAlerts) {
      if (a.affected_assets) {
        try {
          const assets = JSON.parse(a.affected_assets);
          if (Array.isArray(assets)) assets.forEach((x: string) => allAssets.add(x));
        } catch { /* ignore */ }
      }
    }

    // Gather tags
    const allTags = new Set<string>();
    for (const a of clusterAlerts) {
      if (a.tags) {
        try {
          const tags = JSON.parse(a.tags);
          if (Array.isArray(tags)) tags.forEach((t: string) => allTags.add(t));
        } catch { /* ignore */ }
      }
    }

    // Compute cluster confidence (average pairwise similarity)
    let totalSim = 0;
    let pairCount = 0;
    for (let i = 0; i < indices.length; i++) {
      for (let j = i + 1; j < indices.length; j++) {
        totalSim += similarity[indices[i]][indices[j]];
        pairCount++;
      }
    }
    const confidence = pairCount > 0 ? Math.round((totalSim / pairCount) * 100) : 0;

    // Build suggested title
    const titleKeywords = extractCommonKeywords(clusterAlerts.map((a) => a.title));
    const suggestedTitle = titleKeywords.length > 0
      ? `Correlated: ${titleKeywords.join(', ')} (${alertIds.length} alerts)`
      : `${severity.charAt(0).toUpperCase() + severity.slice(1)} Alert Cluster (${alertIds.length} alerts)`;

    return {
      cluster_id: crypto.randomUUID(),
      title: suggestedTitle,
      alert_ids: alertIds,
      alert_count: alertIds.length,
      severity,
      common_source: commonSource,
      common_type: commonType,
      common_assets: Array.from(allAssets),
      common_tags: Array.from(allTags),
      common_mitre_tactic: commonTactic,
      confidence,
      suggested_incident_title: suggestedTitle,
    };
  });
}

/**
 * Auto-cluster and create incidents from alert clusters.
 */
export async function autoClusterAndEscalate(
  db: D1Database,
  windowHours: number = 24,
  minConfidence: number = 50
): Promise<{ clusters_found: number; incidents_created: number; alerts_linked: number }> {
  const clusters = await clusterAlerts(db, windowHours, 2, 0.5);

  let incidentsCreated = 0;
  let alertsLinked = 0;

  for (const cluster of clusters) {
    if (cluster.confidence < minConfidence) continue;

    // Create incident from cluster
    const incidentId = crypto.randomUUID();
    const priority = cluster.severity === 'critical' ? 1 : cluster.severity === 'high' ? 2 : 3;

    await db
      .prepare(
        `INSERT INTO soc_incidents (
          id, title, description, severity, status, priority, incident_type,
          alert_count, affected_asset_count, tags, mitre_tactics,
          started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'open', ?, 'security', ?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now'))`
      )
      .bind(
        incidentId,
        cluster.suggested_incident_title,
        `Auto-created by ForgeML correlation engine. Confidence: ${cluster.confidence}%. ` +
          `Clustered ${cluster.alert_count} related alerts based on shared attributes.`,
        cluster.severity,
        priority,
        cluster.alert_count,
        cluster.common_assets.length,
        JSON.stringify(cluster.common_tags),
        cluster.common_mitre_tactic ? JSON.stringify([cluster.common_mitre_tactic]) : null
      )
      .run();

    // Link alerts to incident
    for (const alertId of cluster.alert_ids) {
      await db
        .prepare('INSERT OR IGNORE INTO soc_alert_incidents (alert_id, incident_id) VALUES (?, ?)')
        .bind(alertId, incidentId)
        .run();

      await db
        .prepare(
          `UPDATE soc_alerts SET
            incident_id = ?,
            status = 'escalated',
            updated_at = datetime('now')
           WHERE id = ? AND incident_id IS NULL`
        )
        .bind(incidentId, alertId)
        .run();

      alertsLinked++;
    }

    // Create timeline entry
    await db
      .prepare(
        `INSERT INTO soc_incident_timeline (id, incident_id, action, description, metadata, created_at)
         VALUES (?, ?, 'created', ?, ?, datetime('now'))`
      )
      .bind(
        crypto.randomUUID(),
        incidentId,
        `Incident auto-created by ForgeML. ${cluster.alert_count} alerts clustered with ${cluster.confidence}% confidence.`,
        JSON.stringify({
          engine: 'forgeml',
          cluster_id: cluster.cluster_id,
          confidence: cluster.confidence,
          signals: {
            common_source: cluster.common_source,
            common_type: cluster.common_type,
            common_tactic: cluster.common_mitre_tactic,
            assets: cluster.common_assets.length,
          },
        })
      )
      .run();

    incidentsCreated++;
  }

  return {
    clusters_found: clusters.length,
    incidents_created: incidentsCreated,
    alerts_linked: alertsLinked,
  };
}

// ─── 3. Confidence Scoring ───────────────────────────────────────────────────

export interface ConfidenceBreakdown {
  score: number;                 // 0–100 final confidence
  level: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  signals: ConfidenceSignal[];
  explanation: string;
}

interface ConfidenceSignal {
  name: string;
  weight: number;
  value: number;         // 0–1 normalized
  contribution: number;  // weight * value
  detail: string;
}

/**
 * Compute a confidence score for a SOC alert based on multiple signals.
 *
 * Signals:
 *  - Severity weight             (critical=1.0, high=0.8, ...)
 *  - Source credibility           (RedOps exploitation > scan > manual)
 *  - Cross-reference validation   (has matching finding? CVE? CWE?)
 *  - MITRE ATT&CK mapping        (has tactic+technique mapped?)
 *  - Asset criticality            (is affected asset high-value?)
 *  - Temporal clustering          (part of a recent spike?)
 *  - Detection rule specificity   (how specific was the matching rule?)
 *  - Corroborating alerts         (other alerts share correlation_id?)
 */
export async function computeAlertConfidence(
  db: D1Database,
  alertId: string
): Promise<ConfidenceBreakdown> {
  const alert = await db
    .prepare('SELECT * FROM soc_alerts WHERE id = ?')
    .bind(alertId)
    .first<Record<string, unknown>>();

  if (!alert) {
    return { score: 0, level: 'informational', signals: [], explanation: 'Alert not found' };
  }

  const signals: ConfidenceSignal[] = [];

  // 1. Severity weight (15%)
  const sevWeights: Record<string, number> = { critical: 1.0, high: 0.8, medium: 0.5, low: 0.3, info: 0.1 };
  const sevValue = sevWeights[alert.severity as string] || 0.5;
  signals.push({
    name: 'severity',
    weight: 15,
    value: sevValue,
    contribution: 15 * sevValue,
    detail: `Alert severity: ${alert.severity}`,
  });

  // 2. Source credibility (20%)
  const sourceWeights: Record<string, number> = {
    forgeredops: 1.0,   // Exploitation confirmed = highest credibility
    forgescan: 0.8,     // Scanner detection
    detection_rule: 0.7,
    system: 0.5,
    manual: 0.4,
  };
  const sourceValue = sourceWeights[alert.source as string] || 0.5;
  signals.push({
    name: 'source_credibility',
    weight: 20,
    value: sourceValue,
    contribution: 20 * sourceValue,
    detail: `Source: ${alert.source} (credibility: ${Math.round(sourceValue * 100)}%)`,
  });

  // 3. Cross-reference validation (20%)
  let crossRefValue = 0;
  let crossRefDetail = 'No cross-reference';

  if (alert.source_finding_id) {
    const finding = await db
      .prepare('SELECT id, cvss_score, cve_id FROM findings WHERE id = ?')
      .bind(alert.source_finding_id)
      .first<{ id: string; cvss_score: number | null; cve_id: string | null }>();

    if (finding) {
      crossRefValue = 0.6;
      crossRefDetail = 'Linked to ForgeScan finding';
      if (finding.cve_id) {
        crossRefValue = 0.8;
        crossRefDetail = `Linked to finding with ${finding.cve_id}`;
      }
      if (finding.cvss_score && finding.cvss_score >= 9.0) {
        crossRefValue = 1.0;
        crossRefDetail = `Linked to ${finding.cve_id} (CVSS ${finding.cvss_score})`;
      }
    }
  }

  // Check RedOps validation
  if (alert.alert_type === 'exploitation' || (alert.source as string) === 'forgeredops') {
    crossRefValue = Math.max(crossRefValue, 0.9);
    crossRefDetail = 'Validated by RedOps exploitation';
  }

  signals.push({
    name: 'cross_reference',
    weight: 20,
    value: crossRefValue,
    contribution: 20 * crossRefValue,
    detail: crossRefDetail,
  });

  // 4. MITRE ATT&CK mapping (10%)
  const hasMapping = !!(alert.mitre_tactic && alert.mitre_technique);
  const hasTactic = !!alert.mitre_tactic;
  const mitreValue = hasMapping ? 1.0 : hasTactic ? 0.5 : 0;
  signals.push({
    name: 'mitre_mapping',
    weight: 10,
    value: mitreValue,
    contribution: 10 * mitreValue,
    detail: hasMapping
      ? `MITRE: ${alert.mitre_tactic} / ${alert.mitre_technique}`
      : hasTactic
        ? `MITRE tactic: ${alert.mitre_tactic}`
        : 'No MITRE mapping',
  });

  // 5. Asset criticality (10%)
  let assetValue = 0.3; // default: unknown assets
  let assetDetail = 'No affected assets identified';
  if (alert.affected_assets) {
    try {
      const assets = JSON.parse(alert.affected_assets as string);
      if (Array.isArray(assets) && assets.length > 0) {
        // Check if any affected asset is high-criticality
        const placeholders = assets.map(() => '?').join(',');
        const criticalAssets = await db
          .prepare(
            `SELECT COUNT(*) as cnt FROM assets
             WHERE (hostname IN (${placeholders}) OR ip_address IN (${placeholders}))
               AND criticality IN ('critical', 'high')`
          )
          .bind(...assets, ...assets)
          .first<{ cnt: number }>();

        if (criticalAssets && criticalAssets.cnt > 0) {
          assetValue = 1.0;
          assetDetail = `${criticalAssets.cnt} critical/high-value asset(s) affected`;
        } else {
          assetValue = 0.5;
          assetDetail = `${assets.length} asset(s) affected`;
        }
      }
    } catch { /* ignore parse errors */ }
  }
  signals.push({
    name: 'asset_criticality',
    weight: 10,
    value: assetValue,
    contribution: 10 * assetValue,
    detail: assetDetail,
  });

  // 6. Temporal clustering (10%)
  const nearbyAlerts = await db
    .prepare(
      `SELECT COUNT(*) as cnt FROM soc_alerts
       WHERE id != ?
         AND created_at BETWEEN datetime(?, '-30 minutes') AND datetime(?, '+30 minutes')
         AND (
           alert_type = ? OR source = ?
           ${alert.correlation_id ? "OR correlation_id = ?" : ""}
         )`
    )
    .bind(
      alertId,
      alert.created_at,
      alert.created_at,
      alert.alert_type,
      alert.source,
      ...(alert.correlation_id ? [alert.correlation_id] : [])
    )
    .first<{ cnt: number }>();

  const nearbyCount = nearbyAlerts?.cnt || 0;
  const temporalValue = Math.min(1.0, nearbyCount / 5); // 5+ nearby = full score
  signals.push({
    name: 'temporal_clustering',
    weight: 10,
    value: temporalValue,
    contribution: 10 * temporalValue,
    detail: nearbyCount > 0
      ? `${nearbyCount} related alert(s) within 30 minutes`
      : 'No temporally correlated alerts',
  });

  // 7. Corroborating evidence (15%)
  let corrobValue = 0;
  let corrobDetail = 'No corroborating alerts';

  if (alert.correlation_id) {
    const correlated = await db
      .prepare(
        'SELECT COUNT(*) as cnt FROM soc_alerts WHERE correlation_id = ? AND id != ?'
      )
      .bind(alert.correlation_id, alertId)
      .first<{ cnt: number }>();

    if (correlated && correlated.cnt > 0) {
      corrobValue = Math.min(1.0, correlated.cnt / 3);
      corrobDetail = `${correlated.cnt} corroborating alert(s) via correlation_id`;
    }
  }

  // Also check if this alert is part of an incident (additional corroboration)
  if (alert.incident_id) {
    const incidentAlerts = await db
      .prepare(
        'SELECT COUNT(*) as cnt FROM soc_alert_incidents WHERE incident_id = ?'
      )
      .bind(alert.incident_id)
      .first<{ cnt: number }>();

    if (incidentAlerts && incidentAlerts.cnt > 1) {
      corrobValue = Math.max(corrobValue, Math.min(1.0, incidentAlerts.cnt / 4));
      corrobDetail = `Part of incident with ${incidentAlerts.cnt} linked alerts`;
    }
  }

  signals.push({
    name: 'corroboration',
    weight: 15,
    value: corrobValue,
    contribution: 15 * corrobValue,
    detail: corrobDetail,
  });

  // Compute final score
  const totalWeight = signals.reduce((s, sig) => s + sig.weight, 0);
  const rawScore = signals.reduce((s, sig) => s + sig.contribution, 0);
  const score = Math.round(rawScore / totalWeight * 100);

  let level: ConfidenceBreakdown['level'] = 'informational';
  if (score >= 80) level = 'critical';
  else if (score >= 60) level = 'high';
  else if (score >= 40) level = 'medium';
  else if (score >= 20) level = 'low';

  const topSignals = signals
    .filter((s) => s.contribution > 0)
    .sort((a, b) => b.contribution - a.contribution)
    .slice(0, 3)
    .map((s) => s.detail);

  return {
    score,
    level,
    signals,
    explanation: `Confidence ${score}% (${level}). Key factors: ${topSignals.join('; ')}`,
  };
}

/**
 * Batch-compute confidence scores for all unscored recent alerts
 * and store in the confidence_score / confidence_level columns.
 */
export async function batchComputeConfidence(
  db: D1Database,
  limit: number = 50
): Promise<{ scored: number }> {
  const unscored = await db
    .prepare(
      `SELECT id FROM soc_alerts
       WHERE confidence_score IS NULL
         AND status NOT IN ('closed', 'false_positive')
       ORDER BY created_at DESC
       LIMIT ?`
    )
    .bind(limit)
    .all<{ id: string }>();

  let scored = 0;

  for (const alert of unscored.results || []) {
    try {
      const result = await computeAlertConfidence(db, alert.id);
      await db
        .prepare(
          `UPDATE soc_alerts SET
            confidence_score = ?,
            confidence_level = ?,
            confidence_signals = ?,
            updated_at = datetime('now')
           WHERE id = ?`
        )
        .bind(result.score, result.level, JSON.stringify(result.signals), alert.id)
        .run();
      scored++;
    } catch {
      // Skip alerts that fail to score
    }
  }

  return { scored };
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

function computeAlertSimilarity(a: ClusterableAlert, b: ClusterableAlert): number {
  let score = 0;
  let totalWeight = 0;

  // Correlation ID match (definitive link)
  const w1 = 1.0;
  totalWeight += w1;
  if (a.correlation_id && a.correlation_id === b.correlation_id) {
    score += w1;
  }

  // Same source finding
  const w2 = 0.9;
  totalWeight += w2;
  if (a.source_finding_id && a.source_finding_id === b.source_finding_id) {
    score += w2;
  } else {
    // Check for shared CVE in raw_data
    const aCve = extractCve(a.raw_data);
    const bCve = extractCve(b.raw_data);
    if (aCve && bCve && aCve === bCve) {
      score += w2 * 0.8;
    }
  }

  // MITRE tactic + technique match
  const w3 = 0.7;
  totalWeight += w3;
  if (a.mitre_tactic && a.mitre_tactic === b.mitre_tactic) {
    score += w3 * 0.5;
    if (a.mitre_technique && a.mitre_technique === b.mitre_technique) {
      score += w3 * 0.5;
    }
  }

  // Shared affected assets
  const w4 = 0.6;
  totalWeight += w4;
  const assetsA = parseJsonArray(a.affected_assets);
  const assetsB = parseJsonArray(b.affected_assets);
  if (assetsA.length > 0 && assetsB.length > 0) {
    const overlap = assetsA.filter((x) => assetsB.includes(x)).length;
    const union = new Set([...assetsA, ...assetsB]).size;
    if (union > 0) score += w4 * (overlap / union);
  }

  // Same alert_type + source
  const w5 = 0.4;
  totalWeight += w5;
  if (a.alert_type === b.alert_type) score += w5 * 0.5;
  if (a.source === b.source) score += w5 * 0.5;

  // Temporal proximity (< 30 min)
  const w6 = 0.3;
  totalWeight += w6;
  const timeDiffMs = Math.abs(new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
  const thirtyMin = 30 * 60 * 1000;
  if (timeDiffMs < thirtyMin) {
    score += w6 * (1 - timeDiffMs / thirtyMin);
  }

  // Title keyword overlap
  const w7 = 0.2;
  totalWeight += w7;
  const kwA = extractKeywords(a.title);
  const kwB = extractKeywords(b.title);
  if (kwA.length > 0 && kwB.length > 0) {
    const overlap = kwA.filter((w) => kwB.includes(w)).length;
    const union = new Set([...kwA, ...kwB]).size;
    if (union > 0) score += w7 * (overlap / union);
  }

  return totalWeight > 0 ? score / totalWeight : 0;
}

function extractCve(rawData: string | null): string | null {
  if (!rawData) return null;
  const match = rawData.match(/CVE-\d{4}-\d{4,}/);
  return match ? match[0] : null;
}

function parseJsonArray(json: string | null): string[] {
  if (!json) return [];
  try {
    const arr = JSON.parse(json);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function extractKeywords(title: string): string[] {
  const stopWords = new Set(['the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 'is', 'and', 'or', 'not', 'with', 'from', 'by']);
  return title
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .split(/\s+/)
    .filter((w) => w.length > 2 && !stopWords.has(w));
}

function extractCommonKeywords(titles: string[]): string[] {
  if (titles.length === 0) return [];
  const allKeywords = titles.map(extractKeywords);
  const first = allKeywords[0];
  return first
    .filter((kw) => allKeywords.every((kws) => kws.includes(kw)))
    .slice(0, 4);
}

function allSame<T>(arr: T[]): boolean {
  return arr.length > 0 && arr.every((v) => v === arr[0]);
}
