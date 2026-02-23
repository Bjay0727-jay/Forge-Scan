import { Hono } from 'hono';

interface Env { DB: D1Database; STORAGE: R2Bucket; CACHE: KVNamespace; JWT_SECRET: string }
interface AuthUser { id: string; email: string; role: string; display_name: string }
type Ctx = { Bindings: Env; Variables: { user: AuthUser } };

const threatIntel = new Hono<Ctx>();

// ─── Built-in Feed Sources ─────────────────────────────────────────────────
// Public/free threat intel sources that can be polled without credentials

const BUILTIN_FEEDS = [
  { name: 'CISA Known Exploited Vulnerabilities', feed_type: 'vulnerability', format: 'json', source_url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', description: 'CISA KEV catalog of actively exploited CVEs' },
  { name: 'Abuse.ch URLhaus', feed_type: 'indicator', format: 'csv', source_url: 'https://urlhaus.abuse.ch/downloads/csv_recent/', description: 'Recently reported malicious URLs' },
  { name: 'Abuse.ch Feodo Tracker', feed_type: 'indicator', format: 'csv', source_url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv', description: 'Botnet C2 IP blocklist' },
  { name: 'Abuse.ch SSL Blocklist', feed_type: 'indicator', format: 'csv', source_url: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', description: 'SSL certificate abuse IP blocklist' },
  { name: 'AlienVault OTX Pulse', feed_type: 'indicator', format: 'json', source_url: 'https://otx.alienvault.com/api/v1/pulses/subscribed', description: 'AlienVault OTX community threat pulses' },
  { name: 'Emerging Threats Rules', feed_type: 'indicator', format: 'csv', source_url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', description: 'Compromised IP addresses' },
  { name: 'PhishTank Verified', feed_type: 'indicator', format: 'json', source_url: 'http://data.phishtank.com/data/online-valid.json', description: 'Verified active phishing URLs' },
  { name: 'MITRE ATT&CK', feed_type: 'apt', format: 'stix', source_url: 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json', description: 'MITRE ATT&CK enterprise techniques and groups' },
];

// ─── Feeds CRUD ────────────────────────────────────────────────────────────

threatIntel.get('/feeds', async (c) => {
  const { enabled } = c.req.query();
  const where = enabled !== undefined ? `WHERE enabled = ${enabled === 'true' ? 1 : 0}` : '';
  const feeds = await c.env.DB.prepare(`SELECT * FROM threat_intel_feeds ${where} ORDER BY updated_at DESC`).all();
  return c.json({ items: feeds.results || [], total: (feeds.results || []).length });
});

threatIntel.post('/feeds', async (c) => {
  try {
    const body = await c.req.json();
    const { name, feed_type, source_url, format, auth_config, poll_interval_minutes } = body;
    if (!name || !feed_type) return c.json({ error: 'name and feed_type are required' }, 400);

    const user = c.get('user');
    const id = crypto.randomUUID();

    await c.env.DB.prepare(`
      INSERT INTO threat_intel_feeds (id, name, feed_type, source_url, format, auth_config, poll_interval_minutes, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, name, feed_type, source_url || null, format || 'json', auth_config ? JSON.stringify(auth_config) : null, poll_interval_minutes || 60, user.id).run();

    const feed = await c.env.DB.prepare('SELECT * FROM threat_intel_feeds WHERE id = ?').bind(id).first();
    return c.json(feed, 201);
  } catch (err) {
    console.error('Create feed error:', err);
    return c.json({ error: 'Failed to create feed' }, 500);
  }
});

threatIntel.get('/feeds/:id', async (c) => {
  const id = c.req.param('id');
  const feed = await c.env.DB.prepare('SELECT * FROM threat_intel_feeds WHERE id = ?').bind(id).first();
  if (!feed) return c.json({ error: 'Feed not found' }, 404);

  const indicatorCount = await c.env.DB.prepare('SELECT COUNT(*) as count FROM threat_intel_indicators WHERE feed_id = ? AND is_active = 1').bind(id).first<{ count: number }>();
  const matchCount = await c.env.DB.prepare(`
    SELECT COUNT(*) as count FROM threat_intel_matches tm
    JOIN threat_intel_indicators ti ON tm.indicator_id = ti.id WHERE ti.feed_id = ?
  `).bind(id).first<{ count: number }>();

  const recentIndicators = await c.env.DB.prepare(
    'SELECT * FROM threat_intel_indicators WHERE feed_id = ? ORDER BY created_at DESC LIMIT 20'
  ).bind(id).all();

  return c.json({ ...feed, active_indicators: indicatorCount?.count || 0, total_matches: matchCount?.count || 0, recent_indicators: recentIndicators.results || [] });
});

threatIntel.put('/feeds/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();
  const { name, feed_type, source_url, format, auth_config, poll_interval_minutes, enabled } = body;

  const updates: string[] = [];
  const values: (string | number | null)[] = [];

  if (name !== undefined) { updates.push('name = ?'); values.push(name); }
  if (feed_type !== undefined) { updates.push('feed_type = ?'); values.push(feed_type); }
  if (source_url !== undefined) { updates.push('source_url = ?'); values.push(source_url); }
  if (format !== undefined) { updates.push('format = ?'); values.push(format); }
  if (auth_config !== undefined) { updates.push('auth_config = ?'); values.push(JSON.stringify(auth_config)); }
  if (poll_interval_minutes !== undefined) { updates.push('poll_interval_minutes = ?'); values.push(poll_interval_minutes); }
  if (enabled !== undefined) { updates.push('enabled = ?'); values.push(enabled ? 1 : 0); }

  if (updates.length === 0) return c.json({ error: 'No fields to update' }, 400);
  updates.push("updated_at = datetime('now')");
  values.push(id);

  const result = await c.env.DB.prepare(`UPDATE threat_intel_feeds SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
  if (!result.meta.changes) return c.json({ error: 'Feed not found' }, 404);

  const feed = await c.env.DB.prepare('SELECT * FROM threat_intel_feeds WHERE id = ?').bind(id).first();
  return c.json(feed);
});

threatIntel.delete('/feeds/:id', async (c) => {
  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT id FROM threat_intel_feeds WHERE id = ?').bind(id).first();
  if (!existing) return c.json({ error: 'Feed not found' }, 404);
  await c.env.DB.prepare('DELETE FROM threat_intel_feeds WHERE id = ?').bind(id).run();
  return c.json({ message: 'Feed and associated indicators deleted' });
});

// ─── Feed Sync (Pull) ─────────────────────────────────────────────────────

// Simulate feed sync — in production, fetches from source_url and parses indicators
threatIntel.post('/feeds/:id/sync', async (c) => {
  const feedId = c.req.param('id');
  const feed = await c.env.DB.prepare('SELECT * FROM threat_intel_feeds WHERE id = ?').bind(feedId).first();
  if (!feed) return c.json({ error: 'Feed not found' }, 404);

  // Generate simulated indicators based on feed type
  const indicators = generateIndicators(feedId, feed.feed_type as string, feed.name as string);

  for (const ind of indicators) {
    await c.env.DB.prepare(`
      INSERT OR REPLACE INTO threat_intel_indicators (id, feed_id, indicator_type, indicator_value, severity, confidence, tlp, tags, context, source_ref, first_seen, last_seen, expires_at, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now', '+30 days'), 1)
    `).bind(ind.id, feedId, ind.type, ind.value, ind.severity, ind.confidence, ind.tlp, JSON.stringify(ind.tags), JSON.stringify(ind.context), ind.ref).run();
  }

  await c.env.DB.prepare(`
    UPDATE threat_intel_feeds SET last_fetch_at = datetime('now'), last_fetch_status = 'success',
      indicators_count = (SELECT COUNT(*) FROM threat_intel_indicators WHERE feed_id = ? AND is_active = 1),
      updated_at = datetime('now')
    WHERE id = ?
  `).bind(feedId, feedId).run();

  return c.json({
    feed_id: feedId, status: 'success',
    indicators_imported: indicators.length,
    message: `Synced ${indicators.length} indicators from ${feed.name}`,
  });
});

// ─── Indicators ────────────────────────────────────────────────────────────

threatIntel.get('/indicators', async (c) => {
  const { page = '1', page_size = '50', type, severity, feed_id, search, active } = c.req.query();
  const pageNum = parseInt(page);
  const limit = Math.min(parseInt(page_size), 200);
  const offset = (pageNum - 1) * limit;

  const conditions: string[] = [];
  const params: (string | number)[] = [];

  if (type) { conditions.push('indicator_type = ?'); params.push(type); }
  if (severity) { conditions.push('severity = ?'); params.push(severity); }
  if (feed_id) { conditions.push('feed_id = ?'); params.push(feed_id); }
  if (search) { conditions.push('indicator_value LIKE ?'); params.push(`%${search}%`); }
  if (active !== undefined) { conditions.push('is_active = ?'); params.push(active === 'true' ? 1 : 0); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const total = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM threat_intel_indicators ${where}`).bind(...params).first<{ count: number }>();
  const indicators = await c.env.DB.prepare(`
    SELECT ti.*, f.name as feed_name FROM threat_intel_indicators ti
    JOIN threat_intel_feeds f ON f.id = ti.feed_id
    ${where} ORDER BY ti.last_seen DESC LIMIT ? OFFSET ?
  `).bind(...params, limit, offset).all();

  return c.json({ items: indicators.results || [], total: total?.count || 0, page: pageNum, page_size: limit, total_pages: Math.ceil((total?.count || 0) / limit) });
});

// ─── Threat Correlation (Match indicators against internal data) ───────────

threatIntel.post('/correlate', async (c) => {
  const db = c.env.DB;

  // Get active indicators
  const indicators = await db.prepare(
    'SELECT id, indicator_type, indicator_value, severity, confidence FROM threat_intel_indicators WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > datetime(\'now\'))'
  ).all();

  let matchCount = 0;
  const matches: Array<{ indicator: string; type: string; entity: string; entity_id: string }> = [];

  for (const ind of indicators.results || []) {
    const indType = ind.indicator_type as string;
    const indValue = ind.indicator_value as string;
    const indId = ind.id as string;

    // Match IPs against asset ip_addresses
    if (indType === 'ip' || indType === 'cidr') {
      const assetMatch = await db.prepare(
        "SELECT id, hostname FROM assets WHERE ip_addresses LIKE ?"
      ).bind(`%${indValue}%`).first<{ id: string; hostname: string }>();

      if (assetMatch) {
        const existing = await db.prepare(
          'SELECT id FROM threat_intel_matches WHERE indicator_id = ? AND matched_entity_id = ?'
        ).bind(indId, assetMatch.id).first();

        if (!existing) {
          await db.prepare(`
            INSERT INTO threat_intel_matches (id, indicator_id, match_type, matched_entity_type, matched_entity_id, match_confidence)
            VALUES (?, ?, 'asset_ip', 'asset', ?, ?)
          `).bind(crypto.randomUUID(), indId, assetMatch.id, ind.confidence as number).run();
          matches.push({ indicator: indValue, type: 'asset_ip', entity: 'asset', entity_id: assetMatch.id });
          matchCount++;
        }
      }
    }

    // Match CVEs against findings
    if (indType === 'cve') {
      const findingMatch = await db.prepare(
        "SELECT id, title FROM findings WHERE cve_id = ? AND state NOT IN ('resolved','false_positive') LIMIT 1"
      ).bind(indValue).first<{ id: string; title: string }>();

      if (findingMatch) {
        const existing = await db.prepare(
          'SELECT id FROM threat_intel_matches WHERE indicator_id = ? AND matched_entity_id = ?'
        ).bind(indId, findingMatch.id).first();

        if (!existing) {
          await db.prepare(`
            INSERT INTO threat_intel_matches (id, indicator_id, match_type, matched_entity_type, matched_entity_id, match_confidence)
            VALUES (?, ?, 'finding_cve', 'finding', ?, ?)
          `).bind(crypto.randomUUID(), indId, findingMatch.id, ind.confidence as number).run();
          matches.push({ indicator: indValue, type: 'finding_cve', entity: 'finding', entity_id: findingMatch.id });
          matchCount++;
        }
      }
    }

    // Match domains against assets
    if (indType === 'domain') {
      const domainMatch = await db.prepare(
        "SELECT id, fqdn FROM assets WHERE fqdn LIKE ?"
      ).bind(`%${indValue}%`).first<{ id: string; fqdn: string }>();

      if (domainMatch) {
        const existing = await db.prepare(
          'SELECT id FROM threat_intel_matches WHERE indicator_id = ? AND matched_entity_id = ?'
        ).bind(indId, domainMatch.id).first();

        if (!existing) {
          await db.prepare(`
            INSERT INTO threat_intel_matches (id, indicator_id, match_type, matched_entity_type, matched_entity_id, match_confidence)
            VALUES (?, ?, 'domain_match', 'asset', ?, ?)
          `).bind(crypto.randomUUID(), indId, domainMatch.id, ind.confidence as number).run();
          matches.push({ indicator: indValue, type: 'domain_match', entity: 'asset', entity_id: domainMatch.id });
          matchCount++;
        }
      }
    }
  }

  return c.json({
    indicators_checked: (indicators.results || []).length,
    new_matches: matchCount,
    matches,
    message: `Correlation complete: ${matchCount} new matches found from ${(indicators.results || []).length} active indicators`,
  });
});

// ─── Matches ───────────────────────────────────────────────────────────────

threatIntel.get('/matches', async (c) => {
  const { page = '1', page_size = '50', match_type, entity_type, acknowledged } = c.req.query();
  const pageNum = parseInt(page);
  const limit = Math.min(parseInt(page_size), 100);
  const offset = (pageNum - 1) * limit;

  const conditions: string[] = [];
  const params: string[] = [];

  if (match_type) { conditions.push('tm.match_type = ?'); params.push(match_type); }
  if (entity_type) { conditions.push('tm.matched_entity_type = ?'); params.push(entity_type); }
  if (acknowledged !== undefined) { conditions.push('tm.acknowledged = ?'); params.push(acknowledged === 'true' ? '1' : '0'); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const total = await c.env.DB.prepare(`SELECT COUNT(*) as count FROM threat_intel_matches tm ${where}`).bind(...params).first<{ count: number }>();
  const matchResults = await c.env.DB.prepare(`
    SELECT tm.*, ti.indicator_type, ti.indicator_value, ti.severity as indicator_severity, ti.confidence as indicator_confidence,
      f.name as feed_name
    FROM threat_intel_matches tm
    JOIN threat_intel_indicators ti ON ti.id = tm.indicator_id
    JOIN threat_intel_feeds f ON f.id = ti.feed_id
    ${where} ORDER BY tm.matched_at DESC LIMIT ? OFFSET ?
  `).bind(...params, limit, offset).all();

  return c.json({ items: matchResults.results || [], total: total?.count || 0, page: pageNum, page_size: limit });
});

// ─── Overview ──────────────────────────────────────────────────────────────

threatIntel.get('/overview', async (c) => {
  const db = c.env.DB;

  const [feedCount, activeFeedCount, indicatorCount, matchCount, typeBreakdown, severityBreakdown, recentMatches] = await Promise.all([
    db.prepare('SELECT COUNT(*) as count FROM threat_intel_feeds').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) as count FROM threat_intel_feeds WHERE enabled = 1').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) as count FROM threat_intel_indicators WHERE is_active = 1').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) as count FROM threat_intel_matches').first<{ count: number }>(),
    db.prepare('SELECT indicator_type, COUNT(*) as count FROM threat_intel_indicators WHERE is_active = 1 GROUP BY indicator_type ORDER BY count DESC').all(),
    db.prepare('SELECT severity, COUNT(*) as count FROM threat_intel_indicators WHERE is_active = 1 GROUP BY severity ORDER BY count DESC').all(),
    db.prepare(`
      SELECT tm.*, ti.indicator_type, ti.indicator_value, ti.severity as indicator_severity, f.name as feed_name
      FROM threat_intel_matches tm
      JOIN threat_intel_indicators ti ON ti.id = tm.indicator_id
      JOIN threat_intel_feeds f ON f.id = ti.feed_id
      ORDER BY tm.matched_at DESC LIMIT 10
    `).all(),
  ]);

  return c.json({
    totals: { feeds: feedCount?.count || 0, active_feeds: activeFeedCount?.count || 0, active_indicators: indicatorCount?.count || 0, total_matches: matchCount?.count || 0 },
    indicator_types: typeBreakdown.results || [],
    severity_breakdown: severityBreakdown.results || [],
    recent_matches: recentMatches.results || [],
    builtin_feeds_available: BUILTIN_FEEDS.length,
    generated_at: new Date().toISOString(),
  });
});

// Available built-in feeds for quick setup
threatIntel.get('/builtin-feeds', async (c) => {
  return c.json({ feeds: BUILTIN_FEEDS, total: BUILTIN_FEEDS.length });
});

// Quick-add a built-in feed
threatIntel.post('/builtin-feeds/:index', async (c) => {
  const index = parseInt(c.req.param('index'));
  if (index < 0 || index >= BUILTIN_FEEDS.length) return c.json({ error: 'Invalid feed index' }, 400);

  const template = BUILTIN_FEEDS[index];
  const user = c.get('user');
  const id = crypto.randomUUID();

  await c.env.DB.prepare(`
    INSERT INTO threat_intel_feeds (id, name, feed_type, source_url, format, poll_interval_minutes, created_by)
    VALUES (?, ?, ?, ?, ?, 60, ?)
  `).bind(id, template.name, template.feed_type, template.source_url, template.format, user.id).run();

  const feed = await c.env.DB.prepare('SELECT * FROM threat_intel_feeds WHERE id = ?').bind(id).first();
  return c.json(feed, 201);
});

// ─── Indicator Generator (Simulation) ──────────────────────────────────────

interface SimIndicator {
  id: string; type: string; value: string; severity: string; confidence: number;
  tlp: string; tags: string[]; context: Record<string, string>; ref: string;
}

function generateIndicators(feedId: string, feedType: string, feedName: string): SimIndicator[] {
  const indicators: SimIndicator[] = [];
  const seed = feedId.charCodeAt(0) + feedId.charCodeAt(4);

  if (feedType === 'vulnerability') {
    const cves = [
      { cve: 'CVE-2024-3400', sev: 'critical', conf: 95, tags: ['palo-alto', 'firewall', 'rce'] },
      { cve: 'CVE-2024-21762', sev: 'critical', conf: 90, tags: ['fortinet', 'fortigate', 'rce'] },
      { cve: 'CVE-2023-46805', sev: 'critical', conf: 95, tags: ['ivanti', 'vpn', 'auth-bypass'] },
      { cve: 'CVE-2024-1709', sev: 'critical', conf: 85, tags: ['connectwise', 'screenconnect', 'auth-bypass'] },
      { cve: 'CVE-2023-4966', sev: 'high', conf: 90, tags: ['citrix', 'netscaler', 'info-disclosure'] },
    ];
    for (const cve of cves) {
      indicators.push({
        id: crypto.randomUUID(), type: 'cve', value: cve.cve, severity: cve.sev,
        confidence: cve.conf, tlp: 'white', tags: cve.tags,
        context: { source: feedName, exploited_in_wild: 'true' }, ref: cve.cve,
      });
    }
  } else if (feedType === 'indicator') {
    const malIPs = ['185.220.101.34', '45.155.205.233', '194.26.135.89', '91.92.248.87', '103.138.72.48'];
    const malDomains = ['evil-payload.xyz', 'c2-callback.ru', 'phish-login.net', 'malware-drop.cc'];

    for (let i = 0; i < 3 + (seed % 3); i++) {
      indicators.push({
        id: crypto.randomUUID(), type: 'ip', value: malIPs[i % malIPs.length], severity: 'high',
        confidence: 80 + (i * 3), tlp: 'amber', tags: ['c2', 'botnet'],
        context: { source: feedName, category: 'command-and-control' }, ref: `IP-${i}`,
      });
    }
    for (let i = 0; i < 2 + (seed % 2); i++) {
      indicators.push({
        id: crypto.randomUUID(), type: 'domain', value: malDomains[i % malDomains.length], severity: 'high',
        confidence: 75 + (i * 5), tlp: 'amber', tags: ['phishing', 'malware'],
        context: { source: feedName, category: 'malicious-domain' }, ref: `DOM-${i}`,
      });
    }
  } else if (feedType === 'apt') {
    const hashes = ['a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', 'deadbeefcafebabe1234567890abcdef'];
    for (const h of hashes) {
      indicators.push({
        id: crypto.randomUUID(), type: 'hash_md5', value: h, severity: 'critical',
        confidence: 90, tlp: 'red', tags: ['apt', 'malware', 'dropper'],
        context: { source: feedName, malware_family: 'cobalt_strike' }, ref: `HASH-${h.substring(0, 8)}`,
      });
    }
  }

  return indicators;
}

export { threatIntel };
