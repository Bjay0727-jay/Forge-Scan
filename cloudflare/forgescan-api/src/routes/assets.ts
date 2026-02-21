import { Hono } from 'hono';
import type { Env } from '../index';

export const assets = new Hono<{ Bindings: Env }>();

// List all assets
assets.get('/', async (c) => {
  const { page = '1', page_size = '20', search, type, sort_by = 'last_seen', sort_order = 'desc' } = c.req.query();
  const pageNum = parseInt(page);
  const pageSizeNum = parseInt(page_size);
  const offset = (pageNum - 1) * pageSizeNum;

  // Validated sort
  const validSortFields = ['hostname', 'risk_score', 'asset_type', 'last_seen', 'created_at'];
  const sortField = validSortFields.includes(sort_by) ? sort_by : 'last_seen';
  const order = sort_order.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

  let query = 'SELECT * FROM assets';
  let countQuery = 'SELECT COUNT(*) as total FROM assets';
  const conditions: string[] = [];
  const params: string[] = [];

  if (search) {
    conditions.push('(hostname LIKE ? OR fqdn LIKE ? OR ip_addresses LIKE ?)');
    const searchPattern = `%${search}%`;
    params.push(searchPattern, searchPattern, searchPattern);
  }

  if (type) {
    conditions.push('asset_type = ?');
    params.push(type);
  }

  if (conditions.length > 0) {
    const whereClause = ' WHERE ' + conditions.join(' AND ');
    query += whereClause;
    countQuery += whereClause;
  }

  query += ` ORDER BY ${sortField} ${order} NULLS LAST LIMIT ? OFFSET ?`;

  const result = await c.env.DB.prepare(query)
    .bind(...params, pageSizeNum, offset)
    .all();

  const countResult = await c.env.DB.prepare(countQuery)
    .bind(...params)
    .first<{ total: number }>();

  const total = countResult?.total || 0;
  const totalPages = Math.ceil(total / pageSizeNum);

  // Helper to safely parse JSON or wrap plain strings in an array
  function safeParseArray(value: unknown): string[] {
    if (!value) return [];
    const str = String(value);
    try {
      const parsed = JSON.parse(str);
      return Array.isArray(parsed) ? parsed : [str];
    } catch {
      return str ? [str] : [];
    }
  }

  // Transform to match frontend expected format
  const items = (result.results || []).map((asset: Record<string, unknown>) => {
    const ipAddresses = safeParseArray(asset.ip_addresses);
    const displayName = asset.hostname || asset.fqdn || (ipAddresses.length > 0 ? ipAddresses[0] : 'Unknown');

    return {
      id: asset.id,
      name: displayName,
      type: asset.asset_type || 'host',
      identifier: asset.fqdn || asset.hostname || (ipAddresses.length > 0 ? ipAddresses[0] : String(asset.id)),
      metadata: {
        ip_addresses: ipAddresses,
        os: asset.os,
        os_version: asset.os_version,
        network_zone: asset.network_zone,
      },
      tags: safeParseArray(asset.tags),
      risk_score: asset.risk_score || 0,
      created_at: asset.first_seen || asset.created_at,
      updated_at: asset.last_seen || asset.updated_at,
    };
  });

  return c.json({
    items,
    total,
    page: pageNum,
    page_size: pageSizeNum,
    total_pages: totalPages,
  });
});

// Get asset by ID
assets.get('/:id', async (c) => {
  const id = c.req.param('id');

  const asset = await c.env.DB.prepare(
    'SELECT * FROM assets WHERE id = ?'
  ).bind(id).first();

  if (!asset) {
    return c.json({ error: 'Asset not found' }, 404);
  }

  // Get findings for this asset
  const findings = await c.env.DB.prepare(
    'SELECT * FROM findings WHERE asset_id = ? ORDER BY severity DESC, last_seen DESC'
  ).bind(id).all();

  return c.json({
    ...asset,
    findings: findings.results,
    findings_count: findings.results?.length || 0,
  });
});

// Create asset
assets.post('/', async (c) => {
  const body = await c.req.json();
  const id = crypto.randomUUID();

  await c.env.DB.prepare(`
    INSERT INTO assets (id, hostname, fqdn, ip_addresses, mac_addresses, os, os_version, asset_type, network_zone, tags, attributes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    body.hostname || null,
    body.fqdn || null,
    JSON.stringify(body.ip_addresses || []),
    JSON.stringify(body.mac_addresses || []),
    body.os || null,
    body.os_version || null,
    body.asset_type || 'unknown',
    body.network_zone || null,
    JSON.stringify(body.tags || []),
    JSON.stringify(body.attributes || {}),
  ).run();

  return c.json({ id, message: 'Asset created' }, 201);
});

// Update asset
assets.put('/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();

  const existing = await c.env.DB.prepare(
    'SELECT id FROM assets WHERE id = ?'
  ).bind(id).first();

  if (!existing) {
    return c.json({ error: 'Asset not found' }, 404);
  }

  await c.env.DB.prepare(`
    UPDATE assets SET
      hostname = COALESCE(?, hostname),
      fqdn = COALESCE(?, fqdn),
      ip_addresses = COALESCE(?, ip_addresses),
      os = COALESCE(?, os),
      os_version = COALESCE(?, os_version),
      asset_type = COALESCE(?, asset_type),
      tags = COALESCE(?, tags),
      last_seen = datetime('now'),
      updated_at = datetime('now')
    WHERE id = ?
  `).bind(
    body.hostname,
    body.fqdn,
    body.ip_addresses ? JSON.stringify(body.ip_addresses) : null,
    body.os,
    body.os_version,
    body.asset_type,
    body.tags ? JSON.stringify(body.tags) : null,
    id,
  ).run();

  return c.json({ message: 'Asset updated' });
});

// Delete asset
assets.delete('/:id', async (c) => {
  const id = c.req.param('id');

  await c.env.DB.prepare('DELETE FROM findings WHERE asset_id = ?').bind(id).run();
  await c.env.DB.prepare('DELETE FROM assets WHERE id = ?').bind(id).run();

  return c.json({ message: 'Asset deleted' });
});

// Get asset findings summary
assets.get('/:id/summary', async (c) => {
  const id = c.req.param('id');

  const summary = await c.env.DB.prepare(`
    SELECT
      severity,
      COUNT(*) as count
    FROM findings
    WHERE asset_id = ? AND state = 'open'
    GROUP BY severity
  `).bind(id).all();

  return c.json({
    asset_id: id,
    severity_counts: summary.results,
  });
});
