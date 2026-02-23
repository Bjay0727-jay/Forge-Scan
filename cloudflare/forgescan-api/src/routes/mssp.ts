import { Hono } from 'hono';
import { requireRole } from '../middleware/auth';

interface Env {
  DB: D1Database;
  STORAGE: R2Bucket;
  CACHE: KVNamespace;
  JWT_SECRET: string;
}

interface AuthUser {
  id: string;
  email: string;
  role: string;
  display_name: string;
}

type MSSPContext = { Bindings: Env; Variables: { user: AuthUser } };

const mssp = new Hono<MSSPContext>();

// ─── Helper ────────────────────────────────────────────────────────────────
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 48);
}

// ─── MSSP Portal Overview ─────────────────────────────────────────────────
// Returns aggregate stats across all managed tenants
mssp.get('/overview', requireRole('platform_admin'), async (c) => {
  const db = c.env.DB;

  const [orgs, userCount, totalAssets, totalFindings, totalScans, totalAlerts] = await Promise.all([
    db.prepare(`SELECT id, name, slug, tier, status, max_assets, max_users, contact_email, industry, created_at FROM organizations ORDER BY created_at DESC`).all(),
    db.prepare(`SELECT COUNT(*) as count FROM users WHERE is_active = 1`).first<{ count: number }>(),
    db.prepare(`SELECT org_id, COUNT(*) as count FROM assets WHERE org_id IS NOT NULL GROUP BY org_id`).all(),
    db.prepare(`SELECT org_id, COUNT(*) as count FROM findings WHERE org_id IS NOT NULL GROUP BY org_id`).all(),
    db.prepare(`SELECT org_id, COUNT(*) as count FROM scans WHERE org_id IS NOT NULL GROUP BY org_id`).all(),
    db.prepare(`SELECT org_id, COUNT(*) as count FROM soc_alerts WHERE org_id IS NOT NULL GROUP BY org_id`).all(),
  ]);

  // Build per-org stats map
  const statsMap: Record<string, { assets: number; findings: number; scans: number; alerts: number }> = {};
  const addStats = (rows: D1Result<Record<string, unknown>>, key: string) => {
    for (const row of rows.results || []) {
      const orgId = row.org_id as string;
      if (!orgId) continue;
      if (!statsMap[orgId]) statsMap[orgId] = { assets: 0, findings: 0, scans: 0, alerts: 0 };
      (statsMap[orgId] as Record<string, number>)[key] = row.count as number;
    }
  };
  addStats(totalAssets, 'assets');
  addStats(totalFindings, 'findings');
  addStats(totalScans, 'scans');
  addStats(totalAlerts, 'alerts');

  // Member counts per org
  const memberCounts = await db.prepare(
    `SELECT organization_id, COUNT(*) as count FROM organization_members GROUP BY organization_id`
  ).all();
  const memberMap: Record<string, number> = {};
  for (const row of memberCounts.results || []) {
    memberMap[row.organization_id as string] = row.count as number;
  }

  // Enrich org list
  type OrgRow = { id: string; name: string; slug: string; tier: string; status: string; max_assets: number; max_users: number; contact_email: string | null; industry: string | null; created_at: string };
  const tenants = (orgs.results || []).map((org) => {
    const o = org as unknown as OrgRow;
    return {
      ...org,
      member_count: memberMap[o.id] || 0,
      stats: statsMap[o.id] || { assets: 0, findings: 0, scans: 0, alerts: 0 },
    };
  });

  // Aggregate totals
  const orgRows = (orgs.results || []) as unknown as OrgRow[];
  const totals = {
    organizations: tenants.length,
    active: orgRows.filter(t => t.status === 'active').length,
    suspended: orgRows.filter(t => t.status === 'suspended').length,
    total_users: userCount?.count || 0,
    total_assets: (totalAssets.results || []).reduce((s, r) => s + (r.count as number), 0),
    total_findings: (totalFindings.results || []).reduce((s, r) => s + (r.count as number), 0),
    total_scans: (totalScans.results || []).reduce((s, r) => s + (r.count as number), 0),
    total_alerts: (totalAlerts.results || []).reduce((s, r) => s + (r.count as number), 0),
  };

  // Tier breakdown
  const tierBreakdown: Record<string, number> = {};
  for (const t of orgRows) {
    const tier = t.tier || 'standard';
    tierBreakdown[tier] = (tierBreakdown[tier] || 0) + 1;
  }

  return c.json({
    totals,
    tier_breakdown: tierBreakdown,
    tenants,
    generated_at: new Date().toISOString(),
  });
});

// ─── List Organizations ────────────────────────────────────────────────────
mssp.get('/organizations', requireRole('platform_admin'), async (c) => {
  const { page = '1', page_size = '25', status, tier, search } = c.req.query();
  const pageNum = parseInt(page);
  const pageSizeNum = Math.min(parseInt(page_size), 100);
  const offset = (pageNum - 1) * pageSizeNum;

  const conditions: string[] = [];
  const params: (string | number)[] = [];

  if (status) {
    conditions.push('o.status = ?');
    params.push(status);
  }
  if (tier) {
    conditions.push('o.tier = ?');
    params.push(tier);
  }
  if (search) {
    conditions.push('(o.name LIKE ? OR o.slug LIKE ? OR o.contact_email LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countResult = await c.env.DB.prepare(
    `SELECT COUNT(*) as total FROM organizations o ${where}`
  ).bind(...params).first<{ total: number }>();
  const total = countResult?.total || 0;

  const orgs = await c.env.DB.prepare(`
    SELECT o.*,
      (SELECT COUNT(*) FROM organization_members om WHERE om.organization_id = o.id) as member_count
    FROM organizations o ${where}
    ORDER BY o.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(...params, pageSizeNum, offset).all();

  return c.json({
    items: orgs.results || [],
    total,
    page: pageNum,
    page_size: pageSizeNum,
    total_pages: Math.ceil(total / pageSizeNum),
  });
});

// ─── Get Organization Detail ───────────────────────────────────────────────
mssp.get('/organizations/:id', requireRole('platform_admin'), async (c) => {
  const orgId = c.req.param('id');
  const db = c.env.DB;

  const org = await db.prepare('SELECT * FROM organizations WHERE id = ?').bind(orgId).first();
  if (!org) return c.json({ error: 'Organization not found' }, 404);

  const [members, branding, assetCount, findingCount, scanCount, alertCount, incidentCount] = await Promise.all([
    db.prepare(`
      SELECT om.*, u.email, u.display_name, u.role as global_role, u.is_active, u.last_login_at
      FROM organization_members om
      JOIN users u ON om.user_id = u.id
      WHERE om.organization_id = ?
      ORDER BY om.joined_at
    `).bind(orgId).all(),
    db.prepare('SELECT * FROM organization_branding WHERE organization_id = ?').bind(orgId).first(),
    db.prepare('SELECT COUNT(*) as count FROM assets WHERE org_id = ?').bind(orgId).first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) as count FROM findings WHERE org_id = ?').bind(orgId).first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) as count FROM scans WHERE org_id = ?').bind(orgId).first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) as count FROM soc_alerts WHERE org_id = ?').bind(orgId).first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) as count FROM soc_incidents WHERE org_id = ?').bind(orgId).first<{ count: number }>(),
  ]);

  // Severity breakdown for this tenant
  const severityBreakdown = await db.prepare(
    `SELECT severity, COUNT(*) as count FROM findings WHERE org_id = ? AND state NOT IN ('resolved','false_positive') GROUP BY severity`
  ).bind(orgId).all();

  return c.json({
    ...org,
    members: members.results || [],
    branding: branding || null,
    stats: {
      assets: assetCount?.count || 0,
      findings: findingCount?.count || 0,
      scans: scanCount?.count || 0,
      alerts: alertCount?.count || 0,
      incidents: incidentCount?.count || 0,
      severity_breakdown: severityBreakdown.results || [],
    },
  });
});

// ─── Create Organization ───────────────────────────────────────────────────
mssp.post('/organizations', requireRole('platform_admin'), async (c) => {
  try {
    const body = await c.req.json();
    const { name, tier, max_assets, max_users, max_scanners, contact_email, contact_name, industry, notes } = body;

    if (!name) return c.json({ error: 'name is required' }, 400);

    const id = crypto.randomUUID();
    let slug = slugify(name);

    // Ensure slug uniqueness
    const existing = await c.env.DB.prepare('SELECT id FROM organizations WHERE slug = ?').bind(slug).first();
    if (existing) slug = `${slug}-${id.substring(0, 6)}`;

    const user = c.get('user');

    await c.env.DB.prepare(`
      INSERT INTO organizations (id, name, slug, tier, max_assets, max_users, max_scanners, contact_email, contact_name, industry, notes, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id, name, slug,
      tier || 'standard',
      max_assets || 1000,
      max_users || 25,
      max_scanners || 5,
      contact_email || null,
      contact_name || null,
      industry || null,
      notes || null,
      user.id,
    ).run();

    // Create default branding row
    await c.env.DB.prepare(`
      INSERT INTO organization_branding (id, organization_id, company_name)
      VALUES (?, ?, ?)
    `).bind(crypto.randomUUID(), id, name).run();

    const org = await c.env.DB.prepare('SELECT * FROM organizations WHERE id = ?').bind(id).first();
    return c.json(org, 201);
  } catch (err) {
    console.error('Create org error:', err);
    return c.json({ error: 'Failed to create organization', message: err instanceof Error ? err.message : 'Unknown' }, 500);
  }
});

// ─── Update Organization ───────────────────────────────────────────────────
mssp.put('/organizations/:id', requireRole('platform_admin'), async (c) => {
  try {
    const orgId = c.req.param('id');
    const body = await c.req.json();
    const { name, tier, status, max_assets, max_users, max_scanners, contact_email, contact_name, industry, notes } = body;

    const existing = await c.env.DB.prepare('SELECT id FROM organizations WHERE id = ?').bind(orgId).first();
    if (!existing) return c.json({ error: 'Organization not found' }, 404);

    const updates: string[] = [];
    const values: (string | number | null)[] = [];

    const fields: Record<string, unknown> = { name, tier, status, max_assets, max_users, max_scanners, contact_email, contact_name, industry, notes };
    for (const [key, val] of Object.entries(fields)) {
      if (val !== undefined) {
        updates.push(`${key} = ?`);
        values.push(val as string | number | null);
      }
    }

    if (updates.length === 0) return c.json({ error: 'No fields to update' }, 400);

    updates.push("updated_at = datetime('now')");
    values.push(orgId);

    await c.env.DB.prepare(
      `UPDATE organizations SET ${updates.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    const org = await c.env.DB.prepare('SELECT * FROM organizations WHERE id = ?').bind(orgId).first();
    return c.json(org);
  } catch (err) {
    console.error('Update org error:', err);
    return c.json({ error: 'Failed to update organization' }, 500);
  }
});

// ─── Delete Organization ───────────────────────────────────────────────────
mssp.delete('/organizations/:id', requireRole('platform_admin'), async (c) => {
  const orgId = c.req.param('id');

  const existing = await c.env.DB.prepare('SELECT id, name FROM organizations WHERE id = ?').bind(orgId).first();
  if (!existing) return c.json({ error: 'Organization not found' }, 404);

  // Cascade: members and branding are CASCADE. Data remains but is orphaned (org_id still set).
  await c.env.DB.prepare('DELETE FROM organizations WHERE id = ?').bind(orgId).run();

  return c.json({ message: `Organization '${existing.name}' deleted` });
});

// ─── Organization Members ──────────────────────────────────────────────────

// Add member to organization
mssp.post('/organizations/:id/members', requireRole('platform_admin'), async (c) => {
  try {
    const orgId = c.req.param('id');
    const body = await c.req.json();
    const { user_id, org_role, is_primary } = body;

    if (!user_id) return c.json({ error: 'user_id is required' }, 400);

    const [org, user] = await Promise.all([
      c.env.DB.prepare('SELECT id FROM organizations WHERE id = ?').bind(orgId).first(),
      c.env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(user_id).first(),
    ]);
    if (!org) return c.json({ error: 'Organization not found' }, 404);
    if (!user) return c.json({ error: 'User not found' }, 404);

    // Check capacity
    const memberCount = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM organization_members WHERE organization_id = ?'
    ).bind(orgId).first<{ count: number }>();
    const orgDetail = await c.env.DB.prepare('SELECT max_users FROM organizations WHERE id = ?').bind(orgId).first<{ max_users: number }>();
    if (orgDetail && memberCount && memberCount.count >= orgDetail.max_users) {
      return c.json({ error: `Organization has reached its user limit (${orgDetail.max_users})` }, 400);
    }

    const id = crypto.randomUUID();
    const validRoles = ['owner', 'admin', 'analyst', 'viewer'];
    const role = validRoles.includes(org_role) ? org_role : 'viewer';

    // If is_primary, clear other primary flags for this user
    if (is_primary) {
      await c.env.DB.prepare(
        'UPDATE organization_members SET is_primary = 0 WHERE user_id = ?'
      ).bind(user_id).run();
    }

    await c.env.DB.prepare(`
      INSERT INTO organization_members (id, organization_id, user_id, org_role, is_primary)
      VALUES (?, ?, ?, ?, ?)
    `).bind(id, orgId, user_id, role, is_primary ? 1 : 0).run();

    return c.json({ id, organization_id: orgId, user_id, org_role: role, is_primary: !!is_primary }, 201);
  } catch (err) {
    const msg = err instanceof Error ? err.message : '';
    if (msg.includes('UNIQUE')) return c.json({ error: 'User is already a member of this organization' }, 409);
    console.error('Add member error:', err);
    return c.json({ error: 'Failed to add member' }, 500);
  }
});

// Update member role
mssp.put('/organizations/:id/members/:userId', requireRole('platform_admin'), async (c) => {
  const orgId = c.req.param('id');
  const userId = c.req.param('userId');
  const body = await c.req.json();
  const { org_role, is_primary } = body;

  const updates: string[] = [];
  const values: (string | number)[] = [];

  if (org_role !== undefined) {
    const validRoles = ['owner', 'admin', 'analyst', 'viewer'];
    if (!validRoles.includes(org_role)) return c.json({ error: 'Invalid org_role' }, 400);
    updates.push('org_role = ?');
    values.push(org_role);
  }
  if (is_primary !== undefined) {
    if (is_primary) {
      await c.env.DB.prepare('UPDATE organization_members SET is_primary = 0 WHERE user_id = ?').bind(userId).run();
    }
    updates.push('is_primary = ?');
    values.push(is_primary ? 1 : 0);
  }

  if (updates.length === 0) return c.json({ error: 'No fields to update' }, 400);

  values.push(orgId, userId);
  const result = await c.env.DB.prepare(
    `UPDATE organization_members SET ${updates.join(', ')} WHERE organization_id = ? AND user_id = ?`
  ).bind(...values).run();

  if (!result.meta.changes) return c.json({ error: 'Membership not found' }, 404);

  return c.json({ message: 'Member updated' });
});

// Remove member
mssp.delete('/organizations/:id/members/:userId', requireRole('platform_admin'), async (c) => {
  const orgId = c.req.param('id');
  const userId = c.req.param('userId');

  const result = await c.env.DB.prepare(
    'DELETE FROM organization_members WHERE organization_id = ? AND user_id = ?'
  ).bind(orgId, userId).run();

  if (!result.meta.changes) return c.json({ error: 'Membership not found' }, 404);

  return c.json({ message: 'Member removed' });
});

// ─── White-Label Branding ──────────────────────────────────────────────────

// Get branding for an organization
mssp.get('/organizations/:id/branding', requireRole('platform_admin'), async (c) => {
  const orgId = c.req.param('id');
  const branding = await c.env.DB.prepare(
    'SELECT * FROM organization_branding WHERE organization_id = ?'
  ).bind(orgId).first();

  if (!branding) return c.json({ error: 'Branding not found' }, 404);
  return c.json(branding);
});

// Update branding
mssp.put('/organizations/:id/branding', requireRole('platform_admin'), async (c) => {
  try {
    const orgId = c.req.param('id');
    const body = await c.req.json();
    const {
      company_name, logo_url, favicon_url, primary_color, accent_color, sidebar_bg,
      login_title, login_subtitle, support_email, support_url, custom_domain, powered_by_visible,
    } = body;

    const fields: Record<string, unknown> = {
      company_name, logo_url, favicon_url, primary_color, accent_color, sidebar_bg,
      login_title, login_subtitle, support_email, support_url, custom_domain, powered_by_visible,
    };

    const updates: string[] = [];
    const values: (string | number | null)[] = [];
    for (const [key, val] of Object.entries(fields)) {
      if (val !== undefined) {
        updates.push(`${key} = ?`);
        values.push(val as string | number | null);
      }
    }

    if (updates.length === 0) return c.json({ error: 'No fields to update' }, 400);

    updates.push("updated_at = datetime('now')");
    values.push(orgId);

    // Upsert: try update first, if no rows affected then insert
    const result = await c.env.DB.prepare(
      `UPDATE organization_branding SET ${updates.join(', ')} WHERE organization_id = ?`
    ).bind(...values).run();

    if (!result.meta.changes) {
      // Insert new branding row
      await c.env.DB.prepare(`
        INSERT INTO organization_branding (id, organization_id, company_name, logo_url, favicon_url, primary_color, accent_color, sidebar_bg, login_title, login_subtitle, support_email, support_url, custom_domain, powered_by_visible)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        crypto.randomUUID(), orgId,
        company_name || null, logo_url || null, favicon_url || null,
        primary_color || '#14b8a6', accent_color || '#0d9488', sidebar_bg || '#0b1929',
        login_title || null, login_subtitle || null,
        support_email || null, support_url || null, custom_domain || null,
        powered_by_visible !== undefined ? (powered_by_visible ? 1 : 0) : 1,
      ).run();
    }

    const branding = await c.env.DB.prepare(
      'SELECT * FROM organization_branding WHERE organization_id = ?'
    ).bind(orgId).first();

    return c.json(branding);
  } catch (err) {
    console.error('Update branding error:', err);
    return c.json({ error: 'Failed to update branding' }, 500);
  }
});

// ─── Tenant Health Scorecard ───────────────────────────────────────────────
// Quick health check across all tenants (for the MSSP dashboard cards)
mssp.get('/health', requireRole('platform_admin'), async (c) => {
  const db = c.env.DB;

  const orgs = await db.prepare(
    `SELECT id, name, slug, tier, status FROM organizations WHERE status = 'active' ORDER BY name`
  ).all();

  const healthCards = [];
  for (const org of orgs.results || []) {
    const orgId = org.id as string;

    const [critFindings, openAlerts, activeScans, lastScan] = await Promise.all([
      db.prepare(`SELECT COUNT(*) as count FROM findings WHERE org_id = ? AND severity IN ('critical','high') AND state NOT IN ('resolved','false_positive')`).bind(orgId).first<{ count: number }>(),
      db.prepare(`SELECT COUNT(*) as count FROM soc_alerts WHERE org_id = ? AND status NOT IN ('resolved','closed','false_positive')`).bind(orgId).first<{ count: number }>(),
      db.prepare(`SELECT COUNT(*) as count FROM scans WHERE org_id = ? AND status IN ('running','pending')`).bind(orgId).first<{ count: number }>(),
      db.prepare(`SELECT MAX(completed_at) as last FROM scans WHERE org_id = ? AND status = 'completed'`).bind(orgId).first<{ last: string | null }>(),
    ]);

    const critCount = critFindings?.count || 0;
    const alertCount = openAlerts?.count || 0;

    // Simple risk level
    let risk_level = 'low';
    if (critCount > 20 || alertCount > 50) risk_level = 'critical';
    else if (critCount > 5 || alertCount > 15) risk_level = 'high';
    else if (critCount > 0 || alertCount > 5) risk_level = 'medium';

    healthCards.push({
      org_id: orgId,
      name: org.name,
      slug: org.slug,
      tier: org.tier,
      risk_level,
      critical_findings: critCount,
      open_alerts: alertCount,
      active_scans: activeScans?.count || 0,
      last_scan_at: lastScan?.last || null,
    });
  }

  // Sort by risk (critical first)
  const riskOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  healthCards.sort((a, b) => (riskOrder[a.risk_level] || 3) - (riskOrder[b.risk_level] || 3));

  return c.json({ tenants: healthCards, generated_at: new Date().toISOString() });
});

// ─── Tenant Context Switch ─────────────────────────────────────────────────
// Returns context info for an MSSP admin switching into a tenant view
mssp.get('/organizations/:id/context', requireRole('platform_admin'), async (c) => {
  const orgId = c.req.param('id');
  const db = c.env.DB;

  const [org, branding] = await Promise.all([
    db.prepare('SELECT * FROM organizations WHERE id = ?').bind(orgId).first(),
    db.prepare('SELECT * FROM organization_branding WHERE organization_id = ?').bind(orgId).first(),
  ]);

  if (!org) return c.json({ error: 'Organization not found' }, 404);

  return c.json({
    organization: org,
    branding: branding || null,
    context_header: `Managing: ${org.name}`,
  });
});

// ─── User's Organizations ──────────────────────────────────────────────────
// Available to any authenticated user — returns orgs they belong to
mssp.get('/my-organizations', async (c) => {
  const user = c.get('user');
  if (!user) return c.json({ error: 'Unauthorized' }, 401);

  // Platform admins see all organizations
  if (user.role === 'platform_admin') {
    const orgs = await c.env.DB.prepare(
      `SELECT o.*, ob.company_name as brand_name, ob.primary_color, ob.logo_url
       FROM organizations o
       LEFT JOIN organization_branding ob ON ob.organization_id = o.id
       WHERE o.status = 'active'
       ORDER BY o.name`
    ).all();
    return c.json({ items: orgs.results || [], is_mssp_admin: true });
  }

  // Regular users see only their memberships
  const orgs = await c.env.DB.prepare(`
    SELECT o.*, om.org_role, om.is_primary, ob.company_name as brand_name, ob.primary_color, ob.logo_url
    FROM organization_members om
    JOIN organizations o ON om.organization_id = o.id
    LEFT JOIN organization_branding ob ON ob.organization_id = o.id
    WHERE om.user_id = ? AND o.status = 'active'
    ORDER BY om.is_primary DESC, o.name
  `).bind(user.id).all();

  return c.json({ items: orgs.results || [], is_mssp_admin: false });
});

export { mssp };
