import { Context, MiddlewareHandler } from 'hono';
import { verifyJWT, hashApiKey } from '../lib/crypto';

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  display_name: string;
  organization_id: string | null;
  org_role: string | null;
}

type AuthEnv = {
  Bindings: {
    DB: D1Database;
    JWT_SECRET: string;
  };
  Variables: {
    user: AuthUser;
  };
};

const PUBLIC_PATHS = [
  '/api/v1/auth/login',
  '/api/v1/auth/register',
  '/api/v1/auth/refresh',
];

// Only skip global auth for scanner agent endpoints that use X-Scanner-Key.
// Admin scanner endpoints (listing/managing scanners) require JWT auth.
const SCANNER_AGENT_PATHS = [
  '/api/v1/scanner/register',
  '/api/v1/scanner/heartbeat',
  '/api/v1/scanner/tasks',
];

/** Look up the user's organization membership and return org context. */
async function resolveOrgMembership(
  db: D1Database,
  userId: string,
  requestedOrgId?: string | null,
): Promise<{ organization_id: string | null; org_role: string | null }> {
  if (requestedOrgId) {
    // Validate that user is actually a member of the requested org
    const membership = await db.prepare(
      'SELECT organization_id, org_role FROM organization_members WHERE user_id = ? AND organization_id = ?'
    ).bind(userId, requestedOrgId).first<{ organization_id: string; org_role: string }>();
    if (membership) {
      return { organization_id: membership.organization_id, org_role: membership.org_role };
    }
    // If not a member, fall through to primary org
  }

  // Get primary org membership
  const primary = await db.prepare(
    'SELECT organization_id, org_role FROM organization_members WHERE user_id = ? AND is_primary = 1 LIMIT 1'
  ).bind(userId).first<{ organization_id: string; org_role: string }>();
  if (primary) {
    return { organization_id: primary.organization_id, org_role: primary.org_role };
  }

  // Fallback to any membership
  const any = await db.prepare(
    'SELECT organization_id, org_role FROM organization_members WHERE user_id = ? LIMIT 1'
  ).bind(userId).first<{ organization_id: string; org_role: string }>();
  if (any) {
    return { organization_id: any.organization_id, org_role: any.org_role };
  }

  return { organization_id: null, org_role: null };
}

export const authMiddleware: MiddlewareHandler<AuthEnv> = async (c, next) => {
  const path = c.req.path;

  // Skip auth for public paths
  if (PUBLIC_PATHS.some(p => path === p)) {
    return next();
  }

  // Skip auth for health checks
  if (path === '/' || path === '/health') {
    return next();
  }

  // Skip auth for OPTIONS (CORS preflight)
  if (c.req.method === 'OPTIONS') {
    return next();
  }

  // Only skip global auth for scanner agent endpoints — they use X-Scanner-Key via authenticateScanner
  const isScannerAgentPath = SCANNER_AGENT_PATHS.some(prefix => path === prefix || path.startsWith(prefix + '/'));
  if (isScannerAgentPath) {
    return next();
  }

  // Optional org override header
  const requestedOrgId = c.req.header('X-Organization-Id') || null;

  // Try Bearer token first
  const authHeader = c.req.header('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    if (payload) {
      // Verify session still exists and hasn't been revoked
      const session = await c.env.DB.prepare(
        'SELECT id FROM sessions WHERE token_hash = ? AND expires_at > datetime(\'now\')'
      ).bind(payload.jti).first<{ id: string }>();

      if (session) {
        // Resolve organization membership
        const orgInfo = await resolveOrgMembership(c.env.DB, payload.sub, requestedOrgId);

        c.set('user', {
          id: payload.sub,
          email: payload.email,
          role: payload.role,
          display_name: payload.display_name,
          organization_id: orgInfo.organization_id,
          org_role: orgInfo.org_role,
        });
        return next();
      }
    }
  }

  // Try API key
  const apiKey = c.req.header('X-API-Key');
  if (apiKey) {
    const keyHash = await hashApiKey(apiKey);
    const keyRecord = await c.env.DB.prepare(`
      SELECT ak.user_id, ak.permissions, u.email, u.role, u.display_name, u.is_active
      FROM api_keys ak
      JOIN users u ON ak.user_id = u.id
      WHERE ak.key_hash = ? AND ak.is_active = 1
        AND (ak.expires_at IS NULL OR ak.expires_at > datetime('now'))
    `).bind(keyHash).first<{
      user_id: string;
      permissions: string;
      email: string;
      role: string;
      display_name: string;
      is_active: number;
    }>();

    if (keyRecord && keyRecord.is_active) {
      // Update last_used_at
      await c.env.DB.prepare(
        'UPDATE api_keys SET last_used_at = datetime(\'now\') WHERE key_hash = ?'
      ).bind(keyHash).run();

      // Resolve organization membership
      const orgInfo = await resolveOrgMembership(c.env.DB, keyRecord.user_id, requestedOrgId);

      c.set('user', {
        id: keyRecord.user_id,
        email: keyRecord.email,
        role: keyRecord.role,
        display_name: keyRecord.display_name,
        organization_id: orgInfo.organization_id,
        org_role: orgInfo.org_role,
      });
      return next();
    }
  }

  return c.json({ error: 'Unauthorized', message: 'Valid authentication required' }, 401);
};

// Role-based access control middleware factory
export function requireRole(...allowedRoles: string[]): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const user = c.get('user');
    if (!user) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    // platform_admin always has access
    if (user.role === 'platform_admin' || allowedRoles.includes(user.role)) {
      return next();
    }

    return c.json({
      error: 'Forbidden',
      message: `Role '${user.role}' does not have access to this resource`,
    }, 403);
  };
}
