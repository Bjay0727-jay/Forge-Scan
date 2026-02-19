import { Context, MiddlewareHandler } from 'hono';
import { verifyJWT, hashApiKey } from '../lib/crypto';

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  display_name: string;
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
];

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
        c.set('user', {
          id: payload.sub,
          email: payload.email,
          role: payload.role,
          display_name: payload.display_name,
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

      c.set('user', {
        id: keyRecord.user_id,
        email: keyRecord.email,
        role: keyRecord.role,
        display_name: keyRecord.display_name,
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
