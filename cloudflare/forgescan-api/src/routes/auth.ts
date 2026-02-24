import { Hono } from 'hono';
import {
  generateSalt,
  hashPassword,
  verifyPassword,
  signJWT,
  hashApiKey,
  generateApiKey,
} from '../lib/crypto';
import { requireRole } from '../middleware/auth';
import { seedFrameworks } from '../services/compliance';
import { auditLog, getClientIP } from '../services/audit';

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  JWT_SECRET: string;
}

interface AuthUser {
  id: string;
  email: string;
  role: string;
  display_name: string;
}

type AuthContext = { Bindings: Env; Variables: { user: AuthUser } };

const VALID_ROLES = ['platform_admin', 'scan_admin', 'vuln_manager', 'remediation_owner', 'auditor'];

const auth = new Hono<AuthContext>();

// --- Public Routes ---

// Register (first user becomes platform_admin, subsequent require admin auth)
auth.post('/register', async (c) => {
  try {
    const body = await c.req.json();
    const { email, password, display_name } = body;

    if (!email || !password || !display_name) {
      return c.json({ error: 'email, password, and display_name are required' }, 400);
    }

    if (password.length < 8) {
      return c.json({ error: 'Password must be at least 8 characters' }, 400);
    }

    // Check if this is the first user (bootstrap)
    const userCount = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM users'
    ).first<{ count: number }>();

    const isBootstrap = !userCount || userCount.count === 0;

    // If not bootstrap, require platform_admin
    if (!isBootstrap) {
      const currentUser = c.get('user');
      if (!currentUser || currentUser.role !== 'platform_admin') {
        return c.json({ error: 'Only platform administrators can create new users' }, 403);
      }
    }

    // Check if email already exists
    const existing = await c.env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first();

    if (existing) {
      return c.json({ error: 'Email already registered' }, 409);
    }

    const id = crypto.randomUUID();
    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);
    const role = isBootstrap ? 'platform_admin' : (body.role && VALID_ROLES.includes(body.role) ? body.role : 'auditor');

    await c.env.DB.prepare(`
      INSERT INTO users (id, email, password_hash, salt, display_name, role)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(id, email.toLowerCase(), passwordHash, salt, display_name, role).run();

    // Auto-seed compliance frameworks on first admin account creation
    if (isBootstrap) {
      try {
        await seedFrameworks(c.env.DB);
      } catch (seedErr) {
        console.error('Auto-seed compliance failed (non-fatal):', seedErr);
      }
    }

    // Audit: registration
    auditLog(c.env.DB, { action: 'auth.register', actor_email: email.toLowerCase(), resource_type: 'user', resource_id: id, details: { role, is_bootstrap: isBootstrap }, ip_address: getClientIP(c) });

    return c.json({
      id,
      email: email.toLowerCase(),
      display_name,
      role,
      is_active: true,
      is_bootstrap: isBootstrap,
      created_at: new Date().toISOString(),
    }, 201);
  } catch (err) {
    console.error('Register error:', err);
    return c.json({ error: 'Registration failed', message: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// Login
auth.post('/login', async (c) => {
  try {
    const body = await c.req.json();
    const { email, password } = body;

    if (!email || !password) {
      return c.json({ error: 'email and password are required' }, 400);
    }

    const user = await c.env.DB.prepare(
      'SELECT id, email, password_hash, salt, display_name, role, is_active FROM users WHERE email = ?'
    ).bind(email.toLowerCase()).first<{
      id: string;
      email: string;
      password_hash: string;
      salt: string;
      display_name: string;
      role: string;
      is_active: number;
    }>();

    if (!user) {
      auditLog(c.env.DB, { action: 'auth.login_failed', actor_email: email.toLowerCase(), details: { reason: 'user_not_found' }, ip_address: getClientIP(c) });
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    if (!user.is_active) {
      auditLog(c.env.DB, { action: 'auth.login_failed', actor_id: user.id, actor_email: user.email, details: { reason: 'account_deactivated' }, ip_address: getClientIP(c) });
      return c.json({ error: 'Account is deactivated' }, 403);
    }

    const valid = await verifyPassword(password, user.salt, user.password_hash);
    if (!valid) {
      auditLog(c.env.DB, { action: 'auth.login_failed', actor_id: user.id, actor_email: user.email, details: { reason: 'invalid_password' }, ip_address: getClientIP(c) });
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    // Generate JWT
    const { token, jti, expiresAt } = await signJWT(
      {
        sub: user.id,
        email: user.email,
        role: user.role,
        display_name: user.display_name,
      },
      c.env.JWT_SECRET
    );

    // Store session (using jti as token_hash for session lookup)
    const sessionId = crypto.randomUUID();
    const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown';
    const ua = c.req.header('User-Agent') || 'unknown';

    await c.env.DB.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(sessionId, user.id, jti, expiresAt, ip, ua).run();

    // Update last_login_at
    await c.env.DB.prepare(
      'UPDATE users SET last_login_at = datetime(\'now\') WHERE id = ?'
    ).bind(user.id).run();

    // Audit: successful login
    auditLog(c.env.DB, { action: 'auth.login', actor_id: user.id, actor_email: user.email, details: { role: user.role }, ip_address: getClientIP(c) });

    return c.json({
      token,
      expires_at: expiresAt,
      user: {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    return c.json({ error: 'Login failed', message: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});

// --- Authenticated Routes ---

// Logout
auth.post('/logout', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      // Parse the JWT to get jti without full verification (we just need to delete the session)
      const parts = token.split('.');
      if (parts.length === 3) {
        try {
          const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
          if (payload.jti) {
            await c.env.DB.prepare(
              'DELETE FROM sessions WHERE token_hash = ?'
            ).bind(payload.jti).run();
          }
        } catch {
          // Ignore parse errors
        }
      }
    }
    return c.json({ message: 'Logged out successfully' });
  } catch (err) {
    return c.json({ message: 'Logged out' });
  }
});

// Get current user profile
auth.get('/me', async (c) => {
  const user = c.get('user');
  if (!user) return c.json({ error: 'Unauthorized' }, 401);

  const fullUser = await c.env.DB.prepare(
    'SELECT id, email, display_name, role, is_active, last_login_at, created_at, updated_at FROM users WHERE id = ?'
  ).bind(user.id).first();

  if (!fullUser) return c.json({ error: 'User not found' }, 404);

  return c.json(fullUser);
});

// Change password
auth.put('/password', async (c) => {
  const user = c.get('user');
  if (!user) return c.json({ error: 'Unauthorized' }, 401);

  try {
    const body = await c.req.json();
    const { current_password, new_password } = body;

    if (!current_password || !new_password) {
      return c.json({ error: 'current_password and new_password are required' }, 400);
    }

    if (new_password.length < 8) {
      return c.json({ error: 'New password must be at least 8 characters' }, 400);
    }

    const dbUser = await c.env.DB.prepare(
      'SELECT password_hash, salt FROM users WHERE id = ?'
    ).bind(user.id).first<{ password_hash: string; salt: string }>();

    if (!dbUser) return c.json({ error: 'User not found' }, 404);

    const valid = await verifyPassword(current_password, dbUser.salt, dbUser.password_hash);
    if (!valid) {
      return c.json({ error: 'Current password is incorrect' }, 401);
    }

    const newSalt = generateSalt();
    const newHash = await hashPassword(new_password, newSalt);

    await c.env.DB.prepare(`
      UPDATE users SET password_hash = ?, salt = ?, password_changed_at = datetime('now'), updated_at = datetime('now')
      WHERE id = ?
    `).bind(newHash, newSalt, user.id).run();

    // Invalidate all other sessions for this user
    await c.env.DB.prepare(
      'DELETE FROM sessions WHERE user_id = ?'
    ).bind(user.id).run();

    return c.json({ message: 'Password changed successfully. Please log in again.' });
  } catch (err) {
    console.error('Password change error:', err);
    return c.json({ error: 'Password change failed' }, 500);
  }
});

// --- API Key Management ---

// List own API keys
auth.get('/api-keys', async (c) => {
  const user = c.get('user');
  if (!user) return c.json({ error: 'Unauthorized' }, 401);

  const keys = await c.env.DB.prepare(
    'SELECT id, name, key_prefix, permissions, last_used_at, expires_at, is_active, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC'
  ).bind(user.id).all();

  return c.json({ items: keys.results || [] });
});

// Create API key
auth.post('/api-keys', async (c) => {
  const user = c.get('user');
  if (!user) return c.json({ error: 'Unauthorized' }, 401);

  try {
    const body = await c.req.json();
    const { name, permissions, expires_in_days } = body;

    if (!name) {
      return c.json({ error: 'name is required' }, 400);
    }

    const id = crypto.randomUUID();
    const rawKey = generateApiKey();
    const keyHash = await hashApiKey(rawKey);
    const keyPrefix = rawKey.substring(0, 12);
    const expiresAt = expires_in_days
      ? new Date(Date.now() + expires_in_days * 86400000).toISOString()
      : null;

    await c.env.DB.prepare(`
      INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, permissions, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      user.id,
      name,
      keyHash,
      keyPrefix,
      JSON.stringify(permissions || []),
      expiresAt
    ).run();

    // Return the raw key ONCE - it cannot be retrieved again
    return c.json({
      id,
      name,
      key: rawKey,
      key_prefix: keyPrefix,
      expires_at: expiresAt,
      message: 'Save this key now. It will not be shown again.',
    }, 201);
  } catch (err) {
    console.error('API key creation error:', err);
    return c.json({ error: 'Failed to create API key' }, 500);
  }
});

// Delete API key
auth.delete('/api-keys/:id', async (c) => {
  const user = c.get('user');
  if (!user) return c.json({ error: 'Unauthorized' }, 401);

  const keyId = c.req.param('id');

  // Users can delete own keys, admins can delete any
  const condition = user.role === 'platform_admin'
    ? 'id = ?'
    : 'id = ? AND user_id = ?';
  const params = user.role === 'platform_admin'
    ? [keyId]
    : [keyId, user.id];

  const result = await c.env.DB.prepare(
    `DELETE FROM api_keys WHERE ${condition}`
  ).bind(...params).run();

  if (!result.meta.changes || result.meta.changes === 0) {
    return c.json({ error: 'API key not found' }, 404);
  }

  return c.json({ message: 'API key deleted' });
});

// --- Admin: User Management ---

// List all users (admin only)
auth.get('/users', requireRole('platform_admin'), async (c) => {
  const { page = '1', page_size = '20', search = '' } = c.req.query();
  const pageNum = parseInt(page);
  const pageSizeNum = Math.min(parseInt(page_size), 100);
  const offset = (pageNum - 1) * pageSizeNum;

  let whereClause = '';
  const params: string[] = [];

  if (search) {
    whereClause = 'WHERE (email LIKE ? OR display_name LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }

  const countResult = await c.env.DB.prepare(
    `SELECT COUNT(*) as total FROM users ${whereClause}`
  ).bind(...params).first<{ total: number }>();

  const total = countResult?.total || 0;

  const users = await c.env.DB.prepare(`
    SELECT id, email, display_name, role, is_active, last_login_at, created_at, updated_at
    FROM users ${whereClause}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).bind(...params, pageSizeNum, offset).all();

  return c.json({
    items: users.results || [],
    total,
    page: pageNum,
    page_size: pageSizeNum,
    total_pages: Math.ceil(total / pageSizeNum),
  });
});

// Create user (admin only)
auth.post('/users', requireRole('platform_admin'), async (c) => {
  try {
    const body = await c.req.json();
    const { email, password, display_name, role } = body;

    if (!email || !password || !display_name) {
      return c.json({ error: 'email, password, and display_name are required' }, 400);
    }

    if (password.length < 8) {
      return c.json({ error: 'Password must be at least 8 characters' }, 400);
    }

    if (role && !VALID_ROLES.includes(role)) {
      return c.json({ error: `Invalid role. Must be one of: ${VALID_ROLES.join(', ')}` }, 400);
    }

    const existing = await c.env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email.toLowerCase()).first();

    if (existing) {
      return c.json({ error: 'Email already registered' }, 409);
    }

    const id = crypto.randomUUID();
    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);

    await c.env.DB.prepare(`
      INSERT INTO users (id, email, password_hash, salt, display_name, role)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(id, email.toLowerCase(), passwordHash, salt, display_name, role || 'auditor').run();

    return c.json({
      id,
      email: email.toLowerCase(),
      display_name,
      role: role || 'auditor',
      is_active: true,
      created_at: new Date().toISOString(),
    }, 201);
  } catch (err) {
    console.error('Create user error:', err);
    return c.json({ error: 'Failed to create user' }, 500);
  }
});

// Update user (admin only)
auth.put('/users/:id', requireRole('platform_admin'), async (c) => {
  try {
    const userId = c.req.param('id');
    const body = await c.req.json();
    const { display_name, role, is_active } = body;

    const existing = await c.env.DB.prepare(
      'SELECT id FROM users WHERE id = ?'
    ).bind(userId).first();

    if (!existing) {
      return c.json({ error: 'User not found' }, 404);
    }

    const updates: string[] = [];
    const values: (string | number)[] = [];

    if (display_name !== undefined) {
      updates.push('display_name = ?');
      values.push(display_name);
    }
    if (role !== undefined) {
      if (!VALID_ROLES.includes(role)) {
        return c.json({ error: `Invalid role. Must be one of: ${VALID_ROLES.join(', ')}` }, 400);
      }
      updates.push('role = ?');
      values.push(role);
    }
    if (is_active !== undefined) {
      updates.push('is_active = ?');
      values.push(is_active ? 1 : 0);
    }

    if (updates.length === 0) {
      return c.json({ error: 'No fields to update' }, 400);
    }

    updates.push('updated_at = datetime(\'now\')');
    values.push(userId);

    await c.env.DB.prepare(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    // If deactivating, invalidate their sessions
    if (is_active === false) {
      await c.env.DB.prepare(
        'DELETE FROM sessions WHERE user_id = ?'
      ).bind(userId).run();
    }

    const updated = await c.env.DB.prepare(
      'SELECT id, email, display_name, role, is_active, last_login_at, created_at, updated_at FROM users WHERE id = ?'
    ).bind(userId).first();

    return c.json(updated);
  } catch (err) {
    console.error('Update user error:', err);
    return c.json({ error: 'Failed to update user' }, 500);
  }
});

// Delete user (admin only)
auth.delete('/users/:id', requireRole('platform_admin'), async (c) => {
  const userId = c.req.param('id');
  const currentUser = c.get('user');

  // Prevent self-deletion
  if (userId === currentUser.id) {
    return c.json({ error: 'Cannot delete your own account' }, 400);
  }

  const existing = await c.env.DB.prepare(
    'SELECT id FROM users WHERE id = ?'
  ).bind(userId).first();

  if (!existing) {
    return c.json({ error: 'User not found' }, 404);
  }

  // Delete sessions and API keys first (cascade should handle this but be explicit)
  await c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
  await c.env.DB.prepare('DELETE FROM api_keys WHERE user_id = ?').bind(userId).run();
  await c.env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();

  return c.json({ message: 'User deleted' });
});

// Get user sessions (admin or own)
auth.get('/sessions', async (c) => {
  const user = c.get('user');
  if (!user) return c.json({ error: 'Unauthorized' }, 401);

  const sessions = await c.env.DB.prepare(
    'SELECT id, ip_address, user_agent, created_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > datetime(\'now\') ORDER BY created_at DESC'
  ).bind(user.id).all();

  return c.json({ items: sessions.results || [] });
});

export { auth };
