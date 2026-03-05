/**
 * Organization scoping middleware and helpers.
 *
 * Ensures every data query is filtered by the authenticated user's
 * organization, preventing cross-tenant data leakage.
 */
import { Context, MiddlewareHandler } from 'hono';
import type { AuthUser } from './auth';

interface OrgScopeEnv {
  Variables: {
    user: AuthUser;
    orgId: string | null;
  };
}

/**
 * Middleware that extracts the user's organization_id and makes it
 * available via `c.get('orgId')`.
 *
 * - Regular users: must have an org membership, otherwise 403.
 * - platform_admin: orgId is null (sees all) unless X-Organization-Id header is set.
 */
export const orgScopeMiddleware: MiddlewareHandler<OrgScopeEnv> = async (c, next) => {
  const user = c.get('user');

  // If no user is set (public paths, scanner paths), skip scoping
  if (!user) {
    return next();
  }

  // Platform admins can see all data unless they explicitly scope to an org
  if (user.role === 'platform_admin') {
    c.set('orgId', user.organization_id);
    return next();
  }

  // Regular users must have an org
  if (!user.organization_id) {
    return c.json({
      error: 'Forbidden',
      message: 'No organization membership found. Contact your administrator.',
    }, 403);
  }

  c.set('orgId', user.organization_id);
  return next();
};

/**
 * Get the organization filter info from context.
 * Returns { orgId, isAdmin } for use in building SQL queries.
 *
 * Usage in route handlers:
 * ```ts
 * const { orgId, isAdmin } = getOrgFilter(c);
 * if (orgId) {
 *   conditions.push('org_id = ?');
 *   params.push(orgId);
 * }
 * ```
 */
export function getOrgFilter(c: Context): { orgId: string | null; isAdmin: boolean } {
  const user = c.get('user') as AuthUser | undefined;
  const orgId = c.get('orgId') as string | null ?? null;
  const isAdmin = user?.role === 'platform_admin';
  return { orgId, isAdmin };
}

/**
 * Helper that returns SQL WHERE clause fragment and params for org scoping.
 * Handles the common pattern of "add org_id filter unless platform_admin without org scope".
 *
 * @param c - Hono context
 * @param tableAlias - Optional table alias prefix (e.g., 'f' for 'f.org_id')
 * @returns { clause: string, params: string[] } - e.g. { clause: 'AND f.org_id = ?', params: ['org-123'] }
 */
export function orgWhereClause(c: Context, tableAlias?: string): { clause: string; params: string[] } {
  const { orgId } = getOrgFilter(c);
  if (!orgId) {
    return { clause: '', params: [] };
  }
  const col = tableAlias ? `${tableAlias}.org_id` : 'org_id';
  return { clause: ` AND ${col} = ?`, params: [orgId] };
}

/**
 * Like orgWhereClause but returns a WHERE clause (not AND).
 * Useful when there are no other conditions.
 */
export function orgWhereStart(c: Context, tableAlias?: string): { clause: string; params: string[] } {
  const { orgId } = getOrgFilter(c);
  if (!orgId) {
    return { clause: '', params: [] };
  }
  const col = tableAlias ? `${tableAlias}.org_id` : 'org_id';
  return { clause: ` WHERE ${col} = ?`, params: [orgId] };
}

/**
 * Returns the orgId for use in INSERT statements.
 * Throws if a non-admin user has no org.
 */
export function getOrgIdForInsert(c: Context): string | null {
  const { orgId, isAdmin } = getOrgFilter(c);
  if (!orgId && !isAdmin) {
    throw new Error('Organization context required for data creation');
  }
  return orgId;
}
