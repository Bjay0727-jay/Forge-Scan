/**
 * Audit logging service.
 *
 * Writes structured audit events to the forge_events table with event_type
 * prefixed by "audit.". Uses fire-and-forget via waitUntil() so that audit
 * writes never block API responses.
 */

interface AuditEntry {
  action: string;
  actor_id?: string;
  actor_email?: string;
  resource_type?: string;
  resource_id?: string;
  details?: Record<string, unknown>;
  ip_address?: string;
}

/**
 * Write an audit log entry to the forge_events table.
 *
 * Designed to be called with `c.executionCtx.waitUntil(auditLog(...))` so
 * it doesn't block the HTTP response.
 */
export async function auditLog(db: D1Database, entry: AuditEntry): Promise<void> {
  const id = crypto.randomUUID();
  const payload = {
    actor_id: entry.actor_id,
    actor_email: entry.actor_email,
    resource_type: entry.resource_type,
    resource_id: entry.resource_id,
    details: entry.details,
    ip_address: entry.ip_address,
  };

  try {
    await db.prepare(
      `INSERT INTO forge_events (id, event_type, source, payload, created_at)
       VALUES (?, ?, 'api', ?, datetime('now'))`
    ).bind(id, `audit.${entry.action}`, JSON.stringify(payload)).run();
  } catch {
    // Audit logging should never cause request failures
  }
}

/**
 * Helper to extract client IP from a Hono context.
 */
export function getClientIP(c: { req: { header: (name: string) => string | undefined } }): string {
  return c.req.header('CF-Connecting-IP')
    || c.req.header('X-Forwarded-For')?.split(',')[0]?.trim()
    || 'unknown';
}
