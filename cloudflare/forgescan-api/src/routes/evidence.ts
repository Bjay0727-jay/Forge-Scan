/**
 * Evidence Vault Routes
 *
 * R2-backed evidence file management with hash verification and expiration.
 * Supports upload, download, hash verification, and expiration management.
 */
import { Hono } from 'hono';
import type { Env } from '../index';
import { badRequest, notFound, databaseError } from '../lib/errors';
import { getOrgFilter, getOrgIdForInsert } from '../middleware/org-scope';
import { parsePositiveInt } from '../lib/validate';

interface AuthUser {
  id: string;
  email: string;
  role: string;
}

export const evidence = new Hono<{ Bindings: Env; Variables: { user: AuthUser } }>();

// ─── List evidence files ────────────────────────────────────────────────────

evidence.get('/', async (c) => {
  const { orgId } = getOrgFilter(c);
  const { limit = '20', offset = '0', finding_id, mapping_id, expired } = c.req.query();
  const limitNum = parsePositiveInt(limit, 20);
  const offsetNum = parseInt(offset) || 0;

  let query = 'SELECT * FROM evidence_files WHERE 1=1';
  const params: any[] = [];

  if (orgId) {
    query += ' AND org_id = ?';
    params.push(orgId);
  }
  if (finding_id) {
    query += ' AND finding_id = ?';
    params.push(finding_id);
  }
  if (mapping_id) {
    query += ' AND compliance_mapping_id = ?';
    params.push(mapping_id);
  }
  if (expired === 'true') {
    query += " AND expires_at IS NOT NULL AND expires_at < datetime('now')";
  } else if (expired === 'false') {
    query += " AND (expires_at IS NULL OR expires_at >= datetime('now'))";
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limitNum, offsetNum);

  try {
    const result = await c.env.DB.prepare(query).bind(...params).all();
    return c.json({ data: result.results, pagination: { limit: limitNum, offset: offsetNum } });
  } catch (err) {
    throw databaseError(err);
  }
});

// ─── Upload evidence file ───────────────────────────────────────────────────

evidence.post('/upload', async (c) => {
  const orgId = getOrgIdForInsert(c);
  const user = c.get('user');

  const contentType = c.req.header('content-type') || '';
  if (!contentType.includes('multipart/form-data')) {
    throw badRequest('Content-Type must be multipart/form-data');
  }

  const formData = await c.req.formData();
  const file = formData.get('file') as unknown as File | null;
  if (!file) {
    throw badRequest('No file provided');
  }

  const title = (formData.get('title') as string) || file.name || 'Untitled';
  const description = (formData.get('description') as string) || null;
  const findingId = (formData.get('finding_id') as string) || null;
  const mappingId = (formData.get('compliance_mapping_id') as string) || null;
  const tagsRaw = (formData.get('tags') as string) || '[]';
  const expiresAt = (formData.get('expires_at') as string) || null;

  // Read file content and compute SHA-256 hash
  const fileBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', fileBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const sha256Hash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

  const id = crypto.randomUUID();
  const r2Key = `evidence/${orgId || 'default'}/${id}/${file.name}`;

  try {
    // Upload to R2
    await c.env.STORAGE.put(r2Key, fileBuffer, {
      customMetadata: {
        evidenceId: id,
        orgId: orgId || 'default',
        sha256: sha256Hash,
        uploadedBy: user.id,
      },
      httpMetadata: {
        contentType: file.type || 'application/octet-stream',
      },
    });

    // Store metadata in D1
    await c.env.DB.prepare(`
      INSERT INTO evidence_files (
        id, org_id, title, description, file_name, file_size, mime_type,
        r2_key, sha256_hash, uploaded_by, compliance_mapping_id, finding_id,
        tags, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id, orgId, title, description, file.name, fileBuffer.byteLength,
      file.type || 'application/octet-stream', r2Key, sha256Hash,
      user.id, mappingId, findingId, tagsRaw, expiresAt,
    ).run();

    return c.json({
      id,
      title,
      file_name: file.name,
      file_size: fileBuffer.byteLength,
      sha256_hash: sha256Hash,
      r2_key: r2Key,
      created_at: new Date().toISOString(),
    }, 201);
  } catch (err) {
    // Clean up R2 on DB failure
    try { await c.env.STORAGE.delete(r2Key); } catch { /* best effort */ }
    throw databaseError(err);
  }
});

// ─── Get evidence file metadata ─────────────────────────────────────────────

evidence.get('/:id', async (c) => {
  const id = c.req.param('id');
  const { orgId } = getOrgFilter(c);

  const query = orgId
    ? 'SELECT * FROM evidence_files WHERE id = ? AND org_id = ?'
    : 'SELECT * FROM evidence_files WHERE id = ?';
  const params = orgId ? [id, orgId] : [id];

  const file = await c.env.DB.prepare(query).bind(...params).first();
  if (!file) {
    throw notFound('Evidence file', id);
  }

  return c.json(file);
});

// ─── Download evidence file ─────────────────────────────────────────────────

evidence.get('/:id/download', async (c) => {
  const id = c.req.param('id');
  const { orgId } = getOrgFilter(c);

  const query = orgId
    ? 'SELECT * FROM evidence_files WHERE id = ? AND org_id = ?'
    : 'SELECT * FROM evidence_files WHERE id = ?';
  const params = orgId ? [id, orgId] : [id];

  const file = await c.env.DB.prepare(query).bind(...params).first<{
    r2_key: string; file_name: string; mime_type: string; sha256_hash: string;
  }>();

  if (!file) {
    throw notFound('Evidence file', id);
  }

  const object = await c.env.STORAGE.get(file.r2_key);
  if (!object) {
    throw notFound('Evidence file in storage', id);
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': file.mime_type,
      'Content-Disposition': `attachment; filename="${file.file_name}"`,
      'X-Content-SHA256': file.sha256_hash,
    },
  });
});

// ─── Verify evidence file hash ──────────────────────────────────────────────

evidence.post('/:id/verify', async (c) => {
  const id = c.req.param('id');
  const { orgId } = getOrgFilter(c);

  const query = orgId
    ? 'SELECT * FROM evidence_files WHERE id = ? AND org_id = ?'
    : 'SELECT * FROM evidence_files WHERE id = ?';
  const params = orgId ? [id, orgId] : [id];

  const file = await c.env.DB.prepare(query).bind(...params).first<{
    r2_key: string; sha256_hash: string; file_name: string;
  }>();

  if (!file) {
    throw notFound('Evidence file', id);
  }

  const object = await c.env.STORAGE.get(file.r2_key);
  if (!object) {
    return c.json({
      verified: false,
      reason: 'File not found in storage',
      expected_hash: file.sha256_hash,
    });
  }

  const buffer = await object.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const currentHash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

  return c.json({
    verified: currentHash === file.sha256_hash,
    expected_hash: file.sha256_hash,
    actual_hash: currentHash,
    file_name: file.file_name,
    verified_at: new Date().toISOString(),
  });
});

// ─── Update evidence expiration ─────────────────────────────────────────────

evidence.patch('/:id', async (c) => {
  const id = c.req.param('id');
  const { orgId } = getOrgFilter(c);
  const body = await c.req.json();

  const checkQuery = orgId
    ? 'SELECT id FROM evidence_files WHERE id = ? AND org_id = ?'
    : 'SELECT id FROM evidence_files WHERE id = ?';
  const checkParams = orgId ? [id, orgId] : [id];

  const existing = await c.env.DB.prepare(checkQuery).bind(...checkParams).first();
  if (!existing) {
    throw notFound('Evidence file', id);
  }

  const updates: string[] = [];
  const updateParams: any[] = [];

  if (body.title !== undefined) {
    updates.push('title = ?');
    updateParams.push(body.title);
  }
  if (body.description !== undefined) {
    updates.push('description = ?');
    updateParams.push(body.description);
  }
  if (body.expires_at !== undefined) {
    updates.push('expires_at = ?');
    updateParams.push(body.expires_at);
  }
  if (body.tags !== undefined) {
    updates.push('tags = ?');
    updateParams.push(typeof body.tags === 'string' ? body.tags : JSON.stringify(body.tags));
  }
  if (body.compliance_mapping_id !== undefined) {
    updates.push('compliance_mapping_id = ?');
    updateParams.push(body.compliance_mapping_id);
  }
  if (body.finding_id !== undefined) {
    updates.push('finding_id = ?');
    updateParams.push(body.finding_id);
  }

  if (updates.length === 0) {
    throw badRequest('No fields to update');
  }

  updates.push("updated_at = datetime('now')");
  updateParams.push(id);
  if (orgId) updateParams.push(orgId);

  const updateQuery = `UPDATE evidence_files SET ${updates.join(', ')} WHERE id = ?${orgId ? ' AND org_id = ?' : ''}`;
  await c.env.DB.prepare(updateQuery).bind(...updateParams).run();

  return c.json({ id, message: 'Evidence file updated' });
});

// ─── Delete evidence file ───────────────────────────────────────────────────

evidence.delete('/:id', async (c) => {
  const id = c.req.param('id');
  const { orgId } = getOrgFilter(c);

  const query = orgId
    ? 'SELECT * FROM evidence_files WHERE id = ? AND org_id = ?'
    : 'SELECT * FROM evidence_files WHERE id = ?';
  const params = orgId ? [id, orgId] : [id];

  const file = await c.env.DB.prepare(query).bind(...params).first<{ r2_key: string }>();
  if (!file) {
    throw notFound('Evidence file', id);
  }

  // Delete from R2 and D1
  try { await c.env.STORAGE.delete(file.r2_key); } catch { /* best effort */ }

  const deleteQuery = orgId
    ? 'DELETE FROM evidence_files WHERE id = ? AND org_id = ?'
    : 'DELETE FROM evidence_files WHERE id = ?';
  await c.env.DB.prepare(deleteQuery).bind(...params).run();

  return c.json({ message: 'Evidence file deleted' });
});

// ─── Cleanup expired evidence ───────────────────────────────────────────────

evidence.post('/cleanup', async (c) => {
  const { orgId } = getOrgFilter(c);

  let query = "SELECT id, r2_key FROM evidence_files WHERE expires_at IS NOT NULL AND expires_at < datetime('now')";
  const params: any[] = [];

  if (orgId) {
    query += ' AND org_id = ?';
    params.push(orgId);
  }

  const expired = await c.env.DB.prepare(query).bind(...params).all<{ id: string; r2_key: string }>();
  let deleted = 0;

  for (const file of expired.results || []) {
    try {
      await c.env.STORAGE.delete(file.r2_key);
      const delQuery = orgId
        ? 'DELETE FROM evidence_files WHERE id = ? AND org_id = ?'
        : 'DELETE FROM evidence_files WHERE id = ?';
      const delParams = orgId ? [file.id, orgId] : [file.id];
      await c.env.DB.prepare(delQuery).bind(...delParams).run();
      deleted++;
    } catch {
      // Continue with other files
    }
  }

  return c.json({
    expired_count: expired.results?.length || 0,
    deleted_count: deleted,
  });
});
