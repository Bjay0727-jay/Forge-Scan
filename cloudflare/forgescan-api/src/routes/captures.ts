import { Hono } from 'hono';
import type { Env } from '../index';
import { requireRole } from '../middleware/auth';

type CapturesEnv = {
  Bindings: Env;
  Variables: {
    user?: { id: string; email: string; role: string; display_name: string };
  };
};

export const captures = new Hono<CapturesEnv>();

// GET / - List capture sessions (platform_admin, scan_admin)
captures.get('/', requireRole('platform_admin', 'scan_admin'), async (c) => {
  try {
    const { status, scanner_id, scan_id, limit = '50', offset = '0' } = c.req.query();
    const limitNum = Math.min(parseInt(limit) || 50, 200);
    const offsetNum = parseInt(offset) || 0;

    let query = 'SELECT * FROM capture_sessions WHERE 1=1';
    let countQuery = 'SELECT COUNT(*) as total FROM capture_sessions WHERE 1=1';
    const params: string[] = [];
    const countParams: string[] = [];

    if (status) {
      query += ' AND status = ?';
      countQuery += ' AND status = ?';
      params.push(status);
      countParams.push(status);
    }

    if (scanner_id) {
      query += ' AND scanner_id = ?';
      countQuery += ' AND scanner_id = ?';
      params.push(scanner_id);
      countParams.push(scanner_id);
    }

    if (scan_id) {
      query += ' AND scan_id = ?';
      countQuery += ' AND scan_id = ?';
      params.push(scan_id);
      countParams.push(scan_id);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';

    const result = await c.env.DB.prepare(query).bind(...params, limitNum, offsetNum).all();
    const countResult = await c.env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>();

    return c.json({
      captures: result.results || [],
      total: countResult?.total || 0,
      limit: limitNum,
      offset: offsetNum,
    });
  } catch (error: unknown) {
    console.error('List captures error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to list captures', message }, 500);
  }
});

// GET /:id - Get single capture session (platform_admin, scan_admin)
captures.get('/:id', requireRole('platform_admin', 'scan_admin'), async (c) => {
  try {
    const id = c.req.param('id');
    const session = await c.env.DB.prepare(
      'SELECT * FROM capture_sessions WHERE id = ?'
    ).bind(id).first();

    if (!session) {
      return c.json({ error: 'Capture session not found' }, 404);
    }

    return c.json(session);
  } catch (error: unknown) {
    console.error('Get capture error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to get capture', message }, 500);
  }
});

// GET /:id/download - Download PCAP from R2 (platform_admin, scan_admin)
captures.get('/:id/download', requireRole('platform_admin', 'scan_admin'), async (c) => {
  try {
    const id = c.req.param('id');

    const session = await c.env.DB.prepare(
      'SELECT id, pcap_r2_key, pcap_size_bytes, scanner_id FROM capture_sessions WHERE id = ?'
    ).bind(id).first<{
      id: string;
      pcap_r2_key: string | null;
      pcap_size_bytes: number;
      scanner_id: string;
    }>();

    if (!session) {
      return c.json({ error: 'Capture session not found' }, 404);
    }

    if (!session.pcap_r2_key) {
      return c.json({ error: 'No PCAP file uploaded for this capture session' }, 404);
    }

    const object = await c.env.STORAGE.get(session.pcap_r2_key);
    if (!object) {
      return c.json({ error: 'PCAP file not found in storage' }, 404);
    }

    const filename = `capture_${id}.pcap`;
    return new Response(object.body, {
      headers: {
        'Content-Type': 'application/vnd.tcpdump.pcap',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Length': String(session.pcap_size_bytes || object.size),
      },
    });
  } catch (error: unknown) {
    console.error('Download PCAP error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to download PCAP', message }, 500);
  }
});

// DELETE /:id - Delete capture session and associated PCAP (platform_admin only)
captures.delete('/:id', requireRole('platform_admin'), async (c) => {
  try {
    const id = c.req.param('id');

    const session = await c.env.DB.prepare(
      'SELECT id, pcap_r2_key FROM capture_sessions WHERE id = ?'
    ).bind(id).first<{ id: string; pcap_r2_key: string | null }>();

    if (!session) {
      return c.json({ error: 'Capture session not found' }, 404);
    }

    // Delete from R2 if uploaded
    if (session.pcap_r2_key) {
      await c.env.STORAGE.delete(session.pcap_r2_key);
    }

    // Delete from DB
    await c.env.DB.prepare('DELETE FROM capture_sessions WHERE id = ?').bind(id).run();

    return c.json({ message: 'Capture session deleted' });
  } catch (error: unknown) {
    console.error('Delete capture error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return c.json({ error: 'Failed to delete capture', message }, 500);
  }
});
