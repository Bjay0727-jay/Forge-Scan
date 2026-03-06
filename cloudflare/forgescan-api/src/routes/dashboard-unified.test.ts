import { describe, it, expect, vi } from 'vitest';
import { dashboard } from './dashboard';
import { createTestApp, createMockDB } from '../test-helpers';

function createApp(db?: any) {
  return createTestApp(dashboard as any, '/api/v1/dashboard', db);
}

describe('Unified Dashboard', () => {
  describe('GET /api/v1/dashboard/unified', () => {
    it('returns unified compliance + threats view', async () => {
      const db = createMockDB({
        firstResult: {
          // Used for threat counts, POA&M stats, evidence stats
          total_open: 25, critical: 3, high: 8, medium: 10, low: 4, risk_score: 100,
          total: 10, open_count: 5, in_progress: 3, completed: 1, delayed: 1, overdue: 2,
          total_evidence: 15, expired: 1,
        },
        allResults: [],
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/dashboard/unified');
      expect(res.status).toBe(200);
      const body = await res.json() as any;

      // Check top-level sections exist
      expect(body.threat_posture).toBeDefined();
      expect(body.compliance_posture).toBeDefined();
      expect(body.poam_summary).toBeDefined();
      expect(body.evidence_summary).toBeDefined();
      expect(body.control_threat_correlation).toBeDefined();
      expect(body.recent_events).toBeDefined();
      expect(body.generated_at).toBeDefined();
    });

    it('includes risk score and grade', async () => {
      const db = createMockDB({
        firstResult: {
          total_open: 5, critical: 0, high: 0, medium: 3, low: 2, risk_score: 8,
          total: 0, open_count: 0, in_progress: 0, completed: 0, delayed: 0, overdue: 0,
          total_evidence: 0, expired: 0,
        },
        allResults: [],
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/dashboard/unified');
      const body = await res.json() as any;

      expect(body.threat_posture.risk_score).toBeDefined();
      expect(body.threat_posture.risk_grade).toBeDefined();
      expect(['A', 'B', 'C', 'D', 'F']).toContain(body.threat_posture.risk_grade);
    });

    it('includes compliance posture with frameworks array', async () => {
      const db = createMockDB({
        firstResult: {
          total_open: 0, critical: 0, high: 0, medium: 0, low: 0, risk_score: 0,
          total: 0, open_count: 0, in_progress: 0, completed: 0, delayed: 0, overdue: 0,
          total_evidence: 0, expired: 0,
          total_controls: 10, compliant: 7, non_compliant: 2, partial: 1, not_assessed: 0,
        },
        allResults: [],
      });
      const app = createApp(db);

      const res = await app.request('/api/v1/dashboard/unified');
      const body = await res.json() as any;

      expect(body.compliance_posture.frameworks).toBeDefined();
      expect(Array.isArray(body.compliance_posture.frameworks)).toBe(true);
      expect(body.compliance_posture.overall_compliance_pct).toBeDefined();
    });

    it('returns consistent data across calls', async () => {
      const db = createMockDB({
        firstResult: {
          total_open: 5, critical: 1, high: 2, medium: 1, low: 1, risk_score: 42,
          total: 3, open_count: 2, in_progress: 1, completed: 0, delayed: 0, overdue: 1,
          total_evidence: 5, expired: 0,
        },
        allResults: [],
      });
      const app = createApp(db);

      const res1 = await app.request('/api/v1/dashboard/unified');
      expect(res1.status).toBe(200);
      const body1 = await res1.json() as any;

      const res2 = await app.request('/api/v1/dashboard/unified');
      expect(res2.status).toBe(200);
      const body2 = await res2.json() as any;

      // Both calls should return the same structure
      expect(body1.threat_posture.risk_score).toBe(body2.threat_posture.risk_score);
      expect(body1.threat_posture.risk_grade).toBe(body2.threat_posture.risk_grade);
    });
  });
});
