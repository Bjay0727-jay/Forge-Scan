import { describe, it, expect } from 'vitest';
import { transformNVDtoCVE, type NVDVulnerability } from './nvd-client';

// Helper to create a minimal valid NVD item
function makeNVDItem(overrides: Partial<NVDVulnerability['cve']> = {}): NVDVulnerability {
  return {
    cve: {
      id: 'CVE-2024-1234',
      descriptions: [
        { lang: 'en', value: 'A test vulnerability' },
        { lang: 'es', value: 'Una vulnerabilidad de prueba' },
      ],
      published: '2024-01-15T12:00:00.000',
      lastModified: '2024-02-01T08:00:00.000',
      ...overrides,
    },
  };
}

describe('transformNVDtoCVE', () => {
  it('extracts the CVE ID', () => {
    const result = transformNVDtoCVE(makeNVDItem());
    expect(result.cve_id).toBe('CVE-2024-1234');
  });

  it('extracts English description from descriptions array', () => {
    const result = transformNVDtoCVE(makeNVDItem());
    expect(result.description).toBe('A test vulnerability');
  });

  it('returns empty description when no English entry', () => {
    const result = transformNVDtoCVE(
      makeNVDItem({ descriptions: [{ lang: 'es', value: 'Solo español' }] })
    );
    expect(result.description).toBe('');
  });

  it('extracts CVSS v3.1 score and vector when present', () => {
    const result = transformNVDtoCVE(
      makeNVDItem({
        metrics: {
          cvssMetricV31: [
            {
              cvssData: {
                version: '3.1',
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                baseScore: 9.8,
                baseSeverity: 'CRITICAL',
              },
            },
          ],
        },
      })
    );
    expect(result.cvss_score).toBe(9.8);
    expect(result.cvss_vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result.cvss_version).toBe('3.1');
    expect(result.severity).toBe('critical');
  });

  it('falls back to CVSS v2 when v3.1 is absent', () => {
    const result = transformNVDtoCVE(
      makeNVDItem({
        metrics: {
          cvssMetricV2: [
            {
              cvssData: {
                version: '2.0',
                vectorString: 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
                baseScore: 7.5,
              },
            },
          ],
        },
      })
    );
    expect(result.cvss_score).toBe(7.5);
    expect(result.cvss_version).toBe('2.0');
    expect(result.severity).toBe('high'); // scoreSeverity(7.5) = 'high'
  });

  it('handles missing metrics entirely', () => {
    const result = transformNVDtoCVE(makeNVDItem({ metrics: undefined }));
    expect(result.cvss_score).toBeNull();
    expect(result.cvss_vector).toBeNull();
    expect(result.severity).toBe('unknown');
  });

  it('derives severity from score when baseSeverity is absent', () => {
    const result = transformNVDtoCVE(
      makeNVDItem({
        metrics: {
          cvssMetricV31: [
            {
              cvssData: {
                version: '3.1',
                vectorString: 'CVSS:3.1/...',
                baseScore: 4.5,
                baseSeverity: '', // empty
              },
            },
          ],
        },
      })
    );
    expect(result.severity).toBe('medium'); // scoreSeverity(4.5) = 'medium'
  });

  it('extracts CWE IDs, filtering out NVD-CWE-Other and NVD-CWE-noinfo', () => {
    const result = transformNVDtoCVE(
      makeNVDItem({
        weaknesses: [
          {
            description: [
              { lang: 'en', value: 'CWE-79' },
              { lang: 'en', value: 'NVD-CWE-Other' },
              { lang: 'en', value: 'NVD-CWE-noinfo' },
              { lang: 'en', value: 'CWE-89' },
            ],
          },
        ],
      })
    );
    expect(result.cwe_ids).toEqual(['CWE-79', 'CWE-89']);
  });

  it('extracts vulnerable CPE strings from configurations', () => {
    const result = transformNVDtoCVE(
      makeNVDItem({
        configurations: [
          {
            nodes: [
              {
                cpeMatch: [
                  { vulnerable: true, criteria: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*' },
                  { vulnerable: false, criteria: 'cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*' },
                  { vulnerable: true, criteria: 'cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*' },
                ],
              },
            ],
          },
        ],
      })
    );
    expect(result.affected_products).toHaveLength(2);
    expect(result.affected_products[0]).toContain('product:1.0');
    expect(result.affected_products[1]).toContain('product:2.0');
  });

  it('limits affected_products to 50 entries', () => {
    const manyCPEs = Array.from({ length: 60 }, (_, i) => ({
      vulnerable: true,
      criteria: `cpe:2.3:a:vendor:product:${i}:*:*:*:*:*:*:*`,
    }));
    const result = transformNVDtoCVE(
      makeNVDItem({
        configurations: [{ nodes: [{ cpeMatch: manyCPEs }] }],
      })
    );
    expect(result.affected_products).toHaveLength(50);
  });

  it('limits references to 20 entries', () => {
    const manyRefs = Array.from({ length: 25 }, (_, i) => ({
      url: `https://example.com/ref/${i}`,
    }));
    const result = transformNVDtoCVE(
      makeNVDItem({ references: manyRefs })
    );
    expect(result.references_list).toHaveLength(20);
  });

  it('extracts references URLs', () => {
    const result = transformNVDtoCVE(
      makeNVDItem({
        references: [
          { url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234' },
          { url: 'https://github.com/advisory/GHSA-1234' },
        ],
      })
    );
    expect(result.references_list).toEqual([
      'https://nvd.nist.gov/vuln/detail/CVE-2024-1234',
      'https://github.com/advisory/GHSA-1234',
    ]);
  });

  it('preserves published and modified dates', () => {
    const result = transformNVDtoCVE(makeNVDItem());
    expect(result.published_at).toBe('2024-01-15T12:00:00.000');
    expect(result.modified_at).toBe('2024-02-01T08:00:00.000');
  });
});

// Test severity mapping indirectly via transformNVDtoCVE with CVSS v2 scores
describe('scoreSeverity (via transformNVDtoCVE)', () => {
  function makeWithScore(score: number): NVDVulnerability {
    return makeNVDItem({
      metrics: {
        cvssMetricV2: [
          {
            cvssData: {
              version: '2.0',
              vectorString: 'AV:N/...',
              baseScore: score,
            },
          },
        ],
      },
    });
  }

  it('score >= 9.0 returns critical', () => {
    expect(transformNVDtoCVE(makeWithScore(9.0)).severity).toBe('critical');
    expect(transformNVDtoCVE(makeWithScore(10.0)).severity).toBe('critical');
  });

  it('score >= 7.0 returns high', () => {
    expect(transformNVDtoCVE(makeWithScore(7.0)).severity).toBe('high');
    expect(transformNVDtoCVE(makeWithScore(8.9)).severity).toBe('high');
  });

  it('score >= 4.0 returns medium', () => {
    expect(transformNVDtoCVE(makeWithScore(4.0)).severity).toBe('medium');
    expect(transformNVDtoCVE(makeWithScore(6.9)).severity).toBe('medium');
  });

  it('score > 0 returns low', () => {
    expect(transformNVDtoCVE(makeWithScore(0.1)).severity).toBe('low');
    expect(transformNVDtoCVE(makeWithScore(3.9)).severity).toBe('low');
  });

  it('score 0 returns info', () => {
    expect(transformNVDtoCVE(makeWithScore(0)).severity).toBe('info');
  });
});
