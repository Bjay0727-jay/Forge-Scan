// NVD API 2.0, CISA KEV, and FIRST EPSS clients
// Designed for Cloudflare Workers (fetch-based, no native HTTP/2)

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_API_BASE = 'https://api.first.org/data/v1/epss';

// --- NVD Types ---

export interface NVDResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: NVDVulnerability[];
}

export interface NVDVulnerability {
  cve: {
    id: string;
    descriptions: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: {
          version: string;
          vectorString: string;
          baseScore: number;
          baseSeverity: string;
        };
      }>;
      cvssMetricV2?: Array<{
        cvssData: {
          version: string;
          vectorString: string;
          baseScore: number;
        };
      }>;
    };
    weaknesses?: Array<{
      description: Array<{ lang: string; value: string }>;
    }>;
    configurations?: Array<{
      nodes: Array<{
        cpeMatch: Array<{
          vulnerable: boolean;
          criteria: string;
        }>;
      }>;
    }>;
    references?: Array<{ url: string; source?: string; tags?: string[] }>;
    published: string;
    lastModified: string;
  };
}

export interface NVDFetchParams {
  lastModStartDate?: string;
  lastModEndDate?: string;
  pubStartDate?: string;
  pubEndDate?: string;
  startIndex?: number;
  resultsPerPage?: number;
  keywordSearch?: string;
  cveId?: string;
}

// --- KEV Types ---

export interface KEVCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KEVEntry[];
}

export interface KEVEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
  knownRansomwareCampaignUse: string;
}

// --- EPSS Types ---

export interface EPSSResponse {
  status: string;
  'status-code': number;
  total: number;
  offset: number;
  limit: number;
  data: EPSSEntry[];
}

export interface EPSSEntry {
  cve: string;
  epss: string;
  percentile: string;
  date: string;
}

// --- Transformed output ---

export interface VulnerabilityRecord {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss_version: string;
  severity: string;
  cwe_ids: string[];
  affected_products: string[];
  references_list: string[];
  published_at: string;
  modified_at: string;
}

// --- NVD Client ---

export class NVDClient {
  private apiKey?: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey;
  }

  private async fetchWithRetry(url: string, maxRetries = 3): Promise<Response> {
    const headers: Record<string, string> = {
      'User-Agent': 'ForgeScan/1.0',
    };
    // NVD recommends sending the API key via header, not query param
    if (this.apiKey) {
      headers['apiKey'] = this.apiKey;
    }

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const response = await fetch(url, { headers });

      if (response.status === 429 || response.status === 403) {
        // Rate limited — exponential backoff: 8s, 16s, 32s
        const backoffMs = Math.min(8000 * Math.pow(2, attempt), 32000);
        console.log(`NVD rate limited (${response.status}), backing off ${backoffMs}ms (attempt ${attempt + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, backoffMs));
        continue;
      }

      return response;
    }

    // Final attempt after all retries exhausted
    return fetch(url, { headers });
  }

  async fetchCVEs(params: NVDFetchParams = {}): Promise<NVDResponse> {
    const searchParams = new URLSearchParams();

    if (params.lastModStartDate) searchParams.set('lastModStartDate', params.lastModStartDate);
    if (params.lastModEndDate) searchParams.set('lastModEndDate', params.lastModEndDate);
    if (params.pubStartDate) searchParams.set('pubStartDate', params.pubStartDate);
    if (params.pubEndDate) searchParams.set('pubEndDate', params.pubEndDate);
    if (params.startIndex !== undefined) searchParams.set('startIndex', String(params.startIndex));
    if (params.resultsPerPage !== undefined) searchParams.set('resultsPerPage', String(params.resultsPerPage));
    if (params.keywordSearch) searchParams.set('keywordSearch', params.keywordSearch);
    if (params.cveId) searchParams.set('cveId', params.cveId);

    const url = `${NVD_API_BASE}?${searchParams.toString()}`;
    const response = await this.fetchWithRetry(url);

    if (!response.ok) {
      throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  async fetchKEV(): Promise<KEVCatalog> {
    const response = await fetch(KEV_URL, {
      headers: { 'User-Agent': 'ForgeScan/1.0' },
    });

    if (!response.ok) {
      throw new Error(`CISA KEV error: ${response.status}`);
    }

    return response.json();
  }

  async fetchEPSS(cveIds?: string[]): Promise<EPSSResponse> {
    let url = EPSS_API_BASE;

    if (cveIds && cveIds.length > 0) {
      // Batch up to 100 CVEs per request
      const batch = cveIds.slice(0, 100);
      url += `?cve=${batch.join(',')}`;
    } else {
      // Get latest scores (limited)
      url += '?limit=100&offset=0';
    }

    const response = await fetch(url, {
      headers: { 'User-Agent': 'ForgeScan/1.0' },
    });

    if (!response.ok) {
      throw new Error(`EPSS API error: ${response.status}`);
    }

    return response.json();
  }
}

// --- Transform NVD data to our schema ---

export function transformNVDtoCVE(nvdItem: NVDVulnerability): VulnerabilityRecord {
  const cve = nvdItem.cve;

  // Extract English description
  const description = cve.descriptions?.find(d => d.lang === 'en')?.value || '';

  // Extract CVSS v3.1 score (prefer v3.1 over v2)
  let cvssScore: number | null = null;
  let cvssVector: string | null = null;
  let cvssVersion = '3.1';
  let severity = 'unknown';

  if (cve.metrics?.cvssMetricV31?.length) {
    const metric = cve.metrics.cvssMetricV31[0];
    cvssScore = metric.cvssData.baseScore;
    cvssVector = metric.cvssData.vectorString;
    cvssVersion = metric.cvssData.version;
    severity = metric.cvssData.baseSeverity?.toLowerCase() || scoreSeverity(cvssScore);
  } else if (cve.metrics?.cvssMetricV2?.length) {
    const metric = cve.metrics.cvssMetricV2[0];
    cvssScore = metric.cvssData.baseScore;
    cvssVector = metric.cvssData.vectorString;
    cvssVersion = '2.0';
    severity = scoreSeverity(cvssScore);
  }

  // Extract CWE IDs
  const cweIds: string[] = [];
  cve.weaknesses?.forEach(w => {
    w.description?.forEach(d => {
      if (d.value && d.value !== 'NVD-CWE-Other' && d.value !== 'NVD-CWE-noinfo') {
        cweIds.push(d.value);
      }
    });
  });

  // Extract affected products (CPE strings)
  const affectedProducts: string[] = [];
  cve.configurations?.forEach(config => {
    config.nodes?.forEach(node => {
      node.cpeMatch?.forEach(match => {
        if (match.vulnerable) {
          affectedProducts.push(match.criteria);
        }
      });
    });
  });

  // Extract references
  const referencesList = cve.references?.map(r => r.url) || [];

  return {
    cve_id: cve.id,
    description,
    cvss_score: cvssScore,
    cvss_vector: cvssVector,
    cvss_version: cvssVersion,
    severity,
    cwe_ids: cweIds,
    affected_products: affectedProducts.slice(0, 50), // Limit to prevent massive entries
    references_list: referencesList.slice(0, 20),
    published_at: cve.published,
    modified_at: cve.lastModified,
  };
}

function scoreSeverity(score: number): string {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
