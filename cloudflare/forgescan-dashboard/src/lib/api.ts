import type {
  ApiResponse,
  PaginatedResponse,
  Asset,
  Finding,
  Scan,
  DashboardStats,
  AssetListParams,
  FindingListParams,
  ScanListParams,
  CreateAssetInput,
  CreateScanInput,
  UpdateFindingInput,
  ImportResult,
  ImportFormat,
  Severity,
  ActiveScansResponse,
  ScanTasksResponse,
  IngestJob,
  IngestUploadResult,
  IngestVendorInfo,
  IngestVendor,
  IngestDataType,
} from '@/types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;

  // Inject auth token if available
  const token = localStorage.getItem('forgescan_token');
  const authHeaders: Record<string, string> = {};
  if (token) {
    authHeaders['Authorization'] = `Bearer ${token}`;
  }

  const config: RequestInit = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders,
      ...options.headers,
    },
  };

  try {
    const response = await fetch(url, config);

    // Handle 401 - redirect to login
    if (response.status === 401) {
      localStorage.removeItem('forgescan_token');
      localStorage.removeItem('forgescan_user');
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
      throw new ApiError('Session expired. Please log in again.', 401);
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new ApiError(
        errorData.error || `HTTP error ${response.status}`,
        response.status
      );
    }

    // Handle empty responses
    const text = await response.text();
    if (!text) {
      return {} as T;
    }

    return JSON.parse(text);
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(
      error instanceof Error ? error.message : 'Network error',
      0
    );
  }
}

function buildQueryString(params: Record<string, string | number | boolean | undefined | null | Array<string | number>>): string {
  const searchParams = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      if (Array.isArray(value)) {
        value.forEach((v) => searchParams.append(key, String(v)));
      } else {
        searchParams.append(key, String(value));
      }
    }
  });

  const queryString = searchParams.toString();
  return queryString ? `?${queryString}` : '';
}

// Dashboard API
export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    // Use /overview endpoint and transform response to match DashboardStats
    const overview = await request<{
      totals: { total_assets: number; open_findings: number; fixed_findings: number; completed_scans: number };
      severity_breakdown: Array<{ severity: string; count: number }>;
      recent_findings: Array<Finding>;
      top_vulnerable_assets: Array<unknown>;
      generated_at: string;
    }>('/dashboard/overview');

    // Transform severity breakdown to record
    const findings_by_severity: Record<string, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0
    };
    overview.severity_breakdown?.forEach((item) => {
      findings_by_severity[item.severity] = item.count;
    });

    // Calculate total findings from severity counts
    const total_findings = Object.values(findings_by_severity).reduce((a, b) => a + b, 0);

    return {
      total_assets: overview.totals?.total_assets || 0,
      total_findings,
      total_scans: overview.totals?.completed_scans || 0,
      findings_by_severity: findings_by_severity as Record<Severity, number>,
      findings_by_state: {
        open: overview.totals?.open_findings || 0,
        acknowledged: 0,
        resolved: overview.totals?.fixed_findings || 0,
        false_positive: 0
      },
      recent_findings: overview.recent_findings || [],
      risk_trend: [],
      top_vulnerabilities: [],
    };
  },
};

// Assets API
export const assetsApi = {
  list: async (
    params: AssetListParams = {}
  ): Promise<PaginatedResponse<Asset>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<Asset>>(`/assets${query}`);
  },

  get: async (id: string): Promise<Asset> => {
    return request<Asset>(`/assets/${id}`);
  },

  create: async (data: CreateAssetInput): Promise<Asset> => {
    return request<Asset>('/assets', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  update: async (id: string, data: Partial<CreateAssetInput>): Promise<Asset> => {
    return request<Asset>(`/assets/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  delete: async (id: string): Promise<void> => {
    return request<void>(`/assets/${id}`, {
      method: 'DELETE',
    });
  },
};

// Findings API
export const findingsApi = {
  list: async (
    params: FindingListParams = {}
  ): Promise<PaginatedResponse<Finding>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<Finding>>(`/findings${query}`);
  },

  get: async (id: string): Promise<Finding> => {
    return request<Finding>(`/findings/${id}`);
  },

  update: async (id: string, data: UpdateFindingInput): Promise<Finding> => {
    return request<Finding>(`/findings/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  bulkUpdate: async (
    ids: string[],
    data: UpdateFindingInput
  ): Promise<{ updated: number }> => {
    return request<{ updated: number }>('/findings/bulk', {
      method: 'PUT',
      body: JSON.stringify({ ids, ...data }),
    });
  },
};

// Scans API
export const scansApi = {
  list: async (params: ScanListParams = {}): Promise<PaginatedResponse<Scan>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<Scan>>(`/scans${query}`);
  },

  get: async (id: string): Promise<Scan> => {
    return request<Scan>(`/scans/${id}`);
  },

  create: async (data: CreateScanInput): Promise<Scan> => {
    return request<Scan>('/scans', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  start: async (id: string): Promise<Scan> => {
    return request<Scan>(`/scans/${id}/start`, {
      method: 'POST',
    });
  },

  cancel: async (id: string): Promise<Scan> => {
    return request<Scan>(`/scans/${id}/cancel`, {
      method: 'POST',
    });
  },

  delete: async (id: string): Promise<void> => {
    return request<void>(`/scans/${id}`, {
      method: 'DELETE',
    });
  },

  getFindings: async (
    id: string,
    params: FindingListParams = {}
  ): Promise<PaginatedResponse<Finding>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<Finding>>(`/scans/${id}/findings${query}`);
  },

  getActive: async (): Promise<ActiveScansResponse> => {
    return request<ActiveScansResponse>('/scans/active');
  },

  getTasks: async (id: string): Promise<ScanTasksResponse> => {
    return request<ScanTasksResponse>(`/scans/${id}/tasks`);
  },
};

// Import API
export const importApi = {
  // Import findings
  importData: async (
    format: ImportFormat,
    data: string | object
  ): Promise<ImportResult> => {
    return request<ImportResult>('/import', {
      method: 'POST',
      body: JSON.stringify({ format, data }),
    });
  },

  uploadFile: async (
    format: ImportFormat,
    file: File
  ): Promise<ImportResult> => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('format', format);

    const token = localStorage.getItem('forgescan_token');
    const response = await fetch(`${API_BASE_URL}/import/upload`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new ApiError(
        errorData.error || `HTTP error ${response.status}`,
        response.status
      );
    }

    return response.json();
  },

  // Import assets
  importAssets: async (
    format: string,
    data: string | object
  ): Promise<ImportResult> => {
    return request<ImportResult>('/import/assets', {
      method: 'POST',
      body: JSON.stringify({ format, data }),
    });
  },

  uploadAssetFile: async (
    format: string,
    file: File
  ): Promise<ImportResult> => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('format', format);

    const token = localStorage.getItem('forgescan_token');
    const response = await fetch(`${API_BASE_URL}/import/assets/upload`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new ApiError(
        errorData.error || `HTTP error ${response.status}`,
        response.status
      );
    }

    return response.json();
  },
};

// Ingest API (vendor-specific CSV import)
export const ingestApi = {
  uploadFile: async (
    file: File,
    vendor: IngestVendor = 'generic',
    dataType: IngestDataType = 'findings',
  ): Promise<IngestUploadResult> => {
    const formData = new FormData();
    formData.append('file', file);

    const token = localStorage.getItem('forgescan_token');
    const query = buildQueryString({ vendor, type: dataType });
    const response = await fetch(`${API_BASE_URL}/ingest/upload${query}`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new ApiError(
        errorData.error?.message || errorData.error || `HTTP error ${response.status}`,
        response.status
      );
    }

    return response.json();
  },

  getJobs: async (params: {
    limit?: number;
    vendor?: string;
    status?: string;
  } = {}): Promise<IngestJob[]> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<IngestJob[]>(`/ingest/jobs${query}`);
  },

  getJob: async (id: string): Promise<IngestJob> => {
    return request<IngestJob>(`/ingest/jobs/${id}`);
  },

  getVendors: async (): Promise<IngestVendorInfo> => {
    return request<IngestVendorInfo>('/ingest/vendors');
  },
};

// Health check
export const healthApi = {
  check: async (): Promise<ApiResponse<{ status: string }>> => {
    return request<ApiResponse<{ status: string }>>('/health');
  },
};

export { ApiError };
