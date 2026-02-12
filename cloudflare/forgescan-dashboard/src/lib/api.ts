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

  const config: RequestInit = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  };

  try {
    const response = await fetch(url, config);

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
    return request<DashboardStats>('/dashboard/stats');
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
};

// Import API
export const importApi = {
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

    const response = await fetch(`${API_BASE_URL}/import/upload`, {
      method: 'POST',
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

// Health check
export const healthApi = {
  check: async (): Promise<ApiResponse<{ status: string }>> => {
    return request<ApiResponse<{ status: string }>>('/health');
  },
};

export { ApiError };
