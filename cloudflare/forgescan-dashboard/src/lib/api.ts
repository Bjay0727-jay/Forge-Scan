import type {
  ApiResponse,
  PaginatedResponse,
  Asset,
  Finding,
  Scan,
  DashboardStats,
  ExecutiveMetrics,
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
  RedOpsCampaign,
  RedOpsAgent,
  RedOpsFinding,
  RedOpsAgentType,
  RedOpsOverview,
  CreateCampaignInput,
  SOCAlert,
  SOCIncident,
  SOCDetectionRule,
  SOCOverview,
  Organization,
  OrgBranding,
  MSSPOverview,
  TenantHealthCard,
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

  getExecutiveMetrics: async (days: number = 90): Promise<ExecutiveMetrics> => {
    return request<ExecutiveMetrics>(`/dashboard/executive?days=${days}`);
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

// ForgeRedOPS API
export const redopsApi = {
  // Overview stats
  getOverview: async (): Promise<RedOpsOverview> => {
    return request<RedOpsOverview>('/redops/overview');
  },

  // Campaigns
  listCampaigns: async (params: {
    page?: number;
    page_size?: number;
    status?: string;
    type?: string;
    sort?: string;
  } = {}): Promise<PaginatedResponse<RedOpsCampaign>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<RedOpsCampaign>>(`/redops/campaigns${query}`);
  },

  getCampaign: async (id: string): Promise<RedOpsCampaign> => {
    return request<RedOpsCampaign>(`/redops/campaigns/${id}`);
  },

  createCampaign: async (data: CreateCampaignInput): Promise<RedOpsCampaign> => {
    return request<RedOpsCampaign>('/redops/campaigns', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  updateCampaign: async (id: string, data: Partial<CreateCampaignInput>): Promise<RedOpsCampaign> => {
    return request<RedOpsCampaign>(`/redops/campaigns/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  launchCampaign: async (id: string): Promise<{ campaign: RedOpsCampaign; agents_created: number; message: string }> => {
    return request<{ campaign: RedOpsCampaign; agents_created: number; message: string }>(`/redops/campaigns/${id}/launch`, {
      method: 'POST',
    });
  },

  cancelCampaign: async (id: string): Promise<{ message: string }> => {
    return request<{ message: string }>(`/redops/campaigns/${id}/cancel`, {
      method: 'POST',
    });
  },

  deleteCampaign: async (id: string): Promise<void> => {
    return request<void>(`/redops/campaigns/${id}`, {
      method: 'DELETE',
    });
  },

  // Agents
  getCampaignAgents: async (campaignId: string, params: {
    status?: string;
    category?: string;
  } = {}): Promise<RedOpsAgent[]> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<RedOpsAgent[]>(`/redops/campaigns/${campaignId}/agents${query}`);
  },

  getAgent: async (id: string): Promise<RedOpsAgent> => {
    return request<RedOpsAgent>(`/redops/agents/${id}`);
  },

  getAgentTypes: async (category?: string): Promise<RedOpsAgentType[]> => {
    const query = category ? `?category=${category}` : '';
    return request<RedOpsAgentType[]>(`/redops/agent-types${query}`);
  },

  // Findings
  getCampaignFindings: async (campaignId: string, params: {
    page?: number;
    page_size?: number;
    severity?: string;
    exploitable?: string;
    status?: string;
  } = {}): Promise<PaginatedResponse<RedOpsFinding>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<RedOpsFinding>>(`/redops/campaigns/${campaignId}/findings${query}`);
  },

  listFindings: async (params: {
    page?: number;
    page_size?: number;
    severity?: string;
    exploitable?: string;
    status?: string;
  } = {}): Promise<PaginatedResponse<RedOpsFinding>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<RedOpsFinding>>(`/redops/findings${query}`);
  },

  updateFinding: async (id: string, data: {
    status?: string;
    remediation?: string;
    remediation_effort?: string;
  }): Promise<RedOpsFinding> => {
    return request<RedOpsFinding>(`/redops/findings/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },
};

// ForgeSOC API
export const socApi = {
  getOverview: async (): Promise<SOCOverview> => {
    return request<SOCOverview>('/soc/overview');
  },

  listAlerts: async (params: {
    page?: number;
    page_size?: number;
    severity?: string;
    status?: string;
    alert_type?: string;
    source?: string;
  } = {}): Promise<PaginatedResponse<SOCAlert>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<SOCAlert>>(`/soc/alerts${query}`);
  },

  getAlert: async (id: string): Promise<SOCAlert> => {
    return request<SOCAlert>(`/soc/alerts/${id}`);
  },

  createAlert: async (data: {
    title: string;
    description?: string;
    severity?: string;
    alert_type?: string;
    assigned_to?: string;
    tags?: string[];
  }): Promise<SOCAlert> => {
    return request<SOCAlert>('/soc/alerts', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  updateAlert: async (id: string, data: {
    status?: string;
    severity?: string;
    assigned_to?: string;
    incident_id?: string;
  }): Promise<SOCAlert> => {
    return request<SOCAlert>(`/soc/alerts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  listIncidents: async (params: {
    page?: number;
    page_size?: number;
    status?: string;
    severity?: string;
  } = {}): Promise<PaginatedResponse<SOCIncident>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<SOCIncident>>(`/soc/incidents${query}`);
  },

  getIncident: async (id: string): Promise<SOCIncident> => {
    return request<SOCIncident>(`/soc/incidents/${id}`);
  },

  createIncident: async (data: {
    title: string;
    description?: string;
    severity?: string;
    incident_type?: string;
    lead_analyst?: string;
  }): Promise<SOCIncident> => {
    return request<SOCIncident>('/soc/incidents', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  updateIncident: async (id: string, data: {
    status?: string;
    severity?: string;
    lead_analyst?: string;
    root_cause?: string;
    lessons_learned?: string;
  }): Promise<SOCIncident> => {
    return request<SOCIncident>(`/soc/incidents/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  linkAlertToIncident: async (incidentId: string, alertId: string): Promise<{ message: string }> => {
    return request<{ message: string }>(`/soc/incidents/${incidentId}/alerts`, {
      method: 'POST',
      body: JSON.stringify({ alert_id: alertId }),
    });
  },

  listDetectionRules: async (): Promise<{ items: SOCDetectionRule[] }> => {
    return request<{ items: SOCDetectionRule[] }>('/soc/detection-rules');
  },

  createDetectionRule: async (data: {
    name: string;
    event_pattern: string;
    description?: string;
    conditions?: Record<string, unknown>;
    alert_severity?: string;
    alert_type?: string;
    auto_escalate?: boolean;
    cooldown_seconds?: number;
  }): Promise<SOCDetectionRule> => {
    return request<SOCDetectionRule>('/soc/detection-rules', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  updateDetectionRule: async (id: string, data: {
    name?: string;
    is_active?: number;
    conditions?: Record<string, unknown>;
    alert_severity?: string;
    auto_escalate?: number;
  }): Promise<SOCDetectionRule> => {
    return request<SOCDetectionRule>(`/soc/detection-rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  deleteDetectionRule: async (id: string): Promise<void> => {
    return request<void>(`/soc/detection-rules/${id}`, {
      method: 'DELETE',
    });
  },

  correlateCampaign: async (campaignId: string): Promise<{
    campaign_id: string;
    correlated: number;
    alert_id: string | null;
    incident_id: string | null;
    message: string;
  }> => {
    return request(`/soc/correlate/${campaignId}`, {
      method: 'POST',
    });
  },
};

// Onboarding API
export const onboardingApi = {
  getStatus: async (): Promise<{
    steps: Record<string, boolean>;
    completed: number;
    total: number;
    is_complete: boolean;
    counts: Record<string, number>;
  }> => {
    return request('/onboarding/status');
  },

  seedCompliance: async (): Promise<{ message: string; frameworks: number; controls: number }> => {
    return request('/onboarding/seed-compliance', { method: 'POST' });
  },

  quickScan: async (target: string): Promise<{
    scan_id: string;
    name: string;
    target: string;
    status: string;
    tasks_created: number;
    message: string;
  }> => {
    return request('/onboarding/quick-scan', {
      method: 'POST',
      body: JSON.stringify({ target }),
    });
  },
};

// MSSP / Multi-Tenant API
export const msspApi = {
  getOverview: async (): Promise<MSSPOverview> => {
    return request<MSSPOverview>('/mssp/overview');
  },

  listOrganizations: async (params: {
    page?: number;
    page_size?: number;
    status?: string;
    tier?: string;
    search?: string;
  } = {}): Promise<PaginatedResponse<Organization>> => {
    const query = buildQueryString(params as Record<string, string | number | boolean | undefined>);
    return request<PaginatedResponse<Organization>>(`/mssp/organizations${query}`);
  },

  getOrganization: async (id: string): Promise<Organization & { members: unknown[]; branding: OrgBranding | null; stats: Record<string, unknown> }> => {
    return request(`/mssp/organizations/${id}`);
  },

  createOrganization: async (data: {
    name: string;
    tier?: string;
    max_assets?: number;
    max_users?: number;
    max_scanners?: number;
    contact_email?: string;
    contact_name?: string;
    industry?: string;
    notes?: string;
  }): Promise<Organization> => {
    return request<Organization>('/mssp/organizations', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  updateOrganization: async (id: string, data: Partial<{
    name: string;
    tier: string;
    status: string;
    max_assets: number;
    max_users: number;
    max_scanners: number;
    contact_email: string;
    contact_name: string;
    industry: string;
    notes: string;
  }>): Promise<Organization> => {
    return request<Organization>(`/mssp/organizations/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  deleteOrganization: async (id: string): Promise<{ message: string }> => {
    return request(`/mssp/organizations/${id}`, { method: 'DELETE' });
  },

  addMember: async (orgId: string, data: { user_id: string; org_role?: string; is_primary?: boolean }): Promise<unknown> => {
    return request(`/mssp/organizations/${orgId}/members`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  updateMember: async (orgId: string, userId: string, data: { org_role?: string; is_primary?: boolean }): Promise<unknown> => {
    return request(`/mssp/organizations/${orgId}/members/${userId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  removeMember: async (orgId: string, userId: string): Promise<{ message: string }> => {
    return request(`/mssp/organizations/${orgId}/members/${userId}`, { method: 'DELETE' });
  },

  getBranding: async (orgId: string): Promise<OrgBranding> => {
    return request<OrgBranding>(`/mssp/organizations/${orgId}/branding`);
  },

  updateBranding: async (orgId: string, data: Partial<OrgBranding>): Promise<OrgBranding> => {
    return request<OrgBranding>(`/mssp/organizations/${orgId}/branding`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  getHealth: async (): Promise<{ tenants: TenantHealthCard[]; generated_at: string }> => {
    return request('/mssp/health');
  },

  getMyOrganizations: async (): Promise<{ items: Organization[]; is_mssp_admin: boolean }> => {
    return request('/mssp/my-organizations');
  },
};

// Health check
export const healthApi = {
  check: async (): Promise<ApiResponse<{ status: string }>> => {
    return request<ApiResponse<{ status: string }>>('/health');
  },
};

export { ApiError };
