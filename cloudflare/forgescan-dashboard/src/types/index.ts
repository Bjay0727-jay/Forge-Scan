// User types
export interface User {
  id: string;
  email: string;
  display_name: string;
  role: UserRole;
  is_active?: boolean;
  last_login_at?: string;
  created_at?: string;
  updated_at?: string;
}

export type UserRole = 'platform_admin' | 'scan_admin' | 'vuln_manager' | 'remediation_owner' | 'auditor';

export interface LoginResponse {
  token: string;
  expires_at: string;
  user: User;
}

// Severity levels for findings
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Finding state
export type FindingState = 'open' | 'acknowledged' | 'resolved' | 'false_positive';

// Asset types
export type AssetType = 'host' | 'container' | 'cloud_resource' | 'repository' | 'application';

// Scan types
export type ScanType = 'network' | 'container' | 'cloud' | 'web' | 'code' | 'compliance';

// Scan status
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

// Asset interface
export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  identifier: string;
  metadata: Record<string, unknown>;
  tags: string[];
  risk_score: number;
  created_at: string;
  updated_at: string;
}

// Finding interface
export interface Finding {
  id: string;
  asset_id: string;
  scan_id: string;
  title: string;
  description: string;
  severity: Severity;
  state: FindingState;
  cve_id?: string;
  cvss_score?: number;
  affected_component: string;
  remediation?: string;
  references: string[];
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
}

// Scan interface
export interface Scan {
  id: string;
  name: string;
  type: ScanType;
  status: ScanStatus;
  target: string;
  configuration: Record<string, unknown>;
  findings_count: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

// Dashboard statistics
export interface DashboardStats {
  total_assets: number;
  total_findings: number;
  total_scans: number;
  findings_by_severity: Record<Severity, number>;
  findings_by_state: Record<FindingState, number>;
  recent_findings: Finding[];
  risk_trend: RiskTrendPoint[];
  top_vulnerabilities: TopVulnerability[];
}

export interface RiskTrendPoint {
  date: string;
  risk_score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TopVulnerability {
  cve_id: string;
  title: string;
  severity: Severity;
  affected_assets: number;
  cvss_score: number;
}

// API response types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// Query parameters for list endpoints
export interface ListParams {
  page?: number;
  page_size?: number;
  search?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

export interface AssetListParams extends ListParams {
  type?: AssetType;
  tags?: string[];
}

export interface FindingListParams extends ListParams {
  severity?: Severity;
  state?: FindingState;
  asset_id?: string;
  scan_id?: string;
  cve_id?: string;
}

export interface ScanListParams extends ListParams {
  type?: ScanType;
  status?: ScanStatus;
}

// Create/Update types
export interface CreateAssetInput {
  name: string;
  type: AssetType;
  identifier: string;
  metadata?: Record<string, unknown>;
  tags?: string[];
}

export interface CreateScanInput {
  name: string;
  type: ScanType;
  target: string;
  configuration?: Record<string, unknown>;
}

export interface UpdateFindingInput {
  state?: FindingState;
  remediation?: string;
}

// Import types
export interface ImportResult {
  success: boolean;
  imported_count: number;
  failed_count: number;
  errors: string[];
}

export type ImportFormat = 'sarif' | 'cyclonedx' | 'csv' | 'json';
