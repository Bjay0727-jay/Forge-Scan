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

// Scan task status
export type TaskStatus = 'queued' | 'assigned' | 'running' | 'completed' | 'failed' | 'cancelled';

// Scan task (from scan_tasks table)
export interface ScanTask {
  id: string;
  scan_id: string;
  scanner_id: string | null;
  task_type: string;
  status: TaskStatus;
  priority: number;
  findings_count: number;
  assets_discovered: number;
  result_summary: string | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

// Progress summary for a scan's tasks
export interface ScanProgress {
  total_tasks: number;
  completed_tasks: number;
  running_tasks: number;
  failed_tasks: number;
  queued_tasks: number;
  assigned_tasks: number;
  percentage: number;
}

// Active scan with progress info (from /scans/active)
export interface ActiveScan {
  id: string;
  name: string;
  type: ScanType;
  status: ScanStatus;
  target: string;
  findings_count: number;
  assets_count: number;
  started_at: string | null;
  created_at: string;
  progress: ScanProgress;
}

// Task summary for /scans/:id/tasks
export interface TaskSummary {
  total: number;
  completed: number;
  running: number;
  failed: number;
  queued: number;
  assigned: number;
  total_findings: number;
  total_assets: number;
}

// Scan tasks API response
export interface ScanTasksResponse {
  tasks: ScanTask[];
  summary: TaskSummary;
}

// Active scans API response
export interface ActiveScansResponse {
  items: ActiveScan[];
  has_active: boolean;
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

// Executive dashboard metrics
export interface ExecutiveMetrics {
  risk_grade: {
    grade: string;
    score: number;
    open_findings: number;
    severity_counts: Record<Severity, number>;
  };
  mttr: {
    overall_avg_days: number;
    overall_sample_size: number;
    by_severity: Record<string, {
      avg_days: number;
      min_days: number;
      max_days: number;
      sample_size: number;
    }>;
  };
  sla_compliance: {
    overall_pct: number;
    by_severity: Record<string, {
      total: number;
      within_sla: number;
      compliance_pct: number;
      target_days: number;
    }>;
    targets: Record<string, number>;
    overdue: {
      total: number;
      critical: number;
      high: number;
    };
  };
  posture_trend: Array<{
    week: string;
    new_findings: number;
    fixed: number;
    risk_score: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  redops_coverage: {
    validated_cves: number;
    exploitable: number;
  };
  period_days: number;
  generated_at: string;
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
  vendor?: string;
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

// Ingest types (vendor-specific CSV import via /ingest endpoints)
export type IngestVendor = 'generic' | 'tenable' | 'qualys' | 'rapid7';
export type IngestDataType = 'findings' | 'assets' | 'auto';
export type IngestJobStatus = 'processing' | 'completed' | 'failed';

export interface IngestJob {
  id: string;
  vendor: string;
  source: string;
  status: IngestJobStatus;
  records_processed: number | null;
  records_imported: number | null;
  records_skipped: number | null;
  errors: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface IngestUploadResult {
  job_id: string;
  type: 'findings' | 'assets';
  status: string;
  records_processed: number;
  records_imported: number;
  records_skipped: number;
  errors: string[];
}

export interface IngestVendorInfo {
  vendors: string[];
  note: string;
}

// ─── ForgeRedOPS Types ───────────────────────────────────────────────────────

export type CampaignStatus = 'created' | 'queued' | 'reconnaissance' | 'scanning' | 'exploitation' | 'reporting' | 'completed' | 'failed' | 'cancelled';
export type CampaignType = 'full' | 'targeted' | 'continuous' | 'validation';
export type ExploitationLevel = 'passive' | 'safe' | 'moderate' | 'aggressive';

export type AgentCategory = 'web' | 'api' | 'cloud' | 'network' | 'identity';
export type AgentStatus = 'queued' | 'initializing' | 'reconnaissance' | 'testing' | 'exploiting' | 'reporting' | 'completed' | 'failed' | 'stopped';

export type RedOpsFindingStatus = 'open' | 'confirmed' | 'remediated' | 'accepted_risk' | 'false_positive';
export type RemediationEffort = 'quick_fix' | 'moderate' | 'significant' | 'architectural';

export interface RedOpsCampaign {
  id: string;
  name: string;
  description: string | null;
  status: CampaignStatus;
  campaign_type: CampaignType;
  target_scope: string;
  exclusions: string | null;
  agent_categories: string;
  max_concurrent_agents: number;
  exploitation_level: ExploitationLevel;
  risk_threshold: string;
  auto_poam: number;
  compliance_mapping: number;
  scheduled_at: string | null;
  total_agents: number;
  active_agents: number;
  completed_agents: number;
  failed_agents: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  exploitable_count: number;
  created_by: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  created_at: string;
  updated_at: string;
}

export interface RedOpsAgent {
  id: string;
  campaign_id: string;
  agent_type: string;
  agent_category: AgentCategory;
  status: AgentStatus;
  target: string | null;
  tests_planned: number;
  tests_completed: number;
  tests_passed: number;
  tests_failed: number;
  findings_count: number;
  exploitable_count: number;
  last_activity: string | null;
  error_message: string | null;
  execution_log: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  created_at: string;
  updated_at: string;
}

export interface RedOpsFinding {
  id: string;
  campaign_id: string;
  agent_id: string;
  asset_id: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  attack_vector: string | null;
  attack_category: string | null;
  cwe_id: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  exploitable: number;
  exploitation_proof: string | null;
  exploitation_steps: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  remediation: string | null;
  remediation_effort: RemediationEffort | null;
  nist_controls: string | null;
  status: RedOpsFindingStatus;
  campaign_name?: string;
  discovered_at: string;
  created_at: string;
  updated_at: string;
}

export interface RedOpsAgentType {
  id: string;
  category: AgentCategory;
  display_name: string;
  description: string | null;
  test_count: number;
  mitre_techniques: string | null;
  owasp_categories: string | null;
  enabled: number;
  created_at: string;
}

export interface RedOpsOverview {
  campaigns: {
    total: number;
    active: number;
    completed: number;
  };
  findings: {
    total: number;
    exploitable: number;
    severity_breakdown: Record<string, { count: number; exploitable: number }>;
  };
  agents_by_category: Array<{
    agent_category: string;
    total: number;
    completed: number;
    findings: number;
  }>;
  recent_campaigns: RedOpsCampaign[];
  generated_at: string;
}

export interface CreateCampaignInput {
  name: string;
  description?: string;
  campaign_type?: CampaignType;
  target_scope: Record<string, string[]> | string;
  exclusions?: Record<string, string[]> | string;
  agent_categories?: AgentCategory[];
  max_concurrent_agents?: number;
  exploitation_level?: ExploitationLevel;
  risk_threshold?: string;
  auto_poam?: boolean;
  compliance_mapping?: boolean;
  scheduled_at?: string;
}

// ─── ForgeSOC Types ──────────────────────────────────────────────────────────

export type SOCAlertStatus = 'new' | 'triaged' | 'investigating' | 'escalated' | 'resolved' | 'closed' | 'false_positive';
export type SOCAlertType = 'vulnerability' | 'exploitation' | 'anomaly' | 'compliance' | 'threat_intel';
export type SOCIncidentStatus = 'open' | 'investigating' | 'containment' | 'eradication' | 'recovery' | 'post_incident' | 'closed';

export interface SOCAlert {
  id: string;
  title: string;
  description: string | null;
  severity: Severity;
  status: SOCAlertStatus;
  source: string;
  source_event_id: string | null;
  source_finding_id: string | null;
  alert_type: SOCAlertType;
  tags: string | null;
  assigned_to: string | null;
  incident_id: string | null;
  correlation_id: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  affected_assets: string | null;
  raw_data: string | null;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SOCIncident {
  id: string;
  title: string;
  description: string | null;
  severity: Severity;
  status: SOCIncidentStatus;
  priority: number;
  incident_type: string;
  lead_analyst: string | null;
  alert_count: number;
  affected_asset_count: number;
  tags: string | null;
  mitre_tactics: string | null;
  mitre_techniques: string | null;
  containment_actions: string | null;
  root_cause: string | null;
  lessons_learned: string | null;
  started_at: string | null;
  contained_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
  timeline?: SOCTimelineEntry[];
  alerts?: SOCAlert[];
}

export interface SOCTimelineEntry {
  id: string;
  incident_id: string;
  action: string;
  description: string | null;
  actor: string | null;
  old_value: string | null;
  new_value: string | null;
  created_at: string;
}

export interface SOCDetectionRule {
  id: string;
  name: string;
  description: string | null;
  event_pattern: string;
  conditions: string | null;
  alert_severity: Severity;
  alert_type: string;
  tags: string | null;
  is_active: number;
  auto_escalate: number;
  cooldown_seconds: number;
  last_triggered_at: string | null;
  trigger_count: number;
  created_at: string;
  updated_at: string;
}

// ─── MSSP / Multi-Tenant Types ────────────────────────────────────────────

export type OrgTier = 'trial' | 'standard' | 'professional' | 'enterprise';
export type OrgStatus = 'active' | 'suspended' | 'deactivated';
export type OrgRole = 'owner' | 'admin' | 'analyst' | 'viewer';

export interface Organization {
  id: string;
  name: string;
  slug: string;
  tier: OrgTier;
  status: OrgStatus;
  max_assets: number;
  max_users: number;
  max_scanners: number;
  contact_email: string | null;
  contact_name: string | null;
  industry: string | null;
  notes: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  member_count?: number;
  stats?: {
    assets: number;
    findings: number;
    scans: number;
    alerts: number;
    incidents?: number;
    severity_breakdown?: Array<{ severity: string; count: number }>;
  };
}

export interface OrgMember {
  id: string;
  organization_id: string;
  user_id: string;
  org_role: OrgRole;
  is_primary: number;
  joined_at: string;
  email?: string;
  display_name?: string;
  global_role?: string;
  is_active?: number;
  last_login_at?: string | null;
}

export interface OrgBranding {
  id: string;
  organization_id: string;
  company_name: string | null;
  logo_url: string | null;
  favicon_url: string | null;
  primary_color: string;
  accent_color: string;
  sidebar_bg: string;
  login_title: string | null;
  login_subtitle: string | null;
  support_email: string | null;
  support_url: string | null;
  custom_domain: string | null;
  powered_by_visible: number;
  created_at: string;
  updated_at: string;
}

export interface MSSPOverview {
  totals: {
    organizations: number;
    active: number;
    suspended: number;
    total_users: number;
    total_assets: number;
    total_findings: number;
    total_scans: number;
    total_alerts: number;
  };
  tier_breakdown: Record<string, number>;
  tenants: Array<Organization & { member_count: number; stats: { assets: number; findings: number; scans: number; alerts: number } }>;
  generated_at: string;
}

export interface TenantHealthCard {
  org_id: string;
  name: string;
  slug: string;
  tier: string;
  risk_level: string;
  critical_findings: number;
  open_alerts: number;
  active_scans: number;
  last_scan_at: string | null;
}

export interface SOCOverview {
  alerts: {
    total: number;
    new: number;
    active: number;
    resolved: number;
    last_24h: number;
  };
  incidents: {
    total: number;
    active: number;
    closed: number;
  };
  severity_breakdown: Array<{ severity: string; count: number }>;
  recent_alerts: SOCAlert[];
  active_incidents: SOCIncident[];
  generated_at: string;
}
