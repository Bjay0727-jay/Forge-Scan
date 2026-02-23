import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Shield,
  RefreshCw,
  AlertTriangle,
  Database,
  Clock,
  Activity,
  Search,
  X,
  ExternalLink,
  ChevronRight,
  Copy,
  Check,
  Link as LinkIcon,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Filter,
  XCircle,
} from 'lucide-react';
import { useAuth, hasRole } from '@/lib/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

interface SyncState {
  last_full_sync_at: string | null;
  last_incremental_sync_at: string | null;
  total_cves_synced: number;
  last_kev_sync_at: string | null;
  last_epss_sync_at: string | null;
  kev_total: number;
  epss_total: number;
}

interface SyncJob {
  id: string;
  sync_type: string;
  status: string;
  records_processed: number;
  records_added: number;
  records_updated: number;
  total_results: number;
  current_page: number;
  total_pages: number;
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
}

interface Vulnerability {
  id: string;
  cve_id: string;
  description: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity: string;
  epss_score: number | null;
  in_kev: number;
  published_at: string;
  modified_at: string | null;
  cwe_ids: string[];
  affected_products: string[];
  references: string[];
}

interface VulnDetail extends Vulnerability {
  related_findings: {
    id: string;
    title: string;
    severity: string;
    state: string;
    hostname: string | null;
    ip_addresses: string | null;
  }[];
  related_findings_count: number;
}

interface VulnStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  in_kev: number;
  has_epss: number;
  avg_cvss: number;
}

function getAuthHeaders() {
  const token = localStorage.getItem('forgescan_token');
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return 'Never';
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

const severityColor = (severity: string) => {
  switch (severity) {
    case 'critical': return 'critical' as const;
    case 'high': return 'high' as const;
    case 'medium': return 'medium' as const;
    case 'low': return 'low' as const;
    default: return 'secondary' as const;
  }
};


function CvssScoreBadge({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-muted-foreground">—</span>;
  let color = '#22c55e';
  if (score >= 9.0) color = '#ef4444';
  else if (score >= 7.0) color = '#f97316';
  else if (score >= 4.0) color = '#eab308';
  return (
    <span
      className="inline-flex items-center justify-center rounded-md px-2.5 py-1 font-mono text-sm font-bold"
      style={{ color, background: `${color}15`, border: `1px solid ${color}30` }}
    >
      {score.toFixed(1)}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  CVE Detail Slide-over Panel                                        */
/* ------------------------------------------------------------------ */
function CVEDetailPanel({
  cveId,
  onClose,
}: {
  cveId: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<VulnDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError('');
    fetch(`${API_BASE_URL}/vulnerabilities/${cveId}`, { headers: getAuthHeaders() })
      .then(async (res) => {
        if (!res.ok) throw new Error('Failed to load CVE details');
        const data = await res.json();
        setDetail(data);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [cveId]);

  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      {/* Overlay backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />

      {/* Panel */}
      <div
        className="fixed right-0 top-0 z-50 h-full w-full max-w-2xl overflow-y-auto shadow-2xl"
        style={{ background: '#0a1929', borderLeft: '1px solid rgba(75,119,169,0.25)' }}
      >
        {/* Header */}
        <div
          className="sticky top-0 z-10 flex items-center justify-between px-6 py-4"
          style={{ background: '#0a1929', borderBottom: '1px solid rgba(75,119,169,0.2)' }}
        >
          <div className="flex items-center gap-3">
            <Shield className="h-5 w-5" style={{ color: '#14b8a6' }} />
            <h2 className="text-xl font-bold text-white" style={{ fontFamily: 'Sora, Inter, system-ui, sans-serif' }}>
              {cveId}
            </h2>
            <button
              onClick={() => copyToClipboard(cveId)}
              className="rounded p-1 transition-colors hover:bg-white/10"
              title="Copy CVE ID"
            >
              {copied ? <Check className="h-4 w-4 text-teal-400" /> : <Copy className="h-4 w-4 text-muted-foreground" />}
            </button>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 transition-colors hover:bg-white/10"
          >
            <X className="h-5 w-5 text-muted-foreground" />
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-5 space-y-6">
          {loading && (
            <div className="flex items-center justify-center py-20">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-teal-500 border-t-transparent" />
            </div>
          )}

          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-400">
              {error}
            </div>
          )}

          {detail && !loading && (
            <>
              {/* Severity + Score Row */}
              <div className="flex flex-wrap items-center gap-3">
                <Badge variant={severityColor(detail.severity)} className="text-sm px-3 py-1 uppercase tracking-wider font-semibold">
                  {detail.severity}
                </Badge>
                <CvssScoreBadge score={detail.cvss_score} />
                {detail.in_kev ? (
                  <Badge variant="destructive" className="text-sm px-3 py-1 font-semibold">
                    CISA KEV
                  </Badge>
                ) : null}
                {detail.epss_score ? (
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-sm font-semibold text-blue-400">
                    EPSS: {(detail.epss_score * 100).toFixed(2)}%
                  </span>
                ) : null}
              </div>

              {/* Description */}
              <div>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest" style={{ color: '#4b77a9' }}>
                  Description
                </h3>
                <p className="text-[15px] leading-relaxed text-gray-200">
                  {detail.description || 'No description available.'}
                </p>
              </div>

              {/* Key Details Grid */}
              <div className="grid grid-cols-2 gap-4">
                <DetailField label="Published" value={detail.published_at ? new Date(detail.published_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : '—'} />
                <DetailField label="Last Modified" value={detail.modified_at ? new Date(detail.modified_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : '—'} />
                <DetailField label="CVSS Vector" value={detail.cvss_vector || '—'} mono />
                <DetailField label="CVSS Score" value={detail.cvss_score !== null ? detail.cvss_score.toFixed(1) : '—'} />
              </div>

              {/* CWE IDs */}
              {detail.cwe_ids && detail.cwe_ids.length > 0 && (
                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest" style={{ color: '#4b77a9' }}>
                    CWE Classifications
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {detail.cwe_ids.map((cwe, i) => (
                      <a
                        key={i}
                        href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded-md border border-teal-500/25 bg-teal-500/8 px-2.5 py-1 text-sm font-medium text-teal-400 transition-colors hover:bg-teal-500/15"
                      >
                        {cwe}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Affected Products */}
              {detail.affected_products && detail.affected_products.length > 0 && (
                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest" style={{ color: '#4b77a9' }}>
                    Affected Products
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {detail.affected_products.slice(0, 20).map((product, i) => (
                      <span
                        key={i}
                        className="inline-block rounded-md border border-white/10 bg-white/5 px-2.5 py-1 text-sm text-gray-300"
                      >
                        {product}
                      </span>
                    ))}
                    {detail.affected_products.length > 20 && (
                      <span className="text-sm text-muted-foreground">+{detail.affected_products.length - 20} more</span>
                    )}
                  </div>
                </div>
              )}

              {/* References */}
              {detail.references && detail.references.length > 0 && (
                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest" style={{ color: '#4b77a9' }}>
                    References
                  </h3>
                  <div className="space-y-1.5">
                    {detail.references.slice(0, 15).map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 rounded-md px-3 py-2 text-sm text-blue-400 transition-colors hover:bg-white/5"
                        style={{ border: '1px solid rgba(59,130,246,0.15)' }}
                      >
                        <LinkIcon className="h-3.5 w-3.5 flex-shrink-0" />
                        <span className="truncate">{ref.replace(/^https?:\/\//, '')}</span>
                        <ExternalLink className="ml-auto h-3 w-3 flex-shrink-0 opacity-50" />
                      </a>
                    ))}
                    {detail.references.length > 15 && (
                      <p className="pl-3 text-sm text-muted-foreground">+{detail.references.length - 15} more references</p>
                    )}
                  </div>
                </div>
              )}

              {/* Related Findings */}
              {detail.related_findings && detail.related_findings.length > 0 && (
                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest" style={{ color: '#4b77a9' }}>
                    Related Findings ({detail.related_findings_count})
                  </h3>
                  <div className="space-y-2">
                    {detail.related_findings.map((f) => (
                      <div
                        key={f.id}
                        className="flex items-center gap-3 rounded-lg p-3"
                        style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.15)' }}
                      >
                        <Badge variant={severityColor(f.severity)} className="text-xs uppercase">
                          {f.severity}
                        </Badge>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-white truncate">{f.title}</p>
                          <p className="text-xs text-muted-foreground">
                            {f.hostname || f.ip_addresses || 'Unknown asset'} · {f.state}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* External Links */}
              <div>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest" style={{ color: '#4b77a9' }}>
                  External Resources
                </h3>
                <div className="flex flex-wrap gap-2">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${detail.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 text-sm font-medium text-gray-300 transition-colors hover:bg-white/10"
                  >
                    NVD <ExternalLink className="h-3 w-3" />
                  </a>
                  <a
                    href={`https://www.cvedetails.com/cve/${detail.cve_id}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 text-sm font-medium text-gray-300 transition-colors hover:bg-white/10"
                  >
                    CVE Details <ExternalLink className="h-3 w-3" />
                  </a>
                  <a
                    href={`https://www.exploit-db.com/search?cve=${detail.cve_id.replace('CVE-', '')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 text-sm font-medium text-gray-300 transition-colors hover:bg-white/10"
                  >
                    Exploit-DB <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}

function DetailField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg p-3" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.12)' }}>
      <p className="text-[11px] font-semibold uppercase tracking-widest mb-1" style={{ color: '#4b77a9' }}>
        {label}
      </p>
      <p className={`text-sm text-gray-200 ${mono ? 'font-mono text-xs break-all' : ''}`}>{value}</p>
    </div>
  );
}


/* ================================================================== */
/*  MAIN PAGE                                                          */
/* ================================================================== */
export function Vulnerabilities() {
  const { user } = useAuth();
  const isAdmin = hasRole(user, 'platform_admin', 'scan_admin');

  const [syncState, setSyncState] = useState<SyncState | null>(null);
  const [activeJob, setActiveJob] = useState<SyncJob | null>(null);
  const [recentJobs, setRecentJobs] = useState<SyncJob[]>([]);
  const [stats, setStats] = useState<VulnStats | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState('');
  const [selectedCve, setSelectedCve] = useState<string | null>(null);

  // Sort state
  const [sortBy, setSortBy] = useState<string>('cvss_score');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Filter state
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterKev, setFilterKev] = useState<boolean>(false);
  const [filterEpss, setFilterEpss] = useState<boolean>(false);

  // Sync confirmation dialog
  const [syncConfirm, setSyncConfirm] = useState<string | null>(null);

  const hasActiveFilters = filterSeverity || filterKev || filterEpss;

  function handleSort(column: string) {
    if (sortBy === column) {
      setSortOrder(prev => prev === 'desc' ? 'asc' : 'desc');
    } else {
      setSortBy(column);
      setSortOrder('desc');
    }
  }

  function clearFilters() {
    setFilterSeverity('');
    setFilterKev(false);
    setFilterEpss(false);
  }

  const buildVulnUrl = useCallback(() => {
    const params = new URLSearchParams();
    params.set('limit', '50');
    params.set('sort_by', sortBy);
    params.set('sort_order', sortOrder);
    if (filterKev) params.set('in_kev', 'true');
    if (filterEpss) params.set('has_epss', 'true');
    if (filterSeverity) {
      switch (filterSeverity) {
        case 'critical': params.set('min_cvss', '9.0'); break;
        case 'high': params.set('min_cvss', '7.0'); params.set('max_cvss', '8.9'); break;
        case 'medium': params.set('min_cvss', '4.0'); params.set('max_cvss', '6.9'); break;
        case 'low': params.set('min_cvss', '0.1'); params.set('max_cvss', '3.9'); break;
      }
    }
    return `${API_BASE_URL}/vulnerabilities?${params.toString()}`;
  }, [sortBy, sortOrder, filterSeverity, filterKev, filterEpss]);

  const loadData = useCallback(async () => {
    try {
      const [syncRes, statsRes, vulnsRes] = await Promise.all([
        fetch(`${API_BASE_URL}/vulnerabilities/sync/status`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE_URL}/vulnerabilities/stats`, { headers: getAuthHeaders() }),
        fetch(buildVulnUrl(), { headers: getAuthHeaders() }),
      ]);

      if (syncRes.ok) {
        const syncData = await syncRes.json();
        setSyncState(syncData.state);
        setActiveJob(syncData.activeJob);
        setRecentJobs(syncData.recentJobs || []);
      }
      if (statsRes.ok) setStats(await statsRes.json());
      if (vulnsRes.ok) {
        const vulnsData = await vulnsRes.json();
        setVulns(vulnsData.data || []);
      }
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, [buildVulnUrl]);

  useEffect(() => { loadData(); }, [loadData]);

  // Reload when sort/filter changes
  useEffect(() => {
    if (!loading) {
      fetch(buildVulnUrl(), { headers: getAuthHeaders() })
        .then(async (res) => {
          if (res.ok) {
            const data = await res.json();
            setVulns(data.data || []);
          }
        })
        .catch(() => {});
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sortBy, sortOrder, filterSeverity, filterKev, filterEpss]);

  // Auto-drive sync: when there's an active job, call process-next to advance it
  const processingRef = useRef(false);
  useEffect(() => {
    if (!activeJob || !isAdmin) return;
    let cancelled = false;

    async function driveSync() {
      if (processingRef.current || cancelled) return;
      processingRef.current = true;
      try {
        const res = await fetch(`${API_BASE_URL}/vulnerabilities/sync/process-next`, {
          method: 'POST',
          headers: getAuthHeaders(),
        });
        if (res.ok) {
          const data = await res.json();
          if (data.active_job) {
            setActiveJob(data.active_job);
            setSyncState(data.state);
          } else {
            setActiveJob(null);
            setSyncState(data.state);
          }
        }
      } catch { /* ignore */ } finally {
        processingRef.current = false;
      }
      if (!cancelled) loadData();
    }

    const interval = setInterval(driveSync, 12000);
    driveSync();
    return () => { cancelled = true; clearInterval(interval); };
  }, [activeJob, isAdmin, loadData]);

  function requestSync(type: string) {
    setSyncConfirm(type);
  }

  async function confirmSync() {
    if (!syncConfirm) return;
    const type = syncConfirm;
    setSyncConfirm(null);
    setSyncing(type);
    try {
      const endpoint = type === 'kev' ? '/vulnerabilities/sync/kev'
        : type === 'epss' ? '/vulnerabilities/sync/epss'
        : '/vulnerabilities/sync';

      const body = type === 'full' ? { sync_type: 'full' }
        : type === 'incremental' ? { sync_type: 'incremental' }
        : {};

      await fetch(`${API_BASE_URL}${endpoint}`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(body),
      });

      await new Promise(r => setTimeout(r, 1000));
      loadData();
    } catch { /* ignore */ } finally {
      setSyncing('');
    }
  }

  async function handleSearch() {
    if (!search.trim()) return loadData();
    try {
      const res = await fetch(`${API_BASE_URL}/vulnerabilities/search?q=${encodeURIComponent(search)}`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setVulns(data.data || []);
      }
    } catch { /* ignore */ }
  }

  if (loading) {
    return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" /></div>;
  }

  return (
    <div className="space-y-6 p-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-5 w-5 text-teal-400" />
            Vulnerability Intelligence
          </h1>
          <p className="text-sm text-muted-foreground mt-1">NVD CVEs, CISA KEV, and FIRST EPSS data</p>
        </div>
        <Button variant="outline" size="lg" onClick={loadData} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="forge-card-hover">
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="rounded-xl p-3" style={{ background: 'rgba(13,148,136,0.1)' }}>
                <Database className="h-6 w-6" style={{ color: '#14b8a6' }} />
              </div>
              <div>
                <p className="text-2xl font-bold">{(stats?.total || 0).toLocaleString()}</p>
                <p className="text-sm text-muted-foreground mt-0.5">Total CVEs</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="forge-card-hover">
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="rounded-xl p-3 bg-red-500/10">
                <AlertTriangle className="h-6 w-6 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.critical || 0}</p>
                <p className="text-sm text-muted-foreground mt-0.5">Critical</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="forge-card-hover">
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="rounded-xl p-3 bg-orange-500/10">
                <Shield className="h-6 w-6 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{syncState?.kev_total || 0}</p>
                <p className="text-sm text-muted-foreground mt-0.5">CISA KEV</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="forge-card-hover">
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="rounded-xl p-3 bg-blue-500/10">
                <Activity className="h-6 w-6 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{syncState?.epss_total || 0}</p>
                <p className="text-sm text-muted-foreground mt-0.5">EPSS Scored</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sync Controls (Admin only) */}
      {isAdmin && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Clock className="h-5 w-5" style={{ color: '#14b8a6' }} /> Sync Status
            </CardTitle>
            <CardDescription className="text-sm">
              Last full sync: {timeAgo(syncState?.last_full_sync_at || null)} ·
              Last incremental: {timeAgo(syncState?.last_incremental_sync_at || null)} ·
              KEV: {timeAgo(syncState?.last_kev_sync_at || null)} ·
              EPSS: {timeAgo(syncState?.last_epss_sync_at || null)}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {/* Sync Confirmation Dialog */}
            {syncConfirm && (
              <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-semibold text-amber-300 text-sm">
                      Are you sure you want to proceed?
                    </p>
                    <p className="text-sm text-muted-foreground mt-1">
                      {syncConfirm === 'full'
                        ? 'A full sync will download the entire NVD database. This may take a long time and use significant resources.'
                        : syncConfirm === 'incremental'
                        ? 'An incremental sync will fetch recently modified CVEs from NVD.'
                        : syncConfirm === 'kev'
                        ? 'This will sync the CISA Known Exploited Vulnerabilities catalog.'
                        : 'This will sync EPSS scores for all CVEs in the database.'}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 ml-4 flex-shrink-0">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setSyncConfirm(null)}
                      className="gap-1.5"
                    >
                      <XCircle className="h-4 w-4" /> Cancel
                    </Button>
                    <Button
                      size="sm"
                      onClick={confirmSync}
                      className="gap-1.5"
                      style={{ background: '#14b8a6' }}
                    >
                      <Check className="h-4 w-4" /> Confirm
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {activeJob && (
              <div className="mb-4 rounded-lg border border-teal-500/20 bg-teal-500/10 p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <div className="h-3 w-3 animate-spin rounded-full border-2 border-teal-500 border-t-transparent" />
                    <span className="font-semibold text-teal-400">Sync in progress ({activeJob.sync_type})</span>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground">
                  Page {activeJob.current_page} of {activeJob.total_pages} ·
                  Processed: {activeJob.records_processed.toLocaleString()} / {activeJob.total_results.toLocaleString()} ·
                  Added: {activeJob.records_added} · Updated: {activeJob.records_updated}
                </p>
                <div className="mt-2 h-2.5 rounded-full bg-muted overflow-hidden">
                  <div
                    className="h-full bg-teal-500 transition-all rounded-full"
                    style={{ width: `${activeJob.total_results > 0 ? (activeJob.records_processed / activeJob.total_results * 100) : 0}%` }}
                  />
                </div>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={() => requestSync('incremental')} disabled={!!syncing || !!activeJob || !!syncConfirm}>
                {syncing === 'incremental' ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                Incremental Sync
              </Button>
              <Button size="sm" variant="outline" onClick={() => requestSync('full')} disabled={!!syncing || !!activeJob || !!syncConfirm}>
                {syncing === 'full' ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                Full Sync
              </Button>
              <Button size="sm" variant="outline" onClick={() => requestSync('kev')} disabled={!!syncing || !!syncConfirm}>
                {syncing === 'kev' ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                Sync KEV
              </Button>
              <Button size="sm" variant="outline" onClick={() => requestSync('epss')} disabled={!!syncing || !!syncConfirm}>
                {syncing === 'epss' ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                Sync EPSS
              </Button>
            </div>

            {recentJobs.length > 0 && (
              <div className="mt-4">
                <p className="text-sm font-semibold mb-2" style={{ color: '#4b77a9' }}>Recent Jobs</p>
                <div className="space-y-1.5">
                  {recentJobs.slice(0, 5).map(job => (
                    <div key={job.id} className="flex items-center justify-between text-sm rounded-md px-3 py-1.5" style={{ background: 'rgba(255,255,255,0.02)' }}>
                      <span className="flex items-center gap-2">
                        <Badge variant={job.status === 'completed' ? 'default' : job.status === 'failed' ? 'destructive' : 'secondary'}>
                          {job.status}
                        </Badge>
                        <span className="text-gray-300">{job.sync_type}</span>
                        <span className="text-muted-foreground">— {job.records_processed} records</span>
                      </span>
                      <span className="text-muted-foreground">{timeAgo(job.started_at)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Search & CVE List */}
      <Card>
        <CardHeader className="pb-4">
          <div className="flex items-center gap-4">
            <CardTitle className="text-xl" style={{ fontFamily: 'Sora, Inter, system-ui, sans-serif' }}>CVE Database</CardTitle>
            <div className="flex-1 max-w-lg flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search CVEs, descriptions, products..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  className="pl-10 h-10 text-sm"
                />
              </div>
              <Button variant="outline" onClick={handleSearch} className="h-10 px-4">
                Search
              </Button>
            </div>
            <span className="text-sm text-muted-foreground ml-auto">
              {vulns.length} results
            </span>
          </div>

          {/* Filter Controls */}
          <div className="flex items-center gap-2 mt-3 flex-wrap">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <span className="text-xs font-semibold uppercase tracking-wider mr-1" style={{ color: '#4b77a9' }}>Filters:</span>

            {/* Severity Filter */}
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="h-8 rounded-md border border-white/10 bg-white/5 px-3 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-teal-500/50 cursor-pointer appearance-none"
              style={{ minWidth: '140px' }}
            >
              <option value="" className="bg-[#0a1929]">All Severities</option>
              <option value="critical" className="bg-[#0a1929]">Critical (9.0+)</option>
              <option value="high" className="bg-[#0a1929]">High (7.0–8.9)</option>
              <option value="medium" className="bg-[#0a1929]">Medium (4.0–6.9)</option>
              <option value="low" className="bg-[#0a1929]">Low (0.1–3.9)</option>
            </select>

            {/* KEV Toggle */}
            <button
              onClick={() => setFilterKev(!filterKev)}
              className={`h-8 rounded-md border px-3 text-xs font-semibold uppercase tracking-wide transition-all ${
                filterKev
                  ? 'border-red-500/40 bg-red-500/15 text-red-400'
                  : 'border-white/10 bg-white/5 text-gray-400 hover:bg-white/8 hover:text-gray-200'
              }`}
            >
              KEV Only
            </button>

            {/* EPSS Toggle */}
            <button
              onClick={() => setFilterEpss(!filterEpss)}
              className={`h-8 rounded-md border px-3 text-xs font-semibold uppercase tracking-wide transition-all ${
                filterEpss
                  ? 'border-blue-500/40 bg-blue-500/15 text-blue-400'
                  : 'border-white/10 bg-white/5 text-gray-400 hover:bg-white/8 hover:text-gray-200'
              }`}
            >
              Has EPSS
            </button>

            {/* Clear Filters */}
            {hasActiveFilters && (
              <button
                onClick={clearFilters}
                className="h-8 rounded-md border border-white/10 bg-white/5 px-3 text-xs font-medium text-gray-400 hover:text-white hover:bg-white/10 transition-all flex items-center gap-1.5"
              >
                <XCircle className="h-3.5 w-3.5" /> Clear Filters
              </button>
            )}
          </div>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent" style={{ borderBottom: '1px solid rgba(75,119,169,0.2)' }}>
                <TableHead
                  className="h-11 pl-6 text-xs font-semibold uppercase tracking-wider cursor-pointer select-none hover:text-teal-400 transition-colors"
                  style={{ color: sortBy === 'cve_id' ? '#14b8a6' : '#4b77a9' }}
                  onClick={() => handleSort('cve_id')}
                >
                  <span className="flex items-center gap-1.5">
                    CVE ID
                    {sortBy === 'cve_id' ? (sortOrder === 'desc' ? <ArrowDown className="h-3.5 w-3.5" /> : <ArrowUp className="h-3.5 w-3.5" />) : <ArrowUpDown className="h-3.5 w-3.5 opacity-40" />}
                  </span>
                </TableHead>
                <TableHead className="h-11 text-xs font-semibold uppercase tracking-wider" style={{ color: '#4b77a9' }}>Description</TableHead>
                <TableHead
                  className="h-11 text-xs font-semibold uppercase tracking-wider text-center cursor-pointer select-none hover:text-teal-400 transition-colors"
                  style={{ color: sortBy === 'cvss_score' ? '#14b8a6' : '#4b77a9' }}
                  onClick={() => handleSort('cvss_score')}
                >
                  <span className="flex items-center justify-center gap-1.5">
                    CVSS
                    {sortBy === 'cvss_score' ? (sortOrder === 'desc' ? <ArrowDown className="h-3.5 w-3.5" /> : <ArrowUp className="h-3.5 w-3.5" />) : <ArrowUpDown className="h-3.5 w-3.5 opacity-40" />}
                  </span>
                </TableHead>
                <TableHead className="h-11 text-xs font-semibold uppercase tracking-wider text-center" style={{ color: '#4b77a9' }}>Severity</TableHead>
                <TableHead
                  className="h-11 text-xs font-semibold uppercase tracking-wider text-center cursor-pointer select-none hover:text-teal-400 transition-colors"
                  style={{ color: sortBy === 'epss_score' ? '#14b8a6' : '#4b77a9' }}
                  onClick={() => handleSort('epss_score')}
                >
                  <span className="flex items-center justify-center gap-1.5">
                    EPSS
                    {sortBy === 'epss_score' ? (sortOrder === 'desc' ? <ArrowDown className="h-3.5 w-3.5" /> : <ArrowUp className="h-3.5 w-3.5" />) : <ArrowUpDown className="h-3.5 w-3.5 opacity-40" />}
                  </span>
                </TableHead>
                <TableHead className="h-11 text-xs font-semibold uppercase tracking-wider text-center" style={{ color: '#4b77a9' }}>KEV</TableHead>
                <TableHead
                  className="h-11 text-xs font-semibold uppercase tracking-wider cursor-pointer select-none hover:text-teal-400 transition-colors"
                  style={{ color: sortBy === 'published_at' ? '#14b8a6' : '#4b77a9' }}
                  onClick={() => handleSort('published_at')}
                >
                  <span className="flex items-center gap-1.5">
                    Published
                    {sortBy === 'published_at' ? (sortOrder === 'desc' ? <ArrowDown className="h-3.5 w-3.5" /> : <ArrowUp className="h-3.5 w-3.5" />) : <ArrowUpDown className="h-3.5 w-3.5 opacity-40" />}
                  </span>
                </TableHead>
                <TableHead className="h-11 w-10 pr-6" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {vulns.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-muted-foreground py-16">
                    <Database className="h-10 w-10 mx-auto mb-3 opacity-30" />
                    <p className="text-base">No vulnerabilities yet.</p>
                    {isAdmin && <p className="text-sm mt-1">Run a sync to populate CVE data.</p>}
                  </TableCell>
                </TableRow>
              ) : (
                vulns.map((v) => (
                  <TableRow
                    key={v.id}
                    className="cursor-pointer group transition-colors"
                    style={{ borderBottom: '1px solid rgba(75,119,169,0.1)' }}
                    onClick={() => setSelectedCve(v.cve_id)}
                  >
                    <TableCell className="pl-6 py-3.5">
                      <span className="font-mono text-[15px] font-semibold text-teal-400 group-hover:text-teal-300 transition-colors">
                        {v.cve_id}
                      </span>
                    </TableCell>
                    <TableCell className="max-w-md py-3.5">
                      <span className="text-[14px] leading-snug text-gray-300 line-clamp-2">
                        {v.description}
                      </span>
                    </TableCell>
                    <TableCell className="text-center py-3.5">
                      <CvssScoreBadge score={v.cvss_score} />
                    </TableCell>
                    <TableCell className="text-center py-3.5">
                      <Badge variant={severityColor(v.severity)} className="text-xs px-2.5 py-0.5 uppercase font-semibold">
                        {v.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-center py-3.5">
                      {v.epss_score ? (
                        <span className="font-mono text-sm text-blue-400 font-medium">
                          {(v.epss_score * 100).toFixed(2)}%
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-center py-3.5">
                      {v.in_kev ? (
                        <span className="inline-flex items-center rounded-md bg-red-500/15 border border-red-500/30 px-2 py-0.5 text-xs font-bold text-red-400">
                          KEV
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="py-3.5">
                      <span className="text-sm text-gray-400">
                        {v.published_at ? new Date(v.published_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
                      </span>
                    </TableCell>
                    <TableCell className="pr-6 py-3.5">
                      <ChevronRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* CVE Detail Panel */}
      {selectedCve && (
        <CVEDetailPanel
          cveId={selectedCve}
          onClose={() => setSelectedCve(null)}
        />
      )}
    </div>
  );
}
