import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Shield,
  RefreshCw,
  AlertTriangle,
  Database,
  Clock,
  Activity,
  Search,
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
  severity: string;
  epss_score: number | null;
  in_kev: number;
  published_at: string;
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
    case 'critical': return 'destructive' as const;
    case 'high': return 'destructive' as const;
    case 'medium': return 'default' as const;
    default: return 'secondary' as const;
  }
};

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

  const loadData = useCallback(async () => {
    try {
      const [syncRes, statsRes, vulnsRes] = await Promise.all([
        fetch(`${API_BASE_URL}/vulnerabilities/sync/status`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE_URL}/vulnerabilities/stats`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE_URL}/vulnerabilities?limit=50&sort_by=cvss_score&sort_order=desc`, { headers: getAuthHeaders() }),
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
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // Auto-drive sync: when there's an active job, call process-next to advance it
  // This replaces the cron trigger approach (free plan limit exceeded)
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
      // Refresh full data periodically
      if (!cancelled) loadData();
    }

    // Process next page every 8 seconds while sync is active
    const interval = setInterval(driveSync, 8000);
    // Also trigger immediately
    driveSync();
    return () => { cancelled = true; clearInterval(interval); };
  }, [activeJob, isAdmin, loadData]);

  async function triggerSync(type: string) {
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Shield className="h-8 w-8" /> Vulnerability Intelligence
          </h1>
          <p className="text-muted-foreground mt-1">NVD CVEs, CISA KEV, and FIRST EPSS data</p>
        </div>
        <Button variant="outline" onClick={loadData}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Database className="h-5 w-5 text-muted-foreground" />
              <div>
                <p className="text-2xl font-bold">{(stats?.total || 0).toLocaleString()}</p>
                <p className="text-sm text-muted-foreground">Total CVEs</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              <div>
                <p className="text-2xl font-bold">{stats?.critical || 0}</p>
                <p className="text-sm text-muted-foreground">Critical</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-2xl font-bold">{syncState?.kev_total || 0}</p>
                <p className="text-sm text-muted-foreground">CISA KEV</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-2xl font-bold">{syncState?.epss_total || 0}</p>
                <p className="text-sm text-muted-foreground">EPSS Scored</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sync Controls (Admin only) */}
      {isAdmin && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" /> Sync Status
            </CardTitle>
            <CardDescription>
              Last full sync: {timeAgo(syncState?.last_full_sync_at || null)} |
              Last incremental: {timeAgo(syncState?.last_incremental_sync_at || null)} |
              KEV: {timeAgo(syncState?.last_kev_sync_at || null)} |
              EPSS: {timeAgo(syncState?.last_epss_sync_at || null)}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {activeJob && (
              <div className="mb-4 rounded-lg border border-blue-500/20 bg-blue-500/10 p-4">
                <div className="flex items-center gap-2 mb-2">
                  <div className="h-3 w-3 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
                  <span className="font-medium text-blue-600">Sync in progress ({activeJob.sync_type})</span>
                </div>
                <p className="text-sm text-muted-foreground">
                  Page {activeJob.current_page} of {activeJob.total_pages} |
                  Processed: {activeJob.records_processed.toLocaleString()} / {activeJob.total_results.toLocaleString()} |
                  Added: {activeJob.records_added} | Updated: {activeJob.records_updated}
                </p>
                <div className="mt-2 h-2 rounded-full bg-muted overflow-hidden">
                  <div
                    className="h-full bg-blue-500 transition-all"
                    style={{ width: `${activeJob.total_results > 0 ? (activeJob.records_processed / activeJob.total_results * 100) : 0}%` }}
                  />
                </div>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={() => triggerSync('incremental')} disabled={!!syncing || !!activeJob}>
                {syncing === 'incremental' ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                Incremental Sync
              </Button>
              <Button size="sm" variant="outline" onClick={() => triggerSync('full')} disabled={!!syncing || !!activeJob}>
                {syncing === 'full' ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                Full Sync
              </Button>
              <Button size="sm" variant="outline" onClick={() => triggerSync('kev')} disabled={!!syncing}>
                {syncing === 'kev' ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                Sync KEV
              </Button>
              <Button size="sm" variant="outline" onClick={() => triggerSync('epss')} disabled={!!syncing}>
                {syncing === 'epss' ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
                Sync EPSS
              </Button>
            </div>

            {recentJobs.length > 0 && (
              <div className="mt-4">
                <p className="text-sm font-medium mb-2">Recent Jobs</p>
                <div className="space-y-1">
                  {recentJobs.slice(0, 5).map(job => (
                    <div key={job.id} className="flex items-center justify-between text-sm">
                      <span>
                        <Badge variant={job.status === 'completed' ? 'default' : job.status === 'failed' ? 'destructive' : 'secondary'} className="mr-2">
                          {job.status}
                        </Badge>
                        {job.sync_type} - {job.records_processed} records
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
        <CardHeader>
          <div className="flex items-center gap-4">
            <CardTitle>CVE Database</CardTitle>
            <div className="flex-1 max-w-md flex gap-2">
              <Input
                placeholder="Search CVEs, descriptions, products..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              />
              <Button variant="outline" size="sm" onClick={handleSearch}>
                <Search className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>CVE ID</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>CVSS</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>EPSS</TableHead>
                <TableHead>KEV</TableHead>
                <TableHead>Published</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vulns.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    No vulnerabilities yet. {isAdmin ? 'Run a sync to populate CVE data.' : ''}
                  </TableCell>
                </TableRow>
              ) : (
                vulns.map((v) => (
                  <TableRow key={v.id}>
                    <TableCell className="font-mono text-sm font-medium">{v.cve_id}</TableCell>
                    <TableCell className="max-w-md truncate text-sm">{v.description}</TableCell>
                    <TableCell className="font-mono">{v.cvss_score?.toFixed(1) || '-'}</TableCell>
                    <TableCell>
                      <Badge variant={severityColor(v.severity)}>{v.severity}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {v.epss_score ? `${(v.epss_score * 100).toFixed(2)}%` : '-'}
                    </TableCell>
                    <TableCell>
                      {v.in_kev ? <Badge variant="destructive">KEV</Badge> : '-'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {v.published_at ? new Date(v.published_at).toLocaleDateString() : '-'}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
