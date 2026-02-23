import { useState, useEffect, useCallback } from 'react';
import {
  FileText,
  RefreshCw,
  Download,
  Trash2,
  FileDown,
  FileSpreadsheet,
  FileJson,
  BarChart3,
  Shield,
  Server,
  AlertTriangle,
} from 'lucide-react';
import { useAuth, hasRole } from '@/lib/auth';
import { Button } from '@/components/ui/button';
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

interface Report {
  id: string;
  title: string;
  report_type: string;
  format: string;
  file_size: number;
  status: string;
  error_message: string | null;
  created_at: string;
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
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

const reportTypes = [
  {
    type: 'executive',
    label: 'Executive Summary',
    description: 'High-level security posture overview with risk score, severity breakdown, and recommendations.',
    icon: BarChart3,
    formats: ['pdf', 'json'],
    color: 'text-blue-400',
  },
  {
    type: 'findings',
    label: 'Findings Report',
    description: 'Detailed vulnerability findings with severity, affected assets, CVE data, and remediation guidance.',
    icon: AlertTriangle,
    formats: ['pdf', 'csv', 'json'],
    color: 'text-orange-400',
  },
  {
    type: 'compliance',
    label: 'Compliance Report',
    description: 'Framework compliance status across NIST 800-53, CIS v8, PCI DSS, and HIPAA with gap analysis.',
    icon: Shield,
    formats: ['pdf', 'csv', 'json'],
    color: 'text-green-400',
  },
  {
    type: 'assets',
    label: 'Asset Inventory',
    description: 'Complete asset inventory with finding counts, risk scores, and OS/type breakdown.',
    icon: Server,
    formats: ['pdf', 'csv', 'json'],
    color: 'text-purple-600',
  },
];

const formatIcon = (fmt: string) => {
  switch (fmt) {
    case 'pdf': return <FileDown className="h-4 w-4" />;
    case 'csv': return <FileSpreadsheet className="h-4 w-4" />;
    case 'json': return <FileJson className="h-4 w-4" />;
    default: return <FileText className="h-4 w-4" />;
  }
};

const formatLabel = (fmt: string) => fmt.toUpperCase();

const statusBadge = (status: string) => {
  switch (status) {
    case 'completed': return <Badge className="bg-green-500/15 text-green-400 hover:bg-green-500/20">Completed</Badge>;
    case 'failed': return <Badge variant="destructive">Failed</Badge>;
    case 'pending': return <Badge variant="secondary">Pending</Badge>;
    default: return <Badge variant="secondary">{status}</Badge>;
  }
};

export function Reports() {
  const { user } = useAuth();
  const isAdmin = hasRole(user, 'platform_admin', 'scan_admin');

  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/reports/list/all?limit=50`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setReports(data.data || []);
      }
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadReports(); }, [loadReports]);

  async function generateReport(reportType: string, format: string) {
    const key = `${reportType}-${format}`;
    setGenerating(key);
    try {
      const res = await fetch(`${API_BASE_URL}/reports/generate`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ report_type: reportType, format }),
      });
      if (res.ok) {
        const data = await res.json();
        // Auto-download the report
        if (data.download_url) {
          const token = localStorage.getItem('forgescan_token');
          const downloadRes = await fetch(`${API_BASE_URL}${data.download_url.replace('/api/v1', '')}`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (downloadRes.ok) {
            const blob = await downloadRes.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `report-${data.id}.${format}`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
          }
        }
        await loadReports();
      }
    } catch { /* ignore */ } finally {
      setGenerating(null);
    }
  }

  async function downloadReport(id: string, format: string) {
    try {
      const token = localStorage.getItem('forgescan_token');
      const res = await fetch(`${API_BASE_URL}/reports/${id}/download`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${id}.${format || 'json'}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
      }
    } catch { /* ignore */ }
  }

  async function deleteReport(id: string) {
    try {
      await fetch(`${API_BASE_URL}/reports/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      await loadReports();
    } catch { /* ignore */ }
  }

  if (loading) {
    return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" /></div>;
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <FileText className="h-5 w-5" /> Reports
          </h1>
          <p className="text-muted-foreground mt-1">Generate and download security reports</p>
        </div>
        <Button variant="outline" onClick={loadReports}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      {/* Quick Report Generation */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {reportTypes.map(rt => (
          <Card key={rt.type}>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <rt.icon className={`h-5 w-5 ${rt.color}`} />
                {rt.label}
              </CardTitle>
              <CardDescription className="text-xs">{rt.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2">
                {rt.formats.map(fmt => {
                  const key = `${rt.type}-${fmt}`;
                  const isGenerating = generating === key;
                  return (
                    <Button
                      key={fmt}
                      variant="outline"
                      size="sm"
                      className="flex-1"
                      disabled={!!generating}
                      onClick={() => generateReport(rt.type, fmt)}
                    >
                      {isGenerating ? (
                        <RefreshCw className="mr-1 h-3 w-3 animate-spin" />
                      ) : (
                        <span className="mr-1">{formatIcon(fmt)}</span>
                      )}
                      {formatLabel(fmt)}
                    </Button>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Generated Reports Table */}
      <Card>
        <CardHeader>
          <CardTitle>Generated Reports</CardTitle>
          <CardDescription>{reports.length} report{reports.length !== 1 ? 's' : ''} generated</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Title</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Format</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Generated</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {reports.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    No reports generated yet. Use the quick report cards above to generate your first report.
                  </TableCell>
                </TableRow>
              ) : (
                reports.map(r => (
                  <TableRow key={r.id}>
                    <TableCell className="font-medium text-sm max-w-[200px] truncate">{r.title}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="capitalize">{r.report_type}</Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        {formatIcon(r.format)}
                        <span className="text-xs uppercase">{r.format}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatBytes(r.file_size)}</TableCell>
                    <TableCell>{statusBadge(r.status)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{timeAgo(r.created_at)}</TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {r.status === 'completed' && (
                          <Button variant="ghost" size="icon" onClick={() => downloadReport(r.id, r.format)} title="Download">
                            <Download className="h-4 w-4" />
                          </Button>
                        )}
                        {isAdmin && (
                          <Button variant="ghost" size="icon" onClick={() => deleteReport(r.id)} title="Delete">
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                      </div>
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
