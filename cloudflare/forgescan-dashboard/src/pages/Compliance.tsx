import { useState, useEffect, useCallback } from 'react';
import {
  ClipboardCheck,
  RefreshCw,
  Download,
  CheckCircle,
  XCircle,
  AlertCircle,
  MinusCircle,
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

interface Framework {
  id: string;
  name: string;
  version: string;
  description: string;
  total_controls: number;
  compliance_percentage: number;
  created_at: string;
}

interface Control {
  id: string;
  framework_id: string;
  control_id: string;
  name: string;
  description: string;
  family: string;
  compliance_status: string | null;
  evidence: string | null;
  assessed_at: string | null;
  assessed_by: string | null;
}

interface GapAnalysis {
  non_compliant: Control[];
  not_assessed: Control[];
  partial: Control[];
  total_gaps: number;
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

const statusIcon = (status: string | null) => {
  switch (status) {
    case 'compliant': return <CheckCircle className="h-4 w-4 text-green-500" />;
    case 'non_compliant': return <XCircle className="h-4 w-4 text-red-500" />;
    case 'partial': return <AlertCircle className="h-4 w-4 text-yellow-500" />;
    default: return <MinusCircle className="h-4 w-4 text-muted-foreground" />;
  }
};

const statusBadge = (status: string | null) => {
  switch (status) {
    case 'compliant': return <Badge className="bg-green-500/15 text-green-400 hover:bg-green-500/20">Compliant</Badge>;
    case 'non_compliant': return <Badge variant="destructive">Non-Compliant</Badge>;
    case 'partial': return <Badge className="bg-yellow-500/15 text-yellow-400 hover:bg-yellow-500/20">Partial</Badge>;
    default: return <Badge variant="secondary">Not Assessed</Badge>;
  }
};

const complianceColor = (pct: number) => {
  if (pct >= 80) return 'text-green-400';
  if (pct >= 50) return 'text-yellow-400';
  return 'text-red-400';
};

export function Compliance() {
  const { user } = useAuth();
  const isAdmin = hasRole(user, 'platform_admin', 'scan_admin');

  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);

  // Detail view
  const [selectedFw, setSelectedFw] = useState<string | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [gaps, setGaps] = useState<GapAnalysis | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const loadFrameworks = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/compliance`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setFrameworks(data.data || []);
      }
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadFrameworks(); }, [loadFrameworks]);

  async function loadDetail(fwId: string) {
    if (selectedFw === fwId) { setSelectedFw(null); return; }
    setSelectedFw(fwId);
    setLoadingDetail(true);
    try {
      const [ctrlRes, gapRes] = await Promise.all([
        fetch(`${API_BASE_URL}/compliance/${fwId}/controls`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE_URL}/compliance/${fwId}/gaps`, { headers: getAuthHeaders() }),
      ]);
      if (ctrlRes.ok) {
        const data = await ctrlRes.json();
        setControls(data.data || []);
      }
      if (gapRes.ok) {
        const data = await gapRes.json();
        setGaps(data.gaps || null);
      }
    } catch { /* ignore */ } finally {
      setLoadingDetail(false);
    }
  }

  async function seedFrameworks() {
    setSeeding(true);
    try {
      await fetch(`${API_BASE_URL}/compliance/seed`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });
      await loadFrameworks();
    } catch { /* ignore */ } finally {
      setSeeding(false);
    }
  }

  // Stats
  const totalControls = frameworks.reduce((s, f) => s + (f.total_controls || 0), 0);
  const avgCompliance = frameworks.length
    ? Math.round(frameworks.reduce((s, f) => s + (f.compliance_percentage || 0), 0) / frameworks.length)
    : 0;

  // Group controls by family
  const grouped = controls.reduce<Record<string, Control[]>>((acc, c) => {
    const family = c.family || 'Uncategorized';
    if (!acc[family]) acc[family] = [];
    acc[family].push(c);
    return acc;
  }, {});

  if (loading) {
    return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" /></div>;
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ClipboardCheck className="h-5 w-5" /> Compliance
          </h1>
          <p className="text-muted-foreground mt-1">Framework mappings and gap analysis</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={loadFrameworks}><RefreshCw className="mr-2 h-4 w-4" /> Refresh</Button>
          {isAdmin && (
            <Button onClick={seedFrameworks} disabled={seeding}>
              {seeding ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <Download className="mr-2 h-4 w-4" />}
              Initialize Frameworks
            </Button>
          )}
        </div>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <p className="text-2xl font-bold">{frameworks.length}</p>
            <p className="text-sm text-muted-foreground">Frameworks</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-2xl font-bold">{totalControls}</p>
            <p className="text-sm text-muted-foreground">Total Controls</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className={`text-2xl font-bold ${complianceColor(avgCompliance)}`}>{avgCompliance}%</p>
            <p className="text-sm text-muted-foreground">Avg Compliance</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-2xl font-bold text-red-400">
              {frameworks.filter(f => (f.compliance_percentage || 0) < 50).length}
            </p>
            <p className="text-sm text-muted-foreground">At Risk</p>
          </CardContent>
        </Card>
      </div>

      {/* Framework Cards */}
      {frameworks.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No compliance frameworks loaded. {isAdmin ? 'Click "Initialize Frameworks" to seed framework data.' : ''}
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {frameworks.map(fw => {
            const pct = fw.compliance_percentage || 0;
            return (
              <Card key={fw.id} className={`cursor-pointer transition-shadow hover:shadow-md ${selectedFw === fw.id ? 'ring-2 ring-primary' : ''}`} onClick={() => loadDetail(fw.id)}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">{fw.name}</CardTitle>
                  <CardDescription>v{fw.version}</CardDescription>
                </CardHeader>
                <CardContent>
                  <p className={`text-4xl font-bold ${complianceColor(pct)}`}>{pct}%</p>
                  <div className="mt-2 h-2 rounded-full bg-muted overflow-hidden">
                    <div className="h-full bg-green-500 transition-all" style={{ width: `${pct}%` }} />
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">{fw.total_controls || 0} controls</p>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Framework Detail View */}
      {selectedFw && (
        <>
          {loadingDetail ? (
            <div className="flex items-center justify-center h-32"><div className="h-6 w-6 animate-spin rounded-full border-4 border-primary border-t-transparent" /></div>
          ) : (
            <>
              {/* Controls Table Grouped by Family */}
              <Card>
                <CardHeader>
                  <CardTitle>Controls</CardTitle>
                  <CardDescription>
                    {controls.length} controls across {Object.keys(grouped).length} families
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {Object.entries(grouped).map(([family, ctrls]) => (
                    <div key={family} className="mb-6 last:mb-0">
                      <h3 className="text-sm font-semibold text-muted-foreground mb-2">{family}</h3>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-10"></TableHead>
                            <TableHead>ID</TableHead>
                            <TableHead>Name</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Assessed</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {ctrls.map(ctrl => (
                            <TableRow key={ctrl.id}>
                              <TableCell>{statusIcon(ctrl.compliance_status)}</TableCell>
                              <TableCell className="font-mono text-sm">{ctrl.control_id}</TableCell>
                              <TableCell className="text-sm">{ctrl.name}</TableCell>
                              <TableCell>{statusBadge(ctrl.compliance_status)}</TableCell>
                              <TableCell className="text-sm text-muted-foreground">{timeAgo(ctrl.assessed_at)}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  ))}
                </CardContent>
              </Card>

              {/* Gap Analysis */}
              {gaps && gaps.total_gaps > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <AlertCircle className="h-5 w-5 text-yellow-500" /> Gap Analysis
                    </CardTitle>
                    <CardDescription>{gaps.total_gaps} control{gaps.total_gaps !== 1 ? 's' : ''} require attention</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {gaps.non_compliant.length > 0 && (
                      <div className="mb-4">
                        <h4 className="text-sm font-semibold text-red-400 mb-2">Non-Compliant ({gaps.non_compliant.length})</h4>
                        <div className="space-y-1">
                          {gaps.non_compliant.map(g => (
                            <div key={g.id} className="flex items-center gap-2 text-sm">
                              <XCircle className="h-3 w-3 text-red-500 shrink-0" />
                              <span className="font-mono">{g.control_id}</span>
                              <span className="text-muted-foreground truncate">{g.name}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {gaps.partial.length > 0 && (
                      <div className="mb-4">
                        <h4 className="text-sm font-semibold text-yellow-400 mb-2">Partial ({gaps.partial.length})</h4>
                        <div className="space-y-1">
                          {gaps.partial.map(g => (
                            <div key={g.id} className="flex items-center gap-2 text-sm">
                              <AlertCircle className="h-3 w-3 text-yellow-500 shrink-0" />
                              <span className="font-mono">{g.control_id}</span>
                              <span className="text-muted-foreground truncate">{g.name}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {gaps.not_assessed.length > 0 && (
                      <div>
                        <h4 className="text-sm font-semibold text-muted-foreground mb-2">Not Assessed ({gaps.not_assessed.length})</h4>
                        <div className="space-y-1">
                          {gaps.not_assessed.slice(0, 20).map(g => (
                            <div key={g.id} className="flex items-center gap-2 text-sm">
                              <MinusCircle className="h-3 w-3 text-muted-foreground shrink-0" />
                              <span className="font-mono">{g.control_id}</span>
                              <span className="text-muted-foreground truncate">{g.name}</span>
                            </div>
                          ))}
                          {gaps.not_assessed.length > 20 && (
                            <p className="text-xs text-muted-foreground mt-1">
                              ...and {gaps.not_assessed.length - 20} more
                            </p>
                          )}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
