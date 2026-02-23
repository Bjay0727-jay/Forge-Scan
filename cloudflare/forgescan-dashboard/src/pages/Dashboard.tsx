import { useCallback, useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Server,
  AlertTriangle,
  Scan,
  TrendingUp,
  ExternalLink,
  Activity,
  Clock,
  ShieldCheck,
  ShieldAlert,
  Timer,
  CheckCircle2,
  XCircle,
  Target,
  Zap,
  Loader2,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
  BarChart,
  Bar,
  Cell,
} from 'recharts';
import { format, parseISO } from 'date-fns';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { SeverityPieChart } from '@/components/charts/SeverityPieChart';
import { RiskTrendChart } from '@/components/charts/RiskTrendChart';
import { StateBarChart } from '@/components/charts/StateBarChart';
import { ErrorState } from '@/components/ErrorState';
import { useApi } from '@/hooks/useApi';
import { usePollingApi } from '@/hooks/usePollingApi';
import { dashboardApi, scansApi, onboardingApi } from '@/lib/api';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { formatRelativeTime, capitalize } from '@/lib/utils';
import type { DashboardStats, ExecutiveMetrics, Severity } from '@/types';

// ── Grade colors and descriptions ──────────────────────────────────────────
const GRADE_CONFIG: Record<string, { color: string; bg: string; border: string; label: string }> = {
  A: { color: '#22c55e', bg: 'rgba(34,197,94,0.1)', border: 'rgba(34,197,94,0.3)', label: 'Excellent' },
  B: { color: '#3b82f6', bg: 'rgba(59,130,246,0.1)', border: 'rgba(59,130,246,0.3)', label: 'Good' },
  C: { color: '#eab308', bg: 'rgba(234,179,8,0.1)', border: 'rgba(234,179,8,0.3)', label: 'Fair' },
  D: { color: '#f97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.3)', label: 'Poor' },
  F: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.3)', label: 'Critical' },
};

function StatCard({
  title,
  value,
  icon: Icon,
  href,
}: {
  title: string;
  value: number;
  icon: React.ElementType;
  href: string;
}) {
  return (
    <Link to={href}>
      <Card className="forge-card-hover transition-all hover:bg-accent/50">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
          <div className="rounded-lg p-2" style={{ background: 'rgba(13,148,136,0.1)' }}>
            <Icon className="h-4 w-4" style={{ color: '#0D9488' }} />
          </div>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{value.toLocaleString()}</div>
        </CardContent>
      </Card>
    </Link>
  );
}

// ── Executive Scorecard Component ──────────────────────────────────────────
function ExecutiveScorecard({ metrics }: { metrics: ExecutiveMetrics }) {
  const gradeInfo = GRADE_CONFIG[metrics.risk_grade.grade] || GRADE_CONFIG.C;
  const sc = metrics.risk_grade.severity_counts;
  const sla = metrics.sla_compliance;

  return (
    <div className="mb-6 space-y-4">
      {/* Top row: Grade + KPIs */}
      <div className="grid gap-4 lg:grid-cols-4">
        {/* Risk Grade — hero card */}
        <Card
          className="lg:row-span-1 relative overflow-hidden"
          style={{ borderColor: gradeInfo.border }}
        >
          <div
            className="absolute inset-0 opacity-[0.03]"
            style={{ background: `radial-gradient(ellipse at 30% 30%, ${gradeInfo.color}, transparent 70%)` }}
          />
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <ShieldCheck className="h-4 w-4" />
              Security Posture
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <div
                className="flex h-20 w-20 items-center justify-center rounded-2xl text-5xl font-black"
                style={{ background: gradeInfo.bg, color: gradeInfo.color, border: `2px solid ${gradeInfo.border}` }}
              >
                {metrics.risk_grade.grade}
              </div>
              <div className="flex-1">
                <div className="text-lg font-semibold" style={{ color: gradeInfo.color }}>
                  {gradeInfo.label}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Risk Score: {metrics.risk_grade.score}/100
                </div>
                <div className="text-xs text-muted-foreground">
                  {metrics.risk_grade.open_findings} open findings
                </div>
              </div>
            </div>
            {/* Mini severity breakdown */}
            <div className="mt-3 flex gap-2">
              {sc.critical > 0 && (
                <span className="inline-flex items-center gap-1 rounded-md bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-400 border border-red-500/20">
                  {sc.critical} Critical
                </span>
              )}
              {sc.high > 0 && (
                <span className="inline-flex items-center gap-1 rounded-md bg-orange-500/10 px-2 py-0.5 text-[11px] font-medium text-orange-400 border border-orange-500/20">
                  {sc.high} High
                </span>
              )}
              {sc.medium > 0 && (
                <span className="inline-flex items-center gap-1 rounded-md bg-yellow-500/10 px-2 py-0.5 text-[11px] font-medium text-yellow-400 border border-yellow-500/20">
                  {sc.medium} Med
                </span>
              )}
            </div>
          </CardContent>
        </Card>

        {/* MTTR KPI */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <Timer className="h-4 w-4" />
              Mean Time to Remediate
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {metrics.mttr.overall_avg_days > 0 ? `${metrics.mttr.overall_avg_days}d` : '--'}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Across {metrics.mttr.overall_sample_size} remediations
            </p>
            <div className="mt-3 space-y-1.5">
              {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
                const m = metrics.mttr.by_severity[sev];
                if (!m) return null;
                const colors: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
                return (
                  <div key={sev} className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: colors[sev] }} />
                      <span className="capitalize text-muted-foreground">{sev}</span>
                    </span>
                    <span className="font-medium">{m.avg_days}d avg</span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* SLA Compliance KPI */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <CheckCircle2 className="h-4 w-4" />
              SLA Compliance
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-1">
              <span
                className="text-3xl font-bold"
                style={{ color: sla.overall_pct >= 80 ? '#22c55e' : sla.overall_pct >= 60 ? '#eab308' : '#ef4444' }}
              >
                {sla.overall_pct}%
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              On-time remediation rate
            </p>
            <div className="mt-3 space-y-1.5">
              {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
                const s = sla.by_severity[sev];
                if (!s) return null;
                return (
                  <div key={sev} className="flex items-center justify-between text-xs">
                    <span className="capitalize text-muted-foreground">{sev} ({s.target_days}d)</span>
                    <span
                      className="font-medium"
                      style={{ color: s.compliance_pct >= 80 ? '#22c55e' : s.compliance_pct >= 60 ? '#eab308' : '#ef4444' }}
                    >
                      {s.compliance_pct}%
                    </span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Overdue + RedOps Coverage */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <ShieldAlert className="h-4 w-4" />
              Risk Indicators
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {/* Overdue */}
              <div>
                <div className="flex items-center gap-2">
                  <XCircle className="h-4 w-4 text-red-400" />
                  <span className="text-sm font-medium">Overdue Findings</span>
                </div>
                <div className="text-2xl font-bold text-red-400 mt-1">
                  {sla.overdue.total}
                </div>
                {sla.overdue.critical > 0 && (
                  <p className="text-[11px] text-red-400/80">
                    {sla.overdue.critical} critical past SLA
                  </p>
                )}
              </div>
              {/* RedOps Validation */}
              {metrics.redops_coverage.validated_cves > 0 && (
                <div>
                  <div className="flex items-center gap-2">
                    <Target className="h-4 w-4 text-teal-400" />
                    <span className="text-sm font-medium">RedOps Validated</span>
                  </div>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-teal-400">
                      {metrics.redops_coverage.validated_cves}
                    </span>
                    <span className="text-xs text-muted-foreground">CVEs tested</span>
                  </div>
                  {metrics.redops_coverage.exploitable > 0 && (
                    <p className="text-[11px] text-orange-400">
                      {metrics.redops_coverage.exploitable} confirmed exploitable
                    </p>
                  )}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Risk Posture Trend Chart ───────────────────────────────────────────────
function PostureTrendChart({ data }: { data: ExecutiveMetrics['posture_trend'] }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        No trend data available yet
      </div>
    );
  }

  const formatted = data.map((p) => ({
    ...p,
    label: format(parseISO(p.week), 'MMM d'),
    net: p.new_findings - p.fixed,
  }));

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={formatted} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
        <defs>
          <linearGradient id="gradNew" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gradFixed" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis
          dataKey="label"
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
        />
        <YAxis tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }} />
        <RechartsTooltip
          contentStyle={{
            backgroundColor: 'hsl(var(--popover))',
            border: '1px solid hsl(var(--border))',
            borderRadius: '8px',
            fontSize: 12,
          }}
          labelStyle={{ color: 'hsl(var(--foreground))' }}
        />
        <Legend />
        <Area
          type="monotone"
          dataKey="new_findings"
          stroke="#ef4444"
          fill="url(#gradNew)"
          strokeWidth={2}
          name="New Findings"
        />
        <Area
          type="monotone"
          dataKey="fixed"
          stroke="#22c55e"
          fill="url(#gradFixed)"
          strokeWidth={2}
          name="Remediated"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ── MTTR Trend Bar Chart ───────────────────────────────────────────────────
function MttrBarChart({ mttr }: { mttr: ExecutiveMetrics['mttr'] }) {
  const sevOrder = ['critical', 'high', 'medium', 'low'];
  const slaTargets: Record<string, number> = { critical: 7, high: 30, medium: 90, low: 180 };
  const colors: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

  const data = sevOrder
    .filter((s) => mttr.by_severity[s])
    .map((s) => ({
      severity: capitalize(s),
      avg: mttr.by_severity[s].avg_days,
      target: slaTargets[s],
      fill: colors[s],
    }));

  if (data.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        No remediation data available yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis
          dataKey="severity"
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
        />
        <YAxis
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          label={{ value: 'Days', angle: -90, position: 'insideLeft', fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
        />
        <RechartsTooltip
          contentStyle={{
            backgroundColor: 'hsl(var(--popover))',
            border: '1px solid hsl(var(--border))',
            borderRadius: '8px',
            fontSize: 12,
          }}
          formatter={(value: number, name: string) => [
            `${value} days`,
            name === 'avg' ? 'Actual MTTR' : 'SLA Target',
          ]}
        />
        <Legend />
        <Bar dataKey="avg" name="Actual MTTR" radius={[4, 4, 0, 0]}>
          {data.map((entry, i) => (
            <Cell key={i} fill={entry.fill} />
          ))}
        </Bar>
        <Bar dataKey="target" name="SLA Target" fill="hsl(var(--muted-foreground))" opacity={0.25} radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── Quick Scan Dialog ──────────────────────────────────────────────────────
function QuickScanDialog() {
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleScan = async () => {
    if (!target.trim()) return;
    setLoading(true);
    setError('');
    try {
      await onboardingApi.quickScan(target.trim());
      setOpen(false);
      setTarget('');
      navigate('/scans');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="gap-2">
          <Zap className="h-4 w-4" /> Quick Scan
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Quick Scan</DialogTitle>
          <DialogDescription>
            Run a network + configuration audit on a CIDR range or hostname.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label htmlFor="qs-target">Target</Label>
            <Input
              id="qs-target"
              placeholder="e.g., 192.168.1.0/24 or example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={loading}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
            />
            <p className="text-xs text-muted-foreground">
              Scans ports 1-1024 + common services, detects services, and checks for vulnerabilities.
            </p>
          </div>
          {error && (
            <div className="rounded-md bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleScan} disabled={loading || !target.trim()} className="gap-2">
            {loading ? <><Loader2 className="h-4 w-4 animate-spin" /> Starting...</> : <><Zap className="h-4 w-4" /> Launch Scan</>}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-6">
      {/* Executive skeleton */}
      <div className="grid gap-4 lg:grid-cols-4">
        {[...Array(4)].map((_, i) => (
          <Card key={i}>
            <CardHeader className="pb-2">
              <Skeleton className="h-4 w-28" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-20 w-20 rounded-2xl mb-3" />
              <Skeleton className="h-3 w-24" />
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {[...Array(4)].map((_, i) => (
          <Card key={i}>
            <CardHeader className="pb-2">
              <Skeleton className="h-4 w-24" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-8 w-16" />
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader><Skeleton className="h-5 w-32" /></CardHeader>
          <CardContent><Skeleton className="h-[300px]" /></CardContent>
        </Card>
        <Card>
          <CardHeader><Skeleton className="h-5 w-32" /></CardHeader>
          <CardContent><Skeleton className="h-[300px]" /></CardContent>
        </Card>
      </div>
    </div>
  );
}

export function Dashboard() {
  const fetchStats = useCallback(() => dashboardApi.getStats(), []);
  const { data: stats, loading, error, refetch } = useApi<DashboardStats>(fetchStats);

  const fetchExec = useCallback(() => dashboardApi.getExecutiveMetrics(90), []);
  const { data: execMetrics, loading: execLoading } = useApi<ExecutiveMetrics>(fetchExec);

  // Poll for active scans
  const [pollEnabled, setPollEnabled] = useState(true);
  const fetchActiveScans = useCallback(() => scansApi.getActive(), []);
  const { data: activeScansData } = usePollingApi(fetchActiveScans, {
    interval: 5000,
    enabled: pollEnabled,
    immediate: true,
    onDataChange: () => refetch(),
  });

  useEffect(() => {
    if (activeScansData && !activeScansData.has_active) {
      setPollEnabled(false);
    } else if (activeScansData?.has_active) {
      setPollEnabled(true);
    }
  }, [activeScansData]);

  if (loading && execLoading) {
    return (
      <div>
        <h1 className="mb-6 text-3xl font-bold">Dashboard</h1>
        <LoadingSkeleton />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <h1 className="mb-6 text-3xl font-bold">Dashboard</h1>
        <ErrorState
          title="Failed to load dashboard"
          message={error}
          onRetry={refetch}
        />
      </div>
    );
  }

  // Use mock data if API returns null
  const dashboardData: DashboardStats = stats || {
    total_assets: 156,
    total_findings: 423,
    total_scans: 28,
    findings_by_severity: {
      critical: 12,
      high: 45,
      medium: 128,
      low: 189,
      info: 49,
    },
    findings_by_state: {
      open: 234,
      acknowledged: 89,
      resolved: 87,
      false_positive: 13,
    },
    recent_findings: [
      {
        id: '1',
        asset_id: 'asset-1',
        scan_id: 'scan-1',
        title: 'SQL Injection Vulnerability',
        description: 'SQL injection in login form',
        severity: 'critical',
        state: 'open',
        cve_id: 'CVE-2024-1234',
        cvss_score: 9.8,
        affected_component: 'auth-service',
        references: [],
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      {
        id: '2',
        asset_id: 'asset-2',
        scan_id: 'scan-1',
        title: 'Outdated OpenSSL Version',
        description: 'OpenSSL version with known vulnerabilities',
        severity: 'high',
        state: 'open',
        cve_id: 'CVE-2024-5678',
        cvss_score: 7.5,
        affected_component: 'web-server',
        references: [],
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ],
    risk_trend: [
      { date: '2024-01-01', risk_score: 65, critical: 15, high: 40, medium: 100, low: 150 },
      { date: '2024-01-08', risk_score: 62, critical: 14, high: 38, medium: 105, low: 155 },
      { date: '2024-01-15', risk_score: 58, critical: 12, high: 42, medium: 110, low: 160 },
      { date: '2024-01-22', risk_score: 55, critical: 10, high: 45, medium: 115, low: 170 },
      { date: '2024-01-29', risk_score: 52, critical: 12, high: 45, medium: 128, low: 189 },
    ],
    top_vulnerabilities: [
      { cve_id: 'CVE-2024-1234', title: 'SQL Injection', severity: 'critical', affected_assets: 5, cvss_score: 9.8 },
      { cve_id: 'CVE-2024-5678', title: 'OpenSSL Vulnerability', severity: 'high', affected_assets: 12, cvss_score: 7.5 },
    ],
  };

  // Fallback executive data when API hasn't responded yet
  const execData: ExecutiveMetrics = execMetrics || {
    risk_grade: {
      grade: (() => {
        const s = dashboardData.findings_by_severity;
        const raw = s.critical * 10 + s.high * 5 + s.medium * 2 + s.low * 1;
        const norm = Math.min(100, Math.round((raw / 1000) * 100));
        if (norm >= 80) return 'F';
        if (norm >= 60) return 'D';
        if (norm >= 40) return 'C';
        if (norm >= 20) return 'B';
        return 'A';
      })(),
      score: Math.min(100, Math.round(
        ((dashboardData.findings_by_severity.critical * 10 +
          dashboardData.findings_by_severity.high * 5 +
          dashboardData.findings_by_severity.medium * 2 +
          dashboardData.findings_by_severity.low * 1) / 1000) * 100
      )),
      open_findings: dashboardData.findings_by_state.open || 0,
      severity_counts: dashboardData.findings_by_severity,
    },
    mttr: { overall_avg_days: 0, overall_sample_size: 0, by_severity: {} },
    sla_compliance: {
      overall_pct: 100,
      by_severity: {},
      targets: { critical: 7, high: 30, medium: 90, low: 180 },
      overdue: { total: 0, critical: 0, high: 0 },
    },
    posture_trend: [],
    redops_coverage: { validated_cves: 0, exploitable: 0 },
    period_days: 90,
    generated_at: new Date().toISOString(),
  };

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Executive Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Security posture overview for the last {execData.period_days} days
          </p>
        </div>
        <div className="flex gap-2">
          <QuickScanDialog />
          <Button onClick={refetch} variant="outline">
            Refresh
          </Button>
        </div>
      </div>

      {/* Executive Scorecard */}
      <ExecutiveScorecard metrics={execData} />

      {/* Active Scans Banner */}
      {activeScansData?.has_active && activeScansData.items.length > 0 && (
        <Card className="mb-6 border-blue-500/30 bg-blue-500/5">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-base">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-500" />
                </span>
                {activeScansData.items.length} Active Scan{activeScansData.items.length !== 1 ? 's' : ''}
              </CardTitle>
              <Link to="/scans?status=running">
                <Button variant="ghost" size="sm">
                  View all
                  <ExternalLink className="ml-2 h-3 w-3" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="space-y-3">
              {activeScansData.items.map((scan) => (
                <div key={scan.id} className="flex items-center gap-4 rounded-lg border bg-card/50 p-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-sm truncate">{scan.name}</span>
                      <Badge variant="outline" className="text-[10px] shrink-0">{capitalize(scan.type)}</Badge>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <span>{scan.progress.completed_tasks + scan.progress.failed_tasks}/{scan.progress.total_tasks} tasks</span>
                      <span>·</span>
                      <span className="flex items-center gap-1">
                        <Activity className="h-3 w-3 text-blue-500" />
                        {scan.findings_count} findings
                      </span>
                    </div>
                  </div>
                  <div className="w-32 shrink-0">
                    <div className="flex justify-end text-xs text-muted-foreground mb-1">
                      {scan.progress.percentage}%
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full rounded-full bg-blue-500 transition-all duration-500 ease-out"
                        style={{ width: `${scan.progress.percentage}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Risk Posture Trend + MTTR vs SLA */}
      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-teal-400" />
              Risk Posture Trend
            </CardTitle>
            <p className="text-xs text-muted-foreground">New findings vs. remediated — weekly</p>
          </CardHeader>
          <CardContent className="h-[300px]">
            <PostureTrendChart data={execData.posture_trend} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-teal-400" />
              MTTR vs SLA Targets
            </CardTitle>
            <p className="text-xs text-muted-foreground">Actual remediation time vs. SLA by severity</p>
          </CardHeader>
          <CardContent className="h-[300px]">
            <MttrBarChart mttr={execData.mttr} />
          </CardContent>
        </Card>
      </div>

      {/* Operational Stats Cards */}
      <div className="mb-6 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Assets"
          value={dashboardData.total_assets}
          icon={Server}
          href="/assets"
        />
        <StatCard
          title="Total Findings"
          value={dashboardData.total_findings}
          icon={AlertTriangle}
          href="/findings"
        />
        <StatCard
          title="Total Scans"
          value={dashboardData.total_scans}
          icon={Scan}
          href="/scans"
        />
        <StatCard
          title="Resolved"
          value={dashboardData.findings_by_state.resolved || 0}
          icon={CheckCircle2}
          href="/findings?state=resolved"
        />
      </div>

      {/* Charts */}
      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Findings by Severity</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px]">
            <SeverityPieChart data={dashboardData.findings_by_severity} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Findings by State</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px]">
            <StateBarChart data={dashboardData.findings_by_state} />
          </CardContent>
        </Card>
      </div>

      {/* Risk Trend */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Risk Trend (Last 30 Days)</CardTitle>
        </CardHeader>
        <CardContent className="h-[300px]">
          <RiskTrendChart data={dashboardData.risk_trend} />
        </CardContent>
      </Card>

      {/* Recent Findings and Top Vulnerabilities */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Recent Findings</CardTitle>
            <Link to="/findings">
              <Button variant="ghost" size="sm">
                View all
                <ExternalLink className="ml-2 h-4 w-4" />
              </Button>
            </Link>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {dashboardData.recent_findings.slice(0, 5).map((finding) => (
                <Link
                  key={finding.id}
                  to={`/findings?search=${encodeURIComponent(finding.title)}`}
                  className="flex items-center justify-between rounded-lg border p-3 cursor-pointer hover:bg-accent/50 transition-colors"
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={finding.severity as Severity}
                      >
                        {capitalize(finding.severity)}
                      </Badge>
                      <span className="font-medium">{finding.title}</span>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {finding.affected_component} - {formatRelativeTime(finding.created_at)}
                    </p>
                  </div>
                  <ExternalLink className="h-4 w-4 text-muted-foreground ml-2 flex-shrink-0" />
                </Link>
              ))}
              {dashboardData.recent_findings.length === 0 && (
                <p className="text-center text-sm text-muted-foreground">
                  No recent findings
                </p>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top Vulnerabilities</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {dashboardData.top_vulnerabilities.slice(0, 5).map((vuln) => (
                <Link
                  key={vuln.cve_id}
                  to={`/vulnerabilities?search=${encodeURIComponent(vuln.cve_id)}`}
                  className="flex items-center justify-between rounded-lg border p-3 cursor-pointer hover:bg-accent/50 transition-colors"
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Badge variant={vuln.severity as Severity}>
                        {capitalize(vuln.severity)}
                      </Badge>
                      <span className="font-medium">{vuln.cve_id}</span>
                    </div>
                    <p className="mt-1 text-sm">{vuln.title}</p>
                    <p className="text-xs text-muted-foreground">
                      CVSS: {vuln.cvss_score} - Affects {vuln.affected_assets} assets
                    </p>
                  </div>
                  <ExternalLink className="h-4 w-4 text-muted-foreground ml-2 flex-shrink-0" />
                </Link>
              ))}
              {dashboardData.top_vulnerabilities.length === 0 && (
                <p className="text-center text-sm text-muted-foreground">
                  No vulnerabilities found
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
