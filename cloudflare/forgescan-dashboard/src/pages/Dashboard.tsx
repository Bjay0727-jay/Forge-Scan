import { useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  Server,
  AlertTriangle,
  Scan,
  TrendingUp,
  ExternalLink,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { SeverityPieChart } from '@/components/charts/SeverityPieChart';
import { RiskTrendChart } from '@/components/charts/RiskTrendChart';
import { StateBarChart } from '@/components/charts/StateBarChart';
import { ErrorState } from '@/components/ErrorState';
import { useApi } from '@/hooks/useApi';
import { dashboardApi } from '@/lib/api';
import { formatRelativeTime, capitalize } from '@/lib/utils';
import type { DashboardStats, Severity } from '@/types';

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
      <Card className="transition-colors hover:bg-accent">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">{title}</CardTitle>
          <Icon className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{value.toLocaleString()}</div>
        </CardContent>
      </Card>
    </Link>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-6">
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
          <CardHeader>
            <Skeleton className="h-5 w-32" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[300px]" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <Skeleton className="h-5 w-32" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[300px]" />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export function Dashboard() {
  const fetchStats = useCallback(() => dashboardApi.getStats(), []);
  const { data: stats, loading, error, refetch } = useApi<DashboardStats>(fetchStats);

  if (loading) {
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

  const riskScore = Math.round(
    (dashboardData.findings_by_severity.critical * 10 +
      dashboardData.findings_by_severity.high * 7 +
      dashboardData.findings_by_severity.medium * 4 +
      dashboardData.findings_by_severity.low * 1) /
      Math.max(dashboardData.total_findings, 1)
  );

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <Button onClick={refetch} variant="outline">
          Refresh
        </Button>
      </div>

      {/* Stats Cards */}
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
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{riskScore}/10</div>
            <p className="text-xs text-muted-foreground">
              Based on open findings
            </p>
          </CardContent>
        </Card>
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
                <div
                  key={finding.id}
                  className="flex items-center justify-between rounded-lg border p-3"
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
                </div>
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
                <div
                  key={vuln.cve_id}
                  className="flex items-center justify-between rounded-lg border p-3"
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
                </div>
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
