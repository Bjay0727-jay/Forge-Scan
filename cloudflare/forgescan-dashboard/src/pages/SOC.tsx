import { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  AlertTriangle,
  Bell,
  Activity,
  Eye,
  RefreshCw,
  Target,
  Zap,
} from 'lucide-react';
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
import { socApi } from '@/lib/api';
import type {
  SOCOverview,
  SOCAlert,
  SOCIncident,
  SOCDetectionRule,
  PaginatedResponse,
} from '@/types';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function severityBadge(severity: string) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  };
  return (
    <Badge className={`text-[10px] border ${colors[severity] || colors.info}`}>
      {severity}
    </Badge>
  );
}

function statusBadge(status: string) {
  const colors: Record<string, string> = {
    new: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
    triaged: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    investigating: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    escalated: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    resolved: 'bg-green-500/20 text-green-400 border-green-500/30',
    closed: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    false_positive: 'bg-gray-600/20 text-gray-500 border-gray-600/30',
    open: 'bg-red-500/20 text-red-400 border-red-500/30',
    containment: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    eradication: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    recovery: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    post_incident: 'bg-teal-500/20 text-teal-400 border-teal-500/30',
  };
  return (
    <Badge className={`text-[10px] border ${colors[status] || colors.new}`}>
      {status.replace('_', ' ')}
    </Badge>
  );
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// ─── Tabs ────────────────────────────────────────────────────────────────────

type TabId = 'overview' | 'alerts' | 'incidents' | 'rules';

// ─── Component ───────────────────────────────────────────────────────────────

export function SOC() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [overview, setOverview] = useState<SOCOverview | null>(null);
  const [alerts, setAlerts] = useState<PaginatedResponse<SOCAlert> | null>(null);
  const [incidents, setIncidents] = useState<PaginatedResponse<SOCIncident> | null>(null);
  const [rules, setRules] = useState<SOCDetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [alertFilter, setAlertFilter] = useState<{ severity?: string; status?: string }>({});
  const [alertPage, setAlertPage] = useState(1);

  const loadOverview = useCallback(async () => {
    try {
      const data = await socApi.getOverview();
      setOverview(data);
    } catch { /* empty */ }
  }, []);

  const loadAlerts = useCallback(async () => {
    try {
      const data = await socApi.listAlerts({ page: alertPage, page_size: 25, ...alertFilter });
      setAlerts(data);
    } catch { /* empty */ }
  }, [alertPage, alertFilter]);

  const loadIncidents = useCallback(async () => {
    try {
      const data = await socApi.listIncidents({ page: 1, page_size: 25 });
      setIncidents(data);
    } catch { /* empty */ }
  }, []);

  const loadRules = useCallback(async () => {
    try {
      const data = await socApi.listDetectionRules();
      setRules(data.items);
    } catch { /* empty */ }
  }, []);

  const loadAll = useCallback(async () => {
    setLoading(true);
    await Promise.all([loadOverview(), loadAlerts(), loadIncidents(), loadRules()]);
    setLoading(false);
  }, [loadOverview, loadAlerts, loadIncidents, loadRules]);

  useEffect(() => { loadAll(); }, [loadAll]);

  useEffect(() => { loadAlerts(); }, [loadAlerts]);

  const tabs: { id: TabId; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: 'overview', label: 'Overview', icon: <Activity className="h-4 w-4" /> },
    { id: 'alerts', label: 'Alerts', icon: <Bell className="h-4 w-4" />, count: overview?.alerts.new || 0 },
    { id: 'incidents', label: 'Incidents', icon: <Target className="h-4 w-4" />, count: overview?.incidents.active || 0 },
    { id: 'rules', label: 'Detection Rules', icon: <Zap className="h-4 w-4" /> },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="h-7 w-7" style={{ color: '#14b8a6' }} />
            ForgeSOC
          </h1>
          <p className="text-sm" style={{ color: '#6b8fb9' }}>
            Security Operations Center — Alert triage, incident response, and detection rules
          </p>
        </div>
        <Button
          size="sm"
          onClick={loadAll}
          disabled={loading}
          className="gap-1.5"
          style={{ background: 'rgba(13,148,136,0.15)', color: '#14b8a6', border: '1px solid rgba(13,148,136,0.2)' }}
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Tab Bar */}
      <div className="flex gap-1 p-1 rounded-lg" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(75,119,169,0.2)' }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all"
            style={{
              background: activeTab === tab.id ? 'rgba(13,148,136,0.15)' : 'transparent',
              color: activeTab === tab.id ? '#14b8a6' : '#6b8fb9',
              border: activeTab === tab.id ? '1px solid rgba(13,148,136,0.2)' : '1px solid transparent',
            }}
          >
            {tab.icon}
            {tab.label}
            {tab.count !== undefined && tab.count > 0 && (
              <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && <OverviewTab overview={overview} loading={loading} />}
      {activeTab === 'alerts' && (
        <AlertsTab
          alerts={alerts}
          loading={loading}
          filter={alertFilter}
          onFilterChange={setAlertFilter}
          page={alertPage}
          onPageChange={setAlertPage}
        />
      )}
      {activeTab === 'incidents' && <IncidentsTab incidents={incidents} loading={loading} />}
      {activeTab === 'rules' && <RulesTab rules={rules} loading={loading} />}
    </div>
  );
}

// ─── Overview Tab ────────────────────────────────────────────────────────────

function OverviewTab({ overview, loading }: { overview: SOCOverview | null; loading: boolean }) {
  if (loading || !overview) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-6 w-6 animate-spin" style={{ color: '#14b8a6' }} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Alerts"
          value={overview.alerts.total}
          subtitle={`${overview.alerts.last_24h} in last 24h`}
          icon={<Bell className="h-5 w-5" />}
          color="#14b8a6"
        />
        <StatCard
          title="New Alerts"
          value={overview.alerts.new}
          subtitle="Awaiting triage"
          icon={<AlertTriangle className="h-5 w-5" />}
          color={overview.alerts.new > 0 ? '#ef4444' : '#14b8a6'}
        />
        <StatCard
          title="Active Incidents"
          value={overview.incidents.active}
          subtitle={`${overview.incidents.total} total`}
          icon={<Target className="h-5 w-5" />}
          color={overview.incidents.active > 0 ? '#f97316' : '#14b8a6'}
        />
        <StatCard
          title="Resolved"
          value={overview.alerts.resolved}
          subtitle={`${overview.incidents.closed} incidents closed`}
          icon={<Eye className="h-5 w-5" />}
          color="#22c55e"
        />
      </div>

      {/* Severity Breakdown + Active Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Breakdown */}
        <Card style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.2)' }}>
          <CardHeader>
            <CardTitle className="text-white text-sm">Alert Severity Breakdown</CardTitle>
            <CardDescription style={{ color: '#4b77a9' }}>Open alerts by severity level</CardDescription>
          </CardHeader>
          <CardContent>
            {overview.severity_breakdown.length === 0 ? (
              <p className="text-sm" style={{ color: '#4b77a9' }}>No open alerts</p>
            ) : (
              <div className="space-y-3">
                {overview.severity_breakdown.map((item) => {
                  const total = overview.alerts.total || 1;
                  const pct = Math.round((item.count / total) * 100);
                  const barColors: Record<string, string> = {
                    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280',
                  };
                  return (
                    <div key={item.severity} className="space-y-1">
                      <div className="flex items-center justify-between text-sm">
                        <span className="capitalize" style={{ color: barColors[item.severity] || '#6b8fb9' }}>
                          {item.severity}
                        </span>
                        <span style={{ color: '#6b8fb9' }}>{item.count} ({pct}%)</span>
                      </div>
                      <div className="h-2 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
                        <div
                          className="h-full rounded-full transition-all"
                          style={{ width: `${pct}%`, background: barColors[item.severity] || '#6b8fb9' }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Active Incidents */}
        <Card style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.2)' }}>
          <CardHeader>
            <CardTitle className="text-white text-sm">Active Incidents</CardTitle>
            <CardDescription style={{ color: '#4b77a9' }}>Incidents requiring attention</CardDescription>
          </CardHeader>
          <CardContent>
            {overview.active_incidents.length === 0 ? (
              <p className="text-sm" style={{ color: '#4b77a9' }}>No active incidents</p>
            ) : (
              <div className="space-y-3">
                {overview.active_incidents.map((inc: SOCIncident) => (
                  <div
                    key={inc.id}
                    className="flex items-center justify-between p-3 rounded-lg"
                    style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(75,119,169,0.15)' }}
                  >
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-white truncate">{inc.title}</p>
                      <div className="flex items-center gap-2 mt-1">
                        {severityBadge(inc.severity)}
                        {statusBadge(inc.status)}
                        <span className="text-[11px]" style={{ color: '#4b77a9' }}>
                          P{inc.priority} — {inc.alert_count} alerts
                        </span>
                      </div>
                    </div>
                    <span className="text-[11px] ml-2" style={{ color: '#4b77a9' }}>
                      {timeAgo(inc.created_at)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Alerts */}
      <Card style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.2)' }}>
        <CardHeader>
          <CardTitle className="text-white text-sm">Recent Alerts</CardTitle>
          <CardDescription style={{ color: '#4b77a9' }}>Latest alerts from all sources</CardDescription>
        </CardHeader>
        <CardContent>
          {overview.recent_alerts.length === 0 ? (
            <p className="text-sm" style={{ color: '#4b77a9' }}>No alerts yet. Alerts are auto-created when events match detection rules.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow style={{ borderColor: 'rgba(75,119,169,0.2)' }}>
                  <TableHead style={{ color: '#4b77a9' }}>Alert</TableHead>
                  <TableHead style={{ color: '#4b77a9' }}>Severity</TableHead>
                  <TableHead style={{ color: '#4b77a9' }}>Status</TableHead>
                  <TableHead style={{ color: '#4b77a9' }}>Source</TableHead>
                  <TableHead style={{ color: '#4b77a9' }}>Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {overview.recent_alerts.map((alert: SOCAlert) => (
                  <TableRow key={alert.id} style={{ borderColor: 'rgba(75,119,169,0.1)' }}>
                    <TableCell className="text-white text-sm font-medium max-w-[300px] truncate">
                      {alert.title}
                    </TableCell>
                    <TableCell>{severityBadge(alert.severity)}</TableCell>
                    <TableCell>{statusBadge(alert.status)}</TableCell>
                    <TableCell>
                      <span className="text-xs" style={{ color: '#6b8fb9' }}>{alert.source}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs" style={{ color: '#4b77a9' }}>{timeAgo(alert.created_at)}</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Stat Card ───────────────────────────────────────────────────────────────

function StatCard({ title, value, subtitle, icon, color }: {
  title: string; value: number; subtitle: string; icon: React.ReactNode; color: string;
}) {
  return (
    <Card style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.2)' }}>
      <CardContent className="pt-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs font-medium" style={{ color: '#4b77a9' }}>{title}</p>
            <p className="text-2xl font-bold mt-1" style={{ color }}>{value}</p>
            <p className="text-[11px] mt-1" style={{ color: '#4b77a9' }}>{subtitle}</p>
          </div>
          <div className="p-3 rounded-lg" style={{ background: `${color}15`, color }}>
            {icon}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Alerts Tab ──────────────────────────────────────────────────────────────

function AlertsTab({
  alerts,
  loading,
  filter,
  onFilterChange,
  page,
  onPageChange,
}: {
  alerts: PaginatedResponse<SOCAlert> | null;
  loading: boolean;
  filter: { severity?: string; status?: string };
  onFilterChange: (f: { severity?: string; status?: string }) => void;
  page: number;
  onPageChange: (p: number) => void;
}) {
  const severities = ['', 'critical', 'high', 'medium', 'low', 'info'];
  const statuses = ['', 'new', 'triaged', 'investigating', 'escalated', 'resolved', 'closed'];

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-3">
        <select
          value={filter.severity || ''}
          onChange={(e) => { onFilterChange({ ...filter, severity: e.target.value || undefined }); onPageChange(1); }}
          className="rounded-md px-3 py-1.5 text-sm"
          style={{ background: 'rgba(255,255,255,0.06)', color: '#6b8fb9', border: '1px solid rgba(75,119,169,0.2)' }}
        >
          <option value="">All Severities</option>
          {severities.filter(Boolean).map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          value={filter.status || ''}
          onChange={(e) => { onFilterChange({ ...filter, status: e.target.value || undefined }); onPageChange(1); }}
          className="rounded-md px-3 py-1.5 text-sm"
          style={{ background: 'rgba(255,255,255,0.06)', color: '#6b8fb9', border: '1px solid rgba(75,119,169,0.2)' }}
        >
          <option value="">All Statuses</option>
          {statuses.filter(Boolean).map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
        </select>
        <div className="flex-1" />
        <span className="text-xs" style={{ color: '#4b77a9' }}>{alerts?.total || 0} alerts</span>
      </div>

      {/* Table */}
      <Card style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.2)' }}>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow style={{ borderColor: 'rgba(75,119,169,0.2)' }}>
                <TableHead style={{ color: '#4b77a9' }}>Alert</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Severity</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Status</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Type</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Source</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(alerts?.items || []).length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12" style={{ color: '#4b77a9' }}>
                    {loading ? 'Loading...' : 'No alerts found'}
                  </TableCell>
                </TableRow>
              ) : (
                (alerts?.items || []).map((alert) => (
                  <TableRow key={alert.id} style={{ borderColor: 'rgba(75,119,169,0.1)' }}>
                    <TableCell className="text-white text-sm font-medium max-w-[300px] truncate">
                      {alert.title}
                    </TableCell>
                    <TableCell>{severityBadge(alert.severity)}</TableCell>
                    <TableCell>{statusBadge(alert.status)}</TableCell>
                    <TableCell>
                      <span className="text-xs capitalize" style={{ color: '#6b8fb9' }}>{alert.alert_type}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs" style={{ color: '#6b8fb9' }}>{alert.source}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs" style={{ color: '#4b77a9' }}>{timeAgo(alert.created_at)}</span>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Pagination */}
      {alerts && alerts.total_pages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            style={{ color: '#6b8fb9', borderColor: 'rgba(75,119,169,0.2)' }}
          >
            Previous
          </Button>
          <span className="text-xs" style={{ color: '#4b77a9' }}>
            Page {page} of {alerts.total_pages}
          </span>
          <Button
            size="sm"
            variant="outline"
            disabled={page >= alerts.total_pages}
            onClick={() => onPageChange(page + 1)}
            style={{ color: '#6b8fb9', borderColor: 'rgba(75,119,169,0.2)' }}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Incidents Tab ───────────────────────────────────────────────────────────

function IncidentsTab({
  incidents,
  loading,
}: {
  incidents: PaginatedResponse<SOCIncident> | null;
  loading: boolean;
}) {
  return (
    <div className="space-y-4">
      <Card style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.2)' }}>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow style={{ borderColor: 'rgba(75,119,169,0.2)' }}>
                <TableHead style={{ color: '#4b77a9' }}>Incident</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Priority</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Severity</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Status</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Alerts</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(incidents?.items || []).length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12" style={{ color: '#4b77a9' }}>
                    {loading ? 'Loading...' : 'No incidents. Incidents are created when critical alerts are auto-escalated.'}
                  </TableCell>
                </TableRow>
              ) : (
                (incidents?.items || []).map((incident) => (
                  <TableRow key={incident.id} style={{ borderColor: 'rgba(75,119,169,0.1)' }}>
                    <TableCell className="text-white text-sm font-medium max-w-[300px] truncate">
                      {incident.title}
                    </TableCell>
                    <TableCell>
                      <Badge className={`text-[10px] border ${
                        incident.priority <= 1 ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                        incident.priority <= 2 ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                        'bg-blue-500/20 text-blue-400 border-blue-500/30'
                      }`}>
                        P{incident.priority}
                      </Badge>
                    </TableCell>
                    <TableCell>{severityBadge(incident.severity)}</TableCell>
                    <TableCell>{statusBadge(incident.status)}</TableCell>
                    <TableCell>
                      <span className="text-sm" style={{ color: '#6b8fb9' }}>{incident.alert_count}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs" style={{ color: '#4b77a9' }}>{timeAgo(incident.created_at)}</span>
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

// ─── Detection Rules Tab ─────────────────────────────────────────────────────

function RulesTab({
  rules,
  loading,
}: {
  rules: SOCDetectionRule[];
  loading: boolean;
}) {
  return (
    <div className="space-y-4">
      <Card style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.2)' }}>
        <CardHeader>
          <CardTitle className="text-white text-sm">Detection Rules</CardTitle>
          <CardDescription style={{ color: '#4b77a9' }}>
            Rules that automatically create SOC alerts when events match patterns and conditions
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow style={{ borderColor: 'rgba(75,119,169,0.2)' }}>
                <TableHead style={{ color: '#4b77a9' }}>Rule</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Pattern</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Alert Severity</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Auto-Escalate</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Status</TableHead>
                <TableHead style={{ color: '#4b77a9' }}>Triggers</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12" style={{ color: '#4b77a9' }}>
                    {loading ? 'Loading...' : 'No detection rules configured'}
                  </TableCell>
                </TableRow>
              ) : (
                rules.map((rule) => (
                  <TableRow key={rule.id} style={{ borderColor: 'rgba(75,119,169,0.1)' }}>
                    <TableCell>
                      <div>
                        <p className="text-white text-sm font-medium">{rule.name}</p>
                        {rule.description && (
                          <p className="text-[11px] mt-0.5" style={{ color: '#4b77a9' }}>{rule.description}</p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <code className="text-[11px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(255,255,255,0.06)', color: '#6b8fb9' }}>
                        {rule.event_pattern}
                      </code>
                    </TableCell>
                    <TableCell>{severityBadge(rule.alert_severity)}</TableCell>
                    <TableCell>
                      {rule.auto_escalate ? (
                        <Badge className="text-[10px] border bg-orange-500/20 text-orange-400 border-orange-500/30">Yes</Badge>
                      ) : (
                        <span className="text-xs" style={{ color: '#4b77a9' }}>No</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge className={`text-[10px] border ${
                        rule.is_active
                          ? 'bg-green-500/20 text-green-400 border-green-500/30'
                          : 'bg-gray-500/20 text-gray-400 border-gray-500/30'
                      }`}>
                        {rule.is_active ? 'Active' : 'Disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm" style={{ color: '#6b8fb9' }}>{rule.trigger_count}</span>
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
