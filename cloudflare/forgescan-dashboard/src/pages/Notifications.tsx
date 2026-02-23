import { useState, useEffect, useCallback } from 'react';
import { Bell, RefreshCw, Plus, Trash2, TestTube2, Activity } from 'lucide-react';
import { useAuth, hasRole } from '@/lib/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle, DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';

const API = import.meta.env.VITE_API_URL || '/api';

function getAuthHeaders() {
  const token = localStorage.getItem('forgescan_token');
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const EVENT_TYPES = [
  'scan.completed', 'scan.failed', 'finding.critical', 'finding.high',
  'finding.detected', 'nvd.sync_completed', 'report.generated',
];

interface Rule {
  id: string; name: string; event_type: string; conditions: string;
  integration_id: string; integration_name: string | null; integration_type: string | null;
  template: string | null; is_active: number; trigger_count: number;
  last_triggered_at: string | null; created_at: string;
}
interface Stats {
  total_rules: number; active_rules: number; total_sent: number;
  total_failed: number; recent_24h: number;
}
interface LogEntry {
  id: string; rule_id: string; rule_name: string | null; event_type: string;
  channel: string; status: string; error_message: string | null; created_at: string;
}
interface Integration {
  id: string; name: string; type: string; is_active: number;
}

export function Notifications() {
  const { user } = useAuth();
  const isAdmin = hasRole(user, 'platform_admin');

  const [rules, setRules] = useState<Rule[]>([]);
  const [stats, setStats] = useState<Stats>({ total_rules: 0, active_rules: 0, total_sent: 0, total_failed: 0, recent_24h: 0 });
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState<string | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: '', event_type: '', integration_id: '', conditions: '', template: '' });

  const loadData = useCallback(async () => {
    try {
      const [rulesRes, statsRes, logsRes, intRes] = await Promise.all([
        fetch(`${API}/notifications`, { headers: getAuthHeaders() }),
        fetch(`${API}/notifications/stats`, { headers: getAuthHeaders() }),
        fetch(`${API}/notifications/log?limit=30`, { headers: getAuthHeaders() }),
        fetch(`${API}/integrations`, { headers: getAuthHeaders() }),
      ]);
      if (rulesRes.ok) { const d = await rulesRes.json(); setRules(d.rules || []); }
      if (statsRes.ok) { const d = await statsRes.json(); setStats(d); }
      if (logsRes.ok) { const d = await logsRes.json(); setLogs(d.logs || []); }
      if (intRes.ok) { const d = await intRes.json(); setIntegrations(d.integrations || []); }
    } catch { /* ignore */ } finally { setLoading(false); }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [loadData]);

  async function createRule() {
    setCreating(true);
    try {
      let conditions = {};
      if (form.conditions.trim()) {
        try { conditions = JSON.parse(form.conditions); } catch { /* keep empty */ }
      }
      const res = await fetch(`${API}/notifications`, {
        method: 'POST', headers: getAuthHeaders(),
        body: JSON.stringify({ name: form.name, event_type: form.event_type, integration_id: form.integration_id, conditions, template: form.template || undefined }),
      });
      if (res.ok) {
        setCreateOpen(false);
        setForm({ name: '', event_type: '', integration_id: '', conditions: '', template: '' });
        loadData();
      }
    } catch { /* ignore */ } finally { setCreating(false); }
  }

  async function toggleRule(id: string, currentActive: number) {
    try {
      await fetch(`${API}/notifications/${id}`, {
        method: 'PUT', headers: getAuthHeaders(),
        body: JSON.stringify({ is_active: !currentActive }),
      });
      loadData();
    } catch { /* ignore */ }
  }

  async function testRule(id: string) {
    setTesting(id);
    try {
      await fetch(`${API}/notifications/${id}/test`, { method: 'POST', headers: getAuthHeaders() });
      loadData();
    } catch { /* ignore */ } finally { setTesting(null); }
  }

  async function deleteRule(id: string) {
    try {
      await fetch(`${API}/notifications/${id}`, { method: 'DELETE', headers: getAuthHeaders() });
      loadData();
    } catch { /* ignore */ }
  }

  if (loading) {
    return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" /></div>;
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Bell className="h-5 w-5" /> Notifications</h1>
          <p className="text-muted-foreground mt-1">Event-driven alerting rules and delivery log</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={loadData}><RefreshCw className="mr-2 h-4 w-4" /> Refresh</Button>
          {isAdmin && (
            <Dialog open={createOpen} onOpenChange={setCreateOpen}>
              <DialogTrigger asChild>
                <Button><Plus className="mr-2 h-4 w-4" /> New Rule</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create Notification Rule</DialogTitle>
                  <DialogDescription>Define when and where to send alerts.</DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid gap-2">
                    <Label>Name</Label>
                    <Input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Critical findings alert" />
                  </div>
                  <div className="grid gap-2">
                    <Label>Event Type</Label>
                    <Select value={form.event_type} onValueChange={v => setForm({ ...form, event_type: v })}>
                      <SelectTrigger><SelectValue placeholder="Select event..." /></SelectTrigger>
                      <SelectContent>
                        {EVENT_TYPES.map(e => <SelectItem key={e} value={e}>{e}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label>Integration</Label>
                    <Select value={form.integration_id} onValueChange={v => setForm({ ...form, integration_id: v })}>
                      <SelectTrigger><SelectValue placeholder="Select integration..." /></SelectTrigger>
                      <SelectContent>
                        {integrations.filter(i => i.is_active).map(i => (
                          <SelectItem key={i.id} value={i.id}>{i.name} ({i.type})</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label>Conditions (JSON, optional)</Label>
                    <Textarea value={form.conditions} onChange={e => setForm({ ...form, conditions: e.target.value })} placeholder='{"min_severity": "high"}' rows={2} />
                  </div>
                  <div className="grid gap-2">
                    <Label>Template Override (optional)</Label>
                    <Input value={form.template} onChange={e => setForm({ ...form, template: e.target.value })} placeholder="Custom template name" />
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
                  <Button onClick={createRule} disabled={creating || !form.name || !form.event_type || !form.integration_id}>
                    {creating ? 'Creating...' : 'Create Rule'}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 grid-cols-2 md:grid-cols-5">
        {[
          { label: 'Total Rules', value: stats.total_rules, color: '' },
          { label: 'Active', value: stats.active_rules, color: 'text-green-400' },
          { label: 'Sent (all time)', value: stats.total_sent, color: 'text-blue-400' },
          { label: 'Failed', value: stats.total_failed, color: 'text-red-500' },
          { label: 'Last 24h', value: stats.recent_24h, color: 'text-orange-500' },
        ].map(s => (
          <Card key={s.label}>
            <CardContent className="pt-6">
              <p className="text-sm text-muted-foreground">{s.label}</p>
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Notification Rules */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Activity className="h-5 w-5" /> Rules</CardTitle>
          <CardDescription>{rules.length} notification rule{rules.length !== 1 ? 's' : ''} configured</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Event Type</TableHead>
                <TableHead>Integration</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Triggers</TableHead>
                <TableHead>Last Triggered</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    No notification rules configured. Create one to start alerting.
                  </TableCell>
                </TableRow>
              ) : rules.map(r => (
                <TableRow key={r.id}>
                  <TableCell className="font-medium">{r.name}</TableCell>
                  <TableCell><Badge variant="outline">{r.event_type}</Badge></TableCell>
                  <TableCell className="text-sm">
                    {r.integration_name || r.integration_id.substring(0, 8)}
                    {r.integration_type && <Badge variant="outline" className="ml-1 text-xs">{r.integration_type}</Badge>}
                  </TableCell>
                  <TableCell>
                    <Badge variant={r.is_active ? 'default' : 'secondary'} className="cursor-pointer"
                      onClick={() => isAdmin && toggleRule(r.id, r.is_active)}>
                      {r.is_active ? 'Active' : 'Disabled'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm">{r.trigger_count ?? 0}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{timeAgo(r.last_triggered_at)}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button variant="ghost" size="icon" onClick={() => testRule(r.id)} disabled={testing === r.id}>
                        {testing === r.id ? <RefreshCw className="h-4 w-4 animate-spin" /> : <TestTube2 className="h-4 w-4 text-blue-400" />}
                      </Button>
                      {isAdmin && (
                        <Button variant="ghost" size="icon" onClick={() => deleteRule(r.id)}>
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Notification Log */}
      <Card>
        <CardHeader>
          <CardTitle>Delivery Log</CardTitle>
          <CardDescription>Recent notification dispatch history</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Rule</TableHead>
                <TableHead>Event Type</TableHead>
                <TableHead>Channel</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Error</TableHead>
                <TableHead>Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No notifications sent yet.
                  </TableCell>
                </TableRow>
              ) : logs.map(l => (
                <TableRow key={l.id}>
                  <TableCell className="text-sm font-medium">{l.rule_name || l.rule_id?.substring(0, 8) || '-'}</TableCell>
                  <TableCell><Badge variant="outline">{l.event_type}</Badge></TableCell>
                  <TableCell className="text-sm">{l.channel || '-'}</TableCell>
                  <TableCell>
                    <Badge variant={l.status === 'sent' || l.status === 'success' ? 'default' : 'destructive'}>{l.status}</Badge>
                  </TableCell>
                  <TableCell className="text-xs text-red-500 max-w-xs truncate">{l.error_message || '-'}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{timeAgo(l.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
