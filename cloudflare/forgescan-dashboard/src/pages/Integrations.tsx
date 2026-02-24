import { useState, useEffect, useCallback } from 'react';
import {
  Plug,
  RefreshCw,
  Plus,
  Trash2,
  TestTube2,
  Mail,
  Webhook,
  CheckCircle,
  XCircle,
  Eye,
} from 'lucide-react';
import { ConfirmBanner } from '@/components/ConfirmBanner';
import { useAuth, hasRole } from '@/lib/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

interface Integration {
  id: string;
  name: string;
  type: string;
  provider: string;
  config: string;
  is_active: number;
  last_tested_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

interface IntegrationLog {
  id: string;
  integration_id: string;
  integration_name?: string;
  integration_type?: string;
  event_type: string;
  status: string;
  response_code: number | null;
  error_message: string | null;
  duration_ms: number;
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

export function Integrations() {
  const { user } = useAuth();
  const isAdmin = hasRole(user, 'platform_admin');

  const [items, setItems] = useState<Integration[]>([]);
  const [logs, setLogs] = useState<IntegrationLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; success: boolean; message: string } | null>(null);

  // Create dialog
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({
    name: '',
    type: 'email' as 'email' | 'webhook',
    provider: 'sendgrid',
    // Email fields
    from_address: '',
    to_addresses: '',
    // Webhook fields
    url: '',
    secret: '',
  });

  // Confirm actions
  const [confirmAction, setConfirmAction] = useState<{ type: 'delete' | 'disable'; id: string; name: string } | null>(null);

  // Logs dialog
  const [logsOpen, setLogsOpen] = useState(false);
  const [logsIntegration, setLogsIntegration] = useState<Integration | null>(null);
  const [integrationLogs, setIntegrationLogs] = useState<IntegrationLog[]>([]);

  const loadData = useCallback(async () => {
    try {
      const [intRes, logRes] = await Promise.all([
        fetch(`${API_BASE_URL}/integrations`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE_URL}/integrations/logs/recent?limit=20`, { headers: getAuthHeaders() }),
      ]);

      if (intRes.ok) {
        const data = await intRes.json();
        setItems(data.integrations || []);
      }
      if (logRes.ok) {
        const data = await logRes.json();
        setLogs(data.logs || []);
      }
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed to load integrations'); } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  async function createIntegration() {
    setCreating(true);
    try {
      const config = form.type === 'email'
        ? { from_address: form.from_address, to_addresses: form.to_addresses.split(',').map(s => s.trim()).filter(Boolean) }
        : { url: form.url, secret: form.secret || undefined };

      const res = await fetch(`${API_BASE_URL}/integrations`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          name: form.name,
          type: form.type,
          provider: form.type === 'email' ? form.provider : 'generic_webhook',
          config,
        }),
      });
      if (res.ok) {
        setCreateOpen(false);
        setForm({ name: '', type: 'email', provider: 'sendgrid', from_address: '', to_addresses: '', url: '', secret: '' });
        loadData();
      }
    } catch { /* ignore */ } finally {
      setCreating(false);
    }
  }

  async function testIntegration(id: string) {
    setTesting(id);
    setTestResult(null);
    try {
      const res = await fetch(`${API_BASE_URL}/integrations/${id}/test`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });
      const data = await res.json();
      setTestResult({ id, success: data.success, message: data.message || data.error || 'Unknown' });
      loadData();
    } catch { setTestResult({ id, success: false, message: 'Request failed' }); } finally {
      setTesting(null);
    }
  }

  async function toggleIntegration(id: string, currentActive: number) {
    try {
      await fetch(`${API_BASE_URL}/integrations/${id}`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({ is_active: !currentActive }),
      });
      setConfirmAction(null);
      loadData();
    } catch { /* ignore */ }
  }

  async function deleteIntegration(id: string) {
    try {
      await fetch(`${API_BASE_URL}/integrations/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      setConfirmAction(null);
      loadData();
    } catch { /* ignore */ }
  }

  async function viewLogs(integration: Integration) {
    setLogsIntegration(integration);
    setLogsOpen(true);
    try {
      const res = await fetch(`${API_BASE_URL}/integrations/${integration.id}/logs?limit=30`, { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setIntegrationLogs(data.logs || []);
      }
    } catch { /* ignore */ }
  }

  if (loading) {
    return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" /></div>;
  }
  if (error) return <ErrorState message={error} onRetry={loadData} />;
  if (!loading && items.length === 0 && logs.length === 0) return <EmptyState icon={Plug} title="No Integrations" description="Connect email (SendGrid, Mailgun) or webhook integrations to receive alerts and forward events." actionLabel="Add Integration" onAction={() => setCreateOpen(true)} />;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Plug className="h-5 w-5" /> Integrations
          </h1>
          <p className="text-muted-foreground mt-1">Email notifications and webhook dispatching</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={loadData}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          {isAdmin && (
            <Dialog open={createOpen} onOpenChange={setCreateOpen}>
              <DialogTrigger asChild>
                <Button><Plus className="mr-2 h-4 w-4" /> Add Integration</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>New Integration</DialogTitle>
                  <DialogDescription>Configure an email or webhook integration.</DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid gap-2">
                    <Label>Name</Label>
                    <Input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Production Alerts" />
                  </div>
                  <div className="grid gap-2">
                    <Label>Type</Label>
                    <Select value={form.type} onValueChange={v => setForm({ ...form, type: v as 'email' | 'webhook' })}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="email">Email</SelectItem>
                        <SelectItem value="webhook">Webhook</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {form.type === 'email' ? (
                    <>
                      <div className="grid gap-2">
                        <Label>Provider</Label>
                        <Select value={form.provider} onValueChange={v => setForm({ ...form, provider: v })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="sendgrid">SendGrid</SelectItem>
                            <SelectItem value="mailgun">Mailgun</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2">
                        <Label>From Address</Label>
                        <Input value={form.from_address} onChange={e => setForm({ ...form, from_address: e.target.value })} placeholder="alerts@yourdomain.com" />
                      </div>
                      <div className="grid gap-2">
                        <Label>To Addresses (comma-separated)</Label>
                        <Textarea value={form.to_addresses} onChange={e => setForm({ ...form, to_addresses: e.target.value })} placeholder="admin@company.com, security@company.com" rows={2} />
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="grid gap-2">
                        <Label>Webhook URL</Label>
                        <Input value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} placeholder="https://hooks.example.com/forgescan" />
                      </div>
                      <div className="grid gap-2">
                        <Label>Signing Secret (optional)</Label>
                        <Input value={form.secret} onChange={e => setForm({ ...form, secret: e.target.value })} placeholder="whsec_..." type="password" />
                        <p className="text-xs text-muted-foreground">Used for HMAC-SHA256 payload signing</p>
                      </div>
                    </>
                  )}
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
                  <Button onClick={createIntegration} disabled={creating || !form.name}>
                    {creating ? 'Creating...' : 'Create'}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </div>

      {/* Confirm Action Banner */}
      {confirmAction && (
        <ConfirmBanner
          title={confirmAction.type === 'delete' ? 'Delete Integration' : 'Disable Integration'}
          description={
            confirmAction.type === 'delete'
              ? `Are you sure you want to delete "${confirmAction.name}"? This cannot be undone.`
              : `Are you sure you want to disable "${confirmAction.name}"? It will stop sending notifications.`
          }
          confirmLabel={confirmAction.type === 'delete' ? 'Delete' : 'Disable'}
          onConfirm={() => {
            if (confirmAction.type === 'delete') deleteIntegration(confirmAction.id);
            else toggleIntegration(confirmAction.id, 1);
          }}
          onCancel={() => setConfirmAction(null)}
          variant={confirmAction.type === 'delete' ? 'destructive' : 'warning'}
        />
      )}

      {/* Integrations List */}
      <Card>
        <CardHeader>
          <CardTitle>Configured Integrations</CardTitle>
          <CardDescription>{items.length} integration{items.length !== 1 ? 's' : ''}</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Tested</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    No integrations configured. Add one to enable alerts.
                  </TableCell>
                </TableRow>
              ) : (
                items.map(i => (
                  <TableRow key={i.id}>
                    <TableCell className="font-medium">{i.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="flex items-center gap-1 w-fit">
                        {i.type === 'email' ? <Mail className="h-3 w-3" /> : <Webhook className="h-3 w-3" />}
                        {i.type}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">{i.provider}</TableCell>
                    <TableCell>
                      <Badge
                        variant={i.is_active ? 'default' : 'secondary'}
                        className="cursor-pointer"
                        onClick={() => {
                          if (!isAdmin) return;
                          if (i.is_active) {
                            setConfirmAction({ type: 'disable', id: i.id, name: i.name });
                          } else {
                            toggleIntegration(i.id, i.is_active);
                          }
                        }}
                      >
                        {i.is_active ? 'Active' : 'Disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{timeAgo(i.last_tested_at)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{timeAgo(i.last_used_at)}</TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="icon" onClick={() => testIntegration(i.id)} disabled={testing === i.id}>
                          {testing === i.id
                            ? <RefreshCw className="h-4 w-4 animate-spin" />
                            : <TestTube2 className="h-4 w-4 text-blue-400" />}
                        </Button>
                        <Button variant="ghost" size="icon" onClick={() => viewLogs(i)}>
                          <Eye className="h-4 w-4" />
                        </Button>
                        {isAdmin && (
                          <Button variant="ghost" size="icon" onClick={() => setConfirmAction({ type: 'delete', id: i.id, name: i.name })}>
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                      </div>
                      {testResult?.id === i.id && (
                        <div className={`mt-1 flex items-center gap-1 text-xs ${testResult.success ? 'text-green-400' : 'text-red-500'}`}>
                          {testResult.success ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                          {testResult.message}
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Recent Logs */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
          <CardDescription>Latest integration dispatch logs</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Integration</TableHead>
                <TableHead>Event</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Response</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead>Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No activity yet.
                  </TableCell>
                </TableRow>
              ) : (
                logs.map(l => (
                  <TableRow key={l.id}>
                    <TableCell className="text-sm">
                      {l.integration_name || l.integration_id.substring(0, 8)}
                      {l.integration_type && <Badge variant="outline" className="ml-1 text-xs">{l.integration_type}</Badge>}
                    </TableCell>
                    <TableCell><Badge variant="outline">{l.event_type}</Badge></TableCell>
                    <TableCell>
                      <Badge variant={l.status === 'success' ? 'default' : 'destructive'}>{l.status}</Badge>
                    </TableCell>
                    <TableCell className="text-sm">
                      {l.response_code || '-'}
                      {l.error_message && <span className="ml-1 text-red-500 text-xs">{l.error_message}</span>}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{l.duration_ms}ms</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{timeAgo(l.created_at)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Integration Logs Dialog */}
      <Dialog open={logsOpen} onOpenChange={setLogsOpen}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Logs: {logsIntegration?.name}</DialogTitle>
            <DialogDescription>Dispatch history for this integration</DialogDescription>
          </DialogHeader>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Event</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Code</TableHead>
                <TableHead>Error</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead>Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {integrationLogs.map(l => (
                <TableRow key={l.id}>
                  <TableCell><Badge variant="outline">{l.event_type}</Badge></TableCell>
                  <TableCell><Badge variant={l.status === 'success' ? 'default' : 'destructive'}>{l.status}</Badge></TableCell>
                  <TableCell>{l.response_code || '-'}</TableCell>
                  <TableCell className="text-xs text-red-500 max-w-xs truncate">{l.error_message || '-'}</TableCell>
                  <TableCell>{l.duration_ms}ms</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{timeAgo(l.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </DialogContent>
      </Dialog>
    </div>
  );
}
