import { useState, useEffect, useCallback } from 'react';
import {
  Cpu,
  RefreshCw,
  Plus,
  Trash2,
  Copy,
  Check,
  Wifi,
  WifiOff,
  Activity,
} from 'lucide-react';
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

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

interface Scanner {
  id: string;
  scanner_id: string;
  hostname: string;
  version: string | null;
  status: string;
  capabilities: string;
  api_key_prefix: string;
  last_heartbeat_at: string | null;
  tasks_completed: number;
  tasks_failed: number;
  completed_tasks: number;
  running_tasks: number;
  assigned_tasks: number;
  created_at: string;
  updated_at: string;
}

interface ScanTask {
  id: string;
  scan_id: string;
  scanner_id: string | null;
  task_type: string;
  status: string;
  priority: number;
  findings_count: number;
  assets_discovered: number;
  error_message: string | null;
  assigned_at: string | null;
  started_at: string | null;
  completed_at: string | null;
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

const statusColor = (status: string) => {
  switch (status) {
    case 'active': return 'default' as const;
    case 'registered': return 'secondary' as const;
    case 'offline': return 'secondary' as const;
    case 'disabled': return 'destructive' as const;
    default: return 'secondary' as const;
  }
};

const taskStatusColor = (status: string) => {
  switch (status) {
    case 'completed': return 'default' as const;
    case 'running': return 'default' as const;
    case 'assigned': return 'secondary' as const;
    case 'queued': return 'secondary' as const;
    case 'failed': return 'destructive' as const;
    case 'cancelled': return 'destructive' as const;
    default: return 'secondary' as const;
  }
};

export function Scanners() {
  const { user } = useAuth();
  const isAdmin = hasRole(user, 'platform_admin');

  const [scanners, setScanners] = useState<Scanner[]>([]);
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [taskFilter, setTaskFilter] = useState('all');
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Register dialog state
  const [registerOpen, setRegisterOpen] = useState(false);
  const [registerForm, setRegisterForm] = useState({
    scanner_id: '',
    hostname: '',
    version: '',
    capabilities: [] as string[],
  });
  const [registering, setRegistering] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const [scannersRes, tasksRes] = await Promise.all([
        fetch(`${API_BASE_URL}/scanner`, { headers: getAuthHeaders() }),
        fetch(`${API_BASE_URL}/scanner/tasks?limit=50${taskFilter !== 'all' ? `&status=${taskFilter}` : ''}`, { headers: getAuthHeaders() }),
      ]);

      if (scannersRes.ok) {
        const data = await scannersRes.json();
        setScanners(data.scanners || []);
      }
      if (tasksRes.ok) {
        const data = await tasksRes.json();
        setTasks(data.tasks || []);
      }
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, [taskFilter]);

  useEffect(() => { loadData(); }, [loadData]);

  // Auto-refresh every 15 seconds
  useEffect(() => {
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  async function registerScanner() {
    setRegistering(true);
    try {
      const res = await fetch(`${API_BASE_URL}/scanner/register`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(registerForm),
      });
      if (res.ok) {
        const data = await res.json();
        setNewKey(data.api_key);
        setRegisterOpen(false);
        setRegisterForm({ scanner_id: '', hostname: '', version: '', capabilities: [] });
        loadData();
      }
    } catch { /* ignore */ } finally {
      setRegistering(false);
    }
  }

  async function deactivateScanner(id: string) {
    try {
      await fetch(`${API_BASE_URL}/scanner/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      loadData();
    } catch { /* ignore */ }
  }

  function copyKey() {
    if (newKey) {
      navigator.clipboard.writeText(newKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  const capabilities = ['network', 'container', 'web', 'code', 'cloud', 'compliance'];

  if (loading) {
    return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" /></div>;
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Cpu className="h-8 w-8" /> Scanner Management
          </h1>
          <p className="text-muted-foreground mt-1">Register and monitor scanner engines</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={loadData}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          {isAdmin && (
            <Dialog open={registerOpen} onOpenChange={setRegisterOpen}>
              <DialogTrigger asChild>
                <Button><Plus className="mr-2 h-4 w-4" /> Register Scanner</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Register New Scanner</DialogTitle>
                  <DialogDescription>
                    Register a scanner engine to process scan tasks.
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid gap-2">
                    <Label>Scanner ID</Label>
                    <Input
                      value={registerForm.scanner_id}
                      onChange={(e) => setRegisterForm({ ...registerForm, scanner_id: e.target.value })}
                      placeholder="scanner-prod-01"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label>Hostname</Label>
                    <Input
                      value={registerForm.hostname}
                      onChange={(e) => setRegisterForm({ ...registerForm, hostname: e.target.value })}
                      placeholder="scanner.example.com"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label>Version (optional)</Label>
                    <Input
                      value={registerForm.version}
                      onChange={(e) => setRegisterForm({ ...registerForm, version: e.target.value })}
                      placeholder="1.0.0"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label>Capabilities</Label>
                    <div className="flex flex-wrap gap-2">
                      {capabilities.map(cap => (
                        <Badge
                          key={cap}
                          variant={registerForm.capabilities.includes(cap) ? 'default' : 'outline'}
                          className="cursor-pointer"
                          onClick={() => {
                            const caps = registerForm.capabilities.includes(cap)
                              ? registerForm.capabilities.filter(c => c !== cap)
                              : [...registerForm.capabilities, cap];
                            setRegisterForm({ ...registerForm, capabilities: caps });
                          }}
                        >
                          {cap}
                        </Badge>
                      ))}
                    </div>
                    <p className="text-xs text-muted-foreground">Click to toggle scan types this scanner supports</p>
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setRegisterOpen(false)}>Cancel</Button>
                  <Button onClick={registerScanner} disabled={registering || !registerForm.scanner_id || !registerForm.hostname}>
                    {registering ? 'Registering...' : 'Register'}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </div>

      {/* New Key Display */}
      {newKey && (
        <Card className="border-green-500/20 bg-green-500/5">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-green-600">Scanner API Key (save this - shown only once)</p>
                <code className="mt-1 block rounded bg-muted px-3 py-2 font-mono text-sm">{newKey}</code>
              </div>
              <Button variant="outline" size="sm" onClick={copyKey}>
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
            <Button variant="ghost" size="sm" className="mt-2" onClick={() => setNewKey(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Scanners Table */}
      <Card>
        <CardHeader>
          <CardTitle>Registered Scanners</CardTitle>
          <CardDescription>{scanners.length} scanner{scanners.length !== 1 ? 's' : ''} registered</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Scanner ID</TableHead>
                <TableHead>Hostname</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Capabilities</TableHead>
                <TableHead>Last Heartbeat</TableHead>
                <TableHead>Tasks</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scanners.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-muted-foreground py-8">
                    No scanners registered. Register one to start processing scans.
                  </TableCell>
                </TableRow>
              ) : (
                scanners.map(s => {
                  const caps = (() => { try { return JSON.parse(s.capabilities); } catch { return []; } })();
                  return (
                    <TableRow key={s.id}>
                      <TableCell className="font-mono font-medium">{s.scanner_id}</TableCell>
                      <TableCell className="text-sm">{s.hostname}</TableCell>
                      <TableCell>
                        <Badge variant={statusColor(s.status)} className="flex items-center gap-1 w-fit">
                          {s.status === 'active' ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
                          {s.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{s.version || '-'}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {caps.length > 0 ? caps.map((c: string) => (
                            <Badge key={c} variant="outline" className="text-xs">{c}</Badge>
                          )) : <span className="text-muted-foreground text-xs">All</span>}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{timeAgo(s.last_heartbeat_at)}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2 text-sm">
                          <span className="text-green-600">{s.tasks_completed} done</span>
                          {s.running_tasks > 0 && <Badge variant="default" className="text-xs">{s.running_tasks} running</Badge>}
                          {s.tasks_failed > 0 && <span className="text-red-500">{s.tasks_failed} failed</span>}
                        </div>
                      </TableCell>
                      <TableCell>
                        {isAdmin && s.status !== 'disabled' && (
                          <Button variant="ghost" size="icon" onClick={() => deactivateScanner(s.id)}>
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Task Queue */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" /> Task Queue
              </CardTitle>
              <CardDescription>Scan tasks dispatched to scanners</CardDescription>
            </div>
            <Select value={taskFilter} onValueChange={setTaskFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tasks</SelectItem>
                <SelectItem value="queued">Queued</SelectItem>
                <SelectItem value="assigned">Assigned</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Task ID</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Scanner</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Assets</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tasks.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    No tasks found.
                  </TableCell>
                </TableRow>
              ) : (
                tasks.map(t => (
                  <TableRow key={t.id}>
                    <TableCell className="font-mono text-xs">{t.id.substring(0, 8)}...</TableCell>
                    <TableCell>
                      <Badge variant="outline">{t.task_type}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={taskStatusColor(t.status)}>{t.status}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">{t.scanner_id || '-'}</TableCell>
                    <TableCell>{t.findings_count}</TableCell>
                    <TableCell>{t.assets_discovered}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{timeAgo(t.created_at)}</TableCell>
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
