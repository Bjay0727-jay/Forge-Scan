import { useState, useCallback, useMemo } from 'react';
import { Scan as ScanIcon, Search, Plus, Play, XCircle, Trash2, Eye, Globe, Shield, Server, Code, Cloud, FileCheck, ArrowUpDown, ArrowUp, ArrowDown, Activity } from 'lucide-react';
import { ConfirmBanner } from '@/components/ConfirmBanner';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
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
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/ErrorState';
import { EmptyState } from '@/components/EmptyState';
import { Pagination } from '@/components/Pagination';
import { usePaginatedApi } from '@/hooks/useApi';
import { usePollingApi } from '@/hooks/usePollingApi';
import { scansApi } from '@/lib/api';
import { formatDateTime, capitalize, getStatusColor } from '@/lib/utils';
import type { Scan, ScanType, ScanStatus, ScanListParams, ActiveScan, ScanProgress, ScanTask } from '@/types';

const scanTypes: ScanType[] = [
  'network',
  'container',
  'cloud',
  'web',
  'code',
  'compliance',
];

const scanStatuses: ScanStatus[] = [
  'pending',
  'running',
  'completed',
  'failed',
  'cancelled',
];

interface ScanConfig {
  // Network scan options
  ports?: string;
  intensity?: 'light' | 'normal' | 'aggressive';
  // Container scan options
  registry?: string;
  image?: string;
  // Cloud scan options
  provider?: 'aws' | 'azure' | 'gcp';
  regions?: string;
  // Web scan options
  authenticated?: boolean;
  maxDepth?: number;
  // Code scan options
  branch?: string;
  languages?: string;
  // Compliance scan options
  framework?: 'cis' | 'nist' | 'pci-dss' | 'hipaa' | 'soc2';
}

function CreateScanDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    type: 'network' as ScanType,
    target: '',
  });
  const [config, setConfig] = useState<ScanConfig>({
    ports: '1-1000',
    intensity: 'normal',
  });

  const handleTypeChange = (type: ScanType) => {
    setFormData({ ...formData, type });
    // Reset config with defaults for the selected type
    switch (type) {
      case 'network':
        setConfig({ ports: '1-1000', intensity: 'normal' });
        break;
      case 'container':
        setConfig({ registry: '', image: '' });
        break;
      case 'cloud':
        setConfig({ provider: 'aws', regions: 'us-east-1' });
        break;
      case 'web':
        setConfig({ authenticated: false, maxDepth: 3 });
        break;
      case 'code':
        setConfig({ branch: 'main', languages: '' });
        break;
      case 'compliance':
        setConfig({ framework: 'cis' });
        break;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await scansApi.create({
        name: formData.name,
        type: formData.type,
        target: formData.target,
        configuration: config as Record<string, unknown>,
      });
      setOpen(false);
      setFormData({ name: '', type: 'network', target: '' });
      setConfig({ ports: '1-1000', intensity: 'normal' });
      onSuccess();
    } catch (error) {
      console.error('Failed to create scan:', error);
    } finally {
      setLoading(false);
    }
  };

  const renderConfigFields = () => {
    switch (formData.type) {
      case 'network':
        return (
          <>
            <div className="grid gap-2">
              <Label htmlFor="ports">Port Range</Label>
              <Input
                id="ports"
                value={config.ports || ''}
                onChange={(e) => setConfig({ ...config, ports: e.target.value })}
                placeholder="1-1000, 3389, 8080-8090"
              />
              <p className="text-xs text-muted-foreground">
                Specify ports to scan (e.g., 1-1000, 22, 80, 443)
              </p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="intensity">Scan Intensity</Label>
              <Select
                value={config.intensity || 'normal'}
                onValueChange={(value) => setConfig({ ...config, intensity: value as 'light' | 'normal' | 'aggressive' })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="light">Light (Fast, less thorough)</SelectItem>
                  <SelectItem value="normal">Normal (Balanced)</SelectItem>
                  <SelectItem value="aggressive">Aggressive (Slow, thorough)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </>
        );
      case 'container':
        return (
          <>
            <div className="grid gap-2">
              <Label htmlFor="registry">Container Registry</Label>
              <Input
                id="registry"
                value={config.registry || ''}
                onChange={(e) => setConfig({ ...config, registry: e.target.value })}
                placeholder="docker.io, gcr.io, ecr.aws"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="image">Image Name (optional)</Label>
              <Input
                id="image"
                value={config.image || ''}
                onChange={(e) => setConfig({ ...config, image: e.target.value })}
                placeholder="myapp:latest"
              />
              <p className="text-xs text-muted-foreground">
                Leave empty to scan all images
              </p>
            </div>
          </>
        );
      case 'cloud':
        return (
          <>
            <div className="grid gap-2">
              <Label htmlFor="provider">Cloud Provider</Label>
              <Select
                value={config.provider || 'aws'}
                onValueChange={(value) => setConfig({ ...config, provider: value as 'aws' | 'azure' | 'gcp' })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="aws">Amazon Web Services (AWS)</SelectItem>
                  <SelectItem value="azure">Microsoft Azure</SelectItem>
                  <SelectItem value="gcp">Google Cloud Platform</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="regions">Regions</Label>
              <Input
                id="regions"
                value={config.regions || ''}
                onChange={(e) => setConfig({ ...config, regions: e.target.value })}
                placeholder="us-east-1, eu-west-1"
              />
              <p className="text-xs text-muted-foreground">
                Comma-separated list of regions to scan
              </p>
            </div>
          </>
        );
      case 'web':
        return (
          <>
            <div className="grid gap-2">
              <Label htmlFor="maxDepth">Crawl Depth</Label>
              <Select
                value={String(config.maxDepth || 3)}
                onValueChange={(value) => setConfig({ ...config, maxDepth: parseInt(value) })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 - Homepage only</SelectItem>
                  <SelectItem value="2">2 - Shallow</SelectItem>
                  <SelectItem value="3">3 - Normal</SelectItem>
                  <SelectItem value="5">5 - Deep</SelectItem>
                  <SelectItem value="10">10 - Very Deep</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="authenticated"
                checked={config.authenticated || false}
                onChange={(e) => setConfig({ ...config, authenticated: e.target.checked })}
                className="h-4 w-4 rounded border-gray-300"
              />
              <Label htmlFor="authenticated">Authenticated Scan</Label>
            </div>
          </>
        );
      case 'code':
        return (
          <>
            <div className="grid gap-2">
              <Label htmlFor="branch">Branch</Label>
              <Input
                id="branch"
                value={config.branch || ''}
                onChange={(e) => setConfig({ ...config, branch: e.target.value })}
                placeholder="main"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="languages">Languages (optional)</Label>
              <Input
                id="languages"
                value={config.languages || ''}
                onChange={(e) => setConfig({ ...config, languages: e.target.value })}
                placeholder="javascript, python, go"
              />
              <p className="text-xs text-muted-foreground">
                Leave empty to auto-detect
              </p>
            </div>
          </>
        );
      case 'compliance':
        return (
          <div className="grid gap-2">
            <Label htmlFor="framework">Compliance Framework</Label>
            <Select
              value={config.framework || 'cis'}
              onValueChange={(value) => setConfig({ ...config, framework: value as 'cis' | 'nist' | 'pci-dss' | 'hipaa' | 'soc2' })}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="cis">CIS Benchmarks</SelectItem>
                <SelectItem value="nist">NIST 800-53</SelectItem>
                <SelectItem value="pci-dss">PCI-DSS</SelectItem>
                <SelectItem value="hipaa">HIPAA</SelectItem>
                <SelectItem value="soc2">SOC 2</SelectItem>
              </SelectContent>
            </Select>
          </div>
        );
      default:
        return null;
    }
  };

  const getTargetPlaceholder = () => {
    switch (formData.type) {
      case 'network':
        return '192.168.1.0/24 or hostname';
      case 'container':
        return 'docker.io/myorg or container ID';
      case 'cloud':
        return 'AWS Account ID or subscription';
      case 'web':
        return 'https://example.com';
      case 'code':
        return 'https://github.com/org/repo';
      case 'compliance':
        return 'Environment or resource group';
      default:
        return 'Target';
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="mr-2 h-4 w-4" />
          New Scan
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Create New Scan</DialogTitle>
            <DialogDescription>
              Configure and start a new security scan.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="name">Scan Name</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
                placeholder="Weekly Production Scan"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="type">Scan Type</Label>
              <Select
                value={formData.type}
                onValueChange={(value) => handleTypeChange(value as ScanType)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {scanTypes.map((type) => (
                    <SelectItem key={type} value={type}>
                      {capitalize(type)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="target">Target</Label>
              <Input
                id="target"
                value={formData.target}
                onChange={(e) =>
                  setFormData({ ...formData, target: e.target.value })
                }
                placeholder={getTargetPlaceholder()}
                required
              />
            </div>

            {/* Dynamic configuration fields based on scan type */}
            <div className="border-t pt-4 mt-2">
              <h4 className="text-sm font-medium mb-3">Scan Configuration</h4>
              {renderConfigFields()}
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Creating...' : 'Create Scan'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

const scanTypeIcons: Record<string, typeof Globe> = {
  network: Globe,
  container: Server,
  cloud: Cloud,
  web: Globe,
  code: Code,
  compliance: FileCheck,
};

const scanTypeLabels: Record<string, string> = {
  network: 'Network Scan',
  container: 'Container Scan',
  cloud: 'Cloud Security Scan',
  web: 'Web Application Scan',
  code: 'Code Analysis',
  compliance: 'Compliance Audit',
};

const configLabels: Record<string, string> = {
  ports: 'Port Range',
  intensity: 'Scan Intensity',
  registry: 'Container Registry',
  image: 'Image Name',
  provider: 'Cloud Provider',
  regions: 'Target Regions',
  authenticated: 'Authenticated Scan',
  maxDepth: 'Crawl Depth',
  branch: 'Branch',
  languages: 'Languages',
  framework: 'Compliance Framework',
  port_range: 'Port Range',
  scan_type: 'Scan Type',
  target: 'Target',
  max_depth: 'Crawl Depth',
};

const frameworkLabels: Record<string, string> = {
  cis: 'CIS Controls v8',
  nist: 'NIST 800-53 Rev. 5',
  'pci-dss': 'PCI DSS v4.0',
  hipaa: 'HIPAA Security Rule',
  soc2: 'SOC 2 Type II',
};

const intensityLabels: Record<string, { label: string; color: string }> = {
  light: { label: 'Light', color: 'bg-green-500/15 text-green-400' },
  normal: { label: 'Normal', color: 'bg-blue-500/15 text-blue-400' },
  aggressive: { label: 'Aggressive', color: 'bg-red-500/15 text-red-400' },
};

function formatConfigValue(key: string, value: unknown): React.ReactNode {
  if (key === 'intensity' && typeof value === 'string' && intensityLabels[value]) {
    const { label, color } = intensityLabels[value];
    return <Badge className={color}>{label}</Badge>;
  }
  if (key === 'framework' && typeof value === 'string' && frameworkLabels[value]) {
    return <span className="font-medium">{frameworkLabels[value]}</span>;
  }
  if (key === 'provider' && typeof value === 'string') {
    return <span className="font-medium uppercase">{value}</span>;
  }
  if (key === 'authenticated') {
    return <Badge variant={value ? 'default' : 'secondary'}>{value ? 'Yes' : 'No'}</Badge>;
  }
  if (key === 'ports' || key === 'port_range') {
    return <code className="rounded bg-muted px-2 py-0.5 text-xs font-mono">{String(value)}</code>;
  }
  if (typeof value === 'string' || typeof value === 'number') {
    return <span className="text-sm">{String(value)}</span>;
  }
  return <span className="text-sm text-muted-foreground">{JSON.stringify(value)}</span>;
}

function ScanProgressBar({ progress }: { progress: ScanProgress }) {
  return (
    <div className="mt-1.5 space-y-1">
      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
        <span>{progress.completed_tasks + progress.failed_tasks}/{progress.total_tasks} tasks</span>
        <span>{progress.percentage}%</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
        <div
          className="h-full rounded-full bg-blue-500 transition-all duration-500 ease-out"
          style={{ width: `${progress.percentage}%` }}
        />
      </div>
    </div>
  );
}

function TaskStatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    completed: 'bg-green-500',
    running: 'bg-blue-500 animate-pulse',
    failed: 'bg-red-500',
    queued: 'bg-gray-400',
    assigned: 'bg-yellow-500',
    cancelled: 'bg-gray-500',
  };
  return <span className={`inline-block h-2 w-2 rounded-full ${colors[status] || 'bg-gray-400'}`} />;
}

function TaskProgressSection({ scanId, isRunning }: { scanId: string; isRunning: boolean }) {
  const fetchTasks = useCallback(() => scansApi.getTasks(scanId), [scanId]);
  const { data: tasksData } = usePollingApi(fetchTasks, {
    interval: 3000,
    enabled: isRunning,
    immediate: true,
  });

  if (!tasksData) return null;

  const { tasks, summary } = tasksData;

  return (
    <div>
      <h4 className="mb-3 text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
        Task Progress
        {isRunning && <Activity className="h-3 w-3 text-blue-500 animate-pulse" />}
      </h4>
      {/* Overall progress */}
      <div className="rounded-lg border bg-card p-3 mb-3">
        <div className="flex items-center justify-between text-sm mb-2">
          <span className="font-medium">{summary.completed + summary.failed} of {summary.total} tasks complete</span>
          <span className="text-muted-foreground">
            {summary.total > 0 ? Math.round((summary.completed + summary.failed) / summary.total * 100) : 0}%
          </span>
        </div>
        <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
          <div
            className="h-full rounded-full bg-blue-500 transition-all duration-500 ease-out"
            style={{ width: `${summary.total > 0 ? Math.round((summary.completed + summary.failed) / summary.total * 100) : 0}%` }}
          />
        </div>
        <div className="mt-2 flex gap-4 text-xs text-muted-foreground">
          {summary.running > 0 && <span className="flex items-center gap-1"><TaskStatusDot status="running" /> {summary.running} running</span>}
          {summary.queued > 0 && <span className="flex items-center gap-1"><TaskStatusDot status="queued" /> {summary.queued} queued</span>}
          {summary.failed > 0 && <span className="flex items-center gap-1"><TaskStatusDot status="failed" /> {summary.failed} failed</span>}
          {summary.completed > 0 && <span className="flex items-center gap-1"><TaskStatusDot status="completed" /> {summary.completed} done</span>}
        </div>
      </div>
      {/* Individual tasks */}
      {tasks.length > 0 && (
        <div className="rounded-lg border divide-y max-h-48 overflow-y-auto">
          {tasks.map((task: ScanTask) => (
            <div key={task.id} className="flex items-center justify-between px-3 py-2 text-sm">
              <div className="flex items-center gap-2">
                <TaskStatusDot status={task.status} />
                <span className="font-mono text-xs">{task.task_type}</span>
              </div>
              <div className="flex items-center gap-3">
                {task.findings_count > 0 && (
                  <span className="text-xs text-muted-foreground">{task.findings_count} findings</span>
                )}
                <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                  {capitalize(task.status)}
                </Badge>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ScanDetailDialog({
  scan,
  open,
  onOpenChange,
  activeScan,
}: {
  scan: Scan | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  activeScan?: ActiveScan | null;
}) {
  if (!scan) return null;

  const ScanTypeIcon = scanTypeIcons[scan.type] || Shield;
  const scanLabel = scanTypeLabels[scan.type] || capitalize(scan.type);
  const config = scan.configuration || {};
  const configEntries = Object.entries(config).filter(
    ([, v]) => v !== undefined && v !== null && v !== ''
  );

  // Calculate scan duration
  let duration = '';
  if (scan.started_at && scan.completed_at) {
    const start = new Date(scan.started_at).getTime();
    const end = new Date(scan.completed_at).getTime();
    const diffMs = end - start;
    if (diffMs < 1000) duration = '<1s';
    else if (diffMs < 60000) duration = `${Math.round(diffMs / 1000)}s`;
    else if (diffMs < 3600000) duration = `${Math.round(diffMs / 60000)}m ${Math.round((diffMs % 60000) / 1000)}s`;
    else duration = `${Math.floor(diffMs / 3600000)}h ${Math.round((diffMs % 3600000) / 60000)}m`;
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-primary/10 p-2">
              <ScanTypeIcon className="h-5 w-5 text-primary" />
            </div>
            <div className="flex-1">
              <DialogTitle className="text-lg">{scan.name}</DialogTitle>
              <DialogDescription className="flex items-center gap-2 mt-1">
                <Badge className={getStatusColor(scan.status)}>
                  {capitalize(scan.status)}
                </Badge>
                <span>{scanLabel}</span>
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-5">
          {/* Target & Findings Summary */}
          <div className="rounded-lg border bg-card p-4">
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Target</p>
                <p className="mt-1 font-mono text-sm font-medium">{scan.target}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Findings</p>
                <p className="mt-1 text-2xl font-bold text-primary">{scan.findings_count}</p>
              </div>
              {duration && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Duration</p>
                  <p className="mt-1 text-sm font-medium">{duration}</p>
                </div>
              )}
            </div>
          </div>

          {/* Timeline */}
          <div>
            <h4 className="mb-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Timeline</h4>
            <div className="grid grid-cols-3 gap-4">
              <div className="flex items-start gap-2">
                <div className="mt-0.5 h-2 w-2 rounded-full bg-muted-foreground" />
                <div>
                  <p className="text-xs text-muted-foreground">Created</p>
                  <p className="text-sm">{formatDateTime(scan.created_at)}</p>
                </div>
              </div>
              {scan.started_at && (
                <div className="flex items-start gap-2">
                  <div className="mt-0.5 h-2 w-2 rounded-full bg-blue-500" />
                  <div>
                    <p className="text-xs text-muted-foreground">Started</p>
                    <p className="text-sm">{formatDateTime(scan.started_at)}</p>
                  </div>
                </div>
              )}
              {scan.completed_at && (
                <div className="flex items-start gap-2">
                  <div className={`mt-0.5 h-2 w-2 rounded-full ${scan.status === 'completed' ? 'bg-green-500' : 'bg-red-500'}`} />
                  <div>
                    <p className="text-xs text-muted-foreground">{scan.status === 'failed' ? 'Failed' : 'Completed'}</p>
                    <p className="text-sm">{formatDateTime(scan.completed_at)}</p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Task Progress - shown for running/pending scans */}
          {(scan.status === 'running' || scan.status === 'pending') && (
            <TaskProgressSection scanId={scan.id} isRunning={scan.status === 'running'} />
          )}

          {/* Live findings from active scan data */}
          {activeScan && scan.status === 'running' && activeScan.findings_count > scan.findings_count && (
            <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3">
              <div className="flex items-center gap-2 text-sm">
                <Activity className="h-4 w-4 text-blue-500 animate-pulse" />
                <span className="text-muted-foreground">Live findings count:</span>
                <span className="font-bold text-blue-400">{activeScan.findings_count}</span>
              </div>
            </div>
          )}

          {/* Configuration */}
          {configEntries.length > 0 && (
            <div>
              <h4 className="mb-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Scan Configuration</h4>
              <div className="rounded-lg border divide-y">
                {configEntries.map(([key, value]) => (
                  <div key={key} className="flex items-center justify-between px-4 py-2.5">
                    <span className="text-sm text-muted-foreground">
                      {configLabels[key] || capitalize(key.replace(/_/g, ' '))}
                    </span>
                    <div>{formatConfigValue(key, value)}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-4">
      {[...Array(5)].map((_, i) => (
        <Skeleton key={i} className="h-16 w-full" />
      ))}
    </div>
  );
}

export function Scans() {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<ScanType | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<ScanStatus | 'all'>('all');
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [deleteConfirm, setDeleteConfirm] = useState<{ id: string; name: string } | null>(null);
  const [cancelConfirm, setCancelConfirm] = useState<{ id: string; name: string } | null>(null);

  const handleSort = (column: string) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(column);
      setSortOrder('desc');
    }
  };

  const SortIcon = ({ column }: { column: string }) => {
    if (sortBy !== column) return <ArrowUpDown className="ml-1 h-3 w-3 opacity-50" />;
    return sortOrder === 'asc'
      ? <ArrowUp className="ml-1 h-3 w-3 text-primary" />
      : <ArrowDown className="ml-1 h-3 w-3 text-primary" />;
  };

  const fetchScans = useCallback(
    (page: number, pageSize: number) => {
      const params: ScanListParams = {
        page,
        page_size: pageSize,
        search: search || undefined,
        type: typeFilter === 'all' ? undefined : typeFilter,
        status: statusFilter === 'all' ? undefined : statusFilter,
        sort_by: sortBy,
        sort_order: sortOrder,
      };
      return scansApi.list(params);
    },
    [search, typeFilter, statusFilter, sortBy, sortOrder]
  );

  const {
    items: scans,
    total,
    totalPages,
    page,
    loading,
    error,
    setPage,
    refetch,
  } = usePaginatedApi<Scan>(fetchScans);

  // Check if any visible scans are running/pending
  const hasRunningScans = useMemo(
    () => scans.some((s) => s.status === 'running' || s.status === 'pending'),
    [scans]
  );

  // Poll active scans for progress data
  const fetchActiveScans = useCallback(() => scansApi.getActive(), []);
  const { data: activeScansData } = usePollingApi(fetchActiveScans, {
    interval: 5000,
    enabled: hasRunningScans,
    immediate: hasRunningScans,
    onDataChange: () => refetch(),
  });

  // Map active scan data by ID for quick lookup
  const activeScanMap = useMemo(() => {
    const map = new Map<string, ActiveScan>();
    activeScansData?.items?.forEach((s) => map.set(s.id, s));
    return map;
  }, [activeScansData]);

  const handleStartScan = async (id: string) => {
    try {
      await scansApi.start(id);
      refetch();
    } catch (error) {
      console.error('Failed to start scan:', error);
    }
  };

  const handleCancelScan = async (id: string) => {
    try {
      await scansApi.cancel(id);
      setCancelConfirm(null);
      refetch();
    } catch (error) {
      console.error('Failed to cancel scan:', error);
    }
  };

  const handleDeleteScan = async (id: string) => {
    try {
      await scansApi.delete(id);
      setDeleteConfirm(null);
      refetch();
    } catch (error) {
      console.error('Failed to delete scan:', error);
    }
  };

  const handleViewScan = (scan: Scan) => {
    setSelectedScan(scan);
    setDetailOpen(true);
  };

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Scans</h1>
          <p className="text-muted-foreground">
            Manage and monitor security scans
          </p>
        </div>
        <CreateScanDialog onSuccess={refetch} />
      </div>

      {/* Filters */}
      <Card className="mb-6">
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search scans..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select
              value={typeFilter}
              onValueChange={(value) =>
                setTypeFilter(value as ScanType | 'all')
              }
            >
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {scanTypes.map((type) => (
                  <SelectItem key={type} value={type}>
                    {capitalize(type)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={statusFilter}
              onValueChange={(value) =>
                setStatusFilter(value as ScanStatus | 'all')
              }
            >
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                {scanStatuses.map((status) => (
                  <SelectItem key={status} value={status}>
                    {capitalize(status)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {loading ? (
        <LoadingSkeleton />
      ) : error ? (
        <ErrorState
          title="Failed to load scans"
          message={error}
          onRetry={refetch}
        />
      ) : scans.length === 0 ? (
        <EmptyState
          icon={ScanIcon}
          title="No scans found"
          description={
            search || typeFilter !== 'all' || statusFilter !== 'all'
              ? 'Try adjusting your filters'
              : 'Create your first scan to get started'
          }
        />
      ) : (
        <>
          {deleteConfirm && (
            <ConfirmBanner
              title="Delete Scan"
              description={`Are you sure you want to delete "${deleteConfirm.name}"? This cannot be undone.`}
              confirmLabel="Delete"
              onConfirm={() => handleDeleteScan(deleteConfirm.id)}
              onCancel={() => setDeleteConfirm(null)}
              variant="destructive"
            />
          )}

          {cancelConfirm && (
            <ConfirmBanner
              title="Cancel Scan"
              description={`Are you sure you want to cancel "${cancelConfirm.name}"?`}
              confirmLabel="Cancel Scan"
              onConfirm={() => handleCancelScan(cancelConfirm.id)}
              onCancel={() => setCancelConfirm(null)}
              variant="warning"
            />
          )}

          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">
                {total} scan{total !== 1 ? 's' : ''} found
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="cursor-pointer select-none" onClick={() => handleSort('name')}>
                      <span className="flex items-center">Name <SortIcon column="name" /></span>
                    </TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => handleSort('scan_type')}>
                      <span className="flex items-center">Type <SortIcon column="scan_type" /></span>
                    </TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => handleSort('status')}>
                      <span className="flex items-center">Status <SortIcon column="status" /></span>
                    </TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => handleSort('findings_count')}>
                      <span className="flex items-center">Findings <SortIcon column="findings_count" /></span>
                    </TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => handleSort('created_at')}>
                      <span className="flex items-center">Created <SortIcon column="created_at" /></span>
                    </TableHead>
                    <TableHead className="w-[150px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scans.map((scan) => {
                    const activeScan = activeScanMap.get(scan.id);
                    return (
                    <TableRow key={scan.id}>
                      <TableCell className="font-medium">{scan.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{capitalize(scan.type)}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {scan.target}
                      </TableCell>
                      <TableCell>
                        <div>
                          <div className="flex items-center gap-1.5">
                            {scan.status === 'running' && (
                              <span className="relative flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500" />
                              </span>
                            )}
                            <Badge className={getStatusColor(scan.status)}>
                              {capitalize(scan.status)}
                            </Badge>
                          </div>
                          {activeScan?.progress && scan.status === 'running' && (
                            <ScanProgressBar progress={activeScan.progress} />
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {activeScan && scan.status === 'running' ? (
                          <span className="flex items-center gap-1">
                            <span className="font-medium text-blue-400">{activeScan.findings_count}</span>
                            <Activity className="h-3 w-3 text-blue-500 animate-pulse" />
                          </span>
                        ) : (
                          scan.findings_count
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDateTime(scan.created_at)}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleViewScan(scan)}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          {scan.status === 'pending' && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleStartScan(scan.id)}
                            >
                              <Play className="h-4 w-4 text-green-400" />
                            </Button>
                          )}
                          {scan.status === 'running' && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => setCancelConfirm({ id: scan.id, name: scan.name })}
                            >
                              <XCircle className="h-4 w-4 text-orange-400" />
                            </Button>
                          )}
                          {(scan.status === 'completed' ||
                            scan.status === 'failed' ||
                            scan.status === 'cancelled') && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => setDeleteConfirm({ id: scan.id, name: scan.name })}
                            >
                              <Trash2 className="h-4 w-4 text-destructive" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {totalPages > 1 && (
            <div className="mt-6">
              <Pagination
                page={page}
                totalPages={totalPages}
                onPageChange={setPage}
              />
            </div>
          )}
        </>
      )}

      <ScanDetailDialog
        scan={selectedScan}
        open={detailOpen}
        onOpenChange={setDetailOpen}
        activeScan={selectedScan ? activeScanMap.get(selectedScan.id) : null}
      />
    </div>
  );
}
