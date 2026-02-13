import { useState, useCallback } from 'react';
import { Scan as ScanIcon, Search, Plus, Play, XCircle, Trash2, Eye } from 'lucide-react';
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
import { scansApi } from '@/lib/api';
import { formatDateTime, capitalize, getStatusColor } from '@/lib/utils';
import type { Scan, ScanType, ScanStatus, ScanListParams } from '@/types';

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

function ScanDetailDialog({
  scan,
  open,
  onOpenChange,
}: {
  scan: Scan | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  if (!scan) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <Badge className={getStatusColor(scan.status)}>
              {capitalize(scan.status)}
            </Badge>
            <DialogTitle>{scan.name}</DialogTitle>
          </div>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="mb-1 text-sm font-medium">Type</h4>
              <p className="text-sm">{capitalize(scan.type)}</p>
            </div>
            <div>
              <h4 className="mb-1 text-sm font-medium">Target</h4>
              <p className="font-mono text-sm">{scan.target}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="mb-1 text-sm font-medium">Created</h4>
              <p className="text-sm text-muted-foreground">
                {formatDateTime(scan.created_at)}
              </p>
            </div>
            {scan.started_at && (
              <div>
                <h4 className="mb-1 text-sm font-medium">Started</h4>
                <p className="text-sm text-muted-foreground">
                  {formatDateTime(scan.started_at)}
                </p>
              </div>
            )}
          </div>

          {scan.completed_at && (
            <div>
              <h4 className="mb-1 text-sm font-medium">Completed</h4>
              <p className="text-sm text-muted-foreground">
                {formatDateTime(scan.completed_at)}
              </p>
            </div>
          )}

          <div>
            <h4 className="mb-1 text-sm font-medium">Findings</h4>
            <p className="text-2xl font-bold">{scan.findings_count}</p>
          </div>

          {Object.keys(scan.configuration).length > 0 && (
            <div>
              <h4 className="mb-1 text-sm font-medium">Configuration</h4>
              <pre className="rounded-lg bg-muted p-4 text-xs overflow-auto">
                {JSON.stringify(scan.configuration, null, 2)}
              </pre>
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

  const fetchScans = useCallback(
    (page: number, pageSize: number) => {
      const params: ScanListParams = {
        page,
        page_size: pageSize,
        search: search || undefined,
        type: typeFilter === 'all' ? undefined : typeFilter,
        status: statusFilter === 'all' ? undefined : statusFilter,
      };
      return scansApi.list(params);
    },
    [search, typeFilter, statusFilter]
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
      refetch();
    } catch (error) {
      console.error('Failed to cancel scan:', error);
    }
  };

  const handleDeleteScan = async (id: string) => {
    if (!confirm('Are you sure you want to delete this scan?')) return;
    try {
      await scansApi.delete(id);
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
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Findings</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="w-[150px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scans.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell className="font-medium">{scan.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{capitalize(scan.type)}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {scan.target}
                      </TableCell>
                      <TableCell>
                        <Badge className={getStatusColor(scan.status)}>
                          {capitalize(scan.status)}
                        </Badge>
                      </TableCell>
                      <TableCell>{scan.findings_count}</TableCell>
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
                              <Play className="h-4 w-4 text-green-600" />
                            </Button>
                          )}
                          {scan.status === 'running' && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleCancelScan(scan.id)}
                            >
                              <XCircle className="h-4 w-4 text-orange-600" />
                            </Button>
                          )}
                          {(scan.status === 'completed' ||
                            scan.status === 'failed' ||
                            scan.status === 'cancelled') && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleDeleteScan(scan.id)}
                            >
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
      />
    </div>
  );
}
