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
import { Textarea } from '@/components/ui/textarea';
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

function CreateScanDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    type: 'network' as ScanType,
    target: '',
    configuration: '',
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      let config = {};
      if (formData.configuration) {
        try {
          config = JSON.parse(formData.configuration);
        } catch {
          alert('Invalid JSON configuration');
          setLoading(false);
          return;
        }
      }

      await scansApi.create({
        name: formData.name,
        type: formData.type,
        target: formData.target,
        configuration: config,
      });
      setOpen(false);
      setFormData({ name: '', type: 'network', target: '', configuration: '' });
      onSuccess();
    } catch (error) {
      console.error('Failed to create scan:', error);
    } finally {
      setLoading(false);
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
      <DialogContent className="max-w-lg">
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
                onValueChange={(value) =>
                  setFormData({ ...formData, type: value as ScanType })
                }
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
                placeholder="192.168.1.0/24 or hostname"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="configuration">Configuration (JSON)</Label>
              <Textarea
                id="configuration"
                value={formData.configuration}
                onChange={(e) =>
                  setFormData({ ...formData, configuration: e.target.value })
                }
                placeholder='{"ports": "1-1000", "intensity": "normal"}'
                rows={4}
              />
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
