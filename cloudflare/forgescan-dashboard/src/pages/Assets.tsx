import { useState, useCallback, useEffect } from 'react';
import { Server, Search, Plus, Trash2, Eye, Shield } from 'lucide-react';
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
import { assetsApi } from '@/lib/api';
import { formatDateTime, capitalize } from '@/lib/utils';
import type { Asset, AssetType, AssetListParams } from '@/types';

const assetTypes: AssetType[] = [
  'host',
  'container',
  'cloud_resource',
  'repository',
  'application',
];

function AssetTypeIcon({ type }: { type: AssetType }) {
  const colors: Record<AssetType, string> = {
    host: 'bg-blue-100 text-blue-600',
    container: 'bg-purple-100 text-purple-600',
    cloud_resource: 'bg-cyan-100 text-cyan-600',
    repository: 'bg-green-100 text-green-600',
    application: 'bg-orange-100 text-orange-600',
  };

  return (
    <div className={`rounded p-1.5 ${colors[type]}`}>
      <Server className="h-4 w-4" />
    </div>
  );
}

function CreateAssetDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    type: 'host' as AssetType,
    identifier: '',
    tags: '',
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await assetsApi.create({
        name: formData.name,
        type: formData.type,
        identifier: formData.identifier,
        tags: formData.tags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
      });
      setOpen(false);
      setFormData({ name: '', type: 'host', identifier: '', tags: '' });
      onSuccess();
    } catch (error) {
      console.error('Failed to create asset:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="mr-2 h-4 w-4" />
          Add Asset
        </Button>
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Add New Asset</DialogTitle>
            <DialogDescription>
              Add a new asset to track vulnerabilities and security findings.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
                placeholder="Production Server 1"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="type">Type</Label>
              <Select
                value={formData.type}
                onValueChange={(value) =>
                  setFormData({ ...formData, type: value as AssetType })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {assetTypes.map((type) => (
                    <SelectItem key={type} value={type}>
                      {capitalize(type)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="identifier">Identifier</Label>
              <Input
                id="identifier"
                value={formData.identifier}
                onChange={(e) =>
                  setFormData({ ...formData, identifier: e.target.value })
                }
                placeholder="192.168.1.100 or hostname"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="tags">Tags (comma-separated)</Label>
              <Input
                id="tags"
                value={formData.tags}
                onChange={(e) =>
                  setFormData({ ...formData, tags: e.target.value })
                }
                placeholder="production, web, critical"
              />
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Creating...' : 'Create Asset'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function AssetDetailDialog({
  asset,
  open,
  onOpenChange,
}: {
  asset: Asset | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (open && asset) {
      setLoading(true);
      assetsApi.get(asset.id)
        .then((data) => setDetail(data as unknown as Record<string, unknown>))
        .catch((err) => console.error('Failed to load asset detail:', err))
        .finally(() => setLoading(false));
    }
  }, [open, asset]);

  if (!asset) return null;

  const findings = (detail as any)?.findings as Array<Record<string, unknown>> || [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <AssetTypeIcon type={asset.type} />
            <DialogTitle>{asset.name}</DialogTitle>
          </div>
          <DialogDescription>
            {asset.identifier} &middot; {capitalize(asset.type)}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="mb-1 text-sm font-medium">IP Addresses</h4>
              <p className="text-sm font-mono text-muted-foreground">
                {(asset.metadata?.ip_addresses as string[])?.join(', ') || 'N/A'}
              </p>
            </div>
            <div>
              <h4 className="mb-1 text-sm font-medium">Operating System</h4>
              <p className="text-sm text-muted-foreground">
                {(asset.metadata as any)?.os || 'Unknown'}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="mb-1 text-sm font-medium">Risk Score</h4>
              <div className="flex items-center gap-2">
                <div className="h-2 w-20 rounded-full bg-muted">
                  <div
                    className="h-2 rounded-full bg-primary"
                    style={{ width: `${asset.risk_score * 10}%` }}
                  />
                </div>
                <span className="text-sm font-medium">{asset.risk_score}/10</span>
              </div>
            </div>
            <div>
              <h4 className="mb-1 text-sm font-medium">Last Seen</h4>
              <p className="text-sm text-muted-foreground">
                {formatDateTime(asset.updated_at)}
              </p>
            </div>
          </div>

          {asset.tags.length > 0 && (
            <div>
              <h4 className="mb-1 text-sm font-medium">Tags</h4>
              <div className="flex flex-wrap gap-1">
                {asset.tags.map((tag) => (
                  <Badge key={tag} variant="secondary">{tag}</Badge>
                ))}
              </div>
            </div>
          )}

          {/* Findings for this asset */}
          <div>
            <h4 className="mb-2 text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Findings ({loading ? '...' : findings.length})
            </h4>
            {loading ? (
              <Skeleton className="h-16 w-full" />
            ) : findings.length === 0 ? (
              <p className="text-sm text-muted-foreground">No findings for this asset</p>
            ) : (
              <div className="space-y-2">
                {findings.map((f: Record<string, unknown>) => (
                  <div key={String(f.id)} className="rounded border p-3 text-sm">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant={String(f.severity) as any}>
                          {capitalize(String(f.severity))}
                        </Badge>
                        <span className="font-medium">{String(f.title)}</span>
                      </div>
                      <Badge variant={f.state === 'open' ? 'destructive' : 'secondary'}>
                        {capitalize(String(f.state))}
                      </Badge>
                    </div>
                    {f.port != null && (
                      <p className="mt-1 text-xs text-muted-foreground font-mono">
                        Port {String(f.port)}/{String(f.protocol)}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
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

export function Assets() {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<AssetType | 'all'>('all');
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const handleViewAsset = (asset: Asset) => {
    setSelectedAsset(asset);
    setDetailOpen(true);
  };

  const fetchAssets = useCallback(
    (page: number, pageSize: number) => {
      const params: AssetListParams = {
        page,
        page_size: pageSize,
        search: search || undefined,
        type: typeFilter === 'all' ? undefined : typeFilter,
      };
      return assetsApi.list(params);
    },
    [search, typeFilter]
  );

  const {
    items: assets,
    total,
    totalPages,
    page,
    loading,
    error,
    setPage,
    refetch,
  } = usePaginatedApi<Asset>(fetchAssets);

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this asset?')) return;
    try {
      await assetsApi.delete(id);
      refetch();
    } catch (error) {
      console.error('Failed to delete asset:', error);
    }
  };

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Assets</h1>
          <p className="text-muted-foreground">
            Manage your infrastructure assets
          </p>
        </div>
        <CreateAssetDialog onSuccess={refetch} />
      </div>

      {/* Filters */}
      <Card className="mb-6">
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search assets..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select
              value={typeFilter}
              onValueChange={(value) =>
                setTypeFilter(value as AssetType | 'all')
              }
            >
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {assetTypes.map((type) => (
                  <SelectItem key={type} value={type}>
                    {capitalize(type)}
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
          title="Failed to load assets"
          message={error}
          onRetry={refetch}
        />
      ) : assets.length === 0 ? (
        <EmptyState
          icon={Server}
          title="No assets found"
          description={
            search || typeFilter !== 'all'
              ? 'Try adjusting your filters'
              : 'Add your first asset to get started'
          }
        />
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">
                {total} asset{total !== 1 ? 's' : ''} found
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Identifier</TableHead>
                    <TableHead>Risk Score</TableHead>
                    <TableHead>Tags</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead className="w-[100px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((asset) => (
                    <TableRow key={asset.id}>
                      <TableCell>
                        <button
                          className="flex items-center gap-3 hover:underline text-left cursor-pointer"
                          onClick={() => handleViewAsset(asset)}
                        >
                          <AssetTypeIcon type={asset.type} />
                          <span className="font-medium text-primary">{asset.name}</span>
                        </button>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{capitalize(asset.type)}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {asset.identifier}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-16 rounded-full bg-muted">
                            <div
                              className="h-2 rounded-full bg-primary"
                              style={{ width: `${asset.risk_score * 10}%` }}
                            />
                          </div>
                          <span className="text-sm">{asset.risk_score}/10</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {asset.tags.slice(0, 3).map((tag) => (
                            <Badge key={tag} variant="secondary" className="text-xs">
                              {tag}
                            </Badge>
                          ))}
                          {asset.tags.length > 3 && (
                            <Badge variant="secondary" className="text-xs">
                              +{asset.tags.length - 3}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDateTime(asset.updated_at)}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button variant="ghost" size="icon" onClick={() => handleViewAsset(asset)}>
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleDelete(asset.id)}
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
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

      <AssetDetailDialog
        asset={selectedAsset}
        open={detailOpen}
        onOpenChange={setDetailOpen}
      />
    </div>
  );
}
