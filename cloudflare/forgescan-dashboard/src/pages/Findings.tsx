import { useState, useCallback } from 'react';
import { AlertTriangle, Search, CheckCircle, Eye, ArrowUpDown, ArrowUp, ArrowDown, XCircle } from 'lucide-react';
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
} from '@/components/ui/dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/ErrorState';
import { EmptyState } from '@/components/EmptyState';
import { Pagination } from '@/components/Pagination';
import { usePaginatedApi } from '@/hooks/useApi';
import { findingsApi } from '@/lib/api';
import { formatDateTime, capitalize, truncate } from '@/lib/utils';
import type { Finding, Severity, FindingState, FindingListParams } from '@/types';

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const states: FindingState[] = ['open', 'acknowledged', 'resolved', 'false_positive'];

function FindingDetailDialog({
  finding,
  open,
  onOpenChange,
  onUpdate,
}: {
  finding: Finding | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUpdate: () => void;
}) {
  const [updating, setUpdating] = useState(false);

  if (!finding) return null;

  const handleStateChange = async (newState: FindingState) => {
    setUpdating(true);
    try {
      await findingsApi.update(finding.id, { state: newState });
      onUpdate();
    } catch (error) {
      console.error('Failed to update finding:', error);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <Badge variant={finding.severity as Severity}>
              {capitalize(finding.severity)}
            </Badge>
            <DialogTitle>{finding.title}</DialogTitle>
          </div>
          <DialogDescription>
            {finding.cve_id && (
              <a
                href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline"
              >
                {finding.cve_id}
              </a>
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <h4 className="mb-1 text-sm font-medium">Description</h4>
            <p className="text-sm text-muted-foreground">{finding.description}</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="mb-1 text-sm font-medium">Affected Component</h4>
              <p className="text-sm font-mono">{finding.affected_component}</p>
            </div>
            {finding.cvss_score !== undefined && (
              <div>
                <h4 className="mb-1 text-sm font-medium">CVSS Score</h4>
                <p className="text-sm">{finding.cvss_score}</p>
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="mb-1 text-sm font-medium">First Seen</h4>
              <p className="text-sm text-muted-foreground">
                {formatDateTime(finding.first_seen)}
              </p>
            </div>
            <div>
              <h4 className="mb-1 text-sm font-medium">Last Seen</h4>
              <p className="text-sm text-muted-foreground">
                {formatDateTime(finding.last_seen)}
              </p>
            </div>
          </div>

          {finding.remediation && (
            <div>
              <h4 className="mb-1 text-sm font-medium">Remediation</h4>
              <p className="text-sm text-muted-foreground">{finding.remediation}</p>
            </div>
          )}

          {finding.references.length > 0 && (
            <div>
              <h4 className="mb-1 text-sm font-medium">References</h4>
              <ul className="list-inside list-disc text-sm text-muted-foreground">
                {finding.references.map((ref, i) => (
                  <li key={i}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline"
                    >
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div>
            <h4 className="mb-2 text-sm font-medium">Status</h4>
            <div className="flex gap-2">
              {states.map((state) => (
                <Button
                  key={state}
                  variant={finding.state === state ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => handleStateChange(state)}
                  disabled={updating || finding.state === state}
                >
                  {capitalize(state)}
                </Button>
              ))}
            </div>
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

export function Findings() {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [stateFilter, setStateFilter] = useState<FindingState | 'all'>('all');
  const [vendorFilter, setVendorFilter] = useState('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [sortBy, setSortBy] = useState('severity');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

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

  const hasActiveFilters = severityFilter !== 'all' || stateFilter !== 'all' || vendorFilter !== 'all' || search !== '';

  const clearFilters = () => {
    setSearch('');
    setSeverityFilter('all');
    setStateFilter('all');
    setVendorFilter('all');
  };

  const fetchFindings = useCallback(
    (page: number, pageSize: number) => {
      const params: FindingListParams = {
        page,
        page_size: pageSize,
        search: search || undefined,
        severity: severityFilter === 'all' ? undefined : severityFilter,
        state: stateFilter === 'all' ? undefined : stateFilter,
        vendor: vendorFilter === 'all' ? undefined : vendorFilter,
        sort_by: sortBy,
        sort_order: sortOrder,
      };
      return findingsApi.list(params);
    },
    [search, severityFilter, stateFilter, vendorFilter, sortBy, sortOrder]
  );

  const {
    items: findings,
    total,
    totalPages,
    page,
    loading,
    error,
    setPage,
    refetch,
  } = usePaginatedApi<Finding>(fetchFindings);

  const handleViewFinding = (finding: Finding) => {
    setSelectedFinding(finding);
    setDetailOpen(true);
  };

  const handleQuickResolve = async (finding: Finding) => {
    try {
      await findingsApi.update(finding.id, { state: 'resolved' });
      refetch();
    } catch (error) {
      console.error('Failed to resolve finding:', error);
    }
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-3xl font-bold">Findings</h1>
        <p className="text-muted-foreground">
          View and manage security findings
        </p>
      </div>

      {/* Filters */}
      <Card className="mb-6">
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search findings..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select
              value={severityFilter}
              onValueChange={(value) =>
                setSeverityFilter(value as Severity | 'all')
              }
            >
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                {severities.map((severity) => (
                  <SelectItem key={severity} value={severity}>
                    {capitalize(severity)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={stateFilter}
              onValueChange={(value) =>
                setStateFilter(value as FindingState | 'all')
              }
            >
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="State" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All States</SelectItem>
                {states.map((state) => (
                  <SelectItem key={state} value={state}>
                    {capitalize(state)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={vendorFilter}
              onValueChange={setVendorFilter}
            >
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Vendor" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Vendors</SelectItem>
                <SelectItem value="nessus">Nessus</SelectItem>
                <SelectItem value="qualys">Qualys</SelectItem>
                <SelectItem value="rapid7">Rapid7</SelectItem>
                <SelectItem value="crowdstrike">CrowdStrike</SelectItem>
                <SelectItem value="forgescan">ForgeScan</SelectItem>
              </SelectContent>
            </Select>
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters} className="gap-1.5 text-muted-foreground hover:text-foreground">
                <XCircle className="h-4 w-4" /> Clear Filters
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {loading ? (
        <LoadingSkeleton />
      ) : error ? (
        <ErrorState
          title="Failed to load findings"
          message={error}
          onRetry={refetch}
        />
      ) : findings.length === 0 ? (
        <EmptyState
          icon={AlertTriangle}
          title="No findings found"
          description={
            search || severityFilter !== 'all' || stateFilter !== 'all'
              ? 'Try adjusting your filters'
              : 'No security findings have been detected yet'
          }
        />
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">
                {total} finding{total !== 1 ? 's' : ''} found
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="cursor-pointer select-none" onClick={() => handleSort('severity')}>
                      <span className="flex items-center">Severity <SortIcon column="severity" /></span>
                    </TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => handleSort('title')}>
                      <span className="flex items-center">Title <SortIcon column="title" /></span>
                    </TableHead>
                    <TableHead>CVE</TableHead>
                    <TableHead>Component</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => handleSort('last_seen')}>
                      <span className="flex items-center">Last Seen <SortIcon column="last_seen" /></span>
                    </TableHead>
                    <TableHead className="w-[120px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.map((finding) => (
                    <TableRow key={finding.id}>
                      <TableCell>
                        <Badge variant={finding.severity as Severity}>
                          {capitalize(finding.severity)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="font-medium">
                          {truncate(finding.title, 50)}
                        </span>
                      </TableCell>
                      <TableCell>
                        {finding.cve_id ? (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono text-sm text-primary hover:underline"
                          >
                            {finding.cve_id}
                          </a>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {truncate(finding.affected_component, 30)}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            finding.state === 'open'
                              ? 'destructive'
                              : finding.state === 'resolved'
                                ? 'default'
                                : 'secondary'
                          }
                        >
                          {capitalize(finding.state)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDateTime(finding.last_seen)}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleViewFinding(finding)}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          {finding.state === 'open' && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleQuickResolve(finding)}
                            >
                              <CheckCircle className="h-4 w-4 text-green-400" />
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

      <FindingDetailDialog
        finding={selectedFinding}
        open={detailOpen}
        onOpenChange={setDetailOpen}
        onUpdate={refetch}
      />
    </div>
  );
}
