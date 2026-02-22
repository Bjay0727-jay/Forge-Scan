import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Crosshair,
  Play,
  Square,
  Trash2,
  Plus,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Shield,
  Bug,
  Loader2,
  AlertTriangle,
  Globe,
  Cloud,
  Network,
  KeyRound,
  Zap,
  Target,
  Clock,
  CheckCircle,
  XCircle,
  Radio,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { redopsApi } from '@/lib/api';
import { usePollingApi } from '@/hooks/usePollingApi';
import { formatRelativeTime, getSeverityColor } from '@/lib/utils';
import type {
  RedOpsCampaign,
  RedOpsOverview,
  RedOpsAgent,
  CampaignType,
  ExploitationLevel,
  AgentCategory,
} from '@/types';

// ─── Helpers ────────────────────────────────────────────────────────────────

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  web: <Globe className="h-4 w-4" />,
  api: <Zap className="h-4 w-4" />,
  cloud: <Cloud className="h-4 w-4" />,
  network: <Network className="h-4 w-4" />,
  identity: <KeyRound className="h-4 w-4" />,
};

const CATEGORY_COLORS: Record<string, string> = {
  web: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  api: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  cloud: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  network: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  identity: 'bg-pink-500/15 text-pink-400 border-pink-500/30',
};

function CampaignStatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    created: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
    queued: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    reconnaissance: 'bg-blue-500/15 text-blue-400 border-blue-500/30 animate-pulse',
    scanning: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30 animate-pulse',
    exploitation: 'bg-red-500/15 text-red-400 border-red-500/30 animate-pulse',
    reporting: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
    completed: 'bg-green-500/15 text-green-400 border-green-500/30',
    failed: 'bg-red-500/15 text-red-400 border-red-500/30',
    cancelled: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
  };

  return (
    <Badge className={`text-xs border ${styles[status] || ''}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </Badge>
  );
}

function AgentStatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    queued: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
    initializing: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    reconnaissance: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
    testing: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30 animate-pulse',
    exploiting: 'bg-red-500/15 text-red-400 border-red-500/30 animate-pulse',
    reporting: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
    completed: 'bg-green-500/15 text-green-400 border-green-500/30',
    failed: 'bg-red-500/15 text-red-400 border-red-500/30',
    stopped: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
  };

  return (
    <Badge className={`text-xs border ${styles[status] || ''}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </Badge>
  );
}

function ExploitationBadge({ level }: { level: string }) {
  const styles: Record<string, string> = {
    passive: 'bg-green-500/15 text-green-400 border-green-500/30',
    safe: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
    moderate: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    aggressive: 'bg-red-500/15 text-red-400 border-red-500/30',
  };

  return (
    <Badge className={`text-xs border ${styles[level] || ''}`}>
      {level.charAt(0).toUpperCase() + level.slice(1)}
    </Badge>
  );
}

// ─── Overview Stats ─────────────────────────────────────────────────────────

function OverviewStats({ overview }: { overview: RedOpsOverview | null }) {
  if (!overview) return null;

  const stats = [
    { label: 'Total Campaigns', value: overview.campaigns.total, icon: <Target className="h-5 w-5" /> },
    { label: 'Active', value: overview.campaigns.active, icon: <Loader2 className="h-5 w-5 animate-spin" />, highlight: overview.campaigns.active > 0 },
    { label: 'Findings', value: overview.findings.total, icon: <Bug className="h-5 w-5" /> },
    { label: 'Exploitable', value: overview.findings.exploitable, icon: <AlertTriangle className="h-5 w-5" />, highlight: true, color: 'text-red-400' },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-4">
      {stats.map((stat) => (
        <Card key={stat.label}>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">{stat.label}</p>
                <p className={`text-3xl font-bold ${stat.color || ''}`}>{stat.value}</p>
              </div>
              <div className={`rounded-lg p-3 ${stat.highlight ? 'bg-red-500/10' : 'bg-muted'}`}>
                {stat.icon}
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Severity Summary Bar ───────────────────────────────────────────────────

function SeverityBar({ overview }: { overview: RedOpsOverview | null }) {
  if (!overview) return null;
  const sb = overview.findings.severity_breakdown;
  const total = overview.findings.total || 1;

  const segments = [
    { key: 'critical', label: 'Critical', color: 'bg-red-500', count: sb.critical?.count || 0 },
    { key: 'high', label: 'High', color: 'bg-orange-500', count: sb.high?.count || 0 },
    { key: 'medium', label: 'Medium', color: 'bg-yellow-500', count: sb.medium?.count || 0 },
    { key: 'low', label: 'Low', color: 'bg-blue-500', count: sb.low?.count || 0 },
    { key: 'info', label: 'Info', color: 'bg-slate-500', count: sb.info?.count || 0 },
  ];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-lg">Findings by Severity</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-4 w-full rounded-full bg-muted flex overflow-hidden">
          {segments.map((s) => (
            s.count > 0 && (
              <div
                key={s.key}
                className={`${s.color} h-full transition-all`}
                style={{ width: `${(s.count / total) * 100}%` }}
                title={`${s.label}: ${s.count}`}
              />
            )
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-4 text-xs">
          {segments.map((s) => (
            <div key={s.key} className="flex items-center gap-1.5">
              <div className={`h-2.5 w-2.5 rounded-full ${s.color}`} />
              <span className="text-muted-foreground">{s.label}</span>
              <span className="font-medium">{s.count}</span>
              {sb[s.key]?.exploitable > 0 && (
                <span className="text-red-400">({sb[s.key].exploitable} exploitable)</span>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Campaign Row (expandable) ──────────────────────────────────────────────

function CampaignRow({
  campaign,
  onLaunch,
  onCancel,
  onDelete,
}: {
  campaign: RedOpsCampaign;
  onLaunch: (id: string) => void;
  onCancel: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  const isRunningCampaign = ['reconnaissance', 'scanning', 'exploitation', 'queued'].includes(campaign.status);

  // Use polling for agent data — polls every 3s when campaign is running & expanded
  const agentApiCall = useCallback(
    () => redopsApi.getCampaignAgents(campaign.id),
    [campaign.id]
  );

  const {
    data: agents,
    loading: agentsLoading,
    refetch: refetchAgents,
  } = usePollingApi<RedOpsAgent[]>(agentApiCall, {
    interval: 3000,
    enabled: expanded && campaign.total_agents > 0 && isRunningCampaign,
    immediate: expanded && campaign.total_agents > 0,
  });

  // Fetch agents once when expanding a non-running campaign
  useEffect(() => {
    if (expanded && campaign.total_agents > 0 && !isRunningCampaign && !agents) {
      refetchAgents();
    }
  }, [expanded, campaign.total_agents, isRunningCampaign, agents, refetchAgents]);

  const canLaunch = campaign.status === 'created' || campaign.status === 'failed';
  const canCancel = isRunningCampaign;
  const canDelete = !['reconnaissance', 'scanning', 'exploitation'].includes(campaign.status);

  const categories: string[] = (() => {
    try { return JSON.parse(campaign.agent_categories); }
    catch { return []; }
  })();

  const progress = campaign.total_agents > 0
    ? Math.round((campaign.completed_agents / campaign.total_agents) * 100)
    : 0;

  return (
    <div className="rounded-lg border transition-colors hover:bg-muted/30">
      <div
        className="flex items-center justify-between p-4 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-4 min-w-0 flex-1">
          <div className="hidden sm:flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/10">
            <Crosshair className="h-5 w-5 text-red-400" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-medium truncate">{campaign.name}</span>
              <CampaignStatusBadge status={campaign.status} />
              <ExploitationBadge level={campaign.exploitation_level} />
            </div>
            <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground flex-wrap">
              <span className="capitalize">{campaign.campaign_type}</span>
              <span>•</span>
              <span>{campaign.total_agents} agents</span>
              {campaign.findings_count > 0 && (
                <>
                  <span>•</span>
                  <span>{campaign.findings_count} findings</span>
                </>
              )}
              {campaign.exploitable_count > 0 && (
                <>
                  <span>•</span>
                  <span className="text-red-400">{campaign.exploitable_count} exploitable</span>
                </>
              )}
              <span>•</span>
              <Clock className="h-3 w-3" />
              <span>{formatRelativeTime(campaign.started_at || campaign.created_at)}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 ml-4">
          {/* Severity mini-badges */}
          {campaign.critical_count > 0 && (
            <Badge className={`text-xs ${getSeverityColor('critical')}`}>{campaign.critical_count}C</Badge>
          )}
          {campaign.high_count > 0 && (
            <Badge className={`text-xs ${getSeverityColor('high')}`}>{campaign.high_count}H</Badge>
          )}

          {/* Progress bar */}
          {campaign.total_agents > 0 && (
            <div className="hidden md:block w-20">
              <div className="h-1.5 w-full rounded-full bg-muted">
                <div
                  className="h-1.5 rounded-full bg-green-500 transition-all"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          {expanded ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
        </div>
      </div>

      {expanded && (
        <div className="border-t px-4 py-4 space-y-4">
          {/* Action buttons */}
          <div className="flex items-center gap-2 flex-wrap">
            {canLaunch && (
              <Button
                size="sm"
                onClick={(e) => { e.stopPropagation(); onLaunch(campaign.id); }}
                className="bg-red-600 hover:bg-red-700"
              >
                <Play className="mr-1 h-3 w-3" /> Launch
              </Button>
            )}
            {canCancel && (
              <Button
                size="sm"
                variant="outline"
                onClick={(e) => { e.stopPropagation(); onCancel(campaign.id); }}
              >
                <Square className="mr-1 h-3 w-3" /> Cancel
              </Button>
            )}
            {canDelete && (
              <Button
                size="sm"
                variant="outline"
                className="text-red-400 hover:text-red-300"
                onClick={(e) => { e.stopPropagation(); onDelete(campaign.id); }}
              >
                <Trash2 className="mr-1 h-3 w-3" /> Delete
              </Button>
            )}
          </div>

          {/* Campaign details */}
          <div className="grid gap-4 md:grid-cols-2 text-sm">
            <div>
              {campaign.description && (
                <p className="text-muted-foreground mb-3">{campaign.description}</p>
              )}
              <div className="space-y-1.5">
                <div><span className="text-muted-foreground">Categories:</span>
                  <span className="ml-2 inline-flex gap-1 flex-wrap">
                    {categories.map((cat) => (
                      <Badge key={cat} className={`text-xs border ${CATEGORY_COLORS[cat] || ''}`}>
                        {CATEGORY_ICONS[cat]} <span className="ml-1 capitalize">{cat}</span>
                      </Badge>
                    ))}
                  </span>
                </div>
                {campaign.duration_seconds && (
                  <div><span className="text-muted-foreground">Duration:</span> <span className="ml-2">{Math.round(campaign.duration_seconds / 60)}m {campaign.duration_seconds % 60}s</span></div>
                )}
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="rounded-lg bg-muted p-2">
                <p className="text-lg font-bold">{campaign.completed_agents}</p>
                <p className="text-xs text-muted-foreground">Completed</p>
              </div>
              <div className="rounded-lg bg-muted p-2">
                <p className="text-lg font-bold">{campaign.active_agents}</p>
                <p className="text-xs text-muted-foreground">Active</p>
              </div>
              <div className="rounded-lg bg-muted p-2">
                <p className="text-lg font-bold text-red-400">{campaign.exploitable_count}</p>
                <p className="text-xs text-muted-foreground">Exploitable</p>
              </div>
            </div>
          </div>

          {/* Agent list */}
          {campaign.total_agents > 0 && (
            <div>
              <h4 className="text-sm font-medium mb-2">Agents</h4>
              {agentsLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                  <Loader2 className="h-4 w-4 animate-spin" /> Loading agents...
                </div>
              ) : (
                <div className="grid gap-1.5">
                  {(agents || []).map((agent) => (
                    <div key={agent.id} className="flex items-center justify-between rounded bg-muted/50 px-3 py-2 text-sm">
                      <div className="flex items-center gap-2">
                        {CATEGORY_ICONS[agent.agent_category]}
                        <span className="font-medium">{agent.agent_type.replace(/_/g, ' ')}</span>
                        <AgentStatusBadge status={agent.status} />
                      </div>
                      <div className="flex items-center gap-3 text-xs text-muted-foreground">
                        {agent.findings_count > 0 && (
                          <span>{agent.findings_count} findings</span>
                        )}
                        {agent.tests_completed > 0 && (
                          <span>{agent.tests_completed}/{agent.tests_planned} tests</span>
                        )}
                        {agent.status === 'completed' && <CheckCircle className="h-3.5 w-3.5 text-green-400" />}
                        {agent.status === 'failed' && <XCircle className="h-3.5 w-3.5 text-red-400" />}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Create Campaign Dialog ─────────────────────────────────────────────────

function CreateCampaignDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [campaignType, setCampaignType] = useState<CampaignType>('full');
  const [targetScope, setTargetScope] = useState('');
  const [exploitationLevel, setExploitationLevel] = useState<ExploitationLevel>('safe');
  const [selectedCategories, setSelectedCategories] = useState<AgentCategory[]>(['web', 'api', 'cloud', 'network', 'identity']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const allCategories: AgentCategory[] = ['web', 'api', 'cloud', 'network', 'identity'];

  const toggleCategory = (cat: AgentCategory) => {
    setSelectedCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]
    );
  };

  const handleSubmit = async () => {
    if (!name.trim()) { setError('Campaign name is required'); return; }
    if (!targetScope.trim()) { setError('Target scope is required'); return; }

    setLoading(true);
    setError(null);

    try {
      // Parse target scope: support both JSON and simple line-separated hosts
      let parsedScope: Record<string, string[]> | string;
      try {
        parsedScope = JSON.parse(targetScope);
      } catch {
        // Treat as line-separated hosts
        const hosts = targetScope.split('\n').map((h) => h.trim()).filter(Boolean);
        parsedScope = { hosts };
      }

      await redopsApi.createCampaign({
        name: name.trim(),
        description: description.trim() || undefined,
        campaign_type: campaignType,
        target_scope: parsedScope,
        exploitation_level: exploitationLevel,
        agent_categories: selectedCategories,
      });

      // Reset form
      setName('');
      setDescription('');
      setTargetScope('');
      setCampaignType('full');
      setExploitationLevel('safe');
      setSelectedCategories(['web', 'api', 'cloud', 'network', 'identity']);
      onCreated();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create campaign');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Crosshair className="h-5 w-5 text-red-400" />
            New Pen Test Campaign
          </DialogTitle>
          <DialogDescription>
            Configure and create an AI-powered penetration test
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <Label htmlFor="name">Campaign Name</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Q1 2026 External Pen Test"
              className="mt-1"
            />
          </div>

          <div>
            <Label htmlFor="description">Description</Label>
            <Input
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
              className="mt-1"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Campaign Type</Label>
              <Select value={campaignType} onValueChange={(v) => setCampaignType(v as CampaignType)}>
                <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="full">Full Assessment</SelectItem>
                  <SelectItem value="targeted">Targeted</SelectItem>
                  <SelectItem value="continuous">Continuous</SelectItem>
                  <SelectItem value="validation">Validation</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Exploitation Level</Label>
              <Select value={exploitationLevel} onValueChange={(v) => setExploitationLevel(v as ExploitationLevel)}>
                <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="passive">Passive (recon only)</SelectItem>
                  <SelectItem value="safe">Safe (no exploitation)</SelectItem>
                  <SelectItem value="moderate">Moderate</SelectItem>
                  <SelectItem value="aggressive">Aggressive</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <Label htmlFor="scope">Target Scope</Label>
            <Textarea
              id="scope"
              value={targetScope}
              onChange={(e) => setTargetScope(e.target.value)}
              placeholder={'Enter one host/IP per line, or JSON:\n192.168.1.0/24\nexample.com\n10.0.0.1'}
              rows={4}
              className="mt-1 font-mono text-sm"
            />
          </div>

          <div>
            <Label>Agent Categories</Label>
            <div className="mt-2 flex flex-wrap gap-2">
              {allCategories.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => toggleCategory(cat)}
                  className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm transition-colors ${
                    selectedCategories.includes(cat)
                      ? CATEGORY_COLORS[cat]
                      : 'border-muted text-muted-foreground opacity-50'
                  }`}
                >
                  {CATEGORY_ICONS[cat]}
                  <span className="capitalize">{cat}</span>
                </button>
              ))}
            </div>
          </div>

          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
              {error}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={loading}>Cancel</Button>
          <Button
            onClick={handleSubmit}
            disabled={loading}
            className="bg-red-600 hover:bg-red-700"
          >
            {loading ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Creating...</> : 'Create Campaign'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export function RedOps() {
  const [showCreate, setShowCreate] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Fetch overview + campaigns in a single polling call
  const fetchDashboard = useCallback(async () => {
    const [overviewData, campaignsData] = await Promise.all([
      redopsApi.getOverview(),
      redopsApi.listCampaigns({ page: 1, page_size: 20, sort: 'desc' }),
    ]);
    return { overview: overviewData, campaigns: campaignsData.items };
  }, []);

  // Determine if any campaigns are active (for adaptive polling)
  const {
    data,
    loading,
    error,
    isPolling,
    lastUpdated,
    refetch,
  } = usePollingApi(fetchDashboard, {
    interval: 5000,
    enabled: true,
    immediate: true,
  });

  const overview = data?.overview ?? null;
  const campaigns = data?.campaigns ?? [];

  // Enable faster polling (3s) when campaigns are active
  const hasActiveCampaigns = useMemo(
    () => campaigns.some((c) => ['reconnaissance', 'scanning', 'exploitation', 'queued'].includes(c.status)),
    [campaigns]
  );

  const {
    data: activeData,
    refetch: refetchActive,
  } = usePollingApi(fetchDashboard, {
    interval: 3000,
    enabled: hasActiveCampaigns,
    immediate: false,
  });

  // Use active data when available and campaigns are running
  const effectiveOverview = (hasActiveCampaigns && activeData?.overview) ? activeData.overview : overview;
  const effectiveCampaigns = (hasActiveCampaigns && activeData?.campaigns) ? activeData.campaigns : campaigns;

  const handleLaunch = async (id: string) => {
    try {
      setActionError(null);
      await redopsApi.launchCampaign(id);
      refetch();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to launch campaign');
    }
  };

  const handleCancel = async (id: string) => {
    try {
      setActionError(null);
      await redopsApi.cancelCampaign(id);
      refetch();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to cancel campaign');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      setActionError(null);
      await redopsApi.deleteCampaign(id);
      refetch();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to delete campaign');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-red-400" />
      </div>
    );
  }

  const displayError = actionError || error;

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Crosshair className="h-8 w-8 text-red-400" />
            ForgeRedOPS
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-powered penetration testing &amp; offensive security
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* Live indicator */}
          {isPolling && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Radio className="h-3 w-3 text-green-400 animate-pulse" />
              <span>Live</span>
              {lastUpdated && (
                <span className="text-muted-foreground/60">
                  {formatRelativeTime(lastUpdated.toISOString())}
                </span>
              )}
            </div>
          )}
          <Button variant="outline" size="sm" onClick={refetch}>
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Button
            onClick={() => setShowCreate(true)}
            className="bg-red-600 hover:bg-red-700"
          >
            <Plus className="mr-2 h-4 w-4" /> New Campaign
          </Button>
        </div>
      </div>

      {displayError && (
        <div className="mb-6 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-medium">Error</p>
            <p className="mt-1">{displayError}</p>
          </div>
        </div>
      )}

      {/* Overview Stats */}
      <div className="space-y-6">
        <OverviewStats overview={effectiveOverview} />
        <SeverityBar overview={effectiveOverview} />

        {/* Campaigns List */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Pen Test Campaigns</CardTitle>
                <CardDescription>
                  {effectiveCampaigns.length} campaign{effectiveCampaigns.length !== 1 ? 's' : ''}
                  {hasActiveCampaigns && (
                    <span className="ml-2 text-cyan-400">
                      — polling every 3s
                    </span>
                  )}
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {effectiveCampaigns.length === 0 ? (
              <div className="text-center py-12">
                <Shield className="mx-auto h-12 w-12 text-muted-foreground/30" />
                <h3 className="mt-4 text-lg font-medium">No campaigns yet</h3>
                <p className="mt-2 text-sm text-muted-foreground">
                  Create your first AI penetration test campaign to get started
                </p>
                <Button
                  onClick={() => setShowCreate(true)}
                  className="mt-4 bg-red-600 hover:bg-red-700"
                >
                  <Plus className="mr-2 h-4 w-4" /> Create Campaign
                </Button>
              </div>
            ) : (
              <div className="space-y-2">
                {effectiveCampaigns.map((campaign) => (
                  <CampaignRow
                    key={campaign.id}
                    campaign={campaign}
                    onLaunch={handleLaunch}
                    onCancel={handleCancel}
                    onDelete={handleDelete}
                  />
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Create Campaign Dialog */}
      <CreateCampaignDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={refetch}
      />
    </div>
  );
}
