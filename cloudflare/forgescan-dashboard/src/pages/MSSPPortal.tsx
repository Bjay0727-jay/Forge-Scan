import { useState, useEffect, useCallback } from 'react';
import { msspApi } from '@/lib/api';
import type { MSSPOverview, Organization, TenantHealthCard, OrgBranding } from '@/types';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  Building2,
  Users,
  Shield,
  AlertTriangle,
  Activity,
  Plus,
  Search,
  ChevronRight,
  Palette,
  HeartPulse,
  Server,
  Bug,
  Scan,
  RefreshCw,
} from 'lucide-react';

// ─── Tier badge colors ─────────────────────────────────────────────────────
function tierBadge(tier: string) {
  switch (tier) {
    case 'enterprise': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    case 'professional': return 'bg-teal-500/20 text-teal-400 border-teal-500/30';
    case 'standard': return 'bg-sky-500/20 text-sky-400 border-sky-500/30';
    case 'trial': return 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30';
    default: return 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30';
  }
}

function statusBadge(status: string) {
  switch (status) {
    case 'active': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
    case 'suspended': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    case 'deactivated': return 'bg-red-500/20 text-red-400 border-red-500/30';
    default: return 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30';
  }
}

function riskBadge(level: string) {
  switch (level) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'medium': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    case 'low': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
    default: return 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30';
  }
}

// ─── Main Component ────────────────────────────────────────────────────────
export function MSSPPortal() {
  const [overview, setOverview] = useState<MSSPOverview | null>(null);
  const [healthCards, setHealthCards] = useState<TenantHealthCard[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [showDetail, setShowDetail] = useState<string | null>(null);
  const [detailData, setDetailData] = useState<(Organization & { members: unknown[]; branding: OrgBranding | null; stats: Record<string, unknown> }) | null>(null);
  const [showBranding, setShowBranding] = useState<string | null>(null);
  const [brandingData, setBrandingData] = useState<Partial<OrgBranding>>({});
  const [activeTab, setActiveTab] = useState<'overview' | 'tenants' | 'health'>('overview');

  // Create form state
  const [newOrg, setNewOrg] = useState({
    name: '', tier: 'standard', contact_email: '', contact_name: '', industry: '',
    max_assets: 1000, max_users: 25, max_scanners: 5,
  });

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [overviewRes, healthRes] = await Promise.all([
        msspApi.getOverview(),
        msspApi.getHealth(),
      ]);
      setOverview(overviewRes);
      setHealthCards(healthRes.tenants);
    } catch (err) {
      console.error('MSSP load error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const handleCreateOrg = async () => {
    if (!newOrg.name.trim()) return;
    try {
      await msspApi.createOrganization(newOrg);
      setShowCreate(false);
      setNewOrg({ name: '', tier: 'standard', contact_email: '', contact_name: '', industry: '', max_assets: 1000, max_users: 25, max_scanners: 5 });
      loadData();
    } catch (err) {
      console.error('Create org error:', err);
    }
  };

  const openDetail = async (orgId: string) => {
    try {
      const data = await msspApi.getOrganization(orgId);
      setDetailData(data);
      setShowDetail(orgId);
    } catch (err) {
      console.error('Load detail error:', err);
    }
  };

  const openBranding = async (orgId: string) => {
    try {
      const data = await msspApi.getBranding(orgId);
      setBrandingData(data);
      setShowBranding(orgId);
    } catch (err) {
      setBrandingData({});
      setShowBranding(orgId);
    }
  };

  const saveBranding = async () => {
    if (!showBranding) return;
    try {
      await msspApi.updateBranding(showBranding, brandingData);
      setShowBranding(null);
      loadData();
    } catch (err) {
      console.error('Save branding error:', err);
    }
  };

  const filteredTenants = overview?.tenants.filter(t =>
    !search || t.name.toLowerCase().includes(search.toLowerCase()) || (t.slug as string).toLowerCase().includes(search.toLowerCase())
  ) || [];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-teal-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">MSSP Portal</h1>
          <p className="text-sm text-[#6b8fb9] mt-1">Manage client environments, monitor tenant health, configure white-label branding</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={loadData} className="border-[#1e3a5f] text-[#6b8fb9] hover:text-white hover:border-teal-500/50">
            <RefreshCw className="h-4 w-4 mr-1" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setShowCreate(true)} className="bg-teal-600 hover:bg-teal-700 text-white">
            <Plus className="h-4 w-4 mr-1" /> New Tenant
          </Button>
        </div>
      </div>

      {/* Tab navigation */}
      <div className="flex gap-1 p-1 rounded-lg" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(75,119,169,0.2)' }}>
        {(['overview', 'tenants', 'health'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab
                ? 'bg-teal-600/20 text-teal-400 border border-teal-500/30'
                : 'text-[#6b8fb9] hover:text-white border border-transparent'
            }`}
          >
            {tab === 'overview' ? 'Overview' : tab === 'tenants' ? 'Tenant Management' : 'Health Monitor'}
          </button>
        ))}
      </div>

      {/* ─── Overview Tab ──────────────────────────────────────────────── */}
      {activeTab === 'overview' && overview && (
        <>
          {/* Aggregate stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Managed Tenants', value: overview.totals.organizations, sub: `${overview.totals.active} active`, icon: Building2, color: '#14b8a6' },
              { label: 'Total Users', value: overview.totals.total_users, sub: 'across all tenants', icon: Users, color: '#3b82f6' },
              { label: 'Total Assets', value: overview.totals.total_assets.toLocaleString(), sub: `${overview.totals.total_scans} scans`, icon: Server, color: '#8b5cf6' },
              { label: 'Total Findings', value: overview.totals.total_findings.toLocaleString(), sub: `${overview.totals.total_alerts} SOC alerts`, icon: Bug, color: '#f59e0b' },
            ].map((stat) => (
              <Card key={stat.label} className="border-[#1e3a5f]/60" style={{ background: 'rgba(255,255,255,0.03)' }}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-2">
                    <stat.icon className="h-5 w-5" style={{ color: stat.color }} />
                    <span className="text-2xl font-bold text-white">{stat.value}</span>
                  </div>
                  <p className="text-sm font-medium text-white">{stat.label}</p>
                  <p className="text-xs text-[#4b77a9]">{stat.sub}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Tier breakdown */}
          <Card className="border-[#1e3a5f]/60" style={{ background: 'rgba(255,255,255,0.03)' }}>
            <CardContent className="p-4">
              <h3 className="text-sm font-semibold text-white mb-3">Tier Distribution</h3>
              <div className="flex gap-4 flex-wrap">
                {Object.entries(overview.tier_breakdown).map(([tier, count]) => (
                  <div key={tier} className="flex items-center gap-2">
                    <Badge className={`text-xs border ${tierBadge(tier)}`}>{tier}</Badge>
                    <span className="text-sm text-white font-medium">{count}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Quick tenant list */}
          <Card className="border-[#1e3a5f]/60" style={{ background: 'rgba(255,255,255,0.03)' }}>
            <CardContent className="p-4">
              <h3 className="text-sm font-semibold text-white mb-3">All Tenants</h3>
              <div className="space-y-2">
                {overview.tenants.map((tenant) => (
                  <div
                    key={tenant.id}
                    className="flex items-center justify-between p-3 rounded-lg hover:bg-white/[0.04] cursor-pointer transition-colors"
                    style={{ border: '1px solid rgba(75,119,169,0.15)' }}
                    onClick={() => openDetail(tenant.id)}
                  >
                    <div className="flex items-center gap-3">
                      <Building2 className="h-4 w-4 text-teal-400" />
                      <div>
                        <p className="text-sm font-medium text-white">{tenant.name}</p>
                        <p className="text-xs text-[#4b77a9]">{tenant.contact_email || tenant.slug}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge className={`text-[10px] border ${tierBadge(tenant.tier)}`}>{tenant.tier}</Badge>
                      <Badge className={`text-[10px] border ${statusBadge(tenant.status)}`}>{tenant.status}</Badge>
                      <div className="text-right text-xs text-[#6b8fb9]">
                        <span>{tenant.stats.assets} assets</span>
                        <span className="mx-1">·</span>
                        <span>{tenant.stats.findings} findings</span>
                      </div>
                      <ChevronRight className="h-4 w-4 text-[#4b77a9]" />
                    </div>
                  </div>
                ))}
                {overview.tenants.length === 0 && (
                  <p className="text-sm text-[#4b77a9] text-center py-8">No tenants yet. Click "New Tenant" to onboard your first client.</p>
                )}
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {/* ─── Tenant Management Tab ─────────────────────────────────────── */}
      {activeTab === 'tenants' && (
        <>
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[#4b77a9]" />
              <Input
                placeholder="Search tenants..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 bg-transparent border-[#1e3a5f] text-white placeholder:text-[#4b77a9]"
              />
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {filteredTenants.map((tenant) => (
              <Card key={tenant.id} className="border-[#1e3a5f]/60 hover:border-teal-500/30 transition-colors cursor-pointer" style={{ background: 'rgba(255,255,255,0.03)' }}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h3 className="text-sm font-semibold text-white">{tenant.name}</h3>
                      <p className="text-xs text-[#4b77a9]">{tenant.slug}</p>
                    </div>
                    <div className="flex gap-1">
                      <Badge className={`text-[10px] border ${tierBadge(tenant.tier)}`}>{tenant.tier}</Badge>
                      <Badge className={`text-[10px] border ${statusBadge(tenant.status)}`}>{tenant.status}</Badge>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 mb-3">
                    <div className="text-xs">
                      <span className="text-[#4b77a9]">Assets: </span>
                      <span className="text-white font-medium">{tenant.stats.assets}</span>
                    </div>
                    <div className="text-xs">
                      <span className="text-[#4b77a9]">Findings: </span>
                      <span className="text-white font-medium">{tenant.stats.findings}</span>
                    </div>
                    <div className="text-xs">
                      <span className="text-[#4b77a9]">Scans: </span>
                      <span className="text-white font-medium">{tenant.stats.scans}</span>
                    </div>
                    <div className="text-xs">
                      <span className="text-[#4b77a9]">Members: </span>
                      <span className="text-white font-medium">{tenant.member_count}</span>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" className="flex-1 text-xs border-[#1e3a5f] text-[#6b8fb9] hover:text-white hover:border-teal-500/50" onClick={() => openDetail(tenant.id)}>
                      <Shield className="h-3 w-3 mr-1" /> Manage
                    </Button>
                    <Button variant="outline" size="sm" className="text-xs border-[#1e3a5f] text-[#6b8fb9] hover:text-white hover:border-teal-500/50" onClick={() => openBranding(tenant.id)}>
                      <Palette className="h-3 w-3 mr-1" /> Brand
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </>
      )}

      {/* ─── Health Monitor Tab ────────────────────────────────────────── */}
      {activeTab === 'health' && (
        <div className="space-y-4">
          <div className="grid gap-3">
            {healthCards.map((card) => (
              <div
                key={card.org_id}
                className="flex items-center justify-between p-4 rounded-lg"
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.15)' }}
              >
                <div className="flex items-center gap-4">
                  <HeartPulse className="h-5 w-5 text-teal-400" />
                  <div>
                    <p className="text-sm font-medium text-white">{card.name}</p>
                    <p className="text-xs text-[#4b77a9]">
                      Last scan: {card.last_scan_at ? new Date(card.last_scan_at).toLocaleDateString() : 'Never'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right text-xs space-y-0.5">
                    <div className="flex items-center gap-1 justify-end">
                      <AlertTriangle className="h-3 w-3 text-red-400" />
                      <span className="text-white">{card.critical_findings} critical</span>
                    </div>
                    <div className="flex items-center gap-1 justify-end">
                      <Activity className="h-3 w-3 text-amber-400" />
                      <span className="text-white">{card.open_alerts} alerts</span>
                    </div>
                    <div className="flex items-center gap-1 justify-end">
                      <Scan className="h-3 w-3 text-sky-400" />
                      <span className="text-white">{card.active_scans} active scans</span>
                    </div>
                  </div>
                  <Badge className={`text-xs border min-w-[70px] justify-center ${riskBadge(card.risk_level)}`}>
                    {card.risk_level}
                  </Badge>
                </div>
              </div>
            ))}
            {healthCards.length === 0 && (
              <p className="text-sm text-[#4b77a9] text-center py-12">No active tenants to monitor.</p>
            )}
          </div>
        </div>
      )}

      {/* ─── Create Tenant Dialog ──────────────────────────────────────── */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="sm:max-w-lg" style={{ background: '#0f2133', border: '1px solid rgba(75,119,169,0.3)' }}>
          <DialogHeader>
            <DialogTitle className="text-white">Onboard New Tenant</DialogTitle>
            <DialogDescription className="text-[#6b8fb9]">Create a new client environment with isolated data.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 mt-2">
            <div>
              <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Organization Name *</label>
              <Input value={newOrg.name} onChange={(e) => setNewOrg(p => ({ ...p, name: e.target.value }))} placeholder="Acme Corporation" className="bg-transparent border-[#1e3a5f] text-white" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Contact Name</label>
                <Input value={newOrg.contact_name} onChange={(e) => setNewOrg(p => ({ ...p, contact_name: e.target.value }))} placeholder="John Doe" className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Contact Email</label>
                <Input value={newOrg.contact_email} onChange={(e) => setNewOrg(p => ({ ...p, contact_email: e.target.value }))} placeholder="john@acme.com" className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Tier</label>
                <select value={newOrg.tier} onChange={(e) => setNewOrg(p => ({ ...p, tier: e.target.value }))} className="w-full rounded-md px-3 py-2 text-sm bg-transparent text-white" style={{ border: '1px solid #1e3a5f' }}>
                  <option value="trial">Trial</option>
                  <option value="standard">Standard</option>
                  <option value="professional">Professional</option>
                  <option value="enterprise">Enterprise</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Industry</label>
                <Input value={newOrg.industry} onChange={(e) => setNewOrg(p => ({ ...p, industry: e.target.value }))} placeholder="Healthcare" className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Max Assets</label>
                <Input type="number" value={newOrg.max_assets} onChange={(e) => setNewOrg(p => ({ ...p, max_assets: parseInt(e.target.value) || 1000 }))} className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Max Users</label>
                <Input type="number" value={newOrg.max_users} onChange={(e) => setNewOrg(p => ({ ...p, max_users: parseInt(e.target.value) || 25 }))} className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Max Scanners</label>
                <Input type="number" value={newOrg.max_scanners} onChange={(e) => setNewOrg(p => ({ ...p, max_scanners: parseInt(e.target.value) || 5 }))} className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setShowCreate(false)} className="border-[#1e3a5f] text-[#6b8fb9]">Cancel</Button>
              <Button onClick={handleCreateOrg} className="bg-teal-600 hover:bg-teal-700 text-white">Create Tenant</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* ─── Tenant Detail Dialog ──────────────────────────────────────── */}
      <Dialog open={!!showDetail} onOpenChange={() => setShowDetail(null)}>
        <DialogContent className="sm:max-w-2xl max-h-[80vh] overflow-y-auto" style={{ background: '#0f2133', border: '1px solid rgba(75,119,169,0.3)' }}>
          {detailData && (
            <>
              <DialogHeader>
                <DialogTitle className="text-white flex items-center gap-2">
                  <Building2 className="h-5 w-5 text-teal-400" />
                  {detailData.name}
                </DialogTitle>
                <DialogDescription className="text-[#6b8fb9]">
                  {detailData.slug} · {detailData.tier} tier · {detailData.contact_email || 'No contact email'}
                </DialogDescription>
              </DialogHeader>

              {/* Stats grid */}
              <div className="grid grid-cols-3 gap-3 mt-4">
                {[
                  { label: 'Assets', value: detailData.stats?.assets ?? 0 },
                  { label: 'Findings', value: detailData.stats?.findings ?? 0 },
                  { label: 'Scans', value: detailData.stats?.scans ?? 0 },
                  { label: 'SOC Alerts', value: detailData.stats?.alerts ?? 0 },
                  { label: 'Incidents', value: detailData.stats?.incidents ?? 0 },
                  { label: 'Members', value: (detailData.members || []).length },
                ].map((s) => (
                  <div key={s.label} className="p-3 rounded-lg text-center" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(75,119,169,0.15)' }}>
                    <p className="text-lg font-bold text-white">{typeof s.value === 'number' ? s.value.toLocaleString() : s.value}</p>
                    <p className="text-[10px] text-[#4b77a9] uppercase tracking-wider">{s.label}</p>
                  </div>
                ))}
              </div>

              {/* Members table */}
              <div className="mt-4">
                <h4 className="text-sm font-semibold text-white mb-2">Team Members</h4>
                {(detailData.members as Array<{ user_id: string; email?: string; display_name?: string; org_role: string; is_active?: number }>).length > 0 ? (
                  <div className="space-y-1">
                    {(detailData.members as Array<{ user_id: string; email?: string; display_name?: string; org_role: string; is_active?: number }>).map((m) => (
                      <div key={m.user_id} className="flex items-center justify-between p-2 rounded text-sm" style={{ background: 'rgba(255,255,255,0.03)' }}>
                        <div>
                          <span className="text-white">{m.display_name || m.email}</span>
                          {m.email && <span className="text-[#4b77a9] ml-2 text-xs">{m.email}</span>}
                        </div>
                        <Badge className="text-[10px] border bg-teal-500/15 text-teal-400 border-teal-500/30">{m.org_role}</Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-[#4b77a9]">No members assigned yet.</p>
                )}
              </div>

              {/* Branding preview */}
              {detailData.branding && (
                <div className="mt-4">
                  <h4 className="text-sm font-semibold text-white mb-2">White-Label Branding</h4>
                  <div className="p-3 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.15)' }}>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div>
                        <span className="text-[#4b77a9]">Brand Name: </span>
                        <span className="text-white">{detailData.branding.company_name || '—'}</span>
                      </div>
                      <div>
                        <span className="text-[#4b77a9]">Primary Color: </span>
                        <span className="text-white inline-flex items-center gap-1">
                          <span className="w-3 h-3 rounded-sm inline-block" style={{ background: detailData.branding.primary_color }} />
                          {detailData.branding.primary_color}
                        </span>
                      </div>
                      <div>
                        <span className="text-[#4b77a9]">Custom Domain: </span>
                        <span className="text-white">{detailData.branding.custom_domain || '—'}</span>
                      </div>
                      <div>
                        <span className="text-[#4b77a9]">Powered By: </span>
                        <span className="text-white">{detailData.branding.powered_by_visible ? 'Visible' : 'Hidden'}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* ─── Branding Editor Dialog ────────────────────────────────────── */}
      <Dialog open={!!showBranding} onOpenChange={() => setShowBranding(null)}>
        <DialogContent className="sm:max-w-lg" style={{ background: '#0f2133', border: '1px solid rgba(75,119,169,0.3)' }}>
          <DialogHeader>
            <DialogTitle className="text-white flex items-center gap-2">
              <Palette className="h-5 w-5 text-teal-400" /> White-Label Settings
            </DialogTitle>
            <DialogDescription className="text-[#6b8fb9]">Customize branding for partner delivery.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 mt-2">
            <div>
              <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Company Name</label>
              <Input value={brandingData.company_name || ''} onChange={(e) => setBrandingData(p => ({ ...p, company_name: e.target.value }))} placeholder="Partner Corp" className="bg-transparent border-[#1e3a5f] text-white" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Logo URL</label>
                <Input value={brandingData.logo_url || ''} onChange={(e) => setBrandingData(p => ({ ...p, logo_url: e.target.value }))} placeholder="https://..." className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Favicon URL</label>
                <Input value={brandingData.favicon_url || ''} onChange={(e) => setBrandingData(p => ({ ...p, favicon_url: e.target.value }))} placeholder="https://..." className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Primary Color</label>
                <div className="flex gap-2">
                  <input type="color" value={brandingData.primary_color || '#14b8a6'} onChange={(e) => setBrandingData(p => ({ ...p, primary_color: e.target.value }))} className="h-9 w-10 rounded border-0 cursor-pointer" />
                  <Input value={brandingData.primary_color || '#14b8a6'} onChange={(e) => setBrandingData(p => ({ ...p, primary_color: e.target.value }))} className="bg-transparent border-[#1e3a5f] text-white text-xs" />
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Accent Color</label>
                <div className="flex gap-2">
                  <input type="color" value={brandingData.accent_color || '#0d9488'} onChange={(e) => setBrandingData(p => ({ ...p, accent_color: e.target.value }))} className="h-9 w-10 rounded border-0 cursor-pointer" />
                  <Input value={brandingData.accent_color || '#0d9488'} onChange={(e) => setBrandingData(p => ({ ...p, accent_color: e.target.value }))} className="bg-transparent border-[#1e3a5f] text-white text-xs" />
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Sidebar BG</label>
                <div className="flex gap-2">
                  <input type="color" value={brandingData.sidebar_bg || '#0b1929'} onChange={(e) => setBrandingData(p => ({ ...p, sidebar_bg: e.target.value }))} className="h-9 w-10 rounded border-0 cursor-pointer" />
                  <Input value={brandingData.sidebar_bg || '#0b1929'} onChange={(e) => setBrandingData(p => ({ ...p, sidebar_bg: e.target.value }))} className="bg-transparent border-[#1e3a5f] text-white text-xs" />
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Login Title</label>
                <Input value={brandingData.login_title || ''} onChange={(e) => setBrandingData(p => ({ ...p, login_title: e.target.value }))} placeholder="Welcome to SecOps Portal" className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Login Subtitle</label>
                <Input value={brandingData.login_subtitle || ''} onChange={(e) => setBrandingData(p => ({ ...p, login_subtitle: e.target.value }))} placeholder="Powered by your MSSP" className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Support Email</label>
                <Input value={brandingData.support_email || ''} onChange={(e) => setBrandingData(p => ({ ...p, support_email: e.target.value }))} placeholder="support@partner.com" className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
              <div>
                <label className="text-xs font-medium text-[#6b8fb9] mb-1 block">Custom Domain</label>
                <Input value={brandingData.custom_domain || ''} onChange={(e) => setBrandingData(p => ({ ...p, custom_domain: e.target.value }))} placeholder="security.partner.com" className="bg-transparent border-[#1e3a5f] text-white" />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" checked={brandingData.powered_by_visible !== 0} onChange={(e) => setBrandingData(p => ({ ...p, powered_by_visible: e.target.checked ? 1 : 0 }))} className="rounded" />
              <label className="text-xs text-[#6b8fb9]">Show "Powered by Forge Cyber Defense" footer</label>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setShowBranding(null)} className="border-[#1e3a5f] text-[#6b8fb9]">Cancel</Button>
              <Button onClick={saveBranding} className="bg-teal-600 hover:bg-teal-700 text-white">Save Branding</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
