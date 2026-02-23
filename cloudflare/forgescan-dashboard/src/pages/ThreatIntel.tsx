import { useState, useEffect, useCallback } from 'react';
import { threatIntelApi } from '@/lib/api';
import type { ThreatIntelOverview, ThreatIntelFeed } from '@/types';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Globe, RefreshCw, Plus, Rss, Target, AlertTriangle, Database, Link2, Zap } from 'lucide-react';

function sevBadge(s: string) {
  const map: Record<string, string> = { critical: 'bg-red-500/20 text-red-400 border-red-500/30', high: 'bg-orange-500/20 text-orange-400 border-orange-500/30', medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30', low: 'bg-sky-500/20 text-sky-400 border-sky-500/30' };
  return map[s] || 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30';
}

export function ThreatIntel() {
  const [overview, setOverview] = useState<ThreatIntelOverview | null>(null);
  const [feeds, setFeeds] = useState<ThreatIntelFeed[]>([]);
  const [loading, setLoading] = useState(true);
  const [showBuiltin, setShowBuiltin] = useState(false);
  const [builtinFeeds, setBuiltinFeeds] = useState<Array<{ name: string; feed_type: string; format: string; description: string }>>([]);
  const [syncing, setSyncing] = useState<string | null>(null);
  const [correlating, setCorrelating] = useState(false);
  const [correlationResult, setCorrelationResult] = useState<{ indicators_checked: number; new_matches: number; matches: unknown[] } | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'feeds' | 'matches'>('overview');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [ov, f] = await Promise.all([threatIntelApi.getOverview(), threatIntelApi.listFeeds()]);
      setOverview(ov);
      setFeeds(f.items || []);
    } catch (e) { console.error(e); } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const openBuiltin = async () => {
    const res = await threatIntelApi.getBuiltinFeeds();
    setBuiltinFeeds(res.feeds as Array<{ name: string; feed_type: string; format: string; description: string }>);
    setShowBuiltin(true);
  };

  const addBuiltin = async (index: number) => {
    await threatIntelApi.addBuiltinFeed(index);
    setShowBuiltin(false);
    load();
  };

  const syncFeed = async (id: string) => {
    setSyncing(id);
    try { await threatIntelApi.syncFeed(id); load(); } catch (e) { console.error(e); } finally { setSyncing(null); }
  };

  const runCorrelation = async () => {
    setCorrelating(true);
    try {
      const res = await threatIntelApi.correlate();
      setCorrelationResult(res);
      load();
    } catch (e) { console.error(e); } finally { setCorrelating(false); }
  };

  if (loading && !overview) return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-teal-500 border-t-transparent" /></div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>
          <p className="text-sm text-muted-foreground mt-1">Aggregate feeds, correlate indicators against your assets, surface hidden threats</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={runCorrelation} disabled={correlating} className="border-border text-muted-foreground hover:text-white">
            {correlating ? <RefreshCw className="h-4 w-4 mr-1 animate-spin" /> : <Target className="h-4 w-4 mr-1" />} Correlate
          </Button>
          <Button size="sm" onClick={openBuiltin} className="bg-teal-600 hover:bg-teal-700 text-white"><Plus className="h-4 w-4 mr-1" /> Add Feed</Button>
        </div>
      </div>

      <div className="flex gap-1 p-1 rounded-lg bg-white/[0.04] border border-navy-400/20">
        {(['overview', 'feeds', 'matches'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)} className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${activeTab === tab ? 'bg-teal-600/20 text-teal-400 border border-teal-500/30' : 'text-muted-foreground hover:text-white border border-transparent'}`}>
            {tab === 'overview' ? 'Overview' : tab === 'feeds' ? 'Feeds' : 'Matches'}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && overview && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Active Feeds', value: overview.totals.active_feeds, sub: `${overview.totals.feeds} total`, icon: Rss, color: 'text-violet-400' },
              { label: 'Indicators', value: overview.totals.active_indicators.toLocaleString(), sub: 'active IOCs', icon: Database, color: 'text-teal-400' },
              { label: 'Matches', value: overview.totals.total_matches, sub: 'correlated hits', icon: Target, color: 'text-amber-400' },
              { label: 'Built-in Feeds', value: overview.builtin_feeds_available, sub: 'available', icon: Globe, color: 'text-blue-400' },
            ].map(s => (
              <Card key={s.label} className="border-border/60 bg-white/[0.03]">
                <CardContent className="p-4 flex items-center justify-between">
                  <div><p className="text-2xl font-bold text-white">{s.value}</p><p className="text-xs text-muted-foreground">{s.label}</p><p className="text-[10px] text-muted-foreground/60">{s.sub}</p></div>
                  <s.icon className={`h-6 w-6 opacity-50 ${s.color}`} />
                </CardContent>
              </Card>
            ))}
          </div>

          {overview.indicator_types.length > 0 && (
            <Card className="border-border/60 bg-white/[0.03]">
              <CardContent className="p-4">
                <h3 className="text-sm font-semibold text-white mb-3">Indicator Types</h3>
                <div className="flex gap-3 flex-wrap">
                  {overview.indicator_types.map(t => (
                    <div key={t.indicator_type} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.04] border border-navy-400/15">
                      <span className="text-xs text-white font-medium">{t.indicator_type}</span>
                      <Badge className="text-[10px] bg-teal-500/15 text-teal-400 border-teal-500/30">{t.count}</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {overview.recent_matches.length > 0 && (
            <Card className="border-border/60 bg-white/[0.03]">
              <CardContent className="p-4">
                <h3 className="text-sm font-semibold text-white mb-3">Recent Matches</h3>
                <div className="space-y-2">
                  {overview.recent_matches.map((m, i) => {
                    const match = m as Record<string, unknown>;
                    return (
                      <div key={i} className="flex items-center justify-between p-2 rounded text-xs bg-white/[0.03]">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="h-3 w-3 text-amber-400" />
                          <span className="text-white font-medium">{match.indicator_value as string}</span>
                          <Badge className={`text-[10px] border ${sevBadge(match.indicator_severity as string)}`}>{match.indicator_severity as string}</Badge>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-muted-foreground">{match.match_type as string}</span>
                          <span className="text-muted-foreground/60">{match.feed_name as string}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Feeds Tab */}
      {activeTab === 'feeds' && (
        <div className="space-y-2">
          {feeds.map(feed => (
            <div key={feed.id} className="flex items-center justify-between p-4 rounded-lg bg-white/[0.03] border border-navy-400/15">
              <div className="flex items-center gap-3">
                <Rss className="h-5 w-5 text-purple-400" />
                <div>
                  <p className="text-sm font-medium text-white">{feed.name}</p>
                  <p className="text-xs text-muted-foreground">{feed.feed_type} · {feed.format} · {feed.indicators_count} indicators · Last: {feed.last_fetch_at ? new Date(feed.last_fetch_at).toLocaleDateString() : 'Never'}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge className={`text-[10px] border ${feed.enabled ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30'}`}>
                  {feed.enabled ? 'Active' : 'Disabled'}
                </Badge>
                {feed.last_fetch_status && (
                  <Badge className={`text-[10px] border ${feed.last_fetch_status === 'success' ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' : 'bg-red-500/15 text-red-400 border-red-500/30'}`}>
                    {feed.last_fetch_status}
                  </Badge>
                )}
                <Button variant="outline" size="sm" onClick={() => syncFeed(feed.id)} disabled={syncing === feed.id} className="text-xs border-border text-muted-foreground hover:text-white hover:border-teal-500/50">
                  {syncing === feed.id ? <RefreshCw className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                  <span className="ml-1">Sync</span>
                </Button>
              </div>
            </div>
          ))}
          {feeds.length === 0 && <p className="text-sm text-muted-foreground text-center py-12">No feeds configured. Click "Add Feed" to subscribe to threat intelligence sources.</p>}
        </div>
      )}

      {/* Matches Tab */}
      {activeTab === 'matches' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">Indicators matched against your internal assets, findings, and alerts</p>
            <Button variant="outline" size="sm" onClick={runCorrelation} disabled={correlating} className="border-teal-500/30 text-teal-400 hover:bg-teal-500/10">
              {correlating ? <RefreshCw className="h-3 w-3 animate-spin mr-1" /> : <Zap className="h-3 w-3 mr-1" />} Run Correlation
            </Button>
          </div>
          {overview && overview.recent_matches.length > 0 ? (
            <div className="space-y-2">
              {overview.recent_matches.map((m, i) => {
                const match = m as Record<string, unknown>;
                return (
                  <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-white/[0.03] border border-navy-400/15">
                    <div className="flex items-center gap-3">
                      <Link2 className="h-4 w-4 text-amber-400" />
                      <div>
                        <p className="text-sm font-medium text-white">{match.indicator_value as string}</p>
                        <p className="text-xs text-muted-foreground">{match.indicator_type as string} · {match.match_type as string} · {match.feed_name as string}</p>
                      </div>
                    </div>
                    <Badge className={`text-xs border ${sevBadge(match.indicator_severity as string)}`}>{match.indicator_severity as string}</Badge>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-12">No matches yet. Add feeds, sync indicators, then run correlation.</p>
          )}
        </div>
      )}

      {/* Built-in Feeds Dialog */}
      <Dialog open={showBuiltin} onOpenChange={setShowBuiltin}>
        <DialogContent className="sm:max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader><DialogTitle className="flex items-center gap-2"><Globe className="h-5 w-5 text-teal-400" /> Available Threat Feeds</DialogTitle><DialogDescription>One-click subscribe to curated threat intelligence sources.</DialogDescription></DialogHeader>
          <div className="space-y-3 mt-2">
            {builtinFeeds.map((f, i) => (
              <div key={i} className="flex items-start justify-between p-3 rounded-lg bg-white/[0.04] border border-navy-400/15">
                <div>
                  <p className="text-sm font-medium text-white">{f.name}</p>
                  <p className="text-xs text-muted-foreground mt-1">{f.description}</p>
                  <div className="flex gap-2 mt-1">
                    <Badge className="text-[10px] bg-sky-500/15 text-sky-400 border-sky-500/30">{f.feed_type}</Badge>
                    <Badge className="text-[10px] bg-zinc-500/15 text-zinc-400 border-zinc-500/30">{f.format}</Badge>
                  </div>
                </div>
                <Button size="sm" onClick={() => addBuiltin(i)} className="bg-teal-600 hover:bg-teal-700 text-white text-xs">Subscribe</Button>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>

      {/* Correlation Result */}
      <Dialog open={!!correlationResult} onOpenChange={() => setCorrelationResult(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Correlation Results</DialogTitle></DialogHeader>
          {correlationResult && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">Checked {correlationResult.indicators_checked} indicators against internal data</p>
              <p className="text-lg font-bold text-white">{correlationResult.new_matches} new matches found</p>
              {(correlationResult.matches as Array<{ indicator: string; type: string }>).slice(0, 5).map((m, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <Target className="h-3 w-3 text-amber-400" />
                  <span className="text-white">{m.indicator}</span>
                  <span className="text-muted-foreground">({m.type})</span>
                </div>
              ))}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
