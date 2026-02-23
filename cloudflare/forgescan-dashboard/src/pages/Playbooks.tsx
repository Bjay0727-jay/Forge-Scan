import { useState, useEffect, useCallback } from 'react';
import { soarApi } from '@/lib/api';
import type { SOAROverview, SOARPlaybook } from '@/types';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Workflow, Play, Pause, Plus, RefreshCw, CheckCircle, XCircle, Clock, Zap, BookOpen } from 'lucide-react';

export function Playbooks() {
  const [overview, setOverview] = useState<SOAROverview | null>(null);
  const [playbooks, setPlaybooks] = useState<SOARPlaybook[]>([]);
  const [loading, setLoading] = useState(true);
  const [templates, setTemplates] = useState<Array<{ name: string; description: string; trigger_type: string; trigger_config: unknown; steps: unknown[] }>>([]);
  const [showTemplates, setShowTemplates] = useState(false);
  const [executing, setExecuting] = useState<string | null>(null);
  const [execResult, setExecResult] = useState<{ status: string; steps_completed: number; step_results: Array<{ action: string; status: string; result: string }> } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [ov, pbs] = await Promise.all([soarApi.getOverview(), soarApi.listPlaybooks()]);
      setOverview(ov);
      setPlaybooks((pbs.items || []) as SOARPlaybook[]);
    } catch (e) { console.error(e); } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const loadTemplates = async () => {
    const res = await soarApi.getTemplates();
    setTemplates(res.templates as Array<{ name: string; description: string; trigger_type: string; trigger_config: unknown; steps: unknown[] }>);
    setShowTemplates(true);
  };

  const installTemplate = async (tmpl: { name: string; description: string; trigger_type: string; trigger_config: unknown; steps: unknown[] }) => {
    await soarApi.createPlaybook({ name: tmpl.name, description: tmpl.description, trigger_type: tmpl.trigger_type, trigger_config: tmpl.trigger_config, steps: tmpl.steps as unknown[] });
    setShowTemplates(false);
    load();
  };

  const togglePlaybook = async (pb: SOARPlaybook) => {
    await soarApi.updatePlaybook(pb.id, { enabled: !pb.enabled });
    load();
  };

  const executePlaybook = async (id: string) => {
    setExecuting(id);
    try {
      const res = await soarApi.executePlaybook(id);
      setExecResult(res as unknown as { status: string; steps_completed: number; step_results: Array<{ action: string; status: string; result: string }> });
      load();
    } catch (e) { console.error(e); } finally { setExecuting(null); }
  };

  if (loading && !overview) return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-teal-500 border-t-transparent" /></div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">SOAR Playbooks</h1>
          <p className="text-sm text-[#6b8fb9] mt-1">Automated response actions — isolate hosts, escalate incidents, enrich IOCs, create tickets</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load} className="border-[#1e3a5f] text-[#6b8fb9] hover:text-white"><RefreshCw className="h-4 w-4 mr-1" /> Refresh</Button>
          <Button size="sm" onClick={loadTemplates} className="bg-teal-600 hover:bg-teal-700 text-white"><Plus className="h-4 w-4 mr-1" /> From Template</Button>
        </div>
      </div>

      {overview && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Playbooks', value: `${overview.totals.enabled}/${overview.totals.playbooks}`, sub: 'enabled', icon: Workflow, color: '#8b5cf6' },
            { label: 'Executions', value: overview.totals.total_executions, sub: 'total runs', icon: Zap, color: '#14b8a6' },
            { label: 'Success Rate', value: `${overview.totals.success_rate}%`, sub: `${overview.totals.successful} passed`, icon: CheckCircle, color: '#22c55e' },
            { label: 'Failed', value: overview.totals.failed, sub: 'runs failed', icon: XCircle, color: '#ef4444' },
          ].map(s => (
            <Card key={s.label} className="border-[#1e3a5f]/60" style={{ background: 'rgba(255,255,255,0.03)' }}>
              <CardContent className="p-4 flex items-center justify-between">
                <div><p className="text-2xl font-bold text-white">{s.value}</p><p className="text-xs text-[#4b77a9]">{s.label}</p><p className="text-[10px] text-[#3a6590]">{s.sub}</p></div>
                <s.icon className="h-8 w-8" style={{ color: s.color, opacity: 0.5 }} />
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <div className="space-y-3">
        {playbooks.map(pb => {
          const steps = JSON.parse(pb.steps || '[]') as Array<{ action_type: string }>;
          return (
            <div key={pb.id} className="p-4 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.15)' }}>
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-3">
                  <Workflow className="h-5 w-5 text-purple-400" />
                  <div>
                    <p className="text-sm font-medium text-white">{pb.name}</p>
                    <p className="text-xs text-[#4b77a9]">{pb.description || 'No description'}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge className={`text-[10px] border ${pb.enabled ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30'}`}>
                    {pb.enabled ? 'Active' : 'Disabled'}
                  </Badge>
                  <Badge className="text-[10px] border bg-sky-500/15 text-sky-400 border-sky-500/30">{pb.trigger_type}</Badge>
                </div>
              </div>

              <div className="flex items-center gap-2 mb-3 flex-wrap">
                {steps.map((s, i) => (
                  <div key={i} className="flex items-center">
                    <span className="text-[10px] px-2 py-0.5 rounded bg-white/[0.06] text-[#6b8fb9]">{s.action_type.replace(/_/g, ' ')}</span>
                    {i < steps.length - 1 && <span className="text-[#3a6590] mx-1">→</span>}
                  </div>
                ))}
              </div>

              <div className="flex items-center justify-between">
                <div className="flex gap-4 text-xs text-[#4b77a9]">
                  <span className="flex items-center gap-1"><Zap className="h-3 w-3" /> {pb.trigger_count} runs</span>
                  <span className="flex items-center gap-1"><CheckCircle className="h-3 w-3 text-emerald-400" /> {pb.success_count}</span>
                  <span className="flex items-center gap-1"><XCircle className="h-3 w-3 text-red-400" /> {pb.failure_count}</span>
                  {pb.last_triggered_at && <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> {new Date(pb.last_triggered_at).toLocaleDateString()}</span>}
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => togglePlaybook(pb)} className="text-xs border-[#1e3a5f] text-[#6b8fb9] hover:text-white">
                    {pb.enabled ? <><Pause className="h-3 w-3 mr-1" /> Disable</> : <><Play className="h-3 w-3 mr-1" /> Enable</>}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => executePlaybook(pb.id)} disabled={executing === pb.id} className="text-xs border-teal-500/30 text-teal-400 hover:bg-teal-500/10">
                    {executing === pb.id ? <RefreshCw className="h-3 w-3 animate-spin mr-1" /> : <Play className="h-3 w-3 mr-1" />} Run Now
                  </Button>
                </div>
              </div>
            </div>
          );
        })}
        {playbooks.length === 0 && <p className="text-sm text-[#4b77a9] text-center py-12">No playbooks configured. Click "From Template" to install pre-built response workflows.</p>}
      </div>

      {/* Templates Dialog */}
      <Dialog open={showTemplates} onOpenChange={setShowTemplates}>
        <DialogContent className="sm:max-w-2xl max-h-[80vh] overflow-y-auto" style={{ background: '#0f2133', border: '1px solid rgba(75,119,169,0.3)' }}>
          <DialogHeader><DialogTitle className="text-white flex items-center gap-2"><BookOpen className="h-5 w-5 text-teal-400" /> Playbook Templates</DialogTitle><DialogDescription className="text-[#6b8fb9]">Install pre-built automated response playbooks.</DialogDescription></DialogHeader>
          <div className="space-y-3 mt-2">
            {templates.map((tmpl, i) => (
              <div key={i} className="p-4 rounded-lg" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(75,119,169,0.15)' }}>
                <div className="flex items-start justify-between">
                  <div><p className="text-sm font-medium text-white">{tmpl.name}</p><p className="text-xs text-[#4b77a9] mt-1">{tmpl.description}</p></div>
                  <Button size="sm" onClick={() => installTemplate(tmpl)} className="bg-teal-600 hover:bg-teal-700 text-white text-xs">Install</Button>
                </div>
                <div className="flex items-center gap-1 mt-2 flex-wrap">
                  {(tmpl.steps as Array<{ action_type: string }>).map((s, j) => (
                    <span key={j} className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.06] text-[#6b8fb9]">{s.action_type.replace(/_/g, ' ')}{j < tmpl.steps.length - 1 ? ' →' : ''}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>

      {/* Execution Result Dialog */}
      <Dialog open={!!execResult} onOpenChange={() => setExecResult(null)}>
        <DialogContent style={{ background: '#0f2133', border: '1px solid rgba(75,119,169,0.3)' }}>
          <DialogHeader><DialogTitle className="text-white">Playbook Execution Result</DialogTitle></DialogHeader>
          {execResult && (
            <div className="space-y-3">
              <Badge className={`text-xs border ${execResult.status === 'completed' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'}`}>{execResult.status}</Badge>
              <p className="text-xs text-[#6b8fb9]">{execResult.steps_completed} steps completed</p>
              <div className="space-y-1">
                {execResult.step_results.map((sr, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    {sr.status === 'completed' ? <CheckCircle className="h-3 w-3 text-emerald-400" /> : <XCircle className="h-3 w-3 text-red-400" />}
                    <span className="text-white">{sr.action.replace(/_/g, ' ')}</span>
                    <span className="text-[#4b77a9]">{sr.result}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
