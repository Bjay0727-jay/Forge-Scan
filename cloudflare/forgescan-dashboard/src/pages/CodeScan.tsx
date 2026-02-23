import { useState, useEffect, useCallback } from 'react';
import { sastApi } from '@/lib/api';
import type { SASTOverview, SASTProject } from '@/types';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Code, Search, Plus, RefreshCw, Play, AlertTriangle, FileCode, Bug } from 'lucide-react';

function sevBadge(s: string) {
  const map: Record<string, string> = { critical: 'bg-red-500/20 text-red-400 border-red-500/30', high: 'bg-orange-500/20 text-orange-400 border-orange-500/30', medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30', low: 'bg-sky-500/20 text-sky-400 border-sky-500/30' };
  return map[s] || 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30';
}

export function CodeScan() {
  const [overview, setOverview] = useState<SASTOverview | null>(null);
  const [projects, setProjects] = useState<SASTProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [newProject, setNewProject] = useState({ name: '', repository_url: '', branch: 'main', language: 'typescript' });
  const [scanning, setScanning] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<{ message: string; issues_found: number; critical: number; high: number } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [ov, projs] = await Promise.all([sastApi.getOverview(), sastApi.listProjects({ page_size: 50, search: search || undefined })]);
      setOverview(ov);
      setProjects((projs.items || []) as SASTProject[]);
    } catch (e) { console.error(e); } finally { setLoading(false); }
  }, [search]);

  useEffect(() => { load(); }, [load]);

  const handleAdd = async () => {
    if (!newProject.name) return;
    await sastApi.addProject(newProject);
    setShowAdd(false);
    setNewProject({ name: '', repository_url: '', branch: 'main', language: 'typescript' });
    load();
  };

  const handleScan = async (id: string) => {
    setScanning(id);
    try {
      const res = await sastApi.scanProject(id);
      setScanResult(res);
      load();
    } catch (e) { console.error(e); } finally { setScanning(null); }
  };

  if (loading && !overview) return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-teal-500 border-t-transparent" /></div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Code Security (SAST)</h1>
          <p className="text-sm text-[#6b8fb9] mt-1">Static analysis for injection, XSS, auth flaws, crypto weaknesses, and misconfigurations</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load} className="border-[#1e3a5f] text-[#6b8fb9] hover:text-white"><RefreshCw className="h-4 w-4 mr-1" /> Refresh</Button>
          <Button size="sm" onClick={() => setShowAdd(true)} className="bg-teal-600 hover:bg-teal-700 text-white"><Plus className="h-4 w-4 mr-1" /> Add Project</Button>
        </div>
      </div>

      {overview && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Projects', value: overview.totals.projects, icon: FileCode, color: '#8b5cf6' },
            { label: 'Scans Run', value: overview.totals.scans, icon: Code, color: '#14b8a6' },
            { label: 'Open Issues', value: overview.totals.open_issues, icon: Bug, color: '#ef4444' },
            { label: 'SAST Rules', value: overview.rules_count, icon: AlertTriangle, color: '#f59e0b' },
          ].map(s => (
            <Card key={s.label} className="border-[#1e3a5f]/60" style={{ background: 'rgba(255,255,255,0.03)' }}>
              <CardContent className="p-4 flex items-center justify-between">
                <div><p className="text-2xl font-bold text-white">{s.value}</p><p className="text-xs text-[#4b77a9]">{s.label}</p></div>
                <s.icon className="h-8 w-8" style={{ color: s.color, opacity: 0.5 }} />
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {overview && overview.category_breakdown.length > 0 && (
        <Card className="border-[#1e3a5f]/60" style={{ background: 'rgba(255,255,255,0.03)' }}>
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold text-white mb-3">Issues by Category</h3>
            <div className="flex gap-3 flex-wrap">
              {overview.category_breakdown.map(cat => (
                <div key={cat.category} className="flex items-center gap-2 px-3 py-1.5 rounded-lg" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(75,119,169,0.15)' }}>
                  <span className="text-xs text-white font-medium">{cat.category}</span>
                  <Badge className="text-[10px] bg-teal-500/15 text-teal-400 border-teal-500/30">{cat.count}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[#4b77a9]" />
        <Input placeholder="Search projects..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 bg-transparent border-[#1e3a5f] text-white placeholder:text-[#4b77a9]" />
      </div>

      <div className="space-y-2">
        {projects.map(proj => (
          <div key={proj.id} className="flex items-center justify-between p-4 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(75,119,169,0.15)' }}>
            <div className="flex items-center gap-3">
              <FileCode className="h-5 w-5 text-purple-400" />
              <div>
                <p className="text-sm font-medium text-white">{proj.name}</p>
                <p className="text-xs text-[#4b77a9]">{proj.language || 'unknown'} · {proj.branch} · {proj.loc ? `${proj.loc.toLocaleString()} LOC` : 'Not scanned'}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {(proj.total_issues || 0) > 0 && <Badge className="text-xs border bg-red-500/15 text-red-400 border-red-500/30">{proj.total_issues} issues</Badge>}
              <Button variant="outline" size="sm" onClick={() => handleScan(proj.id)} disabled={scanning === proj.id} className="border-[#1e3a5f] text-[#6b8fb9] hover:text-white hover:border-teal-500/50">
                {scanning === proj.id ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                <span className="ml-1">Scan</span>
              </Button>
            </div>
          </div>
        ))}
        {projects.length === 0 && <p className="text-sm text-[#4b77a9] text-center py-12">No projects added. Click "Add Project" to register a codebase.</p>}
      </div>

      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent style={{ background: '#0f2133', border: '1px solid rgba(75,119,169,0.3)' }}>
          <DialogHeader><DialogTitle className="text-white">Add Code Project</DialogTitle><DialogDescription className="text-[#6b8fb9]">Register a codebase for SAST scanning.</DialogDescription></DialogHeader>
          <div className="space-y-3 mt-2">
            <Input value={newProject.name} onChange={e => setNewProject(p => ({ ...p, name: e.target.value }))} placeholder="Project name" className="bg-transparent border-[#1e3a5f] text-white" />
            <Input value={newProject.repository_url} onChange={e => setNewProject(p => ({ ...p, repository_url: e.target.value }))} placeholder="https://github.com/org/repo" className="bg-transparent border-[#1e3a5f] text-white" />
            <div className="grid grid-cols-2 gap-3">
              <Input value={newProject.branch} onChange={e => setNewProject(p => ({ ...p, branch: e.target.value }))} placeholder="main" className="bg-transparent border-[#1e3a5f] text-white" />
              <select value={newProject.language} onChange={e => setNewProject(p => ({ ...p, language: e.target.value }))} className="rounded-md px-3 py-2 text-sm bg-transparent text-white" style={{ border: '1px solid #1e3a5f' }}>
                <option value="typescript">TypeScript</option><option value="javascript">JavaScript</option><option value="python">Python</option><option value="java">Java</option><option value="go">Go</option>
              </select>
            </div>
            <div className="flex justify-end gap-2"><Button variant="outline" onClick={() => setShowAdd(false)} className="border-[#1e3a5f] text-[#6b8fb9]">Cancel</Button><Button onClick={handleAdd} className="bg-teal-600 hover:bg-teal-700 text-white">Add Project</Button></div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={!!scanResult} onOpenChange={() => setScanResult(null)}>
        <DialogContent style={{ background: '#0f2133', border: '1px solid rgba(75,119,169,0.3)' }}>
          <DialogHeader><DialogTitle className="text-white">SAST Scan Complete</DialogTitle></DialogHeader>
          {scanResult && (
            <div className="space-y-3">
              <p className="text-sm text-[#6b8fb9]">{scanResult.message}</p>
              <div className="flex gap-3">
                <Badge className={`text-xs border ${sevBadge('critical')}`}>{scanResult.critical} critical</Badge>
                <Badge className={`text-xs border ${sevBadge('high')}`}>{scanResult.high} high</Badge>
                <Badge className="text-xs border bg-zinc-500/20 text-zinc-400 border-zinc-500/30">{scanResult.issues_found} total</Badge>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
