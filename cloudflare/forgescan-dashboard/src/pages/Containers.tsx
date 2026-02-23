import { useState, useEffect, useCallback } from 'react';
import { containersApi } from '@/lib/api';
import type { ContainerOverview, ContainerImage } from '@/types';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Box, Search, Plus, RefreshCw, Play, AlertTriangle, Shield, Layers } from 'lucide-react';

function sevBadge(s: string) {
  const map: Record<string, string> = { critical: 'bg-red-500/20 text-red-400 border-red-500/30', high: 'bg-orange-500/20 text-orange-400 border-orange-500/30', medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30', low: 'bg-sky-500/20 text-sky-400 border-sky-500/30' };
  return map[s] || 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30';
}

export function Containers() {
  const [overview, setOverview] = useState<ContainerOverview | null>(null);
  const [images, setImages] = useState<ContainerImage[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [newImage, setNewImage] = useState({ registry: 'docker.io', repository: '', tag: 'latest' });
  const [scanning, setScanning] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<{ message: string; critical: number; high: number } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [ov, imgs] = await Promise.all([containersApi.getOverview(), containersApi.listImages({ page_size: 50, search: search || undefined })]);
      setOverview(ov);
      setImages((imgs.items || []) as ContainerImage[]);
    } catch (e) { console.error(e); } finally { setLoading(false); }
  }, [search]);

  useEffect(() => { load(); }, [load]);

  const handleAdd = async () => {
    if (!newImage.repository) return;
    await containersApi.addImage(newImage);
    setShowAdd(false);
    setNewImage({ registry: 'docker.io', repository: '', tag: 'latest' });
    load();
  };

  const handleScan = async (id: string) => {
    setScanning(id);
    try {
      const res = await containersApi.scanImage(id);
      setScanResult(res);
      load();
    } catch (e) { console.error(e); } finally { setScanning(null); }
  };

  if (loading && !overview) return <div className="flex items-center justify-center h-64"><div className="h-8 w-8 animate-spin rounded-full border-4 border-teal-500 border-t-transparent" /></div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Container Security</h1>
          <p className="text-sm text-muted-foreground mt-1">Scan container images for OS/app vulnerabilities, misconfigurations, and secrets</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load} className="border-border text-muted-foreground hover:text-white"><RefreshCw className="h-4 w-4 mr-1" /> Refresh</Button>
          <Button size="sm" onClick={() => setShowAdd(true)} className="bg-teal-600 hover:bg-teal-700 text-white"><Plus className="h-4 w-4 mr-1" /> Add Image</Button>
        </div>
      </div>

      {overview && (
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: 'Container Images', value: overview.totals.images, icon: Box, color: 'text-violet-400' },
            { label: 'Scans Completed', value: overview.totals.scans, icon: Shield, color: 'text-teal-400' },
            { label: 'Open Findings', value: overview.totals.open_findings, icon: AlertTriangle, color: 'text-amber-400' },
          ].map(s => (
            <Card key={s.label} className="border-border/60 bg-white/[0.03]">
              <CardContent className="p-4 flex items-center justify-between">
                <div><p className="text-2xl font-bold text-white">{s.value}</p><p className="text-xs text-muted-foreground">{s.label}</p></div>
                <s.icon className={`h-6 w-6 opacity-50 ${s.color}`} />
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input placeholder="Search images..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 bg-transparent border-border text-white placeholder:text-muted-foreground" />
      </div>

      <div className="space-y-2">
        {images.map(img => (
          <div key={img.id} className="flex items-center justify-between p-4 rounded-lg bg-white/[0.03] border border-navy-400/15">
            <div className="flex items-center gap-3">
              <Layers className="h-5 w-5 text-purple-400" />
              <div>
                <p className="text-sm font-medium text-white">{img.repository}:{img.tag}</p>
                <p className="text-xs text-muted-foreground">{img.registry} · Last scan: {img.last_scanned ? new Date(img.last_scanned).toLocaleDateString() : 'Never'}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {(img.total_critical || 0) > 0 && <Badge className={`text-xs border ${sevBadge('critical')}`}>{img.total_critical} critical</Badge>}
              {(img.total_high || 0) > 0 && <Badge className={`text-xs border ${sevBadge('high')}`}>{img.total_high} high</Badge>}
              <Button variant="outline" size="sm" onClick={() => handleScan(img.id)} disabled={scanning === img.id} className="border-border text-muted-foreground hover:text-white hover:border-teal-500/50">
                {scanning === img.id ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                <span className="ml-1">Scan</span>
              </Button>
            </div>
          </div>
        ))}
        {images.length === 0 && <p className="text-sm text-muted-foreground text-center py-12">No container images registered. Click "Add Image" to get started.</p>}
      </div>

      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent>
          <DialogHeader><DialogTitle>Register Container Image</DialogTitle><DialogDescription>Add a container image to scan for vulnerabilities.</DialogDescription></DialogHeader>
          <div className="space-y-3 mt-2">
            <Input value={newImage.registry} onChange={e => setNewImage(p => ({ ...p, registry: e.target.value }))} placeholder="docker.io" className="bg-transparent border-border text-white" />
            <Input value={newImage.repository} onChange={e => setNewImage(p => ({ ...p, repository: e.target.value }))} placeholder="myapp/backend" className="bg-transparent border-border text-white" />
            <Input value={newImage.tag} onChange={e => setNewImage(p => ({ ...p, tag: e.target.value }))} placeholder="latest" className="bg-transparent border-border text-white" />
            <div className="flex justify-end gap-2"><Button variant="outline" onClick={() => setShowAdd(false)}>Cancel</Button><Button onClick={handleAdd} className="bg-teal-600 hover:bg-teal-700 text-white">Add Image</Button></div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={!!scanResult} onOpenChange={() => setScanResult(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Scan Complete</DialogTitle></DialogHeader>
          {scanResult && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">{scanResult.message}</p>
              <div className="flex gap-3">
                <Badge className={`text-xs border ${sevBadge('critical')}`}>{scanResult.critical} critical</Badge>
                <Badge className={`text-xs border ${sevBadge('high')}`}>{scanResult.high} high</Badge>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
