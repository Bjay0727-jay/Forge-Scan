import { useMemo } from 'react';
import {
  Server,
  AlertTriangle,
  Scan,
  ShieldAlert,
  ClipboardCheck,
  Crosshair,
  Cpu,
  Activity,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Eyebrow } from '@/components/ui/eyebrow';
import { SeverityBadge, SEVERITY_ORDER, type Severity } from '@/components/ui/severity-badge';
import { StatCard } from '@/components/ui/stat-card';
import { RiskGrade, type RiskGrade as RiskGradeType } from '@/components/ui/risk-grade';
import { LivePulse } from '@/components/ui/live-pulse';
import { useToast } from '@/components/ui/toast-context';

const NAVY_SCALE = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900] as const;
const TEAL_SCALE = [400, 500, 600, 700] as const;
const GRADES: { letter: RiskGradeType; score: number; label: string }[] = [
  { letter: 'A', score: 95, label: 'Excellent' },
  { letter: 'B', score: 82, label: 'Good' },
  { letter: 'C', score: 68, label: 'Fair' },
  { letter: 'D', score: 50, label: 'Poor' },
  { letter: 'F', score: 22, label: 'Critical' },
];

const TYPE_SPECIMENS: { token: string; size: string; sample: string; family: 'heading' | 'body' | 'mono' }[] = [
  { token: 'forge-text-hero', size: '56px', sample: 'See every exposure.', family: 'heading' },
  { token: 'forge-text-3xl',  size: '38.5px', sample: 'Continuous posture, real-time.', family: 'heading' },
  { token: 'forge-text-2xl',  size: '28px', sample: '14,208 findings under management', family: 'heading' },
  { token: 'forge-text-xl',   size: '21px', sample: 'Critical exposures by control plane', family: 'heading' },
  { token: 'forge-text-lg',   size: '15.75px', sample: 'Asset inventory · 2,341 hosts', family: 'body' },
  { token: 'forge-text-md',   size: '14px', sample: 'Scan completed at 14:32 UTC.', family: 'body' },
  { token: 'forge-text-base', size: '12.25px', sample: 'dc-prod-01.forge.int  ·  10.0.42.7', family: 'mono' },
  { token: 'forge-text-sm',   size: '11.4px', sample: 'NIST 800-53 · AC-2(12)', family: 'mono' },
  { token: 'forge-text-xs',   size: '10.5px', sample: 'CVE-2024-21412 · KEV', family: 'mono' },
];

const SEVERITY_COUNTS: Record<Severity, number> = {
  critical: 14,
  high:     63,
  medium:   208,
  low:      512,
  info:     8412,
};

export function DesignSystem() {
  const { toast } = useToast();
  const total = useMemo(
    () => Object.values(SEVERITY_COUNTS).reduce((a, b) => a + b, 0),
    [],
  );

  const fireToast = (variant: Severity | 'success' | 'neutral') => {
    const palette: Record<typeof variant, { title: string; description: string }> = {
      critical: { title: 'Critical: Log4Shell on dc-prod-01', description: 'CVE-2021-44228 · 3 production hosts affected.' },
      high:     { title: 'High: Outbound C2 beacon detected', description: 'fin-app-04 → 185.197.74.61 · Severity rising.' },
      medium:   { title: 'Medium: Patch SLA breached',         description: '7 hosts past 14-day window for KB5037772.' },
      low:      { title: 'Low: Backup verification passed',    description: 'All evidence captured for IR-4 control.' },
      info:     { title: 'New scan profile published',         description: '“Federal Quarterly” scope is now active.' },
      success:  { title: 'Remediation accepted',               description: 'Finding #14208 · Closed by k.morales.' },
      neutral:  { title: 'Sync complete',                       description: 'Asset inventory refreshed · 2,341 hosts.' },
    };
    toast({ variant, ...palette[variant] });
  };

  return (
    <div className="space-y-12 pb-16">
      {/* Page header — eyebrow + H1 + lead */}
      <header className="border-b border-border pb-8">
        <Eyebrow>v1.0 · Dark Canonical</Eyebrow>
        <h1 className="mt-2 font-heading text-forge-3xl font-bold text-foreground">
          Forge Cyber Defense — Design System
        </h1>
        <p className="mt-3 max-w-3xl text-forge-md text-muted-foreground leading-relaxed">
          Every token, type, and primitive that ships across ForgeScan,
          ForgeSOC, ForgeRedOps, and ForgeComply 360. Pulled directly from
          this dashboard — what you see here is what your customers see when
          they log in.
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-2 font-mono text-xs text-muted-foreground">
          <Badge variant="outline" className="font-mono">
            <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-teal-400" />
            Production
          </Badge>
          <span>·</span>
          <span>src/index.css</span>
          <span>·</span>
          <span>tailwind.config.js</span>
        </div>
      </header>

      {/* Color system — navy + teal scales */}
      <section aria-labelledby="colors-heading" className="space-y-4">
        <div>
          <Eyebrow variant="kicker">Foundations · Color</Eyebrow>
          <h2 id="colors-heading" className="mt-1 font-heading text-forge-xl font-semibold">
            Brand palette
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Navy carries the canvas; teal earns its place by scarcity. Never
            invent new brand colors.
          </p>
        </div>

        <div>
          <p className="mb-2 forge-eyebrow">Navy</p>
          <div className="grid grid-cols-5 gap-2 sm:grid-cols-10">
            {NAVY_SCALE.map((step) => (
              <Swatch
                key={`navy-${step}`}
                token={`--forge-navy-${step}`}
                color={`var(--forge-navy-${step})`}
                label={`navy-${step}`}
              />
            ))}
          </div>
        </div>

        <div>
          <p className="mb-2 forge-eyebrow">Teal</p>
          <div className="grid grid-cols-4 gap-2">
            {TEAL_SCALE.map((step) => (
              <Swatch
                key={`teal-${step}`}
                token={`--forge-teal-${step}`}
                color={`var(--forge-teal-${step})`}
                label={`teal-${step}`}
              />
            ))}
          </div>
        </div>
      </section>

      {/* Severity — contractual */}
      <section aria-labelledby="severity-heading" className="space-y-4">
        <div>
          <Eyebrow variant="kicker">Foundations · Severity</Eyebrow>
          <h2 id="severity-heading" className="mt-1 font-heading text-forge-xl font-semibold">
            Severity colors are contractual
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Order: Critical → High → Medium → Low → Info. Never substitute,
            never invent new severity levels.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          {SEVERITY_ORDER.map((sev) => (
            <Card key={sev} className="forge-card-hover">
              <CardContent className="p-4">
                <SeverityBadge severity={sev} />
                <p className="mt-3 font-heading text-2xl font-bold text-foreground">
                  {SEVERITY_COUNTS[sev].toLocaleString()}
                </p>
                <p className="font-mono text-[11px] text-muted-foreground">
                  {((SEVERITY_COUNTS[sev] / total) * 100).toFixed(1)}% of {total.toLocaleString()}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      {/* Risk grade ring */}
      <section aria-labelledby="grade-heading" className="space-y-4">
        <div>
          <Eyebrow variant="kicker">Foundations · Risk Grade</Eyebrow>
          <h2 id="grade-heading" className="mt-1 font-heading text-forge-xl font-semibold">
            Executive Scorecard glyph
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            FRS (Forge Risk Score) maps to A–F. Only appears in the
            scorecard — never as ornament.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          {GRADES.map((g) => (
            <Card key={g.letter} className="forge-card-hover">
              <CardContent className="flex items-center gap-4 p-4">
                <RiskGrade grade={g.letter} score={g.score} size={72} />
                <div>
                  <p className="font-heading text-sm font-semibold text-foreground">
                    Grade {g.letter}
                  </p>
                  <p className="font-mono text-[11px] text-muted-foreground">{g.label}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      {/* Typography */}
      <section aria-labelledby="type-heading" className="space-y-4">
        <div>
          <Eyebrow variant="kicker">Foundations · Type</Eyebrow>
          <h2 id="type-heading" className="mt-1 font-heading text-forge-xl font-semibold">
            Sora · Inter · JetBrains Mono
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Headings, body, code-shaped data. No other fonts ship.
          </p>
        </div>
        <Card>
          <CardContent className="divide-y divide-dashed divide-border p-0">
            {TYPE_SPECIMENS.map((spec) => (
              <div key={spec.token} className="grid grid-cols-[140px_1fr] items-baseline gap-6 px-5 py-4">
                <div className="font-mono text-[10.5px] uppercase tracking-wider text-muted-foreground">
                  <span className="block font-heading text-[11px] normal-case tracking-normal text-foreground">
                    {spec.token}
                  </span>
                  {spec.size}
                </div>
                <div
                  className="text-foreground"
                  style={{
                    fontSize: `var(--${spec.token})`,
                    fontFamily:
                      spec.family === 'heading'
                        ? 'var(--forge-font-heading)'
                        : spec.family === 'mono'
                          ? 'var(--forge-font-mono)'
                          : 'var(--forge-font-body)',
                    fontWeight: spec.family === 'heading' ? 600 : 400,
                  }}
                >
                  {spec.sample}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </section>

      {/* Stat cards */}
      <section aria-labelledby="stats-heading" className="space-y-4">
        <div>
          <Eyebrow variant="kicker">Components · Stats</Eyebrow>
          <h2 id="stats-heading" className="mt-1 font-heading text-forge-xl font-semibold">
            StatCard
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            32px teal icon chip top-right, Sora 28/700 hero number,
            optional live-pulse and trend chip.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="Open Findings"
            value="14,208"
            icon={AlertTriangle}
            trend={{ direction: 'down', value: '−6.2% wk/wk' }}
            live
          />
          <StatCard
            label="Assets Discovered"
            value="2,341"
            icon={Server}
            trend={{ direction: 'up', value: '+18 today' }}
          />
          <StatCard
            label="Scans Last 24h"
            value="186"
            icon={Scan}
            helper="Avg 3.4 min · 99.7% complete"
          />
          <StatCard
            label="Controls Failing"
            value="7"
            icon={ClipboardCheck}
            trend={{ direction: 'flat', value: 'No change' }}
          />
        </div>
      </section>

      {/* Buttons + form primitives */}
      <section aria-labelledby="forms-heading" className="space-y-4">
        <div>
          <Eyebrow variant="kicker">Components · Buttons + Forms</Eyebrow>
          <h2 id="forms-heading" className="mt-1 font-heading text-forge-xl font-semibold">
            Primitives
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            shadcn-derived. h-9 default. Never pill buttons for primary actions.
          </p>
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="font-heading text-base">Buttons</CardTitle>
              <CardDescription>default · destructive · outline · secondary · ghost · link</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center gap-2">
              <Button>Run scan</Button>
              <Button variant="destructive">Quarantine</Button>
              <Button variant="outline">Export</Button>
              <Button variant="secondary">Save draft</Button>
              <Button variant="ghost">Cancel</Button>
              <Button variant="link">Open finding</Button>
              <Button size="sm" variant="outline">Small</Button>
              <Button size="lg">Large</Button>
              <Button size="icon" aria-label="Run scan"><Scan className="h-4 w-4" /></Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="font-heading text-base">Form fields</CardTitle>
              <CardDescription>Input · Select · Textarea</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <Label htmlFor="ds-asset">Asset hostname</Label>
                <Input id="ds-asset" placeholder="dc-prod-01.forge.int" />
              </div>
              <div>
                <Label htmlFor="ds-scope">Scope</Label>
                <Select>
                  <SelectTrigger id="ds-scope"><SelectValue placeholder="Select scope" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="production">Production</SelectItem>
                    <SelectItem value="staging">Staging</SelectItem>
                    <SelectItem value="federal">Federal Quarterly</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="ds-notes">Operator notes</Label>
                <Textarea
                  id="ds-notes"
                  rows={3}
                  placeholder="Findings will be reviewed by the on-call Tier 3 analyst."
                />
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Tabs + live pulse + iconography */}
      <section aria-labelledby="composite-heading" className="space-y-4">
        <div>
          <Eyebrow variant="kicker">Composition</Eyebrow>
          <h2 id="composite-heading" className="mt-1 font-heading text-forge-xl font-semibold">
            Tabs, motion, iconography
          </h2>
        </div>
        <Card>
          <CardContent className="p-4">
            <Tabs defaultValue="live">
              <TabsList>
                <TabsTrigger value="live" className="gap-2">
                  <LivePulse tone="teal" />
                  Live feed
                </TabsTrigger>
                <TabsTrigger value="findings">Findings</TabsTrigger>
                <TabsTrigger value="controls">Controls</TabsTrigger>
              </TabsList>

              <TabsContent value="live" className="mt-4">
                <ul className="divide-y divide-border">
                  {[
                    { ts: '14:32:08Z', sev: 'critical' as Severity, msg: 'Log4Shell exploit attempt — dc-prod-01' },
                    { ts: '14:31:55Z', sev: 'high'     as Severity, msg: 'Outbound C2 beacon — fin-app-04 → 185.197.74.61' },
                    { ts: '14:31:42Z', sev: 'medium'   as Severity, msg: 'Patch SLA breach — 7 hosts past 14-day window' },
                    { ts: '14:31:24Z', sev: 'info'     as Severity, msg: 'Scan profile updated — Federal Quarterly' },
                  ].map((e) => (
                    <li key={e.ts} className="flex items-center gap-3 py-2 text-sm">
                      <span className="font-mono text-[11px] text-muted-foreground">{e.ts}</span>
                      <SeverityBadge severity={e.sev} withDot={false} />
                      <span className="truncate text-foreground">{e.msg}</span>
                    </li>
                  ))}
                </ul>
              </TabsContent>

              <TabsContent value="findings" className="mt-4 space-y-2">
                {SEVERITY_ORDER.map((sev) => (
                  <div
                    key={sev}
                    className="flex items-center justify-between rounded-md border border-border bg-card/50 px-3 py-2"
                  >
                    <SeverityBadge severity={sev} />
                    <span className="font-mono text-xs text-muted-foreground">
                      {SEVERITY_COUNTS[sev].toLocaleString()} findings
                    </span>
                  </div>
                ))}
              </TabsContent>

              <TabsContent value="controls" className="mt-4">
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {[
                    { icon: Server,         name: 'Assets' },
                    { icon: AlertTriangle,  name: 'Findings' },
                    { icon: Scan,           name: 'Scans' },
                    { icon: Crosshair,      name: 'RedOps' },
                    { icon: ShieldAlert,    name: 'Vulns' },
                    { icon: ClipboardCheck, name: 'Compliance' },
                    { icon: Cpu,            name: 'Scanners' },
                    { icon: Activity,       name: 'Live' },
                  ].map(({ icon: Icon, name }) => (
                    <div key={name} className="flex items-center gap-2 rounded-md border border-border p-2.5">
                      <span className="forge-stat-chip">
                        <Icon className="h-4 w-4" strokeWidth={1.5} />
                      </span>
                      <span className="font-heading text-sm font-medium">{name}</span>
                    </div>
                  ))}
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </section>

      {/* Toast playground */}
      <section aria-labelledby="toast-heading" className="space-y-4">
        <div>
          <Eyebrow variant="kicker">Components · Notifications</Eyebrow>
          <h2 id="toast-heading" className="mt-1 font-heading text-forge-xl font-semibold">
            Toast variants
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Severity-keyed. Critical/High get role=alert + aria-live=assertive.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="destructive" onClick={() => fireToast('critical')}>Fire Critical</Button>
          <Button variant="outline" onClick={() => fireToast('high')}>Fire High</Button>
          <Button variant="outline" onClick={() => fireToast('medium')}>Fire Medium</Button>
          <Button variant="outline" onClick={() => fireToast('low')}>Fire Low</Button>
          <Button variant="outline" onClick={() => fireToast('info')}>Fire Info</Button>
          <Button onClick={() => fireToast('success')}>Fire Success</Button>
          <Button variant="secondary" onClick={() => fireToast('neutral')}>Fire Neutral</Button>
        </div>
      </section>

      {/* Logos */}
      <section aria-labelledby="logos-heading" className="space-y-4">
        <div>
          <Eyebrow variant="kicker">Brand · Logos</Eyebrow>
          <h2 id="logos-heading" className="mt-1 font-heading text-forge-xl font-semibold">
            Approved lockups
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Use only the approved files. Never recolor outside the monochrome variants.
          </p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { src: '/forge-logo-horizontal.svg',        label: 'Horizontal' },
            { src: '/forge-logo-stacked-vertical.svg',  label: 'Stacked' },
            { src: '/forge-wordmark.svg',               label: 'Wordmark' },
            { src: '/forge-shield-icon.svg',            label: 'Shield mark' },
            { src: '/forge-logo-full-dark-bg.svg',      label: 'Full · dark bg' },
            { src: '/forge-logo-monochrome-teal.svg',   label: 'Mono · teal' },
            { src: '/forge-logo-monochrome-white.svg',  label: 'Mono · white' },
            { src: '/forge-logo-white-reverse.svg',     label: 'White reverse' },
          ].map(({ src, label }) => (
            <Card key={src} className="forge-card-hover">
              <CardContent className="flex h-32 items-center justify-center p-4">
                <img src={src} alt={label} className="max-h-12 w-auto" />
              </CardContent>
              <div className="border-t border-border px-4 py-2 font-mono text-[11px] text-muted-foreground">
                {label}
              </div>
            </Card>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border pt-6 font-mono text-[11px] text-muted-foreground">
        Forge Cyber Defense · Design System v1.0 · Dark Canonical · 14px base ·
        Sora · Inter · JetBrains Mono
      </footer>
    </div>
  );
}

function Swatch({ token, color, label }: { token: string; color: string; label: string }) {
  return (
    <div className="overflow-hidden rounded-md border border-border">
      <div className="aspect-square" style={{ background: color }} />
      <div className="bg-card p-2">
        <p className="font-heading text-[11px] font-semibold text-foreground">{label}</p>
        <p className="font-mono text-[10px] text-muted-foreground">{token}</p>
      </div>
    </div>
  );
}
